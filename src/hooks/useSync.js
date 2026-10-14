import { useEffect, useRef } from 'react';
import axios from 'axios';
import secureLogger from '../secureLogger';
import { sanitizeErrorMessage } from '../utils/security';
import { readAllSecrets } from '../utils/readAllSecrets';
import { useOptionalTranslation } from '../i18n';

// PERFORMANCE : regroupement des écritures. La vérification des AUTRES coffres (clés
// ajoutées par une migration ou une copie) a lieu une seule fois, RECONCILE_DELAY_MS
// après la dernière écriture.
export const RECONCILE_DELAY_MS = 1000;
// Coffre relu par le tableau (fetchSecrets) depuis moins de RECENT_PUSH_MS : déjà à jour.
const RECENT_PUSH_MS = 10000;

// Champs transmis à l'extension (`engine` sert à l'extension à construire le nom de clé TOTP)
const toExtensionEntry = (secret, engineName) => ({
  name: secret.name,
  username: secret.username,
  password: secret.password,
  url: secret.url,
  website: secret.website,
  notes: secret.notes,
  engine: engineName,
});

const ENTRY_FIELDS = ['name', 'username', 'password', 'url', 'website', 'notes', 'engine'];
const sameEntries = (a, b) => a.length === b.length
  && a.every((x, i) => ENTRY_FIELDS.every(f => x[f] === b[i][f]));

/**
 * Lecture partielle : les entrées dont la lecture a échoué gardent leur dernière version
 * connue (jamais de disparition silencieuse d'une entrée côté extension).
 */
function mergeWithPrevious(fresh, failedNames, previous) {
  if (!failedNames.size || !previous) return fresh;
  const freshNames = new Set(fresh.map(e => e.name));
  const kept = previous.entries.filter(e => failedNames.has(e.name) && !freshNames.has(e.name));
  return kept.length ? [...fresh, ...kept] : fresh;
}

/**
 * Synchronisation INCRÉMENTALE de l'extension (cache par coffre, lié à la session).
 *
 * Avant : chaque écriture relisait toutes les entrées de tous les coffres (10 800 requêtes
 * et un IPC de 1 Mo pour un seul mot de passe modifié sur 5 000 entrées). Désormais :
 * - connexion / coffre ajouté : lecture (priorité basse) des seuls coffres absents du cache ;
 * - relecture du tableau (fetchSecrets, après une écriture ou un changement de coffre) :
 *   le résultat est réutilisé tel quel pour CE coffre (aucune requête supplémentaire) ;
 * - après une écriture (appel sans argument) : les autres coffres sont seulement LISTÉS,
 *   un délai après la dernière écriture ; seules les clés nouvelles sont lues (migration,
 *   copie), les clés disparues sont retirées ;
 * - coffre supprimé : retiré du cache (dernier coffre : état vide publié) ; politique « RBI uniquement »
 *   réappliquée à chaque envoi ;
 * - coffres écrits hors des chemins suivis (import) : relus en entier sur demande (invalidate).
 * @param {Function} getLatest - () => valeurs du dernier rendu
 */
export function createExtensionSync(getLatest) {
  const fresh = (token) => ({
    token,
    byEngine: new Map(),  // nom du coffre → { entries, knownKeys, seq, at, fromTable }
    inFlight: new Map(),  // nom du coffre → AbortController de la lecture de fond en cours
    seq: 0,
    ready: false,         // première synchro terminée : avant, aucun envoi partiel
    reconcileTimer: null,
    publishQueued: false,
    reportedTruncated: 0, // troncature déjà signalée (plafond du processus principal) : pas de toast répété
  });
  let state = fresh(null);

  const reset = () => {
    clearTimeout(state.reconcileTimer);
    for (const ac of state.inFlight.values()) ac.abort();
    // SÉCURITÉ : mots de passe en cache libérés immédiatement (fin de session, démontage)
    state.byEngine.clear();
    state.inFlight.clear();
    state = fresh(null);
  };

  // SÉCURITÉ : cache propre à la session ; nouvelle session ou déconnexion → vidé, lectures abandonnées
  const session = () => {
    const { token } = getLatest();
    if (state.token !== token) {
      reset();
      state.token = token;
    }
    return state;
  };

  const current = (st, startToken) => !!startToken && st === state && st.token === startToken
    && getLatest().isSessionCurrent(startToken);

  /**
   * Réponse de sync-write-state : au-delà du plafond de défense en profondeur du processus principal
   * (CONFIG.MAX_SYNC_SECRETS), les entrées suivantes ne sont pas transmises à l'extension ({ truncated,
   * stored }). Signalé (toast traduit) une fois par valeur, et de nouveau si elle change.
   */
  const reportTruncation = (st, startToken, res) => {
    const truncated = Math.max(0, Math.floor(Number(res?.truncated) || 0));
    if (!truncated) { st.reportedTruncated = 0; return; }
    if (st.reportedTruncated === truncated || !current(st, startToken)) return;
    st.reportedTruncated = truncated;
    secureLogger.warn('[Sync] Entrées non transmises à l\'extension (plafond) :', truncated);
    const { showToast, t } = getLatest();
    if (typeof showToast === 'function' && typeof t === 'function') {
      showToast(t('error.extensionSyncTruncated', { count: truncated, max: Math.max(0, Math.floor(Number(res.stored) || 0)) }), 'warning', 8000);
    }
  };

  const publish = async (st, startToken) => {
    // SÉCURITÉ : déconnexion / expiration entre-temps → ne pas réécrire « connecté + mots de passe »
    if (!current(st, startToken)) {
      secureLogger.debug('[Sync] Session terminée : synchronisation abandonnée');
      return;
    }
    const { secretEngines, isRbiOnly, vaultUrl, authUser } = getLatest();
    const secrets = [];
    for (const engine of secretEngines || []) {
      const cached = st.byEngine.get(engine.name);
      if (!cached) continue;
      for (const entry of cached.entries) {
        // SÉCURITÉ : les secrets « RBI uniquement » ne sont jamais transmis (politique courante)
        if (!isRbiOnly(entry.name, engine)) secrets.push(entry);
      }
    }
    // Synchroniser avec l'extension (SÉCURITÉ: ne PAS inclure le token Vault)
    if (window.electronSync?.writeState) {
      const username = localStorage.getItem('vault-client.username') || authUser;
      const res = await window.electronSync.writeState({ vaultUrl, username, connected: true, secrets });
      reportTruncation(st, startToken, res);
      secureLogger.debug('[Sync] Extension synchronisée');
    }
  };

  // Envoi regroupé (micro-tâche) : plusieurs mises à jour dans le même tour → un seul envoi
  const publishSoon = () => {
    const st = session();
    const startToken = st.token;
    if (!st.ready || st.publishQueued || !startToken) return;
    st.publishQueued = true;
    Promise.resolve().then(async () => {
      st.publishQueued = false;
      try { await publish(st, startToken); } catch { secureLogger.error('[Sync] Erreur extension'); }
    });
  };

  const report = (failures) => {
    if (!failures) return;
    secureLogger.warn('[Sync] Éléments non synchronisés :', failures);
    const { showToast, t } = getLatest();
    if (typeof showToast === 'function' && typeof t === 'function') {
      showToast(t('error.extensionSyncPartial', { count: failures }), 'warning', 6000);
    }
  };

  /**
   * Lecture de fond d'un coffre : complète, ou des seules clés absentes de `known`.
   * @returns {Promise<{ failures: number, changed: boolean }>}
   */
  const readEngine = async (st, engine, startToken, known) => {
    const ac = new AbortController();
    st.inFlight.get(engine.name)?.abort();
    st.inFlight.set(engine.name, ac);
    const seqAtStart = st.seq;
    try {
      // PERFORMANCE : lecture par les listes gardées du tableau (useSecrets.readEnginesWithCache) quand elle
      // est fournie — chaque entrée n'est lue qu'une fois par session pour le tableau, la recherche et
      // l'extension (ensuite : nouvelles entrées et entrées écrites seulement, journal des écritures).
      const readEngines = getLatest().readEngines;
      const viaCache = typeof readEngines === 'function';
      const r = viaCache
        ? await readEngines([engine], { signal: ac.signal, priority: 'low' })
        : await readAllSecrets(getLatest().vaultApi, [engine], {
          signal: ac.signal,
          priority: 'low',
          mapSecret: (secret) => toExtensionEntry(secret, engine.name),
          keyFilter: known ? (e, keys) => keys.filter(k => !known.has(k)) : undefined,
        });
      if (r.aborted || ac.signal.aborted || !current(st, startToken)) return { failures: 0, changed: false };
      const previous = st.byEngine.get(engine.name);
      // Mise à jour plus récente arrivée pendant la lecture (relecture du tableau) : elle prime
      if (previous && previous.seq > seqAtStart) return { failures: 0, changed: false };
      // Listage impossible (réseau…) : dernière version connue conservée, échec signalé.
      // Listage PARTIEL (borne LIST_TOO_LARGE / LIST_TOO_DEEP, r.partialEngines) : la liste partielle est
      // utilisée, comme dans le tableau, et l'incomplétude est signalée (un échec compté).
      const partial = (r.partialEngines || []).some(p => p.engine === engine.name);
      if (r.failedEngines.length && !partial) return { failures: 1, changed: false };

      const listed = r.listedKeys[engine.name] || [];
      const failedNames = new Set(r.failedKeys.map(f => f.key));
      let entries;
      if (viaCache) {
        // Entrées complètes du coffre (gardées + relues) : celles en échec gardent leur dernière version
        entries = mergeWithPrevious(r.secrets.map(sec => toExtensionEntry(sec, engine.name)), failedNames, previous);
      } else if (known && previous) {
        const listedSet = new Set(listed);
        entries = [...previous.entries.filter(e => listedSet.has(e.name)), ...r.secrets];
      } else {
        entries = mergeWithPrevious(r.secrets, failedNames, previous);
      }
      const changed = !previous || !sameEntries(previous.entries, entries);
      st.byEngine.set(engine.name, {
        entries,
        // Clés en échec non mémorisées : elles seront relues à la prochaine vérification
        knownKeys: new Set(listed.filter(k => !failedNames.has(k))),
        seq: ++st.seq,
        at: Date.now(),
        fromTable: false,
      });
      return { failures: r.failedKeys.length + (partial ? 1 : 0), changed };
    } finally {
      if (st.inFlight.get(engine.name) === ac) st.inFlight.delete(engine.name);
    }
  };

  const sum = (results) => results.reduce((n, r) => n + r.failures, 0);

  /** Connexion, coffres ajoutés ou retirés : lit les coffres absents du cache puis publie. */
  const syncEngines = async () => {
    const st = session();
    const { token, secretEngines } = getLatest();
    if (!token || !secretEngines) return;
    if (secretEngines.length === 0) {
      // APP-9 : plus aucun coffre (dernier coffre supprimé). Avant : sortie immédiate, l'extension
      // continuait de servir les mots de passe du coffre supprimé jusqu'à la déconnexion. Cache vidé,
      // lectures abandonnées et, si l'extension a déjà reçu un état, état « connecté » vide publié.
      // Rien à la connexion (liste des coffres pas encore chargée : aucun état publié, cache vide).
      const published = st.ready || st.byEngine.size > 0;
      for (const ac of st.inFlight.values()) ac.abort();
      st.inFlight.clear();
      st.byEngine.clear();
      if (!published) return;
      st.ready = true;
      await publish(st, token);
      return;
    }
    const names = new Set(secretEngines.map(e => e.name));
    for (const name of Array.from(st.byEngine.keys())) if (!names.has(name)) st.byEngine.delete(name);
    for (const [name, ac] of Array.from(st.inFlight)) {
      if (!names.has(name)) { ac.abort(); st.inFlight.delete(name); }
    }
    const missing = secretEngines.filter(e => !st.byEngine.has(e.name) && !st.inFlight.has(e.name));
    const results = await Promise.all(missing.map(engine => readEngine(st, engine, token)));
    if (!current(st, token)) {
      secureLogger.debug('[Sync] Session terminée pendant la lecture : synchronisation abandonnée');
      return;
    }
    report(sum(results));
    if (!st.ready) {
      // Synchro initiale : un seul envoi, complet, quand la dernière lecture de fond est terminée
      if (st.inFlight.size > 0) return;
      st.ready = true;
    }
    // Coffres ajoutés ou retirés, URL ou utilisateur changés
    await publish(st, token);
  };

  /** Après une écriture : liste les autres coffres et ne lit que les clés nouvelles. */
  const reconcile = async (st) => {
    const { token, secretEngines } = getLatest();
    if (!current(st, token)) return;
    if (!st.ready) { requestReconcile(); return; } // synchro initiale en cours : plus tard
    const now = Date.now();
    const targets = (secretEngines || []).filter((engine) => {
      if (st.inFlight.has(engine.name)) return false;
      const cached = st.byEngine.get(engine.name);
      // Coffre que le tableau vient de relire (celui qui a été modifié) : déjà à jour
      return !(cached && cached.fromTable && now - cached.at < RECENT_PUSH_MS);
    });
    const results = await Promise.all(targets.map((engine) => {
      const cached = st.byEngine.get(engine.name);
      return readEngine(st, engine, token, cached ? cached.knownKeys : undefined);
    }));
    if (!current(st, token)) return;
    report(sum(results));
    if (results.some(r => r.changed)) await publish(st, token);
  };

  const requestReconcile = () => {
    const st = session();
    if (!st.token) return;
    clearTimeout(st.reconcileTimer);
    st.reconcileTimer = setTimeout(() => {
      st.reconcileTimer = null;
      reconcile(st).catch(() => secureLogger.error('[Sync] Erreur extension'));
    }, RECONCILE_DELAY_MS);
  };

  /** Relecture d'un coffre par le tableau : réutilisée telle quelle (aucune requête). */
  const push = ({ engine, secrets, failedKeys = [], listedKeys, api }) => {
    const st = session();
    const { token, vaultApi, isSessionCurrent } = getLatest();
    if (!token || !engine?.name || api !== vaultApi || !isSessionCurrent(token)) return;
    const previous = st.byEngine.get(engine.name);
    const failedNames = new Set(failedKeys);
    const entries = mergeWithPrevious(secrets.map(s => toExtensionEntry(s, engine.name)), failedNames, previous);
    st.byEngine.set(engine.name, {
      entries,
      knownKeys: new Set((Array.isArray(listedKeys) ? listedKeys : entries.map(e => e.name)).filter(k => !failedNames.has(k))),
      seq: ++st.seq,
      at: Date.now(),
      fromTable: true,
    });
    // Lecture de fond en cours pour ce coffre : inutile, la relecture du tableau est aussi récente
    const ac = st.inFlight.get(engine.name);
    if (ac) { ac.abort(); st.inFlight.delete(engine.name); }
    if (!previous || !sameEntries(previous.entries, entries)) publishSoon();
  };

  /**
   * APP-6 : coffres modifiés hors des chemins suivis (import des Paramètres, entrées existantes écrasées) :
   * relus EN ENTIER (la vérification après écriture ne lit que les clés nouvelles), puis publiés s'ils
   * ont changé. Lecture en échec : dernière version connue conservée (comme readEngine).
   * @param {string[]} engineNames
   */
  const invalidate = async (engineNames) => {
    const st = session();
    const { token, secretEngines } = getLatest();
    if (!token || !Array.isArray(engineNames) || engineNames.length === 0) return;
    const wanted = new Set(engineNames);
    const targets = (secretEngines || []).filter(e => wanted.has(e.name));
    if (!targets.length) return;
    const results = await Promise.all(targets.map(engine => readEngine(st, engine, token)));
    if (!current(st, token)) return;
    report(sum(results));
    if (!st.ready) {
      // Synchro initiale encore en cours : l'envoi complet a lieu à la fin de la dernière lecture
      if (st.inFlight.size > 0) return;
      st.ready = true;
      await publish(st, token);
      return;
    }
    if (results.some(r => r.changed)) await publish(st, token);
  };

  const dispose = () => reset();

  return { push, requestReconcile, syncEngines, invalidate, publishSoon, dispose };
}

/**
 * Hook useSync — gère la synchronisation avec l'extension Chrome,
 * les listeners IPC CLI (secrets, engines, list) et les requêtes TOTP IPC.
 *
 * NOTE : côté Electron, `sync-read-state` ne renvoie plus les secrets (seulement
 * vaultUrl/username/connected/timestamp/secretCount, et serverError) et `electronSync.getPath()`
 * renvoie toujours une erreur : ce hook n'utilise que `serverError` (serveur de synchronisation
 * non démarré, signalé une fois après la connexion). `writeState` peut renvoyer `truncated`
 * (plafond du processus principal) : signalé par un toast. `onResyncRequest` (fenêtre de nouveau
 * réactive après un gel) : état republié depuis le cache.
 *
 * `syncExtensionRef.current(update)` :
 * - `update = { engine, secrets, failedKeys, listedKeys, api }` (fetchSecrets) : coffre relu ;
 * - `update = { invalidate: [noms de coffres] }` (import des Paramètres) : coffres relus en entier ;
 * - sans argument (après une écriture) : vérification différée des autres coffres.
 *
 * @param {Object} [params.sessionTokenRef] - { current } jeton de la session en cours, mis à jour
 *   de façon SYNCHRONE par useAuth (connexion / déconnexion / expiration)
 * @param {Function} [params.isSecretRbiOnly] - (nomSecret, coffre) => true si le secret est
 *   « RBI uniquement » : il n'est alors ni envoyé à l'extension ni servi à la CLI
 * @param {Object} [params.readEnginesRef] - { current } lecture multi-coffres à listes gardées
 *   (useSecrets.readEnginesWithCache) : lectures de fond partagées avec le tableau ; absente, readAllSecrets
 */
export function useSync({
  vaultApi,
  token,
  vaultUrl,
  authUser,
  secretEngines,
  selectedEngine,
  syncExtensionRef,
  totpRateLimit,
  showToast,
  sessionTokenRef,
  isSecretRbiOnly,
  readEnginesRef
}) {
  const { baseHeaders, axiosConfig, readSecretV2, readSecretV1, listKeysV2, listKeysV1 } = vaultApi;
  const i18n = useOptionalTranslation();

  // Jeton du dernier rendu (repli si sessionTokenRef n'est pas fourni)
  const latestTokenRef = useRef(token);
  latestTokenRef.current = token;

  // SÉCURITÉ : une opération lancée avec `startToken` n'a d'effet que si la session
  // est toujours la même au moment d'écrire (ni déconnexion, ni expiration, ni
  // changement d'utilisateur entre-temps).
  const isSessionCurrent = (startToken) => {
    if (!startToken || latestTokenRef.current !== startToken) return false;
    return !sessionTokenRef || sessionTokenRef.current === startToken;
  };

  // SÉCURITÉ : secret « RBI uniquement » (coffre entier ou secret désigné par la policy)
  const isRbiOnly = (secretName, engine) => {
    if (typeof isSecretRbiOnly !== 'function' || !engine) return false;
    const raw = String(secretName ?? '');
    // Variantes de chemin acceptées par Vault (« /a//b/ » ≡ « a/b ») : vérifier aussi la forme normalisée
    const normalized = raw.replace(/\/{2,}/g, '/').replace(/^\/+|\/+$/g, '');
    return isSecretRbiOnly(raw, engine) || isSecretRbiOnly(normalized, engine);
  };

  // Valeurs du dernier rendu, lues par la synchro incrémentale (fonctions stables)
  const latestRef = useRef(null);
  latestRef.current = {
    vaultApi, token, vaultUrl, authUser, secretEngines, isRbiOnly, isSessionCurrent, showToast, t: i18n?.t,
    readEngines: readEnginesRef?.current,
  };
  const extensionSyncRef = useRef(null);
  if (!extensionSyncRef.current) extensionSyncRef.current = createExtensionSync(() => latestRef.current);
  const extensionSync = extensionSyncRef.current;

  // Point d'entrée appelé par les autres hooks (voir l'en-tête)
  useEffect(() => {
    syncExtensionRef.current = (update) => {
      if (update && Array.isArray(update.invalidate)) {
        extensionSync.invalidate(update.invalidate).catch(() => secureLogger.error('[Sync] Erreur extension'));
      } else if (update && update.engine && Array.isArray(update.secrets)) extensionSync.push(update);
      else extensionSync.requestReconcile();
    };
  });

  // Synchroniser au démarrage et quand les coffres changent (seuls les coffres absents du cache sont lus)
  useEffect(() => {
    extensionSync.syncEngines().catch(() => secureLogger.error('[Sync] Erreur extension'));
  }, [secretEngines, token, vaultUrl, authUser]); // eslint-disable-line

  // Politique « RBI uniquement » chargée ou modifiée : renvoi (filtré) sans relecture
  useEffect(() => {
    extensionSync.publishSoon();
  }, [isSecretRbiOnly]); // eslint-disable-line

  // Démontage : minuteries et lectures de fond abandonnées
  useEffect(() => () => extensionSync.dispose(), [extensionSync]);

  // Interface de nouveau réactive après un gel (processus principal, évènement 'responsive' de la fenêtre) :
  // l'état servi à l'extension a été purgé pendant le gel (SYNC-28) ; il est republié depuis le cache de
  // la session courante (aucune relecture du coffre ; rien si la session est terminée).
  useEffect(() => {
    if (!window.electronSync?.onResyncRequest) return undefined;
    return window.electronSync.onResyncRequest(() => extensionSync.publishSoon());
  }, [extensionSync]);

  // Serveur de synchronisation non démarré (port déjà pris : autre session Windows, autre programme ;
  // sync-read-state renvoie serverError) : l'extension ne recevra rien. Signalé une fois (toast traduit)
  // après la connexion, en plus de la boîte affichée par le processus principal au démarrage.
  const serverErrorShownRef = useRef(false);
  useEffect(() => {
    if (!token || serverErrorShownRef.current || !window.electronSync?.readState) return undefined;
    let cancelled = false;
    Promise.resolve()
      .then(() => window.electronSync.readState())
      .then((r) => {
        const code = r && typeof r.serverError === 'string' ? r.serverError : '';
        if (cancelled || !code || serverErrorShownRef.current) return;
        const { showToast: toast, t } = latestRef.current;
        if (typeof toast !== 'function' || typeof t !== 'function') return;
        serverErrorShownRef.current = true;
        secureLogger.warn('[Sync] Serveur de synchronisation indisponible');
        toast(t('error.syncServerUnavailable', { code: /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'ERROR' }), 'warning', 10000);
      })
      .catch(() => { /* état indisponible : rien à signaler */ });
    return () => { cancelled = true; };
  }, [token]);

  // Gestionnaire IPC pour les demandes de code TOTP de l'extension Chrome
  useEffect(() => {
    if (!window.electronSync?.onTotpRequest || !token) return;

    const handleTotpRequest = async (totpKeyName, requestId) => {
      secureLogger.debug('[TOTP IPC] Demande de code TOTP');

      if (!totpRateLimit.canCall()) {
        window.electronSync.sendTotpResponse({ success: false, error: 'Rate limit exceeded' }, requestId);
        return;
      }
      totpRateLimit.registerCall();

      try {
        // Récupérer le code TOTP depuis Vault
        const response = await axios.get(
          `${vaultUrl}/v1/TOTP/code/${encodeURIComponent(totpKeyName)}`,
          axiosConfig({ headers: baseHeaders() })
        );

        const code = response.data?.data?.code;

        if (code) {
          secureLogger.debug('[TOTP IPC] Code TOTP généré');
          window.electronSync.sendTotpResponse({ success: true, code }, requestId);
        } else {
          secureLogger.debug('[TOTP IPC] Pas de code dans la réponse');
          window.electronSync.sendTotpResponse({ success: false, error: 'No code in response' }, requestId);
        }
      } catch (err) {
        secureLogger.error('[TOTP IPC] Erreur génération code TOTP');
        window.electronSync.sendTotpResponse({
          success: false,
          error: sanitizeErrorMessage(err, 'TOTP generation failed')
        }, requestId);
      }
    };

    // Enregistrer le listener et récupérer la fonction de cleanup
    const removeListener = window.electronSync.onTotpRequest(handleTotpRequest);

    // Cleanup : supprimer le listener quand le composant se démonte ou que le token change
    return removeListener;
  }, [token]); // eslint-disable-line

  // Restaurer les règles CLI au montage (appel actif, pas d'écoute passive)
  // SÉCURITÉ : la session CLI (token) reste côté Electron ; elle n'est JAMAIS
  // copiée dans localStorage (accessible à tout script du renderer).
  useEffect(() => {
    if (!window.electronCLI) return;

    const restoreCLISettings = async () => {
      // Restaurer les règles d'auto-approbation via IPC
      try {
        const saved = JSON.parse(localStorage.getItem('rdvault-cli-auto-approve') || '{}');
        const rules = Object.entries(saved)
          .filter(([, enabled]) => enabled)
          .map(([engine]) => `${engine.replace(/\/+$/, '')}/*`);
        if (rules.length > 0 && window.electronCLI?.setAutoApproveRules) {
          window.electronCLI.setAutoApproveRules(rules);
        }
      } catch { /* ignore */ }

      // Restaurer les engines autorisés pour le listing via IPC
      try {
        const savedList = JSON.parse(localStorage.getItem('rdvault-cli-list-approve') || '{}');
        const allowedEngines = Object.entries(savedList)
          .filter(([, enabled]) => enabled)
          .map(([engine]) => engine.replace(/\/+$/, ''));
        if (allowedEngines.length > 0 && window.electronCLI?.setListSecretsEngines) {
          window.electronCLI.setListSecretsEngines(allowedEngines);
        }
      } catch { /* ignore */ }
    };

    restoreCLISettings();
  }, []);

  // Gestionnaire IPC pour les demandes de secrets provenant de la CLI mvault
  useEffect(() => {
    if (!window.electronCLI?.onSecretRequest || !token) return;

    const handleCLISecretRequest = async ({ engine: engineName, path: secretPath, requestId }) => {
      try {
        // Chercher l'engine par nom dans la liste des engines connus
        const engine = secretEngines.find(e =>
          e.name === engineName || e.name === engineName + '/' || e.name === '/' + engineName
        );

        if (!engine) {
          window.electronCLI.sendSecretResponse(
            { success: false, error: `Engine "${engineName}" introuvable` },
            requestId
          );
          return;
        }

        // SÉCURITÉ : un secret « RBI uniquement » ne s'utilise que dans une session
        // RBI ; la CLI (get --reveal, ssh, winrm) n'y a pas accès.
        if (isRbiOnly(secretPath, engine)) {
          window.electronCLI.sendSecretResponse(
            { success: false, error: 'Access denied (RBI-only)' },
            requestId
          );
          return;
        }

        const startToken = token;
        // Lire le secret via les fonctions Vault existantes
        const data = engine.version === 2
          ? await readSecretV2(engine, secretPath)
          : await readSecretV1(engine, secretPath);

        // SÉCURITÉ : session terminée pendant la lecture → ne rien transmettre
        if (!isSessionCurrent(startToken)) {
          window.electronCLI.sendSecretResponse({ success: false, error: 'Session expired' }, requestId);
          return;
        }

        window.electronCLI.sendSecretResponse(
          { success: true, data },
          requestId
        );
      } catch (err) {
        window.electronCLI.sendSecretResponse(
          { success: false, error: err.response?.status === 404 ? 'Secret introuvable' : (err.response?.status === 403 ? 'Access denied' : 'Error reading secret') },
          requestId
        );
      }
    };

    const removeListener = window.electronCLI.onSecretRequest(handleCLISecretRequest);

    // Écouter aussi les demandes de listage d'engines
    let removeEnginesListener;
    if (window.electronCLI.onEnginesRequest) {
      removeEnginesListener = window.electronCLI.onEnginesRequest(({ requestId }) => {
        const engines = secretEngines.map(e => ({
          name: e.name,
          version: e.version,
          type: e.type || 'kv'
        }));
        window.electronCLI.sendEnginesResponse(engines, requestId);
      });
    }

    return () => {
      removeListener();
      if (removeEnginesListener) removeEnginesListener();
    };
  }, [token, secretEngines]); // eslint-disable-line

  // Gestionnaire IPC pour les demandes de listage de secrets provenant de la CLI mvault
  useEffect(() => {
    if (!window.electronCLI?.onListSecretsRequest || !token) return;

    const handleListSecretsRequest = async ({ engine: engineName, path: folderPath, requestId }) => {
      try {
        const engine = secretEngines.find(e =>
          e.name === engineName || e.name === engineName + '/' || e.name === '/' + engineName
        );

        if (!engine) {
          window.electronCLI.sendListSecretsResponse([], requestId);
          return;
        }

        const keys = engine.version === 2
          ? await listKeysV2(engine, folderPath)
          : await listKeysV1(engine);

        window.electronCLI.sendListSecretsResponse(keys, requestId);
      } catch {
        window.electronCLI.sendListSecretsResponse([], requestId);
      }
    };

    const removeListener = window.electronCLI.onListSecretsRequest(handleListSecretsRequest);
    return removeListener;
  }, [token, secretEngines]); // eslint-disable-line
}
