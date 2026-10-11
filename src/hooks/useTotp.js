import { useState, useCallback, useRef } from 'react';
import axios from 'axios';
import { useRateLimit } from '../useRateLimit';
import { sanitizeErrorMessage } from '../utils/security';
import { createVaultApi } from '../services/vaultApi';
import { isolateInRtl } from '../components/admin/i18nHelpers';

// ========================================
// NOMMAGE DES CLÉS TOTP (convention historique, NE PAS MODIFIER)
// ========================================
// Clé TOTP d'une entrée = `${PRÉFIXE}-${nom de l'entrée}`, où PRÉFIXE = nom du coffre sans
// « users/<u>/ » ni « / » final, en majuscules. Les clés TOTP existantes du coffre de l'utilisateur,
// l'extension (content.js), le serveur local (secretsService.deleteEngine) et les policies Vault
// générées (« TOTP/keys/PRÉFIXE-* », PolicyBuilderModal) reposent sur ce format : le changer rendrait
// les TOTP existants introuvables. Il n'est pas injectif (« Banque » et « users/x/Banque » donnent la
// même clé) : avant de SUPPRIMER une clé, vérifier qu'elle n'est pas partagée (findEngineSharingTotpKey).

const DEFAULT_TOTP_PERIOD = 30;

// SECRETS-12 : « Supprimer le TOTP » détruit une graine non relisible (aucune version, aucune
// sauvegarde possible). Sans boîte de confirmation fournie par l'appelant ({ confirmed: true }),
// la suppression n'a lieu qu'à une SECONDE demande pour la même clé dans ce délai.
export const TOTP_DELETE_CONFIRM_MS = 10000;

/** Préfixe TOTP d'un coffre */
export function totpKeyPrefix(engineName) {
  return String(engineName || '')
    .replace(/^users\/[^/]+\//i, '')
    .replace(/\/$/, '')
    .toUpperCase();
}

/** Nom de la clé TOTP de l'entrée `secretName` du coffre `engineName` */
export function buildTotpKeyName(engineName, secretName) {
  return `${totpKeyPrefix(engineName)}-${secretName}`;
}

/**
 * Cherche un AUTRE coffre visible dont une entrée revendique EXACTEMENT la même clé TOTP. Même règle
 * que le serveur local (secretsService.deleteEngine, LOCALVAULT-2) : pour chaque autre coffre dont
 * `${préfixe}-` commence le nom de la clé, l'entrée « reste du nom » de ce coffre revendique la clé.
 * Couvre le même préfixe (« Banque » / « users/x/Banque ») ET l'ambiguïté du tiret (« Prod-EU » + « db »
 * et « Prod » + « EU-db » donnent tous deux PROD-EU-db). La clé ne doit alors pas être supprimée.
 * Un coffre non lisible (403) est ignoré : ses entrées ne sont pas celles de l'utilisateur, et le
 * coffre local refuse de toute façon l'accès à une clé TOTP d'un autre propriétaire.
 * @param {Object} vaultApi - Service createVaultApi (listEngines, secretStatus)
 * @param {{ name: string }} engine - Coffre de l'entrée
 * @param {string} secretName - Nom de l'entrée
 * @returns {Promise<string|null>} Nom du coffre qui partage la clé, ou null.
 *   Lève une erreur si l'inventaire des coffres est impossible (l'appelant conserve alors la clé).
 */
export async function findEngineSharingTotpKey(vaultApi, engine, secretName) {
  const clean = (n) => String(n || '').replace(/^\/+|\/+$/g, '');
  const keyName = buildTotpKeyName(engine.name, secretName);
  const engines = await vaultApi.listEngines();
  for (const other of engines) {
    if (clean(other.name) === clean(engine.name)) continue;
    const otherPrefix = `${totpKeyPrefix(other.name)}-`;
    if (otherPrefix === '-' || !keyName.startsWith(otherPrefix)) continue;
    const claimedEntry = keyName.slice(otherPrefix.length);
    if (!claimedEntry) continue;
    // Entrée présente (même supprimée : restaurable) ou impossible à vérifier → clé partagée
    const status = await vaultApi.secretStatus(other, claimedEntry);
    if (status !== 'absent' && status !== 'forbidden') return clean(other.name);
  }
  return null;
}

// Jeton de session porté par les en-têtes (X-Vault-Token) ; null s'il est absent ou illisible
function headerToken(baseHeaders) {
  if (typeof baseHeaders !== 'function') return null;
  try {
    const headers = baseHeaders();
    return (headers && headers['X-Vault-Token']) || null;
  } catch {
    return null;
  }
}

/**
 * Hook de gestion TOTP (Time-based One-Time Password).
 * Gere la configuration, l'affichage, la copie et la suppression des cles TOTP.
 *
 * @param {Object} options
 * @param {string} options.vaultUrl - URL du serveur Vault
 * @param {Function} options.baseHeaders - Fonction retournant les headers de base
 * @param {Function} options.axiosConfig - Fonction retournant la config axios
 * @param {Object|null} options.selectedEngine - Engine actuellement selectionne
 * @param {Function} options.startClipboardTimer - Fonction pour copier avec timer
 * @param {Function} options.showToast - Fonction pour afficher un toast
 * @param {Function} options.t - Fonction de traduction
 * @param {Function} options.restoreFocus - Fonction pour restaurer le focus
 * @param {Object} [options.vaultApi] - Service createVaultApi (ou ref { current }) : inventaire des coffres
 *   avant de supprimer une clé TOTP. Absent : service équivalent reconstruit depuis baseHeaders().
 * @param {{ current: string }} [options.sessionTokenRef] - Jeton de la session en cours, mis à jour de
 *   façon synchrone par useAuth ('' après la déconnexion). Facultatif : sans lui, la session est suivie
 *   par le jeton des en-têtes (baseHeaders), relu à chaque rendu.
 * @returns {Object} Etats et handlers TOTP
 */
export function useTotp({ vaultUrl, baseHeaders, axiosConfig, selectedEngine, startClipboardTimer, showToast, t, restoreFocus, vaultApi, sessionTokenRef }) {
  const totpEngineName = 'TOTP';

  const [totpDisplay, setTotpDisplay] = useState(null);
  const [totpConfig, setTotpConfig] = useState(null);

  const totpRateLimit = useRateLimit(10, 60000); // Max 10 generations TOTP par minute

  // Dernière traduction reçue : les callbacks mémoïsés traduisent toujours dans la langue courante
  const tRef = useRef(t);
  tRef.current = t;

  // ========================================
  // GARDE DE SESSION (APP-3)
  // ========================================
  // Une réponse arrivée après une déconnexion, une expiration ou une nouvelle connexion (éventuellement
  // d'un autre utilisateur) n'a plus aucun effet : ni code copié dans le presse-papiers, ni modale, ni
  // suppression, ni toast. Avant, « Copier le code TOTP » lancé juste avant la déconnexion copiait le code
  // de la session précédente à l'arrivée de la réponse. La session est identifiée par le jeton relevé
  // de façon synchrone par useAuth (sessionTokenRef, si fourni) ET par le jeton des en-têtes du dernier
  // rendu (change au rendu qui suit la déconnexion, sans dépendre de l'appelant).
  const headerTokenRef = useRef(null);
  headerTokenRef.current = headerToken(baseHeaders);
  const hasSessionRef = !!sessionTokenRef && typeof sessionTokenRef === 'object' && 'current' in sessionTokenRef;
  const sessionSnapshot = () => ({ auth: hasSessionRef ? sessionTokenRef.current : null, header: headerTokenRef.current });
  const sessionChanged = (start) => {
    if (hasSessionRef && sessionTokenRef.current !== start.auth) return true;
    return headerTokenRef.current !== start.header;
  };

  // BIDI : valeurs isolées dans les toasts en RTL (clé TOTP, nom de coffre : de gauche à droite ; nom
  // d'entrée, texte libre : dans son propre sens). Texte inchangé dans les langues LTR.
  const entryName = (name) => isolateInRtl(name, 'auto');
  const technical = (value) => isolateInRtl(value, 'ltr');

  // Demande de suppression TOTP en attente de confirmation : { key, engine, until }
  const pendingTotpDeleteRef = useRef(null);

  // Mémoïsé : passé en prop/dépendance d'effets (EditSecretModalWrapper, ModalOrchestrator…)
  const getTotpKeyName = useCallback((secretName) => {
    if (!selectedEngine) return secretName;
    return buildTotpKeyName(selectedEngine.name, secretName);
  }, [selectedEngine]);

  // Erreur TOTP relevée : message assaini et traduit, statut HTTP conservé (sans le corps de la
  // réponse du serveur) pour que les toasts affichent la cause (« Ressource introuvable »,
  // « Accès refusé »…) au lieu d'un « Une erreur est survenue » générique.
  const totpError = useCallback((err) => {
    const wrapped = new Error(sanitizeErrorMessage(err, undefined, tRef.current));
    const status = err?.response?.status;
    if (status) wrapped.response = { status };
    if (typeof err?.code === 'string') wrapped.code = err.code; // ECONNREFUSED, ECONNABORTED…
    return wrapped;
  }, []);

  const getTotpCode = useCallback(async (keyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/${totpEngineName}/code/${encodeURIComponent(keyName)}`, axiosConfig({ headers: baseHeaders() }));
      return res.data?.data?.code || null;
    } catch (err) {
      throw totpError(err);
    }
  }, [vaultUrl, axiosConfig, baseHeaders, totpError]);

  const configureTotpKey = async (keyName, config) => {
    try {
      await axios.post(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(keyName)}`, config, axiosConfig({ headers: baseHeaders() }));
    } catch (err) {
      throw totpError(err);
    }
  };

  // Service d'inventaire des coffres : celui fourni par l'appelant, sinon un service équivalent
  // (même URL, même jeton, même espace de noms) reconstruit depuis les en-têtes de la session.
  const resolveVaultApi = () => {
    const provided = vaultApi && typeof vaultApi === 'object' && 'current' in vaultApi ? vaultApi.current : vaultApi;
    if (provided && typeof provided.listEngines === 'function') return provided;
    const headers = (typeof baseHeaders === 'function' && baseHeaders()) || {};
    return createVaultApi(vaultUrl, headers['X-Vault-Token'], headers['X-Vault-Namespace']);
  };

  // Message d'erreur TOTP traduit (statut HTTP pris en compte)
  const errorText = (err) => sanitizeErrorMessage(err, undefined, t);

  // Mémoïsé : utilisé dans les deps d'un useEffect (EditSecretModalWrapper)
  const checkTotpExists = useCallback(async (keyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(keyName)}`, axiosConfig({ headers: baseHeaders() }));
      return res.status === 200;
    } catch (err) {
      // 404 = pas de clé TOTP ; toute autre erreur est traitée comme "inexistant"
      return false;
    }
  }, [vaultUrl, axiosConfig, baseHeaders]);

  // Période (s) de la clé, lue dans sa configuration (mode local comme Vault renvoient `period`).
  // Configuration illisible (policy « code » seule, erreur) → 30 s, valeur par défaut des clés.
  const getTotpPeriod = useCallback(async (keyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(keyName)}`, axiosConfig({ headers: baseHeaders() }));
      const period = Number(res.data?.data?.period);
      return Number.isFinite(period) && period > 0 ? period : DEFAULT_TOTP_PERIOD;
    } catch {
      return DEFAULT_TOTP_PERIOD;
    }
  }, [vaultUrl, axiosConfig, baseHeaders]);

  const handleShowTotp = async (secret) => {
    if (!totpRateLimit.canCall()) { showToast(t('error.totpRateLimit'), 'error'); return; }
    totpRateLimit.registerCall();
    const session = sessionSnapshot();
    try {
      const totpKeyName = getTotpKeyName(secret.name);
      // La modale calcule compte à rebours et rafraîchissement sur la période RÉELLE de la clé
      const [code, period] = await Promise.all([getTotpCode(totpKeyName), getTotpPeriod(totpKeyName)]);
      if (sessionChanged(session)) return; // code d'une session terminée : jamais affiché
      setTotpDisplay({ secretName: secret.name, totpKeyName, code, period });
    } catch (err) {
      if (sessionChanged(session)) return;
      showToast(`${t('error.totpCode')} ${errorText(err)}`, 'error');
    }
  };

  const handleCopyTotp = async (secret) => {
    if (!totpRateLimit.canCall()) { showToast(t('error.totpRateLimit'), 'error'); return; }
    totpRateLimit.registerCall();
    const session = sessionSnapshot();
    try {
      const totpKeyName = getTotpKeyName(secret.name);
      const code = await getTotpCode(totpKeyName);
      // Réponse arrivée après la fin de la session : le code n'est JAMAIS copié dans le presse-papiers
      if (sessionChanged(session)) return;
      // Libellé du minuteur traduit (I18N-32 : « Code TOTP » codé en dur → « Code TOTP copied »)
      await startClipboardTimer(t('totp.title'), code);
    } catch (err) {
      if (sessionChanged(session)) return;
      showToast(`${t('error.totpCode')} ${errorText(err)}`, 'error');
    }
  };

  const handleConfigureTotp = async (secret) => {
    const session = sessionSnapshot();
    const totpKeyName = getTotpKeyName(secret.name);
    const exists = await checkTotpExists(totpKeyName);
    // Session terminée pendant la vérification : la fiche (qui contient tout le secret) n'est pas ouverte
    if (sessionChanged(session)) return;

    if (exists) {
      showToast(t('error.totpAlreadyExists', { name: entryName(secret.name) }), 'error', 2500);
      return;
    }

    const engineName = selectedEngine?.name ? totpKeyPrefix(selectedEngine.name) : '';

    setTotpConfig({
      ...secret,
      totpKeyName,
      engineName
    });
  };

  /**
   * « Supprimer le TOTP » (SECRETS-12). La graine n'est pas relisible : sa destruction est définitive.
   * - Sans `confirmed`, le premier appel ne supprime rien : il demande confirmation (toast) et seul un
   *   second appel pour la même clé, dans TOTP_DELETE_CONFIRM_MS, la supprime. Une boîte de
   *   confirmation de l'appelant passe `{ confirmed: true }`.
   * - Jamais si une entrée d'un autre coffre revendique la même clé (nommage non injectif), ni si
   *   l'inventaire des coffres est impossible (dans le doute, la graine est conservée).
   * @returns {Promise<boolean>} true si la clé a été supprimée
   */
  const handleDeleteTotp = async (secret, { confirmed = false } = {}) => {
    if (!secret?.name) return false;
    const totpKeyName = getTotpKeyName(secret.name);
    const engineName = selectedEngine?.name || '';
    const pending = pendingTotpDeleteRef.current;
    const alreadyAsked = !!pending && pending.key === totpKeyName && pending.engine === engineName && Date.now() <= pending.until;
    if (!confirmed && !alreadyAsked) {
      pendingTotpDeleteRef.current = { key: totpKeyName, engine: engineName, until: Date.now() + TOTP_DELETE_CONFIRM_MS };
      showToast(t('toast.totpDeleteConfirm', {
        name: entryName(secret.name),
        action: t('contextMenu.deleteTotp'),
        seconds: Math.round(TOTP_DELETE_CONFIRM_MS / 1000),
      }), 'warning', TOTP_DELETE_CONFIRM_MS);
      return false;
    }
    pendingTotpDeleteRef.current = null;
    const session = sessionSnapshot();

    // Clé revendiquée ailleurs (ou inventaire impossible) : conservée
    if (selectedEngine) {
      let sharedWith = null;
      try {
        sharedWith = await findEngineSharingTotpKey(resolveVaultApi(), selectedEngine, secret.name);
      } catch {
        if (sessionChanged(session)) return false;
        showToast(t('error.totpDeleteUnverified'), 'warning', 6000);
        return false;
      }
      // Session terminée pendant l'inventaire : rien n'est supprimé (la graine est conservée)
      if (sessionChanged(session)) return false;
      if (sharedWith) {
        showToast(t('error.totpDeleteShared', { engine: technical(sharedWith) }), 'warning', 6000);
        return false;
      }
    }

    try {
      await axios.delete(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(totpKeyName)}`, axiosConfig({ headers: baseHeaders() }));
      if (!sessionChanged(session)) showToast(t('toast.totpDeleted', { name: entryName(secret.name) }), 'success');
      return true;
    } catch (err) {
      if (!sessionChanged(session)) showToast(`${t('error.totpDelete')} ${errorText(err)}`, 'error');
      return false;
    }
  };

  const handleSaveTotpConfig = async (config) => {
    const session = sessionSnapshot();
    try {
      if (!totpConfig) return;
      await configureTotpKey(totpConfig.totpKeyName, config);
      if (sessionChanged(session)) return; // modale déjà fermée par la fin de session : aucun toast
      setTotpConfig(null);
      restoreFocus();
      showToast(t('toast.totpConfigured', { name: technical(totpConfig.totpKeyName) }), 'success');
    } catch (err) {
      if (!sessionChanged(session)) showToast(`${t('error.totpConfig')} ${errorText(err)}`, 'error');
      throw err;
    }
  };

  return {
    totpDisplay, setTotpDisplay,
    totpConfig, setTotpConfig,
    totpRateLimit,
    totpEngineName,
    getTotpKeyName,
    getTotpCode,
    configureTotpKey,
    checkTotpExists,
    handleShowTotp,
    handleCopyTotp,
    handleConfigureTotp,
    handleDeleteTotp,
    handleSaveTotpConfig
  };
}
