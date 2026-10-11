// ========================================
// SERVICE: Vault API
// ========================================
// Encapsule tous les appels HTTP vers HashiCorp Vault.
// Extrait de App.jsx pour modularisation.
//
// Usage:
//   const vaultApi = createVaultApi(vaultUrl, token, vaultNs);
//   const secret = await vaultApi.readSecretV2(engine, key);

import axios from 'axios';
import { encodeEnginePath } from '../utils/security';
import * as validation from '../validation';
import secureLogger from '../secureLogger';

// Bornes du listage récursif d'un coffre KV v2 (protection contre un serveur ou une arborescence
// démesurés). Elles ne tronquent plus en silence : au-delà, une erreur traduite est levée (code
// LIST_TOO_LARGE / LIST_TOO_DEEP, clé i18n posée sur l'erreur) que l'appelant signale. L'ancienne
// borne de 5 000 entrées masquait sans avertissement les entrées suivantes.
export const MAX_LIST_DEPTH = 20;
export const MAX_LIST_KEYS = 20000;

// Clés SSH (entrées de type « ssh ») : EditSecretModal range la clé privée (PEM/OpenSSH, toujours
// multi-lignes) dans `password` et la clé publique dans `url`. Ces deux champs ne peuvent donc pas
// passer par validatePassword (aucun saut de ligne admis) ni par isValidUrl.
const SSH_KEY_MAX_LENGTH = 16384; // une clé RSA 8192 bits au format OpenSSH fait ~6,7 Ko

/** Vrai si la chaîne contient un caractère de contrôle autre que tabulation, LF ou CR (NUL, ESC, DEL…) */
function hasForbiddenControlChars(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c <= 0x1F && c !== 0x09 && c !== 0x0A && c !== 0x0D) || c === 0x7F) return true;
  }
  return false;
}

/**
 * Valide une entrée avant écriture. Entrée SSH : clé privée et clé publique validées comme des clés
 * (longueur bornée, retours à la ligne admis, autres contrôles refusés) ; tous les autres champs
 * (nom, passphrase, notes…) passent par validateSecret comme pour une entrée classique.
 * Chaque échec porte un code traduisible (`codes`, clés `validation.*` des locales) en plus du
 * texte français historique (`errors`, conservé pour les journaux).
 * @param {Object} entry
 * @returns {{ valid: boolean, errors: Object, codes: Object }}
 */
function validateEntry(entry) {
  if (!entry || entry.entryType !== 'ssh') {
    const result = validation.validateSecret(entry);
    return { valid: result.valid, errors: result.errors, codes: result.codes || {} };
  }

  const base = validation.validateSecret({ ...entry, password: '', url: '' });
  const allErrors = { ...base.errors };
  const codes = { ...(base.codes || {}) };
  // [champ, libellé historique, préfixe du code de traduction]
  const keyFields = [['password', 'La clé privée', 'privateKey'], ['url', 'La clé publique', 'publicKey']];
  for (const [field, label, prefix] of keyFields) {
    const value = entry[field];
    if (value === undefined || value === null || value === '') continue;
    if (typeof value !== 'string') {
      allErrors[field] = `${label} est invalide`;
      codes[field] = { code: `${prefix}Invalid` };
    } else if (value.length > SSH_KEY_MAX_LENGTH) {
      allErrors[field] = `${label} est trop longue (max ${SSH_KEY_MAX_LENGTH} caractères)`;
      codes[field] = { code: `${prefix}TooLong`, params: { max: SSH_KEY_MAX_LENGTH } };
    } else if (hasForbiddenControlChars(value)) {
      allErrors[field] = `${label} contient des caractères de contrôle`;
      codes[field] = { code: `${prefix}ControlChars` };
    }
  }
  return { valid: Object.keys(allErrors).length === 0, errors: allErrors, codes };
}

/**
 * Erreur d'une entrée refusée avant écriture. Le message français historique (« Validation échouée: … »)
 * reste pour les journaux ; l'interface affiche le message traduit du premier code via
 * sanitizeError / sanitizeErrorMessage (utils/security.js).
 */
function validationError(result) {
  const err = new Error(`Validation échouée: ${Object.values(result.errors).join(', ')}`);
  err.code = 'VALIDATION';
  err.validationErrors = Object.keys(result.errors).map((field) => {
    const c = result.codes ? result.codes[field] : null;
    if (!c) return { field };
    return c.params ? { field, code: c.code, params: c.params } : { field, code: c.code };
  });
  return err;
}

/** Erreur de listage au-delà des bornes (jamais de troncature silencieuse) */
function listLimitError(code, i18nKey, max, partialKeys) {
  const err = new Error(code === 'LIST_TOO_LARGE'
    ? `Listage interrompu : plus de ${max} entrées`
    : `Listage interrompu : plus de ${max} niveaux de dossiers`);
  err.code = code;
  err.i18nKey = i18nKey;
  err.i18nVars = { max };
  // Clés déjà listées, pour un appelant qui voudrait afficher une liste partielle EN LE SIGNALANT
  err.partialKeys = partialKeys;
  return err;
}

export function createVaultApi(vaultUrl, token, vaultNs) {
  const baseHeaders = (overrideToken) => {
    const h = { 'X-Vault-Request': 'true' };
    const t = overrideToken || token;
    if (t) h['X-Vault-Token'] = t;
    if (vaultNs && vaultNs.trim()) h['X-Vault-Namespace'] = vaultNs.trim();
    return h;
  };

  // SÉCURITÉ / ROBUSTESSE : timeout par défaut de 30 s sur tous les appels Vault
  // (évite les requêtes qui restent bloquées indéfiniment). Peut être surchargé
  // par l'appelant via config.timeout.
  const axiosConfig = (config = {}) => {
    return { timeout: 30000, ...config };
  };

  // ========================================
  // DÉTECTION VERSION KV
  // ========================================
  const detectKvVersion = async (name, tkn) => {
    const clean = name.replace(/^\/+|\/+$/g, '');
    try {
      const r2 = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}/metadata?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
      if ([200, 403].includes(r2.status)) return 2;
    } catch {}
    try {
      const r1 = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
      if ([200, 403].includes(r1.status)) return 1;
    } catch {}
    return 2;
  };

  // ========================================
  // VÉRIFICATION D'ACCÈS
  // ========================================
  const canAccessEngine = async ({ name, version }, tkn) => {
    const clean = name.replace(/^\/+|\/+$/g, '');
    let canList = false;
    let accessible = false;
    let canWrite = false;

    try {
      if (version === 2) {
        const r = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}/metadata?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
        accessible = true;
        canList = r.status === 200;
      } else {
        const r = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
        accessible = true;
        canList = r.status === 200;
      }
    } catch (err) {
      if (err.response?.status === 403) {
        return { accessible: false, canList: false, canWrite: false };
      }
      if (err.response?.status === 404) {
        accessible = true;
        canList = true;
      } else {
        return { accessible: false, canList: false, canWrite: false };
      }
    }

    try {
      const path = version === 2 ? `${clean}/data/*` : `${clean}/*`;
      const capRes = await axios.post(
        `${vaultUrl}/v1/sys/capabilities-self`,
        { paths: [path] },
        axiosConfig({ headers: baseHeaders(tkn) })
      );
      const caps = capRes.data?.data?.[path] || capRes.data?.[path] || [];
      canWrite = caps.includes('create') || caps.includes('update');
    } catch (err) {
      canWrite = false;
    }

    return { accessible, canList, canWrite };
  };

  // ========================================
  // PARSING DES ENGINES
  // ========================================
  const parseFromSysMounts = (obj) =>
    Object.entries(obj || {})
      .filter(([mountPath, cfg]) => {
        const name = mountPath.replace(/\/$/, '').toLowerCase();
        return cfg && cfg.type === 'kv' && name !== 'totp' && name !== 'pki' && name !== 'tags-shared';
      })
      .map(([mountPath, cfg]) => ({
        name: mountPath.replace(/\/$/, ''),
        version: Number(cfg?.options?.version) === 2 ? 2 : 1,
        source: 'sys'
      }));

  // REMOTE-1 : format RÉEL de Vault pour GET /v1/sys/internal/ui/mounts (route non authentifiée,
  // filtrée selon les droits du jeton) : { data: { auth: {…}, secret: { 'kv/': { type, options } } } }.
  // C'est la seule découverte possible pour un utilisateur sans droit sur sys/mounts. Le coffre local
  // répond, lui, au format « plat » { 'kv/': { type, options } }.
  const parseFromUiMounts = (payload) => {
    const data = payload?.data ?? payload ?? {};
    let items = [];

    const fromMap = (map) => Object.entries(map).map(([path, cfg]) => ({ path, ...(cfg && typeof cfg === 'object' ? cfg : {}) }));
    if (Array.isArray(data.secrets)) items = data.secrets;
    else if (Array.isArray(data.secret)) items = data.secret;
    else if (data.secret && typeof data.secret === 'object') items = fromMap(data.secret);
    else if (data.mounts && typeof data.mounts === 'object') items = fromMap(data.mounts);
    else if (data && typeof data === 'object' && Object.keys(data).every(k => data[k] && typeof data[k] === 'object')) {
      items = fromMap(data);
    }

    return (items || [])
      .filter(it => {
        if (!it) return false;
        const raw = (it.path || it.mount_path || it.name || '');
        const name = String(raw).replace(/\/$/, '').toLowerCase();
        if (name === 'totp' || name === 'pki' || name === 'tags-shared') return false;
        // Type connu : seuls les montages KV (« generic » = ancien nom du KV v1). Les montages
        // cubbyhole/, identity/, sys/… ne sont plus pris pour des coffres KV v1 (barre finale).
        if (typeof it.type === 'string' && it.type) return it.type === 'kv' || it.type === 'generic';
        return !!it.options?.version;
      })
      .map(it => {
        const raw = (it.path || it.mount_path || it.name || '');
        const name = String(raw).replace(/\/$/, '');
        const version = Number(it.options?.version) === 2 ? 2 : 1;
        return name ? { name, version, source: 'ui' } : null;
      })
      .filter(Boolean);
  };

  // ========================================
  // DÉCOUVERTE DES ENGINES (HTTP/parsing uniquement)
  // ========================================
  // Inventaire brut des coffres KV (sans test d'accès) : union des trois listings de montages
  const listEngineCandidates = async (userToken) => {
    const [uiFilterRes, uiRes, sysRes] = await Promise.allSettled([
      axios.get(`${vaultUrl}/v1/sys/internal/ui/mounts?filter=secrets`, axiosConfig({ headers: baseHeaders(userToken) })),
      axios.get(`${vaultUrl}/v1/sys/internal/ui/mounts`, axiosConfig({ headers: baseHeaders(userToken) })),
      axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders(userToken) })),
    ]);

    const errors = {
      uiError: uiRes.status === 'rejected' ? (uiRes.reason?.response?.data?.errors?.[0] || uiRes.reason?.message || 'ui/mounts échoué') : '',
      sysError: sysRes.status === 'rejected' ? (sysRes.reason?.response?.data?.errors?.[0] || sysRes.reason?.message || 'sys/mounts échoué') : '',
    };
    const allFailed = [uiFilterRes, uiRes, sysRes].every(r => r.status === 'rejected');

    const fromUiFilter = uiFilterRes.status === 'fulfilled' ? parseFromUiMounts(uiFilterRes.value.data) : [];
    const fromUi = uiRes.status === 'fulfilled' ? parseFromUiMounts(uiRes.value.data) : [];
    const fromSys = sysRes.status === 'fulfilled' ? parseFromSysMounts(sysRes.value.data) : [];

    const map = new Map();
    for (const e of [...fromUiFilter, ...fromUi, ...fromSys]) {
      if (!e?.name) continue;
      if (!map.has(e.name)) map.set(e.name, e);
    }
    return { merged: Array.from(map.values()), errors, allFailed };
  };

  /**
   * Liste légère des coffres KV visibles ({ name, version }), sans test d'accès par coffre.
   * Lève une erreur si aucun listing n'a répondu (inventaire impossible : à l'appelant d'être prudent).
   */
  const listEngines = async (userToken) => {
    const { merged, allFailed } = await listEngineCandidates(userToken);
    if (allFailed) throw new Error('Inventaire des coffres impossible');
    return merged;
  };

  const fetchEnginesRaw = async (userToken) => {
    const { merged, errors } = await listEngineCandidates(userToken);

    const prepared = [];
    for (const e of merged) {
      const version = e.version || await detectKvVersion(e.name, userToken);
      const access = await canAccessEngine({ name: e.name, version }, userToken);
      if (access.accessible) {
        prepared.push({
          name: e.name,
          version,
          source: e.source || 'auto',
          canList: access.canList,
          canWrite: access.canWrite
        });
      }
    }

    prepared.sort((a, b) => a.name.localeCompare(b.name));
    return { engines: prepared, errors };
  };

  // ========================================
  // KV v2 OPERATIONS
  // ========================================
  // Listage récursif : `acc` reçoit toutes les clés du coffre (borne globale MAX_LIST_KEYS)
  const listFolderV2 = async (engine, path, depth, acc) => {
    if (depth > MAX_LIST_DEPTH) {
      throw listLimitError('LIST_TOO_DEEP', 'error.listTooDeep', MAX_LIST_DEPTH, acc.slice());
    }

    const url = path
      ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${path.split('/').map(s => encodeURIComponent(s)).join('/')}?list=true`
      : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata?list=true`;

    const list = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
    const keys = list.data?.data?.keys || [];

    for (const key of keys) {
      if (key.endsWith('/')) {
        const fullPath = path ? `${path}${key}` : key;
        try {
          await listFolderV2(engine, fullPath, depth + 1, acc);
        } catch (err) {
          const status = err?.response?.status;
          // Sous-dossier non listable par une policy par dossier (403) ou disparu entre deux
          // listages (404) : ignoré, comme avant. Toute autre erreur (réseau, délai, 5xx, bornes)
          // remonte : l'appelant la signale et relance, au lieu d'entrées disparues sans message.
          if (status !== 403 && status !== 404) throw err;
          secureLogger.debug('[listKeysV2] Sous-dossier ignoré (HTTP ' + status + ')');
        }
      } else {
        if (acc.length >= MAX_LIST_KEYS) {
          secureLogger.warn('[listKeysV2] Borne de listage dépassée');
          throw listLimitError('LIST_TOO_LARGE', 'error.listTooLarge', MAX_LIST_KEYS, acc.slice());
        }
        acc.push(path ? `${path}${key}` : key);
      }
    }
    return acc;
  };

  const listKeysV2 = async (engine, path = '', depth = 0) => {
    const allKeys = await listFolderV2(engine, path, depth, []);
    secureLogger.debug('[listKeysV2]', allKeys.length, 'keys');
    return allKeys;
  };

  const readSecretV2 = async (engine, key) => {
    const res = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
    const data = res.data?.data?.data || {};

    const customFields = data.CustomFields || [];
    const portField = customFields.find(f => f.key === 'Port' || f.key === 'port');

    return {
      name: key,
      username: data.Username || '',
      password: data.Password || '',
      url: data.URL || '',
      website: data.Website || '',
      notes: data.Notes || '',
      tags: data.Tags || '',
      Port: portField ? portField.value : '',
      customFields: customFields,
      attachments: data.Attachments || [],
      entryType: data.EntryType || 'secret'
    };
  };

  const writeSecretV2 = async (engine, entry) => {
    const secretValidation = validateEntry(entry);
    if (!secretValidation.valid) throw validationError(secretValidation);

    const data = {
      Username: entry.username,
      Password: entry.password,
      URL: entry.url,
      Website: entry.website,
      Notes: entry.notes,
      Tags: entry.tags || '',
      EntryType: entry.entryType || 'secret'
    };

    let customFields = entry.customFields || [];

    if (entry.Port) {
      customFields = customFields.filter(f => f.key !== 'Port' && f.key !== 'port');
      customFields.push({ key: 'Port', value: entry.Port });
    }

    if (customFields.length > 0) {
      data.CustomFields = customFields;
    }

    if (entry.attachments && entry.attachments.length > 0) {
      data.Attachments = entry.attachments;
    }

    await axios.post(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(entry.name)}`, { data }, axiosConfig({ headers: baseHeaders() }));
  };

  const deleteSecretV2 = async (engine, key) => {
    const metaRes = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
    const versions = Object.keys(metaRes.data?.data?.versions || {}).map(Number);

    if (versions.length > 0) {
      await axios.post(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/delete/${encodeURIComponent(key)}`, { versions }, axiosConfig({ headers: baseHeaders() }));
    }
  };

  // ========================================
  // KV v1 OPERATIONS
  // ========================================
  const listKeysV1 = async (engine) => {
    const list = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}?list=true`, axiosConfig({ headers: baseHeaders() }));
    return (list.data?.data?.keys || []).filter(k => !k.endsWith('/'));
  };

  const readSecretV1 = async (engine, key) => {
    const res = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
    const data = res.data?.data || {};

    const customFields = data.CustomFields || [];
    const portField = customFields.find(f => f.key === 'Port' || f.key === 'port');

    return {
      name: key,
      username: data.Username || '',
      password: data.Password || '',
      url: data.URL || '',
      website: data.Website || '',
      notes: data.Notes || '',
      tags: data.Tags || '',
      Port: portField ? portField.value : '',
      customFields: customFields,
      attachments: data.Attachments || [],
      entryType: data.EntryType || 'secret'
    };
  };

  const writeSecretV1 = async (engine, entry) => {
    const secretValidation = validateEntry(entry);
    if (!secretValidation.valid) throw validationError(secretValidation);

    const data = {
      Username: entry.username,
      Password: entry.password,
      URL: entry.url,
      Website: entry.website,
      Notes: entry.notes,
      Tags: entry.tags || '',
      EntryType: entry.entryType || 'secret'
    };

    let customFields = entry.customFields || [];

    if (entry.Port) {
      customFields = customFields.filter(f => f.key !== 'Port' && f.key !== 'port');
      customFields.push({ key: 'Port', value: entry.Port });
    }

    if (customFields.length > 0) {
      data.CustomFields = customFields;
    }

    if (entry.attachments && entry.attachments.length > 0) {
      data.Attachments = entry.attachments;
    }

    await axios.post(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(entry.name)}`, data, axiosConfig({ headers: baseHeaders() }));
  };

  const deleteSecretV1 = async (engine, key) => {
    await axios.delete(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
  };

  // ========================================
  // EXISTENCE (avant renommage, suppression d'une clé TOTP partagée…)
  // ========================================
  /**
   * État d'une entrée, sans lire son contenu (KV v2 : métadonnées) :
   * 'live' (version courante lisible), 'deleted' (connue mais supprimée/détruite), 'absent' (404),
   * 'forbidden' (403 : coffre non lisible par l'utilisateur), 'unknown' (autre erreur).
   */
  const secretStatus = async (engine, key) => {
    const enginePath = encodeEnginePath(engine.name);
    const cfg = () => axiosConfig({ headers: baseHeaders() });
    const statusOf = (err) => {
      const s = err?.response?.status;
      return s === 404 ? 'absent' : s === 403 ? 'forbidden' : 'unknown';
    };
    if (engine.version === 1) {
      try {
        await axios.get(`${vaultUrl}/v1/${enginePath}/${encodeURIComponent(key)}`, cfg());
        return 'live';
      } catch (err) { return statusOf(err); }
    }
    try {
      const res = await axios.get(`${vaultUrl}/v1/${enginePath}/metadata/${encodeURIComponent(key)}`, cfg());
      const meta = res.data?.data || {};
      const current = meta.versions?.[meta.current_version];
      return current && !current.deletion_time && !current.destroyed ? 'live' : 'deleted';
    } catch (err) {
      if (err?.response?.status !== 403) return statusOf(err);
      // Policy sans lecture des métadonnées : repli sur la lecture de la donnée
      try {
        await axios.get(`${vaultUrl}/v1/${enginePath}/data/${encodeURIComponent(key)}`, cfg());
        return 'live';
      } catch (err2) { return statusOf(err2); }
    }
  };

  /** Vrai si la clé TOTP existe et est lisible (même contrôle que useTotp.checkTotpExists) */
  const totpKeyExists = async (keyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/TOTP/keys/${encodeURIComponent(keyName)}`, axiosConfig({ headers: baseHeaders() }));
      return res.status === 200;
    } catch {
      return false;
    }
  };

  // ========================================
  // MIGRATION OPERATIONS
  // ========================================
  // REMOTE-8 : même délai de 30 s que tous les autres appels Vault (axiosConfig) : une requête sans
  // réponse ne bloque plus indéfiniment un déplacement ou une migration.
  const readSecretForMigration = async (engine, secretName) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      if (engine.version === 2) {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/data/${encodeURIComponent(cleanKey)}`,
          axiosConfig({ headers: baseHeaders() })
        );
        return res.data?.data?.data || null;
      } else {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          axiosConfig({ headers: baseHeaders() })
        );
        return res.data?.data || null;
      }
    } catch (err) {
      secureLogger.error('[Lecture] Erreur');
      return null;
    }
  };

  /**
   * Écriture brute (migration, déplacement, import). Renvoie true si l'écriture a eu lieu, false sinon.
   * options.cas (KV v2 uniquement, entier ≥ 0) : check-and-set de Vault, transmis dans `options` ; l'écriture
   * n'a lieu que si la version courante de l'entrée vaut cas, 0 = l'entrée ne doit pas exister (SECRETS-36 :
   * deux clients qui créent la même entrée n'écrasent pas l'écriture de l'autre). Version différente :
   * Vault et le coffre local répondent 400 (« check-and-set parameter did not match the current version »)
   * et rien n'est écrit → false. Valeur de cas invalide : false, sans requête (jamais d'écriture sans le
   * contrôle demandé). KV v1 : aucun contrôle de version n'existe, l'option est ignorée.
   */
  const writeSecretToEngine = async (engine, secretName, data, options = {}) => {
    const cas = options && options.cas !== undefined ? options.cas : undefined;
    if (cas !== undefined && engine.version === 2 && !(Number.isSafeInteger(cas) && cas >= 0)) {
      secureLogger.error('[Écriture] Paramètre check-and-set invalide');
      return false;
    }
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      // SÉCURITÉ: Sanitiser les caractères de contrôle dangereux avant écriture
      if (data && typeof data === 'object') {
        for (const key of Object.keys(data)) {
          // eslint-disable-next-line no-control-regex -- volontaire : détection des caractères de contrôle (hors \t, \n, \r)
          if (typeof data[key] === 'string' && /[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(data[key])) {
            // eslint-disable-next-line no-control-regex -- volontaire : retrait de ces caractères avant écriture
            data[key] = data[key].replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
          }
        }
      }

      if (engine.version === 2) {
        await axios.post(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/data/${encodeURIComponent(cleanKey)}`,
          cas !== undefined ? { options: { cas }, data } : { data },
          axiosConfig({ headers: baseHeaders() })
        );
      } else {
        await axios.post(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          data,
          axiosConfig({ headers: baseHeaders() })
        );
      }
      return true;
    } catch (err) {
      const reason = err?.response?.data?.errors?.[0];
      secureLogger.error(cas !== undefined && typeof reason === 'string' && /check-and-set/i.test(reason)
        ? '[Écriture] Refusée : version concurrente (check-and-set)'
        : '[Écriture] Erreur');
      return false;
    }
  };

  const deleteSecretFromEngine = async (engine, secretName) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      if (engine.version === 2) {
        await axios.delete(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/metadata/${encodeURIComponent(cleanKey)}`,
          axiosConfig({ headers: baseHeaders() })
        );
      } else {
        await axios.delete(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          axiosConfig({ headers: baseHeaders() })
        );
      }
      return true;
    } catch (err) {
      secureLogger.error('[Suppression] Erreur');
      return false;
    }
  };

  return {
    baseHeaders,
    axiosConfig,
    detectKvVersion,
    canAccessEngine,
    parseFromSysMounts,
    parseFromUiMounts,
    fetchEnginesRaw,
    listEngines,
    secretStatus,
    totpKeyExists,
    listKeysV2,
    readSecretV2,
    writeSecretV2,
    deleteSecretV2,
    listKeysV1,
    readSecretV1,
    writeSecretV1,
    deleteSecretV1,
    readSecretForMigration,
    writeSecretToEngine,
    deleteSecretFromEngine,
  };
}
