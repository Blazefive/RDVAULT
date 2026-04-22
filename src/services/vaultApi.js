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

const MAX_LIST_DEPTH = 20;
const MAX_LIST_KEYS = 5000;

export function createVaultApi(vaultUrl, token, vaultNs) {
  const baseHeaders = (overrideToken) => {
    const h = { 'X-Vault-Request': 'true' };
    const t = overrideToken || token;
    if (t) h['X-Vault-Token'] = t;
    if (vaultNs && vaultNs.trim()) h['X-Vault-Namespace'] = vaultNs.trim();
    return h;
  };

  const axiosConfig = (config = {}) => {
    return { ...config };
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

  const parseFromUiMounts = (payload) => {
    const data = payload?.data ?? payload ?? {};
    let items = [];

    if (Array.isArray(data.secrets)) items = data.secrets;
    else if (Array.isArray(data.secret)) items = data.secret;
    else if (data.mounts && typeof data.mounts === 'object') {
      items = Object.entries(data.mounts).map(([path, cfg]) => ({ path, ...(cfg || {}) }));
    } else if (typeof data === 'object' && Object.keys(data).every(k => typeof data[k] === 'object')) {
      items = Object.entries(data).map(([path, cfg]) => ({ path, ...(cfg || {}) }));
    }

    return (items || [])
      .filter(it => {
        if (!it) return false;
        const raw = (it.path || it.mount_path || it.name || '');
        const name = String(raw).replace(/\/$/, '').toLowerCase();
        if (name === 'totp' || name === 'pki' || name === 'tags-shared') return false;
        return it.type === 'kv' || it.options?.version || /\/$/.test(raw);
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
  const fetchEnginesRaw = async (userToken) => {
    const [uiFilterRes, uiRes, sysRes] = await Promise.allSettled([
      axios.get(`${vaultUrl}/v1/sys/internal/ui/mounts?filter=secrets`, axiosConfig({ headers: baseHeaders(userToken) })),
      axios.get(`${vaultUrl}/v1/sys/internal/ui/mounts`, axiosConfig({ headers: baseHeaders(userToken) })),
      axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders(userToken) })),
    ]);

    const errors = {
      uiError: uiRes.status === 'rejected' ? (uiRes.reason?.response?.data?.errors?.[0] || uiRes.reason?.message || 'ui/mounts échoué') : '',
      sysError: sysRes.status === 'rejected' ? (sysRes.reason?.response?.data?.errors?.[0] || sysRes.reason?.message || 'sys/mounts échoué') : '',
    };

    const fromUiFilter = uiFilterRes.status === 'fulfilled' ? parseFromUiMounts(uiFilterRes.value.data) : [];
    const fromUi = uiRes.status === 'fulfilled' ? parseFromUiMounts(uiRes.value.data) : [];
    const fromSys = sysRes.status === 'fulfilled' ? parseFromSysMounts(sysRes.value.data) : [];

    const map = new Map();
    for (const e of [...fromUiFilter, ...fromUi, ...fromSys]) {
      if (!e?.name) continue;
      if (!map.has(e.name)) map.set(e.name, e);
    }
    const merged = Array.from(map.values());

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
  const listKeysV2 = async (engine, path = '', depth = 0) => {
    if (depth > MAX_LIST_DEPTH) return [];

    const url = path
      ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${path.split('/').map(s => encodeURIComponent(s)).join('/')}?list=true`
      : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata?list=true`;

    const list = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
    const keys = list.data?.data?.keys || [];

    const allKeys = [];

    for (const key of keys) {
      if (allKeys.length >= MAX_LIST_KEYS) break;
      if (key.endsWith('/')) {
        const fullPath = path ? `${path}${key}` : key;
        try {
          const subKeys = await listKeysV2(engine, fullPath, depth + 1);
          allKeys.push(...subKeys);
        } catch (err) {
          secureLogger.warn('[Vault] Erreur listing dossier');
        }
      } else {
        const fullKey = path ? `${path}${key}` : key;
        allKeys.push(fullKey);
      }
    }

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
    const secretValidation = validation.validateSecret(entry);
    if (!secretValidation.valid) {
      const errorMessages = Object.values(secretValidation.errors).join(', ');
      throw new Error(`Validation échouée: ${errorMessages}`);
    }

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
    const secretValidation = validation.validateSecret(entry);
    if (!secretValidation.valid) {
      const errorMessages = Object.values(secretValidation.errors).join(', ');
      throw new Error(`Validation échouée: ${errorMessages}`);
    }

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
  // MIGRATION OPERATIONS
  // ========================================
  const readSecretForMigration = async (engine, secretName) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      if (engine.version === 2) {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/data/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
        );
        return res.data?.data?.data || null;
      } else {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
        );
        return res.data?.data || null;
      }
    } catch (err) {
      secureLogger.error('[Lecture] Erreur');
      return null;
    }
  };

  const writeSecretToEngine = async (engine, secretName, data) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      // SÉCURITÉ: Sanitiser les caractères de contrôle dangereux avant écriture
      if (data && typeof data === 'object') {
        for (const key of Object.keys(data)) {
          if (typeof data[key] === 'string' && /[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(data[key])) {
            data[key] = data[key].replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
          }
        }
      }

      if (engine.version === 2) {
        await axios.post(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/data/${encodeURIComponent(cleanKey)}`,
          { data },
          { headers: baseHeaders() }
        );
      } else {
        await axios.post(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          data,
          { headers: baseHeaders() }
        );
      }
      return true;
    } catch (err) {
      secureLogger.error('[Écriture] Erreur');
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
          { headers: baseHeaders() }
        );
      } else {
        await axios.delete(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
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
