// ========================================
// OUTIL DE TEST : faux serveur Vault en mémoire (remplace axios dans Jest)
// ========================================
// Reproduit le comportement du coffre local (electron/localVault) pour les routes utilisées par
// les hooks : KV v2 (data, metadata, delete, undelete, listage par dossier), TOTP (keys, code),
// sys/mounts et tags-shared. Les segments d'URL sont décodés une fois, comme le dispatcher local.
// Aucun appel réseau : chaque test branche axios.get/post/delete sur vault.axios.*.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';

const httpError = (status) => {
  const e = new Error(`HTTP ${status}`);
  e.response = { status, data: { errors: [`status ${status}`] } };
  return Promise.reject(e);
};
const ok = (data, status = 200) => Promise.resolve({ status, data });

export function createFakeVault() {
  const engines = new Map(); // nom -> { name, version, secrets: Map<clé, [{ data, deletion_time, destroyed }]> }
  const totp = new Map();    // nom -> { period, digits, algorithm, key }
  const calls = [];
  // Échecs injectés : (method, chemin décodé) => code HTTP ou null
  let failWhen = null;

  const addEngine = (name, version = 2) => {
    const e = { name, version, secrets: new Map() };
    engines.set(name, e);
    return { name, version, canWrite: true, canList: true };
  };
  const writeRaw = (engineName, key, data) => {
    const e = engines.get(engineName);
    const versions = e.secrets.get(key) || [];
    versions.push({ data: JSON.parse(JSON.stringify(data)), deletion_time: '', destroyed: false });
    e.secrets.set(key, versions);
    return versions.length;
  };
  const versionsOf = (engineName, key) => engines.get(engineName)?.secrets.get(key) || null;
  // Dernière version (supprimée ou non) : { version, data, deletion_time }
  const latest = (engineName, key) => {
    const v = versionsOf(engineName, key);
    if (!v || !v.length) return null;
    return { version: v.length, ...v[v.length - 1] };
  };
  const isLive = (engineName, key) => {
    const l = latest(engineName, key);
    return !!l && !l.deletion_time && !l.destroyed;
  };
  const addTotp = (name, opts = {}) => totp.set(name, { period: 30, digits: 6, algorithm: 'SHA1', key: 'JBSWY3DPEHPK3PXP', ...opts });

  const listFolder = (e, prefix) => {
    const folder = prefix ? prefix.replace(/\/+$/, '') + '/' : '';
    const out = new Set();
    for (const key of e.secrets.keys()) {
      if (folder && !key.startsWith(folder)) continue;
      const rel = key.slice(folder.length);
      if (!rel) continue;
      const i = rel.indexOf('/');
      out.add(i === -1 ? rel : rel.slice(0, i + 1));
    }
    return Array.from(out).sort();
  };

  const handle = (method, url, body) => {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    calls.push({ method, path: parts.join('/'), query: u.search, body });
    if (failWhen) {
      const code = failWhen(method, parts.join('/'), body);
      if (code) return httpError(code);
    }
    if (parts[0] !== 'v1') return httpError(404);
    const p = parts.slice(1);

    if (p[0] === 'sys') {
      if (method === 'get' && p[1] === 'mounts' && p.length === 2) {
        const out = {};
        for (const e of engines.values()) out[`${e.name}/`] = { type: 'kv', options: { version: String(e.version) } };
        return ok(out);
      }
      if (method === 'post' && p[1] === 'capabilities-self') return ok({ data: {} });
      return httpError(404);
    }

    if (p[0] === 'TOTP') {
      const name = p[2];
      if (p[1] === 'keys' && name) {
        if (method === 'get') return totp.has(name) ? ok({ data: { name, ...totp.get(name), key: undefined } }) : httpError(404);
        if (method === 'post') { addTotp(name, { period: body?.period || 30 }); return ok({}, 204); }
        if (method === 'delete') { totp.delete(name); return ok({}, 204); }
      }
      if (p[1] === 'code' && name && method === 'get') {
        return totp.has(name) ? ok({ data: { code: '123456' } }) : httpError(404);
      }
      return httpError(404);
    }

    // KV : coffre le plus long qui préfixe le chemin
    const full = p.join('/');
    const engine = Array.from(engines.values())
      .sort((a, b) => b.name.length - a.name.length)
      .find(e => full === e.name || full.startsWith(e.name + '/'));
    if (!engine) return httpError(404);
    const rest = full.slice(engine.name.length + 1).split('/');
    const op = rest[0];
    const key = rest.slice(1).join('/');

    if (op === 'metadata') {
      if (method === 'get' && u.searchParams.get('list') === 'true') {
        const keys = listFolder(engine, key);
        return keys.length ? ok({ data: { keys } }) : httpError(404);
      }
      const v = engine.secrets.get(key);
      if (method === 'get') {
        if (!v) return httpError(404);
        const versions = {};
        v.forEach((x, i) => { versions[i + 1] = { deletion_time: x.deletion_time, destroyed: x.destroyed }; });
        return ok({ data: { current_version: v.length, versions } });
      }
      if (method === 'delete') { engine.secrets.delete(key); return ok({}, 204); }
    }
    if (op === 'data') {
      if (method === 'get') {
        const ver = Number(u.searchParams.get('version')) || null;
        const v = engine.secrets.get(key);
        if (!v) return httpError(404);
        const x = ver ? v[ver - 1] : v[v.length - 1];
        if (!x || x.deletion_time || x.destroyed) return httpError(404);
        return ok({ data: { data: JSON.parse(JSON.stringify(x.data)), metadata: { version: ver || v.length } } });
      }
      if (method === 'post') {
        const version = writeRaw(engine.name, key, body?.data ?? body);
        return ok({ data: { version } });
      }
    }
    if (op === 'delete' && method === 'post') {
      const v = engine.secrets.get(key) || [];
      for (const n of body?.versions || []) if (v[n - 1]) v[n - 1].deletion_time = '2026-01-01T00:00:00Z';
      return ok({}, 204);
    }
    if (op === 'undelete' && method === 'post') {
      const v = engine.secrets.get(key) || [];
      for (const n of body?.versions || []) if (v[n - 1]) v[n - 1].deletion_time = '';
      return ok({}, 204);
    }
    return httpError(404);
  };

  return {
    VAULT_URL: 'http://127.0.0.1:8200',
    engines, totp, calls,
    addEngine, writeRaw, versionsOf, latest, isLive, addTotp,
    setFailWhen: (fn) => { failWhen = fn; },
    axios: {
      get: (url) => handle('get', url),
      post: (url, body) => handle('post', url, body),
      put: (url, body) => handle('post', url, body),
      delete: (url) => handle('delete', url),
    },
  };
}

// Rend un hook réel dans un composant React 18 (sans Testing Library) et expose sa valeur courante
export function renderHook(useHook) {
  const result = { current: null };
  function Harness() { result.current = useHook(); return null; }
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { root.render(React.createElement(Harness)); });
  return {
    result,
    rerender: () => act(() => { root.render(React.createElement(Harness)); }),
    unmount: () => act(() => { root.unmount(); }),
  };
}

// Traduction factice : renvoie la clé (+ variables) pour vérifier les toasts
export const fakeT = (k, v) => (v ? `${k} ${JSON.stringify(v)}` : k);
