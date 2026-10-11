// ========================================
// TESTS : useSync — synchronisation INCRÉMENTALE de l'extension (PERF-6)
// ========================================
// Avant : chaque écriture (enregistrer, supprimer, restaurer, déplacer…) relisait TOUTES les
// entrées de TOUS les coffres (10 800 requêtes et un IPC de 1 Mo pour un mot de passe modifié
// sur un coffre de 5 000 entrées). Désormais : la relecture du tableau (fetchSecrets) est
// réutilisée pour le coffre modifié ; les autres coffres sont seulement listés (clés nouvelles
// lues, clés disparues retirées) ; cohérence conservée (suppression, renommage, déplacement,
// coffre supprimé, politique « RBI uniquement », fin de session).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider } from '../i18n';
import { useSync, RECONCILE_DELAY_MS } from './useSync';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

// Rend le hook dans l'I18nProvider réel (messages d'avertissement traduits, comme dans App)
const roots = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function renderHook(useHook) {
  const result = { current: null };
  function Harness() { result.current = useHook(); return null; }
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  roots.push(root);
  const paint = () => act(() => { mountInRoot(root, <I18nProvider defaultLang="en"><Harness /></I18nProvider>); });
  paint();
  return { result, rerender: paint };
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const flush = async (n = 30) => { for (let i = 0; i < n; i++) await act(async () => { await Promise.resolve(); }); };
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });

// Coffres en mémoire ; lectures comptées par coffre
function fakeVaultApi(data) {
  const reads = {};
  const lists = {};
  const control = { failRead: () => false, listGate: null };
  const list = async (engine) => {
    lists[engine.name] = (lists[engine.name] || 0) + 1;
    if (control.listGate && control.listGate.engine === engine.name) await control.listGate.promise;
    if (!data[engine.name]) throw Object.assign(new Error('404'), { response: { status: 404 } });
    return Object.keys(data[engine.name]);
  };
  const read = async (engine, key) => {
    reads[engine.name] = (reads[engine.name] || 0) + 1;
    await Promise.resolve();
    if (control.failRead(engine, key)) throw networkError();
    const v = data[engine.name]?.[key];
    if (!v) throw Object.assign(new Error('404'), { response: { status: 404 } });
    return { name: key, username: v.username || 'u', password: v.password, url: v.url || '', website: '', notes: '', tags: '' };
  };
  return {
    reads, lists, control,
    api: { listKeysV2: list, listKeysV1: list, readSecretV2: read, readSecretV1: read, baseHeaders: () => ({}), axiosConfig: (c) => c },
  };
}

let writes;
beforeEach(() => {
  writes = [];
  window.electronSync = { writeState: jest.fn(async (s) => { writes.push(JSON.parse(JSON.stringify(s))); return { success: true }; }) };
});
afterEach(() => {
  roots.splice(0).forEach(root => act(() => root.unmount()));
  delete window.electronSync;
  document.body.innerHTML = '';
});

function mountSync(vault, engines, { isSecretRbiOnly, token = 'tok-1' } = {}) {
  const props = { token, secretEngines: engines, isSecretRbiOnly: isSecretRbiOnly || (() => false), vaultApi: vault.api };
  const sessionTokenRef = { current: token };
  const syncExtensionRef = { current: null };
  const toasts = [];
  const view = renderHook(() => useSync({
    vaultApi: props.vaultApi, token: props.token, vaultUrl: 'http://v', authUser: 'alice',
    secretEngines: props.secretEngines, selectedEngine: props.secretEngines[0],
    syncExtensionRef, totpRateLimit: { canCall: () => true, registerCall: () => {} },
    showToast: (m, k) => toasts.push([k, m]), sessionTokenRef, isSecretRbiOnly: props.isSecretRbiOnly,
  }));
  const update = (patch) => {
    Object.assign(props, patch);
    if ('token' in patch) sessionTokenRef.current = patch.token;
    view.rerender();
  };
  return { ...view, props, update, syncExtensionRef, toasts };
}

const lastConnected = () => [...writes].reverse().find(w => w.connected);
const names = (w) => w.secrets.map(s => `${s.engine}/${s.name}`).sort();
const many = (prefix, n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`${prefix}${i}`, { password: `${prefix}-pw-${i}` }]));

// Ce que fait fetchSecrets (useSecrets) après une écriture dans le coffre `engine`
function tableRefresh(ctx, vault, data, engine) {
  const keys = Object.keys(data[engine.name]);
  const secrets = keys.map(k => ({ name: k, username: 'u', password: data[engine.name][k].password, url: '', website: '', notes: '', deleted: false }));
  ctx.syncExtensionRef.current({ engine, secrets, failedKeys: [], listedKeys: keys, api: vault.api });
}

describe('PERF-6 : synchronisation incrémentale', () => {
  test('connexion : une lecture de chaque coffre et un seul envoi complet', async () => {
    const data = { A: many('a', 40), B: many('b', 5), C: many('c', 5) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B', 'C'].map(name => ({ name, version: 2 }));
    mountSync(vault, engines);
    await flush();
    expect(vault.reads).toEqual({ A: 40, B: 5, C: 5 });
    expect(writes.filter(w => w.connected)).toHaveLength(1);
    expect(lastConnected().secrets).toHaveLength(50);
  });

  test('modification d\'une entrée du coffre A : aucune lecture dans les autres coffres', async () => {
    const data = { A: many('a', 40), B: many('b', 30), C: many('c', 30) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B', 'C'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    const readsBefore = { ...vault.reads };

    // handleEditSecretSave : écriture, fetchSecrets(A) (relecture transmise), puis appel sans argument
    data.A.a3 = { password: 'MODIFIE' };
    await act(async () => { tableRefresh(ctx, vault, data, engines[0]); ctx.syncExtensionRef.current(); });
    await flush();
    await act(async () => { await sleep(RECONCILE_DELAY_MS + 100); });
    await flush();

    expect(vault.reads.B).toBe(readsBefore.B); // avant : 30 lectures de plus (toutes les entrées)
    expect(vault.reads.C).toBe(readsBefore.C);
    expect(vault.reads.A).toBe(readsBefore.A); // A : relecture du tableau réutilisée
    const sent = lastConnected().secrets.find(s => s.name === 'a3');
    expect(sent.password).toBe('MODIFIE');
    expect(lastConnected().secrets).toHaveLength(100);
  });

  test('suppression, renommage : l\'état envoyé suit la relecture du coffre', async () => {
    const data = { A: many('a', 5), B: many('b', 2) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    delete data.A.a1;                                   // suppression
    data.A.renomme = data.A.a2; delete data.A.a2;       // renommage
    await act(async () => { tableRefresh(ctx, vault, data, engines[0]); });
    await flush();
    expect(names(lastConnected())).toEqual(['A/a0', 'A/a3', 'A/a4', 'A/renomme', 'B/b0', 'B/b1']);
  });

  test('déplacement vers un autre coffre : seule la clé nouvelle du coffre cible est lue', async () => {
    const data = { A: many('a', 5), B: many('b', 20) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    const readsB = vault.reads.B;
    // useMigration : écriture dans B, suppression dans A, fetchSecrets(A), appel sans argument
    data.B.a4 = data.A.a4; delete data.A.a4;
    await act(async () => { tableRefresh(ctx, vault, data, engines[0]); ctx.syncExtensionRef.current(); });
    await act(async () => { await sleep(RECONCILE_DELAY_MS + 100); });
    await flush();
    expect(vault.reads.B - readsB).toBe(1);
    expect(names(lastConnected())).toContain('B/a4');
    expect(names(lastConnected())).not.toContain('A/a4');
  });

  test('écritures en rafale : une seule vérification des autres coffres', async () => {
    const data = { A: many('a', 3), B: many('b', 3) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    const listsB = vault.lists.B;
    await act(async () => { for (let i = 0; i < 5; i++) ctx.syncExtensionRef.current(); });
    await act(async () => { await sleep(RECONCILE_DELAY_MS + 100); });
    await flush();
    expect(vault.lists.B - listsB).toBe(1);
  });

  test('coffre supprimé : ses entrées ne sont plus envoyées (sans relecture des autres)', async () => {
    const data = { A: many('a', 3), B: many('b', 3) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    const reads = { ...vault.reads };
    ctx.update({ secretEngines: [engines[0]] });
    await flush();
    expect(names(lastConnected())).toEqual(['A/a0', 'A/a1', 'A/a2']);
    expect(vault.reads).toEqual(reads);
  });

  test('relecture partielle du tableau : une entrée illisible garde sa dernière version (pas de disparition)', async () => {
    const data = { A: many('a', 4) };
    const vault = fakeVaultApi(data);
    const engines = [{ name: 'A', version: 2 }];
    const ctx = mountSync(vault, engines);
    await flush();
    const keys = Object.keys(data.A);
    const secrets = keys.filter(k => k !== 'a2').map(k => ({ name: k, username: 'u', password: data.A[k].password, deleted: false }));
    await act(async () => { ctx.syncExtensionRef.current({ engine: engines[0], secrets, failedKeys: ['a2'], listedKeys: keys, api: vault.api }); });
    await flush();
    expect(names(lastConnected())).toEqual(['A/a0', 'A/a1', 'A/a2', 'A/a3']);
  });

  test('lecture de fond en échec : signalée (toast) et entrées connues conservées', async () => {
    const data = { A: many('a', 3), B: many('b', 3) };
    const vault = fakeVaultApi(data);
    vault.control.failRead = (engine, key) => key === 'b1';
    const engines = ['A', 'B'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await act(async () => { await sleep(1500); }); // relances (200 ms puis 600 ms)
    await flush();
    expect(ctx.toasts.some(([kind]) => kind === 'warning')).toBe(true);
    expect(names(lastConnected())).not.toContain('B/b1');
    // La clé en échec sera relue à la prochaine vérification
    vault.control.failRead = () => false;
    await act(async () => { ctx.syncExtensionRef.current(); await sleep(RECONCILE_DELAY_MS + 100); });
    await flush();
    expect(names(lastConnected())).toContain('B/b1');
  });
});

// Vague F : signaux du processus principal jusque-là ignorés par le renderer
describe('Vague F : troncature, serveur indisponible, republication, liste partielle', () => {
  test('writeState signale une troncature (plafond du processus principal) : toast traduit, une seule fois par valeur', async () => {
    window.electronSync.writeState = jest.fn(async (s) => {
      writes.push(JSON.parse(JSON.stringify(s)));
      return { success: true, stored: 3, truncated: 2 };
    });
    const data = { A: many('a', 5) };
    const vault = fakeVaultApi(data);
    const engines = [{ name: 'A', version: 2 }];
    const ctx = mountSync(vault, engines);
    await flush();
    const warnings = () => ctx.toasts.filter(([k, m]) => k === 'warning' && m.includes('beyond the limit'));
    expect(warnings()).toHaveLength(1); // avant : aucun signal (truncated ignoré)
    expect(warnings()[0][1]).toBe('Browser extension sync incomplete: 2 entry(ies) beyond the limit of 3 were not sent to the extension.');
    // Nouvel envoi, même troncature : pas de nouveau toast
    data.A.a1 = { password: 'MODIFIE' };
    await act(async () => { tableRefresh(ctx, vault, data, engines[0]); });
    await flush();
    expect(writes.filter(w => w.connected).length).toBeGreaterThan(1);
    expect(warnings()).toHaveLength(1);
  });

  test('serveur de synchronisation non démarré (serverError) : toast traduit après la connexion, une seule fois', async () => {
    window.electronSync.readState = jest.fn(async () => ({ success: true, data: null, serverError: 'EADDRINUSE' }));
    const vault = fakeVaultApi({ A: many('a', 2) });
    const engines = [{ name: 'A', version: 2 }];
    const ctx = mountSync(vault, engines);
    await flush();
    const shown = () => ctx.toasts.filter(([k, m]) => k === 'warning' && m.includes('EADDRINUSE'));
    expect(shown()).toHaveLength(1); // avant : aucun signal dans l'interface
    expect(shown()[0][1]).toMatch(/^The link with the browser extension could not be opened \(EADDRINUSE\)/);
    // Déconnexion puis nouvelle connexion : pas de répétition
    ctx.update({ token: '' });
    await flush();
    ctx.update({ token: 'tok-2' });
    await flush();
    expect(shown()).toHaveLength(1);
  });

  test('serveur démarré (serverError null) : aucun toast', async () => {
    window.electronSync.readState = jest.fn(async () => ({ success: true, data: null, serverError: null }));
    const vault = fakeVaultApi({ A: many('a', 2) });
    const ctx = mountSync(vault, [{ name: 'A', version: 2 }]);
    await flush();
    expect(window.electronSync.readState).toHaveBeenCalled();
    expect(ctx.toasts).toHaveLength(0);
  });

  test('fenêtre de nouveau réactive (onResyncRequest) : état republié depuis le cache, sans relecture ; rien après la déconnexion', async () => {
    let resync = null;
    window.electronSync.onResyncRequest = jest.fn((cb) => { resync = cb; return () => { resync = null; }; });
    const data = { A: many('a', 4), B: many('b', 2) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'B'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    const reads = { ...vault.reads };
    const before = writes.filter(w => w.connected).length;
    expect(typeof resync).toBe('function');
    await act(async () => { resync(); });
    await flush();
    const connected = writes.filter(w => w.connected);
    expect(connected.length).toBe(before + 1);
    expect(names(connected[connected.length - 1])).toEqual(['A/a0', 'A/a1', 'A/a2', 'A/a3', 'B/b0', 'B/b1']);
    expect(vault.reads).toEqual(reads);
    // Session terminée : aucune republication
    ctx.update({ token: '' });
    await flush();
    const count = writes.filter(w => w.connected).length;
    if (resync) await act(async () => { resync(); });
    await flush();
    expect(writes.filter(w => w.connected).length).toBe(count);
  });

  test('coffre listé partiellement (LIST_TOO_LARGE) : entrées déjà listées transmises, incomplétude signalée', async () => {
    const data = { A: many('a', 2), BIG: many('big', 5) };
    const vault = fakeVaultApi(data);
    const list = vault.api.listKeysV2;
    vault.api.listKeysV2 = async (engine) => {
      if (engine.name !== 'BIG') return list(engine);
      throw Object.assign(new Error('Listage interrompu'), {
        code: 'LIST_TOO_LARGE', i18nKey: 'error.listTooLarge', i18nVars: { max: 3 }, partialKeys: ['big0', 'big1', 'big2'],
      });
    };
    vault.api.listKeysV1 = vault.api.listKeysV2;
    const engines = ['A', 'BIG'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines);
    await flush();
    // Avant : aucune entrée de BIG transmise à l'extension
    expect(names(lastConnected())).toEqual(['A/a0', 'A/a1', 'BIG/big0', 'BIG/big1', 'BIG/big2']);
    expect(ctx.toasts.some(([k, m]) => k === 'warning' && m.startsWith('Browser extension sync incomplete'))).toBe(true);
  });
});

describe('Sécurité conservée', () => {
  test('secrets « RBI uniquement » jamais envoyés ; politique modifiée → renvoi filtré sans relecture', async () => {
    const data = { A: many('a', 3), SECURE: many('s', 2) };
    const vault = fakeVaultApi(data);
    const engines = ['A', 'SECURE'].map(name => ({ name, version: 2 }));
    const ctx = mountSync(vault, engines, { isSecretRbiOnly: (n, e) => e.name === 'SECURE' });
    await flush();
    expect(names(lastConnected())).toEqual(['A/a0', 'A/a1', 'A/a2']);
    const reads = { ...vault.reads };
    ctx.update({ isSecretRbiOnly: (n, e) => e.name === 'SECURE' || n === 'a1' });
    await flush();
    expect(names(lastConnected())).toEqual(['A/a0', 'A/a2']);
    expect(vault.reads).toEqual(reads);
  });

  test('fin de session pendant la lecture : aucun état « connecté » écrit ensuite', async () => {
    const data = { A: many('a', 3) };
    const vault = fakeVaultApi(data);
    let release;
    vault.control.listGate = { engine: 'A', promise: new Promise(r => { release = r; }) };
    const engines = [{ name: 'A', version: 2 }];
    const ctx = mountSync(vault, engines);
    await flush();
    ctx.update({ token: '' });
    await act(async () => { release(); });
    await flush();
    expect(writes.filter(w => w.connected)).toHaveLength(0);
  });

  test('relecture d\'une autre session (ancien service) ignorée', async () => {
    const data = { A: many('a', 2) };
    const vault = fakeVaultApi(data);
    const engines = [{ name: 'A', version: 2 }];
    const ctx = mountSync(vault, engines);
    await flush();
    const count = writes.length;
    await act(async () => {
      ctx.syncExtensionRef.current({ engine: engines[0], secrets: [{ name: 'intrus', password: 'x' }], listedKeys: ['intrus'], api: { autre: true } });
    });
    await flush();
    expect(writes.length).toBe(count);
  });
});
