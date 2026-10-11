// ========================================
// TESTS : usePasskeys — coffre des passkeys, écritures concurrentes, compteur de signatures
// ========================================
// - PASSKEYS-16 : le coffre personnel est trouvé par le préfixe EXACT « users/<nom>/ » (casse
//   ignorée, sans assainissement) ; jamais de repli vers le coffre d'un autre utilisateur ni vers
//   le premier coffre venu. Compatibilité : lecture seule de l'ancien emplacement s'il appartient
//   à l'utilisateur, écriture (fusion) dans le coffre personnel, ancien blob jamais supprimé.
// - PASSKEYS-17 : lectures-modifications-écritures du blob sérialisées (file d'attente) et, en
//   KV v2, contrôle de version (CAS) avec nouvel essai en cas de conflit.
// - PASSKEYS-19 : compteur de signatures monotone (jamais de recul) et réservation atomique.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';
// eslint-disable-next-line import/first
import { usePasskeys, PASSKEY_SECRET_KEY } from './usePasskeys';

global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'http://v';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const blobUrl = (engine) => `${VAULT}/v1/${engine.split('/').map(encodeURIComponent).join('/')}/data/${encodeURIComponent(PASSKEY_SECRET_KEY)}`;

// ---- Faux KV v2 en mémoire : versions, CAS (comme HashiCorp Vault), latence simulée ----
let kv;
function installKv({ honorCas = true } = {}) {
  kv = { store: new Map(), calls: [], delayMs: 0, beforeWrite: null };
  axios.get.mockImplementation(async (url) => {
    kv.calls.push(['GET', url]);
    await sleep(kv.delayMs);
    const e = kv.store.get(url);
    if (!e) { const err = new Error('404'); err.response = { status: 404, data: { errors: [] } }; throw err; }
    return { data: { data: { data: JSON.parse(JSON.stringify(e.data)), metadata: { version: e.version } } } };
  });
  axios.post.mockImplementation(async (url, payload) => {
    kv.calls.push(['POST', url, payload]);
    await sleep(kv.delayMs);
    if (kv.beforeWrite) { const fn = kv.beforeWrite; kv.beforeWrite = null; fn(url); }
    const cur = kv.store.get(url);
    const cas = payload && payload.options ? payload.options.cas : undefined;
    if (honorCas && cas !== undefined && cas !== (cur ? cur.version : 0)) {
      const err = new Error('400'); err.response = { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } }; throw err;
    }
    kv.store.set(url, { data: JSON.parse(JSON.stringify(payload.data)), version: (cur ? cur.version : 0) + 1 });
    return { data: { data: { version: (cur ? cur.version : 0) + 1 } } };
  });
}
const put = (engine, data) => { const url = blobUrl(engine); const cur = kv.store.get(url); kv.store.set(url, { data, version: (cur ? cur.version : 0) + 1 }); };
const get = (engine) => (kv.store.get(blobUrl(engine)) || {}).data;
const posts = () => kv.calls.filter((c) => c[0] === 'POST').map((c) => c[1]);

let handler; let responses; let root;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function mountHook(props) {
  responses = [];
  window.electronPasskey = {
    onRequest: (fn) => { handler = fn; return () => {}; },
    sendResponse: (channel, result, requestId) => responses.push({ channel, result, requestId }),
  };
  function H() { usePasskeys(props); return null; }
  const host = document.createElement('div'); document.body.appendChild(host);
  root = createRoot(host);
  act(() => { mountInRoot(root, <H />); });
}
afterEach(() => { if (root) act(() => root.unmount()); root = null; document.body.innerHTML = ''; delete window.electronPasskey; });

const vaultApi = { baseHeaders: () => ({}), axiosConfig: (c) => c };
const mount = (secretEngines, authUser) => mountHook({ vaultApi, token: 't', vaultUrl: VAULT, secretEngines, authUser });
const call = async (channel, req) => { await act(async () => { await handler(channel, { requestId: 'r' + Math.random(), ...req }); }); return responses[responses.length - 1].result; };
const pk = (rpId, credentialId, extra = {}) => ({ rpId, credentialId, privateKeyJwk: { d: credentialId + '-private' }, ...extra });

describe('PASSKEYS-16 : coffre personnel exact, aucun repli vers le coffre d\'autrui', () => {
  const ALICE = 'users/alice/Perso';
  const JEAN = 'users/jean.dupont/Mes-Secrets';

  test('« jean.dupont » (vue administrateur) : ne lit pas les passkeys d\'alice et écrit dans SON coffre', async () => {
    installKv();
    put(ALICE, { items: { 'github.com': [pk('github.com', 'ALICE', { userName: 'alice' })] } });
    mount([{ name: ALICE, version: 2 }, { name: JEAN, version: 2 }], 'jean.dupont');

    const list = await call('passkey-list', { rpId: 'github.com' });
    expect(list).toEqual({ success: true, passkeys: [] });

    const st = await call('passkey-store', { passkey: pk('gitlab.com', 'JEAN') });
    expect(st.success).toBe(true);
    expect(posts()).toEqual([blobUrl(JEAN)]);
    expect(get(JEAN).items['gitlab.com'][0].privateKeyJwk.d).toBe('JEAN-private');
    expect(get(ALICE)).toEqual({ items: { 'github.com': [pk('github.com', 'ALICE', { userName: 'alice' })] } });
  });

  test.each(['Élodie', 'j.doe@corp.fr', 'Иван', 'jean dupont'])('nom « %s » : son propre coffre, jamais users/aaron/', async (name) => {
    installKv();
    mount([{ name: 'users/aaron/Mes-Secrets', version: 2 }, { name: `users/${name}/Mes-Secrets`, version: 2 }], name);
    await call('passkey-store', { passkey: pk('a.com', 'X') });
    expect(posts()).toEqual([blobUrl(`users/${name}/Mes-Secrets`)]);
  });

  test('casse ignorée (« Jean.Dupont » → users/jean.dupont/), « Mes-Secrets » préféré', async () => {
    installKv();
    mount([{ name: 'users/jean.dupont/Archive', version: 2 }, { name: JEAN, version: 2 }], 'Jean.Dupont');
    await call('passkey-store', { passkey: pk('a.com', 'X') });
    expect(posts()).toEqual([blobUrl(JEAN)]);
  });

  test('aucun coffre personnel : refus (success:false), aucune lecture ni écriture ailleurs', async () => {
    installKv();
    put('secret', { items: { 'a.com': [pk('a.com', 'SHARED')] } });
    mount([{ name: 'secret', version: 2 }, { name: 'users/alice/Perso', version: 2 }], 'bob');
    expect((await call('passkey-list', { rpId: 'a.com' })).success).toBe(false);
    expect((await call('passkey-store', { passkey: pk('a.com', 'B') })).success).toBe(false);
    expect((await call('passkey-update-count', { rpId: 'a.com', credentialId: 'SHARED', signCount: 3 })).success).toBe(false);
    expect(kv.calls).toEqual([]);
  });

  test('nom contenant « / » : jamais interprété comme un sous-chemin du coffre d\'un autre', async () => {
    installKv();
    mount([{ name: 'users/alice/bob/Perso', version: 2 }], 'alice/bob');
    expect((await call('passkey-store', { passkey: pk('a.com', 'B') })).success).toBe(false);
    expect(kv.calls).toEqual([]);
  });

  test('compatibilité : passkeys écrites par l\'ancien code dans « Archive » (même utilisateur) lues, puis fusionnées dans le coffre personnel sans supprimer l\'ancien blob', async () => {
    installKv();
    const ARCHIVE = 'users/jean.dupont/Archive';
    const legacy = { items: { 'old.com': [pk('old.com', 'OLD', { signCount: 4 })] } };
    put(ARCHIVE, legacy);
    mount([{ name: ARCHIVE, version: 2 }, { name: JEAN, version: 2 }], 'jean.dupont');

    const list = await call('passkey-list', { rpId: 'old.com' });
    expect(list.passkeys.map((p) => p.credentialId)).toEqual(['OLD']);

    await call('passkey-store', { passkey: pk('new.com', 'NEW') });
    expect(posts()).toEqual([blobUrl(JEAN)]);
    expect(Object.keys(get(JEAN).items).sort()).toEqual(['new.com', 'old.com']);
    expect(get(ARCHIVE)).toEqual(legacy); // ancien blob intact

    // Le coffre personnel a désormais un blob : c'est lui qui fait foi
    const cnt = await call('passkey-update-count', { rpId: 'old.com', credentialId: 'OLD', signCount: 5 });
    expect(cnt).toMatchObject({ success: true, reserved: true, signCount: 5 });
    expect(get(JEAN).items['old.com'][0].signCount).toBe(5);
    expect(get(ARCHIVE).items['old.com'][0].signCount).toBe(4);
  });

  test('compatibilité : l\'ancien emplacement d\'un AUTRE utilisateur n\'est jamais lu', async () => {
    installKv();
    // Ancien algorithme pour « jean.dupont » : nom assaini « jeandupont » → coffre de l'utilisateur « jeandupont »
    put('users/jeandupont/Mes-Secrets', { items: { 'a.com': [pk('a.com', 'OTHER')] } });
    mount([{ name: 'users/jeandupont/Mes-Secrets', version: 2 }, { name: JEAN, version: 2 }], 'jean.dupont');
    expect((await call('passkey-list', { rpId: 'a.com' })).passkeys).toEqual([]);
    expect(kv.calls.map((c) => c[1])).toEqual([blobUrl(JEAN)]);
  });

  test('nom déjà en [a-z0-9_-] : même coffre qu\'avant (aucun changement pour les comptes existants)', async () => {
    installKv();
    put('users/alice/Mes-Secrets', { items: { 'a.com': [pk('a.com', 'A')] } });
    mount([{ name: 'users/alice/Archive', version: 2 }, { name: 'users/alice/Mes-Secrets', version: 2 }, { name: 'users/bob/Mes-Secrets', version: 2 }], 'alice');
    expect((await call('passkey-list', { rpId: 'a.com' })).passkeys.map((p) => p.credentialId)).toEqual(['A']);
    expect(kv.calls.map((c) => c[1])).toEqual([blobUrl('users/alice/Mes-Secrets')]);
  });

  test('coffre KV v1 : format de blob inchangé (pas d\'enveloppe data/options)', async () => {
    installKv();
    const url = `${VAULT}/v1/users/alice/Perso/${encodeURIComponent(PASSKEY_SECRET_KEY)}`;
    axios.post.mockImplementation(async (u, payload) => { kv.calls.push(['POST', u, payload]); return { data: {} }; });
    axios.get.mockImplementation(async () => { const err = new Error('404'); err.response = { status: 404 }; throw err; });
    mount([{ name: 'users/alice/Perso', version: 1 }], 'alice');
    await call('passkey-store', { passkey: pk('a.com', 'A') });
    expect(kv.calls[0][1]).toBe(url);
    expect(kv.calls[0][2]).toEqual({ items: { 'a.com': [pk('a.com', 'A')] } });
  });
});

describe('PASSKEYS-17 : lectures-modifications-écritures sérialisées', () => {
  const JEAN = 'users/jean.dupont/Mes-Secrets';

  test('création et mise à jour du compteur en parallèle : aucune passkey perdue', async () => {
    installKv();
    put(JEAN, { items: { 'b.com': [pk('b.com', 'B', { signCount: 3 })] } });
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    kv.delayMs = 20;
    await act(async () => {
      await Promise.all([
        handler('passkey-store', { requestId: 's1', passkey: pk('a.com', 'A') }),
        handler('passkey-update-count', { requestId: 'c1', rpId: 'b.com', credentialId: 'B', signCount: 4 }),
        handler('passkey-store', { requestId: 's2', passkey: pk('c.com', 'C') }),
      ]);
    });
    expect(responses.every((r) => r.result.success === true)).toBe(true);
    expect(Object.keys(get(JEAN).items).sort()).toEqual(['a.com', 'b.com', 'c.com']);
    expect(get(JEAN).items['b.com'][0].signCount).toBe(4);
  });

  test('KV v2 : écriture conditionnelle (cas = version lue) et nouvel essai si un autre poste a écrit entre-temps', async () => {
    installKv();
    put(JEAN, { items: { 'b.com': [pk('b.com', 'B')] } });
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    // Un autre poste ajoute une passkey juste avant notre écriture
    kv.beforeWrite = () => { const cur = get(JEAN); cur.items['remote.com'] = [pk('remote.com', 'R')]; put(JEAN, cur); };
    const st = await call('passkey-store', { passkey: pk('a.com', 'A') });
    expect(st.success).toBe(true);
    const casSent = kv.calls.filter((c) => c[0] === 'POST').map((c) => c[2].options && c[2].options.cas);
    expect(casSent).toEqual([1, 2]); // premier essai refusé (version 2 en place), second accepté
    expect(Object.keys(get(JEAN).items).sort()).toEqual(['a.com', 'b.com', 'remote.com']);
  });

  test('KV v2 : premier blob créé avec cas = 0 (création seulement s\'il n\'existe pas encore)', async () => {
    installKv();
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    await call('passkey-store', { passkey: pk('a.com', 'A') });
    expect(kv.calls.filter((c) => c[0] === 'POST')[0][2]).toEqual({ data: { items: { 'a.com': [pk('a.com', 'A')] } }, options: { cas: 0 } });
  });

  test('conflit CAS persistant : échec signalé (success:false), sans écriture forcée', async () => {
    installKv();
    put(JEAN, { items: {} });
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    axios.post.mockImplementation(async () => { const err = new Error('400'); err.response = { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } }; throw err; });
    const st = await call('passkey-store', { passkey: pk('a.com', 'A') });
    expect(st.success).toBe(false);
    expect(axios.post.mock.calls.length).toBeGreaterThan(1);
    expect(axios.post.mock.calls.length).toBeLessThanOrEqual(6);
  });

  test('une erreur d\'écriture ne bloque pas la file : l\'opération suivante passe', async () => {
    installKv();
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    axios.post.mockImplementationOnce(async () => { const err = new Error('500'); err.response = { status: 500, data: {} }; throw err; });
    expect((await call('passkey-store', { passkey: pk('a.com', 'A') })).success).toBe(false);
    expect((await call('passkey-store', { passkey: pk('b.com', 'B') })).success).toBe(true);
    expect(Object.keys(get(JEAN).items)).toEqual(['b.com']);
  });
});

describe('PASSKEYS-19 : compteur de signatures monotone et réservé', () => {
  const JEAN = 'users/jean.dupont/Mes-Secrets';

  test('mise à jour tardive (6 après 7) : le compteur ne recule pas, réservation refusée avec la valeur courante', async () => {
    installKv();
    put(JEAN, { items: { 'b.com': [pk('b.com', 'B', { signCount: 7 })] } });
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    const r = await call('passkey-update-count', { rpId: 'b.com', credentialId: 'B', signCount: 6 });
    expect(r).toEqual({ success: true, signCount: 7, reserved: false });
    expect(get(JEAN).items['b.com'][0].signCount).toBe(7);
    expect(posts()).toEqual([]); // rien à écrire
  });

  test('valeur supérieure : réservée et enregistrée', async () => {
    installKv();
    put(JEAN, { items: { 'b.com': [pk('b.com', 'B', { signCount: 7 })] } });
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    expect(await call('passkey-update-count', { rpId: 'b.com', credentialId: 'B', signCount: 8 })).toEqual({ success: true, signCount: 8, reserved: true });
    expect(get(JEAN).items['b.com'][0].signCount).toBe(8);
  });

  test('deux réservations simultanées de la même valeur : une seule l\'obtient', async () => {
    installKv();
    put(JEAN, { items: { 'b.com': [pk('b.com', 'B', { signCount: 5 })] } });
    mount([{ name: JEAN, version: 2 }], 'jean.dupont');
    kv.delayMs = 10;
    await act(async () => {
      await Promise.all([
        handler('passkey-update-count', { requestId: 'a', rpId: 'b.com', credentialId: 'B', signCount: 6 }),
        handler('passkey-update-count', { requestId: 'b', rpId: 'b.com', credentialId: 'B', signCount: 6 }),
      ]);
    });
    const res = responses.map((r) => r.result.reserved).sort();
    expect(res).toEqual([false, true]);
    expect(get(JEAN).items['b.com'][0].signCount).toBe(6);
  });
});
