// ========================================
// TESTS : useTotp — garde de session (APP-3) et isolation bidi des toasts
// ========================================
// Une requête TOTP lancée pendant une session répond après la déconnexion (ou après la connexion d'un
// autre utilisateur) : le code n'est jamais copié dans le presse-papiers, aucune modale ne s'ouvre,
// aucune clé n'est supprimée et aucun toast ne s'affiche. Session suivie par sessionTokenRef (useAuth,
// synchrone) ou, à défaut, par le jeton des en-têtes (baseHeaders) relu à chaque rendu.
// En arabe (<html dir="rtl">), les valeurs des toasts sont isolées : nom d'entrée dans son propre sens
// (FSI … PDI), clé TOTP et nom de coffre de gauche à droite (LRI … PDI).
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { useTotp } from './useTotp';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

const LRI = String.fromCharCode(0x2066);
const FSI = String.fromCharCode(0x2068);
const PDI = String.fromCharCode(0x2069);
const BIDI = new RegExp('[' + String.fromCharCode(0x2066) + '-' + String.fromCharCode(0x2069) + ']');

let vault;
let gate;
beforeEach(() => {
  vault = createFakeVault();
  gate = { on: false, pending: [] };
  // Requêtes TOTP (/v1/TOTP/…) retenues tant que gate.on
  const held = (fn) => (url, ...rest) => {
    if (gate.on && /\/v1\/TOTP\//.test(String(url))) return new Promise(r => gate.pending.push(r)).then(() => fn(url, ...rest));
    return fn(url, ...rest);
  };
  axios.get.mockImplementation(held(vault.axios.get));
  axios.post.mockImplementation(held(vault.axios.post));
  axios.delete.mockImplementation(held(vault.axios.delete));
});
afterEach(() => {
  document.body.innerHTML = '';
  document.documentElement.dir = '';
});

const flushAll = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve(); // eslint-disable-line no-await-in-loop
};
const release = () => act(async () => { gate.pending.splice(0).forEach(r => r()); await flushAll(); });

/**
 * Monte useTotp. `state.token` est lu à chaque rendu (en-têtes) ; sessionTokenRef est fourni sauf si
 * withSessionRef === false (appelant qui ne le passe pas : repli sur les en-têtes).
 */
function mount(state, { withSessionRef = true, vaultApi } = {}) {
  const copies = [];
  const toasts = [];
  const sessionTokenRef = { current: state.token };
  const view = renderHook(() => useTotp({
    vaultUrl: vault.VAULT_URL,
    baseHeaders: () => (state.token ? { 'X-Vault-Token': state.token } : {}),
    axiosConfig: (c = {}) => c,
    selectedEngine: { name: 'kv', version: 2 },
    startClipboardTimer: async (label, code) => { copies.push(code); },
    showToast: (m, k) => toasts.push([k, m]),
    t: fakeT,
    restoreFocus: () => {},
    vaultApi,
    sessionTokenRef: withSessionRef ? sessionTokenRef : undefined,
  }));
  return { ...view, copies, toasts, sessionTokenRef };
}

// Lance une action du hook sans l'attendre (la requête reste retenue par la barrière)
const start = (fn) => {
  let promise;
  act(() => { promise = fn(); });
  return promise;
};

describe('APP-3 : « Copier le code TOTP » et déconnexion', () => {
  test('réponse après la déconnexion (sessionTokenRef vidé) : rien n\'est copié, aucun toast', async () => {
    vault.addTotp('KV-banque');
    const state = { token: 'tok-alice' };
    const { result, copies, toasts, sessionTokenRef } = mount(state);
    gate.on = true;
    const pending = start(() => result.current.handleCopyTotp({ name: 'banque' }));
    // Déconnexion : useAuth vide le jeton de façon synchrone (avant tout nouveau rendu)
    sessionTokenRef.current = '';
    state.token = '';
    await release();
    await act(async () => { await pending; });
    expect(copies).toEqual([]);
    expect(toasts).toEqual([]);
  });

  test('sans sessionTokenRef : nouvelle session détectée par le jeton des en-têtes (connexion de bob)', async () => {
    vault.addTotp('KV-banque');
    const state = { token: 'tok-alice' };
    const { result, copies, rerender } = mount(state, { withSessionRef: false });
    gate.on = true;
    const pending = start(() => result.current.handleCopyTotp({ name: 'banque' }));
    state.token = 'tok-bob';
    rerender();
    await release();
    await act(async () => { await pending; });
    expect(copies).toEqual([]);
  });

  test('erreur arrivée après la déconnexion : aucun toast d\'erreur sur l\'écran de connexion', async () => {
    vault.setFailWhen((method, path) => (path.startsWith('v1/TOTP/code/') ? 500 : null));
    const state = { token: 'tok-alice' };
    const { result, toasts, sessionTokenRef } = mount(state);
    gate.on = true;
    const pending = start(() => result.current.handleCopyTotp({ name: 'banque' }));
    sessionTokenRef.current = '';
    await release();
    await act(async () => { await pending; });
    expect(toasts).toEqual([]);
  });

  test('témoin : même session, le code est copié', async () => {
    vault.addTotp('KV-banque');
    const { result, copies } = mount({ token: 'tok-alice' });
    gate.on = true;
    const pending = start(() => result.current.handleCopyTotp({ name: 'banque' }));
    await release();
    await act(async () => { await pending; });
    expect(copies).toEqual(['123456']);
  });
});

describe('APP-3 : autres actions TOTP après la fin de la session', () => {
  test('« Afficher le code » : la modale ne s\'ouvre pas avec le code de la session précédente', async () => {
    vault.addTotp('KV-banque');
    const state = { token: 'tok-alice' };
    const { result, sessionTokenRef } = mount(state);
    gate.on = true;
    const pending = start(() => result.current.handleShowTotp({ name: 'banque' }));
    sessionTokenRef.current = '';
    await release();
    await act(async () => { await pending; });
    expect(result.current.totpDisplay).toBeNull();
  });

  test('« Configurer le TOTP » : la fiche (qui contient le secret) ne s\'ouvre pas', async () => {
    const state = { token: 'tok-alice' };
    const { result, sessionTokenRef } = mount(state);
    gate.on = true;
    const pending = start(() => result.current.handleConfigureTotp({ name: 'banque', password: 'MDP-ALICE' }));
    sessionTokenRef.current = 'tok-bob';
    await release();
    await act(async () => { await pending; });
    expect(result.current.totpConfig).toBeNull();
  });

  test('« Supprimer le TOTP » confirmé puis déconnexion pendant l\'inventaire : la graine est conservée', async () => {
    vault.addTotp('KV-banque');
    let releaseList = null;
    const vaultApi = {
      listEngines: () => new Promise((resolve) => { releaseList = () => resolve([{ name: 'kv', version: 2 }]); }),
      secretStatus: async () => 'absent',
    };
    const state = { token: 'tok-alice' };
    const { result, toasts, sessionTokenRef } = mount(state, { vaultApi });
    const pending = start(() => result.current.handleDeleteTotp({ name: 'banque' }, { confirmed: true }));
    sessionTokenRef.current = '';
    await act(async () => { releaseList(); await flushAll(); });
    let deleted;
    await act(async () => { deleted = await pending; });
    expect(deleted).toBe(false);
    expect(vault.totp.has('KV-banque')).toBe(true);
    expect(toasts).toEqual([]);
  });
});

describe('BIDI : valeurs des toasts isolées en RTL', () => {
  test('arabe : nom d\'entrée isolé (FSI) ; clé TOTP isolée de gauche à droite (LRI)', async () => {
    document.documentElement.dir = 'rtl';
    vault.addTotp('KV-banque');
    const { result, toasts } = mount({ token: 'tok' });
    await act(async () => { await result.current.handleConfigureTotp({ name: 'banque' }); });
    expect(toasts[0][1]).toContain(`${FSI}banque${PDI}`);

    await act(async () => { await result.current.handleConfigureTotp({ name: 'wifi' }); });
    expect(result.current.totpConfig).toMatchObject({ totpKeyName: 'KV-wifi' });
    await act(async () => { await result.current.handleSaveTotpConfig({ key: 'JBSWY3DPEHPK3PXP' }); });
    expect(toasts[toasts.length - 1]).toEqual(['success', expect.stringContaining(`${LRI}KV-wifi${PDI}`)]);
  });

  test('arabe : coffre qui partage la clé isolé de gauche à droite', async () => {
    document.documentElement.dir = 'rtl';
    vault.addTotp('KV-banque');
    const vaultApi = {
      listEngines: async () => [{ name: 'kv', version: 2 }, { name: 'users/bob/kv', version: 2 }],
      secretStatus: async () => 'live',
    };
    const { result, toasts } = mount({ token: 'tok' }, { vaultApi });
    await act(async () => { await result.current.handleDeleteTotp({ name: 'banque' }, { confirmed: true }); });
    expect(toasts[0][1]).toContain(`${LRI}users/bob/kv${PDI}`);
    expect(vault.totp.has('KV-banque')).toBe(true);
  });

  test('langue LTR : texte des toasts inchangé (aucun caractère invisible)', async () => {
    document.documentElement.dir = 'ltr';
    vault.addTotp('KV-banque');
    const { result, toasts } = mount({ token: 'tok' });
    await act(async () => { await result.current.handleConfigureTotp({ name: 'banque' }); });
    expect(toasts[0][1]).toBe('error.totpAlreadyExists {"name":"banque"}');
    expect(BIDI.test(toasts[0][1])).toBe(false);
  });
});
