// ========================================
// TESTS : useTotp — convention de nommage des clés TOTP et période affichée
// ========================================
// - Le nom des clés TOTP suit une convention HISTORIQUE (PRÉFIXE-DU-COFFRE-EN-MAJUSCULES-entrée) dont
//   dépendent les clés existantes, l'extension et les policies Vault : elle ne doit pas changer.
// - DATA-17 : « Afficher le code TOTP » transmet la période de la clé à la modale (sinon 30 s par défaut).
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { useTotp, buildTotpKeyName, totpKeyPrefix } from './useTotp';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => { document.body.innerHTML = ''; });

const baseHeaders = () => ({ 'X-Vault-Token': 'tok' });
const axiosConfig = (c = {}) => c;
function mount(engine, toasts = []) {
  return renderHook(() => useTotp({
    vaultUrl: vault.VAULT_URL, baseHeaders, axiosConfig, selectedEngine: engine,
    startClipboardTimer: async () => {}, showToast: (m, k) => toasts.push([k, m]), t: fakeT, restoreFocus: () => {}
  }));
}

describe('Convention de nommage (compatibilité des clés existantes)', () => {
  test('préfixe : chemin sans « users/<u>/ » ni « / » final, en majuscules', () => {
    expect(totpKeyPrefix('users/alice/Banque/')).toBe('BANQUE');
    expect(totpKeyPrefix('Perso')).toBe('PERSO');
    expect(totpKeyPrefix('equipe/infra')).toBe('EQUIPE/INFRA');
    expect(buildTotpKeyName('users/alice/Banque', 'dossier/github')).toBe('BANQUE-dossier/github');
  });

  test('getTotpKeyName et la modale de configuration utilisent la même convention', async () => {
    const { result } = mount({ name: 'users/hunter/Banque', version: 2 });
    expect(result.current.getTotpKeyName('github')).toBe('BANQUE-github');
    await act(async () => { await result.current.handleConfigureTotp({ name: 'github' }); });
    expect(result.current.totpConfig).toMatchObject({ totpKeyName: 'BANQUE-github', engineName: 'BANQUE' });
  });
});

describe('DATA-17 : période de la clé transmise à la modale d\'affichage', () => {
  test('clé à 20 s : totpDisplay.period = 20', async () => {
    vault.addTotp('KV-github', { period: 20 });
    const { result } = mount({ name: 'kv', version: 2 });
    await act(async () => { await result.current.handleShowTotp({ name: 'github' }); });
    expect(result.current.totpDisplay).toMatchObject({ secretName: 'github', totpKeyName: 'KV-github', code: '123456', period: 20 });
  });

  test('configuration illisible (403) : période par défaut de 30 s, le code reste affiché', async () => {
    vault.addTotp('KV-github', { period: 60 });
    vault.setFailWhen((method, path) => (method === 'get' && path === 'v1/TOTP/keys/KV-github' ? 403 : null));
    const { result } = mount({ name: 'kv', version: 2 });
    await act(async () => { await result.current.handleShowTotp({ name: 'github' }); });
    expect(result.current.totpDisplay).toMatchObject({ code: '123456', period: 30 });
  });
});
