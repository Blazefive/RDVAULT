// ========================================
// TESTS : useMigration — création seule à destination (check-and-set 0) et synchro extension (APP-7)
// ========================================
// Hook réel + createVaultApi réel contre un faux Vault qui applique options.cas comme Vault et le
// coffre local (400 « check-and-set parameter did not match the current version »).
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useMigration } from './useMigration';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
let beforeWrite; // (chemin décodé) => void : écriture d'un autre client juste avant la nôtre
beforeEach(() => {
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  vault = createFakeVault();
  beforeWrite = null;
  axios.get.mockImplementation(vault.axios.get);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
  axios.post.mockImplementation((url, body) => {
    const m = String(url).match(/\/v1\/([^/]+)\/data\/(.+)$/);
    if (m) {
      const [engine, key] = [decodeURIComponent(m[1]), decodeURIComponent(m[2])];
      if (beforeWrite) beforeWrite(engine, key);
      const cas = body?.options?.cas;
      const current = vault.versionsOf(engine, key)?.length || 0;
      if (cas !== undefined && cas !== current) {
        const e = new Error('HTTP 400');
        e.response = { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } };
        return Promise.reject(e);
      }
    }
    return vault.axios.post(url, body);
  });
});
afterEach(() => {
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

function mount(engine, engines, toasts, syncExtensionRef = { current: null }) {
  const vaultApi = createVaultApi(vault.VAULT_URL, 'tok');
  return renderHook(() => useMigration({
    vaultApi, selectedEngine: engine, secretEngines: engines,
    fetchSecretsRef: { current: async () => {} }, clearSelection: () => {},
    syncExtensionRef, showToast: (m, k) => toasts.push([k, m]), t: fakeT
  }));
}
const run = (fn) => act(async () => { await fn(); });

test('entrée créée à destination par un autre client pendant le glisser-déposer : non écrasée, source conservée', async () => {
  const A = vault.addEngine('A');
  const B = vault.addEngine('B');
  vault.writeRaw(A.name, 'github', { Username: 'a', Password: 'MDP-A' });
  beforeWrite = (engine, key) => {
    if (engine === 'B' && key === 'github' && !vault.versionsOf('B', 'github')) vault.writeRaw('B', 'github', { Password: 'AUTRE-CLIENT' });
  };
  const toasts = [];
  const { result } = mount(A, [A, B], toasts);
  await run(() => result.current.migrateSecretsToEngine(['github'], A.name, 2, B));

  expect(vault.latest('B', 'github')).toMatchObject({ version: 1, data: { Password: 'AUTRE-CLIENT' } });
  expect(vault.isLive('A', 'github')).toBe(true);
  expect(toasts[toasts.length - 1][0]).toBe('warning');
  expect(toasts[toasts.length - 1][1]).toContain('migrate.partialResult');
});

test('écriture à destination : options.cas = 0 (KV v2) ; migration réussie sinon', async () => {
  const A = vault.addEngine('A');
  const B = vault.addEngine('B');
  vault.writeRaw(A.name, 'github', { Username: 'a', Password: 'MDP-A' });
  const toasts = [];
  const { result } = mount(A, [A, B], toasts);
  await run(() => result.current.handleMigrateSecrets([{ name: 'github' }], B, 'copy'));
  const write = axios.post.mock.calls.find(c => String(c[0]).endsWith('/v1/B/data/github'));
  expect(write[1]).toEqual({ options: { cas: 0 }, data: { Username: 'a', Password: 'MDP-A' } });
  expect(vault.latest('B', 'github').data.Password).toBe('MDP-A');
  expect(toasts[toasts.length - 1][0]).toBe('success');
});

test('nom supprimé en douceur à destination : jamais visé (listé), renommage « _1 » (pas de refus check-and-set)', async () => {
  const A = vault.addEngine('A');
  const B = vault.addEngine('B');
  vault.writeRaw(A.name, 'github', { Password: 'MDP-A' });
  vault.writeRaw(B.name, 'github', { Password: 'ANCIEN-B' });
  vault.versionsOf('B', 'github')[0].deletion_time = '2026-01-01T00:00:00Z';
  const toasts = [];
  const { result } = mount(A, [A, B], toasts);
  await run(() => result.current.migrateSecretsToEngine(['github'], A.name, 2, B));
  expect(vault.latest('B', 'github_1').data.Password).toBe('MDP-A');
  expect(vault.latest('B', 'github').deletion_time).not.toBe('');
  expect(toasts[toasts.length - 1][0]).toBe('success');
});

test('APP-7 : glisser-déposer (coffre et dossier) : synchro de l\'extension demandée', async () => {
  const A = vault.addEngine('A');
  const B = vault.addEngine('B');
  vault.writeRaw(A.name, 'github', { Password: 'MDP-A' });
  vault.writeRaw(A.name, 'jira', { Password: 'MDP-J' });
  const sync = { current: jest.fn() };
  const { result } = mount(A, [A, B], [], sync);
  await run(() => result.current.migrateSecretsToEngine(['github'], A.name, 2, B));
  expect(sync.current).toHaveBeenCalledTimes(1);
  expect(sync.current).toHaveBeenCalledWith();
  await run(() => result.current.moveSecretsToFolder(['jira'], 'pro'));
  expect(sync.current).toHaveBeenCalledTimes(2);
  expect(vault.isLive('A', 'pro/jira')).toBe(true);
});
