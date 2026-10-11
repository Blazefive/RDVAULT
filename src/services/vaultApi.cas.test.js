// ========================================
// TESTS : vaultApi.writeSecretToEngine — check-and-set (options.cas, KV v2) — SECRETS-36
// ========================================
// Deux clients qui créent la même entrée ne doivent pas écraser l'écriture de l'autre : avec options.cas,
// la requête porte { options: { cas }, data } (format Vault KV v2) ; une version concurrente (400 de Vault ou
// du coffre local) donne false. Sans l'option, la requête est inchangée.
import { createVaultApi } from './vaultApi';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

const engine2 = { name: 'kv', version: 2 };
const engine1 = { name: 'kv1', version: 1 };
let api;

beforeEach(() => {
  axios.post.mockReset();
  api = createVaultApi('https://vault.test', 'tok', '');
});

test('KV v2 sans option : corps { data } inchangé, délai de 30 s', async () => {
  axios.post.mockResolvedValue({ status: 200 });
  expect(await api.writeSecretToEngine(engine2, 'a', { Password: 'x' })).toBe(true);
  const [url, body, config] = axios.post.mock.calls[0];
  expect(url).toBe('https://vault.test/v1/kv/data/a');
  expect(body).toEqual({ data: { Password: 'x' } });
  expect(config).toMatchObject({ timeout: 30000, headers: { 'X-Vault-Token': 'tok' } });
});

test('KV v2 avec cas = 0 (création) puis cas = 3 : options transmises comme Vault', async () => {
  axios.post.mockResolvedValue({ status: 200 });
  expect(await api.writeSecretToEngine(engine2, 'dossier/a', { Password: 'x' }, { cas: 0 })).toBe(true);
  expect(await api.writeSecretToEngine(engine2, 'a', { Password: 'y' }, { cas: 3 })).toBe(true);
  expect(axios.post.mock.calls[0][0]).toBe('https://vault.test/v1/kv/data/dossier%2Fa');
  expect(axios.post.mock.calls[0][1]).toEqual({ options: { cas: 0 }, data: { Password: 'x' } });
  expect(axios.post.mock.calls[1][1]).toEqual({ options: { cas: 3 }, data: { Password: 'y' } });
  expect(axios.post.mock.calls[1][2]).toMatchObject({ timeout: 30000 });
});

test('version concurrente (400 « check-and-set… ») → false, aucune exception', async () => {
  const err = new Error('Request failed with status code 400');
  err.response = { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } };
  axios.post.mockRejectedValue(err);
  expect(await api.writeSecretToEngine(engine2, 'a', { Password: 'x' }, { cas: 0 })).toBe(false);
});

test('cas invalide → false sans aucune requête (jamais d\'écriture sans le contrôle demandé)', async () => {
  for (const cas of [-1, 1.5, '0', null, NaN, true]) {
    expect(await api.writeSecretToEngine(engine2, 'a', { Password: 'x' }, { cas })).toBe(false);
  }
  expect(axios.post).not.toHaveBeenCalled();
});

test('KV v1 : pas de contrôle de version dans Vault, option ignorée (corps = données)', async () => {
  axios.post.mockResolvedValue({ status: 204 });
  expect(await api.writeSecretToEngine(engine1, 'a', { Password: 'x' }, { cas: 0 })).toBe(true);
  expect(axios.post.mock.calls[0][0]).toBe('https://vault.test/v1/kv1/a');
  expect(axios.post.mock.calls[0][1]).toEqual({ Password: 'x' });
});
