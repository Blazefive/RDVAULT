// ========================================
// TESTS : vaultApi — lecture groupée du coffre local et journal des écritures
// ========================================
import { createVaultApi, BATCH_READ_OP, entryFromKvData } from './vaultApi';
import { vaultWriteSeq, vaultWritesSince, READ_ONLY_REQUEST_FLAG } from './vaultWriteLog';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

const V = 'http://127.0.0.1:8200';
const engine = { name: 'users/alice/Mes-Secrets', version: 2 };
const ok = (data) => Promise.resolve({ status: 200, data });
const httpError = (status) => Promise.reject(Object.assign(new Error(`HTTP ${status}`), { response: { status } }));

test('absente sans l\'option batchRead (Vault distant) : seule l\'API KV standard est employée', () => {
  expect(createVaultApi(V, 'tok').readSecretsBatchV2).toBeUndefined();
  expect(createVaultApi(V, 'tok', '', { batchRead: false }).readSecretsBatchV2).toBeUndefined();
  expect(typeof createVaultApi(V, 'tok', '', { batchRead: true }).readSecretsBatchV2).toBe('function');
});

test('une requête POST (jeton, lecture marquée), entrées converties comme readSecretV2, statuts par clé', async () => {
  const api = createVaultApi(V, 'tok', '', { batchRead: true });
  axios.post.mockImplementation((url, body) => ok({
    data: {
      results: [
        { key: 'banque', status: 200, data: { Username: 'a', Password: 'p', CustomFields: [{ key: 'Port', value: '22' }] } },
        { key: 'vieille', status: 404, deleted: true, metadata: {} },
        { key: 'absente', status: 404 },
        { key: 'cassee', status: 500, error: 'decryption failed' },
        { key: 'non-demandee', status: 200, data: { Password: 'jamais' } },
      ],
      remaining: [],
    },
  }));
  const r = await api.readSecretsBatchV2(engine, ['banque', 'vieille', 'absente', 'cassee', 'oubliee']);
  expect(axios.post).toHaveBeenCalledTimes(1);
  const [url, body, cfg] = axios.post.mock.calls[0];
  expect(url).toBe(`${V}/v1/users/alice/Mes-Secrets/${BATCH_READ_OP}`);
  expect(body).toEqual({ keys: ['banque', 'vieille', 'absente', 'cassee', 'oubliee'] });
  expect(cfg.headers['X-Vault-Token']).toBe('tok');
  expect(cfg[READ_ONLY_REQUEST_FLAG]).toBe(true);
  expect(r.map(x => x.key)).toEqual(['banque', 'vieille', 'absente', 'cassee', 'oubliee']);
  expect(r[0].item).toEqual(entryFromKvData('banque', { Username: 'a', Password: 'p', CustomFields: [{ key: 'Port', value: '22' }] }));
  expect(r[0].item.Port).toBe('22');
  expect(r[1]).toEqual({ key: 'vieille', deleted: true });
  expect(r[2].error.response.status).toBe(404);
  expect(r[3].error.response.status).toBe(500);
  // Clé demandée absente de la réponse : illisible (500), jamais « absente »
  expect(r[4].error.response.status).toBe(500);
  expect(r.some(x => x.key === 'non-demandee')).toBe(false);
});

test('réponse bornée : les clés restantes sont redemandées ; réponse sans progrès ou invalide → rejet (repli unitaire)', async () => {
  const api = createVaultApi(V, 'tok', '', { batchRead: true });
  axios.post
    .mockImplementationOnce(() => ok({ data: { results: [{ key: 'a', status: 200, data: {} }], remaining: ['b', 'c'] } }))
    .mockImplementationOnce(() => ok({ data: { results: [{ key: 'b', status: 200, data: {} }, { key: 'c', status: 200, data: {} }], remaining: [] } }));
  const r = await api.readSecretsBatchV2(engine, ['a', 'b', 'c']);
  expect(axios.post).toHaveBeenCalledTimes(2);
  expect(axios.post.mock.calls[1][1]).toEqual({ keys: ['b', 'c'] });
  expect(r.every(x => x.item)).toBe(true);

  axios.post.mockImplementation(() => ok({ data: { results: [], remaining: ['a'] } }));
  await expect(api.readSecretsBatchV2(engine, ['a'])).rejects.toThrow();
  axios.post.mockImplementation(() => ok({ unexpected: true }));
  await expect(api.readSecretsBatchV2(engine, ['a'])).rejects.toThrow();
  await expect(api.readSecretsBatchV2(engine, Array.from({ length: 251 }, (_, i) => `k${i}`))).rejects.toThrow();
});

test('route refusée (405) : plus tentée pour ce service ; 404 (coffre supprimé) ou réseau : nouvelle tentative possible', async () => {
  const api = createVaultApi(V, 'tok', '', { batchRead: true });
  axios.post.mockImplementation(() => httpError(503));
  await expect(api.readSecretsBatchV2(engine, ['a'])).rejects.toThrow();
  axios.post.mockImplementation(() => httpError(404));
  await expect(api.readSecretsBatchV2(engine, ['a'])).rejects.toThrow();
  axios.post.mockImplementation(() => ok({ data: { results: [{ key: 'a', status: 200, data: {} }], remaining: [] } }));
  await expect(api.readSecretsBatchV2(engine, ['a'])).resolves.toHaveLength(1);
  axios.post.mockImplementation(() => httpError(405));
  await expect(api.readSecretsBatchV2(engine, ['a'])).rejects.toThrow();
  axios.post.mockClear();
  await expect(api.readSecretsBatchV2(engine, ['a'])).rejects.toThrow();
  expect(axios.post).not.toHaveBeenCalled();
});

test('écritures notées dans le journal (création, suppression douce, KV v1, migration) — lectures non notées', async () => {
  const api = createVaultApi(V, 'tok');
  axios.post.mockImplementation(() => ok({}));
  axios.delete.mockImplementation(() => ok({}));
  axios.get.mockImplementation(() => ok({ data: { versions: { 1: {} } } }));
  const since = vaultWriteSeq();
  await api.writeSecretV2(engine, { name: 'neuve', username: '', password: '', url: '', website: '', notes: '' });
  await api.deleteSecretV2(engine, 'dossier/vieille');
  await api.writeSecretToEngine(engine, 'copie', { Password: 'x' }, { cas: 0 });
  await api.deleteSecretFromEngine(engine, 'detruite');
  await api.readSecretV2(engine, 'lue');
  const legacy = { name: 'legacy', version: 1 };
  await api.writeSecretV1(legacy, { name: 'v1', username: '', password: '', url: '', website: '', notes: '' });
  await api.deleteSecretV1(legacy, 'v1-sup');
  expect(Array.from(vaultWritesSince(engine, since)).sort()).toEqual(['copie', 'detruite', 'dossier/vieille', 'neuve']);
  expect(Array.from(vaultWritesSince(legacy, since)).sort()).toEqual(['v1', 'v1-sup']);
});
