// ========================================
// TESTS : useTags — lecture des tags partagés (tags-shared)
// ========================================
// Le secret tags-shared/data/tags est souvent absent (404) : chaque rafraîchissement de la liste le
// relisait (requête + 404 dans le journal). L'absence est désormais mise en cache pour la session
// (mêmes en-têtes, donc même jeton) jusqu'à la première écriture vers tags-shared.
import { act } from 'react';
import { renderHook, fakeT } from './testUtils/fakeVault';
import { useTags } from './useTags';

jest.mock('axios', () => ({
  __esModule: true,
  default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(), interceptors: { request: { use: jest.fn() } } }
}));
// eslint-disable-next-line import/first
import axios from 'axios';

// Intercepteur enregistré au chargement du module (capturé avant la remise à zéro des simulations)
const interceptor = axios.interceptors.request.use.mock.calls[0]?.[0];

global.IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => { document.body.innerHTML = ''; });

const notFound = () => Promise.reject(Object.assign(new Error('404'), { response: { status: 404 } }));
const axiosConfig = (c = {}) => c;

function mount(baseHeaders) {
  return renderHook(() => useTags({
    vaultUrl: 'http://v', baseHeaders, axiosConfig,
    selectedEngine: { name: 'kv', version: 2 }, secretEngines: [], multiVaultSearch: false,
    vaultApi: { writeSecretV2: jest.fn(), writeSecretV1: jest.fn() }, fetchSecretsRef: { current: async () => {} },
    setAllVaultSecrets: () => {}, setLoadingAllSecrets: () => {}, showToast: () => {}, t: fakeT
  }));
}
const tagsGets = () => axios.get.mock.calls.filter(([u]) => u === 'http://v/v1/tags-shared/data/tags').length;

test('absence (404) mise en cache : une seule lecture pour plusieurs rafraîchissements', async () => {
  axios.get.mockImplementation(notFound);
  const baseHeaders = () => ({ 'X-Vault-Token': 'a' });
  const { result } = mount(baseHeaders);
  let tags;
  await act(async () => { tags = await result.current.mergeDiscoveredAndSharedTags([{ tags: 'prod web' }]); });
  await act(async () => { await result.current.mergeDiscoveredAndSharedTags([]); });
  await act(async () => { tags = await result.current.mergeDiscoveredAndSharedTags([{ tags: 'prod' }]); });
  expect(tags).toEqual(['prod']);
  expect(tagsGets()).toBe(1);
});

test('une écriture vers tags-shared invalide le cache (relecture suivante)', async () => {
  expect(typeof interceptor).toBe('function');
  axios.get.mockImplementation(notFound);
  const baseHeaders = () => ({ 'X-Vault-Token': 'b' });
  const { result } = mount(baseHeaders);
  await act(async () => { await result.current.mergeDiscoveredAndSharedTags([]); });
  // Requête d'écriture observée (ex. AdminPanel → tagManager.saveSharedTags)
  const cfg = { method: 'post', url: 'http://v/v1/tags-shared/data/tags' };
  expect(interceptor(cfg)).toBe(cfg);
  axios.get.mockImplementation(() => Promise.resolve({ status: 200, data: { data: { data: { tags: ['#partage'] } } } }));
  let tags;
  await act(async () => { tags = await result.current.mergeDiscoveredAndSharedTags([]); });
  expect(tags).toEqual(['#partage']);
  expect(tagsGets()).toBe(2);
  // Une lecture GET ne compte pas comme écriture
  interceptor({ method: 'get', url: 'http://v/v1/tags-shared/data/tags' });
});

test('nouvelle session (autres en-têtes) : relecture ; tags présents : jamais mis en cache', async () => {
  axios.get.mockImplementation(notFound);
  const h1 = () => ({ 'X-Vault-Token': 'c' });
  const { result: first } = mount(h1);
  await act(async () => { await first.current.mergeDiscoveredAndSharedTags([]); });
  const h2 = () => ({ 'X-Vault-Token': 'd' });
  const { result: second } = mount(h2);
  await act(async () => { await second.current.mergeDiscoveredAndSharedTags([]); });
  expect(tagsGets()).toBe(2);

  axios.get.mockImplementation(() => Promise.resolve({ status: 200, data: { data: { data: { tags: ['#t'] } } } }));
  const h3 = () => ({ 'X-Vault-Token': 'e' });
  const { result: third } = mount(h3);
  await act(async () => { await third.current.mergeDiscoveredAndSharedTags([]); });
  await act(async () => { await third.current.mergeDiscoveredAndSharedTags([]); });
  expect(tagsGets()).toBe(4);
});

test('erreur réseau : liste vide, sans mise en cache', async () => {
  axios.get.mockImplementation(() => Promise.reject(Object.assign(new Error('net'), { code: 'ECONNREFUSED' })));
  const h = () => ({ 'X-Vault-Token': 'f' });
  const { result } = mount(h);
  let tags;
  await act(async () => { tags = await result.current.mergeDiscoveredAndSharedTags([]); });
  await act(async () => { await result.current.mergeDiscoveredAndSharedTags([]); });
  expect(tags).toEqual([]);
  expect(tagsGets()).toBe(2);
});
