// ========================================
// TESTS : useTags — rechargement multi-coffre partiel et liste du coffre sélectionné (APP-5, suite F3 n°2)
// ========================================
import { act } from 'react';
import { renderHook, fakeT } from './testUtils/fakeVault';
import { useTags } from './useTags';

jest.mock('axios', () => ({
  __esModule: true,
  default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() },
}));

global.IS_REACT_ACT_ENVIRONMENT = true;
beforeEach(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

function mount({ selected, partialEngine = null }) {
  const toasts = [];
  const fetched = [];
  const limitErr = Object.assign(new Error('large'), {
    code: 'LIST_TOO_LARGE', i18nKey: 'error.listTooLarge', i18nVars: { max: 20000 }, partialKeys: ['a'],
  });
  const vaultApi = {
    writeSecretV2: jest.fn(async () => {}), writeSecretV1: jest.fn(),
    listKeysV2: async (engine) => { if (engine.name === partialEngine) throw limitErr; return ['a']; },
    listKeysV1: async () => [],
    readSecretV2: async (engine, key) => ({ name: key, password: 'p', tags: '' }),
    readSecretV1: async () => null,
  };
  const engines = [{ name: 'kv', version: 2 }, { name: 'big', version: 2 }];
  const view = renderHook(() => useTags({
    vaultUrl: 'http://v', baseHeaders: () => ({}), axiosConfig: (c) => c,
    selectedEngine: engines.find(e => e.name === selected), secretEngines: engines, multiVaultSearch: true,
    vaultApi, fetchSecretsRef: { current: async (engine) => { fetched.push(engine.name); } },
    setAllVaultSecrets: () => {}, setLoadingAllSecrets: () => {},
    showToast: (m, k) => toasts.push([k, m]), t: fakeT,
  }));
  return { ...view, toasts, fetched };
}

test('coffre listé partiellement au rechargement : message de borne (et non error.secretsUnreadable)', async () => {
  const { result, toasts } = mount({ selected: 'kv', partialEngine: 'big' });
  await act(async () => {
    await result.current.handleAddTagToSecret({ name: 'a', tags: '', engineName: 'kv', engineVersion: 2 }, 'prod');
  });
  const last = toasts[toasts.length - 1];
  expect(last[0]).toBe('warning');
  expect(last[1]).toContain('error.listTooLargePartial');
  expect(last[1]).toContain('"max":20000');
  expect(last[1]).not.toContain('error.secretsUnreadable');
});

test('APP-5 : tag écrit sur une entrée du coffre sélectionné → sa liste est relue aussi', async () => {
  const { result, fetched } = mount({ selected: 'kv' });
  await act(async () => {
    await result.current.handleRemoveTagFromSecret({ name: 'a', tags: 'prod', engineName: 'kv', engineVersion: 2 }, 'prod');
  });
  expect(fetched).toEqual(['kv']);
});

test('APP-5 : tag écrit sur une entrée d\'un autre coffre → liste du coffre sélectionné non relue', async () => {
  const { result, fetched } = mount({ selected: 'kv' });
  await act(async () => {
    await result.current.handleRemoveTagFromSecret({ name: 'a', tags: 'prod', engineName: 'big', engineVersion: 2 }, 'prod');
  });
  expect(fetched).toEqual([]);
});
