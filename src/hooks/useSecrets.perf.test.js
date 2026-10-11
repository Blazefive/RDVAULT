// ========================================
// TESTS : useSecrets.fetchSecrets — lecture d'un gros coffre (PERF-5 / PERF-7)
// ========================================
// - PERF-5 : lecture bornée (file globale), échecs comptés et signalés (avant : une requête
//   par entrée toutes en même temps, erreurs réseau avalées → entrées disparues sans message).
// - PERF-7 : rafraîchir le coffre affiché ne remplace plus le tableau par le spinner et réutilise
//   les objets inchangés (les lignes mémoïsées ne se re-rendent pas) ; une lecture caduque
//   (coffre changé entre-temps) n'écrase plus la liste affichée.
import { useState, act } from 'react';
import { renderHook, fakeT } from './testUtils/fakeVault';
import { useSecrets } from './useSecrets';
import { DEFAULT_READ_CONCURRENCY } from '../utils/mapLimit';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => { document.body.innerHTML = ''; });

const tick = () => new Promise(r => setTimeout(r, 0));
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });

// Faux service Vault : coffres en mémoire, lectures asynchrones instrumentées
function fakeApi(data) {
  const stats = { inFlight: 0, peak: 0, reads: 0 };
  const behaviour = { fail: () => false, gate: null };
  const read = async (engine, key) => {
    stats.inFlight++; stats.peak = Math.max(stats.peak, stats.inFlight); stats.reads++;
    try {
      if (behaviour.gate && behaviour.gate.engine === engine.name) await behaviour.gate.promise;
      await tick();
      if (behaviour.fail(engine, key)) throw networkError();
      const v = data[engine.name][key];
      return { name: key, username: v.username || '', password: v.password || '', url: '', website: '', notes: '', tags: '', Port: '', customFields: [], attachments: [], entryType: 'secret' };
    } finally {
      stats.inFlight--;
    }
  };
  const list = async (engine) => Object.keys(data[engine.name] || {});
  return { stats, behaviour, api: { listKeysV2: list, listKeysV1: list, readSecretV2: read, readSecretV1: read, baseHeaders: () => ({}), axiosConfig: (c) => c } };
}

function mount(api, extra = {}) {
  const toasts = [];
  const vaultApiRef = { current: api };
  const syncExtensionRef = { current: jest.fn() };
  const view = renderHook(() => {
    const [secrets, setSecrets] = useState([]);
    const s = useSecrets({
      vaultApiRef, vaultUrl: 'http://v', selectedEngine: { name: 'A', version: 2 }, search: '', showDeleted: false,
      secrets, setSecrets, multiVaultSearch: false, allVaultSecrets: [],
      mergeDiscoveredAndSharedTagsRef: { current: null }, setDiscoveredTags: () => {},
      syncExtensionRef, restoreFocus: () => {},
      getTotpKeyName: (n) => n, checkTotpExists: async () => false, totpEngineName: 'TOTP',
      showToast: (m, k) => toasts.push([k, m]), t: fakeT, ...extra,
    });
    return { ...s, secrets };
  });
  return { ...view, toasts, syncExtensionRef, vaultApiRef };
}

const engineA = { name: 'A', version: 2 };
const many = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`e-${String(i).padStart(4, '0')}`, { password: `p${i}` }]));

test('PERF-5 : au plus DEFAULT_READ_CONCURRENCY lectures en vol (avant : une par entrée)', async () => {
  const { api, stats } = fakeApi({ A: many(400) });
  const { result } = mount(api);
  await act(async () => { await result.current.fetchSecrets(engineA); });
  expect(result.current.secrets).toHaveLength(400);
  expect(stats.peak).toBeLessThanOrEqual(DEFAULT_READ_CONCURRENCY);
});

test('PERF-5 : entrées illisibles (erreur réseau) signalées par un avertissement', async () => {
  const { api, behaviour } = fakeApi({ A: many(30) });
  behaviour.fail = (engine, key) => key === 'e-0007' || key === 'e-0011';
  const { result, toasts } = mount(api);
  await act(async () => { await result.current.fetchSecrets(engineA); });
  expect(result.current.secrets).toHaveLength(28);
  const warning = toasts.find(([kind, msg]) => kind === 'warning' && msg.includes('error.secretsUnreadable'));
  expect(warning).toBeTruthy(); // avant : aucun message, deux entrées absentes
  expect(warning[1]).toContain('"count":2');
});

test('PERF-7 : rafraîchir le coffre affiché garde le tableau (pas de spinner) et les objets inchangés', async () => {
  const data = { A: many(50) };
  const { api, behaviour } = fakeApi(data);
  const { result } = mount(api);
  // Lecture lancée puis rendu intermédiaire observé (avant la fin des lectures)
  let pending;
  await act(async () => { pending = result.current.fetchSecrets(engineA); });
  expect(result.current.loadingSecrets).toBe(true); // premier chargement : spinner
  await act(async () => { await pending; });
  expect(result.current.loadingSecrets).toBe(false);
  const before = result.current.secrets;

  // Écriture d'une entrée, puis relecture du coffre ; une autre lecture échoue cette fois
  data.A['e-0003'] = { password: 'nouveau' };
  behaviour.fail = (engine, key) => key === 'e-0020';
  await act(async () => { pending = result.current.fetchSecrets(engineA); });
  expect(result.current.loadingSecrets).toBe(false); // avant : spinner puis remontage des lignes
  expect(result.current.secrets).toBe(before);       // lignes affichées pendant la relecture
  await act(async () => { await pending; });
  const after = result.current.secrets;
  expect(after).toHaveLength(50); // l'entrée momentanément illisible garde sa ligne
  expect(after.find(s => s.name === 'e-0003').password).toBe('nouveau');
  expect(after.find(s => s.name === 'e-0003')).not.toBe(before.find(s => s.name === 'e-0003'));
  // Objets inchangés réutilisés (lignes mémoïsées non re-rendues)
  expect(after.find(s => s.name === 'e-0001')).toBe(before.find(s => s.name === 'e-0001'));
  expect(after.find(s => s.name === 'e-0020')).toBe(before.find(s => s.name === 'e-0020'));

  // Rien de changé : la liste elle-même est conservée
  behaviour.fail = () => false;
  const stable = result.current.secrets;
  await act(async () => { await result.current.fetchSecrets(engineA); });
  expect(result.current.secrets).toBe(stable);
});

test('lecture caduque (coffre changé pendant le chargement) : n\'écrase pas la liste affichée', async () => {
  const { api, behaviour } = fakeApi({ A: { a1: {}, a2: {} }, B: { b1: {} } });
  let release;
  behaviour.gate = { engine: 'A', promise: new Promise(r => { release = r; }) };
  // Coffre sélectionné modifiable (comme App : l'utilisateur ouvre B, l'effet relit B)
  const sel = { engine: engineA };
  const { result, rerender } = mount(api, { get selectedEngine() { return sel.engine; } });
  let slow;
  await act(async () => { slow = result.current.fetchSecrets(engineA); await tick(); });
  sel.engine = { name: 'B', version: 2 };
  rerender();
  await act(async () => { await result.current.fetchSecrets(sel.engine); });
  expect(result.current.secrets.map(s => s.name)).toEqual(['b1']);
  await act(async () => { release(); await slow; });
  expect(result.current.secrets.map(s => s.name)).toEqual(['b1']); // avant : remplacée par a1, a2
  expect(result.current.loadingSecrets).toBe(false);
});

test('PERF-6 : la liste relue est transmise à la synchro de l\'extension (aucune relecture)', async () => {
  const { api } = fakeApi({ A: { x: { password: 'px' }, y: { password: 'py' } } });
  const { result, syncExtensionRef, vaultApiRef } = mount(api);
  await act(async () => { await result.current.fetchSecrets(engineA); });
  expect(syncExtensionRef.current).toHaveBeenCalledTimes(1);
  const update = syncExtensionRef.current.mock.calls[0][0];
  expect(update.engine).toBe(engineA);
  expect(update.api).toBe(vaultApiRef.current);
  expect(update.secrets.map(s => s.name)).toEqual(['x', 'y']);
  expect(update.listedKeys).toEqual(['x', 'y']);
  expect(update.failedKeys).toEqual([]);
});
