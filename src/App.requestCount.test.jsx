// ========================================
// TESTS : App.jsx — nombre de requêtes par action sur un coffre de 1 200 entrées (chasse « longue session »)
// ========================================
// App réel dans jsdom, axios branché sur le faux coffre du projet (même sémantique que le coffre local).
// Mesure les requêtes adressées au coffre (lectures, listages, écritures, synchro de l'extension comprise)
// pour chaque action utilisateur. Avant : enregistrer UNE entrée relisait tout le coffre (≈ 1 240
// requêtes), changer de coffre aussi, cocher puis décocher « Afficher les supprimés » ≈ 3 660, la
// recherche multi-coffres toutes les entrées de tous les coffres, un glisser-déposer ≈ 1 245.
// Les invariants visibles sont vérifiés en même temps (tableau, extension servie, entrées supprimées,
// entrée déplacée). REQCOUNT_OUT=<fichier> : écrit les mesures (JSON) pour le rapport.
import fs from 'fs';
import fr from './locales/fr.json';
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login, quiet,
  activeEngine, engineCard, rowByName, rowNames, rightClick, menuItem, setInput, typeSearch, multiBox,
  fakeDataTransfer, dispatchDrag, lastExtensionState,
} from './hooks/testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;
jest.setTimeout(120000);

let host; let root;
beforeEach(() => {
  jest.useFakeTimers();
  quiet();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  installBridges();
  ({ host, root } = createHost());
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  removeBridges();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

const N_MAIN = 1200;
const DELETED = ['e-0011', 'e-0012', 'e-0013', 'e-0014', 'e-0015', 'e-0016', 'e-0017', 'e-0018', 'e-0021', 'e-0022'];

function seed(vault) {
  vault.addEngine('Alpha');
  vault.addEngine('Beta');
  vault.addEngine('Gamma');
  for (let i = 0; i < N_MAIN; i++) {
    const n = String(i).padStart(4, '0');
    // Une entrée sur dix rangée dans l'un des 20 dossiers (arborescence réaliste : 21 listages)
    const key = i % 10 === 9 ? `f-${String(Math.floor(i / 10) % 20).padStart(2, '0')}/x-${n}` : `e-${n}`;
    vault.writeRaw('Alpha', key, { Username: `u${i}`, Password: `p${i}`, URL: `https://site${i}.example`, EntryType: 'secret' });
  }
  for (const key of DELETED) {
    const v = vault.versionsOf('Alpha', key);
    v[v.length - 1].deletion_time = '2026-01-01T00:00:00Z';
  }
  for (let i = 0; i < 300; i++) vault.writeRaw('Beta', `b-${String(i).padStart(4, '0')}`, { Password: `b${i}` });
  for (let i = 0; i < 5; i++) vault.writeRaw('Gamma', `g-${i}`, { Password: `g${i}` });
}

// Laisse passer minuteries (synchro de l'extension, anti-rebond) et lectures jusqu'à ce que plus aucune
// requête ne parte pendant plusieurs tours
async function idle(vault) {
  let stable = 0;
  let last = -1;
  for (let i = 0; i < 400 && stable < 4; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { jest.advanceTimersByTime(1500); });
    // eslint-disable-next-line no-await-in-loop
    await flush(30);
    if (vault.calls.length === last) stable++; else { stable = 0; last = vault.calls.length; }
  }
}

// Requêtes adressées au coffre pendant `action` (et ses suites : relectures, synchro de l'extension)
async function measure(vault, action) {
  const from = vault.calls.length;
  await action();
  await idle(vault);
  const calls = vault.calls.slice(from);
  const reads = calls.filter(c => c.method === 'get' && !String(c.query).includes('list=true')).length;
  const lists = calls.filter(c => c.method === 'get' && String(c.query).includes('list=true')).length;
  return { total: calls.length, reads, lists, writes: calls.length - reads - lists };
}

const clickEl = async (el) => {
  await act(async () => { el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); });
  await flush(10);
};
const showDeletedBox = () => Array.from(host.querySelectorAll('.toolbar label.checkbox-label'))
  .find(l => l.textContent.includes(fr.toolbar.showDeleted)).querySelector('input');

test('requêtes par action (coffre de 1 200 entrées) : relectures ciblées et listes gardées', async () => {
  const vault = setupVault();
  seed(vault);
  const results = {};

  results.login = await measure(vault, async () => {
    await renderApp(root);
    await login(host);
  });
  expect(activeEngine(host)).toBe('Alpha');
  expect(rowByName(host, 'e-0001')).not.toBeNull();

  // 1. Enregistrer UNE entrée (« Modifier » puis « Enregistrer »)
  results.saveOne = await measure(vault, async () => {
    await rightClick(rowByName(host, 'e-0001'));
    await act(async () => { menuItem(fr.contextMenu.edit).click(); });
    await flush(30);
    const modal = document.querySelector('[role="dialog"]');
    const pwd = Array.from(modal.querySelectorAll('input')).find(i => i.value === 'p1');
    await act(async () => { setInput(pwd, 'NOUVEAU-MDP-1'); });
    const save = Array.from(modal.querySelectorAll('button')).find(b => b.textContent.trim() === fr.editSecret.save);
    await act(async () => { save.click(); });
    await flush(60);
  });
  expect(vault.latest('Alpha', 'e-0001').data.Password).toBe('NOUVEAU-MDP-1');
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  // Extension servie à jour (état publié après l'écriture)
  expect(lastExtensionState().secrets).toContain('Alpha/e-0001:NOUVEAU-MDP-1');
  expect(lastExtensionState().secrets).not.toContain('Alpha/e-0001:p1');

  // 2. Changer de coffre (première ouverture de Beta : déjà lu par la synchro de fond ou non) puis revenir
  results.switchToBeta = await measure(vault, async () => {
    await act(async () => { engineCard(host, 'Beta').click(); });
    await flush(30);
  });
  expect(activeEngine(host)).toBe('Beta');
  expect(rowByName(host, 'b-0000')).not.toBeNull();
  results.switchBackToAlpha = await measure(vault, async () => {
    await act(async () => { engineCard(host, 'Alpha').click(); });
    await flush(30);
  });
  expect(activeEngine(host)).toBe('Alpha');
  expect(rowNames(host)).toContain('e-0001');

  // 3. « Afficher les supprimés » : cocher, puis décocher
  results.showDeletedOn = await measure(vault, async () => { await clickEl(showDeletedBox()); });
  expect(rowByName(host, 'e-0011')?.querySelector('.deleted-badge')).toBeTruthy();
  results.showDeletedOff = await measure(vault, async () => { await clickEl(showDeletedBox()); });
  expect(rowByName(host, 'e-0011')).toBeNull();

  // 4. Recherche dans tous les coffres (puis une seconde fois)
  results.multiVaultSearch = await measure(vault, async () => {
    await typeSearch(host, 'b-000');
    await clickEl(multiBox(host));
  });
  expect(host.textContent).toContain('b-0001');
  results.multiVaultSearchAgain = await measure(vault, async () => {
    await clickEl(multiBox(host));
    await clickEl(multiBox(host));
  });
  await clickEl(multiBox(host));
  await typeSearch(host, '');
  await idle(vault);

  // 5. Glisser-déposer d'une entrée vers un autre coffre
  results.dragDropToOtherVault = await measure(vault, async () => {
    const dt = fakeDataTransfer();
    await dispatchDrag(rowByName(host, 'e-0002'), 'dragstart', dt);
    await dispatchDrag(engineCard(host, 'Gamma'), 'drop', dt);
    await flush(60);
  });
  expect(vault.isLive('Gamma', 'e-0002')).toBe(true);
  expect(vault.isLive('Alpha', 'e-0002')).toBe(false);
  expect(rowByName(host, 'e-0002')).toBeNull();
  expect(lastExtensionState().secrets).toContain('Gamma/e-0002:p2');
  expect(lastExtensionState().secrets).not.toContain('Alpha/e-0002:p2');

  if (process.env.REQCOUNT_OUT) fs.writeFileSync(process.env.REQCOUNT_OUT, JSON.stringify(results, null, 2));

  // Bornes : quelques listages (21 pour Alpha) et les seules entrées touchées, jamais tout le coffre
  expect(results.saveOne.reads).toBeLessThan(15);
  expect(results.saveOne.total).toBeLessThan(60);
  expect(results.switchBackToAlpha.reads).toBeLessThan(5);
  expect(results.switchBackToAlpha.total).toBeLessThan(30);
  expect(results.showDeletedOn.reads).toBeLessThanOrEqual(DELETED.length + 2);
  expect(results.showDeletedOff.reads).toBeLessThan(3);
  expect(results.multiVaultSearchAgain.reads).toBeLessThan(5);
  expect(results.dragDropToOtherVault.reads).toBeLessThan(20);
  expect(results.dragDropToOtherVault.total).toBeLessThan(80);
});
