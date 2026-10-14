// ========================================
// TESTS : tableau virtualisé dans l'App réelle (faux coffre de 400 entrées)
// ========================================
// Au-delà de 150 lignes, seules les lignes visibles (+ marge) sont dans le DOM. Vérifié ici de bout en
// bout dans l'App : nombre de lignes rendues, menu contextuel d'une ligne atteinte au clavier (Fin),
// sélection par plage (Maj+clic) qui inclut des lignes jamais rendues, puis glisser de cette sélection :
// toutes les entrées sélectionnées partent, pas seulement celles du DOM.
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login,
  tableRows, rightClick, fakeDataTransfer, dispatchDrag, quiet,
} from '../../hooks/testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const N = 400;
const name = (i) => `entree-${String(i).padStart(4, '0')}`;
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

async function bigVault() {
  const vault = setupVault();
  vault.addEngine('users/alice/perso');
  for (let i = 0; i < N; i++) vault.writeRaw('users/alice/perso', name(i), { Username: `u${i}`, Password: `p${i}`, Tags: 'prod' });
  vault.writeRaw('users/alice/perso', 'archives/ancienne', { Username: 'x', Password: 'y' });
  await renderApp(root);
  await login(host, 'alice');
  await flush(200);
  return vault;
}
const rowAt = (i) => host.querySelector(`table.secrets-table tbody tr[aria-rowindex="${i + 2}"]`);
const keydown = (el, key, opts = {}) => act(() => { el.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts })); });

test('400 entrées : tableau fenêtré (aria-rowcount = total), quelques dizaines de lignes dans le DOM', async () => {
  await bigVault();
  const table = host.querySelector('table.secrets-table');
  expect(Number(table.getAttribute('aria-rowcount'))).toBe(N + 2); // 401 entrées + en-tête
  const rendered = tableRows(host).filter(tr => tr.hasAttribute('aria-rowindex'));
  expect(rendered.length).toBeGreaterThan(5);
  expect(rendered.length).toBeLessThan(80);
});

test('Fin au clavier puis clic droit : menu contextuel de la dernière entrée (jamais rendue au départ)', async () => {
  await bigVault();
  const total = Number(host.querySelector('table.secrets-table').getAttribute('aria-rowcount')) - 1;
  expect(rowAt(total - 1)).toBeNull();
  act(() => { rowAt(0).focus(); });
  keydown(rowAt(0), 'End');
  await flush(5);
  const last = rowAt(total - 1);
  expect(document.activeElement).toBe(last);
  await rightClick(last);
  expect(document.querySelector('.context-menu')).not.toBeNull();
  expect(document.querySelector('.context-menu').getAttribute('aria-label')).toBe(last.querySelector('td.cell-name').textContent.replace('✓', '').trim());
});

test('Maj+clic sur une ligne atteinte au clavier : la plage inclut les lignes jamais rendues ; le glisser les emporte toutes', async () => {
  const vault = await bigVault();
  const first = rowAt(0);
  const firstName = first.querySelector('td.cell-name').textContent.trim();
  act(() => { first.click(); });
  await flush(5);
  act(() => { rowAt(0).focus(); });
  keydown(rowAt(0), 'End');
  await flush(5);
  // Flèche haut : avant-dernière ligne rendue et focalisée (jsdom ne fait pas défiler la fenêtre :
  // la ligne focalisée est rendue parce qu'épinglée)
  keydown(document.activeElement, 'ArrowUp');
  await flush(5);
  const total = Number(host.querySelector('table.secrets-table').getAttribute('aria-rowcount')) - 1;
  expect(document.activeElement).toBe(rowAt(total - 2));
  // Maj+clic sur l'avant-dernière ligne : plage 0 → total-2
  act(() => { rowAt(total - 2).dispatchEvent(new MouseEvent('click', { bubbles: true, shiftKey: true })); });
  await flush(5);
  expect(rowAt(total - 2).className).toBe('row-selected');
  // Glisser une ligne sélectionnée : les données du glisser portent toute la sélection
  const dt = fakeDataTransfer();
  await dispatchDrag(rowAt(total - 2), 'dragstart', dt);
  const data = JSON.parse(dt.getData('application/json'));
  expect(data.secrets.length).toBe(total - 1);
  expect(data.secrets).toContain(firstName);
  expect(data.secrets).toContain(name(200)); // jamais rendue
  // Dépôt sur la carte d'un autre coffre absente ici : fin du glisser, la ligne source reste connectée
  const src = rowAt(total - 2);
  await dispatchDrag(src, 'dragend', dt);
  expect(src.isConnected).toBe(true);
  expect(vault.latest('users/alice/perso', name(200))).toBeTruthy();
});
