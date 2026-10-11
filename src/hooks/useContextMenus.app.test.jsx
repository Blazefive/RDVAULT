// ========================================
// TESTS : menus contextuels dans l'App réelle — réponse tardive d'un clic droit sur une ligne (APP-3)
// ========================================
// Même session : un clic droit sur une ligne dont la vérification TOTP est lente, puis un clic droit sur
// la zone vide du tableau ou sur un coffre. La réponse tardive ne remplace plus le menu ouvert ensuite.
import fr from '../locales/fr.json';
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login,
  rowByName, rightClick, quiet,
} from './testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

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

function gatedVault() {
  const gate = { pending: [], on: false };
  const vault = setupVault({
    delayFor: (method, u) => {
      if (gate.on && method === 'get' && /\/v1\/TOTP\//.test(u)) return new Promise(r => gate.pending.push(r));
      return null;
    },
  });
  const release = async () => {
    await act(async () => { gate.pending.splice(0).forEach(r => r()); });
    await flush(40);
  };
  return { vault, gate, release };
}

const menus = () => Array.from(document.querySelectorAll('.context-menu'));
const menuLabels = () => menus().map(m => m.getAttribute('aria-label'));

async function aliceWithSlowRowMenu(vault, gate) {
  vault.addEngine('users/alice/perso');
  vault.writeRaw('users/alice/perso', 'banque', { Username: 'alice', Password: 'MDP-ALICE' });
  vault.addTotp('PERSO-banque');
  await renderApp(root);
  await login(host, 'alice');
  gate.on = true;
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  gate.on = false;
  expect(menus()).toHaveLength(0);
}

test('clic droit lent sur une ligne puis sur la zone vide : le menu « Nouvelle entrée » reste affiché', async () => {
  const { vault, gate, release } = gatedVault();
  await aliceWithSlowRowMenu(vault, gate);
  await rightClick(host.querySelector('table.secrets-table'));
  expect(menuLabels()).toEqual([fr.toolbar.newEntry]);
  await release();
  expect(menuLabels()).toEqual([fr.toolbar.newEntry]);
});

test('clic droit lent sur une ligne puis sur le coffre : le menu du coffre reste le seul menu', async () => {
  const { vault, gate, release } = gatedVault();
  await aliceWithSlowRowMenu(vault, gate);
  await rightClick(host.querySelector('.engine-card.active'));
  expect(menus()).toHaveLength(1);
  await release();
  expect(menus()).toHaveLength(1);
  expect(menuLabels()).not.toContain('banque');
});

test('témoin : clic droit lent sur une ligne seul, son menu s\'ouvre à la réponse', async () => {
  const { vault, gate, release } = gatedVault();
  await aliceWithSlowRowMenu(vault, gate);
  await release();
  expect(menuLabels()).toEqual(['banque']);
});
