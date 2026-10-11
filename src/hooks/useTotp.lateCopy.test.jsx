// ========================================
// TESTS : « Copier TOTP » dans l'App réelle — réponse arrivée après la déconnexion (APP-3, useTotp)
// ========================================
// App réel + faux coffre. Le code TOTP demandé par le menu contextuel d'alice répond après sa
// déconnexion (pendant l'écran de connexion, ou après la connexion de bob) : il n'est jamais copié dans
// le presse-papiers. Témoin : dans la même session, le code est copié.
import fr from '../locales/fr.json';
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login, logout,
  activeEngine, rowByName, rightClick, menuItem, quiet,
} from './testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const COPY_TOTP = fr.contextMenu.copyField.replace('{{field}}', 'TOTP');

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

// Requêtes TOTP (/v1/TOTP/…) retenues par une barrière tant que gate.on
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

async function switchToBob(vault) {
  for (const name of Array.from(vault.engines.keys())) vault.engines.delete(name);
  vault.addEngine('users/bob/perso');
  vault.writeRaw('users/bob/perso', 'wifi', { Username: 'bob', Password: 'MDP-BOB' });
  await login(host, 'bob');
  expect(activeEngine(host)).toBe('users/bob/perso');
}

// alice : entrée « banque » avec un TOTP ; clic droit puis « Copier TOTP » retenu par la barrière
async function aliceAsksForTotpCopy(vault, gate) {
  vault.addEngine('users/alice/perso');
  vault.writeRaw('users/alice/perso', 'banque', { Username: 'alice', Password: 'MDP-ALICE' });
  vault.addTotp('PERSO-banque');
  await renderApp(root);
  await login(host, 'alice');
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  const item = menuItem(COPY_TOTP);
  expect(item).not.toBeNull();
  gate.on = true;
  await act(async () => { item.click(); });
  await flush(5);
  expect(gate.pending.length).toBeGreaterThan(0);
}

test('code TOTP reçu pendant l\'écran de connexion : jamais copié, ni chez bob ensuite', async () => {
  const { vault, gate, release } = gatedVault();
  await aliceAsksForTotpCopy(vault, gate);
  await logout(host);
  await release();
  gate.on = false;
  expect(window.electronClipboard.copySecure).not.toHaveBeenCalled();

  await switchToBob(vault);
  expect(window.electronClipboard.copySecure).not.toHaveBeenCalled();
});

test('code TOTP reçu après la connexion de bob : jamais copié dans sa session', async () => {
  const { vault, gate, release } = gatedVault();
  await aliceAsksForTotpCopy(vault, gate);
  await logout(host);
  gate.on = false;
  await switchToBob(vault);
  await release();
  expect(window.electronClipboard.copySecure).not.toHaveBeenCalled();
  expect(document.body.textContent).not.toContain('123456');
});

test('témoin : même session, le code TOTP est copié', async () => {
  const { vault, gate, release } = gatedVault();
  await aliceAsksForTotpCopy(vault, gate);
  gate.on = false;
  await release();
  expect(window.electronClipboard.copySecure).toHaveBeenCalledWith('123456', expect.any(Number));
});
