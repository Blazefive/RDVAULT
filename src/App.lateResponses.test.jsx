// ========================================
// TESTS : App.jsx — réponses tardives après la fin de la session (APP-3)
// ========================================
// App réel + faux coffre. Une requête lente (vérification TOTP, code TOTP, unwrap d'un partage) lancée
// pendant la session d'alice répond après sa déconnexion : rien ne doit s'afficher sur l'écran de
// connexion ni dans la session suivante (bob), et aucune session RBI ne doit être lancée. Un clic droit
// suivi d'un autre : seul le dernier ouvre son menu.
import fr from './locales/fr.json';
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login, logout,
  activeEngine, rowByName, rightClick, menuItem, quiet, setInput,
} from './hooks/testUtils/appHarness.jsx';

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
  delete window.electronRBI;
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

// bob se connecte : un seul coffre, alice n'y a plus accès
async function switchToBob(vault, bobSecrets) {
  for (const name of Array.from(vault.engines.keys())) vault.engines.delete(name);
  vault.addEngine('users/bob/perso');
  for (const [k, v] of Object.entries(bobSecrets)) vault.writeRaw('users/bob/perso', k, v);
  await login(host, 'bob');
  expect(activeEngine(host)).toBe('users/bob/perso');
}

test('menu contextuel d\'alice en attente pendant la déconnexion : absent de la session de bob', async () => {
  const { vault, gate, release } = gatedVault();
  vault.addEngine('users/alice/perso');
  vault.writeRaw('users/alice/perso', 'banque', { Username: 'alice', Password: 'MDP-ALICE' });
  await renderApp(root);
  await login(host, 'alice');

  gate.on = true;
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  await logout(host);
  gate.on = false;
  await switchToBob(vault, { wifi: { Username: 'bob', Password: 'MDP-BOB' } });

  await release();
  expect(document.querySelector('.context-menu')).toBeNull();
  expect(window.electronClipboard.copySecure).not.toHaveBeenCalled();
});

test('confirmation « Supprimer banque ? » d\'alice : jamais affichée chez bob, son « banque » reste intact', async () => {
  const { vault, gate, release } = gatedVault();
  vault.addEngine('users/alice/perso');
  vault.writeRaw('users/alice/perso', 'banque', { Username: 'alice', Password: 'MDP-ALICE' });
  await renderApp(root);
  await login(host, 'alice');

  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  gate.on = true;
  await act(async () => { menuItem(fr.contextMenu.delete).click(); });
  await flush(10);
  await logout(host);
  gate.on = false;
  await switchToBob(vault, { banque: { Username: 'bob', Password: 'MDP-BOB-BANQUE' } });

  await release();
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  expect(vault.isLive('users/bob/perso', 'banque')).toBe(true);
});

test('réponses arrivées pendant l\'écran de connexion : ni menu ni code TOTP à la connexion suivante', async () => {
  const { vault, gate, release } = gatedVault();
  vault.addEngine('users/alice/perso');
  vault.writeRaw('users/alice/perso', 'banque', { Username: 'alice', Password: 'MDP-ALICE' });
  vault.addTotp('USERS/ALICE/PERSO-banque');
  vault.addTotp('PERSO-banque');
  await renderApp(root);
  await login(host, 'alice');

  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  gate.on = true;
  await act(async () => { menuItem(fr.contextMenu.showTotp).click(); });
  await flush(5);
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  await logout(host);
  await release();
  gate.on = false;
  expect(document.querySelector('.context-menu')).toBeNull();
  expect(document.querySelector('[role="dialog"]')).toBeNull();

  await switchToBob(vault, { wifi: { Username: 'bob', Password: 'MDP-BOB' } });
  expect(document.querySelector('.context-menu')).toBeNull();
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  expect(document.body.textContent).not.toContain('123456');
});

test('lien de partage : unwrap lent puis déconnexion → aucune confirmation, aucune session RBI', async () => {
  const axios = require('axios').default;
  const vault = setupVault();
  vault.addEngine('Alpha');
  let shareCb = null;
  const launches = [];
  window.electronRBI = {
    onShareReceived: (cb) => { shareCb = cb; return () => { if (shareCb === cb) shareCb = null; }; },
    launchSession: async (opts) => { launches.push(opts); return { success: true }; },
  };
  const post = axios.post.getMockImplementation();
  let releaseUnwrap = null;
  axios.post.mockImplementation((url, body, cfg) => {
    if (String(url).includes('/v1/sys/wrapping/unwrap')) {
      return new Promise((resolve) => {
        releaseUnwrap = () => resolve({ status: 200, data: { data: { url: 'https://intranet.example', username: 'svc', password: 'MDP-PARTAGE' } } });
      });
    }
    return post(url, body, cfg);
  });
  await renderApp(root);
  await login(host, 'alice');
  const cb = shareCb;
  await act(async () => { cb('s.' + 'a'.repeat(24)); });
  await flush(5);
  await logout(host);
  await act(async () => { releaseUnwrap(); });
  await flush(20);
  expect(document.querySelector('[role="dialog"]')).toBeNull();

  await login(host, 'bob');
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  expect(launches).toEqual([]);
});

test('lien de partage reçu dans la session : confirmation affichée puis session RBI lancée (témoin)', async () => {
  const axios = require('axios').default;
  const vault = setupVault();
  vault.addEngine('Alpha');
  let shareCb = null;
  const launches = [];
  window.electronRBI = {
    onShareReceived: (cb) => { shareCb = cb; return () => { if (shareCb === cb) shareCb = null; }; },
    launchSession: async (opts) => { launches.push(opts); return { success: true }; },
  };
  const post = axios.post.getMockImplementation();
  axios.post.mockImplementation((url, body, cfg) => {
    if (String(url).includes('/v1/sys/wrapping/unwrap')) {
      return Promise.resolve({ status: 200, data: { data: { url: 'https://intranet.example', username: 'svc', password: 'MDP-PARTAGE' } } });
    }
    return post(url, body, cfg);
  });
  await renderApp(root);
  await login(host, 'alice');
  await act(async () => { shareCb('s.' + 'b'.repeat(24)); });
  await flush(20);
  const dialog = document.querySelector('[role="dialog"]');
  expect(dialog).not.toBeNull();
  const open = Array.from(dialog.querySelectorAll('button')).find(b => b.textContent.trim() === fr.confirm.open);
  await act(async () => { open.click(); });
  await flush(20);
  expect(launches.map(l => l.url)).toEqual(['https://intranet.example']);
});

test('« Session Sécurisée » : code TOTP lent puis déconnexion → aucune session RBI lancée', async () => {
  const { vault, gate, release } = gatedVault();
  const launches = [];
  window.electronRBI = { launchSession: async (opts) => { launches.push(opts); return { success: true }; } };
  vault.addEngine('Alpha');
  vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'MDP-ALICE', URL: 'https://banque.example' });
  vault.addTotp('ALPHA-banque');
  await renderApp(root);
  await login(host, 'alice');

  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  gate.on = true;
  await act(async () => { menuItem(fr.contextMenu.openSecureBrowser).click(); });
  await flush(5);
  await logout(host);
  gate.on = false;
  await release();
  expect(launches).toEqual([]);
});

test('deux clics droits (le premier répond après le second) : le menu affiché est celui du dernier clic', async () => {
  const { vault, gate, release } = gatedVault();
  vault.addEngine('Alpha');
  vault.writeRaw('Alpha', 'banque', { Username: 'a', Password: 'MDP-BANQUE' });
  vault.writeRaw('Alpha', 'wifi', { Username: 'w', Password: 'MDP-WIFI' });
  await renderApp(root);
  await login(host, 'alice');
  gate.on = true;
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  gate.on = false;
  await rightClick(rowByName(host, 'wifi').querySelector('td.cell-name'));
  expect(document.querySelector('.context-menu')?.getAttribute('aria-label')).toBe('wifi');
  await release();
  expect(document.querySelector('.context-menu')?.getAttribute('aria-label')).toBe('wifi');
});

test('session inchangée : clic droit lent puis réponse → menu ouvert normalement (témoin)', async () => {
  const { vault, gate, release } = gatedVault();
  vault.addEngine('Alpha');
  vault.writeRaw('Alpha', 'banque', { Username: 'a', Password: 'MDP-BANQUE' });
  await renderApp(root);
  await login(host, 'alice');
  gate.on = true;
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  expect(document.querySelector('.context-menu')).toBeNull();
  gate.on = false;
  await release();
  expect(document.querySelector('.context-menu')?.getAttribute('aria-label')).toBe('banque');
});

test('connexion : un état posé pendant l\'écran de connexion est remis à zéro (réinitialisation à chaque jeton)', async () => {
  const vault = setupVault();
  vault.addEngine('Alpha');
  vault.writeRaw('Alpha', 'banque', { Username: 'a', Password: 'MDP-BANQUE' });
  await renderApp(root);
  await login(host, 'alice');
  // Fiche ouverte puis déconnexion : fermée, et rien ne réapparaît à la connexion suivante
  await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
  await act(async () => { menuItem(fr.contextMenu.edit).click(); });
  await flush(20);
  expect(document.querySelector('[role="dialog"]')).not.toBeNull();
  await logout(host);
  expect(document.querySelector('[role="dialog"]')).toBeNull();
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], 'bob'); });
  await login(host, 'bob');
  expect(document.querySelector('[role="dialog"]')).toBeNull();
});
