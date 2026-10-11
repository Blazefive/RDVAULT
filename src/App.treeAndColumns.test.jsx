// ========================================
// TESTS : App.jsx — arborescence, mots de passe révélés, colonnes, partage reçu
// ========================================
// App réel, axios branché sur le faux coffre du projet (src/hooks/testUtils/fakeVault.js).
// - TREE-10 : un dossier nommé « constructor », « toString », « __proto__ »… faisait planter tout
//   le rendu en vue arborescence (fenêtre vide à chaque connexion).
// - TREE-18 : une entrée nommée « constructor », « valueOf »… s'affichait EN CLAIR sans clic sur l'œil.
// - TREE-20 : double-clic sur la poignée d'une colonne → toast « Copié » sans aucune copie.
// - Lien de partage RBI (confirmPendingShare) : motif d'échec traduit (rbiLaunchErrorMessage).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from './App.jsx';
import { I18nProvider } from './i18n.js';
import fr from './locales/fr.json';
import { createFakeVault } from './hooks/testUtils/fakeVault';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

function setupVault({ unwrap } = {}) {
  const vault = createFakeVault();
  const route = (method, fn) => (url, body) => {
    const u = String(url);
    if (method === 'post' && u.includes('/v1/auth/ldap/login/')) {
      return Promise.resolve({ status: 200, data: { auth: { client_token: 'tok-' + Math.random().toString(36).slice(2) } } });
    }
    if (method === 'post' && u.includes('/v1/sys/capabilities-self')) {
      const p = body?.paths?.[0];
      return Promise.resolve({ status: 200, data: { data: { [p]: ['create', 'read', 'update', 'delete', 'list'] } } });
    }
    if (method === 'post' && u.includes('/v1/sys/wrapping/unwrap') && unwrap) {
      return Promise.resolve({ status: 200, data: { data: unwrap } });
    }
    return fn(u, body);
  };
  axios.get.mockImplementation(route('get', vault.axios.get));
  axios.post.mockImplementation(route('post', vault.axios.post));
  axios.put.mockImplementation(route('put', vault.axios.put));
  axios.delete.mockImplementation(route('delete', vault.axios.delete));
  return vault;
}

async function flush(rounds = 60) {
  for (let i = 0; i < rounds; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
}
function setInput(el, value) {
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root; let host; let errSpy;
beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  window.electronSync = { writeState: jest.fn(async () => ({ success: true })) };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  errSpy = jest.spyOn(console, 'error');
});
afterEach(() => {
  try { act(() => root.unmount()); } catch { /* rendu déjà démonté */ }
  document.body.innerHTML = '';
  delete window.electronSync;
  delete window.electronRBI;
  errSpy.mockRestore();
  jest.useRealTimers();
});

async function startApp() {
  await act(async () => { mountInRoot(root, <I18nProvider defaultLang="fr"><App /></I18nProvider>); });
  await flush();
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], 'alice'); });
  await act(async () => { setInput(inputs[1], 'motdepasse-maitre'); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(120);
}

const rowNames = () => Array.from(host.querySelectorAll('table.secrets-table tbody tr'))
  .map(tr => tr.querySelector('td')?.textContent.trim());
const toastText = () => document.querySelector('.toast')?.textContent || '';

describe('TREE-10 — vue arborescence et dossiers nommés comme une propriété d\'Object.prototype', () => {
  test('dossiers « constructor », « toString » et « __proto__ » : application affichée, dossiers navigables', async () => {
    localStorage.setItem('rdvault-tree-view-enabled', 'true');
    errSpy.mockImplementation(() => {});
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'prod/web', { Username: 'u', Password: 'p' });
    vault.writeRaw('Alpha', 'constructor/serveur', { Username: 'u2', Password: 'p2' });
    vault.writeRaw('Alpha', 'toString/db', { Username: 'u3', Password: 'p3' });
    vault.writeRaw('Alpha', '__proto__/x', { Username: 'u4', Password: 'p4' });
    await startApp();

    expect(host.querySelector('.sidebar')).not.toBeNull(); // avant : DOM de l'application vide
    expect(rowNames().sort()).toEqual(['📁 __proto__', '📁 constructor', '📁 prod', '📁 toString']);
    const folder = Array.from(host.querySelectorAll('tr.folder-row')).find(tr => tr.textContent.includes('constructor'));
    await act(async () => { folder.click(); });
    await flush(10);
    expect(rowNames()).toEqual(['serveur']);
  });
});

describe('TREE-18 — entrée nommée comme une propriété d\'Object.prototype', () => {
  test('« constructor » et « valueOf » restent masqués sans clic ; l\'œil les révèle puis les masque', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'constructor', { Username: 'u', Password: 'Visible-Sans-Clic!' });
    vault.writeRaw('Alpha', 'valueOf', { Username: 'u', Password: 'Autre-Secret!' });
    vault.writeRaw('Alpha', 'normal', { Username: 'u', Password: 'Masque-Normal!' });
    await startApp();

    const rowOf = (name) => Array.from(host.querySelectorAll('table.secrets-table tbody tr'))
      .find(tr => tr.querySelector('td').textContent.trim() === name);
    const pwdText = (name) => rowOf(name).querySelectorAll('td')[2].textContent;
    const eye = (name) => rowOf(name).querySelector('.btn-action-view');
    expect(document.body.textContent).not.toContain('Visible-Sans-Clic!'); // avant : affiché en clair
    expect(document.body.textContent).not.toContain('Autre-Secret!');
    expect(eye('constructor').getAttribute('aria-pressed')).toBe('false');

    await act(async () => { eye('normal').click(); });
    expect(pwdText('normal')).toContain('Masque-Normal!');
    expect(pwdText('constructor')).not.toContain('Visible-Sans-Clic!'); // révéler une autre entrée n'y touche pas
    await act(async () => { eye('constructor').click(); });
    expect(pwdText('constructor')).toContain('Visible-Sans-Clic!');
    await act(async () => { eye('constructor').click(); });
    expect(pwdText('constructor')).not.toContain('Visible-Sans-Clic!');
    expect(eye('constructor').getAttribute('aria-pressed')).toBe('false');
  });
});

describe('TREE-20 — ajustement automatique de la largeur d\'une colonne', () => {
  test('double-clic sur la poignée : aucun toast « Copié »', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'a1', { Username: 'u', Password: 'p' });
    await startApp();
    await act(async () => { jest.advanceTimersByTime(5000); }); // toasts de connexion expirés
    const resizer = host.querySelector('th .column-resizer');
    await act(async () => { resizer.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true })); });
    expect(toastText()).not.toContain(fr.toast.copied);
    expect(JSON.parse(localStorage.getItem('rdvault-column-widths')).name).toBeGreaterThanOrEqual(100);
  });
});

describe('Partage RBI reçu par lien (confirmPendingShare)', () => {
  test('échec « page hors du domaine » : message traduit, pas le texte brut du processus principal', async () => {
    setupVault({ unwrap: { url: 'https://site.example/login', username: 'bob', password: 'pw' } }).addEngine('Alpha');
    let shareCb = null;
    const launchSession = jest.fn(async () => ({ success: false, error: 'Page de connexion hors du domaine de l\'entrée', code: 'RBI_FOREIGN_ORIGIN' }));
    window.electronRBI = { onShareReceived: (cb) => { shareCb = cb; return () => {}; }, launchSession };
    await startApp();

    await act(async () => { await shareCb('hvs.partage-valide'); });
    await flush(10);
    const confirm = Array.from(document.querySelectorAll('[role="dialog"] button')).find(b => b.textContent.trim() === fr.confirm.open);
    await act(async () => { confirm.click(); });
    await flush(10);
    expect(launchSession).toHaveBeenCalled();
    expect(toastText()).toContain(fr.error.rbiForeignOrigin);
    expect(toastText()).not.toContain('Page de connexion hors du domaine de l\'entrée');
  });
});
