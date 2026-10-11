// ========================================
// TESTS : App.jsx — recherche multi-coffres : les actions visent le coffre DE L'ENTRÉE
// ========================================
// App réel, axios branché sur le faux coffre du projet (src/hooks/testUtils/fakeVault.js, même
// sémantique que le coffre local), ponts Electron simulés.
// - SEARCH-9 / SEARCH-31 : « Modifier », « Supprimer », TOTP, glisser-déposer… sur un résultat d'un
//   AUTRE coffre agissaient sur le coffre SÉLECTIONNÉ (copie écrite dans ce coffre, entrée homonyme
//   supprimée avec sa graine TOTP, identifiants personnels écrits dans un coffre partagé).
// - SEARCH-16 : recherche vidée → case « tous les coffres » cochée ET désactivée, arborescence perdue.
// - SEARCH-17 : anti-rebond non annulé au changement de coffre → filtre fantôme, tableau vide.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from './App.jsx';
import { I18nProvider } from './i18n.js';
import fr from './locales/fr.json';
import { createFakeVault } from './hooks/testUtils/fakeVault';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const fill = (s, vars) => s.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k]);

// Faux coffre branché sur axios : connexion LDAP et droits complets simulés
function setupVault() {
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
  const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root; let host;
beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  window.electronSync = { writeState: jest.fn(async () => ({ success: true })) };
  window.electronClipboard = { copySecure: jest.fn(async () => ({ success: true })), clearNow: jest.fn(async () => ({ success: true })) };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  delete window.electronSync;
  delete window.electronClipboard;
  delete window.electronRBI;
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

const activeEngine = () => host.querySelector('.engine-card.active .engine-name')?.textContent.trim();
const engineCard = (name) => Array.from(host.querySelectorAll('.engine-card'))
  .find(c => c.querySelector('.engine-name')?.textContent.trim() === name);
const multiBox = () => host.querySelector('.toolbar label.checkbox-label input[type="checkbox"]');
const rowCells = () => Array.from(host.querySelectorAll('table.secrets-table tbody tr'))
  .map(tr => Array.from(tr.querySelectorAll('td')).map(td => td.textContent.trim()));
const menuItem = (text) => Array.from(document.querySelectorAll('.context-menu .context-menu-item'))
  .find(b => b.textContent.includes(text)) || null;
const toastText = () => document.querySelector('.toast')?.textContent || '';

async function typeSearch(text) {
  await act(async () => { setInput(host.querySelector('.search-input'), text); });
  await act(async () => { jest.advanceTimersByTime(400); });
  await flush();
}

async function searchAllVaults(term) {
  await typeSearch(term);
  expect(multiBox().disabled).toBe(false);
  await act(async () => { multiBox().click(); });
  await flush(120);
}

// Ligne de la recherche multi-coffres dont la colonne « coffre » vaut engineName
function rowOf(engineName) {
  return Array.from(host.querySelectorAll('table.secrets-table tbody tr'))
    .find(tr => tr.querySelectorAll('td')[1]?.textContent.trim() === engineName) || null;
}

async function openRowMenu(engineName) {
  const cell = rowOf(engineName).querySelector('td.cell-name');
  await act(async () => {
    cell.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 10, clientY: 10 }));
  });
  await flush();
}

const writesTo = (vault, engine) => vault.calls
  .filter(c => c.method === 'post' && (c.path.startsWith(`v1/${engine}/data/`) || c.path.startsWith(`v1/${engine}/delete/`)))
  .map(c => c.path);

describe('SEARCH-9 / SEARCH-31 — actions sur un résultat d\'un autre coffre', () => {
  test('« Modifier » un résultat de « Beta » modifie Beta/banque ; rien n\'est écrit dans le coffre sélectionné « Alpha »', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'autre', { Username: 'x', Password: 'y' });
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'old-pass', URL: 'https://banque.example' });
    await startApp();
    expect(activeEngine()).toBe('Alpha');

    await searchAllVaults('banque');
    expect(rowOf('Beta')).not.toBeNull();
    await openRowMenu('Beta');
    // Libellé explicite : les actions ouvrent le coffre de l'entrée
    expect(document.querySelector('.context-menu').textContent).toContain(fill(fr.contextMenu.otherVaultHint, { engine: 'Beta' }));
    await act(async () => { menuItem(fr.contextMenu.edit).click(); });
    await flush(60);

    // Le coffre de l'entrée est ouvert ; la recherche est conservée, la recherche multi-coffres coupée
    expect(activeEngine()).toBe('Beta');
    expect(multiBox().checked).toBe(false);
    expect(host.querySelector('.search-input').value).toBe('banque');

    const modal = document.querySelector('[role="dialog"]');
    const pwd = Array.from(modal.querySelectorAll('input')).find(i => i.value === 'old-pass');
    await act(async () => { setInput(pwd, 'NEW-pass-2026'); });
    const save = Array.from(modal.querySelectorAll('button')).find(b => b.textContent.trim() === fr.editSecret.save);
    await act(async () => { save.click(); });
    await flush(150);

    expect(vault.latest('Beta', 'banque').version).toBe(2);
    expect(vault.latest('Beta', 'banque').data.Password).toBe('NEW-pass-2026');
    expect(vault.latest('Alpha', 'banque')).toBeNull(); // avant : copie complète créée dans Alpha
    expect(writesTo(vault, 'Alpha')).toEqual([]);
    expect(rowCells().map(r => r[0])).toContain('banque');
  });

  test('« Supprimer » un résultat de « Beta » supprime Beta/banque ; Alpha/banque et la graine ALPHA-banque restent intactes', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.addTotp('ALPHA-banque');
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    vault.addTotp('BETA-banque');
    await startApp();

    await searchAllVaults('banque');
    await openRowMenu('Beta');
    await act(async () => { menuItem(fr.contextMenu.delete).click(); });
    await flush(60);
    expect(activeEngine()).toBe('Beta'); // confirmation affichée dans le coffre de l'entrée
    const dialog = document.querySelector('[role="dialog"]');
    await act(async () => { dialog.querySelector('.btn-danger').click(); });
    await flush(150);

    expect(vault.isLive('Beta', 'banque')).toBe(false);
    expect(vault.isLive('Alpha', 'banque')).toBe(true);       // avant : supprimée à la place
    expect(vault.totp.has('ALPHA-banque')).toBe(true);        // avant : graine TOTP détruite
    expect(writesTo(vault, 'Alpha')).toEqual([]);
    expect(vault.calls.filter(c => c.method === 'delete' && c.path.endsWith('ALPHA-banque'))).toEqual([]);
  });

  test('« Dupliquer » un résultat de « Beta » crée « banque_copie » dans Beta, rien dans Alpha', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    await startApp();

    await searchAllVaults('banque');
    await openRowMenu('Beta');
    await act(async () => { menuItem(fr.contextMenu.duplicate).click(); });
    await flush(60);
    const modal = document.querySelector('[role="dialog"]');
    expect(Array.from(modal.querySelectorAll('input')).some(i => i.value === 'banque_copie')).toBe(true);
    const save = Array.from(modal.querySelectorAll('button')).find(b => b.textContent.trim() === fr.editSecret.save);
    await act(async () => { save.click(); });
    await flush(150);
    expect(vault.latest('Beta', 'banque_copie').data).toEqual(expect.objectContaining({ Username: 'bob', Password: 'beta-pass' }));
    expect(vault.isLive('Beta', 'banque')).toBe(true);
    expect(writesTo(vault, 'Alpha')).toEqual([]);
  });

  test('entrée disparue de son coffre entre la recherche et l\'action : rien n\'est fait, message explicite', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    await startApp();

    await searchAllVaults('banque');
    vault.engines.get('Beta').secrets.delete('banque'); // supprimée par un autre poste
    await openRowMenu('Beta');
    await act(async () => { menuItem(fr.contextMenu.edit).click(); });
    await flush(80);
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(toastText()).toContain(fill(fr.error.entryNotInVault, { name: 'banque', engine: 'Beta' }));
    expect(writesTo(vault, 'Alpha')).toEqual([]);
    expect(writesTo(vault, 'Beta')).toEqual([]);
  });

  test('sens inverse : depuis le coffre partagé sélectionné, modifier un résultat PERSONNEL n\'écrit rien dans le coffre partagé', async () => {
    const vault = setupVault();
    vault.addEngine('a-equipe');
    vault.addEngine('users/alice/Perso');
    vault.writeRaw('a-equipe', 'wiki', { Username: 'equipe', Password: 'wiki-pass' });
    vault.writeRaw('users/alice/Perso', 'banque', { Username: 'alice.perso', Password: 'MDP-BANQUE-PERSO' });
    await startApp();
    await act(async () => { engineCard('a-equipe').click(); });
    await flush(60);
    expect(activeEngine()).toBe('a-equipe');

    await searchAllVaults('banque');
    await openRowMenu('users/alice/Perso');
    await act(async () => { menuItem(fr.contextMenu.edit).click(); });
    await flush(60);
    const modal = document.querySelector('[role="dialog"]');
    const pwd = Array.from(modal.querySelectorAll('input')).find(i => i.value === 'MDP-BANQUE-PERSO');
    await act(async () => { setInput(pwd, 'MDP-BANQUE-PERSO-2'); });
    const save = Array.from(modal.querySelectorAll('button')).find(b => b.textContent.trim() === fr.editSecret.save);
    await act(async () => { save.click(); });
    await flush(150);

    expect(vault.latest('a-equipe', 'banque')).toBeNull(); // avant : identifiants personnels dans le coffre partagé
    expect(writesTo(vault, 'a-equipe')).toEqual([]);
    expect(vault.latest('users/alice/Perso', 'banque').data.Password).toBe('MDP-BANQUE-PERSO-2');
  });

  test('« Afficher le code TOTP » d\'un résultat de « Beta » lit la clé BETA-banque, jamais ALPHA-banque', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.addTotp('ALPHA-banque');
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    vault.addTotp('BETA-banque');
    await startApp();

    await searchAllVaults('banque');
    await openRowMenu('Beta');
    const before = vault.calls.length;
    await act(async () => { menuItem(fr.contextMenu.showTotp).click(); });
    await flush(80);
    const totpCalls = vault.calls.slice(before).filter(c => c.path.startsWith('v1/TOTP/')).map(c => c.path);
    expect(totpCalls).toContain('v1/TOTP/code/BETA-banque');
    expect(totpCalls.some(p => p.endsWith('ALPHA-banque'))).toBe(false);
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
  });

  test('menu d\'un résultat de « Beta » : existence du TOTP vérifiée sur la clé de Beta (« Supprimer le TOTP » proposé à bon escient)', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.addTotp('ALPHA-banque'); // seule Alpha a un TOTP
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    await startApp();

    await searchAllVaults('banque');
    await openRowMenu('Beta');
    await flush(20);
    expect(menuItem(fr.contextMenu.deleteTotp)).toBeNull();
    expect(menuItem(fr.contextMenu.configurTotp).disabled).toBe(false);
    await openRowMenu('Alpha');
    await flush(20);
    expect(menuItem(fr.contextMenu.deleteTotp)).not.toBeNull();
  });

  test('session sécurisée depuis un résultat de « Beta » : TOTP de Beta, identifiants de Beta, coffre sélectionné inchangé', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.addTotp('ALPHA-banque');
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass', URL: 'https://banque.example' });
    vault.addTotp('BETA-banque');
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    await startApp();

    await searchAllVaults('banque');
    await openRowMenu('Beta');
    const before = vault.calls.length;
    await act(async () => { menuItem(fr.contextMenu.openSecureBrowser).click(); });
    await flush(40);
    const totpCalls = vault.calls.slice(before).filter(c => c.path.startsWith('v1/TOTP/')).map(c => c.path);
    expect(totpCalls).toEqual(['v1/TOTP/code/BETA-banque']);
    expect(launchSession).toHaveBeenCalledWith(expect.objectContaining({ username: 'bob', password: 'beta-pass', totp: '123456' }));
    expect(activeEngine()).toBe('Alpha'); // lecture seule : pas de changement de coffre
  });

  test('glisser un résultat de « Beta » depuis la recherche multi-coffres : refusé avec un message explicite', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    await startApp();

    await searchAllVaults('banque');
    const setData = jest.fn();
    const ev = new Event('dragstart', { bubbles: true, cancelable: true });
    ev.dataTransfer = { setData, setDragImage: jest.fn(), effectAllowed: '' };
    await act(async () => { rowOf('Beta').dispatchEvent(ev); });
    await flush(5);
    expect(ev.defaultPrevented).toBe(true);
    expect(setData).not.toHaveBeenCalled(); // avant : source = coffre sélectionné (Alpha)
    expect(toastText()).toContain(fill(fr.error.dragOtherVault, { engine: 'Beta' }));

    // Une ligne du coffre sélectionné reste déplaçable
    const ev2 = new Event('dragstart', { bubbles: true, cancelable: true });
    ev2.dataTransfer = { setData: jest.fn(), setDragImage: jest.fn(), effectAllowed: '' };
    await act(async () => { rowOf('Alpha').dispatchEvent(ev2); });
    expect(JSON.parse(ev2.dataTransfer.setData.mock.calls[0][1])).toEqual(expect.objectContaining({ secrets: ['banque'], sourceEngine: 'Alpha' }));
    await act(async () => { rowOf('Alpha').dispatchEvent(new Event('dragend', { bubbles: true })); });
  });

  test('« Ouvrir dans le coffre » : coffre de l\'entrée sélectionné, entrée visible, mots de passe révélés masqués', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'autre', { Username: 'x', Password: 'y' });
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    vault.writeRaw('Beta', 'mail', { Username: 'bob', Password: 'mail-pass' });
    await startApp();

    await searchAllVaults('banque');
    await openRowMenu('Beta');
    await act(async () => { menuItem(fill(fr.contextMenu.openInVault, { engine: 'Beta' })).click(); });
    await flush(80);
    expect(activeEngine()).toBe('Beta');
    expect(multiBox().checked).toBe(false);
    expect(rowCells().map(r => r[0])).toEqual(['banque']);
    expect(host.querySelector('.btn-action-view').getAttribute('aria-pressed')).toBe('false');
  });
});

describe('SEARCH-16 — recherche multi-coffres après avoir vidé la recherche', () => {
  test('la case se décoche, l\'arborescence et son bouton reviennent', async () => {
    localStorage.setItem('rdvault-tree-view-enabled', 'true');
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'prod/web', { Username: 'u', Password: 'p' });
    vault.writeRaw('Alpha', 'prod/db', { Username: 'u', Password: 'p' });
    vault.writeRaw('Beta', 'x', { Username: 'u', Password: 'p' });
    await startApp();
    const treeButton = () => Array.from(host.querySelectorAll('.toolbar button')).find(b => b.textContent.includes(fr.toolbar.listView));
    expect(treeButton()).toBeDefined();

    await searchAllVaults('web');
    expect(multiBox().checked).toBe(true);
    await typeSearch('');
    expect(multiBox().checked).toBe(false); // avant : cochée ET désactivée
    expect(treeButton()).toBeDefined();     // avant : bouton masqué
    expect(rowCells().map(r => r[0])).toEqual(['📁 prod']); // avant : liste à plat
  });
});

describe('SEARCH-17 — anti-rebond de la recherche et changement de coffre', () => {
  test('frappe puis changement de coffre en moins de 300 ms : le nouveau coffre s\'affiche sans filtre fantôme', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'a1', { Username: 'u', Password: 'p' });
    vault.writeRaw('Beta', 'b1', { Username: 'u', Password: 'p' });
    vault.writeRaw('Beta', 'b2', { Username: 'u', Password: 'p' });
    await startApp();

    await act(async () => { setInput(host.querySelector('.search-input'), 'a1'); });
    await act(async () => { jest.advanceTimersByTime(100); });
    await act(async () => { engineCard('Beta').click(); });
    await act(async () => { jest.advanceTimersByTime(400); });
    await flush(60);
    expect(activeEngine()).toBe('Beta');
    expect(host.querySelector('.search-input').value).toBe('');
    expect(rowCells().map(r => r[0])).toEqual(['b1', 'b2']); // avant : [] (filtre « a1 » rétabli)
  });

  test('frappe normale : la recherche s\'applique après 300 ms', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'a1', { Username: 'u', Password: 'p' });
    vault.writeRaw('Alpha', 'zz', { Username: 'u', Password: 'p' });
    await startApp();
    await typeSearch('a1');
    expect(rowCells().map(r => r[0])).toEqual(['a1']);
  });
});

// Clic sur l'URL d'un résultat « RBI uniquement » (handleUrlAction ne reçoit que le nom de l'entrée) :
// avant, la clé TOTP était toujours celle du coffre SÉLECTIONNÉ (KV-portail) → session lancée avec le
// TOTP d'une autre entrée, ou sans TOTP alors que l'entrée en a un.
describe('SEARCH-9 — clic sur l\'URL d\'un résultat « RBI uniquement » d\'un autre coffre', () => {
  const KV2 = { type: 'kv', options: { version: '2' } };
  function installRbiAxios(entries) {
    const ok = (data) => Promise.resolve({ status: 200, data });
    const notFound = () => Promise.reject(Object.assign(new Error('404'), { response: { status: 404, data: {} } }));
    axios.get.mockImplementation((url) => {
      const u = String(url);
      if (u.includes('/v1/auth/token/lookup-self')) return ok({ data: { entity_name: 'alice', policies: ['default', 'rbi-pol'] } });
      if (u.includes('/v1/sys/policies/acl/rbi-pol')) return ok({ data: { policy: '# RBI-ONLY\npath "SECURE/metadata/*" {\n  capabilities = ["list"]\n}\n' } });
      if (u.includes('/v1/sys/policies/acl/')) return ok({ data: { policy: '' } });
      if (u.includes('/v1/sys/internal/ui/mounts') || u.endsWith('/v1/sys/mounts')) return ok({ 'kv/': KV2, 'SECURE/': KV2 });
      const list = u.match(/\/v1\/(kv|SECURE)\/metadata\?list=true/);
      if (list) return ok({ data: { keys: Object.keys(entries[list[1]]) } });
      const data = u.match(/\/v1\/(kv|SECURE)\/data\/([^?]+)/);
      if (data && entries[data[1]][decodeURIComponent(data[2])]) return ok({ data: { data: entries[data[1]][decodeURIComponent(data[2])] } });
      if (u.includes('/v1/TOTP/code/SECURE-portail')) return ok({ data: { code: '111111' } });
      if (u.includes('/v1/TOTP/code/KV-portail')) return ok({ data: { code: '222222' } });
      return notFound();
    });
    axios.post.mockImplementation((url) => {
      const u = String(url);
      if (u.includes('/v1/auth/ldap/login/')) return ok({ auth: { client_token: 'tok-rbi' } });
      if (u.includes('/v1/sys/capabilities-self')) return ok({ data: {} });
      return Promise.resolve({ status: 204, data: {} });
    });
    axios.delete.mockImplementation(() => Promise.resolve({ status: 204, data: {} }));
  }
  const clickSecureUrl = async () => {
    const tr = rowOf('SECURE');
    await act(async () => { tr.querySelector('button.url-link').click(); });
    await flush(30);
  };

  test('entrée présente dans ce seul coffre : TOTP lu sur la clé de SON coffre (SECURE-portail)', async () => {
    installRbiAxios({
      kv: { autre: { Username: 'alice', Password: 'p' } },
      SECURE: { portail: { Username: 'root', Password: 'rbi-pass', URL: 'https://portail.example' } },
    });
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    await startApp();
    expect(activeEngine()).toBe('kv');
    await searchAllVaults('portail');
    await clickSecureUrl();
    expect(launchSession).toHaveBeenCalledWith(expect.objectContaining({ username: 'root', totp: '111111' })); // avant : null (clé KV-portail)
  });

  test('homonyme dans le coffre sélectionné : jamais le TOTP de l\'autre entrée', async () => {
    installRbiAxios({
      kv: { portail: { Username: 'alice', Password: 'p', URL: 'https://portail.example' } },
      SECURE: { portail: { Username: 'root', Password: 'rbi-pass', URL: 'https://portail.example' } },
    });
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    await startApp();
    await searchAllVaults('portail');
    await clickSecureUrl();
    expect(launchSession).toHaveBeenCalledTimes(1);
    expect(launchSession.mock.calls[0][0].totp).not.toBe('222222'); // avant : TOTP de kv/portail
  });
});
