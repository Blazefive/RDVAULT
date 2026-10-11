// ========================================
// TESTS : App.jsx — recherche multi-coffres : homonymes de coffres différents (vague F)
// ========================================
// App réel, axios branché sur le faux coffre du projet (src/hooks/testUtils/fakeVault.js).
// - Mots de passe révélés et sélection étaient indexés par NOM seul : en recherche multi-coffres,
//   révéler ou sélectionner « Beta/banque » révélait / allumait aussi « Alpha/banque » et
//   « Gamma/banque ». Ils sont désormais indexés par coffre + nom (entryKey, useSelection).
// - Glisser une ligne du coffre sélectionné dont la sélection contient un résultat d'un autre coffre :
//   refusé avec un message explicite (la sélection entière partirait du coffre sélectionné).
// - SECRETS-12 depuis un autre coffre : « Supprimer le TOTP » ouvre le coffre de l'entrée puis une
//   vraie boîte de confirmation ; seule la clé de CE coffre est supprimée.
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
      return Promise.resolve({ status: 200, data: { auth: { client_token: 'tok-homonymes' } } });
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
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(el, value);
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
const multiBox = () => host.querySelector('.toolbar label.checkbox-label input[type="checkbox"]');
const menuItem = (text) => Array.from(document.querySelectorAll('.context-menu .context-menu-item'))
  .find(b => b.textContent.includes(text)) || null;
const toastText = () => document.querySelector('.toast')?.textContent || '';
const dialog = () => document.querySelector('[role="dialog"]');

async function typeSearch(text) {
  await act(async () => { setInput(host.querySelector('.search-input'), text); });
  await act(async () => { jest.advanceTimersByTime(400); });
  await flush();
}
async function searchAllVaults(term) {
  await typeSearch(term);
  await act(async () => { multiBox().click(); });
  await flush(120);
}

// Ligne de la recherche multi-coffres dont la colonne « coffre » vaut engineName
function rowOf(engineName) {
  return Array.from(host.querySelectorAll('table.secrets-table tbody tr'))
    .find(tr => tr.querySelectorAll('td')[1]?.textContent.trim() === engineName) || null;
}
const clickRow = (tr, init = {}) => act(async () => {
  tr.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ...init }));
});
const selectedEngines = () => ['Alpha', 'Beta', 'Gamma'].filter(e => rowOf(e)?.className === 'row-selected');

function threeHomonyms(vault) {
  vault.addEngine('Alpha');
  vault.addEngine('Beta');
  vault.addEngine('Gamma');
  vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'MDP-ALPHA' });
  vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'MDP-BETA' });
  vault.writeRaw('Gamma', 'banque', { Username: 'carol', Password: 'MDP-GAMMA' });
}

describe('recherche multi-coffres : homonymes indexés par coffre + nom', () => {
  test('révéler le mot de passe de Beta/banque ne révèle ni Alpha/banque (coffre sélectionné) ni Gamma/banque', async () => {
    const vault = setupVault();
    threeHomonyms(vault);
    await startApp();
    expect(activeEngine()).toBe('Alpha');
    await searchAllVaults('banque');
    expect(['Alpha', 'Beta', 'Gamma'].every(e => rowOf(e))).toBe(true);

    await act(async () => { rowOf('Beta').querySelector('.btn-action-view').click(); });
    expect(rowOf('Beta').textContent).toContain('MDP-BETA');
    expect(rowOf('Alpha').textContent).not.toContain('MDP-ALPHA'); // avant : révélé aussi
    expect(rowOf('Gamma').textContent).not.toContain('MDP-GAMMA'); // avant : révélé aussi
    expect(rowOf('Alpha').querySelector('.btn-action-view').getAttribute('aria-pressed')).toBe('false');

    // Chaque œil agit sur SA ligne
    await act(async () => { rowOf('Alpha').querySelector('.btn-action-view').click(); });
    await act(async () => { rowOf('Beta').querySelector('.btn-action-view').click(); });
    expect(rowOf('Alpha').textContent).toContain('MDP-ALPHA');
    expect(rowOf('Beta').textContent).not.toContain('MDP-BETA');
    expect(rowOf('Gamma').textContent).not.toContain('MDP-GAMMA');
  });

  test('sélectionner Beta/banque n\'allume que cette ligne ; Ctrl+clic et Maj+clic par coffre + nom', async () => {
    const vault = setupVault();
    threeHomonyms(vault);
    await startApp();
    await searchAllVaults('banque');

    await clickRow(rowOf('Beta'));
    expect(selectedEngines()).toEqual(['Beta']); // avant : les trois lignes « banque » allumées

    await clickRow(rowOf('Gamma'), { ctrlKey: true });
    expect(selectedEngines()).toEqual(['Beta', 'Gamma']);
    // Coche de multi-sélection sur les seules lignes sélectionnées
    expect(rowOf('Beta').querySelector('td.cell-name').textContent).toContain('✓');
    expect(rowOf('Alpha').querySelector('td.cell-name').textContent).not.toContain('✓');

    // Maj+clic : plage entre deux lignes, repérées par leur clé (et non par le nom commun)
    const order = Array.from(host.querySelectorAll('table.secrets-table tbody tr')).map(tr => tr.querySelectorAll('td')[1].textContent.trim());
    await clickRow(rowOf(order[0]));
    expect(selectedEngines()).toEqual([order[0]]);
    await clickRow(rowOf(order[2]), { shiftKey: true });
    expect(selectedEngines()).toEqual(['Alpha', 'Beta', 'Gamma']);
  });

  test('sortie de la recherche multi-coffres : les résultats d\'autres coffres quittent la sélection', async () => {
    const vault = setupVault();
    threeHomonyms(vault);
    await startApp();
    await searchAllVaults('banque');
    await clickRow(rowOf('Beta'));
    expect(selectedEngines()).toEqual(['Beta']);

    await typeSearch(''); // SEARCH-16 : recherche vidée → recherche multi-coffres désactivée
    expect(multiBox().checked).toBe(false);
    const own = Array.from(host.querySelectorAll('table.secrets-table tbody tr'))
      .find(tr => tr.querySelector('td.cell-name')?.textContent.trim() === 'banque');
    await clickRow(own, { ctrlKey: true });
    // Une seule entrée sélectionnée : pas de coche de multi-sélection (Beta/banque n'est plus comptée)
    expect(own.className).toBe('row-selected');
    expect(own.querySelector('td.cell-name').textContent).not.toContain('✓');
  });

  test('glisser une ligne du coffre sélectionné avec un résultat d\'un autre coffre dans la sélection : refusé', async () => {
    const vault = setupVault();
    threeHomonyms(vault);
    await startApp();
    await searchAllVaults('banque');
    await clickRow(rowOf('Beta'));
    await clickRow(rowOf('Alpha'), { ctrlKey: true });
    expect(selectedEngines()).toEqual(['Alpha', 'Beta']);

    const setData = jest.fn();
    const ev = new Event('dragstart', { bubbles: true, cancelable: true });
    ev.dataTransfer = { setData, setDragImage: jest.fn(), effectAllowed: '' };
    await act(async () => { rowOf('Alpha').dispatchEvent(ev); });
    expect(ev.defaultPrevented).toBe(true);
    expect(setData).not.toHaveBeenCalled();
    expect(toastText()).toContain(fill(fr.error.dragOtherVault, { engine: 'Beta' }));

    // Sélection limitée au coffre sélectionné : le glisser-déposer fonctionne comme avant
    await clickRow(rowOf('Alpha'));
    const ev2 = new Event('dragstart', { bubbles: true, cancelable: true });
    ev2.dataTransfer = { setData: jest.fn(), setDragImage: jest.fn(), effectAllowed: '' };
    await act(async () => { rowOf('Alpha').dispatchEvent(ev2); });
    expect(JSON.parse(ev2.dataTransfer.setData.mock.calls[0][1])).toEqual(expect.objectContaining({ secrets: ['banque'], sourceEngine: 'Alpha' }));
    await act(async () => { rowOf('Alpha').dispatchEvent(new Event('dragend', { bubbles: true })); });
  });
});

describe('SECRETS-12 depuis la recherche multi-coffres', () => {
  test('« Supprimer le TOTP » sur Beta/banque : coffre Beta ouvert, boîte de confirmation, seule BETA-banque supprimée', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'alpha-pass' });
    vault.addTotp('ALPHA-banque');
    vault.writeRaw('Beta', 'banque', { Username: 'bob', Password: 'beta-pass' });
    vault.addTotp('BETA-banque');
    await startApp();
    await searchAllVaults('banque');

    const cell = rowOf('Beta').querySelector('td.cell-name');
    await act(async () => { cell.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 10, clientY: 10 })); });
    await flush(30);
    await act(async () => { menuItem(fr.contextMenu.deleteTotp).click(); });
    await flush(80);

    expect(activeEngine()).toBe('Beta');
    expect(dialog()).not.toBeNull(); // avant : simple toast, second clic droit nécessaire
    expect(dialog().textContent).toContain(fill(fr.confirm.deleteTotpMsg, { name: 'banque' }));
    expect(vault.totp.has('BETA-banque')).toBe(true);

    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    await flush(80);
    expect(vault.totp.has('BETA-banque')).toBe(false);
    expect(vault.totp.has('ALPHA-banque')).toBe(true);
    expect(dialog()).toBeNull();
  });
});
