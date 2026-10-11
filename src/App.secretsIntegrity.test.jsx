// ========================================
// TESTS : App.jsx — intégrité des entrées par la vraie interface (vague E, SECRETS-11/12/32/33)
// ========================================
// App réel (menus, modales, glisser-déposer) contre le faux Vault en mémoire du projet ; axios simulé.
// - SECRETS-11 : « + Nouvelle entrée » / deuxième « Dupliquer » sur un nom existant : refus, rien d'écrasé.
// - SECRETS-12 : « Supprimer le TOTP » ouvre une boîte de confirmation (danger), rien n'est détruit
//   avant « Supprimer » ; jamais une clé partagée.
// - SECRETS-33 : Supprimer puis Restaurer une entrée avec TOTP : la graine est toujours là ; la
//   confirmation l'annonce (KV v2).
// - SECRETS-32 : glisser-déposer puis ouverture d'un autre coffre : le tableau reste celui du coffre ouvert.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from './App.jsx';
import { I18nProvider } from './i18n.js';
import fr from './locales/fr.json';
import { createFakeVault } from './hooks/testUtils/fakeVault';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault; let postGate; let root; let host;
function installAxios() {
  axios.get.mockImplementation((url) => {
    const u = String(url);
    if (u.includes('/v1/auth/token/lookup-self')) return Promise.resolve({ status: 200, data: { data: { entity_name: 'alice', policies: ['default'] } } });
    if (u.includes('/v1/sys/policies/acl/')) return Promise.resolve({ status: 200, data: { data: { policy: '' } } });
    return vault.axios.get(u);
  });
  axios.post.mockImplementation((url, body) => {
    const u = String(url);
    if (u.includes('/v1/auth/ldap/login/')) return Promise.resolve({ status: 200, data: { auth: { client_token: 'tok-1' } } });
    if (u.includes('/v1/sys/capabilities-self')) {
      const p = (body?.paths || [])[0];
      return Promise.resolve({ status: 200, data: { data: { [p]: ['create', 'read', 'update', 'delete', 'list'] } } });
    }
    if (postGate && u.includes(postGate.match)) {
      return new Promise((resolve, reject) => { postGate.pending.push(() => vault.axios.post(u, body).then(resolve, reject)); });
    }
    return vault.axios.post(u, body);
  });
  axios.put.mockImplementation((url, body) => vault.axios.post(String(url), body));
  axios.delete.mockImplementation((url) => vault.axios.delete(String(url)));
}

async function flush(rounds = 40) {
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
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
async function renderAndLogin() {
  await act(async () => { mountInRoot(root, <I18nProvider defaultLang="fr"><App /></I18nProvider>); });
  await flush();
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], 'alice'); });
  await act(async () => { setInput(inputs[1], 'motdepasse-maitre'); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(80);
}
const rows = () => Array.from(host.querySelectorAll('.secrets-table tbody tr'));
const rowNamed = (name) => rows().find(r => r.querySelector('td.cell-name')?.textContent === name);
const activeEngine = () => host.querySelector('.engine-card.active .engine-name')?.textContent;
const card = (name) => Array.from(host.querySelectorAll('.engine-card')).find(c => c.querySelector('.engine-name').textContent === name);
const menuItem = (text) => Array.from(document.querySelectorAll('.context-menu-item')).find(b => b.textContent.includes(text));
const toastText = () => document.querySelector('.toast')?.textContent || '';
async function openRowMenu(row) {
  const cell = row.querySelector('td.cell-name');
  await act(async () => { cell.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 10, clientY: 10 })); });
  await flush(10);
}
async function clickMenuItem(text) {
  await act(async () => { menuItem(text).click(); });
  await flush(40);
}
async function saveEditForm() {
  const save = Array.from(document.querySelectorAll('[role="dialog"] button')).find(b => b.textContent === fr.editSecret.save);
  await act(async () => { save.click(); });
  await flush(60);
}

beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  vault = createFakeVault();
  postGate = null;
  installAxios();
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

describe('SECRETS-11 : pas d\'écrasement par création ou duplication', () => {
  test('« + Nouvelle entrée » avec le nom d\'une entrée existante : refus, données et TOTP intacts', async () => {
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Username: 'societe', Password: 'Ancien-MDP-Banque', Notes: 'codes de secours: 1111 2222' });
    vault.addTotp('ALPHA-banque');
    await renderAndLogin();

    const newBtn = Array.from(host.querySelectorAll('.toolbar button')).find(b => b.textContent.includes(fr.toolbar.newEntry));
    await act(async () => { newBtn.click(); });
    await flush(40);
    const modal = document.querySelector('[role="dialog"]');
    await act(async () => { setInput(modal.querySelector(`input[placeholder="${fr.editSecret.placeholderName}"]`), 'banque'); });
    await saveEditForm();

    expect(toastText()).toContain(fr.error.secretNameExists.replace('{{name}}', 'banque'));
    expect(vault.versionsOf('Alpha', 'banque')).toHaveLength(1);
    expect(vault.latest('Alpha', 'banque').data.Notes).toBe('codes de secours: 1111 2222');
    expect(document.querySelector('[role="dialog"]')).not.toBeNull(); // fiche ouverte, saisie conservée
  });

  test('« Dupliquer » deux fois : la seconde copie n\'écrase pas « x_copie »', async () => {
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'x', { Username: 'u', Password: 'MDP-X', EntryType: 'secret' });
    await renderAndLogin();

    await openRowMenu(rowNamed('x'));
    await clickMenuItem(fr.contextMenu.duplicate);
    await saveEditForm();
    expect(vault.versionsOf('Alpha', 'x_copie')).toHaveLength(1);

    // La copie est modifiée, puis « x » est dupliquée une seconde fois sous le même nom proposé
    vault.writeRaw('Alpha', 'x_copie', { Username: 'u', Password: 'MDP-COPIE-MODIFIE', EntryType: 'secret' });
    await act(async () => { card('Alpha').click(); });
    await flush(40);
    await openRowMenu(rowNamed('x'));
    await clickMenuItem(fr.contextMenu.duplicate);
    await saveEditForm();

    expect(toastText()).toContain(fr.error.secretNameExists.replace('{{name}}', 'x_copie'));
    expect(vault.versionsOf('Alpha', 'x_copie')).toHaveLength(2);
    expect(vault.latest('Alpha', 'x_copie').data.Password).toBe('MDP-COPIE-MODIFIE');
  });

  test('« Modifier » une entrée existante : enregistrée normalement', async () => {
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'u', Password: 'ancien', EntryType: 'secret' });
    await renderAndLogin();
    await openRowMenu(rowNamed('github'));
    await clickMenuItem(fr.contextMenu.edit);
    const pw = Array.from(document.querySelectorAll('[role="dialog"] input')).find(i => i.value === 'ancien');
    await act(async () => { setInput(pw, 'nouveau'); });
    await saveEditForm();
    expect(vault.latest('Alpha', 'github')).toMatchObject({ version: 2, data: { Password: 'nouveau' } });
  });
});

describe('SECRETS-12 : « Supprimer le TOTP »', () => {
  const dialog = () => document.querySelector('[role="dialog"]');
  const totpDeletes = () => vault.calls.filter(c => c.method === 'delete' && c.path.startsWith('v1/TOTP/keys/'));

  test('clic : boîte de confirmation (danger), rien n\'est supprimé ; Annuler : rien ; Supprimer : clé supprimée', async () => {
    vault.addEngine('KV');
    vault.writeRaw('KV', 'compte', { Username: 'u', Password: 'p' });
    vault.addTotp('KV-compte');
    await renderAndLogin();

    await openRowMenu(rowNamed('compte'));
    await clickMenuItem(fr.contextMenu.deleteTotp);
    // Vraie boîte de confirmation : titre, nom de l'entrée, irréversibilité ; aucun appel DELETE
    expect(dialog()).not.toBeNull();
    expect(dialog().textContent).toContain(fr.confirm.deleteTotp);
    expect(dialog().textContent).toContain(fr.confirm.deleteTotpMsg.replace('{{name}}', 'compte'));
    expect(dialog().querySelector('.btn-danger')).not.toBeNull();
    expect(vault.totp.has('KV-compte')).toBe(true);
    expect(totpDeletes()).toEqual([]);

    // Annuler : rien n'est supprimé
    const cancel = Array.from(dialog().querySelectorAll('button')).find(b => b.textContent === fr.common.cancel);
    await act(async () => { cancel.click(); });
    await flush(20);
    expect(dialog()).toBeNull();
    expect(vault.totp.has('KV-compte')).toBe(true);

    // Supprimer : la clé est détruite (une seule demande, plus de second clic)
    await openRowMenu(rowNamed('compte'));
    await clickMenuItem(fr.contextMenu.deleteTotp);
    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    await flush(60);
    expect(vault.totp.has('KV-compte')).toBe(false);
    expect(totpDeletes().map(c => c.path)).toEqual(['v1/TOTP/keys/KV-compte']);
    expect(dialog()).toBeNull();
    expect(toastText()).toContain(fr.toast.totpDeleted.replace('{{name}}', 'compte'));
  });

  test('clé partagée avec « users/alice/Banque/compte » : jamais supprimée, même confirmée', async () => {
    vault.addEngine('Banque');
    vault.addEngine('users/alice/Banque');
    vault.writeRaw('Banque', 'compte', { Username: 'societe', Password: 'p1' });
    vault.writeRaw('users/alice/Banque', 'compte', { Username: 'alice', Password: 'p2' });
    vault.addTotp('BANQUE-compte');
    await renderAndLogin();
    expect(activeEngine()).toBe('Banque');

    await openRowMenu(rowNamed('compte'));
    await clickMenuItem(fr.contextMenu.deleteTotp);
    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    await flush(60);
    expect(vault.totp.has('BANQUE-compte')).toBe(true);
    expect(totpDeletes()).toEqual([]);
    expect(toastText()).toContain('users/alice/Banque');
  });
});

describe('SECRETS-33 : Supprimer puis Restaurer garde la graine TOTP', () => {
  test('entrée de retour AVEC sa clé TOTP', async () => {
    vault.addEngine('kv');
    vault.writeRaw('kv', 'banque', { Username: 'client', Password: 'MDP-BANQUE' });
    vault.addTotp('KV-banque');
    await renderAndLogin();

    await openRowMenu(rowNamed('banque'));
    await clickMenuItem(fr.contextMenu.delete);
    const confirm = Array.from(document.querySelectorAll('[role="dialog"] button')).find(b => b.textContent === fr.common.delete);
    await act(async () => { confirm.click(); });
    await flush(60);
    expect(vault.isLive('kv', 'banque')).toBe(false);
    expect(vault.totp.has('KV-banque')).toBe(true);

    const showDeleted = Array.from(host.querySelectorAll('.toolbar input[type="checkbox"]')).find(i => i.closest('label')?.textContent.includes(fr.toolbar.showDeleted));
    await act(async () => { showDeleted.click(); });
    await flush(60);
    await openRowMenu(rows().find(r => r.textContent.includes('banque')));
    await clickMenuItem(fr.contextMenu.restore);
    await flush(40);
    expect(vault.isLive('kv', 'banque')).toBe(true);
    expect(vault.totp.has('KV-banque')).toBe(true);
  });

  test('KV v2 : la confirmation annonce que la clé TOTP est conservée et restaurable (sans case à cocher)', async () => {
    vault.addEngine('kv');
    vault.writeRaw('kv', 'banque', { Username: 'client', Password: 'MDP-BANQUE' });
    vault.addTotp('KV-banque');
    vault.writeRaw('kv', 'sans-totp', { Username: 'u', Password: 'p' });
    await renderAndLogin();

    await openRowMenu(rowNamed('banque'));
    await clickMenuItem(fr.contextMenu.delete);
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog.textContent).toContain(fr.confirm.deleteSecretTotpKept.replace('{{action}}', fr.contextMenu.restore));
    expect(dialog.querySelector('input[type="checkbox"]')).toBeNull(); // avant : rien n'était dit
    const cancel = Array.from(dialog.querySelectorAll('button')).find(b => b.textContent === fr.common.cancel);
    await act(async () => { cancel.click(); });
    await flush(20);

    // Entrée sans TOTP : message habituel seul
    await openRowMenu(rowNamed('sans-totp'));
    await clickMenuItem(fr.contextMenu.delete);
    const plain = document.querySelector('[role="dialog"]');
    expect(plain.textContent).toContain(fr.confirm.deleteSecretMsg.replace('{{name}}', 'sans-totp'));
    expect(plain.textContent).not.toContain(fr.confirm.deleteSecretTotpKept.split(':')[0]);
  });
});

describe('SECRETS-32 : glisser-déposer puis ouverture d\'un autre coffre', () => {
  test('le tableau affiché reste celui du coffre ouvert ; « Supprimer » vise bien sa ligne', async () => {
    vault.addEngine('a-src'); vault.addEngine('b-dst'); vault.addEngine('c-autre');
    vault.writeRaw('a-src', 'github', { Username: 'src', Password: 'MDP-SRC-GH' });
    vault.writeRaw('a-src', 'jira', { Username: 'src', Password: 'MDP-SRC-JIRA' });
    vault.writeRaw('c-autre', 'github', { Username: 'autre', Password: 'MDP-AUTRE-GH' });
    await renderAndLogin();
    expect(activeEngine()).toBe('a-src');

    postGate = { match: '/v1/b-dst/data/', pending: [] };
    const drop = new Event('drop', { bubbles: true, cancelable: true });
    Object.defineProperty(drop, 'dataTransfer', { value: { getData: () => JSON.stringify({ type: 'secrets', secrets: ['jira'], sourceEngine: 'a-src', sourceVersion: 2 }) } });
    await act(async () => { card('b-dst').dispatchEvent(drop); });
    await flush(20);
    expect(postGate.pending.length).toBe(1);

    await act(async () => { card('c-autre').click(); });
    await flush(40);
    const release = postGate.pending.shift(); postGate = null;
    await act(async () => { release(); });
    await flush(80);

    expect(activeEngine()).toBe('c-autre');
    expect(vault.isLive('b-dst', 'jira')).toBe(true);
    const ghRow = rowNamed('github');
    expect(ghRow.textContent).toContain('autre');
    expect(ghRow.textContent).not.toContain('src');
    expect(rowNamed('jira')).toBeUndefined();
  });
});
