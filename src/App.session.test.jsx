// ========================================
// TESTS : App.jsx — fin de session et restrictions « RBI uniquement »
// ========================================
// App réel, axios simulé (aucun réseau), ponts Electron simulés (même
// sémantique que electron/preload.js).
// - SESSION-14 : à l'expiration, les modales (notes, édition avec mot de passe)
//   sont fermées et ne réapparaissent pas à la connexion suivante.
// - SESSION-15 : une synchro extension en cours au moment de la déconnexion
//   ne réécrit pas l'état « connecté + mots de passe » après l'effacement.
// - SESSION-44 : recherche multi-coffre — un secret d'un coffre « RBI
//   uniquement » n'est ni affiché, ni révélable, ni copiable.
// - SESSION-45 : ces secrets ne sont envoyés ni à l'extension ni à la CLI.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import App from './App.jsx';
import { I18nProvider } from './i18n.js';
import fr from './locales/fr.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const NOTE = 'NOTE-SECRETE-XYZ-codes-de-secours';
const PASS = 'P@ss-TRES-SECRET-42';
const RBI_PASS = 'S3cr3t-RBI!';

function httpError(status) { const e = new Error(String(status)); e.response = { status, data: {} }; return e; }

// Coffres : « kv » (normal) et, selon le scénario, « SECURE » (RBI uniquement) ou « slow » (lecture lente)
function installAxios({ policies = ['default'], policyBodies = {}, mounts, routes }) {
  axios.get.mockImplementation((url) => {
    const u = String(url);
    if (u.includes('/v1/auth/token/lookup-self')) {
      return Promise.resolve({ status: 200, data: { data: { entity_name: 'alice', policies } } });
    }
    const pol = u.match(/\/v1\/sys\/policies\/acl\/([^/?]+)/);
    if (pol) return Promise.resolve({ status: 200, data: { data: { policy: policyBodies[decodeURIComponent(pol[1])] || '' } } });
    if (u.includes('/v1/sys/internal/ui/mounts') || u.endsWith('/v1/sys/mounts')) {
      return Promise.resolve({ status: 200, data: mounts });
    }
    for (const [pattern, handler] of routes) {
      if (u.includes(pattern)) return handler(u);
    }
    return Promise.reject(httpError(404));
  });
  axios.post.mockImplementation((url) => {
    const u = String(url);
    if (u.includes('/v1/auth/ldap/login/')) return Promise.resolve({ status: 200, data: { auth: { client_token: 'tok-' + Math.random().toString(36).slice(2) } } });
    if (u.includes('/v1/sys/capabilities-self')) return Promise.resolve({ status: 200, data: { data: {} } });
    return Promise.resolve({ status: 204, data: {} });
  });
  axios.delete.mockImplementation(() => Promise.resolve({ status: 204, data: {} }));
}

const KV2 = { type: 'kv', options: { version: '2' } };
const ok = (data) => () => Promise.resolve({ status: 200, data });

async function flush(rounds = 40) {
  for (let i = 0; i < rounds; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
}

function setInput(el, value) {
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
}

async function login(host, user = 'alice') {
  const inputs = host.querySelectorAll('.login-form input');
  await act(async () => { setInput(inputs[0], user); });
  await act(async () => { setInput(inputs[1], 'motdepasse-maitre'); });
  await act(async () => { host.querySelector('.btn-login').click(); });
  await flush(80);
}

let root; let host; let writes; let cli;
beforeEach(() => {
  jest.useFakeTimers();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  writes = [];
  window.electronSync = { writeState: jest.fn(async (s) => { writes.push(JSON.parse(JSON.stringify(s))); return { success: true }; }) };
  window.electronClipboard = { copySecure: jest.fn(async () => ({ success: true })), clearNow: jest.fn(async () => ({ success: true })) };
  // Double de preload.js (electronCLI) : un seul callback par canal
  cli = { secret: null, responses: [] };
  window.electronCLI = {
    onSecretRequest: (cb) => { cli.secret = cb; return () => { if (cli.secret === cb) cli.secret = null; }; },
    sendSecretResponse: (result, requestId) => { cli.responses.push({ result, requestId }); },
    revokeSession: async () => {},
  };
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  delete window.electronSync;
  delete window.electronClipboard;
  delete window.electronCLI;
  jest.useRealTimers();
});

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

async function renderApp() {
  await act(async () => { mountInRoot(root, <I18nProvider defaultLang="fr"><App /></I18nProvider>); });
  await flush();
}

describe('SESSION-14 : expiration de session et modales ouvertes', () => {
  beforeEach(() => {
    installAxios({
      mounts: { 'kv/': KV2 },
      routes: [
        ['/v1/kv/metadata?list=true', ok({ data: { keys: ['github'] } })],
        ['/v1/kv/data/github', ok({ data: { data: { Username: 'alice', Password: PASS, Notes: NOTE } } })],
      ],
    });
  });

  test('la popup de notes est fermée à l\'expiration (inactivité)', async () => {
    await renderApp();
    await login(host);
    const notesCell = Array.from(host.querySelectorAll('td')).find(td => td.textContent === NOTE);
    expect(notesCell).toBeTruthy();
    await act(async () => { notesCell.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); });
    await flush(5);

    await act(async () => { jest.advanceTimersByTime(15 * 60 * 1000 + 1000); });
    await flush();

    expect(host.querySelector('.login-form')).not.toBeNull();
    expect(document.body.textContent).not.toContain(NOTE);
  });

  test('la modale d\'édition (mot de passe en clair) est fermée et ne revient pas à la reconnexion', async () => {
    await renderApp();
    await login(host);
    const nameCell = Array.from(host.querySelectorAll('td.cell-name')).find(td => td.textContent.includes('github'));
    await act(async () => { nameCell.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 10, clientY: 10 })); });
    await flush(10);
    const editBtn = Array.from(document.querySelectorAll('.context-menu-item')).find(b => b.textContent.includes('✏'));
    await act(async () => { editBtn.click(); });
    await flush(10);
    const hasPasswordInput = () => Array.from(document.querySelectorAll('input')).some(i => i.value === PASS);
    expect(hasPasswordInput()).toBe(true);

    await act(async () => { jest.advanceTimersByTime(15 * 60 * 1000 + 1000); });
    await flush();
    expect(host.querySelector('.login-form')).not.toBeNull();
    expect(hasPasswordInput()).toBe(false);

    // Un autre utilisateur se connecte sur le poste : aucune modale de la session précédente
    await login(host, 'bob');
    expect(host.querySelector('.secrets-table')).not.toBeNull();
    expect(hasPasswordInput()).toBe(false);
  });
});

describe('SESSION-13 : expiration « PC verrouillé » puis reconnexion', () => {
  test('la session suivante expire après 15 min d\'inactivité et accepte les liens de partage', async () => {
    installAxios({
      mounts: { 'kv/': KV2 },
      routes: [
        ['/v1/kv/metadata?list=true', ok({ data: { keys: ['github'] } })],
        ['/v1/kv/data/github', ok({ data: { data: { Username: 'alice', Password: PASS } } })],
      ],
    });
    // Double de preload.js (electronPowerMonitor) : retiré par removeAllListeners
    const pm = { lock: null, unlock: null };
    window.electronPowerMonitor = {
      onLockScreen: (cb) => { pm.lock = cb; },
      onUnlockScreen: (cb) => { pm.unlock = cb; },
      removeAllListeners: () => { pm.lock = null; pm.unlock = null; },
    };
    let shareCb = null;
    window.electronRBI = { onShareReceived: (cb) => { shareCb = cb; return () => {}; } };
    try {
      await renderApp();
      await login(host);
      await act(async () => { pm.lock(); });
      await act(async () => { jest.advanceTimersByTime(3 * 60 * 60 * 1000 + 1000); });
      await flush();
      expect(host.querySelector('.login-form')).not.toBeNull();
      // Déverrouillage Windows : plus aucun écouteur (session terminée)
      await act(async () => { if (pm.unlock) pm.unlock(); });

      await login(host);
      expect(host.querySelector('.secrets-table')).not.toBeNull();

      // Un lien de partage reçu n'est pas refusé « poste verrouillé »
      axios.post.mockImplementationOnce(() => Promise.reject(httpError(400)));
      await act(async () => { await shareCb('hvs.partage-valide'); });
      await flush(5);
      expect(document.body.textContent).not.toContain(fr.error.shareWhileLocked);

      await act(async () => { jest.advanceTimersByTime(15 * 60 * 1000 + 1000); });
      await flush();
      expect(host.querySelector('.login-form')).not.toBeNull();
      // Message adapté à la cause (inactivité, et non « PC verrouillé »)
      expect(document.body.textContent).toContain(fr.login.sessionExpiredActive);
    } finally {
      delete window.electronPowerMonitor;
      delete window.electronRBI;
    }
  });
});

describe('SESSION-15 : déconnexion pendant une synchronisation de l\'extension', () => {
  test('le dernier état envoyé au processus principal est « déconnecté », sans mot de passe', async () => {
    let releaseSlow = null; let slowListCalls = 0;
    installAxios({
      mounts: { 'kv/': KV2, 'slow/': KV2 },
      routes: [
        ['/v1/kv/metadata?list=true', ok({ data: { keys: ['github'] } })],
        ['/v1/kv/data/github', ok({ data: { data: { Username: 'alice', Password: PASS, URL: 'https://github.com' } } })],
        ['/v1/slow/metadata?list=true', () => {
          slowListCalls++;
          // 1er appel = test d'accès (liste des coffres) ; ensuite = lecture lente de la synchro extension
          if (slowListCalls === 1) return Promise.resolve({ status: 200, data: { data: { keys: [] } } });
          return new Promise((_, reject) => { releaseSlow = () => reject(httpError(403)); });
        }],
      ],
    });
    await renderApp();
    await login(host);
    expect(host.querySelector('.secrets-table')).not.toBeNull();
    expect(typeof releaseSlow).toBe('function'); // synchro extension en cours

    await act(async () => { host.querySelector('.user-menu-trigger').click(); });
    await act(async () => { host.querySelector('.user-menu-item-logout').click(); });
    await flush(40);
    expect(host.querySelector('.login-form')).not.toBeNull();

    // La lecture du coffre lent se termine (403 : jeton révoqué)
    await act(async () => { releaseSlow(); });
    await flush(40);

    const last = writes[writes.length - 1];
    expect(last.connected).toBe(false);
    expect(JSON.stringify(writes.filter(w => w.connected))).not.toContain(PASS);
  });
});

describe('SESSION-44 / SESSION-45 : secrets d\'un coffre « RBI uniquement »', () => {
  beforeEach(() => {
    installAxios({
      policies: ['default', 'rbi-pol'],
      policyBodies: { 'rbi-pol': '# RBI-ONLY\npath "SECURE/metadata/*" {\n  capabilities = ["list"]\n}\n' },
      mounts: { 'kv/': KV2, 'SECURE/': KV2 },
      routes: [
        ['/v1/kv/metadata?list=true', ok({ data: { keys: ['srv-perso'] } })],
        ['/v1/kv/data/srv-perso', ok({ data: { data: { Username: 'alice', Password: PASS, URL: 'https://perso.example', CustomFields: [{ key: 'site', value: 'CF-PERSO' }] } } })],
        ['/v1/SECURE/metadata?list=true', ok({ data: { keys: ['srv-prod'] } })],
        ['/v1/SECURE/data/srv-prod', ok({ data: { data: { Username: 'root', Password: RBI_PASS, URL: 'https://prod.example', Notes: 'note-rbi', CustomFields: [{ key: 'pin', value: 'PIN-RBI-7788' }] } } })],
      ],
    });
  });

  test('recherche multi-coffre : identifiant, mot de passe et notes masqués, ni révélables ni copiables', async () => {
    // Colonne « champs personnalisés » activée par l'utilisateur
    localStorage.setItem('rdvault-visible-columns', JSON.stringify({ customFields: true }));
    await renderApp();
    await login(host);
    expect(host.querySelector('.secrets-table')).not.toBeNull();

    // Recherche « srv » dans tous les coffres, depuis le coffre normal « kv »
    await act(async () => { setInput(host.querySelector('.search-input'), 'srv'); });
    await act(async () => { jest.advanceTimersByTime(400); });
    await flush(10);
    const multi = host.querySelector('.toolbar input[type="checkbox"]');
    await act(async () => { multi.click(); });
    await flush(60);

    const rows = Array.from(host.querySelectorAll('.secrets-table tbody tr'));
    const rbiRow = rows.find(r => r.textContent.includes('srv-prod'));
    const persoRow = rows.find(r => r.textContent.includes('srv-perso'));
    expect(rbiRow).toBeTruthy();
    expect(persoRow).toBeTruthy();

    // Révéler tout ce qui peut l'être
    for (const btn of Array.from(host.querySelectorAll('.btn-action-view'))) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { btn.click(); });
    }
    expect(persoRow.textContent).toContain(PASS); // témoin : le coffre normal reste utilisable
    expect(rbiRow.textContent).not.toContain('root');
    expect(rbiRow.textContent).not.toContain(RBI_PASS);
    expect(rbiRow.textContent).not.toContain('note-rbi');
    expect(rbiRow.querySelector('.btn-action-view')).toBeNull();

    // Double-clic sur chaque cellule de la ligne RBI : aucune copie
    for (const td of Array.from(rbiRow.querySelectorAll('td'))) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { td.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); });
    }
    await flush(5);
    const copied = window.electronClipboard.copySecure.mock.calls.map(c => c[0]);
    expect(copied).not.toContain(RBI_PASS);
    expect(copied).not.toContain('root');
    expect(document.body.textContent).not.toContain('note-rbi');
    // Champs personnalisés : non masqués ligne par ligne → colonne retirée tant qu'un résultat RBI est affiché
    expect(document.body.textContent).not.toContain('PIN-RBI-7788');

    // Témoin : sans résultat RBI affiché, la colonne revient
    await act(async () => { setInput(host.querySelector('.search-input'), 'srv-perso'); });
    await act(async () => { jest.advanceTimersByTime(400); });
    await flush(20);
    expect(host.querySelector('.secrets-table').textContent).toContain('CF-PERSO');
  });

  test('l\'extension ne reçoit pas les secrets RBI ; la CLI se voit refuser leur lecture', async () => {
    await renderApp();
    await login(host);
    await flush(20);

    const connected = writes.filter(w => w.connected);
    expect(connected.length).toBeGreaterThan(0);
    const lastSecrets = connected[connected.length - 1].secrets;
    expect(lastSecrets.map(s => s.name)).toContain('srv-perso'); // témoin
    expect(JSON.stringify(lastSecrets)).not.toContain(RBI_PASS);
    expect(lastSecrets.some(s => s.engine === 'SECURE')).toBe(false);

    expect(typeof cli.secret).toBe('function');
    await act(async () => { await cli.secret({ engine: 'SECURE', path: 'srv-prod', requestId: 'r1' }); });
    await act(async () => { await cli.secret({ engine: 'SECURE', path: '/srv-prod/', requestId: 'r2' }); });
    await act(async () => { await cli.secret({ engine: 'kv', path: 'srv-perso', requestId: 'r3' }); });
    const byId = Object.fromEntries(cli.responses.map(r => [r.requestId, r.result]));
    expect(byId.r1.success).toBe(false);
    expect(JSON.stringify(byId.r1)).not.toContain(RBI_PASS);
    expect(byId.r2.success).toBe(false);
    expect(JSON.stringify(byId.r2)).not.toContain(RBI_PASS);
    expect(byId.r3.success).toBe(true); // témoin
    expect(byId.r3.data.password).toBe(PASS);
  });
});
