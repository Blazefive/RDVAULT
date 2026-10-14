// Demande d'appairage EXPIRÉE distincte d'un refus (EXT-25), côté extension enrichie.
// Avant : la boîte d'appairage de RDVAULT restée sans réponse 60 s renvoyait 403 pairing_denied ; l'extension
// affichait « Accès refusé dans RDVAULT » et s'interdisait toute nouvelle demande pendant une minute.
// Désormais RDVAULT répond 403 {error:'pairing_timeout'} (electron/main.pairingTimeout.test.js) et l'extension :
//  - passe à l'état « expiré » (pas « refusé »), sans délai de carence ;
//  - ne relance AUCUNE demande automatique (onglets, alarme) tant que la popup n'est pas rouverte ;
//  - la popup ouverte affiche « Demande d'appairage expirée : rouvrez l'extension pour réessayer » (12 langues) ;
//  - la réouverture de la popup (port 'rdvault-popup') autorise aussitôt une nouvelle demande.
// auth-manager.js, background.js et popup.js sont exécutés tels quels (vm / jsdom), chrome et fetch simulés.
// Lancement : node --test test/extension/pairing-timeout.test.js
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..', '..');
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const { JSDOM } = require(path.join(ROOT, 'node_modules/jsdom'));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Réponse fetch simulée (clone() lisible, comme une vraie Response) */
function resp(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body, clone: () => resp(status, body) };
}

/** Port chrome.runtime simulé (côté service worker) */
function fakePort(name) {
  const port = { name, posted: [], disconnectListeners: [] };
  port.postMessage = (m) => port.posted.push(m);
  port.onDisconnect = { addListener: (fn) => port.disconnectListeners.push(fn) };
  port.disconnect = () => port.disconnectListeners.forEach((fn) => fn());
  return port;
}

/**
 * Service worker de l'extension : background.js réel, qui charge auth-manager.js réel par importScripts.
 * @param {Function} serverReply - (url) → réponse du serveur de synchronisation simulé
 */
function loadServiceWorker(serverReply) {
  const fetched = [];
  const listeners = { message: [], connect: [] };
  const noopEvent = { addListener() {} };
  const chrome = {
    runtime: {
      id: 'abcdefghijklmnopabcdefghijklmnop',
      getPlatformInfo() {},
      getURL: (p) => 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/' + p,
      onMessage: { addListener: (fn) => listeners.message.push(fn) },
      onConnect: { addListener: (fn) => listeners.connect.push(fn) },
      onInstalled: noopEvent, onStartup: noopEvent,
    },
    storage: { session: { get: async () => ({}), set: async () => {}, remove: async () => {} }, local: { get: async () => ({}), set: async () => {} } },
    alarms: { create: async () => {}, clear: async () => {}, onAlarm: noopEvent },
    tabs: { onUpdated: noopEvent, onActivated: noopEvent, onRemoved: noopEvent, query: async () => [], sendMessage: async () => {} },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setTitle() {} },
    i18n: { getMessage: () => '', getUILanguage: () => 'fr' },
    contextMenus: { create() {}, removeAll(cb) { if (cb) cb(); }, onClicked: noopEvent },
    commands: { onCommand: noopEvent },
    webNavigation: { onCommitted: noopEvent },
    windows: { create: async () => ({}), onRemoved: noopEvent },
  };
  const ctx = {
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    setTimeout, clearTimeout, setInterval, clearInterval, AbortController, URL, URLSearchParams,
    TextEncoder, TextDecoder, crypto: require('node:crypto').webcrypto, Error, TypeError, Promise, Date, JSON, Math,
    fetch: async (url) => { fetched.push(String(url)); return serverReply(String(url)); },
    chrome,
  };
  ctx.self = ctx;
  ctx.globalThis = ctx;
  ctx.importScripts = (...files) => {
    for (const f of files) {
      const file = path.join(EXT, f);
      vm.runInContext(fs.readFileSync(file, 'utf8'), ctx, { filename: file });
    }
  };
  vm.createContext(ctx);
  const bgFile = path.join(EXT, 'background.js');
  vm.runInContext(fs.readFileSync(bgFile, 'utf8'), ctx, { filename: bgFile });
  const authManager = vm.runInContext('authManager', ctx);
  /** Message runtime (comme la popup) : réponse renvoyée par sendResponse */
  const send = (message) => new Promise((resolve) => {
    assert.equal(listeners.message.length, 1, 'un écouteur de messages dans le service worker');
    listeners.message[0](message, { id: chrome.runtime.id, url: chrome.runtime.getURL('popup.html') }, resolve);
  });
  /** Ouverture de la popup : connexion du port 'rdvault-popup' */
  const openPopup = () => { const port = fakePort('rdvault-popup'); listeners.connect.forEach((fn) => fn(port)); return port; };
  const tokenRequests = () => fetched.filter((u) => u.endsWith('/auth/token')).length;
  return { authManager, send, openPopup, tokenRequests, listeners };
}

test('EXT-25 : 403 pairing_timeout → état « expiré » (pas « refusé »), sans délai de carence', async () => {
  const sw = loadServiceWorker(() => resp(403, { error: 'pairing_timeout' }));
  const am = sw.authManager;
  const port = sw.openPopup();
  assert.equal(await am._fetchNewToken(), false);
  assert.equal(am.getPairingState(), 'expired');
  assert.equal(am.isPairingExpired(), true);
  assert.equal(am.isPairingDenied(), false, 'jamais présenté comme un refus');
  assert.equal(am._nextTokenAttemptAt, 0, 'aucun délai de carence d\'une minute');
  assert.deepEqual(JSON.parse(JSON.stringify(port.posted)), [{ type: 'PAIRING_STATE', state: 'expired' }], 'popup ouverte avertie');
});

test('EXT-25 : demande expirée → aucune nouvelle boîte d\'appairage automatique ; réouverture de la popup → nouvelle demande', async () => {
  let reply = resp(403, { error: 'pairing_timeout' });
  const sw = loadServiceWorker(() => reply);
  sw.openPopup();
  const r1 = await sw.send({ type: 'CHECK_AUTH' });
  assert.equal(r1.authenticated, false);
  assert.equal(sw.tokenRequests(), 1);
  assert.equal(sw.authManager.getPairingState(), 'expired');
  assert.notEqual(r1.pairing, 'denied', 'pas « Accès refusé »');

  // Popup toujours ouverte (rafraîchissements), onglets, alarme : aucune nouvelle demande au serveur
  const r2 = await sw.send({ type: 'CHECK_AUTH' });
  assert.equal(r2.pairing, 'expired', 'état « expirée » transmis (ni refusé ni fermé)');
  assert.equal(r2.reachable, true, 'RDVAULT n\'est pas présenté comme fermé');
  await sw.send({ type: 'CHECK_AUTH' });
  assert.equal(await sw.authManager._fetchNewToken(), false);
  await sw.authManager._onRefreshAlarm();
  assert.equal(sw.tokenRequests(), 1, 'aucune boîte de dialogue relancée sans action de l\'utilisateur');

  // Réouverture de la popup : nouvelle demande, approuvée cette fois
  reply = resp(200, { token: 'jeton-de-test' });
  sw.openPopup();
  assert.equal(sw.authManager.getPairingState(), 'idle');
  assert.equal(await sw.authManager._fetchNewToken(), true);
  assert.equal(sw.tokenRequests(), 2);
  assert.equal(sw.authManager.getPairingState(), 'ok');
});

test('EXT-25 : refus explicite (403 pairing_denied) inchangé : « refusé » avec délai de carence', async () => {
  const sw = loadServiceWorker(() => resp(403, { error: 'pairing_denied' }));
  sw.openPopup();
  assert.equal(await sw.authManager._fetchNewToken(), false);
  assert.equal(sw.authManager.getPairingState(), 'denied');
  assert.equal(sw.authManager.isPairingDenied(), true);
  assert.ok(sw.authManager._nextTokenAttemptAt > Date.now() + 50000, 'délai de carence d\'une minute conservé');
  const r = await sw.send({ type: 'CHECK_AUTH' });
  assert.equal(r.pairing, 'denied');
  // Un ancien serveur (403 sans corps JSON) reste traité comme un refus
  const old = loadServiceWorker(() => ({ ok: false, status: 403, json: async () => { throw new Error('vide'); }, clone() { return this; } }));
  assert.equal(await old.authManager._fetchNewToken(), false);
  assert.equal(old.authManager.getPairingState(), 'denied');
});

// ---------- Popup ----------
const LOCALES = ['ar', 'de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'pt', 'ru', 'tr', 'zh_CN'];
const readMessages = (loc) => JSON.parse(fs.readFileSync(path.join(EXT, '_locales', loc, 'messages.json'), 'utf8'));
const OPEN_WINDOWS = [];
test.afterEach(() => { while (OPEN_WINDOWS.length) { try { OPEN_WINDOWS.pop().close(); } catch { /* déjà fermée */ } } });

/** Popup réelle (HTML + script) ; chrome.runtime.connect simulé : renvoie le port côté popup */
async function loadPopup({ locale = null, reply }) {
  const html = fs.readFileSync(path.join(EXT, 'popup.html'), 'utf8');
  const src = fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8');
  const dom = new JSDOM(html.replace('<script src="popup.js"></script>', ''), { runScripts: 'outside-only', pretendToBeVisual: true });
  const ports = [];
  const chrome = {
    runtime: {
      sendMessage: async (m) => reply(m),
      connect: ({ name }) => {
        const listeners = [];
        const port = { name, onMessage: { addListener: (fn) => listeners.push(fn) }, deliver: (m) => listeners.forEach((fn) => fn(m)) };
        ports.push(port);
        return port;
      },
    },
  };
  if (locale) {
    const msgs = { ...readMessages('en'), ...readMessages(locale) };
    chrome.i18n = {
      getMessage: (key) => (key === '@@bidi_dir' ? (locale === 'ar' ? 'rtl' : 'ltr') : (msgs[key] ? msgs[key].message : '')),
      getUILanguage: () => locale.replace('_', '-'),
    };
  }
  dom.window.chrome = chrome;
  OPEN_WINDOWS.push(dom.window);
  dom.window.eval(src);
  if (dom.window.document.readyState === 'loading') {
    await new Promise((r) => dom.window.document.addEventListener('DOMContentLoaded', r));
  }
  await sleep(30);
  return { d: dom.window.document, ports };
}

test('EXT-25 : popup — port « rdvault-popup » ouvert au chargement ; demande expirée → message dédié, pas « Accès refusé »', { timeout: 15000 }, async () => {
  // Pendant l'expiration, le service worker répond « injoignable » (aucune demande relancée)
  const p = await loadPopup({ reply: () => ({ authenticated: false, pairing: null, reachable: false }) });
  assert.equal(p.ports.length, 1);
  assert.equal(p.ports[0].name, 'rdvault-popup');
  p.ports[0].deliver({ type: 'PAIRING_STATE', state: 'expired' });
  const text = () => p.d.getElementById('statusText').textContent;
  assert.equal(text(), 'Demande d\'appairage expirée : rouvrez l\'extension pour réessayer');
  assert.match(p.d.getElementById('statusDetails').textContent, /60 secondes/);
  assert.notEqual(text(), 'Accès refusé dans RDVAULT');
  // Message conservé au rafraîchissement suivant (10 s), alors que le service worker répond « injoignable »
  await sleep(10300);
  assert.equal(text(), 'Demande d\'appairage expirée : rouvrez l\'extension pour réessayer');
});

test('EXT-25 : message « demande expirée » traduit dans les 12 langues', async () => {
  for (const loc of LOCALES) {
    const msgs = readMessages(loc);
    assert.ok(msgs.popupPairingExpiredTitle && msgs.popupPairingExpiredTitle.message, loc + ' : titre');
    assert.ok(msgs.popupPairingExpiredDetail && msgs.popupPairingExpiredDetail.message, loc + ' : détail');
    if (loc !== 'en') {
      assert.notEqual(msgs.popupPairingExpiredTitle.message, readMessages('en').popupPairingExpiredTitle.message, loc + ' : vraie traduction');
    }
    const p = await loadPopup({ locale: loc, reply: () => ({ authenticated: false, reachable: false }) });
    p.ports[0].deliver({ type: 'PAIRING_STATE', state: 'expired' });
    assert.equal(p.d.getElementById('statusText').textContent, msgs.popupPairingExpiredTitle.message, loc);
  }
});
