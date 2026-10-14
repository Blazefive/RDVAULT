// Appairage de l'extension : demande EXPIRÉE distincte d'un refus (EXT-25) — node --test electron/main.pairingTimeout.test.js
// main.js RÉEL sous Node (electron simulé, démarrage complet) ; AUCUN port ouvert : http.createServer est remplacé
// par un double qui capture le gestionnaire du serveur de synchronisation. Serveur CLI et coffre local remplacés
// par des doubles. userData et TEMP jetables.
// Avant : boîte d'appairage restée sans réponse 60 s → 403 {error:'pairing_denied'}, affiché « Accès refusé » par
// l'extension, qui s'interdisait en plus toute nouvelle demande pendant une minute.
// Attendu : 403 {error:'pairing_timeout'} pour une demande expirée ; 'pairing_denied' seulement sur un vrai refus.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { EventEmitter } = require('events');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const servers = [];
const origCreateServer = http.createServer;
// Comportement de la boîte d'appairage simulée, choisi par chaque test
let dialogBehavior = () => Promise.resolve({ response: 1 });
const dialogCalls = [];

const ctx = loadMainWithMockElectron({
  ready: true,
  activate: false,
  dialog: { showMessageBox: (...args) => { dialogCalls.push(args); return dialogBehavior(...args); } },
  beforeRequire: () => {
    http.createServer = (handler) => {
      const s = new EventEmitter();
      s.handler = handler; s.listenArgs = null;
      s.listen = (...a) => { s.listenArgs = a; return s; };
      s.close = () => {};
      servers.push(s);
      return s;
    };
    const cli = require('./cliServer');
    cli.startCLIServer = async () => ({ port: 1, token: 't' });
    try {
      const lv = require('./localVault/localVaultServer');
      lv.start = async () => 1; lv.stop = () => {}; lv.getPort = () => 1;
    } catch { /* ignore */ }
    const rbi = require('./secureSession');
    rbi.cleanupStaleProfiles = () => 0;
  },
});

const flush = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };
const syncServer = () => servers.find((s) => s.listenArgs && s.listenArgs[0] === 45678);

/** Requête simulée sur le serveur de synchronisation (en-têtes en minuscules, comme Node) */
function request(route, headers = {}) {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    Object.assign(req, { method: 'GET', url: route, headers, socket: { remoteAddress: '127.0.0.1' }, destroy() {} });
    const res = {
      status: 0, headers: {},
      setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      writeHead(s) { this.status = s; },
      end(body) { let json = null; try { json = JSON.parse(body); } catch { /* vide */ } resolve({ status: this.status, json }); },
    };
    syncServer().handler(req, res);
  });
}

/** Demande de jeton d'une extension (identifiant de 32 lettres a-p) */
const askToken = (extId) => request('/auth/token', { 'x-vault-extension': 'rdvault', 'x-vault-extension-id': extId });

test.before(async () => { await flush(); assert.ok(syncServer(), 'serveur de synchronisation démarré'); });

test.after(async () => {
  for (const fn of ctx.app.listeners('will-quit')) fn({ preventDefault() {} });
  await flush();
  http.createServer = origCreateServer;
  ctx.cleanup();
});

test('EXT-25 : boîte d\'appairage sans réponse pendant 60 s → 403 pairing_timeout (pas pairing_denied)', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  // Boîte « ouverte » jusqu'à ce que le signal du délai la ferme (Electron : comme une annulation → cancelId)
  dialogBehavior = (win, opts) => new Promise((resolve) => {
    assert.ok(opts && opts.signal, 'la boîte d\'appairage reçoit un signal d\'abandon (délai)');
    opts.signal.addEventListener('abort', () => resolve({ response: opts.cancelId }));
  });
  const before = dialogCalls.length;
  const pending = askToken('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  await flush();
  assert.equal(dialogCalls.length, before + 1, 'boîte d\'appairage affichée');
  let settled = false;
  pending.then(() => { settled = true; });
  t.mock.timers.tick(59000);
  await flush();
  assert.equal(settled, false, 'pas de réponse avant le délai');
  t.mock.timers.tick(1000);
  const r = await pending;
  assert.equal(r.status, 403);
  assert.deepEqual(r.json, { error: 'pairing_timeout' });
});

test('EXT-25 : refus explicite (bouton « Refuser ») → 403 pairing_denied, inchangé', async () => {
  dialogBehavior = () => Promise.resolve({ response: 1 });
  const r = await askToken('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
  assert.equal(r.status, 403);
  assert.deepEqual(r.json, { error: 'pairing_denied' });
});

test('EXT-25 : après une demande expirée, une nouvelle demande rouvre la boîte (aucun refus mémorisé)', async () => {
  dialogBehavior = () => Promise.resolve({ response: 0 });
  const before = dialogCalls.length;
  const r = await askToken('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(dialogCalls.length, before + 1, 'nouvelle boîte d\'appairage affichée');
  assert.equal(r.status, 200);
  assert.match(r.json.token, /^[0-9a-f]{64}$/);
});
