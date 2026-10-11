// Renderer FIGÉ de la fenêtre principale (SYNC-28, suite) — node --test electron/main.unresponsive.test.js
// main.js RÉEL sous Node (electron simulé, démarrage complet) ; AUCUN port ouvert : http.createServer est
// remplacé par un double qui capture le gestionnaire de requêtes du serveur de synchronisation (même méthode
// que main.syncServer.test.js). userData et TEMP jetables (test/helpers/main-electron-mock.js).
// Avant : l'évènement 'unresponsive' (boucle infinie, thread JavaScript bloqué) n'était pas écouté ; la
// déconnexion et le délai d'inactivité, qui vivent dans le renderer, ne pouvaient plus s'exécuter, mais
// l'extension recevait toujours les mots de passe (le heartbeat prolongeait même l'état).
// Attendu : purge comme pour un plantage ; plus rien de servi tant que le renderer est figé ; à
// 'responsive', demande de republication au renderer ('sync-resync-request'), dont la synchro rétablit l'état.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { EventEmitter } = require('events');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const PAIRED = 'abcdefghijklmnopabcdefghijklmnop';
const servers = [];
const origCreateServer = http.createServer;

const ctx = loadMainWithMockElectron({
  ready: true,
  activate: false,
  beforeRequire: ({ userData }) => {
    fs.writeFileSync(path.join(userData, 'paired-extensions.json'), JSON.stringify([PAIRED]));
    // Double de serveur HTTP : aucun port réel, gestionnaire capturé
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

let token = null;
const auth = () => ({ origin: 'chrome-extension://' + PAIRED, authorization: 'Bearer ' + token });
const writeState = () => ctx.invoke('sync-write-state', {
  vaultUrl: 'http://127.0.0.1:1', username: 'alice', connected: true,
  secrets: [{ name: 'racine', engine: 'mes-secrets', username: 'racine-user', password: 'Racine-pass-1', url: 'https://localhost:8457', type: 'login' }],
});
const secretStatus = async () => (await request('/api/secret?host=localhost&engine=mes-secrets&name=racine', auth())).status;
const resyncRequests = () => ctx.win.webContents.sent.filter(([ch]) => ch === 'sync-resync-request').length;

test.before(async () => {
  await flush();
  assert.ok(syncServer(), 'serveur de synchronisation démarré (double)');
  token = (await ctx.invoke('sync-get-auth-token')).token;
  assert.match(token, /^[0-9a-f]{64}$/);
});

test.after(async () => {
  // Arrêt propre (heartbeat, serveurs) : évènement will-quit, comme à la fermeture de l'application
  for (const fn of ctx.app.listeners('will-quit')) fn({ preventDefault() {} });
  await flush();
  http.createServer = origCreateServer;
  ctx.cleanup();
});

test('renderer figé (unresponsive) → état purgé, plus aucun mot de passe servi à l\'extension', async () => {
  await writeState();
  assert.equal(await secretStatus(), 200, 'témoin : mot de passe servi tant que l\'interface répond');

  ctx.win.emit('unresponsive');
  assert.equal(await secretStatus(), 401, 'renderer figé : /api/secret ne doit plus servir le mot de passe');
  assert.deepEqual((await request('/sync', auth())).json, { connected: false });
  assert.equal((await request('/api/secrets?host=localhost', auth())).status, 401);
  assert.equal((await ctx.invoke('sync-read-state')).data, null, 'état (mots de passe) libéré de la mémoire');
});

test('écriture reçue pendant le gel (envoyée juste avant) : jamais servie tant que le renderer est figé', async () => {
  await writeState();
  assert.equal(await secretStatus(), 401);
  assert.deepEqual((await request('/sync', auth())).json, { connected: false });
});

test('de nouveau réactif (responsive) → republication demandée au renderer ; sa synchro rétablit l\'état', async () => {
  const before = resyncRequests();
  ctx.win.emit('responsive');
  assert.equal(resyncRequests(), before + 1, 'demande de republication envoyée au renderer (sync-resync-request)');
  await writeState(); // useSync republie depuis son cache
  assert.equal(await secretStatus(), 200, 'état rétabli par la synchro du renderer');
  assert.equal((await request('/sync', auth())).json.connected, true);
});

test('responsive sans gel préalable : aucune demande de republication', async () => {
  const before = resyncRequests();
  ctx.win.emit('responsive');
  assert.equal(resyncRequests(), before);
  assert.equal(await secretStatus(), 200);
});

test('gel puis rechargement de l\'interface : le nouveau renderer n\'hérite pas de l\'état « figé »', async () => {
  ctx.win.emit('unresponsive');
  assert.equal(await secretStatus(), 401);
  ctx.win.webContents.emit('did-navigate', {}, 'file:///app/build/index.html', 200, 'OK');
  await writeState(); // nouvelle connexion dans l'interface rechargée
  assert.equal(await secretStatus(), 200);
});
