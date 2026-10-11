// Serveur de synchronisation de l'extension Chrome (SYNC-27, SYNC-28, SYNC-30) — node --test electron/main.syncServer.test.js
// main.js RÉEL sous Node (electron simulé, démarrage complet) ; AUCUN port ouvert : http.createServer est
// remplacé par un double qui capture le gestionnaire de requêtes du serveur de synchronisation, appelé ensuite
// avec des requêtes simulées (extension appairée, jeton valide). Serveur CLI et coffre local remplacés par des
// doubles. userData et TEMP jetables.
// - SYNC-27 : clé TOTP d'une entrée rangée dans un dossier (« MES-SECRETS-dossier/compte ») refusée (400) alors
//   que l'application la crée et la sert ; « .. », « \ » et caractères de contrôle restent refusés.
// - SYNC-28 : renderer planté (ou interface rechargée) : l'extension ne doit plus recevoir les mots de passe.
// - SYNC-30 : port de synchronisation déjà pris (autre session Windows, autre programme) : échec signalé.
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
const dialogs = [];
const origCreateServer = http.createServer;

const ctx = loadMainWithMockElectron({
  ready: true,
  activate: false,
  dialog: { showMessageBox: async (...args) => { dialogs.push(args); return { response: 1 }; } },
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
function request(route, headers = {}, method = 'GET') {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    Object.assign(req, { method, url: route, headers, socket: { remoteAddress: '127.0.0.1' }, destroy() {} });
    const res = {
      status: 0, headers: {},
      setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      writeHead(s) { this.status = s; },
      end(body) { let json = null; try { json = JSON.parse(body); } catch { /* vide */ } resolve({ status: this.status, json }); },
    };
    syncServer().handler(req, res);
    if (method === 'POST') setImmediate(() => req.emit('end'));
  });
}

let token = null;
const auth = () => ({ origin: 'chrome-extension://' + PAIRED, authorization: 'Bearer ' + token });
const writeState = () => ctx.invoke('sync-write-state', {
  vaultUrl: 'http://127.0.0.1:1', username: 'alice', connected: true,
  secrets: [
    { name: 'dossier/compte', engine: 'mes-secrets', username: 'nested-user', password: 'Nested-pass-1', url: 'https://localhost:8457', type: 'login' },
    { name: 'racine', engine: 'mes-secrets', username: 'racine-user', password: 'Racine-pass-1', url: 'https://localhost:8457', type: 'login' },
  ],
});

/** Répond à la prochaine demande de code TOTP envoyée au renderer ; renvoie le nom de clé demandé */
async function answerTotp(code) {
  for (let i = 0; i < 50; i++) {
    const sent = ctx.win.webContents.sent.filter(([ch]) => ch === 'get-totp-code');
    const last = sent[sent.length - 1];
    if (last && !last.answered) {
      last.answered = true;
      const [, keyName, requestId] = last;
      ctx.ipcMain.emit('totp-code-response-' + requestId, { sender: ctx.win.webContents }, { success: true, code });
      return keyName;
    }
    await new Promise((r) => setImmediate(r));
  }
  return null;
}

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

test('SYNC-27 : code TOTP d\'une entrée rangée dans un dossier servi à l\'extension (nom de clé avec « / »)', async () => {
  await writeState();
  const pending = request('/api/totp/' + encodeURIComponent('MES-SECRETS-dossier/compte'), auth());
  const keyName = await answerTotp('399951');
  const r = await pending;
  assert.equal(r.status, 200, 'la clé TOTP d\'une entrée en dossier ne doit pas être refusée (' + JSON.stringify(r.json) + ')');
  assert.equal(r.json.code, '399951');
  assert.equal(keyName, 'MES-SECRETS-dossier/compte', 'nom de clé transmis au renderer sans altération');
});

test('SYNC-27 : témoin à la racine inchangé ; « .. », « \\ », caractères de contrôle et clé trop longue toujours refusés', async () => {
  await writeState();
  const pending = request('/api/totp/MES-SECRETS-racine', auth());
  assert.equal(await answerTotp('948187'), 'MES-SECRETS-racine');
  assert.equal((await pending).status, 200);
  for (const bad of ['MES-SECRETS-a/../b', '../etc', 'MES-SECRETS-a\\b', 'MES-SECRETS-a\u0001b', 'MES-SECRETS-a\u007fb', 'a'.repeat(257)]) {
    const r = await request('/api/totp/' + encodeURIComponent(bad), auth());
    assert.equal(r.status, 400, JSON.stringify(bad) + ' doit être refusé');
  }
  assert.equal((await request('/api/totp/%E0%A4%A', auth())).status, 400, 'encodage invalide refusé');
});

test('SYNC-28 : renderer planté → état purgé, plus aucun mot de passe servi à l\'extension', async () => {
  await writeState();
  let r = await request('/api/secret?host=localhost&engine=mes-secrets&name=racine', auth());
  assert.equal(r.status, 200, 'témoin : mot de passe servi tant que l\'interface est vivante');
  assert.equal(r.json.secret.password, 'Racine-pass-1');

  ctx.win.webContents.crash('crashed');
  r = await request('/api/secret?host=localhost&engine=mes-secrets&name=racine', auth());
  assert.equal(r.status, 401, 'après le plantage du renderer, /api/secret ne doit plus servir le mot de passe');
  r = await request('/sync', auth());
  assert.deepEqual(r.json, { connected: false });
  assert.equal((await request('/api/secrets?host=localhost', auth())).status, 401);
  assert.equal((await ctx.invoke('sync-read-state')).data, null, 'état (mots de passe) libéré de la mémoire');
});

test('SYNC-28 : interface rechargée (navigation du cadre principal) → état purgé', async () => {
  ctx.win.webContents.crashed = false; // renderer relancé
  await writeState();
  assert.equal((await request('/api/secret?host=localhost&engine=mes-secrets&name=racine', auth())).status, 200);
  ctx.win.webContents.emit('did-navigate', {}, 'file:///app/build/index.html', 200, 'OK');
  assert.equal((await request('/api/secret?host=localhost&engine=mes-secrets&name=racine', auth())).status, 401);
  assert.equal((await ctx.invoke('sync-read-state')).data, null);
});

test('SYNC-28 : renderer planté sans évènement (défense en profondeur) → plus rien n\'est servi', async () => {
  ctx.win.webContents.crashed = false;
  await writeState();
  ctx.win.webContents.crashed = true; // isCrashed() vrai, évènement manqué
  assert.equal((await request('/api/secret?host=localhost&engine=mes-secrets&name=racine', auth())).status, 401);
  assert.deepEqual((await request('/sync', auth())).json, { connected: false });
  ctx.win.webContents.crashed = false;
});

test('SYNC-30 : port de synchronisation déjà utilisé → avertissement traduit (non modal) et état signalé', async () => {
  const mainI18n = require('./mainI18n');
  const before = dialogs.length;
  const err = Object.assign(new Error('listen EADDRINUSE: address already in use 127.0.0.1:45678'), { code: 'EADDRINUSE' });
  syncServer().emit('error', err);
  await flush();
  const shown = dialogs.slice(before);
  assert.equal(shown.length, 1, 'un avertissement visible (et un seul)');
  const opts = shown[0][shown[0].length - 1];
  assert.equal(shown[0].length, 1, 'boîte indépendante : ne bloque pas la fenêtre principale');
  assert.equal(opts.title, mainI18n.tm('syncPort.title'));
  assert.equal(opts.message, mainI18n.tm('syncPort.message', { port: 45678 }));
  assert.ok(opts.detail.includes('EADDRINUSE'));
  const st = await ctx.invoke('sync-read-state');
  assert.equal(st.serverError, 'EADDRINUSE');
  // Erreur répétée : pas de seconde boîte
  syncServer().emit('error', err);
  await flush();
  assert.equal(dialogs.length, before + 1);
});
