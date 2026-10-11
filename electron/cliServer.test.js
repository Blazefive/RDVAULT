// Tests du serveur CLI (cliServer.js RÉEL sous Node, electron simulé, userData jetable) —
// exécuter avec : node --test electron/cliServer.test.js
// - MAIN-10 : GET /health (non authentifié) et toute requête sans jeton valide ne doivent pas épuiser le quota
//   des commandes AUTHENTIFIÉES (un processus local sans jeton bloquait /secret, /ssh, /engines… par 429) ;
//   les requêtes non authentifiées restent limitées, les authentifiées aussi (compteurs séparés).
// - MAIN-26 : popups natives (accès à un secret, rafale, clé d'hôte SSH) dans la langue de l'interface ;
//   français strictement identique à l'existant ; boutons 0 = approuver, 1 = refuser (défaut / annulation).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const { EventEmitter } = require('events');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-cli-test-'));
process.env.RDVAULT_LOG_LEVEL = 'error';

const dialogs = [];
let dialogAnswer = 1;
class FakeWebContents extends EventEmitter { send() {} }
class FakeWin extends EventEmitter {
  constructor() { super(); this.webContents = new FakeWebContents(); }
  isDestroyed() { return false; } show() {}
}
const fakeWin = new FakeWin();
const electronMock = {
  app: { getPath: () => scratch, getVersion: () => '0.0.0-test', isPackaged: false },
  dialog: { showMessageBox: async (win, opts) => { dialogs.push(opts); return { response: typeof dialogAnswer === 'function' ? dialogAnswer(opts) : dialogAnswer }; } },
  BrowserWindow: { getFocusedWindow: () => fakeWin, getAllWindows: () => [fakeWin] },
};
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electronMock;
  return origLoad.call(this, request, parent, isMain);
};

const cli = require('./cliServer');
const mainI18n = require('./mainI18n');

test.after(() => {
  cli.stopCLIServer();
  Module._load = origLoad;
  mainI18n.resetUiLanguage();
  mainI18n.setDefaultLanguageProvider(null);
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
});

function req(port, method, urlPath, token, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port, method, path: urlPath, headers: {
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
    } }, (res) => { let b = ''; res.on('data', c => { b += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch { /* ignore */ } resolve({ status: res.statusCode, json: j }); }); });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

const readFn = async () => ({ success: true, data: { password: 'pw' } });
const enginesFn = async () => [{ name: 'test', version: 2, type: 'kv' }];
async function freshServer(autoApprove = []) {
  cli.stopCLIServer();
  return cli.startCLIServer(fakeWin, readFn, enginesFn, null, autoApprove);
}

// ─── MAIN-10 : limitation de débit ───

test('31 GET /health non authentifiés : les commandes authentifiées restent servies', async () => {
  const { port, token } = await freshServer();
  let health429 = 0;
  for (let i = 0; i < 31; i++) { const r = await req(port, 'GET', '/health'); if (r.status === 429) health429++; }
  const eng = await req(port, 'GET', '/engines', token);
  assert.equal(eng.status, 200, 'GET /engines authentifié bloqué (429) par des /health non authentifiés');
  const rules = await req(port, 'GET', '/rules', token);
  assert.equal(rules.status, 200);
  assert.ok(health429 <= 1, 'compteur non authentifié : au plus la 31e requête refusée');
});

test('jetons faux en rafale : toujours limités (429), sans bloquer le vrai jeton', async () => {
  const { port, token } = await freshServer();
  let bad429 = 0;
  for (let i = 0; i < 35; i++) { const r = await req(port, 'POST', '/secret', 'f'.repeat(64), { engine: 'e', path: 'p' }); if (r.status === 429) bad429++; }
  assert.ok(bad429 > 0, 'requêtes non authentifiées toujours soumises au limiteur (' + bad429 + ')');
  const h = await req(port, 'GET', '/health');
  assert.equal(h.status, 429, '/health partage le compteur NON authentifié');
  const eng = await req(port, 'GET', '/engines', token);
  assert.equal(eng.status, 200, 'le vrai jeton n\'est pas bloqué par les requêtes non authentifiées');
});

test('requêtes authentifiées : toujours limitées à RATE_LIMIT par minute', async () => {
  const { port, token } = await freshServer();
  let auth429 = 0;
  for (let i = 0; i < cli.CLI_CONFIG.RATE_LIMIT + 3; i++) { const r = await req(port, 'GET', '/rules', token); if (r.status === 429) auth429++; }
  assert.equal(auth429, 3, 'au-delà de RATE_LIMIT, les requêtes authentifiées sont refusées');
  const h = await req(port, 'GET', '/health');
  assert.equal(h.status, 200, '/health n\'est pas bloqué par le compteur authentifié');
});

test('/ssh/resize authentifiés : toujours exemptés (aucun 429, compteur authentifié intact)', async () => {
  const { port, token } = await freshServer();
  for (let i = 0; i < 40; i++) {
    const r = await req(port, 'POST', '/ssh/resize', token, { authSock: 'x', rows: 24, cols: 80 });
    assert.equal(r.status, 200);
  }
  assert.equal((await req(port, 'GET', '/engines', token)).status, 200);
});

// ─── MAIN-26 : langue des popups ───

test('popup d\'accès CLI : français identique à l\'existant (LANG de config = fr)', async () => {
  mainI18n.resetUiLanguage();
  mainI18n.setDefaultLanguageProvider(() => 'fr');
  const { port, token } = await freshServer();
  dialogs.length = 0;
  dialogAnswer = 1;
  const r = await req(port, 'POST', '/secret', token, { engine: 'kv', path: 'prod/db' });
  assert.equal(r.status, 403);
  assert.equal(dialogs.length, 1);
  const d = dialogs[0];
  assert.deepEqual(d.buttons, ['Autoriser', 'Refuser']);
  assert.equal(d.title, 'Accès secret — CLI mvault');
  assert.equal(d.message, 'Un processus CLI demande l\'accès à un secret Vault.');
  assert.equal(d.detail, 'Chemin : kv/prod/db\n\nAutoriser l\'accès ?');
  assert.equal(d.defaultId, 1);
  assert.equal(d.cancelId, 1);
});

test('popup d\'accès CLI : langue de l\'interface (en, de), boutons 0 = approuver / 1 = refuser', async () => {
  const { port, token } = await freshServer();
  mainI18n.setUiLanguage('en');
  dialogs.length = 0;
  dialogAnswer = 0;
  let r = await req(port, 'POST', '/secret', token, { engine: 'kv', path: 'prod/db', key: 'password' });
  assert.equal(r.status, 200, 'réponse 0 = Allow → accès accordé');
  assert.deepEqual(dialogs[0].buttons, ['Allow', 'Deny']);
  assert.equal(dialogs[0].title, 'Secret access — mvault CLI');
  assert.equal(dialogs[0].message, 'A CLI process is requesting access to a Vault secret.');
  assert.equal(dialogs[0].detail, 'Path: kv/prod/db\n\nAllow access?');
  assert.equal(dialogs[0].defaultId, 1);
  mainI18n.setUiLanguage('de');
  dialogAnswer = 1;
  r = await req(port, 'POST', '/secret', token, { engine: 'kv', path: 'prod/db' });
  assert.equal(r.status, 403, 'réponse 1 = Ablehnen → refus');
  assert.deepEqual(dialogs[1].buttons, ['Zulassen', 'Ablehnen']);
  assert.match(dialogs[1].detail, /^Pfad: kv\/prod\/db/);
});

test('rafale d\'accès auto-approuvés : popup forcée et traduite', async () => {
  mainI18n.setUiLanguage('en');
  const { port, token } = await freshServer(['kv/*']);
  dialogs.length = 0;
  dialogAnswer = 1;
  for (let i = 0; i <= cli.CLI_CONFIG.BURST_THRESHOLD; i++) await req(port, 'POST', '/secret', token, { engine: 'kv', path: 'a' + i });
  assert.equal(dialogs.length, 1, 'une seule popup (au-delà du seuil de rafale)');
  assert.match(dialogs[0].detail, /^Path: kv\/a\d+ \[burst: \d+ accesses in \d+s\]\n\nAllow access\?$/);
});

test('langue inconnue : ignorée (langue précédente conservée) ; repli anglais si LANG invalide', async () => {
  mainI18n.setUiLanguage('ja');
  assert.equal(mainI18n.setUiLanguage('xx'), false);
  assert.equal(mainI18n.getLanguage(), 'ja');
  mainI18n.resetUiLanguage();
  mainI18n.setDefaultLanguageProvider(() => 'klingon');
  assert.equal(mainI18n.getLanguage(), 'en');
  const { port, token } = await freshServer();
  dialogs.length = 0;
  await req(port, 'POST', '/secret', token, { engine: 'kv', path: 'x' });
  assert.deepEqual(dialogs[0].buttons, ['Allow', 'Deny']);
});

test('popup « clé d\'hôte SSH inconnue » (CLI) : traduite, refus par défaut, rien mémorisé', async () => {
  const crypto = require('crypto');
  const { Server } = require('ssh2');
  const hostKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
  // Serveur SSH jouet : la clé d'hôte inconnue est refusée avant toute authentification
  const srv = new Server({ hostKeys: [hostKey] }, (client) => { client.on('authentication', (c) => c.reject()); client.on('error', () => {}); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const sshPort = srv.address().port;
  try {
    for (const [lang, title, buttons, detailRe] of [
      ['fr', 'Clé d\'hôte SSH inconnue — CLI mvault', ['Mémoriser et continuer', 'Refuser'], /^Hôte : 127\.0\.0\.1:\d+\nEmpreinte : SHA256:\S+\n\nMémoriser cette clé et continuer \?$/],
      ['en', 'Unknown SSH host key — mvault CLI', ['Remember and continue', 'Deny'], /^Host: 127\.0\.0\.1:\d+\nFingerprint: SHA256:\S+\n\nRemember this key and continue\?$/],
      ['ru', 'Неизвестный ключ хоста SSH — CLI mvault', ['Запомнить и продолжить', 'Отклонить'], /^Хост: 127\.0\.0\.1:\d+\n/],
    ]) {
      mainI18n.setUiLanguage(lang);
      const sshReadFn = async () => ({ success: true, data: { username: 'deploy', password: 'pw' } });
      cli.stopCLIServer();
      const { port, token } = await cli.startCLIServer(fakeWin, sshReadFn, enginesFn, null, ['kv/*']);
      dialogs.length = 0;
      // Accès au secret approuvé (éventuelle popup de rafale : le compteur de rafale est global), clé d'hôte refusée
      dialogAnswer = (o) => (/SSH/.test(o.title) ? 1 : 0);
      const r = await req(port, 'POST', '/ssh', token, { engine: 'kv', path: 'srv', host: '127.0.0.1', port: sshPort, command: 'hostname' });
      assert.equal(r.status, 403, `${lang} : clé refusée → 403 (${JSON.stringify(r.json)})`);
      assert.equal(r.json.error, 'HOST_KEY_REJECTED');
      const d = dialogs.find(o => /SSH/.test(o.title));
      assert.ok(d, `${lang} : popup de clé d'hôte affichée`);
      assert.equal(d.title, title);
      assert.deepEqual(d.buttons, buttons);
      assert.match(d.detail, detailRe);
      assert.equal(d.defaultId, 1);
      assert.equal(d.cancelId, 1);
    }
    assert.equal(fs.existsSync(path.join(scratch, 'known_hosts.json')), false, 'aucune clé mémorisée après refus');
  } finally {
    srv.close();
  }
});
