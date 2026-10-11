// Tests du fichier de session de la CLI (cliServer.js RÉEL sous Node, electron simulé, userData jetable) —
// exécuter avec : node --test electron/cliServer.session.test.js
// STARTUP-23 (défense en profondeur) : stopCLIServer ne supprime cli/session.json que s'il a été écrit par CE
// processus (pid). Avant correction, toute instance qui s'arrêtait (seconde instance, ancienne instance)
// supprimait le fichier de l'instance active : mvault perdait la session en cours.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { EventEmitter } = require('events');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-cli-session-'));
process.env.RDVAULT_LOG_LEVEL = 'error';

class FakeWebContents extends EventEmitter { send() {} }
class FakeWin extends EventEmitter {
  constructor() { super(); this.webContents = new FakeWebContents(); }
  isDestroyed() { return false; } show() {}
}
const fakeWin = new FakeWin();
const electronMock = {
  app: { getPath: () => scratch, getVersion: () => '0.0.0-test', isPackaged: false },
  dialog: { showMessageBox: async () => ({ response: 1 }) },
  BrowserWindow: { getFocusedWindow: () => fakeWin, getAllWindows: () => [fakeWin] },
};
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electronMock;
  return origLoad.call(this, request, parent, isMain);
};

const cli = require('./cliServer');

test.after(() => {
  cli.stopCLIServer();
  Module._load = origLoad;
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
});

const readSession = () => JSON.parse(fs.readFileSync(cli.CLI_SESSION_FILE, 'utf8'));
const start = () => cli.startCLIServer(fakeWin, async () => ({ success: true, data: {} }), async () => [], null, []);

test('le fichier de session est dans le userData simulé (jamais le vrai profil)', () => {
  assert.ok(cli.CLI_SESSION_FILE.startsWith(scratch), cli.CLI_SESSION_FILE);
});

test('arrêt du serveur de CE processus → session.json supprimé', async () => {
  const { port, token } = await start();
  const session = readSession();
  assert.equal(session.pid, process.pid);
  assert.equal(session.port, port);
  assert.equal(session.token, token);
  cli.stopCLIServer();
  assert.equal(fs.existsSync(cli.CLI_SESSION_FILE), false);
});

test('session.json réécrit par une AUTRE instance (autre pid) → conservé intact à l\'arrêt', async () => {
  await start();
  const other = { port: 54321, token: 'jeton-de-l-instance-active', pid: process.pid + 1, started: new Date().toISOString() };
  const content = JSON.stringify(other, null, 2);
  fs.writeFileSync(cli.CLI_SESSION_FILE, content);
  cli.stopCLIServer();
  assert.equal(fs.existsSync(cli.CLI_SESSION_FILE), true, 'session de l\'instance active supprimée');
  assert.equal(fs.readFileSync(cli.CLI_SESSION_FILE, 'utf8'), content, 'contenu modifié');
});

test('instance qui n\'a jamais démarré de serveur (seconde instance) → session.json de l\'instance active conservé', () => {
  const content = JSON.stringify({ port: 4242, token: 't', pid: process.pid + 7 });
  fs.writeFileSync(cli.CLI_SESSION_FILE, content);
  cli.stopCLIServer();
  assert.equal(fs.readFileSync(cli.CLI_SESSION_FILE, 'utf8'), content);
});

test('session.json illisible ou sans pid → conservé (réécrit au prochain démarrage), aucun plantage', async () => {
  for (const content of ['{ pas du json', 'null', JSON.stringify({ port: 1, token: 't' }), JSON.stringify({ pid: String(process.pid) })]) {
    fs.writeFileSync(cli.CLI_SESSION_FILE, content);
    assert.doesNotThrow(() => cli.stopCLIServer());
    assert.equal(fs.readFileSync(cli.CLI_SESSION_FILE, 'utf8'), content, content);
  }
  // Le démarrage suivant réécrit le fichier avec le pid de ce processus, et l'arrêt le supprime
  await start();
  assert.equal(readSession().pid, process.pid);
  cli.stopCLIServer();
  assert.equal(fs.existsSync(cli.CLI_SESSION_FILE), false);
});

test('fichier absent → arrêt sans erreur', () => {
  try { fs.unlinkSync(cli.CLI_SESSION_FILE); } catch { /* déjà absent */ }
  assert.doesNotThrow(() => cli.stopCLIServer());
  assert.equal(fs.existsSync(cli.CLI_SESSION_FILE), false);
});
