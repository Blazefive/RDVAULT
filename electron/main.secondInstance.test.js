// Seconde instance de l'application (STARTUP-23) — node --test electron/main.secondInstance.test.js
// main.js RÉEL sous Node (electron simulé) : verrou d'instance unique REFUSÉ et app.whenReady() résolu, comme
// pour un double-clic sur le raccourci ou un lien rdvault://share/… pendant que RDVAULT tourne. Electron émet
// quand même 'ready' après un app.quit() demandé avant 'ready', et 'will-quit' AVANT 'ready'.
// Attendu : la seconde instance ne démarre RIEN (ni fenêtre, ni serveur de synchronisation, ni serveur CLI, ni
// coffre local) et ne nettoie RIEN de la première instance (userData/cli/session.json intact, profils RBI).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { EventEmitter } = require('events');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const spies = { createServer: 0, cliStart: 0, cliStop: 0, localVaultStart: 0, rbiCleanup: 0, closeAll: 0 };
const FIRST_INSTANCE_SESSION = { port: 59896, token: 'a'.repeat(64), pid: 4242 };
let sessionFile = null;

const origCreateServer = http.createServer;
const ctx = loadMainWithMockElectron({
  singleInstanceLock: false,
  ready: true,
  activate: false,
  beforeRequire: ({ userData }) => {
    // Session CLI de la PREMIÈRE instance (lue par mvault)
    sessionFile = path.join(userData, 'cli', 'session.json');
    fs.mkdirSync(path.dirname(sessionFile), { recursive: true });
    fs.writeFileSync(sessionFile, JSON.stringify(FIRST_INSTANCE_SESSION));
    // Aucun port réel : tout serveur HTTP créé est compté puis remplacé par un double inerte
    http.createServer = () => { spies.createServer++; const s = new EventEmitter(); s.listen = () => s; s.close = () => {}; return s; };
    const cli = require('./cliServer');
    cli.startCLIServer = async () => { spies.cliStart++; return { port: 1, token: 't' }; };
    const realStop = cli.stopCLIServer;
    cli.stopCLIServer = (...a) => { spies.cliStop++; return realStop(...a); };
    try {
      const lv = require('./localVault/localVaultServer');
      lv.start = async () => { spies.localVaultStart++; return 1; };
      lv.stop = () => {};
    } catch { /* module natif indisponible : le démarrage échouerait de toute façon */ }
    const rbi = require('./secureSession');
    rbi.cleanupStaleProfiles = () => { spies.rbiCleanup++; return 0; };
    rbi.closeAllSessions = async () => { spies.closeAll++; };
  },
});

const flush = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

test.after(() => { http.createServer = origCreateServer; ctx.cleanup(); });

test('seconde instance : app.quit() demandé, aucun gestionnaire second-instance', async () => {
  await flush();
  assert.ok(ctx.app.quitCalls >= 1, 'la seconde instance demande sa fermeture');
  assert.equal(ctx.app.listeners('second-instance').length, 0, 'seule la première instance reçoit les liens');
});

test('seconde instance : rien n\'est démarré au \'ready\' (fenêtre, serveurs, coffre local, nettoyage RBI)', async () => {
  await flush();
  assert.equal(ctx.FakeBrowserWindow.all.length, 0, 'aucune fenêtre (pas de « Chargement échoué »)');
  assert.equal(spies.createServer, 0, 'aucun serveur de synchronisation');
  assert.equal(spies.cliStart, 0, 'aucun serveur CLI (session.json de la première instance non réécrit)');
  assert.equal(spies.localVaultStart, 0, 'coffre local non ouvert');
  assert.equal(spies.rbiCleanup, 0, 'profils RBI de la première instance jamais nettoyés par la seconde');
  assert.deepEqual(JSON.parse(fs.readFileSync(sessionFile, 'utf8')), FIRST_INSTANCE_SESSION);
});

test('seconde instance : \'will-quit\' ne touche pas aux ressources de la première (session CLI intacte)', async () => {
  const ev = { prevented: false, preventDefault() { ev.prevented = true; } };
  for (const fn of ctx.app.listeners('will-quit')) await fn(ev);
  const prevented = ev.prevented;
  await flush();
  assert.equal(spies.cliStop, 0, 'stopCLIServer non appelé');
  assert.equal(fs.existsSync(sessionFile), true, 'userData/cli/session.json de la première instance conservé');
  assert.deepEqual(JSON.parse(fs.readFileSync(sessionFile, 'utf8')), FIRST_INSTANCE_SESSION);
  assert.equal(prevented, false, 'la sortie de la seconde instance n\'est pas retardée');
  assert.equal(spies.closeAll, 0);
});

test('seconde instance : \'activate\' ne crée pas de fenêtre', async () => {
  ctx.app.emit('activate');
  await flush();
  assert.equal(ctx.FakeBrowserWindow.all.length, 0);
});
