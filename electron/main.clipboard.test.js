// Tests du presse-papiers sécurisé de main.js (SESSION-16 / SESSION-22) — exécuter avec : node --test electron/
// main.js RÉEL chargé sous Node avec un module « electron » simulé : aucun presse-papiers réel,
// aucun PowerShell, aucun mstsc/FileZilla lancé ; userData et temp dans un dossier jetable.
// Vérifie qu'un mot de passe copié par l'application est effacé à la fermeture (will-quit) :
// - après deux copies rapprochées (le nettoyage différé de la 1re ne doit pas « oublier » la 2e) ;
// - après une copie faite par open-rdp-connection / open-sftp-connection.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { EventEmitter } = require('events');
const child_process = require('child_process');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-clip-test-'));
const userData = path.join(scratch, 'userData');
const tempDir = path.join(scratch, 'tmp');
fs.mkdirSync(userData, { recursive: true });
fs.mkdirSync(tempDir, { recursive: true });
process.env.RDVAULT_LOG_LEVEL = 'error';

// ---------- Module electron simulé ----------
const appEvents = new EventEmitter();
const app = {
  isPackaged: false,
  commandLine: { appendSwitch() {} },
  disableHardwareAcceleration() {},
  on(e, fn) { appEvents.on(e, fn); return app; },
  once(e, fn) { appEvents.once(e, fn); return app; },
  emit(e, ...a) { return appEvents.emit(e, ...a); },
  listeners(e) { return appEvents.listeners(e); },
  getPath(n) { return n === 'userData' ? userData : tempDir; },
  setPath() {},
  requestSingleInstanceLock() { return true; },
  quit() {},
  whenReady() { return new Promise(() => {}); }, // jamais prêt : aucun serveur démarré
  setAsDefaultProtocolClient() { return true; },
  getVersion() { return '0.0.0-test'; },
};
const ipcMain = new EventEmitter();
const handlers = new Map();
ipcMain.handle = (ch, fn) => { handlers.set(ch, fn); };

// Presse-papiers simulé (texte courant)
const clip = { text: '' };
const clipboard = {
  writeText(t) { clip.text = String(t); },
  readText() { return clip.text; },
  clear() { clip.text = ''; },
  write(o) { clip.text = String((o && o.text) || ''); },
};

class WebContents extends EventEmitter {
  constructor() {
    super();
    this.session = {
      setPermissionRequestHandler() {}, setPermissionCheckHandler() {}, setCertificateVerifyProc() {},
      webRequest: { onHeadersReceived() {} },
    };
  }
  setWindowOpenHandler() {}
  send() {}
  focus() {} setIgnoreMenuShortcuts() {} closeDevTools() {}
}
class BrowserWindow extends EventEmitter {
  constructor() { super(); this.webContents = new WebContents(); BrowserWindow.all.push(this); }
  loadFile() { return Promise.resolve(); } loadURL() { return Promise.resolve(); }
  show() {} focus() {} isDestroyed() { return false; } setMenuBarVisibility() {}
  setSize() {} center() {} isMaximized() { return false; } isMinimized() { return false; }
  restore() {} close() {} minimize() {} maximize() {} unmaximize() {} setResizable() {} setMaximizable() {}
  static getAllWindows() { return BrowserWindow.all; }
}
BrowserWindow.all = [];

const electronMock = {
  app, ipcMain, clipboard, BrowserWindow,
  Menu: { setApplicationMenu() {} },
  globalShortcut: { unregisterAll() {} },
  dialog: { showMessageBox: async () => ({ response: 1 }), showErrorBox() {} },
  shell: { openExternal: async () => {} },
  powerMonitor: { on() {} },
};
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electronMock;
  return origLoad.call(this, request, parent, isMain);
};

// Aucun processus externe : nettoyage de l'historique Win+V (PowerShell) et clients RDP/SFTP simulés
const historyClears = [];
child_process.execFile = (file, args, opts, cb) => {
  historyClears.push(file);
  if (typeof cb === 'function') setImmediate(() => cb(null, '', ''));
  return { on() {} };
};
child_process.spawn = () => ({ unref() {}, on() {} });

// FileZilla « installé » (chemins testés par open-sftp-connection), sans rien lancer
const origExistsSync = fs.existsSync;
fs.existsSync = (p) => (/filezilla\.exe$/i.test(String(p)) ? true : origExistsSync(p));

require('./main.js');

// Fenêtre principale (validateIpcSender) créée via l'évènement « activate »
app.emit('activate');
const win = BrowserWindow.all[0];
const ev = { sender: win.webContents };
const invoke = (ch, ...args) => handlers.get(ch)(ev, ...args);
const quit = async () => { for (const fn of app.listeners('will-quit')) await fn({ preventDefault() {} }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clearsDuring = async (fn) => { const before = historyClears.length; await fn(); await sleep(20); return historyClears.length - before; };

test.after(() => {
  fs.existsSync = origExistsSync;
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
});

test('témoin : une copie puis fermeture → presse-papiers vidé', async () => {
  await invoke('clipboard-copy-secure', 'TEMOIN-PWD', 1000);
  await sleep(100);
  await quit();
  assert.equal(clip.text, '');
  await sleep(1200);
});

test('deux copies rapprochées : la fermeture efface encore la seconde (et l\'historique Win+V)', async () => {
  await invoke('clipboard-copy-secure', 'identifiant-A', 1000); // nettoyage différé de A à 1,1 s
  await sleep(500);
  await invoke('clipboard-copy-secure', 'MOT-DE-PASSE-B', 3000); // B effacé à 3,5 s
  await sleep(800); // t = 1,3 s : le nettoyage différé de A a tourné
  const n = await clearsDuring(quit);
  assert.equal(clip.text, '', 'le mot de passe B doit être effacé à la fermeture');
  assert.ok(n > 0, 'l\'historique Win+V doit être vidé à la fermeture');
  await sleep(2500);
});

test('« Effacer maintenant » après le nettoyage différé de la copie précédente : vide aussi l\'historique', async () => {
  await invoke('clipboard-copy-secure', 'identifiant-C', 1000);
  await sleep(500);
  await invoke('clipboard-copy-secure', 'MOT-DE-PASSE-D', 3000);
  await sleep(800);
  const n = await clearsDuring(() => invoke('clipboard-clear-now'));
  assert.equal(clip.text, '');
  assert.ok(n > 0, 'l\'effacement immédiat doit passer par le minuteur de la copie (historique Win+V compris)');
  await sleep(2500);
});

test('open-rdp-connection : le mot de passe copié est effacé à la fermeture', async () => {
  clip.text = '';
  const r = await invoke('open-rdp-connection', { host: 'srv-rdp.example', username: 'admin', password: 'RDP-SECRET-PWD', port: 3389 });
  assert.equal(r && r.success, true);
  assert.equal(clip.text, 'RDP-SECRET-PWD');
  await sleep(50);
  const n = await clearsDuring(quit);
  assert.equal(clip.text, '');
  assert.ok(n > 0);
  await sleep(2200); // laisser supprimer le .rdp temporaire
});

test('open-sftp-connection : le mot de passe copié est effacé à la fermeture', async () => {
  clip.text = '';
  const r = await invoke('open-sftp-connection', { host: 'srv-sftp.example', username: 'admin', password: 'SFTP-SECRET-PWD', port: '22' }); // port en texte, comme urlHandler.js
  assert.equal(r && r.success, true);
  assert.equal(clip.text, 'SFTP-SECRET-PWD');
  await sleep(50);
  await quit();
  assert.equal(clip.text, '');
  await sleep(2200); // laisser supprimer le fichier de session temporaire
});

test('fermeture : un contenu copié par l\'utilisateur après l\'application n\'est pas effacé', async () => {
  await invoke('clipboard-copy-secure', 'MOT-DE-PASSE-E', 3000);
  clipboard.writeText('texte-de-l-utilisateur');
  await quit();
  assert.equal(clip.text, 'texte-de-l-utilisateur');
  await sleep(3200);
});
