// Tests des plafonds d'export / d'import de main.js — exécuter avec : node --test electron/main.exportImport.test.js
// main.js RÉEL chargé sous Node avec un module « electron » simulé : dialogues système simulés
// (aucune fenêtre), fichiers écrits dans un dossier jetable, jamais le vrai coffre (%APPDATA%\RDVAULT).
// Un export accepté par export-save-file (pièces jointes en base64 incluses) doit TOUJOURS pouvoir être
// relu par import-open-file : même plafond, mesuré dans la même unité (octets du fichier).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { EventEmitter } = require('events');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-export-test-'));
const userData = path.join(scratch, 'userData');
const tempDir = path.join(scratch, 'tmp');
fs.mkdirSync(userData, { recursive: true });
fs.mkdirSync(tempDir, { recursive: true });
process.env.RDVAULT_LOG_LEVEL = 'error';

const MB = 1024 * 1024;
const LIMIT = 100 * MB; // plafond attendu, identique à l'export et à l'import

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

// Dialogues système simulés : fichier choisi par « l'utilisateur » = dialogTarget.file
const dialogTarget = { file: null };
const electronMock = {
  app, ipcMain, BrowserWindow,
  clipboard: { writeText() {}, readText() { return ''; }, clear() {}, write() {} },
  Menu: { setApplicationMenu() {} },
  globalShortcut: { unregisterAll() {} },
  dialog: {
    showMessageBox: async () => ({ response: 1 }),
    showErrorBox() {},
    showSaveDialog: async () => ({ canceled: false, filePath: dialogTarget.file }),
    showOpenDialog: async () => ({ canceled: false, filePaths: [dialogTarget.file] }),
  },
  shell: { openExternal: async () => {} },
  powerMonitor: { on() {} },
};
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electronMock;
  return origLoad.call(this, request, parent, isMain);
};

require('./main.js');

// Fenêtre principale (validateIpcSender) créée via l'évènement « activate »
app.emit('activate');
const win = BrowserWindow.all[0];
const ev = { sender: win.webContents };
const invoke = (ch, ...args) => handlers.get(ch)(ev, ...args);
const exportFile = (name, content) => { dialogTarget.file = path.join(scratch, name); return invoke('export-save-file', { defaultName: name, filters: [], content }); };
const importFile = (name) => { dialogTarget.file = path.join(scratch, name); return invoke('import-open-file', { filters: [] }); };

test.after(() => {
  Module._load = origLoad;
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
});

test('export de 60 Mo (pièces jointes en base64) : réimportable (l\'import plafonnait à 50 Mo)', async () => {
  const content = JSON.stringify({ format: 'rdvault-export', attachment: 'QUJD'.repeat(15 * MB) }); // ~60 Mo
  const w = await exportFile('export-60.json', content);
  assert.equal(w.success, true, 'export de 60 Mo accepté');
  const r = await importFile('export-60.json');
  assert.equal(r.success, true, `export de 60 Mo réimportable (erreur : ${r.error})`);
  assert.equal(r.content.length, content.length);
  assert.equal(r.content === content, true, 'contenu relu identique');
});

test('export au plafond exact (100 Mo) : accepté puis réimporté à l\'identique', async () => {
  const content = 'A'.repeat(LIMIT);
  const w = await exportFile('export-max.json', content);
  assert.equal(w.success, true, 'export au plafond accepté');
  assert.equal(fs.statSync(path.join(scratch, 'export-max.json')).size, LIMIT);
  const r = await importFile('export-max.json');
  assert.equal(r.success, true, `export au plafond réimportable (erreur : ${r.error})`);
  assert.equal(r.content.length, LIMIT);
  fs.rmSync(path.join(scratch, 'export-max.json'), { force: true });
});

test('export dépassant le plafond d\'un octet : refusé, aucun fichier écrit', async () => {
  const w = await exportFile('export-over.json', 'A'.repeat(LIMIT + 1));
  assert.equal(w.success, false);
  assert.equal(fs.existsSync(path.join(scratch, 'export-over.json')), false);
});

test('export multi-octets : plafond mesuré en octets écrits (comme à l\'import), pas en caractères', async () => {
  // 52 428 801 caractères (< plafond) mais 104 857 602 octets UTF-8 (> plafond) : jamais réimportable
  const w = await exportFile('export-utf8.json', 'é'.repeat(LIMIT / 2 + 1));
  assert.equal(w.success, false, 'contenu dont la taille UTF-8 dépasse le plafond refusé');
  assert.equal(fs.existsSync(path.join(scratch, 'export-utf8.json')), false);
});

test('import d\'un fichier dépassant le plafond : refusé avec la limite affichée', async () => {
  const big = path.join(scratch, 'import-over.json');
  fs.writeFileSync(big, '');
  fs.truncateSync(big, LIMIT + 1);
  const r = await importFile('import-over.json');
  assert.equal(r.success, false);
  assert.match(String(r.error), /max 100 MB/);
  fs.rmSync(big, { force: true });
});
