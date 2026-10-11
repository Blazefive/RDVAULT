// Chargement de electron/main.js RÉEL sous Node avec un module « electron » simulé (tests node --test).
// Par défaut : aucune fenêtre réelle, aucun serveur démarré (app.whenReady() ne se résout jamais), userData,
// temp et TEMP/TMP (profils RBI) dans un dossier jetable : jamais le vrai coffre (%APPDATA%\RDVAULT) ni le
// dossier temporaire réel. config.cfg du projet seulement LU.
// Options pour les tests de démarrage : ready (whenReady résolu), singleInstanceLock (verrou refusé =
// seconde instance), activate (création de la fenêtre par l'évènement « activate »).

const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { EventEmitter } = require('events');

class FakeWebContents extends EventEmitter {
  constructor() {
    super();
    this.sent = [];
    this.crashed = false;
    this.certVerifyProc = null;   // session.setCertificateVerifyProc (épinglage TLS)
    this.headersListener = null;  // session.webRequest.onHeadersReceived (CSP)
    const wc = this;
    this.session = {
      setPermissionRequestHandler() {}, setPermissionCheckHandler() {},
      setCertificateVerifyProc(proc) { wc.certVerifyProc = proc; },
      webRequest: { onHeadersReceived(...args) { wc.headersListener = args[args.length - 1]; } },
    };
  }
  setWindowOpenHandler() {}
  send(channel, ...args) { this.sent.push([channel, ...args]); }
  focus() {} setIgnoreMenuShortcuts() {} closeDevTools() {}
  isCrashed() { return this.crashed; }
  isDestroyed() { return false; }
  /** Plantage simulé du renderer : même évènement qu'Electron ('render-process-gone') */
  crash(reason = 'crashed') { this.crashed = true; this.emit('render-process-gone', {}, { reason, exitCode: 1 }); }
}

/**
 * Fenêtre simulée qui reproduit le comportement d'Electron 38 (Windows) constaté sur la vraie fenêtre :
 * setResizable(false) FIGE les tailles minimale et maximale sur la taille courante, setResizable(true)
 * les libère, et setSize() est borné par ces contraintes. Chaque appel est journalisé (ordre vérifiable).
 */
class FakeBrowserWindow extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.webContents = new FakeWebContents();
    this.calls = [];
    this.size = [opts.width || 800, opts.height || 600];
    this.resizable = opts.resizable !== false;
    this.maximizable = opts.maximizable !== false;
    this.maximized = false;
    this.min = this.resizable ? [0, 0] : [...this.size];
    this.max = this.resizable ? [Infinity, Infinity] : [...this.size];
    FakeBrowserWindow.all.push(this);
  }
  loadFile() { return Promise.resolve(); } loadURL() { return Promise.resolve(); }
  show() {} focus() {} isDestroyed() { return false; } setMenuBarVisibility() {}
  isMinimized() { return false; } restore() {} close() {} minimize() {}
  isVisible() { return true; }
  isMaximized() { return this.maximized; }
  maximize() { this.calls.push(['maximize']); this.maximized = true; this.emit('maximize'); }
  unmaximize() { this.calls.push(['unmaximize']); if (this.maximized) { this.maximized = false; this.emit('unmaximize'); } }
  center() { this.calls.push(['center']); }
  setMaximizable(v) { this.calls.push(['setMaximizable', v]); this.maximizable = v; }
  setResizable(v) {
    this.calls.push(['setResizable', v]);
    this.resizable = v;
    if (v) { this.min = [0, 0]; this.max = [Infinity, Infinity]; } else { this.min = [...this.size]; this.max = [...this.size]; }
  }
  setSize(w, h) {
    this.calls.push(['setSize', w, h]);
    const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);
    this.size = [clamp(w, this.min[0], this.max[0]), clamp(h, this.min[1], this.max[1])];
  }
  getSize() { return [...this.size]; }
  isResizable() { return this.resizable; }
  static getAllWindows() { return FakeBrowserWindow.all; }
  static getFocusedWindow() { return FakeBrowserWindow.all[0] || null; }
}
FakeBrowserWindow.all = [];

/**
 * Charge electron/main.js avec un module electron simulé et crée la fenêtre principale (évènement « activate »).
 * @param {Object} [opts]
 * @param {Object} [opts.dialog] - méthodes de dialog à remplacer (showMessageBox, showErrorBox…)
 * @param {Function} [opts.beforeRequire] - appelé juste avant require(main.js) ({ electronMock, userData, scratch, tempDir })
 * @param {boolean} [opts.ready=false] - app.whenReady() résolu (démarrage complet : fenêtre, serveurs…)
 * @param {boolean} [opts.singleInstanceLock=true] - false : verrou d'instance unique refusé (seconde instance)
 * @param {boolean} [opts.activate=true] - créer la fenêtre principale par l'évènement « activate »
 * @returns {{ scratch, userData, tempDir, app, ipcMain, handlers, electronMock, win, ev, invoke, send, cleanup }}
 *   win / ev / invoke / send désignent toujours la DERNIÈRE fenêtre créée (fenêtre principale courante).
 */
function loadMainWithMockElectron(opts = {}) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-main-test-'));
  const userData = path.join(scratch, 'userData');
  const tempDir = path.join(scratch, 'tmp');
  fs.mkdirSync(userData, { recursive: true });
  fs.mkdirSync(tempDir, { recursive: true });
  process.env.RDVAULT_LOG_LEVEL = process.env.RDVAULT_LOG_LEVEL || 'error';
  // Nettoyage des profils RBI (os.tmpdir()) limité au dossier jetable : jamais le dossier temporaire réel
  process.env.TEMP = tempDir;
  process.env.TMP = tempDir;

  const appEvents = new EventEmitter();
  const app = {
    isPackaged: false,
    exitCalls: [],
    quitCalls: 0,
    commandLine: { appendSwitch() {} },
    disableHardwareAcceleration() {},
    on(e, fn) { appEvents.on(e, fn); return app; },
    once(e, fn) { appEvents.once(e, fn); return app; },
    emit(e, ...a) { return appEvents.emit(e, ...a); },
    listeners(e) { return appEvents.listeners(e); },
    getPath(n) { return n === 'userData' ? userData : (n === 'home' ? scratch : tempDir); },
    setPath() {},
    requestSingleInstanceLock() { return opts.singleInstanceLock !== false; },
    quit() { app.quitCalls++; },
    exit(code) { app.exitCalls.push(code === undefined ? 0 : code); },
    // Par défaut jamais prêt : aucun serveur démarré
    whenReady() { return opts.ready ? Promise.resolve() : new Promise(() => {}); },
    setAsDefaultProtocolClient() { return true; },
    getVersion() { return '0.0.0-test'; },
  };
  const ipcMain = new EventEmitter();
  const handlers = new Map();
  ipcMain.handle = (ch, fn) => { handlers.set(ch, fn); };

  const electronMock = {
    app, ipcMain, BrowserWindow: FakeBrowserWindow,
    clipboard: { writeText() {}, readText() { return ''; }, clear() {}, write() {} },
    Menu: { setApplicationMenu() {} },
    globalShortcut: { unregisterAll() {} },
    dialog: {
      showMessageBox: async () => ({ response: 1 }),
      showErrorBox() {},
      showSaveDialog: async () => ({ canceled: true }),
      showOpenDialog: async () => ({ canceled: true, filePaths: [] }),
      ...(opts.dialog || {}),
    },
    shell: { openExternal: async () => {} },
    powerMonitor: { on() {} },
  };
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'electron') return electronMock;
    return origLoad.call(this, request, parent, isMain);
  };

  if (typeof opts.beforeRequire === 'function') opts.beforeRequire({ electronMock, userData, scratch, tempDir });
  require(path.join(__dirname, '..', '..', 'electron', 'main.js'));

  // Fenêtre principale (validateIpcSender) créée via l'évènement « activate »
  if (opts.activate !== false) app.emit('activate');
  const latestWin = () => FakeBrowserWindow.all[FakeBrowserWindow.all.length - 1];
  const latestEv = () => { const w = latestWin(); return w ? { sender: w.webContents } : { sender: null }; };
  const invoke = (ch, ...args) => handlers.get(ch)(latestEv(), ...args);
  const send = (ch, ...args) => ipcMain.emit(ch, latestEv(), ...args); // ipcRenderer.send simulé (fenêtre principale)

  const cleanup = () => {
    Module._load = origLoad;
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
  };
  const ctx = { scratch, userData, tempDir, app, ipcMain, handlers, electronMock, invoke, send, cleanup, FakeBrowserWindow, FakeWebContents };
  Object.defineProperty(ctx, 'win', { get: latestWin, enumerable: true });
  Object.defineProperty(ctx, 'ev', { get: latestEv, enumerable: true });
  return ctx;
}

module.exports = { loadMainWithMockElectron, FakeBrowserWindow, FakeWebContents };
