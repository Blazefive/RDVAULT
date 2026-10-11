// Langue des boîtes de dialogue natives et des erreurs IPC de main.js (MAIN-26) —
// exécuter avec : node --test electron/main.uiLanguage.test.js
// main.js RÉEL sous Node (electron simulé, aucune fenêtre réelle, aucun processus externe lancé).
// La langue courante de l'interface est communiquée par le renderer (IPC 'set-ui-language', expéditeur
// validé, liste blanche des 12 langues) ; à défaut LANG de config.cfg ; repli anglais. Le français reste
// strictement identique aux textes d'origine.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const crypto = require('crypto');
const child_process = require('child_process');
const { Server } = require('ssh2');
const { loadMainWithMockElectron, FakeBrowserWindow } = require('../test/helpers/main-electron-mock');
const mainI18n = require('./mainI18n');

// Aucun client externe réel : PuTTY / FileZilla / WinSCP « absents », aucun processus lancé
const origExistsSync = fs.existsSync;
fs.existsSync = (p) => (/(putty|filezilla|winscp)\.exe$/i.test(String(p)) ? false : origExistsSync(p));
const origSpawn = child_process.spawn;
child_process.spawn = () => ({ unref() {}, on() {} });

const dialogs = [];
const errorBoxes = [];
let defaultLang = 'en'; // LANG de config.cfg simulé (fournisseur par défaut de mainI18n)
const origLoadFile = FakeBrowserWindow.prototype.loadFile;
const ctx = loadMainWithMockElectron({
  dialog: {
    showMessageBox: async (win, opts) => { dialogs.push(opts); return { response: 1 }; },
    showErrorBox: (title, content) => { errorBoxes.push({ title, content }); },
  },
  beforeRequire: () => {
    mainI18n.setDefaultLanguageProvider(() => defaultLang);
    // Chargement de l'interface en échec à la création de la fenêtre : showErrorBox traduit
    FakeBrowserWindow.prototype.loadFile = () => Promise.reject(new Error('ERR_FILE_NOT_FOUND'));
  },
});
FakeBrowserWindow.prototype.loadFile = origLoadFile;
const { invoke, send, handlers, ipcMain } = ctx;

test.after(() => {
  fs.existsSync = origExistsSync;
  child_process.spawn = origSpawn;
  mainI18n.resetUiLanguage();
  mainI18n.setDefaultLanguageProvider(null);
  ctx.cleanup();
});

test('échec de chargement de l\'interface : titre de showErrorBox dans la langue par défaut (LANG = en)', async () => {
  await new Promise((r) => setImmediate(r));
  assert.equal(errorBoxes.length, 1);
  assert.equal(errorBoxes[0].title, 'Loading failed');
});

test('sans langue signalée : LANG de config.cfg (fr) → erreurs IPC identiques à l\'existant', async () => {
  defaultLang = 'fr';
  let r = await invoke('open-ssh-connection', { host: 'bad host', username: 'u', port: 22 });
  assert.equal(r.error, 'Nom d\'hôte invalide');
  r = await invoke('open-ssh-connection', { host: 'srv.example', username: 'u;rm', port: 22 });
  assert.equal(r.error, 'Nom d\'utilisateur invalide');
  r = await invoke('open-ssh-connection', { host: 'srv.example', username: 'u', port: 70000 });
  assert.equal(r.error, 'Port invalide (1-65535)');
  r = await invoke('open-ssh-connection', { host: 'srv.example', username: 'u', port: 22 });
  assert.equal(r.error, 'PuTTY non trouvé. Veuillez installer PuTTY.');
  r = await invoke('open-sftp-connection', { host: 'srv.example', username: 'u', password: 'p', port: '22' });
  assert.equal(r.error, 'FileZilla ou WinSCP n\'est pas installé sur ce système');
  r = await invoke('open-rdp-connection', { host: 'srv.example', username: 'DOM#X\\u', password: 'p', port: 3389 });
  assert.equal(r.error, 'Domaine RDP invalide');
  r = await invoke('open-url-in-browser', 'https://example.com', 'netscape');
  assert.equal(r.error, 'Navigateur non reconnu');
  r = await invoke('open-url-in-browser', 'ms-msdt:/id PCWDiagnostic', 'chrome');
  assert.equal(r.error, 'Protocole URL non autorisé');
  r = await invoke('open-external-link', 'file:///C:/Windows/System32/calc.exe');
  assert.equal(r.error, 'Protocole URL non autorisé');
});

test('langue signalée par l\'interface (en) : erreurs IPC en anglais', async () => {
  send('set-ui-language', 'en');
  let r = await invoke('open-ssh-connection', { host: 'bad host', username: 'u', port: 22 });
  assert.equal(r.error, 'Invalid host name');
  r = await invoke('open-ssh-connection', { host: 'srv.example', username: 'u', port: 22 });
  assert.equal(r.error, 'PuTTY not found. Please install PuTTY.');
  r = await invoke('open-sftp-connection', { host: 'srv.example', username: 'u', password: 'p', port: '22' });
  assert.equal(r.error, 'Neither FileZilla nor WinSCP is installed on this system');
  r = await invoke('open-rdp-connection', { host: 'srv.example', username: 'DOM#X\\u', password: 'p', port: 3389 });
  assert.equal(r.error, 'Invalid RDP domain');
  r = await invoke('open-url-in-browser', 'https://example.com', 'netscape');
  assert.equal(r.error, 'Unrecognized browser');
});

test('set-ui-language : expéditeur non autorisé et langue inconnue ignorés', async () => {
  send('set-ui-language', 'de');
  ipcMain.emit('set-ui-language', { sender: {} }, 'ja'); // autre webContents (popup, devtools…) : ignoré
  let r = await invoke('open-ssh-connection', { host: 'bad host', username: 'u', port: 22 });
  assert.equal(r.error, 'Ungültiger Hostname');
  for (const bad of ['xx', '', null, 42, { lang: 'en' }, 'e'.repeat(100), '__proto__']) send('set-ui-language', bad);
  r = await invoke('open-ssh-connection', { host: 'bad host', username: 'u', port: 22 });
  assert.equal(r.error, 'Ungültiger Hostname', 'langue précédente conservée');
  send('set-ui-language', 'pt-BR');
  r = await invoke('open-ssh-connection', { host: 'bad host', username: 'u', port: 22 });
  assert.equal(r.error, 'Nome de host inválido', 'sous-étiquette régionale acceptée');
  assert.equal(typeof handlers.get('set-ui-language'), 'undefined', 'canal à sens unique (ipcRenderer.send), pas de handle');
});

// Serveur SSH jouet : sa clé d'hôte est inconnue → invite confirmNewHostKey (réponse simulée : Refuser)
async function withSshServer(fn) {
  const hostKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
  const srv = new Server({ hostKeys: [hostKey] }, (client) => { client.on('authentication', (c) => c.reject()); client.on('error', () => {}); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try { return await fn(srv.address().port); } finally { srv.close(); }
}
const auditSsh = (port) => invoke('audit-tail-log-file', '/var/log/vault/audit.log', 10, { host: '127.0.0.1', port, username: 'audit', password: 'pw' });

test('clé d\'hôte SSH inconnue (audit) : français identique, puis anglais selon l\'interface', async () => {
  await withSshServer(async (port) => {
    mainI18n.resetUiLanguage();
    defaultLang = 'fr';
    dialogs.length = 0;
    let r = await auditSsh(port);
    assert.equal(r.success, false);
    assert.equal(r.code, 'HOST_KEY_REJECTED');
    let d = dialogs[0];
    assert.equal(d.title, 'Clé d\'hôte SSH inconnue');
    assert.equal(d.message, `Clé d'hôte SSH inconnue pour 127.0.0.1:${port}`);
    assert.deepEqual(d.buttons, ['Mémoriser et continuer', 'Refuser']);
    assert.match(d.detail, /^Empreinte de la clé d'hôte :\nSHA256:\S+\n\nComparez-la avec celle du serveur \(ssh-keygen -lf \/etc\/ssh\/ssh_host_\*_key\.pub\)\.\nSi vous la mémorisez, toute connexion ultérieure avec une clé différente sera refusée\.$/);
    assert.equal(d.defaultId, 1);
    assert.equal(d.cancelId, 1);

    send('set-ui-language', 'en');
    dialogs.length = 0;
    r = await auditSsh(port);
    assert.equal(r.code, 'HOST_KEY_REJECTED');
    d = dialogs[0];
    assert.equal(d.title, 'Unknown SSH host key');
    assert.equal(d.message, `Unknown SSH host key for 127.0.0.1:${port}`);
    assert.deepEqual(d.buttons, ['Remember and continue', 'Deny']);
    assert.match(d.detail, /^Host key fingerprint:\nSHA256:\S+\n\n/);
    assert.equal(d.defaultId, 1);

    send('set-ui-language', 'zh');
    dialogs.length = 0;
    await auditSsh(port);
    assert.equal(dialogs[0].title, '未知的 SSH 主机密钥');
    assert.deepEqual(dialogs[0].buttons, ['记住并继续', '拒绝']);
  });
});
