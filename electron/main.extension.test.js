// Extension navigateur livrée avec l'application — exécuter avec : node --test electron/main.extension.test.js
// main.js RÉEL sous Node (electron simulé) : informations de l'extension embarquée, ouverture du dossier,
// copie de valeurs non secrètes choisies dans une liste fermée.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const openedPaths = [];
const copied = [];
const ctx = loadMainWithMockElectron({
  beforeRequire: ({ electronMock }) => {
    electronMock.shell.openPath = async (p) => { openedPaths.push(p); return ''; };
    electronMock.clipboard.writeText = (t) => { copied.push(t); };
  },
});
const { invoke, handlers } = ctx;
const EXT_DIR = path.join(__dirname, '..', 'chrome-extension', 'vault-autofill-extension');

test.after(() => ctx.cleanup());

test('extension-info : dossier, version et identifiant fixe dérivé de la clé du manifeste', async () => {
  const info = await invoke('extension-info');
  const manifest = JSON.parse(fs.readFileSync(path.join(EXT_DIR, 'manifest.json'), 'utf8'));
  assert.equal(info.available, true);
  assert.equal(path.resolve(info.folder), path.resolve(EXT_DIR), 'hors empaquetage : dossier du projet');
  assert.equal(info.version, manifest.version);
  assert.match(info.id, /^[a-p]{32}$/, 'identifiant Chrome : 32 lettres a-p');
  const expected = crypto.createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest('hex').slice(0, 32)
    .split('').map(h => String.fromCharCode(97 + parseInt(h, 16))).join('');
  assert.equal(info.id, expected);
});

test('extension-open-folder : ouvre le dossier de l\'extension', async () => {
  const r = await invoke('extension-open-folder');
  assert.equal(r.success, true);
  assert.equal(path.resolve(openedPaths.at(-1)), path.resolve(EXT_DIR));
});

test('extension-copy : seulement des valeurs d\'une liste fermée, jamais un texte du renderer', async () => {
  assert.equal((await invoke('extension-copy', 'chrome')).success, true);
  assert.equal(copied.at(-1), 'chrome://extensions');
  assert.equal((await invoke('extension-copy', 'edge')).success, true);
  assert.equal(copied.at(-1), 'edge://extensions');
  assert.equal((await invoke('extension-copy', 'folder')).success, true);
  assert.equal(path.resolve(copied.at(-1)), path.resolve(EXT_DIR));
  const n = copied.length;
  assert.equal((await invoke('extension-copy', 'C:\\autre\\texte')).success, false);
  assert.equal((await invoke('extension-copy', '__proto__')).success, false);
  assert.equal(copied.length, n, 'rien copié pour une valeur hors liste');
});

test('expéditeur non autorisé : aucune action', async () => {
  const bad = { sender: {} };
  assert.equal((await handlers.get('extension-info')(bad)).available, false);
  assert.equal((await handlers.get('extension-open-folder')(bad)).success, false);
  const n = copied.length;
  assert.equal((await handlers.get('extension-copy')(bad, 'chrome')).success, false);
  assert.equal(copied.length, n);
});
