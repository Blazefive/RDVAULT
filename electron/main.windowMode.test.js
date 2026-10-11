// Tests des modes de fenêtre de main.js (MAIN-30) — exécuter avec : node --test electron/main.windowMode.test.js
// main.js RÉEL sous Node, fenêtre simulée reproduisant Electron 38 : setResizable(false) fige les tailles
// minimale et maximale sur la taille courante. À la déconnexion / expiration (window-set-login-mode),
// la fenêtre doit revenir à la carte de connexion LOGIN_WIDTH×LOGIN_HEIGHT (540×820), non redimensionnable.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const ctx = loadMainWithMockElectron();
const { win, invoke } = ctx;

test.after(() => ctx.cleanup());

test('démarrage : carte de connexion 540×820 non redimensionnable', () => {
  assert.deepEqual(win.getSize(), [540, 820]);
  assert.equal(win.isResizable(), false);
});

test('connexion puis déconnexion : retour à 540×820, non redimensionnable', async () => {
  await invoke('window-set-main-mode');
  assert.deepEqual(win.getSize(), [1280, 800], 'mode principal 1280×800');
  assert.equal(win.isResizable(), true);
  win.calls.length = 0;
  await invoke('window-set-login-mode');
  assert.deepEqual(win.getSize(), [540, 820], 'la fenêtre doit revenir à la carte de connexion (pas 1280 de large)');
  assert.equal(win.isResizable(), false, 'mode connexion non redimensionnable');
  assert.deepEqual(win.min, [540, 820], 'taille minimale figée sur la carte');
  assert.deepEqual(win.max, [540, 820], 'taille maximale figée sur la carte');
  // Ordre : redimensionner AVANT de verrouiller (setResizable(false) fige min = max = taille courante)
  const iSize = win.calls.findIndex(c => c[0] === 'setSize' && c[1] === 540 && c[2] === 820);
  const iLock = win.calls.findIndex(c => c[0] === 'setResizable' && c[1] === false);
  assert.ok(iSize >= 0 && iLock > iSize, 'setSize(540, 820) doit précéder setResizable(false) : ' + JSON.stringify(win.calls));
});

test('déconnexion depuis une fenêtre maximisée : 540×820', async () => {
  await invoke('window-set-main-mode');
  await invoke('window-maximize-toggle');
  assert.equal(win.isMaximized(), true);
  await invoke('window-set-login-mode');
  assert.equal(win.isMaximized(), false);
  assert.deepEqual(win.getSize(), [540, 820]);
  assert.equal(win.isResizable(), false);
});

test('cycles connexion / déconnexion répétés : tailles stables', async () => {
  for (let i = 0; i < 3; i++) {
    await invoke('window-set-main-mode');
    assert.deepEqual(win.getSize(), [1280, 800], `cycle ${i} : mode principal`);
    await invoke('window-set-login-mode');
    assert.deepEqual(win.getSize(), [540, 820], `cycle ${i} : mode connexion`);
  }
});

test('expéditeur non autorisé : la fenêtre ne change pas', async () => {
  await invoke('window-set-main-mode');
  await ctx.handlers.get('window-set-login-mode')({ sender: {} });
  assert.deepEqual(win.getSize(), [1280, 800]);
  await invoke('window-set-login-mode');
});
