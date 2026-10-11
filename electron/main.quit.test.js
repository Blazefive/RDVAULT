// Fermeture de l'application et sessions RBI (suite des notes RBI : will-quit) — node --test electron/main.quit.test.js
// main.js RÉEL sous Node (electron simulé). Electron n'attend pas un gestionnaire 'will-quit' asynchrone : la
// fermeture des navigateurs isolés et la suppression de leurs profils (cookies de session) pouvaient ne jamais
// se terminer. Attendu : sortie suspendue (preventDefault) jusqu'à la fin de closeAllSessions(), bornée dans le
// temps, puis app.exit(0). Le nettoyage des profils orphelins a lieu au démarrage, après le verrou d'instance.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const spies = { rbiCleanup: 0, closeAll: 0 };
let releaseCloseAll = null;
const ctx = loadMainWithMockElectron({
  beforeRequire: () => {
    const rbi = require('./secureSession');
    rbi.cleanupStaleProfiles = () => { spies.rbiCleanup++; return 0; };
    rbi.closeAllSessions = () => { spies.closeAll++; return new Promise((r) => { releaseCloseAll = r; }); };
  },
});

const flush = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };
const quit = () => { const ev = { prevented: 0, preventDefault() { ev.prevented++; } }; for (const fn of ctx.app.listeners('will-quit')) fn(ev); return ev; };

test.after(() => ctx.cleanup());

test('démarrage (verrou obtenu) : profils RBI orphelins nettoyés une fois', () => {
  assert.equal(spies.rbiCleanup, 1);
});

test('will-quit : sortie suspendue jusqu\'à la fermeture des sessions RBI, puis app.exit(0)', async () => {
  const ev = quit();
  assert.equal(ev.prevented, 1, 'la sortie doit attendre la fermeture des sessions RBI');
  await flush();
  assert.equal(spies.closeAll, 1);
  assert.deepEqual(ctx.app.exitCalls, [], 'pas de sortie avant la fin de closeAllSessions');
  releaseCloseAll();
  await flush();
  assert.deepEqual(ctx.app.exitCalls, [0], 'sortie une fois les profils supprimés');
});

test('will-quit : closeAllSessions bloqué → sortie quand même après le délai maximal', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  ctx.app.exitCalls.length = 0;
  quit();
  await flush();
  assert.deepEqual(ctx.app.exitCalls, []);
  t.mock.timers.tick(20000);
  await flush();
  assert.deepEqual(ctx.app.exitCalls, [0], 'la fermeture n\'est jamais bloquée indéfiniment');
});
