// Tests de l'état de synchronisation transmis à l'extension (MAIN-8) — node --test electron/main.syncState.test.js
// main.js RÉEL sous Node (electron simulé, aucun serveur démarré). Le renderer envoie TOUTES les entrées de
// TOUS les coffres (sync-write-state) : au-delà de 5 000, les suivantes (souvent celles des autres coffres,
// aplatis dans l'ordre des noms) n'étaient plus jamais proposées à l'autoremplissage, sans aucun signal.
// Attendu : aucune perte silencieuse ; un plafond très large (défense en profondeur) qui, s'il est atteint,
// est signalé dans la réponse ({ truncated }) et dans sync-read-state.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const ctx = loadMainWithMockElectron();
const { invoke } = ctx;

test.after(() => ctx.cleanup());

const entries = (n, prefix = 'e') => Array.from({ length: n }, (_, i) => ({
  name: `${prefix}-${i}`, engine: i % 2 ? 'V01' : 'V00', username: 'u' + i, password: 'p' + i,
  url: `https://login.site${i}.com`, website: '', type: 'login',
}));
const write = (secrets) => invoke('sync-write-state', { vaultUrl: 'http://127.0.0.1:1', username: 'alice', connected: true, secrets });
const count = async () => (await invoke('sync-read-state')).data.secretCount;

test('5 380 entrées (coffre de 5 000 + 380 dans 19 autres coffres) : toutes transmises', async () => {
  const r = await write(entries(5380));
  assert.equal(r.success, true);
  assert.equal(await count(), 5380, 'aucune entrée ne doit être perdue au-delà de 5 000');
  assert.equal(r.truncated || 0, 0, 'rien de tronqué');
});

test('5 001 entrées : 5 001 conservées', async () => {
  await write(entries(5001));
  assert.equal(await count(), 5001);
});

test('plafond de défense en profondeur dépassé : troncature SIGNALÉE (réponse et sync-read-state)', async () => {
  const r = await write(entries(100005, 'big'));
  assert.equal(r.success, true);
  assert.equal(r.truncated, 5, 'nombre d\'entrées non transmises renvoyé au renderer');
  const st = await invoke('sync-read-state');
  assert.equal(st.data.secretCount, 100000);
  assert.equal(st.data.truncated, 5, 'troncature visible dans l\'état de synchronisation');
});

test('nouvel état sous le plafond : plus de troncature signalée ; déconnexion : état purgé', async () => {
  const r = await write(entries(3));
  assert.equal(r.truncated || 0, 0);
  assert.equal((await invoke('sync-read-state')).data.truncated || 0, 0);
  await invoke('sync-write-state', { connected: false, secrets: [] });
  assert.equal((await invoke('sync-read-state')).data, null);
});

test('entrée aux champs démesurés : acceptée (champs bornés côté main)', async () => {
  await write([{ name: 'n'.repeat(600), engine: 'e'.repeat(300), username: 'x', password: 'p'.repeat(20000), url: 'u', website: 'w', type: 't'.repeat(100) }]);
  assert.equal(await count(), 1);
});
