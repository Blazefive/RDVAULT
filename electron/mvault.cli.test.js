// Tests unitaires du client mvault (cli/mvault.js) : masquage de `mvault get` sans --reveal.
// Placé ici et non dans cli/ (dossier copié tel quel dans l'installeur) : exécuté par « npm run test:electron ».
// Le test de bout en bout (VRAI serveur CLI + VRAI mvault) est dans test/smoke/smoke-ssh-agent.js.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { maskSensitiveData, remoteExitCode, MASK } = require('../cli/mvault');

// Entrée telle que l'application la transmet à la CLI (vaultApi.readSecretV2)
const sshEntry = () => ({
  name: 'cle-prod', username: 'phrase-de-passe-SSH', password: '-----BEGIN OPENSSH PRIVATE KEY-----', url: 'ssh-ed25519 AAAA',
  website: '', notes: 'note', tags: 'prod', Port: '', entryType: 'ssh',
  customFields: [{ key: 'Jeton API', value: 'sk-live-TRES-SECRET', protected: true }, { key: 'Env', value: 'prod', protected: false }],
  attachments: [{ name: 'id_ed25519', type: 'application/octet-stream', size: 6, data: 'c2VjcmV0' }],
});

test('champ personnalisé protégé : nom affiché, valeur masquée (comme « •••• » dans l\'interface)', () => {
  const out = maskSensitiveData(sshEntry());
  assert.deepEqual(out.customFields[0], { key: 'Jeton API', value: MASK, protected: true });
  assert.deepEqual(out.customFields[1], { key: 'Env', value: 'prod', protected: false });
});

test('entrée SSH : phrase de passe (username) et clé privée (password) masquées', () => {
  const out = maskSensitiveData(sshEntry());
  assert.equal(out.username, MASK);
  assert.equal(out.password, MASK);
  assert.equal(out.notes, 'note');
  assert.equal(out.url, 'ssh-ed25519 AAAA');
});

test('entrée ordinaire : username affiché ; phrase de passe SSH vide non transformée en ********', () => {
  assert.equal(maskSensitiveData({ username: 'alice', password: 'x', entryType: 'secret' }).username, 'alice');
  assert.equal(maskSensitiveData({ username: '', entryType: 'ssh' }).username, '');
});

test('pièces jointes : contenu masqué, métadonnées affichées', () => {
  const out = maskSensitiveData(sshEntry());
  assert.deepEqual(out.attachments[0], { name: 'id_ed25519', type: 'application/octet-stream', size: 6, data: MASK });
});

test('champ non protégé au nom sensible (« password », « token ») : valeur masquée', () => {
  const out = maskSensitiveData({ customFields: [{ key: 'Password', value: 'p' }, { key: 'token', value: 't', protected: false }] });
  assert.deepEqual(out.customFields, [{ key: 'Password', value: MASK }, { key: 'token', value: MASK, protected: false }]);
});

test('secret brut (hors forme de l\'application) : règles par nom de clé inchangées, récursives', () => {
  assert.deepEqual(maskSensitiveData({ key: 'k', api: { secret: 's', ok: 1 }, list: [{ token: 't' }] }),
    { key: MASK, api: { secret: MASK, ok: 1 }, list: [{ token: MASK }] });
  assert.equal(maskSensitiveData(null), null);
  assert.equal(maskSensitiveData('texte'), 'texte');
});

test('l\'entrée d\'origine n\'est pas modifiée', () => {
  const e = sshEntry();
  maskSensitiveData(e);
  assert.deepEqual(e, sshEntry());
});

test('remoteExitCode : code distant, 128 + signal, 1 si indéterminé', () => {
  assert.equal(remoteExitCode(7, null), 7);
  assert.equal(remoteExitCode(0, null), 0);
  assert.equal(remoteExitCode(null, 'KILL'), 137);
  assert.equal(remoteExitCode(null, null), 1);
});
