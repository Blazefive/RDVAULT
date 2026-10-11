// Tests du module crypto du coffre local — exécuter avec : node --test electron/
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { encrypt, decrypt, decryptDetailed, generateSalt, deriveKeyWithKdfSync, parseKdf, DEFAULT_KDF, generateToken } = require('./crypto');

// Clés de test en PBKDF2 hérité (descripteur null) : plus rapide que scrypt pour les tests AES
const key = deriveKeyWithKdfSync('mot-de-passe-test', generateSalt(), null);
const otherKey = deriveKeyWithKdfSync('autre-mot-de-passe', generateSalt(), null);

test('chiffrement/déchiffrement avec AAD', () => {
  const { encrypted, iv } = encrypt('secret', key, '1:chemin/secret:1');
  assert.equal(decrypt(encrypted, iv, key, '1:chemin/secret:1'), 'secret');
});

test('un blob déplacé vers un autre contexte (AAD) est rejeté', () => {
  const { encrypted, iv } = encrypt('secret', key, '1:prod/db:1');
  assert.throws(() => decrypt(encrypted, iv, key, '1:test/db:1'));
});

test('une mauvaise clé est rejetée', () => {
  const { encrypted, iv } = encrypt('secret', key, 'ctx');
  assert.throws(() => decrypt(encrypted, iv, otherKey, 'ctx'));
});

test('les données héritées (sans AAD) restent lisibles et sont signalées', () => {
  const { encrypted, iv } = encrypt('ancien', key);
  const result = decryptDetailed(encrypted, iv, key, 'nouveau-contexte');
  assert.equal(result.plaintext, 'ancien');
  assert.equal(result.legacy, true);
});

test('chaque chiffrement utilise un IV différent', () => {
  const a = encrypt('x', key, 'c');
  const b = encrypt('x', key, 'c');
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.encrypted, b.encrypted);
});

test('generateToken produit 64 caractères hex distincts', () => {
  const t1 = generateToken();
  const t2 = generateToken();
  assert.match(t1, /^[0-9a-f]{64}$/);
  assert.notEqual(t1, t2);
});

// ── KDF enfichable (scrypt) + rétro-compatibilité PBKDF2 ──

test('DEFAULT_KDF est scrypt et se parse correctement', () => {
  assert.match(DEFAULT_KDF, /^scrypt:/);
  const { algo, params } = parseKdf(DEFAULT_KDF);
  assert.equal(algo, 'scrypt');
  assert.ok(params.N >= 32768 && params.r >= 1 && params.p >= 1);
});

test('kdf absent/NULL = PBKDF2 hérité (210000 itérations, SHA-512), clé inchangée pour les coffres existants', () => {
  const salt = generateSalt();
  // Référence indépendante du module : la clé des coffres créés par les versions précédentes
  const legacy = require('crypto').pbkdf2Sync('mot-de-passe', Buffer.from(salt, 'hex'), 210000, 32, 'sha512');
  const viaKdfNull = deriveKeyWithKdfSync('mot-de-passe', salt, null);
  const viaKdfPbkdf2 = deriveKeyWithKdfSync('mot-de-passe', salt, 'pbkdf2:i=210000,h=sha512');
  assert.equal(viaKdfNull.toString('hex'), legacy.toString('hex'), 'NULL = PBKDF2 hérité (clé inchangée pour les coffres existants)');
  assert.equal(viaKdfPbkdf2.toString('hex'), legacy.toString('hex'));
  assert.equal(viaKdfNull.length, 32);
});

test('scrypt : déterministe pour (mot de passe, salt) et chiffre/déchiffre', () => {
  const salt = generateSalt();
  const k1 = deriveKeyWithKdfSync('mot-de-passe', salt, DEFAULT_KDF);
  const k2 = deriveKeyWithKdfSync('mot-de-passe', salt, DEFAULT_KDF);
  assert.equal(k1.toString('hex'), k2.toString('hex'), 'déterministe');
  assert.equal(k1.length, 32);
  const { encrypted, iv } = encrypt('secret-scrypt', k1, 'ctx');
  assert.equal(decrypt(encrypted, iv, k2, 'ctx'), 'secret-scrypt');
});

test('scrypt ≠ PBKDF2 et change avec le salt', () => {
  const salt = generateSalt();
  const scryptKey = deriveKeyWithKdfSync('mot-de-passe', salt, DEFAULT_KDF);
  const pbkdf2Key = deriveKeyWithKdfSync('mot-de-passe', salt, null);
  assert.notEqual(scryptKey.toString('hex'), pbkdf2Key.toString('hex'));
  const otherSalt = generateSalt();
  const scryptKey2 = deriveKeyWithKdfSync('mot-de-passe', otherSalt, DEFAULT_KDF);
  assert.notEqual(scryptKey.toString('hex'), scryptKey2.toString('hex'));
});

test('parseKdf rejette un algorithme inconnu', () => {
  assert.throws(() => parseKdf('bcrypt:x=1'));
});
