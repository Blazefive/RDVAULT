// Tests du pinning TLS (electron/certPinning.js) — node --test, sans Electron.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { certificateFingerprintHex, fingerprintMatches } = require('./certPinning');

// Construit un faux certificat { data: <PEM> } à partir d'octets DER arbitraires
function pemCert(der) {
  return { data: '-----BEGIN CERTIFICATE-----\n' + der.toString('base64').replace(/(.{64})/g, '$1\n') + '\n-----END CERTIFICATE-----\n' };
}

test('certificateFingerprintHex : PEM data → SHA-256 hex (64 car. minuscules)', () => {
  const der = nodeCrypto.randomBytes(300);
  const expected = nodeCrypto.createHash('sha256').update(der).digest('hex');
  const got = certificateFingerprintHex(pemCert(der));
  assert.equal(got, expected);
  assert.match(got, /^[0-9a-f]{64}$/);
});

test('certificateFingerprintHex : format « sha256/<base64> » (Electron)', () => {
  const digest = nodeCrypto.randomBytes(32);
  const cert = { fingerprint: 'sha256/' + digest.toString('base64') };
  assert.equal(certificateFingerprintHex(cert), digest.toString('hex'));
});

test('certificateFingerprintHex : entrées illisibles → null', () => {
  assert.equal(certificateFingerprintHex(null), null);
  assert.equal(certificateFingerprintHex({}), null);
  assert.equal(certificateFingerprintHex({ data: '-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----' }), null, 'PEM vide → null');
  assert.equal(certificateFingerprintHex({ fingerprint: 'sha1/abc' }), null, 'algo non sha256 → null');
});

test('fingerprintMatches : membership exact', () => {
  const der = nodeCrypto.randomBytes(200);
  const cert = pemCert(der);
  const fp = certificateFingerprintHex(cert);
  assert.equal(fingerprintMatches(cert, [fp]), true, 'empreinte présente → true');
  assert.equal(fingerprintMatches(cert, ['0'.repeat(64), fp]), true, 'présente dans une liste → true');
  assert.equal(fingerprintMatches(cert, ['a'.repeat(64)]), false, 'empreinte absente → false');
});

test('fingerprintMatches : liste vide = pas de pinning → false', () => {
  const cert = pemCert(nodeCrypto.randomBytes(100));
  assert.equal(fingerprintMatches(cert, []), false);
  assert.equal(fingerprintMatches(cert, null), false);
});

test('fingerprintMatches : certificat illisible (empreinte null) → false', () => {
  assert.equal(fingerprintMatches({}, ['a'.repeat(64)]), false);
});

test('fingerprintMatches : pas de correspondance par préfixe/sous-chaîne', () => {
  // Une empreinte épinglée ne doit pas matcher un certificat dont l'empreinte la contient en préfixe
  const der = nodeCrypto.randomBytes(128);
  const cert = pemCert(der);
  const full = certificateFingerprintHex(cert);
  const prefix = full.slice(0, 40);
  assert.equal(fingerprintMatches(cert, [prefix]), false, 'préfixe épinglé ne matche pas (membership exact)');
});
