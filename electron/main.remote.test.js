// Mode entreprise : épinglage TLS et CSP de la fenêtre principale (REMOTE-3, REMOTE-4) — node --test electron/main.remote.test.js
// main.js RÉEL sous Node (electron simulé) avec une configuration entreprise simulée (configLoader remplacé
// AVANT le chargement de main.js ; config.cfg du projet jamais modifié).
// - REMOTE-3 : TRUSTED_CERT_FINGERPRINTS n'était appliqué que dans 'certificate-error', émis par Chromium pour
//   un certificat qu'il juge INVALIDE. Un certificat reconnu par le magasin Windows (CA publique, CA
//   d'entreprise, proxy d'inspection TLS) était accepté quelle que soit son empreinte. Attendu : refus (-2)
//   pour l'hôte de VAULT_URL si l'empreinte n'est pas épinglée, décision de Chromium (-3) sinon.
// - REMOTE-4 : la CSP (connect-src) n'autorisait pas l'origine de RBI_PROXY_URL : partage RBI inutilisable.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

// Deux « certificats » (DER arbitraires) : seule l'empreinte SHA-256 du DER compte pour l'épinglage
const derPinned = crypto.randomBytes(300);
const derOther = crypto.randomBytes(300);
const pem = (der) => '-----BEGIN CERTIFICATE-----\n' + der.toString('base64').replace(/.{64}/g, '$&\n') + '\n-----END CERTIFICATE-----\n';
const PIN = crypto.createHash('sha256').update(derPinned).digest('hex');

const cfg = {
  APP_MODE: 'enterprise',
  VAULT_URL: 'https://vault.corp.example:8200',
  TRUSTED_DOMAINS: 'corp.example',
  RBI_PROXY_URL: 'https://rbi-proxy.example.com:3001/base/path?x=1',
  LANG: 'fr',
};
let pins = [PIN];

const ctx = loadMainWithMockElectron({
  beforeRequire: () => {
    const cl = require('./configLoader');
    cl.getConfig = () => ({ ...cfg });
    cl.getAppMode = () => cfg.APP_MODE;
    cl.getTrustedDomains = () => cfg.TRUSTED_DOMAINS.split(',');
    cl.getTrustedCertFingerprints = () => pins;
    cl.getRbiProxyUrl = () => cfg.RBI_PROXY_URL;
  },
});

test.after(() => ctx.cleanup());

const verify = (request) => new Promise((resolve) => ctx.win.webContents.certVerifyProc(request, resolve));
const req = (hostname, der, verificationResult = 'net::OK') => ({ hostname, certificate: { data: pem(der) }, verificationResult, errorCode: 0 });

test('REMOTE-3 : vérification des certificats installée sur la session de la fenêtre principale', () => {
  assert.equal(typeof ctx.win.webContents.certVerifyProc, 'function', 'setCertificateVerifyProc doit être appelé');
});

test('REMOTE-3 : certificat VALIDE pour le système mais non épinglé, sur l\'hôte Vault → refusé (-2)', async () => {
  assert.equal(await verify(req('vault.corp.example', derOther, 'net::OK')), -2);
  assert.equal(await verify(req('VAULT.corp.example', derOther, 'net::OK')), -2, 'casse ignorée');
});

test('REMOTE-3 : certificat épinglé → décision de Chromium (-3), jamais une acceptation forcée', async () => {
  assert.equal(await verify(req('vault.corp.example', derPinned, 'net::OK')), -3);
  // Auto-signé mais épinglé : Chromium le juge invalide, 'certificate-error' décide (domaine de confiance + empreinte)
  assert.equal(await verify(req('vault.corp.example', derPinned, 'net::ERR_CERT_AUTHORITY_INVALID')), -3);
});

test('REMOTE-3 : autres hôtes (proxy RBI, HIBP…) et absence d\'épinglage → décision de Chromium (-3)', async () => {
  assert.equal(await verify(req('rbi-proxy.example.com', derOther)), -3);
  assert.equal(await verify(req('api.pwnedpasswords.com', derOther)), -3);
  assert.equal(await verify(req('sub.vault.corp.example', derOther)), -3, 'seul l\'hôte exact de VAULT_URL est épinglé');
  pins = [];
  try {
    assert.equal(await verify(req('vault.corp.example', derOther)), -3, 'sans TRUSTED_CERT_FINGERPRINTS : comportement inchangé');
  } finally {
    pins = [PIN];
  }
});

test('REMOTE-3 : certificate-error inchangé (empreinte inconnue refusée, épinglée acceptée)', () => {
  const [handler] = ctx.app.listeners('certificate-error');
  const run = (der) => { let out = null; handler({ preventDefault() {} }, null, 'https://vault.corp.example:8200/v1/sys/health', 'net::ERR_CERT_AUTHORITY_INVALID', { data: pem(der) }, (ok) => { out = ok; }); return out; };
  assert.equal(run(derOther), false);
  assert.equal(run(derPinned), true);
});

test('REMOTE-4 : la CSP autorise l\'origine (seule) de RBI_PROXY_URL dans connect-src', () => {
  let headers = null;
  ctx.win.webContents.headersListener({ responseHeaders: { 'X-Test': ['1'] } }, (r) => { headers = r.responseHeaders; });
  const raw = headers['Content-Security-Policy'];
  const csp = Array.isArray(raw) ? raw.join(' ') : String(raw);
  const connect = (csp.match(/connect-src ([^;]*);/) || [])[1] || '';
  const sources = connect.trim().split(/\s+/);
  assert.ok(sources.includes('https://rbi-proxy.example.com:3001'), 'origine du proxy RBI autorisée : ' + connect);
  assert.ok(sources.includes('https://vault.corp.example:8200'), 'Vault toujours autorisé');
  assert.ok(sources.includes("'self'") && sources.includes('http://127.0.0.1:45678') && sources.includes('https://api.pwnedpasswords.com'));
  assert.ok(!connect.includes('/base/path') && !connect.includes('?x=1'), 'origine seule, sans chemin ni requête');
  assert.equal(headers['X-Test'][0], '1', 'autres en-têtes conservés');
});
