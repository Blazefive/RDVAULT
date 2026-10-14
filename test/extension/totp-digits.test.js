// Validation des codes TOTP renvoyés par l'app au service worker de l'extension enrichie
// (background.js : getTotpCodeFromDesktop). EXTENSION-20 : seuls les codes à 6 chiffres étaient
// acceptés, alors que l'app propose 8 chiffres (TotpConfigModal) et que le coffre local / Vault
// génèrent 6 à 8 chiffres : tout remplissage TOTP d'une clé à 8 chiffres échouait.
// background.js est chargé tel quel dans un contexte vm (pas de `chrome` : l'écouteur de messages
// n'est pas enregistré) ; auth-manager.js est remplacé par un double qui renvoie la réponse
// de /api/totp/<clé>.
// Lancement : node --test test/extension/totp-digits.test.js
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const BG_FILE = path.resolve(__dirname, '..', '..', 'chrome-extension/vault-autofill-extension/background.js');
const bgSrc = fs.readFileSync(BG_FILE, 'utf8');

/** Charge background.js avec un /api/totp simulé ; renvoie getTotpCodeFromDesktop */
function loadWithDesktopResponse(status, body) {
  const ctx = {
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    URL, URLSearchParams, setTimeout, clearTimeout, setInterval, clearInterval,
    importScripts() {
      ctx.authManager = {
        start: async () => {},
        authenticatedFetch: async () => ({ ok: status >= 200 && status < 300, status, json: async () => body }),
      };
    },
  };
  vm.createContext(ctx);
  vm.runInContext(bgSrc, ctx, { filename: BG_FILE });
  return vm.runInContext('getTotpCodeFromDesktop', ctx);
}

async function totpFor(code) {
  return loadWithDesktopResponse(200, { success: true, code })('MES-SECRETS-site');
}

test('codes TOTP à 6, 7 et 8 chiffres acceptés', async () => {
  for (const code of ['123456', '1234567', '12345678']) {
    const r = await totpFor(code);
    assert.equal(r.success, true, `${code} doit être accepté`);
    assert.equal(r.code, code);
  }
});

test('code numérique transmis sous forme de nombre ou avec séparateur : normalisé', async () => {
  assert.deepEqual({ ...(await totpFor(12345678)) }, { success: true, code: '12345678' });
  assert.deepEqual({ ...(await totpFor('123 456')) }, { success: true, code: '123456' });
});

test('codes trop courts, trop longs ou vides refusés', async () => {
  for (const code of ['12345', '123456789', '', 'abcdef']) {
    const r = await totpFor(code);
    assert.equal(r.success, false, `${JSON.stringify(code)} doit être refusé`);
  }
});

test('erreur de l\'app propagée', async () => {
  const r = await loadWithDesktopResponse(404, { error: 'TOTP not found' })('MES-SECRETS-site');
  assert.equal(r.success, false);
  assert.match(r.error, /404/);
});
