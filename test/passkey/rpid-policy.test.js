// Règle rpId des passkeys côté service worker (background.js : passkeyRpAllowedForSender)
// comparée à celle du content script (passkey-bridge.js : resolveRpId).
// background.js est chargé tel quel dans un contexte vm (importScripts neutralisé, pas de
// `chrome` : l'écouteur de messages n'est pas enregistré) ; resolveRpId est extrait du
// source de passkey-bridge.js et évalué avec un `window.location.hostname` simulé.
// Lancement : node --test test/passkey/rpid-policy.test.js
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const EXT = path.resolve(__dirname, '..', '..', 'chrome-extension/vault-autofill-extension');
const BG_FILE = path.join(EXT, 'background.js');
const BRIDGE_FILE = path.join(EXT, 'passkey-bridge.js');
const bgSrc = fs.readFileSync(BG_FILE, 'utf8');
const bridgeSrc = fs.readFileSync(BRIDGE_FILE, 'utf8');

// --- background.js : fonction réelle, chargée dans un bac à sable ---
const bgCtx = vm.createContext({
  importScripts: () => {},
  console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
  URL, setTimeout, clearTimeout, setInterval, clearInterval
});
vm.runInContext(bgSrc, bgCtx, { filename: BG_FILE });
const passkeyRpAllowedForSender = vm.runInContext('passkeyRpAllowedForSender', bgCtx);

// --- passkey-bridge.js : resolveRpId et ses listes, extraits du source ---
const start = bridgeSrc.indexOf('const PUBLIC_SUFFIXES');
const fnStart = bridgeSrc.indexOf('function resolveRpId(', start);
const end = bridgeSrc.indexOf('\n  }\n', fnStart);
assert.ok(start >= 0 && fnStart > start && end > fnStart, 'resolveRpId introuvable dans passkey-bridge.js');
const bridgeCtx = vm.createContext({ window: { location: { hostname: '' } } });
vm.runInContext(bridgeSrc.slice(start, end + 4) + '\n;globalThis.resolveRpId = resolveRpId;', bridgeCtx, { filename: BRIDGE_FILE });
function bridgeAllows(host, rpId) {
  bridgeCtx.window.location.hostname = host;
  return bridgeCtx.resolveRpId(rpId) !== null;
}

/** Expéditeur Chrome simulé : onglet https (frame principale) */
const senderFor = (host) => ({ tab: { url: `https://${host}/login` }, frameId: 0 });

// [hôte de l'onglet, rpId demandé, autorisé ?]
const CASES = [
  ['example.com', 'example.com', true],
  ['login.example.com', 'example.com', true],
  ['login.example.com', 'EXAMPLE.COM', true],
  ['a.b.example.com', 'b.example.com', true],
  ['shop.example.co.uk', 'example.co.uk', true],
  ['alice.github.io', 'alice.github.io', true],
  ['localhost', 'localhost', true],
  ['192.168.1.10', '192.168.1.10', true],
  // TLD nu
  ['login.example.com', 'com', false],
  ['example.fr', 'fr', false],
  // IP partielle (l'hôte est une adresse IP : aucun rpId parent)
  ['192.168.1.10', '168.1.10', false],
  ['192.168.1.10', '1.10', false],
  ['10.0.0.1', '0.1', false],
  // Suffixes publics (liste partielle + seconds niveaux de ccTLD)
  ['alice.github.io', 'github.io', false],
  ['app.vercel.app', 'vercel.app', false],
  ['shop.example.co.uk', 'co.uk', false],
  ['site.example.com.au', 'com.au', false],
  ['x.example.or.jp', 'or.jp', false],
  // Domaines sans rapport / faux suffixe
  ['example.com', 'evil.com', false],
  ['notexample.com', 'example.com', false],
  ['example.com', 'login.example.com', false]
];

test('passkeyRpAllowedForSender applique la règle « registrable domain suffix » (TLD, IP partielle, suffixes publics refusés)', () => {
  for (const [host, rpId, expected] of CASES) {
    assert.equal(passkeyRpAllowedForSender(rpId, senderFor(host)), expected, `${host} / rpId=${rpId}`);
  }
});

test('passkeyRpAllowedForSender rend exactement la même décision que resolveRpId (passkey-bridge.js)', () => {
  for (const [host, rpId] of CASES) {
    assert.equal(passkeyRpAllowedForSender(rpId, senderFor(host)), bridgeAllows(host, rpId), `${host} / rpId=${rpId}`);
  }
});

test('hôte de référence = frame émettrice (iframe) ; page non https ou rpId vide refusés', () => {
  const iframeSender = { tab: { url: 'https://host.example.org/' }, frameId: 3, url: 'https://pay.example.net/frame' };
  assert.equal(passkeyRpAllowedForSender('example.net', iframeSender), true);
  assert.equal(passkeyRpAllowedForSender('example.org', iframeSender), false);
  assert.equal(passkeyRpAllowedForSender('example.com', { tab: { url: 'http://example.com/' }, frameId: 0 }), false);
  assert.equal(passkeyRpAllowedForSender('', senderFor('example.com')), false);
  assert.equal(passkeyRpAllowedForSender('example.com', null), false);
});

test('listes de suffixes publics, motif ccTLD et détection IP identiques dans background.js et passkey-bridge.js', () => {
  const suffixes = (src) => {
    const m = src.match(/PUBLIC_SUFFIXES = new Set\(\[([\s\S]*?)\]\)/);
    assert.ok(m, 'liste PUBLIC_SUFFIXES introuvable');
    return [...m[1].matchAll(/'([^']+)'/g)].map(x => x[1]).sort();
  };
  const cctld = (src) => (src.match(/CCTLD_SECOND_LEVEL = (\/.+\/);/) || [])[1];
  const ipRule = (src) => (src.match(/[iI]sIpHost = \(h\) => (.+);/) || [])[1];
  assert.deepEqual(suffixes(bgSrc), suffixes(bridgeSrc));
  assert.ok(cctld(bgSrc) && cctld(bgSrc) === cctld(bridgeSrc), 'motif CCTLD_SECOND_LEVEL divergent');
  assert.ok(ipRule(bgSrc) && ipRule(bgSrc) === ipRule(bridgeSrc), 'détection d\'hôte IP divergente');
});
