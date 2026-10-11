// Parcours WebAuthn complet de l'extension, scripts RÉELS : passkey-inject.js (monde de la page)
// ↔ passkey-bridge.js (monde isolé, fenêtre de consentement réelle dans jsdom, clic isTrusted)
// ↔ passkey-core.js, avec un faux service worker / coffre. Vérifie la conformité WebAuthn :
//  - PASSKEYS-19 : compteur de signatures strictement croissant entre onglets (réservation)
//  - PASSKEYS-20 : clientDataJSON.crossOrigin / topOrigin dans une iframe cross-origin déléguée
//  - PASSKEYS-21 : excludeCredentials (InvalidStateError) et pubKeyCredParams (ES256 requis)
//  - UV (décision produit) : coffre déverrouillé par le mot de passe maître = utilisateur vérifié →
//    drapeau UV posé ; userVerification « required » servi par RDVAULT ; coffre verrouillé → rien
//  - PASSKEYS-23 : getAuthenticatorData / getPublicKey / getTransports / toJSON conformes
// Lancement : node --test test/passkey/webauthn-flow.test.js (inclus dans npm run test:passkey)
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..', '..');
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const { JSDOM } = require(path.join(ROOT, 'node_modules/jsdom'));
const idl = require(path.join(ROOT, 'node_modules/jsdom/lib/jsdom/living/generated/utils.js'));
const core = require(path.join(EXT, 'passkey-core.js'));
const BRIDGE_SRC = fs.readFileSync(path.join(EXT, 'passkey-bridge.js'), 'utf8');
const INJECT_SRC = fs.readFileSync(path.join(EXT, 'passkey-inject.js'), 'utf8');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ARM = 650; // délai d'armement de la fenêtre (500 ms) + marge

// ---------- CBOR minimal (décodage) ----------
function cborDecode(bytes) {
  let i = 0;
  function read() {
    const b = bytes[i++]; const major = b >> 5; let n = b & 0x1f;
    if (n === 24) n = bytes[i++];
    else if (n === 25) { n = (bytes[i++] << 8) | bytes[i++]; }
    else if (n === 26) { n = ((bytes[i++] << 24) | (bytes[i++] << 16) | (bytes[i++] << 8) | bytes[i++]) >>> 0; }
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2) { const v = bytes.slice(i, i + n); i += n; return v; }
    if (major === 3) { const v = bytes.slice(i, i + n); i += n; return new TextDecoder().decode(v); }
    if (major === 5) { const m = new Map(); for (let k = 0; k < n; k++) { const key = read(); m.set(key, read()); } return m; }
    throw new Error('cbor major ' + major);
  }
  return read();
}

// ---------- Faux coffre : sémantique du renderer (usePasskeys.js) ----------
// legacyCount : ancien renderer (compteur remplacé tel quel, sans champ « reserved »)
function makeVault({ legacyCount = false } = {}) {
  const items = {}; const calls = [];
  const sw = async (m) => {
    calls.push(m.type);
    await sleep(3);
    if (m.type === 'PASSKEY_LIST') return { success: true, passkeys: JSON.parse(JSON.stringify(items[m.rpId] || [])) };
    if (m.type === 'PASSKEY_STORE') { (items[m.passkey.rpId] ||= []).push(JSON.parse(JSON.stringify(m.passkey))); return { success: true }; }
    if (m.type === 'PASSKEY_UPDATE_COUNT') {
      const e = (items[m.rpId] || []).find((x) => x.credentialId === m.credentialId);
      if (!e) return { success: true };
      if (legacyCount) { e.signCount = Number(m.signCount) || e.signCount; return { success: true }; }
      const stored = Number(e.signCount) || 0; const wanted = Number(m.signCount) || 0;
      if (wanted <= stored) return { success: true, signCount: stored, reserved: false };
      e.signCount = wanted; return { success: true, signCount: wanted, reserved: true };
    }
    return { success: false };
  };
  return { items, calls, sw };
}

// ---------- Une frame : inject (page) + pont (isolé) partageant le même window ----------
// ancestors : valeur de location.ancestorOrigins (undefined = API absente)
function loadFrame({ url, top = true, ancestors, allow = true, vault }) {
  const dom = new JSDOM('<!doctype html><html><head></head><body></body></html>', { url, pretendToBeVisual: true });
  const w = dom.window; const document = w.document;
  const roots = []; let currentHost = null;
  const origAttach = w.Element.prototype.attachShadow;
  w.Element.prototype.attachShadow = function (o) { const r = origAttach.call(this, o); roots.push({ host: this, root: r }); return r; };
  document.elementFromPoint = () => currentHost; // l'hôte de la fenêtre est au premier plan
  document.featurePolicy = { allowsFeature: () => allow };
  const getComputedStyle = () => ({ opacity: '1', visibility: 'visible', filter: 'none', clipPath: 'none', mixBlendMode: 'normal', maskImage: 'none', webkitMaskImage: 'none' });
  const location = { origin: w.location.origin, hostname: w.location.hostname, href: w.location.href };
  if (ancestors !== undefined) location.ancestorOrigins = ancestors;
  const listeners = [];
  const win = {
    location, isSecureContext: true, PublicKeyCredential: function () {},
    postMessage: (m) => { setTimeout(() => listeners.slice().forEach((fn) => fn({ source: win, data: m })), 0); },
    addEventListener: (t, fn) => { if (t === 'message') listeners.push(fn); },
  };
  win.top = top ? win : { location: {} };
  const native = { create: [], get: [] };
  const navigator = { credentials: {
    create: async (o) => { native.create.push(o); return { native: true }; },
    get: async (o) => { native.get.push(o); return { native: true }; },
  } };
  const chrome = { runtime: { sendMessage: (m) => vault.sw(m) } };
  // eslint-disable-next-line no-new-func -- scripts réels de l'extension exécutés avec un window simulé
  new Function('window', 'document', 'chrome', 'globalThis', 'getComputedStyle', 'IntersectionObserver', BRIDGE_SRC)(
    win, document, chrome, { RDVaultPasskeyCore: core }, getComputedStyle, undefined);
  // eslint-disable-next-line no-new-func -- idem (monde de la page)
  new Function('window', 'navigator', 'location', INJECT_SRC)(win, navigator, location);
  // Clic réel (isTrusted) sur un bouton de la n-ième fenêtre ouverte
  const click = (n, sel = '.ok, .ac') => {
    const { host, root } = roots[n];
    const btn = root.querySelector(sel);
    currentHost = host;
    const ev = new w.MouseEvent('click', { bubbles: true, cancelable: true, composed: true });
    idl.implForWrapper(ev).isTrusted = true;
    idl.implForWrapper(btn)._dispatch(idl.implForWrapper(ev));
  };
  return { navigator, native, roots, click };
}

const enc = (s) => new TextEncoder().encode(s);
const createOpts = (extra = {}) => ({ publicKey: {
  challenge: nodeCrypto.randomBytes(32), rp: { name: 'Test' },
  user: { id: enc('user-1'), name: 'alice@test', displayName: 'Alice' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }], ...extra,
} });
const getOpts = (extra = {}) => ({ publicKey: { challenge: nodeCrypto.randomBytes(32), ...extra } });
const authDataOf = (attObj) => cborDecode(new Uint8Array(attObj)).get('authData');
const cdj = (buf) => JSON.parse(Buffer.from(buf).toString('utf8'));
const counterOf = (asrt) => Buffer.from(asrt.response.authenticatorData).readUInt32BE(33);

// Crée une passkey par l'API de la page (clic réel dans la fenêtre)
async function register(frame, n, extra) {
  const p = frame.navigator.credentials.create(createOpts(extra));
  await sleep(ARM); frame.click(n);
  return p;
}

// Décision produit (UV) : le coffre RDVAULT n'est lisible qu'une fois DÉVERROUILLÉ par le mot de passe
// maître, ce qui vaut vérification de l'utilisateur (comme les gestionnaires de mots de passe du marché).
// Une passkey servie par RDVAULT porte donc le drapeau UV ; userVerification « required » est servi par RDVAULT.
test('UV : coffre déverrouillé → drapeau UV posé (UP|UV|AT = 0x45 à la création, UP|UV = 0x05 à l\'authentification)', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  const cred = await register(f, 0);
  const ad = authDataOf(cred.response.attestationObject);
  assert.equal(ad[32], 0x45, 'création : UP | UV | AT (0x' + ad[32].toString(16) + ')');
  assert.deepEqual(new Uint8Array(cred.response.getAuthenticatorData()), ad, 'getAuthenticatorData() porte les mêmes drapeaux');
  const pg = f.navigator.credentials.get(getOpts());
  await sleep(ARM); f.click(1);
  const asrt = await pg;
  assert.equal(Buffer.from(asrt.response.authenticatorData)[32], 0x05, 'assertion : UP | UV');
});

test('UV : userVerification « required » (création et authentification) → servi par RDVAULT, fenêtre affichée, UV posé', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  const cred = await register(f, 0, { authenticatorSelection: { userVerification: 'required', residentKey: 'required' } });
  assert.equal(cred.type, 'public-key', 'création servie par RDVAULT (pas le navigateur)');
  assert.equal(f.native.create.length, 0, 'authentificateur natif non sollicité');
  assert.equal(authDataOf(cred.response.attestationObject)[32] & 0x05, 0x05, 'création : UP et UV');
  assert.equal(vault.items['site-a.com'].length, 1, 'passkey enregistrée dans le coffre');
  const pg = f.navigator.credentials.get(getOpts({ userVerification: 'required', allowCredentials: [{ type: 'public-key', id: new Uint8Array(cred.rawId) }] }));
  await sleep(ARM);
  assert.equal(f.roots.length, 2, 'fenêtre RDVAULT affichée pour l\'authentification');
  f.click(1);
  const asrt = await pg;
  assert.equal(asrt.id, cred.id);
  assert.equal(Buffer.from(asrt.response.authenticatorData)[32] & 0x05, 0x05, 'assertion : UP et UV');
  assert.equal(f.native.get.length, 0, 'authentificateur natif non sollicité');
  assert.deepEqual(vault.calls, ['PASSKEY_STORE', 'PASSKEY_LIST', 'PASSKEY_UPDATE_COUNT']);
});

test('UV : coffre verrouillé ou fermé → aucune passkey RDVAULT (get → navigateur, create → NotAllowedError), jamais d\'UV sans coffre', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  await register(f, 0);
  // Verrouillage : le service worker ne joint plus le coffre (réponse d'échec de l'application)
  const unlocked = vault.sw;
  vault.sw = async (m) => { vault.calls.push(m.type); return { success: false, error: 'Not authenticated' }; };
  const rg = await f.navigator.credentials.get(getOpts({ userVerification: 'required' }));
  assert.deepEqual(rg, { native: true }, 'authentification : passkeys illisibles → navigateur, sans fenêtre');
  assert.equal(f.roots.length, 1, 'aucune nouvelle fenêtre RDVAULT');
  const pc = f.navigator.credentials.create(createOpts({ authenticatorSelection: { userVerification: 'required' } }));
  await sleep(ARM); f.click(1);
  await assert.rejects(pc, (e) => e && e.name === 'NotAllowedError', 'création : rejetée, aucune attestation (clé non enregistrable)');
  assert.equal(vault.items['site-a.com'].length, 1, 'rien ajouté au coffre');
  vault.sw = unlocked;
});

test('PASSKEYS-21 : pubKeyCredParams sans ES256 (-7) → natif ; ES256 parmi d\'autres ou liste vide → RDVAULT', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const r = await f.navigator.credentials.create(createOpts({ pubKeyCredParams: [{ type: 'public-key', alg: -257 }] }));
  assert.deepEqual(r, { native: true }, 'RS256 seul → navigateur');
  assert.equal(f.roots.length, 0);
  const c1 = await register(f, 0, { pubKeyCredParams: [{ type: 'public-key', alg: -257 }, { type: 'public-key', alg: -7 }] });
  assert.equal(c1.type, 'public-key');
  const c2 = await register(f, 1, { pubKeyCredParams: [] }); // liste vide : ES256 et RS256 par défaut
  assert.equal(c2.type, 'public-key');
  assert.equal(vault.items['site-a.com'].length, 2);
});

test('PASSKEYS-21 : excludeCredentials contenant une passkey RDVAULT → InvalidStateError après consentement, aucune passkey ajoutée', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const first = await register(f, 0);
  const p = f.navigator.credentials.create(createOpts({ excludeCredentials: [{ type: 'public-key', id: new Uint8Array(first.rawId) }] }));
  await sleep(ARM);
  assert.equal(f.roots.length, 2, 'la fenêtre est affichée (consentement requis avant de répondre)');
  f.click(1);
  await assert.rejects(p, (e) => e && e.name === 'InvalidStateError');
  assert.equal(vault.items['site-a.com'].length, 1, 'aucune seconde passkey pour le même compte');
  // Identifiant exclu inconnu de RDVAULT (autre authentificateur) : création normale
  const ok = await register(f, 2, { excludeCredentials: [{ type: 'public-key', id: new Uint8Array(16).fill(9) }] });
  assert.equal(ok.type, 'public-key');
  assert.equal(vault.items['site-a.com'].length, 2);
});

test('PASSKEYS-20 : iframe cross-origin déléguée → clientData.crossOrigin = true + topOrigin', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://login.partner.example/sso', top: false, ancestors: ['https://embedder.example'], vault });
  const cred = await register(f, 0);
  const cc = cdj(cred.response.clientDataJSON);
  assert.equal(cc.crossOrigin, true);
  assert.equal(cc.topOrigin, 'https://embedder.example');
  assert.deepEqual(Object.keys(cc), ['type', 'challenge', 'origin', 'crossOrigin', 'topOrigin'], 'ordre de sérialisation de la spécification');
  const pg = f.navigator.credentials.get(getOpts());
  await sleep(ARM); f.click(1);
  const cg = cdj((await pg).response.clientDataJSON);
  assert.equal(cg.crossOrigin, true);
  assert.equal(cg.topOrigin, 'https://embedder.example');
});

test('PASSKEYS-20 : page principale et iframe même origine → crossOrigin = false sans topOrigin ; ancêtres inconnus → natif', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const top = loadFrame({ url: 'https://site-a.com/', vault });
  const c1 = cdj((await register(top, 0)).response.clientDataJSON);
  assert.equal(c1.crossOrigin, false); assert.equal('topOrigin' in c1, false);

  const same = loadFrame({ url: 'https://site-a.com/frame', top: false, ancestors: ['https://site-a.com'], vault });
  const c2 = cdj((await register(same, 0)).response.clientDataJSON);
  assert.equal(c2.crossOrigin, false); assert.equal('topOrigin' in c2, false);

  // Iframe dont les ancêtres ne sont pas connus (API absente / origine masquée) : le navigateur
  // remplit lui-même crossOrigin / topOrigin
  for (const ancestors of [undefined, ['null']]) {
    const unk = loadFrame({ url: 'https://site-b.com/frame', top: false, ancestors, vault });
    assert.deepEqual(await unk.navigator.credentials.create(createOpts()), { native: true });
    assert.equal(unk.roots.length, 0);
  }
});

test('PASSKEYS-19 : deux onglets → compteurs strictement croissants (6, 7 puis 8), coffre à 8', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const kp = await core.createCredential({ rpId: 'shop.example', origin: 'https://shop.example', challenge: 'AAAA' });
  vault.items['shop.example'] = [{ rpId: 'shop.example', credentialId: kp.credentialId, privateKeyJwk: kp.privateKeyJwk, userId: 'dTE', userName: 'u1', signCount: 5 }];
  const tab1 = loadFrame({ url: 'https://shop.example/login', vault });
  const tab2 = loadFrame({ url: 'https://shop.example/account', vault });
  const p1 = tab1.navigator.credentials.get(getOpts()); // fenêtre laissée ouverte (compteur lu : 5)
  await sleep(20);
  const p2 = tab2.navigator.credentials.get(getOpts());
  await sleep(ARM); tab2.click(0);
  const r2 = await p2;
  const p3 = tab2.navigator.credentials.get(getOpts());
  await sleep(ARM); tab2.click(1);
  const r3 = await p3;
  tab1.click(0); // retour sur le premier onglet
  const r1 = await p1;
  assert.deepEqual([counterOf(r2), counterOf(r3), counterOf(r1)], [6, 7, 8]);
  assert.equal(vault.items['shop.example'][0].signCount, 8);
});

test('PASSKEYS-19 : application de bureau antérieure (pas de champ « reserved ») → comportement inchangé', { timeout: 20000 }, async () => {
  const vault = makeVault({ legacyCount: true });
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  await register(f, 0);
  const pg = f.navigator.credentials.get(getOpts());
  await sleep(ARM); f.click(1);
  assert.equal(counterOf(await pg), 1);
  assert.equal(vault.items['site-a.com'][0].signCount, 1);
});

test('PASSKEYS-23 : objet renvoyé par create() et get() conforme (authData, clé publique SPKI, transports, toJSON L3)', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-b.com/register', vault });
  const cred = await register(f, 0);
  const att = cborDecode(new Uint8Array(cred.response.attestationObject));
  const authData = att.get('authData');
  assert.deepEqual(new Uint8Array(cred.response.getAuthenticatorData()), authData, 'getAuthenticatorData() = authData');
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual(cred.response.getTransports(), ['internal']);
  // getPublicKey() : SPKI DER de la clé COSE de l'attestation
  const credIdLen = (authData[53] << 8) | authData[54];
  const cose = cborDecode(authData.slice(55 + credIdLen));
  const spki = nodeCrypto.createPublicKey({ key: Buffer.from(cred.response.getPublicKey()), format: 'der', type: 'spki' });
  const jwk = spki.export({ format: 'jwk' });
  assert.equal(jwk.x, Buffer.from(cose.get(-2)).toString('base64url'));
  assert.equal(jwk.y, Buffer.from(cose.get(-3)).toString('base64url'));

  const j = cred.toJSON();
  assert.deepEqual(j.clientExtensionResults, {});
  assert.equal(j.authenticatorAttachment, 'platform');
  assert.equal(j.type, 'public-key');
  assert.equal(j.id, cred.id); assert.equal(j.rawId, cred.id);
  assert.deepEqual(Object.keys(j.response).sort(), ['attestationObject', 'authenticatorData', 'clientDataJSON', 'publicKey', 'publicKeyAlgorithm', 'transports']);
  assert.equal(j.response.authenticatorData, Buffer.from(authData).toString('base64url'));
  assert.equal(j.response.publicKey, Buffer.from(cred.response.getPublicKey()).toString('base64url'));
  assert.equal(j.response.publicKeyAlgorithm, -7);
  assert.deepEqual(j.response.transports, ['internal']);
  assert.doesNotThrow(() => JSON.stringify(j));

  const pg = f.navigator.credentials.get(getOpts());
  await sleep(ARM); f.click(1);
  const asrt = await pg;
  const ja = asrt.toJSON();
  assert.deepEqual(ja.clientExtensionResults, {});
  assert.equal(ja.authenticatorAttachment, 'platform');
  assert.equal(ja.response.userHandle, Buffer.from('user-1').toString('base64url'));
  assert.deepEqual(Object.keys(ja.response).sort(), ['authenticatorData', 'clientDataJSON', 'signature', 'userHandle']);
});

test('PASSKEYS-19 : background.js relaie « reserved » et « signCount » de l\'application au pont', { timeout: 20000 }, async () => {
  const BG_FILE = path.join(EXT, 'background.js');
  const replies = [];
  const ctx = vm.createContext({
    importScripts: () => {}, console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    URL, setTimeout, clearTimeout, setInterval, clearInterval,
    authManager: { authenticatedFetch: async () => replies.shift() },
  });
  vm.runInContext(fs.readFileSync(BG_FILE, 'utf8'), ctx, { filename: BG_FILE });
  const update = vm.runInContext('handlePasskeyUpdateCount', ctx);
  const sender = { tab: { url: 'https://site-a.com/login' }, frameId: 0 };
  const req = { rpId: 'site-a.com', credentialId: 'X', signCount: 6 };
  replies.push({ ok: true, json: async () => ({ success: true, signCount: 7, reserved: false }) });
  assert.deepEqual(JSON.parse(JSON.stringify(await update(req, sender))), { success: true, signCount: 7, reserved: false });
  replies.push({ ok: true, json: async () => ({ success: true }) }); // application antérieure
  assert.deepEqual(JSON.parse(JSON.stringify(await update(req, sender))), { success: true });
  replies.push({ ok: false, json: async () => ({ success: false, error: 'x' }) });
  assert.equal((await update(req, sender)).success, false);
});
