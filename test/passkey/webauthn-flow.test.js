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
    // État de RDVAULT (fenêtre de création) : ouvert et déverrouillé
    if (m.type === 'PASSKEY_STATUS') return { success: true, ready: true };
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
    location, isSecureContext: true,
    // PublicKeyCredential natif simulé : sans Windows Hello (authentificateur de plateforme absent)
    PublicKeyCredential: Object.assign(function () {}, {
      isUserVerifyingPlatformAuthenticatorAvailable: async () => false,
      getClientCapabilities: async () => ({ hybridTransport: true, userVerifyingPlatformAuthenticator: false, passkeyPlatformAuthenticator: false }),
    }),
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
  // Touche réelle (isTrusted) pressée sur l'élément qui a le focus dans la n-ième fenêtre
  const key = (n, k, opts = {}) => {
    const { root } = roots[n];
    const target = root.activeElement || root.querySelector('.bx');
    const ev = new w.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, composed: true, ...opts });
    idl.implForWrapper(ev).isTrusted = true;
    idl.implForWrapper(target)._dispatch(idl.implForWrapper(ev));
    return ev;
  };
  return { navigator, native, roots, click, key, win, document };
}

// État d'une promesse sans l'attendre ('pending', 'resolved' ou le nom de l'erreur)
function track(p) {
  const t = { state: 'pending', value: null, error: null, at: 0 };
  t.done = p.then((v) => { t.state = 'resolved'; t.value = v; t.at = Date.now(); }, (e) => { t.state = (e && e.name) || 'rejected'; t.error = e; t.at = Date.now(); });
  return t;
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
// Passkey du coffre : sauvegardée et synchronisée avec lui → drapeaux BE | BS (0x08 | 0x10), comme les
// gestionnaires de passkeys du marché ; AAGUID propre à RDVAULT (plus l'AAGUID nul pris pour Apple).
test('UV + sauvegarde : coffre déverrouillé → UP|UV|BE|BS|AT = 0x5d à la création, UP|UV|BE|BS = 0x1d à l\'authentification', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  const cred = await register(f, 0);
  const ad = authDataOf(cred.response.attestationObject);
  assert.equal(ad[32], 0x5d, 'création : UP | UV | BE | BS | AT (0x' + ad[32].toString(16) + ')');
  assert.equal(Buffer.from(ad.slice(37, 53)).toString('hex'), '1c80936c3d174ec8acaf40e1e6a081cd', 'AAGUID RDVAULT');
  assert.deepEqual(new Uint8Array(cred.response.getAuthenticatorData()), ad, 'getAuthenticatorData() porte les mêmes drapeaux');
  assert.equal(vault.items['site-a.com'][0].backupEligible, true, 'BE mémorisé avec la passkey (figé pour sa durée de vie)');
  const pg = f.navigator.credentials.get(getOpts());
  await sleep(ARM); f.click(1);
  const asrt = await pg;
  assert.equal(Buffer.from(asrt.response.authenticatorData)[32], 0x1d, 'assertion : UP | UV | BE | BS');
});

test('Passkey antérieure (enregistrée sans BE) : l\'assertion reste UP|UV = 0x05 (BE ne doit jamais changer)', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  await register(f, 0);
  delete vault.items['site-a.com'][0].backupEligible; // forme stockée par les versions précédentes
  const pg = f.navigator.credentials.get(getOpts());
  await sleep(ARM); f.click(1);
  const asrt = await pg;
  assert.equal(Buffer.from(asrt.response.authenticatorData)[32], 0x05, 'assertion : UP | UV, sans BE/BS');
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
  // PASSKEY_STATUS : état de RDVAULT (GET /sync) vérifié à l'ouverture de la fenêtre de création (EXT-26)
  assert.deepEqual(vault.calls, ['PASSKEY_STATUS', 'PASSKEY_STORE', 'PASSKEY_LIST', 'PASSKEY_UPDATE_COUNT']);
});

// EXT-26 : RDVAULT fermé ou verrouillé → la fenêtre de création le dit et n'active pas « Créer dans
// RDVAULT » (le clic aboutissait à un NotAllowedError muet) ; « Utiliser un autre appareil » reste proposé.
test('UV : coffre verrouillé ou fermé → aucune passkey RDVAULT (get → navigateur ; create : fenêtre « RDVAULT est fermé ou verrouillé », bouton RDVAULT désactivé), jamais d\'UV sans coffre', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  await register(f, 0);
  // Verrouillage : le service worker ne joint plus le coffre (réponse d'échec de l'application)
  const unlocked = vault.sw;
  vault.sw = async (m) => { vault.calls.push(m.type); return { success: false, error: 'Not authenticated' }; };
  const rg = await f.navigator.credentials.get(getOpts({ userVerification: 'required' }));
  assert.deepEqual(rg, { native: true }, 'authentification : passkeys illisibles → navigateur, sans fenêtre');
  assert.equal(f.roots.length, 1, 'aucune nouvelle fenêtre RDVAULT');
  const storesBefore = vault.calls.filter((c) => c === 'PASSKEY_STORE').length;
  const pc = track(f.navigator.credentials.create(createOpts({ authenticatorSelection: { userVerification: 'required' } })));
  await sleep(ARM);
  const root = f.roots[1].root;
  assert.equal(root.querySelector('.ok').disabled, true, '« Créer dans RDVAULT » désactivé');
  assert.equal(root.querySelector('.er').hidden, false, 'explication affichée');
  assert.equal(root.querySelector('.er').textContent, 'RDVAULT est fermé ou verrouillé : ouvrez-le et déverrouillez-le pour continuer, ou utilisez un autre appareil.');
  assert.equal(root.querySelector('.er').getAttribute('role'), 'alert', 'annoncée aux lecteurs d\'écran');
  f.click(1); // clic réel sur le bouton désactivé : sans effet
  await sleep(50);
  assert.equal(pc.state, 'pending', 'aucun échec muet : la fenêtre reste ouverte');
  assert.equal(vault.calls.filter((c) => c === 'PASSKEY_STORE').length, storesBefore, 'aucune tentative d\'enregistrement');
  f.click(1, '.ca');
  await pc.done;
  assert.equal(pc.state, 'NotAllowedError', 'Annuler → NotAllowedError standard');
  // « Utiliser un autre appareil » : authentificateur du navigateur
  const pf = f.navigator.credentials.create(createOpts());
  await sleep(ARM); f.click(2, '.fb');
  assert.deepEqual(await pf, { native: true }, 'autre appareil → navigateur');
  assert.equal(vault.items['site-a.com'].length, 1, 'rien ajouté au coffre');
  vault.sw = unlocked;
});

test('EXT-26 : RDVAULT déverrouillé pendant que la fenêtre est ouverte → bouton réactivé, passkey créée', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const unlocked = vault.sw;
  vault.sw = async (m) => { vault.calls.push(m.type); return { success: false, error: 'Not authenticated' }; };
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const pc = track(f.navigator.credentials.create(createOpts()));
  await sleep(ARM);
  const root = f.roots[0].root;
  assert.equal(root.querySelector('.ok').disabled, true);
  vault.sw = unlocked; // l'utilisateur déverrouille RDVAULT
  await sleep(2800);   // nouvelle vérification (READINESS_POLL_MS = 2,5 s)
  assert.equal(root.querySelector('.ok').disabled, false, 'bouton réactivé');
  assert.equal(root.querySelector('.er').hidden, true, 'explication retirée');
  f.click(0);
  await pc.done;
  assert.equal(pc.state, 'resolved');
  assert.equal(pc.value.type, 'public-key');
  assert.equal(vault.items['site-a.com'].length, 1);
});

test('EXT-26 : enregistrement refusé APRÈS le clic (RDVAULT verrouillé entre-temps) → fenêtre ouverte avec l\'explication, aucune attestation, autre appareil possible', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const unlocked = vault.sw;
  vault.sw = async (m) => (m.type === 'PASSKEY_STORE' ? (vault.calls.push(m.type), { success: false }) : unlocked(m));
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const pc = track(f.navigator.credentials.create(createOpts()));
  await sleep(ARM); f.click(0);
  await sleep(100);
  const root = f.roots[0].root;
  assert.equal(pc.state, 'pending', 'pas de NotAllowedError muet');
  assert.ok(f.roots[0].host.isConnected, 'fenêtre toujours affichée');
  assert.equal(root.querySelector('.er').hidden, false, 'explication affichée');
  assert.equal(root.querySelector('.ok').disabled, true);
  assert.equal(root.activeElement, root.querySelector('.fb'), 'focus sur « Utiliser un autre appareil »');
  f.click(0, '.fb');
  await pc.done;
  assert.deepEqual(pc.value, { native: true }, 'autre appareil → navigateur');
  assert.equal(vault.items['site-a.com'], undefined, 'rien dans le coffre');
});

// EXT-21 : la page annule sa cérémonie (AbortSignal, comme SimpleWebAuthn avant une nouvelle cérémonie)
test('EXT-21 : create() annulé par AbortSignal → AbortError immédiat, fenêtre fermée, aucune passkey enregistrée même après un clic', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const ac = new AbortController();
  const pc = track(f.navigator.credentials.create({ ...createOpts(), signal: ac.signal }));
  await sleep(ARM);
  const { host } = f.roots[0];
  assert.ok(host.isConnected, 'fenêtre affichée');
  const abortedAt = Date.now();
  ac.abort();
  await sleep(30);
  assert.equal(pc.state, 'AbortError', 'promesse rejetée en AbortError');
  assert.ok(pc.at - abortedAt < 30, 'immédiatement');
  assert.equal(host.isConnected, false, 'fenêtre RDVAULT fermée');
  f.click(0); // clic sur la fenêtre retirée : sans effet
  await sleep(100);
  assert.ok(!vault.calls.includes('PASSKEY_STORE'), 'aucune passkey envoyée au coffre');
  assert.equal(f.native.create.length, 0, 'pas de bascule vers le navigateur');
  // Signal déjà annulé : rejet sans fenêtre, raison du signal conservée
  const ac2 = new AbortController(); ac2.abort(new Error('motif'));
  await assert.rejects(f.navigator.credentials.create({ ...createOpts(), signal: ac2.signal }), /motif/);
  assert.equal(f.roots.length, 1, 'aucune nouvelle fenêtre');
});

test('EXT-21 : get() annulé par AbortSignal → AbortError, fenêtre fermée, aucun compteur réservé ni signature', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/login', vault });
  await register(f, 0);
  const ac = new AbortController();
  const pg = track(f.navigator.credentials.get({ ...getOpts(), signal: ac.signal }));
  await sleep(ARM);
  const { host } = f.roots[1];
  ac.abort();
  await sleep(30);
  assert.equal(pg.state, 'AbortError');
  assert.equal(host.isConnected, false, 'fenêtre fermée');
  f.click(1);
  await sleep(100);
  assert.ok(!vault.calls.includes('PASSKEY_UPDATE_COUNT'), 'aucun compteur réservé');
  assert.equal(vault.items['site-a.com'][0].signCount, 0);
});

test('EXT-21 : délai de la cérémonie (publicKey.timeout, borné à 10 s) écoulé → fenêtre fermée AVANT la bascule vers le navigateur, rien enregistré', { timeout: 30000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const start = Date.now();
  const pc = track(f.navigator.credentials.create(createOpts({ timeout: 1000 })));
  await sleep(ARM);
  const { host } = f.roots[0];
  await pc.done;
  const elapsed = pc.at - start;
  assert.deepEqual(pc.value, { native: true }, 'navigateur après le délai');
  assert.ok(elapsed >= 9900 && elapsed < 12000, 'délai du site borné à 10 s (' + elapsed + ' ms)');
  await sleep(20); // message « abort » posté au pont avant la bascule, traité à la tâche suivante
  assert.equal(host.isConnected, false, 'fenêtre RDVAULT fermée');
  f.click(0);
  await sleep(100);
  assert.ok(!vault.calls.includes('PASSKEY_STORE'), 'aucune passkey orpheline');
});

// EXT-24 : fenêtre utilisable au clavier et par les lecteurs d'écran
test('EXT-24 : fenêtre nommée, focus déplacé (jamais sur un bouton qui signe), Tab bouclé, Échap annule, focus rendu à la page', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://site-a.com/register', vault });
  const pageBtn = f.document.createElement('button');
  pageBtn.id = 'create'; f.document.body.appendChild(pageBtn); pageBtn.focus();
  const pc = track(f.navigator.credentials.create(createOpts()));
  await sleep(ARM);
  const { root, host } = f.roots[0];
  const box = root.querySelector('.bx');
  assert.equal(box.getAttribute('role'), 'dialog');
  assert.equal(box.getAttribute('aria-modal'), 'true');
  assert.equal(root.getElementById(box.getAttribute('aria-labelledby')).textContent, 'RDVAULT', 'nom accessible');
  assert.equal(root.getElementById(box.getAttribute('aria-describedby')).textContent, 'Créer une passkey pour site-a.com — alice@test', 'description');
  assert.equal(f.document.activeElement, host, 'focus dans la fenêtre (hôte)');
  assert.equal(root.activeElement, box, 'focus sur la boîte, pas sur « Créer dans RDVAULT »');
  // Tab : boucle sur les boutons de la fenêtre uniquement
  const seen = [];
  for (let i = 0; i < 4; i++) { const ev = f.key(0, 'Tab'); assert.equal(ev.defaultPrevented, true); seen.push(root.activeElement.className); }
  assert.deepEqual(seen, ['ok', 'fb', 'ca', 'ok'], 'Tab bouclé dans la fenêtre');
  f.key(0, 'Tab', { shiftKey: true });
  assert.equal(root.activeElement.className, 'ca', 'Maj+Tab : bouclage inverse');
  // Échap : annulation standard, fenêtre fermée, focus rendu au bouton de la page
  f.key(0, 'Escape');
  await pc.done;
  assert.equal(pc.state, 'NotAllowedError');
  assert.equal(host.isConnected, false);
  assert.equal(f.document.activeElement, pageBtn, 'focus rendu à l\'élément de la page');
  assert.ok(!vault.calls.includes('PASSKEY_STORE'));
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

// Sans Windows Hello, Chrome répond « pas d'authentificateur de plateforme » : des sites (Google) refusent
// alors de créer une passkey sur cet appareil et écartent les passkeys « internal » de RDVAULT.
test('Authentificateur de plateforme : annoncé disponible quand le coffre RDVAULT est déverrouillé, réponse native sinon', { timeout: 20000 }, async () => {
  const vault = makeVault();
  const f = loadFrame({ url: 'https://accounts.example.com/login', vault });
  const PKC = f.win.PublicKeyCredential;
  assert.equal(await PKC.isUserVerifyingPlatformAuthenticatorAvailable(), true, 'coffre déverrouillé → true');
  const caps = await PKC.getClientCapabilities();
  assert.equal(caps.userVerifyingPlatformAuthenticator, true);
  assert.equal(caps.passkeyPlatformAuthenticator, true);
  assert.equal(caps.hybridTransport, true, 'autres capacités natives conservées');

  const locked = makeVault();
  locked.sw = async (m) => { locked.calls.push(m.type); return { success: false, error: 'Not authenticated' }; };
  const g = loadFrame({ url: 'https://accounts.example.com/login', vault: locked });
  assert.equal(await g.win.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), false, 'coffre verrouillé → réponse native (false)');
  assert.equal((await g.win.PublicKeyCredential.getClientCapabilities()).userVerifyingPlatformAuthenticator, false);
  assert.ok(locked.calls.every((c) => c === 'PASSKEY_LIST'), 'seule la liste est interrogée (aucune écriture)');
});
