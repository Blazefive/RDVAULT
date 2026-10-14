// Validation du moteur FIDO2 (chrome-extension/vault-autofill-extension/passkey-core.js)
// Vérifie : structure de l'attestation, disposition des authenticatorData, extraction
// de la clé COSE, et surtout la VALIDITÉ cryptographique de la signature d'assertion
// (y compris l'encodage DER) via le crypto natif de Node.
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const path = require('path');

const core = require(path.resolve(__dirname, '..', '..', 'chrome-extension/vault-autofill-extension/passkey-core.js'));
const { concat, strToBytes, sha256, b64urlDecode } = core._internal;

// --- décodeur CBOR minimal pour valider l'encodeur ---
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

const RP_ID = 'webauthn.io';
const ORIGIN = 'https://webauthn.io';

test('createCredential produit une attestation "none" bien formée', async () => {
  const challenge = nodeCrypto.randomBytes(32);
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(challenge) });

  // clientDataJSON correct
  const cdj = JSON.parse(new TextDecoder().decode(b64urlDecode(cred.clientDataJSONB64u)));
  assert.equal(cdj.type, 'webauthn.create');
  assert.equal(cdj.origin, ORIGIN);

  // attestationObject = {fmt:'none', attStmt:{}, authData}
  const att = cborDecode(b64urlDecode(cred.attestationObjectB64u));
  assert.equal(att.get('fmt'), 'none');
  assert.equal(att.get('attStmt').size, 0);
  const authData = att.get('authData');

  // Disposition authData : rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16) | credIdLen(2) | credId | COSE
  const rpIdHash = await sha256(strToBytes(RP_ID));
  assert.deepEqual(authData.slice(0, 32), rpIdHash, 'rpIdHash');
  assert.equal(authData[32] & 0x40, 0x40, 'flag AT (attested credential data)');
  assert.equal(authData[32] & 0x01, 0x01, 'flag UP (user present)');
  const credIdLen = (authData[53] << 8) | authData[54];
  assert.equal(credIdLen, 16);
  const credId = authData.slice(55, 55 + credIdLen);
  assert.equal(core._internal.b64urlEncode(credId), cred.credentialId);

  // COSE key : kty EC2, alg ES256, crv P-256, x/y 32o
  const cose = cborDecode(authData.slice(55 + credIdLen));
  assert.equal(cose.get(1), 2); assert.equal(cose.get(3), -7); assert.equal(cose.get(-1), 1);
  assert.equal(cose.get(-2).length, 32); assert.equal(cose.get(-3).length, 32);
});

test('getAssertion produit une signature DER valide, vérifiable avec la clé publique', async () => {
  const challenge1 = nodeCrypto.randomBytes(32);
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(challenge1) });

  // Reconstruire la clé publique (x,y du COSE) en KeyObject Node
  const att = cborDecode(b64urlDecode(cred.attestationObjectB64u));
  const authData = att.get('authData');
  const credIdLen = (authData[53] << 8) | authData[54];
  const cose = cborDecode(authData.slice(55 + credIdLen));
  const x = Buffer.from(cose.get(-2)).toString('base64url');
  const y = Buffer.from(cose.get(-3)).toString('base64url');
  const pub = nodeCrypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x, y }, format: 'jwk' });

  // Authentification
  const challenge2 = nodeCrypto.randomBytes(32);
  const asrt = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(challenge2), privateKeyJwk: cred.privateKeyJwk, credentialId: cred.credentialId, signCount: 0 });

  assert.equal(asrt.signCount, 1, 'compteur incrémenté');
  const authData2 = b64urlDecode(asrt.authenticatorDataB64u);
  const clientDataHash = await sha256(b64urlDecode(asrt.clientDataJSONB64u));
  const signed = concat(authData2, clientDataHash);
  const derSig = b64urlDecode(asrt.signatureB64u);

  // Vérification DER + signature avec la clé publique du COSE
  const ok = nodeCrypto.verify('sha256', Buffer.from(signed), { key: pub, dsaEncoding: 'der' }, Buffer.from(derSig));
  assert.equal(ok, true, 'la signature DER est valide pour la clé publique');

  // authData de l'assertion : rpIdHash | flags(UP, PAS AT, PAS UV sans vérification) | signCount
  const rpIdHash = await sha256(strToBytes(RP_ID));
  assert.deepEqual(authData2.slice(0, 32), rpIdHash);
  assert.equal(authData2[32] & 0x40, 0, 'pas de flag AT en assertion');
  assert.equal(authData2[32], 0x01, 'flag UP seul (aucune vérification de l\'utilisateur)');
  assert.equal(((authData2[33] << 24) | (authData2[34] << 16) | (authData2[35] << 8) | authData2[36]) >>> 0, 1);
});

// Moteur seul : UV n'est posé que si l'appelant l'atteste. Le pont l'atteste pour toute cérémonie servie
// depuis le coffre déverrouillé (décision produit, voir test/passkey/webauthn-flow.test.js)
test('PASSKEYS-22 : drapeau UV uniquement si l\'appelant atteste la vérification (userVerified: true)', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32) });
  assert.equal(cborDecode(b64urlDecode(cred.attestationObjectB64u)).get('authData')[32], 0x41, 'création sans vérification : UP | AT');
  const verified = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), userVerified: true });
  assert.equal(cborDecode(b64urlDecode(verified.attestationObjectB64u)).get('authData')[32], 0x45, 'création vérifiée : UP | UV | AT');
  const a1 = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: cred.privateKeyJwk, credentialId: cred.credentialId });
  assert.equal(b64urlDecode(a1.authenticatorDataB64u)[32], 0x01);
  const a2 = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: cred.privateKeyJwk, credentialId: cred.credentialId, userVerified: true });
  assert.equal(b64urlDecode(a2.authenticatorDataB64u)[32], 0x05);
  // Valeur « truthy » autre que true : pas de UV
  const a3 = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: cred.privateKeyJwk, credentialId: cred.credentialId, userVerified: 'yes' });
  assert.equal(b64urlDecode(a3.authenticatorDataB64u)[32], 0x01);
});

test('PASSKEYS-23 : createCredential renvoie authData et clé publique SPKI cohérents avec l\'attestation', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), attestation: 'direct' });
  const authData = cborDecode(b64urlDecode(cred.attestationObjectB64u)).get('authData');
  assert.deepEqual(b64urlDecode(cred.authenticatorDataB64u), authData);
  const jwk = nodeCrypto.createPublicKey({ key: Buffer.from(b64urlDecode(cred.publicKeySpkiB64u)), format: 'der', type: 'spki' }).export({ format: 'jwk' });
  assert.equal(jwk.x, cred.publicKeyJwk.x); assert.equal(jwk.y, cred.publicKeyJwk.y);
});

test('PASSKEYS-20 : clientDataJSON — crossOrigin/topOrigin repris du contexte, topOrigin jamais sans crossOrigin', async () => {
  const cd = (r) => JSON.parse(new TextDecoder().decode(b64urlDecode(r.clientDataJSONB64u)));
  const c0 = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(4) });
  assert.deepEqual(Object.keys(cd(c0)), ['type', 'challenge', 'origin', 'crossOrigin']);
  assert.equal(cd(c0).crossOrigin, false);
  const c1 = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(4), crossOrigin: true, topOrigin: 'https://top.example' });
  assert.deepEqual(cd(c1), { type: 'webauthn.create', challenge: 'AAAAAA', origin: ORIGIN, crossOrigin: true, topOrigin: 'https://top.example' });
  const a = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(4), privateKeyJwk: c0.privateKeyJwk, credentialId: c0.credentialId, crossOrigin: false, topOrigin: 'https://top.example' });
  assert.deepEqual(cd(a), { type: 'webauthn.get', challenge: 'AAAAAA', origin: ORIGIN, crossOrigin: false });
});

test('attestation "packed" (self) : signature de l\'attestation valide', async () => {
  const challenge = nodeCrypto.randomBytes(32);
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(challenge), attestation: 'direct' });

  const att = cborDecode(b64urlDecode(cred.attestationObjectB64u));
  assert.equal(att.get('fmt'), 'packed', 'format packed pour une attestation demandée');
  const attStmt = att.get('attStmt');
  assert.equal(attStmt.get('alg'), -7, 'alg ES256');
  const sig = attStmt.get('sig');
  assert.ok(sig && sig.length > 8, 'signature présente');
  assert.equal(attStmt.has('x5c'), false, 'auto-attestation : pas de chaîne de certificats');

  // La signature de l'attestation = sign(authData || clientDataHash) avec la clé de la passkey
  const authData = att.get('authData');
  const credIdLen = (authData[53] << 8) | authData[54];
  const cose = cborDecode(authData.slice(55 + credIdLen));
  const pub = nodeCrypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: Buffer.from(cose.get(-2)).toString('base64url'), y: Buffer.from(cose.get(-3)).toString('base64url') }, format: 'jwk' });
  const clientDataHash = await sha256(b64urlDecode(cred.clientDataJSONB64u));
  const ok = nodeCrypto.verify('sha256', Buffer.from(concat(authData, clientDataHash)), { key: pub, dsaEncoding: 'der' }, Buffer.from(sig));
  assert.equal(ok, true, 'la signature d\'auto-attestation est valide');

  // AAGUID propre à RDVAULT (une auto-attestation sans x5c ne contraint pas l'AAGUID)
  const aaguid = Buffer.from(authData.slice(37, 53)).toString('hex');
  assert.equal(aaguid, core.AAGUID_HEX, 'AAGUID RDVAULT');
  assert.equal(aaguid, '1c80936c3d174ec8acaf40e1e6a081cd');
});

test('Drapeaux de sauvegarde BE/BS : seulement sur demande (backupEligible: true), à la création comme à l\'assertion', async () => {
  const plain = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32) });
  assert.equal(cborDecode(b64urlDecode(plain.attestationObjectB64u)).get('authData')[32] & 0x18, 0, 'sans demande : ni BE ni BS');
  assert.equal(plain.backupEligible, false);
  const synced = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), backupEligible: true });
  assert.equal(cborDecode(b64urlDecode(synced.attestationObjectB64u)).get('authData')[32], 0x59, 'UP | BE | BS | AT');
  assert.equal(synced.backupEligible, true);
  const a1 = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: synced.privateKeyJwk, credentialId: synced.credentialId, backupEligible: true });
  assert.equal(b64urlDecode(a1.authenticatorDataB64u)[32], 0x19, 'assertion : UP | BE | BS');
  const a2 = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: plain.privateKeyJwk, credentialId: plain.credentialId });
  assert.equal(b64urlDecode(a2.authenticatorDataB64u)[32], 0x01, 'passkey sans BE : UP seul');
});

test('attestation "none" par défaut (format none)', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32) });
  assert.equal(cborDecode(b64urlDecode(cred.attestationObjectB64u)).get('fmt'), 'none');
});

test('signCount s\'incrémente de façon monotone sur des assertions chaînées', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32) });
  let signCount = 0;
  for (let expected = 1; expected <= 3; expected++) {
    const asrt = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: cred.privateKeyJwk, credentialId: cred.credentialId, signCount });
    assert.equal(asrt.signCount, expected, 'compteur monotone');
    signCount = asrt.signCount;
  }
});

test('défi vide (0 octet) : credential produit, challenge vide dans clientDataJSON', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: new Uint8Array(0) });
  const cdj = JSON.parse(new TextDecoder().decode(b64urlDecode(cred.clientDataJSONB64u)));
  assert.equal(cdj.type, 'webauthn.create');
  assert.equal(cdj.challenge, '', 'challenge b64url vide');
});

test('attestation "enterprise" demandée → format packed (auto-attestation)', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), attestation: 'enterprise' });
  assert.equal(cborDecode(b64urlDecode(cred.attestationObjectB64u)).get('fmt'), 'packed');
});

test('getAssertion rejette une clé privée malformée (pas de crash silencieux)', async () => {
  await assert.rejects(() => core.getAssertion({
    rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32),
    privateKeyJwk: { kty: 'EC', crv: 'P-256', x: 'bad', y: 'bad', d: 'bad' }, credentialId: 'abc',
  }));
});

// ---------------------------------------------------------------------------
// Harnais : passkey-inject.js (monde MAIN) et passkey-bridge.js (monde isolé) exécutés
// dans Node avec un window / navigator / chrome simulés. Permet de vérifier ce que l'un
// transmet à l'autre (postMessage) et ce que le pont demande au service worker.
// ---------------------------------------------------------------------------
const fs = require('node:fs');
const EXT_DIR = path.resolve(__dirname, '..', '..', 'chrome-extension/vault-autofill-extension');
const CHANNEL = 'rdvault-passkey';
const b64u = (u8) => Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString('base64url');

function loadInject(hostname = 'site-a.com') {
  const src = fs.readFileSync(path.join(EXT_DIR, 'passkey-inject.js'), 'utf8');
  const posted = []; const listeners = []; const native = { create: [], get: [] };
  const location = { origin: 'https://' + hostname, hostname };
  const navigator = { credentials: {
    create: async (o) => { native.create.push(o); return { native: true }; },
    get: async (o) => { native.get.push(o); return { native: true }; }
  } };
  const win = { PublicKeyCredential: function () {}, location, postMessage: (m) => posted.push(m),
    addEventListener: (t, fn) => { if (t === 'message') listeners.push(fn); } };
  // eslint-disable-next-line no-new-func -- script réel de l'extension exécuté avec un window simulé
  new Function('window', 'navigator', 'location', src)(win, navigator, location);
  // Réponse du pont à la dernière requête (évite le minuteur de 120 s en suspens)
  const reply = (result) => { const m = posted[posted.length - 1]; listeners.forEach(fn => fn({ source: win, data: { source: CHANNEL, dir: 'res', id: m.id, ok: true, result } })); };
  return { navigator, posted, native, reply };
}

// ancestors : location.ancestorOrigins de la frame (undefined = API absente)
function loadBridge({ hostname = 'site-a.com', top = true, policy = null, swReply = null, ancestors } = {}) {
  const src = fs.readFileSync(path.join(EXT_DIR, 'passkey-bridge.js'), 'utf8');
  const listeners = []; const sent = []; const waiters = new Map();
  const location = { origin: 'https://' + hostname, hostname };
  if (ancestors !== undefined) location.ancestorOrigins = ancestors;
  const win = { location, isSecureContext: true,
    postMessage: (m) => { const w = waiters.get(m.id); if (w) { waiters.delete(m.id); w(m); } },
    addEventListener: (t, fn) => { if (t === 'message') listeners.push(fn); } };
  win.top = top ? win : {};
  const document = { featurePolicy: policy ? { allowsFeature: (f) => policy[f] === true } : undefined };
  const chrome = { runtime: { sendMessage: async (m) => { sent.push(m); return swReply ? swReply(m) : { success: true, passkeys: [] }; } } };
  // eslint-disable-next-line no-new-func -- script réel de l'extension exécuté avec un window simulé
  new Function('window', 'document', 'chrome', 'globalThis', src)(win, document, chrome, { RDVaultPasskeyCore: core });
  let seq = 0;
  const request = (op, data) => new Promise((resolve, reject) => {
    const id = 't' + (++seq);
    const to = setTimeout(() => { waiters.delete(id); reject(new Error('pas de réponse du pont')); }, 2000);
    waiters.set(id, (m) => { clearTimeout(to); resolve(m); });
    listeners.forEach(fn => fn({ source: win, data: { source: CHANNEL, dir: 'req', id, op, data } }));
  });
  return { request, sent };
}

test('inject : challenge / allowCredentials / user.id en sous-vue typée → seuls les octets de la vue sont transmis', async () => {
  const h = loadInject();
  const big = Uint8Array.from({ length: 64 }, (_, i) => i);
  const challenge = big.subarray(8, 40);                       // vue décalée (32 octets sur 64)
  const credId = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
  const pool = new Uint8Array(48); pool.set(credId, 8);
  const idView = new Uint8Array(pool.buffer, 8, 16);           // id d'allowCredentials en vue décalée
  const pGet = h.navigator.credentials.get({ publicKey: { challenge, allowCredentials: [{ type: 'public-key', id: idView }] } });
  const req = h.posted[h.posted.length - 1];
  assert.equal(req.data.challenge, b64u(challenge), 'challenge = octets de la vue uniquement');
  assert.deepEqual(req.data.allowCredentials, [b64u(credId)], 'credentialId retrouvable par le pont');
  h.reply({ fallback: true }); await pGet;

  const userBuf = new Uint8Array(32); userBuf.set(Buffer.from('user-123'), 4);
  const userId = new DataView(userBuf.buffer, 4, 8);           // DataView décalée
  const pCreate = h.navigator.credentials.create({ publicKey: { challenge, rp: { id: 'site-a.com' }, user: { id: userId, name: 'a', displayName: 'A' } } });
  const reqC = h.posted[h.posted.length - 1];
  assert.equal(reqC.data.challenge, b64u(challenge));
  assert.equal(reqC.data.userId, Buffer.from('user-123').toString('base64url'), 'user.id = octets de la vue uniquement');
  h.reply({ fallback: true }); await pCreate;
});

test('inject : médiation « conditional » laissée au navigateur (aucune fenêtre RDVAULT)', async () => {
  const h = loadInject();
  const challenge = new Uint8Array(32);
  const n0 = h.posted.length;
  const r = await h.navigator.credentials.get({ mediation: 'conditional', publicKey: { challenge } });
  assert.deepEqual(r, { native: true }, 'get conditionnel → authentificateur natif');
  const rc = await h.navigator.credentials.create({ mediation: 'conditional', publicKey: { challenge, rp: { id: 'site-a.com' }, user: { id: new Uint8Array(4), name: 'a', displayName: 'A' } } });
  assert.deepEqual(rc, { native: true }, 'create conditionnel → authentificateur natif');
  assert.equal(h.posted.length, n0, 'aucune requête relayée au pont');
  assert.equal(h.native.get.length, 1); assert.equal(h.native.create.length, 1);
});

test('pont : rp.id suffixe public (com, co.uk, github.io, IP partielle) refusé → navigateur, coffre jamais interrogé', async () => {
  for (const [hostname, rpId] of [['site-a.com', 'com'], ['bank.co.uk', 'co.uk'], ['alice.github.io', 'github.io'], ['192.168.1.10', '1.10'], ['shop.example.com.au', 'com.au']]) {
    const b = loadBridge({ hostname });
    const m = await b.request('get', { rpId, challenge: 'AAAA', allowCredentials: [] });
    assert.equal(m.ok, true, hostname + ' / ' + rpId);
    assert.deepEqual(m.result, { fallback: true }, hostname + ' / ' + rpId + ' → fallback');
    assert.equal(b.sent.length, 0, hostname + ' / ' + rpId + ' : aucune requête au coffre');
  }
});

test('pont : rp.id domaine enregistrable (égal ou parent) accepté', async () => {
  for (const [hostname, rpId] of [['login.example.com', 'example.com'], ['localhost', 'localhost'], ['www.example.co.uk', 'example.co.uk'], ['alice.github.io', 'alice.github.io'], ['site-a.com', undefined]]) {
    const b = loadBridge({ hostname });
    const m = await b.request('get', { rpId, challenge: 'AAAA', allowCredentials: [] });
    assert.deepEqual(m.result, { fallback: true }, 'aucune passkey dans le coffre simulé');
    assert.equal(b.sent.length, 1, hostname + ' / ' + rpId);
    assert.equal(b.sent[0].type, 'PASSKEY_LIST');
    assert.equal(b.sent[0].rpId, rpId || hostname);
  }
});

test('pont : iframe sans délégation Permissions-Policy → navigateur (pas de fenêtre RDVAULT, coffre non interrogé)', async () => {
  const deny = { 'publickey-credentials-create': false, 'publickey-credentials-get': false };
  let b = loadBridge({ hostname: 'site-a.com', top: false, policy: deny });
  let m = await b.request('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [] });
  assert.deepEqual(m.result, { fallback: true }); assert.equal(b.sent.length, 0);
  m = await b.request('create', { rpId: 'site-a.com', challenge: 'AAAA', userName: 'a' });
  assert.equal(m.ok, true, 'create : fallback sans afficher la fenêtre (' + m.error + ')');
  assert.deepEqual(m.result, { fallback: true }); assert.equal(b.sent.length, 0);

  // API Permissions-Policy absente : prudence, fallback également
  b = loadBridge({ hostname: 'site-a.com', top: false, policy: null });
  m = await b.request('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [] });
  assert.deepEqual(m.result, { fallback: true }); assert.equal(b.sent.length, 0);

  // Délégation explicite (allow="publickey-credentials-get") : RDVAULT consulte le coffre
  b = loadBridge({ hostname: 'site-a.com', top: false, policy: { 'publickey-credentials-get': true }, ancestors: ['https://embedder.example'] });
  m = await b.request('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [] });
  assert.equal(b.sent.length, 1); assert.equal(b.sent[0].type, 'PASSKEY_LIST');

  // Délégation mais ancêtres inconnus (crossOrigin / topOrigin impossibles à établir) : navigateur
  b = loadBridge({ hostname: 'site-a.com', top: false, policy: { 'publickey-credentials-get': true } });
  m = await b.request('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [] });
  assert.deepEqual(m.result, { fallback: true }); assert.equal(b.sent.length, 0);
});

test('une signature pour un autre défi ne valide pas (anti-rejeu)', async () => {
  const cred = await core.createCredential({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32) });
  const att = cborDecode(b64urlDecode(cred.attestationObjectB64u));
  const authData = att.get('authData');
  const credIdLen = (authData[53] << 8) | authData[54];
  const cose = cborDecode(authData.slice(55 + credIdLen));
  const pub = nodeCrypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: Buffer.from(cose.get(-2)).toString('base64url'), y: Buffer.from(cose.get(-3)).toString('base64url') }, format: 'jwk' });

  const asrt = await core.getAssertion({ rpId: RP_ID, origin: ORIGIN, challenge: nodeCrypto.randomBytes(32), privateKeyJwk: cred.privateKeyJwk, credentialId: cred.credentialId });
  const authData2 = b64urlDecode(asrt.authenticatorDataB64u);
  const wrongHash = await sha256(strToBytes('mauvais clientData'));
  const ok = nodeCrypto.verify('sha256', Buffer.from(concat(authData2, wrongHash)), { key: pub, dsaEncoding: 'der' }, Buffer.from(b64urlDecode(asrt.signatureB64u)));
  assert.equal(ok, false);
});
