// ========================================
// PASSKEY CORE — Authentificateur logiciel FIDO2 / WebAuthn (ES256)
// ========================================
// Génère des passkeys (paires de clés P-256), construit les objets d'attestation
// (création) et d'assertion (authentification) conformes à la spécification WebAuthn.
// N'utilise que WebCrypto (globalThis.crypto.subtle) : fonctionne en Node (test) et
// dans le navigateur (monde MAIN de la page, injecté par l'extension).
//
// Réimplémentation indépendante de la spec W3C WebAuthn / CTAP2 — aucun code tiers copié.
//
// Format : attestation "none" (pas d'attestation matérielle), algorithme ES256 (-7),
// AAGUID propre à RDVAULT (RDVAULT_AAGUID). L'ancien AAGUID nul faisait passer les passkeys
// RDVAULT pour des passkeys Apple (« Trousseau iCloud » chez Google), dont les premières
// versions utilisaient aussi un AAGUID nul. Les passkeys déjà créées gardent leur AAGUID d'origine
// (l'AAGUID n'apparaît qu'à la création).

/* global globalThis */ // objet global ES2020 (navigateur et Node)
(function (root, factory) {
  const mod = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = mod; // Node (tests)
  root.RDVaultPasskeyCore = mod;                                            // Navigateur
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict'; // eslint-disable-line strict -- script classique (monde de l'extension, Node), pas un module ES

  const subtle = globalThis.crypto.subtle;

  // ---------- Encodage ----------
  function strToBytes(s) { return new TextEncoder().encode(s); }
  function concat(...arrs) {
    let len = 0; for (const a of arrs) len += a.length;
    const out = new Uint8Array(len); let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  function b64urlEncode(bytes) {
    let s = ''; const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDecode(str) {
    const s = String(str).replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(str.length / 4) * 4, '=');
    const bin = atob(s); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toBytes(v) {
    if (v == null) return new Uint8Array(0);
    if (v instanceof Uint8Array) return v;
    if (v instanceof ArrayBuffer) return new Uint8Array(v);
    if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    if (typeof v === 'string') return b64urlDecode(v); // les challenges/ids arrivent souvent en base64url
    if (Array.isArray(v)) return new Uint8Array(v);
    return new Uint8Array(v);
  }

  // ---------- CBOR minimal (sous-ensemble requis par WebAuthn) ----------
  function cborHead(major, n) {
    if (n < 24) return new Uint8Array([(major << 5) | n]);
    if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
    if (n < 65536) return new Uint8Array([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
    return new Uint8Array([(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
  }
  function cborEncode(value) {
    if (typeof value === 'number' && Number.isInteger(value)) {
      return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    }
    if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
    if (typeof value === 'string') { const b = strToBytes(value); return concat(cborHead(3, b.length), b); }
    if (value instanceof Map) {
      const parts = [cborHead(5, value.size)];
      for (const [k, v] of value) { parts.push(cborEncode(k)); parts.push(cborEncode(v)); }
      return concat(...parts);
    }
    throw new Error('CBOR: type non supporté');
  }

  // ---------- Signature : brut (P1363 r||s, 64o) → DER ASN.1 (exigé par WebAuthn ES256) ----------
  function rawSignatureToDer(raw) {
    const r = raw.slice(0, 32), s = raw.slice(32, 64);
    const trim = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; let x = b.slice(i); if (x[0] & 0x80) x = concat(new Uint8Array([0]), x); return x; };
    const R = trim(r), S = trim(s);
    const seqLen = 2 + R.length + 2 + S.length;
    return concat(new Uint8Array([0x30, seqLen, 0x02, R.length]), R, new Uint8Array([0x02, S.length]), S);
  }

  async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }

  // ---------- COSE public key (ES256) ----------
  function coseKeyFromXY(x, y) {
    return cborEncode(new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
    //                        kty:EC2  alg:ES256 crv:P-256  x       y
  }

  function buildAuthData(rpIdHash, flags, signCount, attestedCredData) {
    const sc = new Uint8Array([(signCount >>> 24) & 0xff, (signCount >> 16) & 0xff, (signCount >> 8) & 0xff, signCount & 0xff]);
    return attestedCredData ? concat(rpIdHash, new Uint8Array([flags]), sc, attestedCredData)
      : concat(rpIdHash, new Uint8Array([flags]), sc);
  }

  const FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_BE = 0x08, FLAG_BS = 0x10, FLAG_AT = 0x40;
  // AAGUID RDVAULT : 1c80936c-3d17-4ec8-acaf-40e1e6a081cd (identifiant de fabricant de l'authentificateur)
  const RDVAULT_AAGUID_HEX = '1c80936c3d174ec8acaf40e1e6a081cd';
  const AAGUID = new Uint8Array(RDVAULT_AAGUID_HEX.match(/../g).map((h) => parseInt(h, 16)));

  // Drapeaux de sauvegarde (WebAuthn §6.1.3) : BE = passkey « synchronisable », BS = sauvegardée.
  // Une passkey RDVAULT vit dans le coffre (sauvegardé et synchronisé avec lui), pas dans ce poste :
  // c'est la déclaration des gestionnaires de passkeys du marché. BE est FIGÉ pour toute la vie
  // de la passkey (un site peut refuser une assertion dont BE diffère de l'enregistrement) :
  // il n'est posé que si l'appelant le demande (p.backupEligible === true) — le pont le demande
  // pour les nouvelles passkeys et le mémorise ; les passkeys créées sans BE restent sans BE.
  const backupFlags = (p) => (p && p.backupEligible === true ? FLAG_BE | FLAG_BS : 0);

  // Drapeaux de l'authenticatorData. UV (« utilisateur vérifié » : PIN, biométrie, mot de passe)
  // n'est posé que si l'appelant atteste qu'une vérification a eu lieu (p.userVerified === true) ;
  // sans cette attestation, présence (UP) seule. Le pont (passkey-bridge.js) l'atteste parce qu'il ne
  // sert une passkey que depuis le coffre DÉVERROUILLÉ par le mot de passe maître (décision produit).
  const ceremonyFlags = (p) => FLAG_UP | (p && p.userVerified === true ? FLAG_UV : 0);

  // clientDataJSON (WebAuthn §5.8.1) : type, challenge, origin, crossOrigin puis topOrigin
  // (présent uniquement pour une cérémonie dans une iframe d'une autre origine que ses ancêtres)
  function clientDataJson(type, challenge, p) {
    const cd = { type, challenge: b64urlEncode(challenge), origin: p.origin, crossOrigin: p.crossOrigin === true };
    if (cd.crossOrigin && typeof p.topOrigin === 'string' && p.topOrigin) cd.topOrigin = p.topOrigin;
    return JSON.stringify(cd);
  }

  /**
   * Création d'une passkey (navigator.credentials.create).
   * @param {Object} p - { rpId, origin, challenge, userId, userName, attestation?, crossOrigin?, topOrigin?, userVerified? }
   *   crossOrigin / topOrigin : contexte de l'appel (iframe d'une autre origine), repris dans clientDataJSON
   *   userVerified : true seulement si l'utilisateur a été vérifié (drapeau UV ; coffre déverrouillé)
   *   attestation : 'none' (défaut) → attestation « none » ; 'direct'/'enterprise'/'indirect'
   *   → auto-attestation « packed » (signée par la clé de la passkey). L'auto-attestation
   *   prouve la possession de la clé mais PAS la provenance : les sites qui vérifient une
   *   chaîne de certificats fabricant (AAGUID connu) la refuseront quand même. Elle améliore
   *   la compatibilité avec les sites qui demandent une attestation mais acceptent « self ».
   * @returns {Promise<Object>} { credentialId(b64url), attestationObjectB64u, clientDataJSONB64u, authenticatorDataB64u,
   *   publicKeySpkiB64u, privateKeyJwk, publicKeyJwk, rpId, signCount }
   */
  async function createCredential(p) {
    const challenge = toBytes(p.challenge);
    const clientData = clientDataJson('webauthn.create', challenge, p);
    const clientDataBytes = strToBytes(clientData);
    const clientDataHash = await sha256(clientDataBytes);

    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pubRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey)); // 0x04 || x(32) || y(32)
    const x = pubRaw.slice(1, 33), y = pubRaw.slice(33, 65);
    const privateKeyJwk = await subtle.exportKey('jwk', kp.privateKey);
    const publicKeyJwk = await subtle.exportKey('jwk', kp.publicKey);
    // Clé publique SubjectPublicKeyInfo (DER) : AuthenticatorAttestationResponse.getPublicKey()
    const publicKeySpki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));

    const credentialId = new Uint8Array(16); globalThis.crypto.getRandomValues(credentialId);
    const rpIdHash = await sha256(strToBytes(p.rpId));
    const cose = coseKeyFromXY(x, y);
    const credIdLen = new Uint8Array([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]);
    const attestedCredData = concat(AAGUID, credIdLen, credentialId, cose);
    const authData = buildAuthData(rpIdHash, ceremonyFlags(p) | backupFlags(p) | FLAG_AT, 0, attestedCredData);

    // Format d'attestation selon la préférence demandée par le site
    const wantsAttestation = ['direct', 'enterprise', 'indirect'].includes(String(p.attestation || 'none'));
    let attestationObject;
    if (wantsAttestation) {
      // Auto-attestation « packed » : signature de (authData || clientDataHash) par la clé de la passkey,
      // alg ES256 (-7), sans x5c (pas de chaîne de certificats ; l'AAGUID n'est contraint qu'avec x5c).
      const rawSig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, concat(authData, clientDataHash)));
      const attStmt = new Map([['alg', -7], ['sig', rawSignatureToDer(rawSig)]]);
      attestationObject = cborEncode(new Map([['fmt', 'packed'], ['attStmt', attStmt], ['authData', authData]]));
    } else {
      attestationObject = cborEncode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    }

    return {
      credentialId: b64urlEncode(credentialId),
      attestationObjectB64u: b64urlEncode(attestationObject),
      clientDataJSONB64u: b64urlEncode(clientDataBytes),
      authenticatorDataB64u: b64urlEncode(authData),
      publicKeySpkiB64u: b64urlEncode(publicKeySpki),
      privateKeyJwk, publicKeyJwk, rpId: p.rpId, signCount: 0,
      backupEligible: p.backupEligible === true, // à mémoriser avec la passkey (BE figé, voir backupFlags)
    };
  }

  /**
   * Assertion (navigator.credentials.get) : signe le défi avec la clé privée stockée.
   * @param {Object} p - { rpId, origin, challenge, privateKeyJwk, credentialId(b64url), signCount?, userHandle?,
   *   crossOrigin?, topOrigin?, userVerified? } ; le compteur signé vaut signCount + 1
   * @returns {Promise<Object>} { authenticatorDataB64u, clientDataJSONB64u, signatureB64u, userHandleB64u, credentialId, signCount }
   */
  async function getAssertion(p) {
    const challenge = toBytes(p.challenge);
    const clientData = clientDataJson('webauthn.get', challenge, p);
    const clientDataBytes = strToBytes(clientData);
    const clientDataHash = await sha256(clientDataBytes);

    const rpIdHash = await sha256(strToBytes(p.rpId));
    const signCount = (p.signCount || 0) + 1;
    const authData = buildAuthData(rpIdHash, ceremonyFlags(p) | backupFlags(p), signCount);

    const priv = await subtle.importKey('jwk', p.privateKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const rawSig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, concat(authData, clientDataHash)));
    const der = rawSignatureToDer(rawSig);

    return {
      credentialId: p.credentialId,
      authenticatorDataB64u: b64urlEncode(authData),
      clientDataJSONB64u: b64urlEncode(clientDataBytes),
      signatureB64u: b64urlEncode(der),
      userHandleB64u: p.userHandle ? b64urlEncode(toBytes(p.userHandle)) : null,
      signCount,
    };
  }

  return {
    createCredential, getAssertion,
    AAGUID_HEX: RDVAULT_AAGUID_HEX,
    _internal: { cborEncode, rawSignatureToDer, b64urlEncode, b64urlDecode, toBytes, sha256, coseKeyFromXY, buildAuthData, concat, strToBytes },
  };
});
