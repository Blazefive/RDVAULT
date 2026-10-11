// ========================================
// PASSKEY INJECT — Monde MAIN (contexte de la page)
// ========================================
// Remplace navigator.credentials.create / get pour proposer les passkeys de RDVAULT.
// Ne fait AUCUNE cryptographie et ne voit JAMAIS de clé privée : il relaie la requête
// au pont (monde isolé) via postMessage, reçoit les éléments publics (attestation /
// assertion en base64url) et reconstruit l'objet PublicKeyCredential attendu par la page.
// Si RDVAULT n'a pas de passkey ou si l'utilisateur annule, on retombe sur
// l'authentificateur natif du navigateur (comportement transparent).

(function () {
  'use strict'; // eslint-disable-line strict -- script classique (monde MAIN de la page), pas un module ES
  if (!window.PublicKeyCredential || !navigator.credentials) return;
  if (window.__rdvaultPasskeyInjected) return;
  window.__rdvaultPasskeyInjected = true;

  const CHANNEL = 'rdvault-passkey';
  const origCreate = navigator.credentials.create.bind(navigator.credentials);
  const origGet = navigator.credentials.get.bind(navigator.credentials);

  let seq = 0;
  const pending = new Map();
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const m = event.data;
    if (!m || m.source !== CHANNEL || m.dir !== 'res') return;
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    m.ok ? p.resolve(m.result) : p.reject(new Error(m.error || 'erreur'));
  }, false);

  function ask(op, data, timeoutMs) {
    return new Promise((resolve, reject) => {
      const id = 'pk' + (++seq);
      pending.set(id, { resolve, reject });
      const to = setTimeout(() => { if (pending.delete(id)) reject(new Error('timeout')); }, timeoutMs);
      const wrap = (fn) => (v) => { clearTimeout(to); fn(v); };
      pending.set(id, { resolve: wrap(resolve), reject: wrap(reject) });
      window.postMessage({ source: CHANNEL, dir: 'req', id, op, data }, window.location.origin === 'null' ? '*' : window.location.origin);
    });
  }

  // ---------- base64url → ArrayBuffer ----------
  function b64uToBuf(s) {
    const t = String(s).replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
    const bin = atob(t); const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u.buffer;
  }
  function bufToB64u(buf) {
    const u = new Uint8Array(buf); let s = '';
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function toB64u(v) {
    if (v == null) return '';
    if (typeof v === 'string') return v; // déjà base64url (rare)
    // Vue typée (subarray, DataView, Buffer poolé…) : uniquement SES octets, pas tout le buffer sous-jacent
    return bufToB64u(v instanceof ArrayBuffer ? v : (ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : v));
  }

  function notAllowed() {
    return new DOMException('The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.', 'NotAllowedError');
  }
  // excludeCredentials : une passkey de ce compte existe déjà dans RDVAULT (erreur standard WebAuthn)
  function invalidState() {
    return new DOMException('The user attempted to register an authenticator that contains one of the credentials already registered with the relying party.', 'InvalidStateError');
  }

  // Transports d'une passkey RDVAULT : authentificateur logiciel de ce poste (pas de « hybrid »)
  const TRANSPORTS = ['internal'];

  // Médiation « conditional » (autofill / mise à niveau automatique) : WebAuthn interdit toute
  // UI modale ; RDVAULT ne s'intègre pas à l'autofill natif → le navigateur gère seul.
  const isConditional = (options) => !!options && options.mediation === 'conditional';

  navigator.credentials.create = async function (options) {
    if (!options || !options.publicKey || isConditional(options)) return origCreate(options);
    let res;
    try {
      const pk = options.publicKey;
      const rpId = (pk.rp && pk.rp.id) || window.location.hostname;
      const params = Array.isArray(pk.pubKeyCredParams) ? pk.pubKeyCredParams : [];
      res = await ask('create', {
        rpId,
        challenge: toB64u(pk.challenge),
        userId: pk.user ? toB64u(pk.user.id) : '',
        userName: pk.user ? pk.user.name : '',
        userDisplayName: pk.user ? pk.user.displayName : '',
        attestation: pk.attestation || 'none',
        // Algorithmes acceptés par le site (null = liste absente ou vide : valeurs par défaut)
        algs: params.length ? params.filter(c => c && c.type === 'public-key').map(c => Number(c.alg)) : null,
        // Identifiants déjà enregistrés pour ce compte (le pont refuse d'en créer un doublon)
        excludeCredentials: Array.isArray(pk.excludeCredentials) ? pk.excludeCredentials.filter(c => c && c.id != null).map(c => toB64u(c.id)) : [],
        // Préférence du site, relayée pour information : « required » compris, la cérémonie est servie
        // par RDVAULT avec le drapeau UV (coffre déverrouillé = utilisateur vérifié, voir passkey-bridge.js)
        userVerification: (pk.authenticatorSelection && pk.authenticatorSelection.userVerification) || 'preferred'
      }, 120000);
    } catch (err) {
      if (err && /timeout/.test(err.message)) return origCreate(options);
      if (err && err.message === 'RDVAULT_EXCLUDED') throw invalidState();
      throw notAllowed(); // annulation utilisateur : erreur standard, PAS de bascule native
    }
    if (res && res.fallback) return origCreate(options); // « autre appareil » : authentificateur natif
    try {
      const rawId = b64uToBuf(res.credentialId);
      const attestationObject = b64uToBuf(res.attestationObjectB64u);
      const clientDataJSON = b64uToBuf(res.clientDataJSONB64u);
      const authenticatorData = b64uToBuf(res.authenticatorDataB64u); // authData seul (pas l'attestationObject)
      const publicKey = b64uToBuf(res.publicKeySpkiB64u);             // SubjectPublicKeyInfo DER (ES256)
      return {
        id: res.credentialId, rawId, type: 'public-key', authenticatorAttachment: 'platform',
        response: {
          clientDataJSON, attestationObject,
          getAuthenticatorData: () => authenticatorData.slice(0),
          getPublicKey: () => publicKey.slice(0),
          getPublicKeyAlgorithm: () => -7,
          getTransports: () => TRANSPORTS.slice()
        },
        getClientExtensionResults: () => ({}),
        // RegistrationResponseJSON (WebAuthn niveau 3)
        toJSON: () => ({
          id: res.credentialId, rawId: res.credentialId, type: 'public-key',
          authenticatorAttachment: 'platform', clientExtensionResults: {},
          response: {
            clientDataJSON: res.clientDataJSONB64u, attestationObject: res.attestationObjectB64u,
            authenticatorData: res.authenticatorDataB64u, transports: TRANSPORTS.slice(),
            publicKey: res.publicKeySpkiB64u, publicKeyAlgorithm: -7
          }
        })
      };
    } catch (err) {
      throw notAllowed();
    }
  };

  navigator.credentials.get = async function (options) {
    if (!options || !options.publicKey || isConditional(options)) return origGet(options);
    let res;
    try {
      const pk = options.publicKey;
      const rpId = pk.rpId || window.location.hostname;
      res = await ask('get', {
        rpId,
        challenge: toB64u(pk.challenge),
        allowCredentials: Array.isArray(pk.allowCredentials) ? pk.allowCredentials.map(c => toB64u(c.id)) : [],
        userVerification: pk.userVerification || 'preferred'
      }, 120000);
    } catch (err) {
      if (err && /timeout/.test(err.message)) return origGet(options);
      throw notAllowed();
    }
    if (res && res.fallback) return origGet(options);
    try {
      const rawId = b64uToBuf(res.credentialId);
      return {
        id: res.credentialId, rawId, type: 'public-key', authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: b64uToBuf(res.clientDataJSONB64u),
          authenticatorData: b64uToBuf(res.authenticatorDataB64u),
          signature: b64uToBuf(res.signatureB64u),
          userHandle: res.userHandleB64u ? b64uToBuf(res.userHandleB64u) : null
        },
        getClientExtensionResults: () => ({}),
        // AuthenticationResponseJSON (WebAuthn niveau 3) : userHandle omis s'il est absent
        toJSON: () => {
          const response = { clientDataJSON: res.clientDataJSONB64u, authenticatorData: res.authenticatorDataB64u, signature: res.signatureB64u };
          if (res.userHandleB64u) response.userHandle = res.userHandleB64u;
          return { id: res.credentialId, rawId: res.credentialId, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {}, response };
        }
      };
    } catch (err) {
      throw notAllowed();
    }
  };
})();
