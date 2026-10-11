// ========================================
// PASSKEY BRIDGE — Monde ISOLÉ (a accès à chrome.runtime)
// ========================================
// Reçoit les requêtes WebAuthn relayées par passkey-inject.js (monde de la page),
// fait toute la cryptographie (via passkey-core.js, ici en monde isolé), affiche
// une pop-up de confirmation, stocke/récupère les passkeys via le service worker,
// et renvoie au monde de la page UNIQUEMENT les éléments publics (attestation /
// assertion en base64url). La clé privée ne quitte jamais ce monde isolé.

/* global chrome, globalThis */ // API d'extension et objet global ES2020 (script de contenu, monde isolé)
(function () {
  'use strict'; // eslint-disable-line strict -- script classique injecté par l'extension, pas un module ES
  if (window.__rdvaultPasskeyBridge) return;
  window.__rdvaultPasskeyBridge = true;

  const core = globalThis.RDVaultPasskeyCore;
  const CHANNEL = 'rdvault-passkey';

  function post(res) { window.postMessage(res, window.location.origin === 'null' ? '*' : window.location.origin); }

  // ---------- Traductions (chrome.i18n : _locales/<langue>/messages.json, repli « en ») ----------
  // Langue du navigateur. `fallback` est le texte français d'origine, identique à _locales/fr :
  // il ne sert que hors extension (tests, page simulée) ; $1… y sont remplacés comme par Chrome.
  // Le monde MAIN (passkey-inject.js) n'affiche aucun texte : tout libellé visible est produit ici.
  function msg(key, fallback, subs) {
    const list = subs === undefined ? [] : [].concat(subs).map(String);
    try {
      if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
        const text = chrome.i18n.getMessage(key, list);
        if (text) return text;
      }
    } catch { /* contexte d'extension invalidé : repli */ }
    return fallback.replace(/\$([1-9])/g, (m, n) => (list[n - 1] !== undefined ? list[n - 1] : ''));
  }
  // Langue et sens d'écriture de la fenêtre (arabe : de droite à gauche)
  function uiLang() {
    try { if (typeof chrome !== 'undefined' && chrome.i18n && chrome.i18n.getUILanguage) return chrome.i18n.getUILanguage(); } catch { /* repli */ }
    return 'fr';
  }

  // ---------- Pop-up de choix (shadow root fermé) ----------
  // Retourne 'use' (passkey RDVAULT), 'fallback' (autre appareil / natif) ou 'cancel'.
  // Avec `accounts` (plusieurs passkeys pour un même rpId) : un bouton par compte remplace
  // le bouton unique et l'index (nombre) du compte choisi est retourné à la place de 'use'.
  // Les libellés viennent du coffre (fournis par le site à la création) : toujours injectés
  // en textContent, jamais en HTML.
  //
  // ANTI-CLICKJACKING : la fenêtre vit dans le DOM de la page ; le shadow root fermé protège son
  // contenu mais pas l'hôte, que la page peut rendre invisible (opacity/mask !important), recouvrir
  // (élément pointer-events:none par-dessus) ou rogner, tout en laissant passer le clic réel de
  // l'utilisateur vers un leurre. Les boutons qui SIGNENT ou CRÉENT (.ok, un compte .ac) ne sont
  // donc « armés » que si : clic isTrusted ; boîte vue entièrement visible et non recouverte par
  // IntersectionObserver v2 (trackVisibility) depuis au moins ARM_DELAY_MS (anti double-clic /
  // tapjacking, comme les bulles de permission du navigateur) ; aucun effet masquant sur l'hôte ni
  // sur <html> (mask, clip-path, opacité, filtre : non vus par IOv2) ; et l'hôte est bien l'élément
  // au premier plan au centre du bouton (document.elementFromPoint). « Autre appareil » (UI native
  // du navigateur) et « Annuler » restent sans condition : ils ne produisent aucune signature.
  const ARM_DELAY_MS = 500;
  function confirmDialog({ title, detail, okLabel, accounts }) {
    return new Promise((resolve) => {
      const host = document.createElement('div');
      host.style.cssText = 'all: initial; position: fixed; inset: 0; z-index: 2147483647;';
      const root = host.attachShadow({ mode: 'closed' });
      root.innerHTML = `
        <style>
          .ov{position:fixed;inset:0;background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center;font-family:system-ui,Segoe UI,Arial,sans-serif}
          .bx{background:#fff;color:#0f172a;max-width:380px;width:calc(100% - 40px);max-height:calc(100vh - 80px);overflow:auto;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.35);padding:20px;animation:p .15s ease}
          @keyframes p{from{transform:scale(.96);opacity:.6}to{transform:none;opacity:1}}
          .hd{display:flex;align-items:center;gap:10px;margin-bottom:10px}
          .lg{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px}
          .ti{font-weight:650;font-size:15px}
          .dt{font-size:13px;color:#475569;line-height:1.5;margin:0 0 16px;word-break:break-word}
          .bt{display:flex;flex-direction:column;gap:8px}
          button{font:inherit;font-size:13px;padding:10px 16px;border-radius:9px;border:1px solid transparent;cursor:pointer;text-align:center}
          .ok{background:#6d28d9;color:#fff;font-weight:600}
          .ac{background:#6d28d9;color:#fff;font-weight:600;text-align:start;display:flex;flex-direction:column;gap:2px}
          .ac small{font-weight:400;font-size:11px;opacity:.85}
          .fb{background:#f1f5f9;color:#334155}
          .ca{background:transparent;color:#64748b;padding:4px}
          .wn{font-size:12px;color:#b45309;background:#fffbeb;border-radius:8px;padding:8px 10px;margin:0 0 12px;line-height:1.4}
          .wn[hidden]{display:none}
        </style>
        <div class="ov"><div class="bx" role="dialog" aria-modal="true">
          <div class="hd"><div class="lg">V</div><div class="ti">RDVAULT</div></div>
          <p class="dt"></p>
          <p class="wn" role="alert" hidden></p>
          <div class="bt">
            <button class="ok" type="button"></button>
            <button class="fb" type="button"></button>
            <button class="ca" type="button"></button>
          </div>
        </div></div>`;
      // Libellés traduits, toujours injectés en textContent
      const ov = root.querySelector('.ov');
      ov.setAttribute('lang', uiLang());
      ov.setAttribute('dir', msg('@@bidi_dir', 'ltr'));
      const otherLabel = msg('pkUseAnotherDevice', 'Utiliser un autre appareil');
      const cancelLabel = msg('pkCancel', 'Annuler');
      root.querySelector('.fb').textContent = otherLabel;
      root.querySelector('.ca').textContent = cancelLabel;
      root.querySelector('.wn').textContent = msg('pkBlockedWarning',
        'Action bloquée : la fenêtre RDVAULT est masquée ou recouverte par la page. Utilisez « $1 » ou « $2 ».', [otherLabel, cancelLabel]);
      root.querySelector('.dt').textContent = title + (detail ? ' — ' + detail : '');
      root.querySelector('.ok').textContent = okLabel;
      const mount = document.documentElement || document.body;
      const box = root.querySelector('.bx');
      const shownAt = performance.now();
      let visibleSince = 0; // instant depuis lequel la boîte est vue entière, visible, non recouverte
      let io = null;
      if (typeof IntersectionObserver === 'function') {
        const v2 = typeof IntersectionObserverEntry === 'function' && 'isVisible' in IntersectionObserverEntry.prototype;
        io = new IntersectionObserver((entries) => {
          const en = entries[entries.length - 1];
          const ok = (v2 ? en.isVisible === true : true) && en.intersectionRatio >= 0.99;
          if (!ok) visibleSince = 0;
          else if (!visibleSince) visibleSince = performance.now();
        }, { trackVisibility: true, delay: 100, threshold: [0, 0.99] });
      } else {
        visibleSince = shownAt;
      }
      // Effets CSS que la page peut poser sur l'hôte ou <html> pour masquer la fenêtre sans
      // empêcher le clic (mask / clip-path échappent à IOv2)
      const unmasked = () => {
        if (!host.isConnected || host.parentNode !== mount) return false;
        return [host, document.documentElement].every((el) => {
          const cs = getComputedStyle(el);
          return cs.opacity === '1' && cs.visibility === 'visible' && cs.filter === 'none'
            && cs.clipPath === 'none' && cs.mixBlendMode === 'normal'
            && (!cs.maskImage || cs.maskImage === 'none') && (!cs.webkitMaskImage || cs.webkitMaskImage === 'none');
        });
      };
      const onTop = (btn) => {
        const r = btn.getBoundingClientRect();
        return document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2) === host;
      };
      const armed = (e) => {
        if (!e.isTrusted) return false;
        const now = performance.now();
        if (!visibleSince || !unmasked() || !onTop(e.currentTarget)) {
          // Avertir seulement après le temps d'apparition normal (pas sur un double-clic initial)
          if (now - shownAt > 1000) root.querySelector('.wn').hidden = false;
          return false;
        }
        return now - visibleSince >= ARM_DELAY_MS; // trop tôt : clic ignoré (anti double-clic)
      };
      const close = (v) => { try { if (io) io.disconnect(); } catch {} try { host.remove(); } catch {} resolve(v); };
      root.querySelector('.ok').addEventListener('click', (e) => { if (armed(e)) close('use'); });
      if (Array.isArray(accounts) && accounts.length > 1) {
        // Plusieurs comptes : un bouton par compte (nom + sous-ligne), le bouton unique disparaît
        const ok = root.querySelector('.ok');
        accounts.forEach((a, i) => {
          const b = document.createElement('button');
          b.className = 'ac'; b.type = 'button';
          const name = document.createElement('span'); name.textContent = a.name;
          b.appendChild(name);
          if (a.sub) { const s = document.createElement('small'); s.textContent = a.sub; b.appendChild(s); }
          b.addEventListener('click', (e) => { if (armed(e)) close(i); });
          ok.parentNode.insertBefore(b, ok);
        });
        ok.remove();
      }
      root.querySelector('.fb').addEventListener('click', (e) => { if (e.isTrusted) close('fallback'); });
      root.querySelector('.ca').addEventListener('click', (e) => { if (e.isTrusted) close('cancel'); });
      root.querySelector('.ov').addEventListener('click', (e) => { if (e.isTrusted && e.target === e.currentTarget) close('cancel'); });
      mount.appendChild(host);
      if (io) io.observe(box);
    });
  }

  // ---------- Accès au stockage (service worker) ----------
  function sw(type, payload) {
    return chrome.runtime.sendMessage({ type, ...payload }).catch(() => null);
  }

  // Suffixes publics (extrait de la Public Suffix List) : un rp.id égal à l'un d'eux serait
  // partagé par des sites distincts. Liste PARTIELLE (hébergeurs mutualisés courants) complétée
  // par le motif des seconds niveaux de ccTLD (co.uk, com.au, or.jp…) ; un rp.id écarté à tort
  // n'est pas bloqué, il est simplement laissé à l'authentificateur natif du navigateur.
  const PUBLIC_SUFFIXES = new Set([
    'github.io', 'gitlab.io', 'bitbucket.io', 'codeberg.page', 'readthedocs.io', 'herokuapp.com',
    'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
    'appspot.com', 'blogspot.com', 'azurewebsites.net', 'azurestaticapps.net', 'cloudfront.net',
    'onrender.com', 'fly.dev', 'glitch.me', 'surge.sh', 'ngrok.io', 'ngrok-free.app', 'myshopify.com'
  ]);
  const CCTLD_SECOND_LEVEL = /^(?:ac|ad|co|com|ed|edu|gen|go|gob|gov|govt|gr|info|int|lg|ltd|mil|ne|net|nic|nom|or|org|plc|sch)\.[a-z]{2}$/;
  const isIpHost = (h) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes(':') || h.startsWith('[');

  // rpId par défaut = hostname de la frame (jamais une valeur fournie par la page sans contrôle)
  function resolveRpId(requested) {
    const host = window.location.hostname;
    if (!requested) return host;
    const r = String(requested).toLowerCase();
    if (host === r) return r;
    // La spec WebAuthn n'autorise un rp.id parent que s'il est un « registrable domain suffix »
    // de l'hôte : jamais pour une adresse IP, un TLD seul ou un suffixe public (com, co.uk, github.io)
    if (isIpHost(host) || !r.includes('.') || PUBLIC_SUFFIXES.has(r) || CCTLD_SECOND_LEVEL.test(r)) return null;
    if (host.endsWith('.' + r)) return r;
    return null; // rp.id non autorisé pour cette origine
  }

  // Permissions-Policy : dans une iframe, WebAuthn n'est permis que si l'embarqueur l'a délégué
  // (allow="publickey-credentials-create|get" ; défaut 'self'). Sinon on laisse le navigateur
  // appliquer la politique (erreur standard) au lieu d'afficher la fenêtre RDVAULT dans la frame.
  function frameAllows(feature) {
    if (!window.isSecureContext) return false;
    if (window.top === window) return true;
    const fp = document.permissionsPolicy || document.featurePolicy;
    return !!(fp && typeof fp.allowsFeature === 'function' && fp.allowsFeature(feature));
  }

  // Contexte de l'appel pour clientDataJSON (WebAuthn §5.8.1) : crossOrigin = true quand la frame
  // n'a pas la même origine que tous ses ancêtres, avec topOrigin = origine de la page principale.
  // Ancêtres inconnus (location.ancestorOrigins absent ou origine masquée « null ») : null → le
  // navigateur traite la cérémonie lui-même et remplit ces champs correctement.
  function callerContext() {
    if (window.top === window) return { crossOrigin: false };
    let ancestors = null;
    try {
      const ao = window.location.ancestorOrigins;
      if (ao && typeof ao.length === 'number') ancestors = Array.from(ao);
    } catch { ancestors = null; }
    if (!ancestors || ancestors.length === 0 || ancestors.some((o) => typeof o !== 'string' || !o || o === 'null')) return null;
    const own = window.location.origin;
    if (ancestors.every((o) => o === own)) return { crossOrigin: false };
    return { crossOrigin: true, topOrigin: ancestors[ancestors.length - 1] };
  }

  // VÉRIFICATION DE L'UTILISATEUR (drapeau UV) — décision produit : le coffre RDVAULT n'est lisible
  // qu'une fois DÉVERROUILLÉ par le mot de passe maître, ce qui constitue la vérification de
  // l'utilisateur (même approche que les gestionnaires de mots de passe du marché). Une cérémonie
  // servie par RDVAULT n'aboutit que si le coffre est déverrouillé :
  //  - authentification : la clé privée vient du coffre (PASSKEY_LIST) et le compteur y est réservé
  //    (PASSKEY_UPDATE_COUNT) AVANT de signer ;
  //  - création : l'attestation n'est renvoyée au site qu'après l'enregistrement de la clé dans le
  //    coffre (PASSKEY_STORE) ; sinon NotAllowedError.
  // Le drapeau UV est donc toujours posé, et userVerification « required » est servi par RDVAULT
  // (plus de bascule vers le navigateur). Coffre verrouillé : aucune passkey lisible, rien n'est signé.
  const VAULT_UNLOCK_VERIFIES_USER = true;

  async function handleCreate(data) {
    if (!frameAllows('publickey-credentials-create')) return { fallback: true };
    const ctx = callerContext();
    if (!ctx) return { fallback: true };
    const rpId = resolveRpId(data.rpId);
    if (!rpId) return { fallback: true }; // rp.id non géré par nous : laisser le navigateur gérer
    // pubKeyCredParams : RDVAULT ne produit que des clés ES256 (-7). Liste absente ou vide = valeurs
    // par défaut de la spécification (ES256, RS256) ; sinon ES256 doit y figurer.
    if (Array.isArray(data.algs) && !data.algs.some((a) => Number(a) === -7)) return { fallback: true };
    // excludeCredentials : une passkey RDVAULT déjà enregistrée pour ce compte → InvalidStateError,
    // APRÈS consentement (le site ne doit pas pouvoir sonder l'existence d'une passkey sans geste)
    const exclude = Array.isArray(data.excludeCredentials) ? data.excludeCredentials.map(String).filter(Boolean) : [];
    let excluded = false, excludeUnknown = false;
    if (exclude.length) {
      const list = await sw('PASSKEY_LIST', { rpId });
      if (!list || list.success !== true) excludeUnknown = true;
      else { const ex = new Set(exclude); excluded = (list.passkeys || []).some((p) => ex.has(p.credentialId)); }
    }
    const userName = data.userName || '';
    const choice = await confirmDialog({
      title: msg('pkCreateTitle', 'Créer une passkey pour $1', rpId), detail: userName, okLabel: msg('pkCreateOk', 'Créer dans RDVAULT')
    });
    if (choice === 'fallback') return { fallback: true };
    if (choice !== 'use') throw new Error('RDVAULT_CANCELLED');
    if (excluded) throw new Error('RDVAULT_EXCLUDED');
    // Coffre illisible : exclusion invérifiable (l'enregistrement échouerait de toute façon)
    if (excludeUnknown) throw new Error('RDVAULT_STORE_FAILED');

    // UV : attestation rendue uniquement si l'enregistrement ci-dessous réussit (coffre déverrouillé)
    const cred = await core.createCredential({
      rpId, origin: window.location.origin, challenge: data.challenge, attestation: data.attestation || 'none',
      crossOrigin: ctx.crossOrigin, topOrigin: ctx.topOrigin, userVerified: VAULT_UNLOCK_VERIFIES_USER
    });
    const stored = await sw('PASSKEY_STORE', { passkey: {
      rpId, credentialId: cred.credentialId, privateKeyJwk: cred.privateKeyJwk,
      userId: data.userId || '', userName, userDisplayName: data.userDisplayName || '',
      signCount: 0, createdAt: Date.now(), origin: window.location.origin
    } });
    // Coffre fermé / verrouillé / écriture échouée : la clé privée n'est conservée nulle part.
    // Ne JAMAIS renvoyer l'attestation (le site enregistrerait une passkey inutilisable) :
    // l'erreur devient un NotAllowedError standard côté site, qui peut réessayer.
    if (!stored || stored.success !== true) throw new Error('RDVAULT_STORE_FAILED');
    return {
      credentialId: cred.credentialId, attestationObjectB64u: cred.attestationObjectB64u, clientDataJSONB64u: cred.clientDataJSONB64u,
      authenticatorDataB64u: cred.authenticatorDataB64u, publicKeySpkiB64u: cred.publicKeySpkiB64u
    };
  }

  // Compteur de signatures RÉSERVÉ dans le coffre AVANT de signer : la valeur lue à l'ouverture
  // de la fenêtre a pu être consommée entre-temps (autre onglet, autre poste). L'application
  // n'accepte qu'une valeur supérieure à celle stockée ; sinon elle répond { reserved: false,
  // signCount: <valeur stockée> } et l'on demande la suivante. Une application antérieure (sans
  // champ « reserved ») enregistre la valeur telle quelle : comportement d'origine. Échec
  // (coffre indisponible) : aucune assertion, sinon la suivante rejouerait le même compteur.
  async function reserveSignCount(rpId, pk) {
    let next = (Number(pk.signCount) || 0) + 1;
    for (let attempt = 0; attempt < 5; attempt++) {
      const r = await sw('PASSKEY_UPDATE_COUNT', { rpId, credentialId: pk.credentialId, signCount: next });
      if (!r || r.success !== true) break;
      if (r.reserved !== false) return next;
      if (!Number.isInteger(r.signCount) || r.signCount < next) break;
      next = r.signCount + 1;
    }
    throw new Error('RDVAULT_COUNT_FAILED');
  }

  // Libellé d'un compte dans le sélecteur : nom affiché (ou identifiant), puis identifiant
  // et date de création en sous-ligne. Uniquement des champs publics (jamais la clé privée).
  function accountLabel(pk) {
    const name = pk.userDisplayName || pk.userName || msg('pkUnnamedAccount', 'Compte sans nom');
    const parts = [];
    if (pk.userName && pk.userName !== name) parts.push(pk.userName);
    if (Number.isFinite(pk.createdAt)) parts.push(msg('pkCreatedOn', 'créée le $1', new Date(pk.createdAt).toLocaleDateString()));
    return { name, sub: parts.join(' · ') };
  }

  async function handleGet(data) {
    if (!frameAllows('publickey-credentials-get')) return { fallback: true };
    const ctx = callerContext();
    if (!ctx) return { fallback: true };
    const rpId = resolveRpId(data.rpId);
    if (!rpId) return { fallback: true };
    const list = (await sw('PASSKEY_LIST', { rpId })) || { passkeys: [] };
    let candidates = list.passkeys || [];
    if (Array.isArray(data.allowCredentials) && data.allowCredentials.length) {
      const allow = new Set(data.allowCredentials.map(String));
      candidates = candidates.filter(p => allow.has(p.credentialId));
    }
    if (candidates.length === 0) return { fallback: true }; // aucune passkey RDVAULT : laisser le navigateur gérer

    // Plusieurs passkeys pour ce rpId (flux « discoverable » sans allowCredentials, ou
    // plusieurs comptes) : laisser l'utilisateur choisir le compte. Un seul : confirmation simple.
    const multi = candidates.length > 1;
    const label = multi ? msg('pkChooseAccount', 'choisissez le compte') : (candidates[0].userName || candidates[0].userDisplayName || '');
    const choice = await confirmDialog({
      title: msg('pkGetTitle', 'Utiliser votre passkey pour $1', rpId), detail: label, okLabel: msg('pkGetOk', 'Utiliser ma passkey RDVAULT'),
      accounts: multi ? candidates.map(accountLabel) : null
    });
    if (choice === 'fallback') return { fallback: true };
    const pk = typeof choice === 'number' ? candidates[choice] : (choice === 'use' ? candidates[0] : null);
    if (!pk) throw new Error('RDVAULT_CANCELLED');

    // Réservation réussie = coffre déverrouillé à cet instant : la signature porte le drapeau UV
    const counter = await reserveSignCount(rpId, pk);
    const asrt = await core.getAssertion({
      rpId, origin: window.location.origin, challenge: data.challenge,
      privateKeyJwk: pk.privateKeyJwk, credentialId: pk.credentialId,
      signCount: counter - 1, // getAssertion signe signCount + 1, soit la valeur réservée
      userHandle: pk.userId || null, crossOrigin: ctx.crossOrigin, topOrigin: ctx.topOrigin,
      userVerified: VAULT_UNLOCK_VERIFIES_USER
    });
    return {
      credentialId: pk.credentialId,
      authenticatorDataB64u: asrt.authenticatorDataB64u,
      clientDataJSONB64u: asrt.clientDataJSONB64u,
      signatureB64u: asrt.signatureB64u,
      userHandleB64u: asrt.userHandleB64u
    };
  }

  window.addEventListener('message', async (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.source !== CHANNEL || msg.dir !== 'req') return;
    if (!core) { post({ source: CHANNEL, dir: 'res', id: msg.id, ok: false, error: 'core indisponible' }); return; }
    try {
      const result = msg.op === 'create' ? await handleCreate(msg.data)
        : msg.op === 'get' ? await handleGet(msg.data)
        : (() => { throw new Error('op inconnue'); })();
      post({ source: CHANNEL, dir: 'res', id: msg.id, ok: true, result });
    } catch (err) {
      post({ source: CHANNEL, dir: 'res', id: msg.id, ok: false, error: (err && err.message) || 'erreur' });
    }
  }, false);
})();
