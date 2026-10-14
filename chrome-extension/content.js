// content.js
// Content script : détection des formulaires de connexion et auto-remplissage
//
// SÉCURITÉ :
// - La liste reçue du background ne contient JAMAIS de mot de passe : il n'est demandé
//   qu'à la sélection (SELECT_CREDENTIAL), utilisé pour le remplissage et non conservé
// - L'UI (icône « V » + menu) vit dans un shadow root FERMÉ : la page ne peut ni la lire,
//   ni la modifier, ni y déclencher de clics
// - Tous les handlers click / focus ignorent les événements synthétiques (isTrusted === false)
// - Le listener de clic est attaché UNE SEULE FOIS par icône, à sa création (pas de fuite)
// - Un seul MutationObserver global ; la liste n'est rechargée qu'au plus toutes les 60 s
//   ou au premier focus d'un nouveau champ identifiant
// - Test de visibilité (dimensions, hors-écran, opacité des ancêtres) avant tout remplissage
//
// Formulaires pris en charge :
// - Identifiant + mot de passe classique
// - Connexion en deux étapes (identifiant seul, puis mot de passe sur une autre vue)
// - SPA React / Angular / Vue (setter natif + événements input / change)
// - Champs dans un shadow DOM ouvert de la page
// - Champ à « étiquette flottante » rendu transparent (opacity:0) tant qu'il est vide et sans
//   focus, s'il est réellement atteignable au clic (ex. login.orange.fr)
// - Formulaire de connexion contenant des champs mot de passe cachés (pot de miel hors écran ou
//   « sr-only » de 1×1 px / découpé par clip / clip-path, section repliée) : seuls les champs
//   présents comptent pour l'heuristique « inscription », et les champs cachés ne sont jamais
//   remplis
// Non pris en charge :
// - Formulaires dans une iframe, même same-origin : le script n'est injecté que dans le
//   document principal (all_frames: false) pour ne pas s'exécuter dans des frames tierces
// - Champ TOTP : cette version parle directement à Vault et n'a pas d'endpoint TOTP
//   (voir la version enrichie, vault-autofill-extension/)

/* global chrome */ // API des extensions Chrome (script de contenu)
(function() {
  'use strict'; // eslint-disable-line strict -- script de contenu classique (IIFE), pas un module ES

  // ============================================================================
  // CONFIGURATION
  // ============================================================================

  const OBSERVER_DEBOUNCE_MS = 300;
  const CREDENTIALS_REFRESH_INTERVAL_MS = 60000;
  const MIN_CONFIDENCE_SCORE = 2;
  const ICON_SIZE_PX = 20;
  const ANCESTOR_OPACITY_DEPTH = 5;
  // Taille minimale (px) d'un champ transparent (opacity:0) pour être pris en compte
  const TRANSPARENT_FIELD_MIN_WIDTH_PX = 60;
  const TRANSPARENT_FIELD_MIN_HEIGHT_PX = 10;
  // Taille (px) jusqu'à laquelle une zone est négligeable : champ de 1×1 px ou découpé par
  // clip / clip-path (motifs « sr-only » / « visually-hidden » des pots de miel)
  const NEGLIGIBLE_SIZE_PX = 2;
  const PROXIMITY_BONUS = 4;
  const USERNAME_INPUT_TYPES = ['text', 'email', 'tel', ''];
  const EXCLUDE_FIELD_RE = /\b(search|recherche|rechercher|query|keyword|quantity|qty|zip|postal|code[\s_-]?postal|coupon|promo|voucher|gift[\s_-]?card|cvv|cvc|card[\s_-]?number|expir)\b/i;

  // ============================================================================
  // ÉTAT
  // ============================================================================

  /** Liste des identifiants du site (SANS mot de passe) : {name, engine, username} */
  let credentialsList = [];
  let credentialsLoadedAt = 0;
  let credentialsLoadPromise = null;
  // Dernier chargement en ÉCHEC (non connecté à Vault, Vault injoignable) et son message
  let credentialsLoadFailed = false;
  let credentialsLoadError = '';

  let activeDropdown = null;
  let activeDropdownField = null;
  let isAutofilling = false;
  let observerDebounceTimer = null;

  const processedFields = new WeakSet();
  const focusedFields = new WeakSet();
  const iconByField = new WeakMap();
  const activeIcons = [];

  let uiHost = null;
  let uiRoot = null;
  // Région role="status" du shadow root : annonces aux lecteurs d'écran (ouverture du menu)
  let liveRegion = null;

  // ============================================================================
  // PATTERNS DE DÉTECTION
  // ============================================================================

  const USERNAME_PATTERNS = {
    autocomplete: ['username', 'email', 'user', 'login'],
    nameId: [
      'user', 'username', 'login', 'email', 'mail', 'identifier',
      'userid', 'user_id', 'user-id', 'utilisateur', 'identifiant',
      'account', 'compte', 'pseudo', 'nickname', 'handle',
      'signin', 'sign-in', 'sign_in', 'logon', 'log-on', 'log_on'
    ],
    text: [
      'email', 'e-mail', 'courriel', 'mail',
      'username', 'user name', 'nom d\'utilisateur',
      'identifiant', 'identifier', 'login', 'connexion',
      'account', 'compte', 'adresse', 'address'
    ],
    classes: ['email', 'username', 'login', 'user', 'identifier', 'signin', 'sign-in', 'logon', 'account']
  };

  const PASSWORD_PATTERNS = {
    autocomplete: ['current-password', 'password', 'new-password'],
    nameId: ['pass', 'password', 'pwd', 'passwd', 'secret', 'mot_de_passe', 'motdepasse', 'mdp', 'credential'],
    text: ['password', 'mot de passe', 'mdp', 'secret', 'passphrase'],
    classes: ['password', 'passwd', 'pwd', 'secret']
  };

  const SIGNUP_FORM_INDICATORS = [
    'signup', 'sign-up', 'sign_up', 'register', 'registration',
    'inscription', 'create-account', 'create_account', 'nouveau', 'new-user', 'join'
  ];

  const LOGIN_FORM_INDICATORS = [
    'login', 'signin', 'sign-in', 'sign_in', 'logon', 'log-on', 'connexion', 'authentication', 'auth'
  ];

  // ============================================================================
  // STYLES (injectés dans le shadow root fermé)
  // ============================================================================

  const STYLES = `
    :host { all: initial; }

    .vault-autofill-icon {
      position: fixed;
      width: ${ICON_SIZE_PX}px;
      height: ${ICON_SIZE_PX}px;
      box-sizing: border-box;
      cursor: pointer;
      background: #3b82f6;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: white;
      font-weight: bold;
      z-index: 2147483647;
      user-select: none;
      box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .vault-autofill-icon:hover { background: #2563eb; }

    .vault-autofill-dropdown {
      position: fixed;
      box-sizing: border-box;
      background: white;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
      z-index: 2147483647;
      min-width: 280px;
      max-width: 400px;
      max-height: 320px;
      overflow-y: auto;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.3;
      color: #111827;
    }
    .vault-autofill-header {
      padding: 10px 12px;
      border-bottom: 1px solid #e5e7eb;
      background: #f9fafb;
      font-size: 11px;
      color: #6b7280;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .vault-autofill-item {
      padding: 12px;
      cursor: pointer;
      border-bottom: 1px solid #f3f4f6;
    }
    .vault-autofill-item:last-child { border-bottom: none; }
    .vault-autofill-item:hover { background: #f3f4f6; }
    .vault-autofill-item-name {
      font-weight: 600;
      font-size: 14px;
      color: #111827;
      margin-bottom: 4px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .vault-autofill-item-username {
      font-size: 12px;
      color: #6b7280;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .vault-autofill-no-results,
    .vault-autofill-loading,
    .vault-autofill-error {
      padding: 16px;
      text-align: center;
      font-size: 13px;
    }
    .vault-autofill-no-results { color: #9ca3af; }
    .vault-autofill-loading { color: #3b82f6; }
    .vault-autofill-error { color: #dc2626; }
    /* Entrée active au clavier (focus) */
    .vault-autofill-item:focus,
    .vault-autofill-item[aria-selected="true"] {
      background: #eff6ff;
      outline: 2px solid #3b82f6;
      outline-offset: -2px;
    }
    /* Région lue par les lecteurs d'écran, invisible à l'écran */
    .vault-autofill-live {
      position: fixed;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
      clip-path: inset(50%);
      white-space: nowrap;
    }
  `;

  // ============================================================================
  // UTILITAIRES
  // ============================================================================

  // Texte traduit dans la langue du navigateur (chrome.i18n, _locales/<langue>/messages.json,
  // repli « en »). `fallback` est le texte français d'origine, identique à _locales/fr : il ne
  // sert que hors extension (tests, page simulée) ; $1… y sont remplacés comme par Chrome.
  function msg(key, fallback, subs) {
    const list = subs === undefined ? [] : [].concat(subs).map(String);
    try {
      if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
        const text = chrome.i18n.getMessage(key, list);
        if (text) return text;
      }
    } catch (e) { /* contexte d'extension invalidé : repli */ }
    return fallback.replace(/\$([1-9])/g, (m, n) => (list[n - 1] !== undefined ? list[n - 1] : ''));
  }

  // Attributs lang / dir de l'UI (arabe : de droite à gauche)
  function uiLangAttrs() {
    let lang = 'fr';
    try {
      if (typeof chrome !== 'undefined' && chrome.i18n && chrome.i18n.getUILanguage) lang = chrome.i18n.getUILanguage();
    } catch (e) { /* repli */ }
    return { lang, dir: msg('@@bidi_dir', 'ltr') };
  }

  function createElement(tag, attrs = {}, text = null) {
    const element = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'className') {
        element.className = value;
      } else {
        element.setAttribute(key, String(value));
      }
    }
    if (typeof text === 'string') {
      element.textContent = text;
    }
    return element;
  }

  function clearChildren(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  // Parent en traversant les frontières de shadow DOM
  function getParentElement(node) {
    if (!node) return null;
    if (node.parentElement) return node.parentElement;
    const parentNode = node.parentNode;
    if (parentNode && parentNode.host) return parentNode.host;
    return null;
  }

  function isExtensionContextValid() {
    try {
      return !!(chrome.runtime && chrome.runtime.id);
    } catch (e) {
      return false;
    }
  }

  function isFieldFocused(field) {
    try {
      const root = field.getRootNode();
      const active = (root && root.activeElement) || document.activeElement;
      return active === field;
    } catch (e) {
      return document.activeElement === field;
    }
  }

  // Champ à opacité nulle mais réellement atteignable par l'utilisateur : motif « étiquette
  // flottante » (relevé sur login.orange.fr) où l'input vide et sans focus est transparent
  // au-dessus de son étiquette, puis redevient opaque au focus. Accepté UNIQUEMENT si c'est lui
  // que l'utilisateur atteint en cliquant en son centre (hit-test elementFromPoint, dans sa propre
  // racine pour un shadow DOM) et s'il a une taille de vrai champ. Les pièges transparents restent
  // exclus : pointer-events:none, recouverts, minuscules, ou centre hors de la fenêtre. Une opacité
  // nulle d'un ANCÊTRE reste rédhibitoire (vérifiée à part). Même règle que la version enrichie.
  function isTransparentButReachable(element, rect) {
    // Taille minimale : exclut les leurres de quelques pixels, et garantit que l'icône
    // (ICON_SIZE_PX, à 8 px du bord droit) ne recouvre jamais le centre du champ.
    if (rect.width < TRANSPARENT_FIELD_MIN_WIDTH_PX || rect.height < TRANSPARENT_FIELD_MIN_HEIGHT_PX) return false;

    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) return false;

    try {
      const root = element.getRootNode();
      const hitRoot = (root && typeof root.elementFromPoint === 'function') ? root : document;
      return hitRoot.elementFromPoint(x, y) === element;
    } catch (e) {
      return false;
    }
  }

  // Longueur CSS calculée en px (unités px ou %, un % étant rapporté à `ref`) ; « 0 » sans unité
  // accepté, toute autre forme (calc(), em, mot-clé…) donne null.
  function cssLengthToPx(value, ref) {
    const m = /^(-?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(px|%)?$/i.exec(String(value).trim());
    if (!m) return null;
    const n = parseFloat(m[1]);
    if (!m[2]) return n === 0 ? 0 : null;
    return m[2] === '%' ? n * ref / 100 : n;
  }

  // Dimensions {width, height} de la zone laissée visible par `clip` (rect(), seulement en
  // position absolute/fixed) et `clip-path` (formes inset / circle / ellipse / polygon, rapportées
  // à la boîte de bordure) d'un élément de taille width×height ; null si aucun découpage
  // interprétable (url(), path(), calc()… sont ignorés : élément traité comme non découpé).
  function clipVisibleSize(style, width, height) {
    let w = Infinity;
    let h = Infinity;
    let clipped = false;

    // clip: rect(haut, droite, bas, gauche), décalages depuis le coin haut-gauche ; auto = bord
    if (style.position === 'absolute' || style.position === 'fixed') {
      const m = /^rect\(([^)]*)\)$/i.exec(String(style.clip || '').trim());
      const parts = m ? m[1].split(/[\s,]+/).filter(Boolean) : [];
      if (parts.length === 4) {
        const edge = (v, autoPx) => (v.toLowerCase() === 'auto' ? autoPx : cssLengthToPx(v, 0));
        const top = edge(parts[0], 0);
        const right = edge(parts[1], width);
        const bottom = edge(parts[2], height);
        const left = edge(parts[3], 0);
        if (top !== null && right !== null && bottom !== null && left !== null) {
          w = right - left;
          h = bottom - top;
          clipped = true;
        }
      }
    }

    // clip-path : forme de base (« inset(50%) » des motifs sr-only, circle(0), polygone dégénéré…)
    const shape = /(inset|circle|ellipse|polygon)\(([^)]*)\)/.exec(String(style.clipPath || '').toLowerCase());
    if (shape) {
      const args = shape[2].trim();
      let sw = null;
      let sh = null;
      if (shape[1] === 'inset') {
        const v = args.split(/\s+round\s+/)[0].trim().split(/\s+/);
        if (v.length <= 4) {
          const t = cssLengthToPx(v[0], height);
          const r = cssLengthToPx(v[1] !== undefined ? v[1] : v[0], width);
          const b = cssLengthToPx(v[2] !== undefined ? v[2] : v[0], height);
          const l = cssLengthToPx(v[3] !== undefined ? v[3] : (v[1] !== undefined ? v[1] : v[0]), width);
          if (t !== null && r !== null && b !== null && l !== null) {
            sw = width - l - r;
            sh = height - t - b;
          }
        }
      } else if (shape[1] === 'circle') {
        const radius = cssLengthToPx(args.split(/\s*\bat\b/)[0].trim(), Math.hypot(width, height) / Math.SQRT2);
        if (radius !== null) sw = sh = 2 * radius;
      } else if (shape[1] === 'ellipse') {
        const radii = args.split(/\s*\bat\b/)[0].trim().split(/\s+/);
        if (radii.length === 2) {
          const rx = cssLengthToPx(radii[0], width);
          const ry = cssLengthToPx(radii[1], height);
          if (rx !== null && ry !== null) { sw = 2 * rx; sh = 2 * ry; }
        }
      } else {
        const points = args.replace(/^(nonzero|evenodd)\s*,/, '').split(',').map(p => p.trim().split(/\s+/));
        if (points.length > 0 && points.every(p => p.length === 2)) {
          const xs = points.map(p => cssLengthToPx(p[0], width));
          const ys = points.map(p => cssLengthToPx(p[1], height));
          if (xs.every(n => n !== null) && ys.every(n => n !== null)) {
            sw = Math.max(...xs) - Math.min(...xs);
            sh = Math.max(...ys) - Math.min(...ys);
          }
        }
      }
      if (sw !== null && sh !== null) {
        w = Math.min(w, sw);
        h = Math.min(h, sh);
        clipped = true;
      }
    }

    return clipped ? { width: w, height: h } : null;
  }

  // true si une zone {width, height} est négligeable (≤ NEGLIGIBLE_SIZE_PX de large ou de haut)
  function isNegligibleArea(area) {
    return Boolean(area) && (area.width <= NEGLIGIBLE_SIZE_PX || area.height <= NEGLIGIBLE_SIZE_PX);
  }

  // Champ réduit à une zone négligeable pour l'utilisateur (pots de miel « sr-only » /
  // « visually-hidden ») : ni proposé, ni rempli, ni compté dans l'heuristique « plusieurs mots de
  // passe = inscription ». Boîte du champ de ≤ 2 px de large ou de haut ; zone laissée visible par
  // clip / clip-path du champ ou d'un ancêtre proche ≤ 2 px ; ancêtre proche de ≤ 2×2 px qui
  // masque son débordement et découpe réellement le champ (sur sa chaîne de blocs conteneurs).
  // Le motif « étiquette flottante » (champ transparent de taille normale) n'est pas concerné ;
  // une section simplement repliée (hauteur nulle, pleine largeur) non plus. Même règle que la
  // version enrichie.
  function isCollapsedOrClipped(element, rect, style) {
    if (rect.width <= NEGLIGIBLE_SIZE_PX || rect.height <= NEGLIGIBLE_SIZE_PX) return true;
    if (isNegligibleArea(clipVisibleSize(style, rect.width, rect.height))) return true;

    // Le débordement d'un ancêtre ne découpe un descendant en position absolute qu'à partir de
    // son bloc conteneur (1er ancêtre positionné), et jamais un descendant en position fixed.
    // clip / clip-path, eux, s'appliquent à tous les descendants.
    let escaping = style.position === 'absolute';
    let fixed = style.position === 'fixed';
    let ancestor = getParentElement(element);
    for (let i = 0; i < ANCESTOR_OPACITY_DEPTH && ancestor; i++) {
      const s = window.getComputedStyle(ancestor);
      if (s.display !== 'contents') {
        const r = ancestor.getBoundingClientRect();
        if (isNegligibleArea(clipVisibleSize(s, r.width, r.height))) return true;
        if (!fixed && (!escaping || s.position !== 'static')) {
          if (s.display !== 'inline' && r.width <= NEGLIGIBLE_SIZE_PX && r.height <= NEGLIGIBLE_SIZE_PX &&
              (s.overflowX !== 'visible' || s.overflowY !== 'visible')) return true;
          escaping = s.position === 'absolute';
        }
        if (s.position === 'fixed') fixed = true;
      }
      ancestor = getParentElement(ancestor);
    }
    return false;
  }

  // Visibilité : DOM, dimensions, hors-écran, styles et opacité des ancêtres (5 niveaux)
  function isElementVisible(element) {
    if (!element) return false;
    if (!element.isConnected) return false;
    if (element.type === 'hidden') return false;
    if (element.disabled) return false;
    if (element.readOnly) return false;

    const rect = element.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;
    if (rect.right < 0 || rect.bottom < 0) return false;
    if (rect.left > window.innerWidth || rect.top > window.innerHeight) return false;

    const style = window.getComputedStyle(element);
    if (style.display === 'none') return false;
    if (style.visibility === 'hidden') return false;
    // Champ de 1×1 px ou découpé par clip / clip-path (pot de miel « sr-only ») : jamais visible
    if (isCollapsedOrClipped(element, rect, style)) return false;
    // Opacité nulle du champ LUI-MÊME : exclu, sauf motif « étiquette flottante » atteignable
    if (parseFloat(style.opacity) === 0 && !isTransparentButReachable(element, rect)) return false;
    if (element.offsetParent === null && style.position !== 'fixed') return false;

    let ancestor = getParentElement(element);
    for (let i = 0; i < ANCESTOR_OPACITY_DEPTH && ancestor; i++) {
      if (parseFloat(window.getComputedStyle(ancestor).opacity) === 0) return false;
      ancestor = getParentElement(ancestor);
    }

    return true;
  }

  // Champ mot de passe réellement présent pour l'utilisateur, pour l'heuristique « plusieurs mots
  // de passe = inscription » d'isLoginForm. Les champs CACHÉS ne comptent pas (pot de miel hors
  // écran ou « sr-only » de 1×1 px / découpé par clip / clip-path, section repliée en
  // display:none, transparent non atteignable) : sinon un vrai formulaire de connexion qui en
  // contient était ignoré. Contrairement à isElementVisible, un champ
  // simplement hors de la fenêtre (plus bas dans un long formulaire) compte, ainsi qu'un champ
  // désactivé : « mot de passe + confirmation » reste reconnu comme inscription.
  function isPresentPasswordField(input) {
    if (!input || !input.isConnected) return false;

    const rect = input.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;
    // Coordonnées négatives dans le DOCUMENT (ex. left:-9999px) : inatteignable, même en défilant
    if (rect.right + window.scrollX <= 0 || rect.bottom + window.scrollY <= 0) return false;

    const style = window.getComputedStyle(input);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    if (isCollapsedOrClipped(input, rect, style)) return false;
    if (parseFloat(style.opacity) === 0 && !isTransparentButReachable(input, rect)) return false;

    let ancestor = getParentElement(input);
    for (let i = 0; i < ANCESTOR_OPACITY_DEPTH && ancestor; i++) {
      if (parseFloat(window.getComputedStyle(ancestor).opacity) === 0) return false;
      ancestor = getParentElement(ancestor);
    }

    return true;
  }

  function getFieldLabelText(field) {
    const texts = [];
    let root = document;
    try {
      const r = field.getRootNode();
      if (r && typeof r.querySelector === 'function') root = r;
    } catch (e) { /* document */ }

    if (field.id) {
      try {
        const label = root.querySelector(`label[for="${CSS.escape(field.id)}"]`);
        if (label) texts.push(label.textContent);
      } catch (e) { /* ignore */ }
    }

    const parentLabel = field.closest('label');
    if (parentLabel) texts.push(parentLabel.textContent);

    const ariaLabel = field.getAttribute('aria-label');
    if (ariaLabel) texts.push(ariaLabel);

    const labelledBy = field.getAttribute('aria-labelledby');
    if (labelledBy) {
      const labelElement = (typeof root.getElementById === 'function')
        ? root.getElementById(labelledBy)
        : document.getElementById(labelledBy);
      if (labelElement) texts.push(labelElement.textContent);
    }

    if (field.placeholder) texts.push(field.placeholder);
    if (field.title) texts.push(field.title);

    const prevSibling = field.previousElementSibling;
    if (prevSibling && ['LABEL', 'SPAN', 'DIV'].includes(prevSibling.tagName)) {
      texts.push(prevSibling.textContent);
    }

    return texts.join(' ').toLowerCase().trim();
  }

  function getElementClasses(element) {
    const classes = [];
    let current = element;
    for (let i = 0; i < 4 && current; i++) {
      if (typeof current.className === 'string' && current.className) {
        classes.push(current.className);
      }
      current = getParentElement(current);
    }
    return classes.join(' ').toLowerCase();
  }

  // ============================================================================
  // DÉTECTION DES CHAMPS
  // ============================================================================

  const DATA_NAME_ATTRS = ['data-testid', 'data-test', 'data-test-id', 'data-qa', 'data-cy', 'data-automation-id', 'ng-reflect-name', 'formcontrolname'];

  function calculateFieldScore(field, patterns) {
    let score = 0;
    const name = (field.name || '').toLowerCase();
    const id = (field.id || '').toLowerCase();
    const autocomplete = (field.autocomplete || '').toLowerCase();
    const labelText = getFieldLabelText(field);
    const classes = getElementClasses(field);
    const dataAttrs = DATA_NAME_ATTRS.map(a => (field.getAttribute(a) || '')).join(' ').toLowerCase();
    const nameHay = (name + ' ' + id + ' ' + dataAttrs).trim();

    for (const pattern of patterns.autocomplete) {
      if (autocomplete.includes(pattern)) { score += 10; break; }
    }
    for (const pattern of patterns.nameId) {
      if (name === pattern || id === pattern) { score += 8; break; }
    }
    for (const pattern of patterns.nameId) {
      if (nameHay.includes(pattern)) { score += 5; break; }
    }
    for (const pattern of patterns.text) {
      if (labelText.includes(pattern)) { score += 4; break; }
    }
    for (const pattern of patterns.classes) {
      if (classes.includes(pattern)) { score += 2; break; }
    }
    return score;
  }

  // Adresse d'envoi réduite à l'hôte et au chemin, SANS chaîne de requête ni fragment : un paramètre
  // technique (« …/login?state=…&registration=%7B%7D » d'Auth0 sur accounts.ikea.com, jeton contenant
  // « Join ») ne doit pas faire passer une connexion pour une inscription. Sans attribut action : adresse
  // de la page. Attribut lu directement (form.action renvoie le champ nommé « action » s'il existe).
  function formActionHostPath(form) {
    const raw = form.getAttribute('action') || '';
    try {
      const url = new URL(raw, document.baseURI);
      return url.host + url.pathname;
    } catch (e) {
      return raw.split(/[?#]/)[0];
    }
  }

  function isLoginForm(form) {
    if (!form) return true;

    // Attributs lus directement (form.id / form.name renvoient un champ ainsi nommé s'il existe)
    const formText = [form.getAttribute('id') || '', form.getAttribute('name') || '', form.getAttribute('class') || '', formActionHostPath(form)]
      .join(' ').toLowerCase();

    for (const indicator of SIGNUP_FORM_INDICATORS) {
      if (formText.includes(indicator)) return false;
    }
    for (const indicator of LOGIN_FORM_INDICATORS) {
      if (formText.includes(indicator)) return true;
    }

    // Plus d'un champ mot de passe PRÉSENT = probablement une inscription
    // (les champs cachés, pots de miel compris, ne comptent pas : voir isPresentPasswordField)
    const pw = Array.from(form.querySelectorAll('input[type="password"]')).filter(isPresentPasswordField);
    if (pw.length > 1) return false;
    // autocomplete="new-password" seul = création de compte / changement de mot de passe
    if (pw.length === 1) {
      const ac = (pw[0].getAttribute('autocomplete') || '').toLowerCase();
      if (ac.includes('new-password') && !ac.includes('current-password')) return false;
    }
    return true;
  }

  // Recherche récursive dans les shadow roots OUVERTS de la page
  function querySelectorAllDeep(root, selector) {
    const results = [];
    results.push(...root.querySelectorAll(selector));
    for (const element of root.querySelectorAll('*')) {
      if (element.shadowRoot) {
        results.push(...querySelectorAllDeep(element.shadowRoot, selector));
      }
    }
    return results;
  }

  // Champ à NE PAS traiter comme identifiant (recherche, carte bancaire, code postal...)
  function isExcludedField(input) {
    const type = (input.type || 'text').toLowerCase();
    if (type === 'search') return true;
    if ((input.getAttribute('role') || '').toLowerCase() === 'searchbox') return true;
    const ac = (input.autocomplete || '').toLowerCase();
    if (/^cc-|one-time-code/.test(ac)) return true;
    if (/\b(username|email)\b/.test(ac)) return false;
    const hay = [input.name, input.id, input.getAttribute('aria-label'), input.placeholder, getFieldLabelText(input)]
      .filter(Boolean).join(' ').toLowerCase();
    return EXCLUDE_FIELD_RE.test(hay);
  }

  function isUsernameCandidate(input) {
    if (!USERNAME_INPUT_TYPES.includes((input.type || 'text').toLowerCase())) return false;
    return !isExcludedField(input);
  }

  function scoreUsername(input) {
    const emailBonus = (input.type || '').toLowerCase() === 'email' ? 6 : 0;
    return calculateFieldScore(input, USERNAME_PATTERNS) + emailBonus;
  }

  // Identifiant associé à un champ password : candidat visible le précédant le plus près
  function findUsernameBeforePassword(passwordField, visibleInputs) {
    const form = passwordField.form || passwordField.closest('form');
    if (form) {
      let best = null;
      for (const el of form.elements) {
        if (el.tagName !== 'INPUT' || !isElementVisible(el) || !isUsernameCandidate(el)) continue;
        if (passwordField.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING) best = el;
      }
      if (best) return best;
    }
    const idx = visibleInputs.indexOf(passwordField);
    for (let i = idx - 1; i >= 0; i--) {
      const cand = visibleInputs[i];
      if ((cand.type || '').toLowerCase() === 'password') break;
      if (isUsernameCandidate(cand)) return cand;
    }
    return null;
  }

  function pageLooksLikeLogin() {
    const LOGIN_WORDS = /(login|log-in|signin|sign-in|logon|connexion|se[\s-]?connecter|authentif|auth|identifi|account|mon[\s-]?compte)/i;
    if (LOGIN_WORDS.test((window.location.href || '').toLowerCase())) return true;
    if (LOGIN_WORDS.test(document.title || '')) return true;
    const NEXT_WORDS = /(continuer|continue|suivant|next|se[\s-]?connecter|log[\s-]?in|sign[\s-]?in|connexion|valider|submit)/i;
    for (const b of querySelectorAllDeep(document, 'button, input[type="submit"], [role="button"]')) {
      if (!isElementVisible(b)) continue;
      const t = (b.textContent || b.value || '').trim();
      if (t && NEXT_WORDS.test(t)) return true;
    }
    return false;
  }

  // Détection par scoring d'attributs + ancrage sur les champs mot de passe
  // (techniques des gestionnaires éprouvés, réimplémentées — aucun code tiers copié).
  function detectFormFields() {
    const visibleInputs = [];
    for (const input of querySelectorAllDeep(document, 'input')) {
      if (!isElementVisible(input)) continue;
      const form = input.closest('form');
      if (form && !isLoginForm(form)) continue;
      visibleInputs.push(input);
    }

    const passwordFields = [];
    const usernameScore = new Map();

    for (const input of visibleInputs) {
      if ((input.type || '').toLowerCase() === 'password') {
        passwordFields.push({ field: input, score: calculateFieldScore(input, PASSWORD_PATTERNS) || 5 });
      }
    }
    for (const input of visibleInputs) {
      if ((input.type || '').toLowerCase() === 'password') continue;
      if (!isUsernameCandidate(input)) continue;
      const score = scoreUsername(input);
      if (score >= MIN_CONFIDENCE_SCORE) usernameScore.set(input, Math.max(usernameScore.get(input) || 0, score));
    }
    for (const pw of passwordFields) {
      const anchor = findUsernameBeforePassword(pw.field, visibleInputs);
      if (anchor) {
        usernameScore.set(anchor, Math.max(usernameScore.get(anchor) || 0, scoreUsername(anchor) + PROXIMITY_BONUS));
      }
    }
    if (passwordFields.length === 0 && usernameScore.size === 0 && pageLooksLikeLogin()) {
      const candidates = visibleInputs.filter(isUsernameCandidate);
      if (candidates.length === 1) usernameScore.set(candidates[0], MIN_CONFIDENCE_SCORE);
    }

    const usernameFields = Array.from(usernameScore.entries()).sort((a, b) => b[1] - a[1]).map(e => e[0]);
    passwordFields.sort((a, b) => b.score - a.score);
    return { usernameFields, passwordFields: passwordFields.map(f => f.field) };
  }

  // ============================================================================
  // UI (shadow root fermé)
  // ============================================================================

  function ensureUiRoot() {
    const mountPoint = document.documentElement || document.body;

    if (uiHost && uiRoot) {
      if (!uiHost.isConnected && mountPoint) mountPoint.appendChild(uiHost);
      return uiRoot;
    }

    uiHost = document.createElement('div');
    uiHost.style.cssText = 'all: initial; position: static; display: block; width: 0; height: 0; overflow: visible;';
    uiRoot = uiHost.attachShadow({ mode: 'closed' });
    uiRoot.appendChild(createElement('style', {}, STYLES));
    // Région présente dès le départ : un lecteur d'écran n'annonce que ses CHANGEMENTS
    liveRegion = createElement('div', { className: 'vault-autofill-live', role: 'status', 'aria-live': 'polite' });
    uiRoot.appendChild(liveRegion);

    if (mountPoint) mountPoint.appendChild(uiHost);
    return uiRoot;
  }

  // Annonce un texte aux lecteurs d'écran (vidée puis remplie : répétée à chaque ouverture)
  function announce(text) {
    if (!liveRegion) return;
    liveRegion.textContent = '';
    setTimeout(() => { if (liveRegion) liveRegion.textContent = text; }, 50);
  }

  function positionIcon(field, icon) {
    if (!isElementVisible(field)) {
      icon.style.display = 'none';
      return;
    }
    const rect = field.getBoundingClientRect();
    icon.style.display = 'flex';
    icon.style.top = `${rect.top + (rect.height - ICON_SIZE_PX) / 2}px`;
    icon.style.left = `${rect.right - ICON_SIZE_PX - 8}px`;
  }

  function positionDropdown(dropdown, field) {
    const rect = field.getBoundingClientRect();
    dropdown.style.top = `${rect.bottom + 4}px`;
    dropdown.style.left = `${rect.left}px`;
    dropdown.style.minWidth = `${Math.max(rect.width, 280)}px`;

    const dropdownRect = dropdown.getBoundingClientRect();
    if (dropdownRect.bottom > window.innerHeight) {
      dropdown.style.top = `${Math.max(0, rect.top - dropdownRect.height - 4)}px`;
    }
    if (dropdownRect.right > window.innerWidth) {
      dropdown.style.left = `${Math.max(0, window.innerWidth - dropdownRect.width - 8)}px`;
    }
  }

  function repositionAllIcons() {
    for (const entry of activeIcons) {
      positionIcon(entry.field, entry.icon);
    }
    if (activeDropdown && activeDropdownField) {
      positionDropdown(activeDropdown, activeDropdownField);
    }
  }

  function cleanupDetachedIcons() {
    for (let i = activeIcons.length - 1; i >= 0; i--) {
      const { field, icon } = activeIcons[i];
      if (!field.isConnected) {
        icon.remove();
        iconByField.delete(field);
        processedFields.delete(field);
        activeIcons.splice(i, 1);
        if (activeDropdownField === field) removeDropdown();
      }
    }
  }

  function createAutofillIcon(field) {
    const existingIcon = iconByField.get(field);
    if (existingIcon && existingIcon.isConnected) return existingIcon;

    const root = ensureUiRoot();
    // Bouton nommé pour les lecteurs d'écran ; au clavier, le menu s'ouvre depuis le champ
    const iconLabel = msg('autofillIconTitle', 'Auto-remplir avec Vault');
    const icon = createElement('div', { className: 'vault-autofill-icon', title: iconLabel, role: 'button', 'aria-label': iconLabel }, 'V');

    root.appendChild(icon);
    iconByField.set(field, icon);
    activeIcons.push({ field, icon });
    positionIcon(field, icon);

    // Listener attaché UNE SEULE FOIS, à la création de l'icône
    icon.addEventListener('click', async (e) => {
      // SÉCURITÉ: ignorer les événements synthétiques
      if (!e.isTrusted) return;
      e.stopPropagation();
      e.preventDefault();

      if (activeDropdown && activeDropdownField === field) {
        removeDropdown();
        return;
      }

      const credentials = await loadCredentials(credentialsList.length === 0);
      // Échec (non connecté à Vault, Vault injoignable) : le dire, au lieu de « aucun identifiant »
      createDropdown(field, credentials, credentialsLoadFailed ? credentialsLoadError : '');
    });

    return icon;
  }

  function setDropdownMessage(dropdown, className, text) {
    const header = dropdown.firstChild;
    clearChildren(dropdown);
    if (header) dropdown.appendChild(header);
    // Erreur annoncée immédiatement (alert), chargement poliment (status)
    const role = className === 'vault-autofill-error' ? 'alert' : 'status';
    dropdown.appendChild(createElement('div', { className, role }, text));
  }

  // Entrées du menu (role="option")
  function menuItems(dropdown) {
    return dropdown ? Array.from(dropdown.querySelectorAll('.vault-autofill-item')) : [];
  }

  // Clavier dans le menu (focus sur une entrée) : Flèches / Origine / Fin pour se déplacer, Entrée
  // ou Espace pour choisir, Échap pour fermer et revenir au champ, Tab pour fermer et poursuivre la
  // navigation depuis le champ. Seuls les événements réels (isTrusted) comptent.
  function onMenuKeydown(e, dropdown, field, credentials) {
    if (!e.isTrusted) return;
    const items = menuItems(dropdown);
    if (!items.length) return;
    const index = items.indexOf(uiRoot ? uiRoot.activeElement : null);
    const focusItem = (i) => items[(i + items.length) % items.length].focus();
    switch (e.key) {
      case 'ArrowDown': focusItem(index + 1); break;
      case 'ArrowUp': focusItem(index < 0 ? -1 : index - 1); break;
      case 'Home': focusItem(0); break;
      case 'End': focusItem(-1); break;
      case 'Enter':
      case ' ':
        if (index < 0) return;
        // preventDefault (ci-dessous) : la touche n'atteint pas le champ (pas de soumission du formulaire vide)
        try { field.focus({ preventScroll: true }); } catch (err) { /* champ retiré */ }
        selectCredential(credentials[index], dropdown, field);
        break;
      case 'Escape':
        removeDropdown();
        try { field.focus({ preventScroll: true }); } catch (err) { /* champ retiré */ }
        break;
      case 'Tab':
        // Retour au champ SANS bloquer la touche : le navigateur avance (ou recule) depuis le champ
        removeDropdown();
        try { field.focus({ preventScroll: true }); } catch (err) { /* champ retiré */ }
        e.stopPropagation();
        return;
      default:
        return;
    }
    e.preventDefault();
    e.stopPropagation();
  }

  function createDropdown(field, credentials, errorMessage = '') {
    removeDropdown();

    const root = ensureUiRoot();
    const dropdown = createElement('div', { className: 'vault-autofill-dropdown', ...uiLangAttrs() });
    const headerText = msg('autofillHeader', 'Identifiants Vault');
    // En-tête (repris comme nom de la liste pour les lecteurs d'écran)
    dropdown.appendChild(createElement('div', { className: 'vault-autofill-header', 'aria-hidden': 'true' }, headerText));

    if (errorMessage) {
      dropdown.appendChild(createElement('div', { className: 'vault-autofill-error', role: 'alert' }, errorMessage));
    } else if (!credentials || credentials.length === 0) {
      dropdown.appendChild(createElement('div', { className: 'vault-autofill-no-results', role: 'status' },
        msg('autofillNoResults', 'Aucun identifiant trouvé pour ce site')));
    } else {
      // Liste accessible : listbox / option, focus déplaçable au clavier (tabindex -1)
      const list = createElement('div', { className: 'vault-autofill-list', role: 'listbox', 'aria-label': headerText });
      credentials.forEach(cred => {
        const name = cred.name || msg('autofillUnnamed', 'Sans nom');
        const user = cred.username || msg('autofillNoUsername', '(pas de username)');
        const item = createElement('div', {
          className: 'vault-autofill-item', role: 'option', tabindex: '-1', 'aria-selected': 'false', 'aria-label': name + ', ' + user
        });
        item.appendChild(createElement('div', { className: 'vault-autofill-item-name' }, name));
        item.appendChild(createElement('div', { className: 'vault-autofill-item-username' }, user));

        item.addEventListener('click', (e) => {
          // SÉCURITÉ: ignorer les événements synthétiques
          if (!e.isTrusted) return;
          e.stopPropagation();
          e.preventDefault();
          selectCredential(cred, dropdown, field);
        });
        item.addEventListener('focus', () => item.setAttribute('aria-selected', 'true'));
        item.addEventListener('blur', () => item.setAttribute('aria-selected', 'false'));

        list.appendChild(item);
      });
      list.addEventListener('keydown', (e) => onMenuKeydown(e, dropdown, field, credentials));
      dropdown.appendChild(list);
      announce(msg('autofillMenuAnnounce', 'Identifiants Vault disponibles : $1. Flèche bas pour choisir, Échap pour fermer.', String(credentials.length)));
    }

    root.appendChild(dropdown);
    positionDropdown(dropdown, field);

    activeDropdown = dropdown;
    activeDropdownField = field;
    return dropdown;
  }

  function removeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
      activeDropdownField = null;
    }
  }

  // Sélection : demande du mot de passe au background (SELECT_CREDENTIAL) puis remplissage
  async function selectCredential(summary, dropdown, originField) {
    if (!summary || typeof summary.name !== 'string' || !summary.name) return;

    setDropdownMessage(dropdown, 'vault-autofill-loading', msg('autofillLoading', 'Récupération de l\'identifiant...'));

    let response = null;
    try {
      if (isExtensionContextValid()) {
        response = await chrome.runtime.sendMessage({
          type: 'SELECT_CREDENTIAL',
          engine: summary.engine || '',
          name: summary.name
        });
      }
    } catch (err) {
      response = null;
    }

    if (!response || !response.success || !response.credential) {
      if (activeDropdown === dropdown) {
        const message = (response && typeof response.error === 'string' && response.error)
          ? response.error
          : msg('autofillFetchFailed', 'Impossible de récupérer l\'identifiant');
        setDropdownMessage(dropdown, 'vault-autofill-error', message);
        setTimeout(() => {
          if (activeDropdown === dropdown) removeDropdown();
        }, 2500);
      }
      return;
    }

    if (activeDropdown === dropdown) removeDropdown();

    autofillCredentials(response.credential, originField);
  }

  // ============================================================================
  // REMPLISSAGE
  // ============================================================================

  function fillField(field, value) {
    if (!field || !value) return;
    if (!isElementVisible(field)) return;

    field.focus();

    // Setter natif : compatibilité React / Angular / Vue (value tracker)
    const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    const nativeSetter = descriptor ? descriptor.set : null;
    if (nativeSetter) {
      nativeSetter.call(field, value);
    } else {
      field.value = value;
    }

    field.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }));
    field.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
  }

  function autofillCredentials(credential, originField) {
    if (!credential || typeof credential !== 'object') return;

    // SÉCURITÉ: jamais de remplissage sur une page non HTTPS
    if (window.location.protocol !== 'https:') {
      console.warn('[Vault] Autofill bloqué : page non HTTPS');
      return;
    }

    isAutofilling = true;

    let { usernameFields, passwordFields } = detectFormFields();

    // Privilégier les champs du formulaire d'origine
    const scope = originField ? (originField.form || originField.closest('form')) : null;
    if (scope) {
      const inScope = f => scope.contains(f);
      const scopedUsernames = usernameFields.filter(inScope);
      const scopedPasswords = passwordFields.filter(inScope);
      if (scopedUsernames.length > 0 || scopedPasswords.length > 0) {
        usernameFields = scopedUsernames;
        passwordFields = scopedPasswords;
      }
    }

    if (usernameFields.length > 0 && typeof credential.username === 'string' && credential.username) {
      fillField(usernameFields[0], credential.username);
    }
    if (passwordFields.length > 0 && typeof credential.password === 'string' && credential.password) {
      fillField(passwordFields[0], credential.password);
    }

    setTimeout(() => { isAutofilling = false; }, 200);
  }

  // ============================================================================
  // COMMUNICATION AVEC LE BACKGROUND
  // ============================================================================

  function toCredentialSummary(item) {
    if (!item || typeof item !== 'object') return null;
    if (typeof item.name !== 'string' || !item.name) return null;
    return {
      name: item.name,
      engine: typeof item.engine === 'string' ? item.engine : '',
      username: typeof item.username === 'string' ? item.username : ''
    };
  }

  // Liste (sans mot de passe) ; le background utilise l'URL de l'onglet comme source de vérité.
  // Rechargée au plus toutes les 60 s, ou si force = true (premier focus d'un nouveau champ).
  async function loadCredentials(force = false) {
    if (!isExtensionContextValid()) return credentialsList;

    const isFresh = credentialsLoadedAt > 0 &&
      (Date.now() - credentialsLoadedAt) < CREDENTIALS_REFRESH_INTERVAL_MS;
    if (!force && isFresh) return credentialsList;

    if (credentialsLoadPromise) return credentialsLoadPromise;

    credentialsLoadPromise = (async () => {
      let loaded = false;
      let loadError = '';
      try {
        const response = await chrome.runtime.sendMessage({ type: 'GET_CREDENTIALS' });
        if (response && response.success && Array.isArray(response.credentials)) {
          credentialsList = response.credentials.map(toCredentialSummary).filter(Boolean);
          loaded = true;
        } else {
          credentialsList = [];
          // Raison de l'échec, traduite par le service worker (non connecté, Vault injoignable…)
          if (response && typeof response.error === 'string') loadError = response.error.slice(0, 300);
        }
      } catch (err) {
        credentialsList = [];
      } finally {
        credentialsLoadedAt = Date.now();
        credentialsLoadFailed = !loaded;
        credentialsLoadError = loaded ? '' : (loadError || msg('autofillFetchFailed', 'Impossible de récupérer l\'identifiant'));
        credentialsLoadPromise = null;
      }
      return credentialsList;
    })();

    return credentialsLoadPromise;
  }

  // SÉCURITÉ: vider la liste en mémoire quand la page n'est plus visible
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      credentialsList = [];
      credentialsLoadedAt = 0;
      removeDropdown();
    }
  });

  // ============================================================================
  // INITIALISATION
  // ============================================================================

  function onUsernameFieldFocus(e) {
    // SÉCURITÉ: ignorer les événements synthétiques
    if (!e.isTrusted) return;
    if (isAutofilling) return;

    const field = e.currentTarget;
    const isNewField = !focusedFields.has(field);
    focusedFields.add(field);

    setTimeout(async () => {
      if (isAutofilling) return;
      const credentials = await loadCredentials(isNewField);
      if (isAutofilling) return;
      if (!isFieldFocused(field)) return;
      if (credentials.length === 0) return;
      createDropdown(field, credentials);
    }, 50);
  }

  async function addAutofillIcons() {
    cleanupDetachedIcons();

    const credentials = await loadCredentials(false);
    if (credentials.length === 0) return;

    const { usernameFields, passwordFields } = detectFormFields();

    passwordFields.forEach(field => {
      if (processedFields.has(field)) return;
      processedFields.add(field);
      createAutofillIcon(field);
      // Ouvrir aussi le menu au focus du champ mot de passe (page mot de passe seule, 2e étape)
      field.addEventListener("focus", onUsernameFieldFocus);
    });

    // Connexion en deux étapes (aucun champ mot de passe visible) : icône aussi sur l'identifiant
    const isUsernameOnlyStep = passwordFields.length === 0;
    usernameFields.forEach(field => {
      if (processedFields.has(field)) return;
      processedFields.add(field);
      field.addEventListener('focus', onUsernameFieldFocus);
      if (isUsernameOnlyStep) createAutofillIcon(field);
    });
  }

  function scheduleScan() {
    if (observerDebounceTimer) clearTimeout(observerDebounceTimer);
    observerDebounceTimer = setTimeout(onDomChanged, OBSERVER_DEBOUNCE_MS);
  }

  function onDomChanged() {
    observerDebounceTimer = null;
    if (!isExtensionContextValid()) return;
    ensureUiRoot();
    addAutofillIcons();
  }

  function init() {
    ensureUiRoot();

    // Fermeture du menu au clic ailleurs (les clics dans le shadow root fermé sont retargetés sur l'hôte)
    document.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      if (!activeDropdown) return;
      if (uiHost && e.target === uiHost) return;
      removeDropdown();
    }, true);

    // Clavier depuis la page. Les touches pressées DANS le menu (shadow root fermé, cible
    // retargetée sur l'hôte) sont traitées par onMenuKeydown.
    //  - Échap : ferme le menu ;
    //  - champ d'origine, menu ouvert : Flèche bas / haut entrent dans la liste, Tab la ferme ;
    //  - champ détecté, menu fermé : Alt+Flèche bas l'ouvre (liste en cache).
    document.addEventListener('keydown', (e) => {
      if (!e.isTrusted) return;
      if (uiHost && e.target === uiHost) return;
      const target = typeof e.composedPath === 'function' ? e.composedPath()[0] : e.target;
      if (activeDropdown) {
        if (e.key === 'Escape') {
          removeDropdown();
          return;
        }
        if (target !== activeDropdownField) return;
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          const items = menuItems(activeDropdown);
          if (!items.length) return;
          e.preventDefault();
          e.stopPropagation();
          (e.key === 'ArrowDown' ? items[0] : items[items.length - 1]).focus();
        } else if (e.key === 'Tab') {
          removeDropdown();
        }
        return;
      }
      if (e.key === 'ArrowDown' && e.altKey && target && processedFields.has(target) && credentialsList.length > 0) {
        e.preventDefault();
        createDropdown(target, credentialsList);
      }
    }, true);

    // Focus parti ailleurs dans la page (ni le champ du menu, ni l'UI) : menu fermé
    document.addEventListener('focusin', (e) => {
      if (!activeDropdown) return;
      if (uiHost && e.target === uiHost) return;
      const target = typeof e.composedPath === 'function' ? e.composedPath()[0] : e.target;
      if (target === activeDropdownField) return;
      removeDropdown();
    }, true);

    const onViewportChange = () => {
      repositionAllIcons();
      scheduleScan();
    };
    window.addEventListener('scroll', onViewportChange, { passive: true, capture: true });
    window.addEventListener('resize', onViewportChange, { passive: true });

    // Observer DOM GLOBAL unique (formulaires dynamiques / SPA, nettoyage)
    const domObserver = new MutationObserver(scheduleScan);

    const start = () => {
      addAutofillIcons();
      const observed = document.documentElement || document.body;
      if (observed) domObserver.observe(observed, { childList: true, subtree: true });
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start);
    } else {
      start();
    }
  }

  init();
})();
