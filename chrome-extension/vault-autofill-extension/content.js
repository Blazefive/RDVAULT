/**
 * content.js - Script de contenu pour Vault Autofill
 *
 * Ce script détecte et remplit automatiquement les formulaires de connexion
 * avec les identifiants stockés dans HashiCorp Vault via l'application Desktop RDVAULT.
 *
 * Fonctionnalités :
 * - Détection intelligente des champs (username, password, TOTP)
 * - Scoring de confiance pour une meilleure précision
 * - Support des formulaires dynamiques (SPA)
 * - Support des Shadow DOM de la page
 * - UI (icône + menu) isolée dans un shadow root FERMÉ, inaccessible à la page
 * - Le mot de passe n'est demandé au background qu'au moment de la sélection
 *   (SELECT_CREDENTIAL) et n'est jamais conservé en mémoire du content script
 *
 * Formulaires pris en charge :
 * - Formulaire classique identifiant + mot de passe
 * - Connexion en deux étapes (identifiant seul, puis mot de passe sur une autre vue) :
 *   la vue « identifiant seul » reçoit aussi l'icône ; la vue « mot de passe » est
 *   détectée par l'observer DOM global (SPA) ou au chargement de la page suivante
 * - SPA React / Angular / Vue : setter natif + événements input / change
 * - Champs dans un shadow DOM ouvert de la page (parcours récursif des shadow roots)
 * - Champ TOTP (même page ou page suivante)
 * - Champ à « étiquette flottante » rendu transparent (opacity:0) tant qu'il est vide et sans
 *   focus, s'il est réellement atteignable au clic (ex. login.orange.fr)
 * - Formulaire de connexion contenant des champs mot de passe cachés (pot de miel hors écran ou
 *   « sr-only » de 1×1 px / découpé par clip / clip-path, section repliée) : seuls les champs
 *   présents comptent pour l'heuristique « inscription », et les champs cachés ne sont jamais
 *   remplis
 *
 * Frames : le script est injecté dans toutes les frames (manifest all_frames: true). Dans une
 * iframe, le background filtre les identifiants sur l'hôte de LA FRAME (sender.url fourni par
 * Chrome), jamais sur celui de la page hôte : une iframe tierce n'obtient que les secrets de
 * son propre domaine.
 *
 * @author Vault Autofill Team
 * @version 2.1.0
 */

/* global chrome */ // API des extensions Chrome (script de contenu)
(function() {
  'use strict'; // eslint-disable-line strict -- script de contenu classique (IIFE), pas un module ES

  // ============================================================================
  // CONFIGURATION
  // ============================================================================

  /** Délai de debounce pour l'observer DOM (ms) */
  const OBSERVER_DEBOUNCE_MS = 300;

  /** Durée maximale de validité d'un identifiant mémorisé pour le TOTP (ms) */
  const CREDENTIAL_TTL_MS = 300000; // 5 minutes

  /** Timeout pour la détection TOTP après login (ms) */
  const TOTP_OBSERVER_TIMEOUT_MS = 20000;

  /** Nombre maximum de tentatives de détection TOTP après login */
  const TOTP_MAX_ATTEMPTS = 40;

  /**
   * Nombre maximum d'échecs de REMPLISSAGE TOTP (champ trouvé mais code refusé : clé absente,
   * limite de débit, app verrouillée). Au-delà, la surveillance s'arrête : sinon chaque changement
   * du DOM redemandait un code pendant TOTP_OBSERVER_TIMEOUT_MS, épuisant la limite de 10 codes
   * par minute partagée avec l'application.
   */
  const TOTP_MAX_FILL_FAILURES = 3;

  /** Score minimum pour considérer un champ comme valide */
  const MIN_CONFIDENCE_SCORE = 2;

  /**
   * Intervalle minimal entre deux rechargements de la liste des identifiants (ms)
   * La liste est rechargée au plus toutes les 60 s, ou au focus d'un nouveau champ.
   */
  const CREDENTIALS_REFRESH_INTERVAL_MS = 60000;

  /**
   * Délais des nouvelles tentatives après un ÉCHEC de chargement de la liste (RDVAULT verrouillé,
   * injoignable, limite de débit). Bornés (~2,5 min au total) : une page ouverte avant le
   * déverrouillage de l'app propose l'icône dès que l'app est déverrouillée, sans boucle infinie.
   */
  const CREDENTIALS_RETRY_DELAYS_MS = [2000, 4000, 8000, 15000, 30000, 30000, 60000];

  /** Taille de l'icône (px) */
  const ICON_SIZE_PX = 20;

  /** Nombre de niveaux d'ancêtres inspectés pour l'opacité */
  const ANCESTOR_OPACITY_DEPTH = 5;

  /** Taille minimale (px) d'un champ transparent (opacity:0) pour être pris en compte */
  const TRANSPARENT_FIELD_MIN_WIDTH_PX = 60;
  const TRANSPARENT_FIELD_MIN_HEIGHT_PX = 10;

  /**
   * Taille (px) jusqu'à laquelle une zone est négligeable : un champ de 1×1 px, ou découpé par
   * clip / clip-path (motifs « sr-only » / « visually-hidden » des pots de miel), n'est pas
   * présenté à l'utilisateur
   */
  const NEGLIGIBLE_SIZE_PX = 2;

  /** Bonus de score accordé à un champ identifiant détecté par proximité d'un champ mot de passe */
  const PROXIMITY_BONUS = 4;

  /** Types d'input pouvant contenir un identifiant */
  const USERNAME_INPUT_TYPES = ['text', 'email', 'tel', ''];

  /** Motifs des champs à ne JAMAIS traiter comme identifiant (recherche, quantité, etc.) */
  const EXCLUDE_FIELD_RE = /\b(search|recherche|rechercher|query|keyword|quantity|qty|zip|postal|code[\s_-]?postal|coupon|promo|voucher|gift[\s_-]?card|cvv|cvc|card[\s_-]?number|expir)\b/i;

  // ============================================================================
  // ÉTAT GLOBAL
  // ============================================================================

  /** Liste des identifiants disponibles pour le site actuel (SANS mot de passe) */
  let credentialsList = [];

  /** Horodatage du dernier chargement de la liste */
  let credentialsLoadedAt = 0;

  /** Promesse de chargement en cours (évite les requêtes concurrentes) */
  let credentialsLoadPromise = null;

  /** Vrai si le dernier chargement de la liste a ÉCHOUÉ (≠ liste vide) */
  let credentialsLoadFailed = false;

  /** Message de l'échec du dernier chargement (« RDVAULT est verrouillé… »), vide sinon */
  let credentialsLoadError = '';

  /** Nouvelles tentatives après échec : index du prochain délai et minuterie en cours */
  let credentialsRetryIndex = 0;
  let credentialsRetryTimer = null;

  /** Référence au dropdown actif et au champ qui l'a ouvert */
  let activeDropdown = null;
  let activeDropdownField = null;

  /** Flag de remplissage en cours (évite l'ouverture du menu pendant le focus programmatique) */
  let isAutofilling = false;

  /** Surveillance TOTP après login : {totpKeyName, attempts, failures, inFlight, timeoutId} */
  let totpWatch = null;

  /** Timer pour le debounce de l'observer DOM */
  let observerDebounceTimer = null;

  /** Set des champs déjà traités (évite les doublons) */
  const processedFields = new WeakSet();

  /** Set des champs username ayant déjà reçu le focus (rechargement au premier focus) */
  const focusedFields = new WeakSet();

  /** Association champ → icône */
  const iconByField = new WeakMap();

  /** Liste des icônes actives : [{field, icon}] */
  const activeIcons = [];

  /** Conteneur hôte et shadow root fermé de l'UI */
  let uiHost = null;
  let uiRoot = null;

  /** Région role="status" du shadow root : annonces aux lecteurs d'écran (ouverture du menu) */
  let liveRegion = null;

  // ============================================================================
  // PATTERNS DE DÉTECTION
  // Ces patterns sont inspirés des meilleures pratiques des gestionnaires
  // de mots de passe modernes (Bitwarden, 1Password, etc.)
  // ============================================================================

  /**
   * Patterns pour détecter les champs username/email
   * Classés par priorité décroissante
   */
  const USERNAME_PATTERNS = {
    // Attributs autocomplete (haute priorité)
    autocomplete: ['username', 'email', 'user', 'login'],

    // Attributs name/id (moyenne priorité)
    nameId: [
      'user', 'username', 'login', 'email', 'mail', 'identifier',
      'userid', 'user_id', 'user-id', 'utilisateur', 'identifiant',
      'account', 'compte', 'pseudo', 'nickname', 'handle',
      'signin', 'sign-in', 'sign_in', 'logon', 'log-on', 'log_on'
    ],

    // Placeholders et labels (basse priorité)
    text: [
      'email', 'e-mail', 'courriel', 'mail',
      'username', 'user name', 'nom d\'utilisateur',
      'identifiant', 'identifier', 'login', 'connexion',
      'account', 'compte', 'adresse', 'address'
    ],

    // Classes CSS courantes
    classes: [
      'email', 'username', 'login', 'user', 'identifier',
      'signin', 'sign-in', 'logon', 'account'
    ]
  };

  /**
   * Patterns pour détecter les champs password
   */
  const PASSWORD_PATTERNS = {
    autocomplete: ['current-password', 'password', 'new-password'],
    nameId: [
      'pass', 'password', 'pwd', 'passwd', 'secret',
      'mot_de_passe', 'motdepasse', 'mdp', 'credential'
    ],
    text: [
      'password', 'mot de passe', 'mdp', 'secret', 'passphrase'
    ],
    classes: [
      'password', 'passwd', 'pwd', 'secret'
    ]
  };

  /**
   * Patterns pour détecter les champs TOTP/MFA
   */
  const TOTP_PATTERNS = {
    autocomplete: ['one-time-code', 'otp'],
    nameId: [
      'otp', 'totp', 'code', 'token', 'mfa', '2fa', 'twofa',
      'two-factor', 'twofactor', 'verification', 'verify',
      'authenticator', 'security-code', 'security_code',
      'passcode', 'one-time', 'onetime'
    ],
    text: [
      'code', 'verification', 'vérification', 'otp', 'totp',
      '2fa', 'mfa', 'authenticator', 'token', 'one-time',
      'à usage unique', 'sécurité', 'security'
    ],
    classes: [
      'otp', 'totp', 'code', 'mfa', '2fa', 'verification', 'token'
    ]
  };

  /**
   * Patterns pour identifier les formulaires de connexion (vs inscription)
   */
  const LOGIN_FORM_INDICATORS = [
    'login', 'signin', 'sign-in', 'sign_in', 'logon', 'log-on',
    'connexion', 'authentication', 'auth'
  ];

  /**
   * Patterns pour identifier les formulaires d'inscription (à ignorer)
   */
  const SIGNUP_FORM_INDICATORS = [
    'signup', 'sign-up', 'sign_up', 'register', 'registration',
    'inscription', 'create-account', 'create_account', 'nouveau',
    'new-user', 'join'
  ];

  // ============================================================================
  // STYLES CSS (injectés dans le shadow root fermé, hors de portée de la page)
  // ============================================================================

  const STYLES = `
    :host {
      all: initial;
    }

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
      pointer-events: auto;
      transition: background-color 0.15s ease;
    }

    .vault-autofill-icon:hover {
      background: #2563eb;
    }

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
      transition: background-color 0.1s ease;
    }

    .vault-autofill-item:last-child {
      border-bottom: none;
    }

    .vault-autofill-item:hover {
      background: #f3f4f6;
    }

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

    .vault-autofill-no-results {
      padding: 16px;
      text-align: center;
      color: #9ca3af;
      font-size: 13px;
    }

    .vault-autofill-loading {
      padding: 16px;
      text-align: center;
      color: #3b82f6;
      font-size: 13px;
    }

    .vault-autofill-error {
      padding: 16px;
      text-align: center;
      color: #dc2626;
      font-size: 13px;
    }

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

  /**
   * Texte traduit dans la langue du navigateur (chrome.i18n, _locales/<langue>/messages.json,
   * repli « en »). `fallback` est le texte français d'origine, identique à _locales/fr : il ne
   * sert que hors extension (tests, page simulée) ; $1… y sont remplacés comme par Chrome.
   * @param {string} key - Nom du message
   * @param {string} fallback - Texte français (repli)
   * @param {string|string[]} [subs] - Substitutions $1…$9
   * @returns {string}
   */
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

  /** Attributs lang / dir de l'UI (arabe : de droite à gauche) */
  function uiLangAttrs() {
    let lang = 'fr';
    try {
      if (typeof chrome !== 'undefined' && chrome.i18n && chrome.i18n.getUILanguage) lang = chrome.i18n.getUILanguage();
    } catch (e) { /* repli */ }
    return { lang, dir: msg('@@bidi_dir', 'ltr') };
  }

  /**
   * Crée un élément DOM de manière sécurisée (sans innerHTML)
   * @param {string} tag - Nom de la balise
   * @param {Object} attrs - Attributs à appliquer
   * @param {string|Node|Node[]} content - Contenu textuel ou enfants
   * @returns {HTMLElement} Élément créé
   */
  function createElement(tag, attrs = {}, content = null) {
    const element = document.createElement(tag);

    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'className') {
        element.className = value;
      } else if (key === 'style' && typeof value === 'object') {
        Object.assign(element.style, value);
      } else {
        element.setAttribute(key, String(value));
      }
    }

    if (content !== null) {
      if (typeof content === 'string') {
        element.textContent = content;
      } else if (Array.isArray(content)) {
        content.forEach(child => {
          if (child instanceof Node) element.appendChild(child);
        });
      } else if (content instanceof Node) {
        element.appendChild(content);
      }
    }

    return element;
  }

  /**
   * Vide un élément de tous ses enfants
   * @param {Element} element - Élément à vider
   */
  function clearChildren(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  /**
   * Retourne l'élément parent, en traversant les frontières de shadow DOM
   * @param {Node} node - Nœud de départ
   * @returns {Element|null} Parent ou null
   */
  function getParentElement(node) {
    if (!node) return null;
    if (node.parentElement) return node.parentElement;
    const parentNode = node.parentNode;
    if (parentNode && parentNode.host) return parentNode.host;
    return null;
  }

  /**
   * Indique si le contexte de l'extension est encore valide
   * (faux après rechargement de l'extension)
   * @returns {boolean}
   */
  function isExtensionContextValid() {
    try {
      return !!(chrome.runtime && chrome.runtime.id);
    } catch (e) {
      return false;
    }
  }

  /**
   * Indique si un champ possède actuellement le focus (y compris dans un shadow root)
   * @param {HTMLElement} field - Champ à tester
   * @returns {boolean}
   */
  function isFieldFocused(field) {
    try {
      const root = field.getRootNode();
      const active = (root && root.activeElement) || document.activeElement;
      return active === field;
    } catch (e) {
      return document.activeElement === field;
    }
  }

  // ============================================================================
  // UTILITAIRES DE DÉTECTION
  // ============================================================================

  /**
   * Champ à opacité nulle mais réellement atteignable par l'utilisateur : motif « étiquette
   * flottante » (relevé sur login.orange.fr) où l'input vide et sans focus est rendu
   * transparent au-dessus de son étiquette, puis redevient opaque dès qu'il reçoit le focus.
   *
   * Accepté UNIQUEMENT si c'est lui que l'utilisateur atteint en cliquant en son centre
   * (hit-test elementFromPoint, dans sa propre racine pour un shadow DOM) et s'il a une
   * taille de vrai champ. Les pièges transparents restent exclus : pointer-events:none,
   * recouverts par un autre élément, minuscules, ou centre hors de la fenêtre. Une opacité
   * nulle d'un ANCÊTRE reste rédhibitoire (vérifiée à part dans isElementVisible).
   *
   * @param {HTMLElement} element - Champ à opacité nulle
   * @param {DOMRect} rect - Boîte du champ (getBoundingClientRect)
   * @returns {boolean}
   */
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

  /**
   * Longueur CSS calculée convertie en px (unités px ou %, un % étant rapporté à `ref`).
   * « 0 » sans unité est accepté ; toute autre forme (calc(), em, mot-clé…) donne null.
   * @param {string} value
   * @param {number} ref - Dimension de référence des pourcentages (px)
   * @returns {number|null}
   */
  function cssLengthToPx(value, ref) {
    const m = /^(-?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(px|%)?$/i.exec(String(value).trim());
    if (!m) return null;
    const n = parseFloat(m[1]);
    if (!m[2]) return n === 0 ? 0 : null;
    return m[2] === '%' ? n * ref / 100 : n;
  }

  /**
   * Dimensions de la zone laissée visible par `clip` (rect(), qui ne s'applique qu'en position
   * absolute/fixed) et par `clip-path` (formes inset / circle / ellipse / polygon, rapportées à
   * la boîte de bordure) d'un élément de taille width×height. Une valeur non interprétable
   * (url(), path(), calc()…) est ignorée : l'élément est alors traité comme non découpé.
   *
   * @param {CSSStyleDeclaration} style - Style calculé de l'élément
   * @param {number} width - Largeur de sa boîte (px)
   * @param {number} height - Hauteur de sa boîte (px)
   * @returns {{width: number, height: number}|null} null si aucun découpage interprétable
   */
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

  /** true si une zone {width, height} est négligeable (≤ NEGLIGIBLE_SIZE_PX de large ou de haut) */
  function isNegligibleArea(area) {
    return Boolean(area) && (area.width <= NEGLIGIBLE_SIZE_PX || area.height <= NEGLIGIBLE_SIZE_PX);
  }

  /**
   * Champ réduit à une zone négligeable pour l'utilisateur : motifs « sr-only » / « visually-
   * hidden » des pots de miel anti-robot. Un tel champ n'est ni proposé, ni rempli, ni compté
   * dans l'heuristique « plusieurs mots de passe = inscription ». Cas reconnus :
   *  - boîte du champ de ≤ 2 px de large ou de haut (1×1 px) ;
   *  - zone laissée visible par clip / clip-path du champ ou d'un ancêtre proche ≤ 2 px ;
   *  - ancêtre proche de ≤ 2×2 px qui masque son débordement (overflow ≠ visible) et découpe
   *    réellement le champ (ancêtre sur sa chaîne de blocs conteneurs).
   * Un champ transparent de taille normale (motif « étiquette flottante », voir
   * isTransparentButReachable) n'est pas concerné. Une section simplement repliée (hauteur nulle,
   * pleine largeur) n'est pas visée par la 3e règle.
   *
   * @param {HTMLElement} element - Champ
   * @param {DOMRect} rect - Sa boîte (getBoundingClientRect)
   * @param {CSSStyleDeclaration} style - Son style calculé
   * @returns {boolean}
   */
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

  /**
   * Vérifie si un élément est visible dans le DOM et dans la fenêtre
   * @param {HTMLElement} element - Élément à vérifier
   * @returns {boolean} True si l'élément est visible
   */
  function isElementVisible(element) {
    if (!element) return false;
    if (!element.isConnected) return false;
    if (element.type === 'hidden') return false;
    if (element.disabled) return false;
    if (element.readOnly) return false;

    const rect = element.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;

    // Hors écran (entièrement en dehors de la fenêtre)
    if (rect.right < 0 || rect.bottom < 0) return false;
    if (rect.left > window.innerWidth || rect.top > window.innerHeight) return false;

    const style = window.getComputedStyle(element);
    if (style.display === 'none') return false;
    if (style.visibility === 'hidden') return false;
    // Champ de 1×1 px ou découpé par clip / clip-path (pot de miel « sr-only ») : jamais visible
    if (isCollapsedOrClipped(element, rect, style)) return false;
    // Opacité nulle du champ LUI-MÊME : exclu, sauf motif « étiquette flottante » atteignable
    if (parseFloat(style.opacity) === 0 && !isTransparentButReachable(element, rect)) return false;

    if (element.offsetParent === null && style.position !== 'fixed') {
      return false;
    }

    // Opacité des ancêtres (jusqu'à ANCESTOR_OPACITY_DEPTH niveaux)
    let ancestor = getParentElement(element);
    for (let i = 0; i < ANCESTOR_OPACITY_DEPTH && ancestor; i++) {
      const ancestorStyle = window.getComputedStyle(ancestor);
      if (parseFloat(ancestorStyle.opacity) === 0) return false;
      ancestor = getParentElement(ancestor);
    }

    return true;
  }

  /**
   * Champ mot de passe réellement présent pour l'utilisateur, pour l'heuristique « plusieurs mots
   * de passe = inscription » d'isLoginForm. Les champs CACHÉS ne comptent pas (pot de miel
   * anti-robot hors écran ou « sr-only » de 1×1 px / découpé par clip / clip-path, section
   * « création de compte » repliée en display:none, transparent non atteignable) : sinon un
   * vrai formulaire de connexion qui en contient était ignoré.
   * Contrairement à isElementVisible, un champ simplement hors de la fenêtre (plus bas dans un
   * long formulaire) compte : « mot de passe + confirmation » reste reconnu comme inscription.
   * Désactivé ou en lecture seule : compte aussi (confirmation activée après la 1re saisie).
   *
   * @param {HTMLInputElement} input - Champ type=password
   * @returns {boolean}
   */
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

  /**
   * Récupère le texte du label associé à un champ
   * Analyse plusieurs sources : label for, aria-label, placeholder, etc.
   * @param {HTMLElement} field - Champ de formulaire
   * @returns {string} Texte du label en minuscules
   */
  function getFieldLabelText(field) {
    const texts = [];
    const root = (() => {
      try {
        const r = field.getRootNode();
        return r && typeof r.querySelector === 'function' ? r : document;
      } catch (e) {
        return document;
      }
    })();

    // Label avec attribut 'for'
    if (field.id) {
      try {
        const label = root.querySelector(`label[for="${CSS.escape(field.id)}"]`);
        if (label) texts.push(label.textContent);
      } catch (e) { /* Ignore CSS.escape errors */ }
    }

    // Label parent
    const parentLabel = field.closest('label');
    if (parentLabel) texts.push(parentLabel.textContent);

    // aria-label
    const ariaLabel = field.getAttribute('aria-label');
    if (ariaLabel) texts.push(ariaLabel);

    // aria-labelledby
    const labelledBy = field.getAttribute('aria-labelledby');
    if (labelledBy) {
      const labelElement = (typeof root.getElementById === 'function')
        ? root.getElementById(labelledBy)
        : document.getElementById(labelledBy);
      if (labelElement) texts.push(labelElement.textContent);
    }

    // Placeholder et title
    if (field.placeholder) texts.push(field.placeholder);
    if (field.title) texts.push(field.title);

    // Texte adjacent (frère précédent)
    const prevSibling = field.previousElementSibling;
    if (prevSibling && ['LABEL', 'SPAN', 'DIV'].includes(prevSibling.tagName)) {
      texts.push(prevSibling.textContent);
    }

    return texts.join(' ').toLowerCase().trim();
  }

  /**
   * Récupère les classes CSS d'un élément et de ses parents (3 niveaux)
   * @param {HTMLElement} element - Élément DOM
   * @returns {string} Classes concaténées en minuscules
   */
  function getElementClasses(element) {
    const classes = [];
    let current = element;

    for (let i = 0; i < 4 && current; i++) {
      if (current.className && typeof current.className === 'string') {
        classes.push(current.className);
      }
      current = getParentElement(current);
    }

    return classes.join(' ').toLowerCase();
  }

  // ============================================================================
  // SYSTÈME DE SCORING INTELLIGENT
  // ============================================================================

  /**
   * Calcule un score de confiance pour un champ selon des patterns
   * Plus le score est élevé, plus on est confiant que c'est le bon type de champ
   *
   * @param {HTMLInputElement} field - Champ à analyser
   * @param {Object} patterns - Patterns de détection à utiliser
   * @returns {number} Score de confiance
   */
  /** Attributs data-* utilisés comme identifiants techniques par les frameworks modernes */
  const DATA_NAME_ATTRS = ['data-testid', 'data-test', 'data-test-id', 'data-qa', 'data-cy', 'data-automation-id', 'ng-reflect-name', 'formcontrolname'];

  function calculateFieldScore(field, patterns) {
    let score = 0;

    const name = (field.name || '').toLowerCase();
    const id = (field.id || '').toLowerCase();
    const autocomplete = (field.autocomplete || '').toLowerCase();
    const labelText = getFieldLabelText(field);
    const classes = getElementClasses(field);
    // Attributs data-* (data-testid, formcontrolname...) : identifiants techniques fiables
    const dataAttrs = DATA_NAME_ATTRS.map(a => (field.getAttribute(a) || '')).join(' ').toLowerCase();
    const nameHay = (name + ' ' + id + ' ' + dataAttrs).trim();

    // Autocomplete HTML5 (score très élevé - standard fiable)
    for (const pattern of patterns.autocomplete || []) {
      if (autocomplete.includes(pattern)) {
        score += 10;
        break;
      }
    }

    // Name/ID exact match (score élevé)
    for (const pattern of patterns.nameId || []) {
      if (name === pattern || id === pattern) {
        score += 8;
        break;
      }
    }

    // Name/ID/data-* contient le pattern (score moyen)
    for (const pattern of patterns.nameId || []) {
      if (nameHay.includes(pattern)) {
        score += 5;
        break;
      }
    }

    // Label/placeholder contient le pattern (score moyen)
    for (const pattern of patterns.text || []) {
      if (labelText.includes(pattern)) {
        score += 4;
        break;
      }
    }

    // Classes CSS (score bas - moins fiable)
    for (const pattern of patterns.classes || []) {
      if (classes.includes(pattern)) {
        score += 2;
        break;
      }
    }

    return score;
  }

  /**
   * Adresse d'envoi du formulaire réduite à l'hôte et au chemin, SANS chaîne de requête ni fragment :
   * un paramètre technique (« …/login?state=…&registration=%7B%7D » d'Auth0 sur accounts.ikea.com, jeton
   * contenant « Join », retour vers « /nouveautes ») ne doit pas faire passer une connexion pour une
   * inscription. Sans attribut action, c'est l'adresse de la page (comme form.action). L'attribut est lu
   * directement : form.action renvoie le champ nommé « action » quand le formulaire en contient un.
   * @param {HTMLFormElement} form
   * @returns {string}
   */
  function formActionHostPath(form) {
    const raw = form.getAttribute('action') || '';
    try {
      const url = new URL(raw, document.baseURI);
      return url.host + url.pathname;
    } catch (e) {
      return raw.split(/[?#]/)[0];
    }
  }

  /**
   * Détermine si un formulaire est de type connexion (vs inscription)
   * @param {HTMLFormElement} form - Formulaire à analyser
   * @returns {boolean} True si c'est un formulaire de connexion
   */
  function isLoginForm(form) {
    if (!form) return true;

    // Attributs lus directement (form.id / form.name renvoient un champ ainsi nommé s'il existe)
    const formText = [
      form.getAttribute('id') || '',
      form.getAttribute('name') || '',
      form.getAttribute('class') || '',
      formActionHostPath(form)
    ].join(' ').toLowerCase();

    // Vérifier les indicateurs d'inscription (prioritaire)
    for (const indicator of SIGNUP_FORM_INDICATORS) {
      if (formText.includes(indicator)) return false;
    }

    // Vérifier les indicateurs de connexion
    for (const indicator of LOGIN_FORM_INDICATORS) {
      if (formText.includes(indicator)) return true;
    }

    // Heuristique : plus de 1 champ password PRÉSENT = probablement inscription
    // (les champs cachés, pots de miel compris, ne comptent pas : voir isPresentPasswordField)
    const passwordFields = Array.from(form.querySelectorAll('input[type="password"]')).filter(isPresentPasswordField);
    if (passwordFields.length > 1) return false;

    // autocomplete="new-password" sans "current-password" = création de compte / changement
    // de mot de passe : ce n'est pas un formulaire de connexion.
    if (passwordFields.length === 1) {
      const ac = (passwordFields[0].getAttribute('autocomplete') || '').toLowerCase();
      if (ac.includes('new-password') && !ac.includes('current-password')) return false;
    }

    return true;
  }

  /**
   * Recherche récursivement dans les Shadow DOM (ouverts) de la page
   * @param {Element|Document|ShadowRoot} root - Élément racine
   * @param {string} selector - Sélecteur CSS
   * @returns {HTMLElement[]} Éléments trouvés
   */
  function querySelectorAllDeep(root, selector) {
    const results = [];
    results.push(...root.querySelectorAll(selector));

    const allElements = root.querySelectorAll('*');
    for (const element of allElements) {
      if (element.shadowRoot) {
        results.push(...querySelectorAllDeep(element.shadowRoot, selector));
      }
    }

    return results;
  }

  // ============================================================================
  // DÉTECTION DES CHAMPS DE FORMULAIRE
  // ============================================================================

  /**
   * Indique si un champ texte doit être EXCLU de la détection d'identifiant
   * (champ de recherche, quantité, carte bancaire, code postal...).
   * @param {HTMLInputElement} input
   * @returns {boolean}
   */
  function isExcludedField(input) {
    const type = (input.type || 'text').toLowerCase();
    if (type === 'search') return true;
    if ((input.getAttribute('role') || '').toLowerCase() === 'searchbox') return true;
    const ac = (input.autocomplete || '').toLowerCase();
    // Champs de carte bancaire / codes à usage unique explicitement marqués
    if (/^cc-|one-time-code/.test(ac)) return true;
    const hay = [input.name, input.id, input.getAttribute('aria-label'), input.placeholder, getFieldLabelText(input)]
      .filter(Boolean).join(' ').toLowerCase();
    // Ne pas exclure si l'autocomplete affirme explicitement « username »/« email »
    if (/\b(username|email)\b/.test(ac)) return false;
    return EXCLUDE_FIELD_RE.test(hay);
  }

  /** Champ pouvant accueillir un identifiant (type + non exclu) */
  function isUsernameCandidate(input) {
    if (!USERNAME_INPUT_TYPES.includes((input.type || 'text').toLowerCase())) return false;
    return !isExcludedField(input);
  }

  /** Score identifiant = scoring d'attributs + bonus pour le type email (signal fort) */
  function scoreUsername(input) {
    const emailBonus = (input.type || '').toLowerCase() === 'email' ? 6 : 0;
    return calculateFieldScore(input, USERNAME_PATTERNS) + emailBonus;
  }

  /**
   * Détecte les champs de formulaire pertinents sur la page.
   *
   * Deux mécanismes complémentaires, repris des gestionnaires de mots de passe
   * éprouvés (techniques réimplémentées, aucun code tiers copié) :
   *  1. SCORING par attributs (name/id/autocomplete/label/classe) — précis quand
   *     les champs sont correctement nommés.
   *  2. ANCRAGE sur les champs mot de passe — pour chaque champ password visible,
   *     le champ identifiant est le candidat visible qui le précède immédiatement
   *     (même formulaire de préférence). Ce mécanisme fonctionne même quand le
   *     champ identifiant n'a AUCUN attribut reconnaissable (id/nom illisibles),
   *     cas fréquent sur les sites modernes.
   *
   * @returns {Object} { usernameFields, passwordFields } triés par confiance
   */
  function detectFormFields() {
    const allInputs = querySelectorAllDeep(document, 'input');

    // Inputs visibles, dans l'ordre du document, hors formulaires d'inscription
    const visibleInputs = [];
    for (const input of allInputs) {
      if (!isElementVisible(input)) continue;
      const form = input.closest('form');
      if (form && !isLoginForm(form)) continue;
      visibleInputs.push(input);
    }

    const passwordFields = [];
    const usernameScore = new Map(); // champ -> meilleur score

    // 1a. Champs password
    for (const input of visibleInputs) {
      if ((input.type || '').toLowerCase() === 'password') {
        passwordFields.push({ field: input, score: calculateFieldScore(input, PASSWORD_PATTERNS) || 5 });
      }
    }

    // 1b. Identifiants par scoring d'attributs (type=email = signal fort)
    for (const input of visibleInputs) {
      if ((input.type || '').toLowerCase() === 'password') continue;
      if (!isUsernameCandidate(input)) continue;
      const score = scoreUsername(input);
      if (score >= MIN_CONFIDENCE_SCORE) {
        usernameScore.set(input, Math.max(usernameScore.get(input) || 0, score));
      }
    }

    // 2. Ancrage : identifiant = candidat visible précédant immédiatement un champ password
    for (const pw of passwordFields) {
      const anchor = findUsernameBeforePassword(pw.field, visibleInputs);
      if (anchor) {
        usernameScore.set(anchor, Math.max(usernameScore.get(anchor) || 0, scoreUsername(anchor) + PROXIMITY_BONUS));
      }
    }

    // 3. Filet pour les pages « identifiant seul » (connexion en deux étapes) dont le
    //    champ n'a aucun attribut reconnaissable : s'il n'y a aucun mot de passe et un
    //    unique candidat identifiant visible, et que la page a un contexte de connexion,
    //    on le propose. Gardé strict pour ne pas déclencher sur un champ de recherche
    //    ou d'inscription à une newsletter.
    if (passwordFields.length === 0 && usernameScore.size === 0 && pageLooksLikeLogin()) {
      const candidates = visibleInputs.filter(isUsernameCandidate);
      if (candidates.length === 1) {
        usernameScore.set(candidates[0], MIN_CONFIDENCE_SCORE);
      }
    }

    const usernameFields = Array.from(usernameScore.entries())
      .sort((a, b) => b[1] - a[1])
      .map(e => e[0]);
    passwordFields.sort((a, b) => b.score - a.score);

    return { usernameFields, passwordFields: passwordFields.map(f => f.field) };
  }

  /**
   * Vrai si la page a un contexte de connexion (URL, titre, ou bouton de
   * soumission évoquant une connexion). Utilisé uniquement pour le filet
   * « identifiant seul » afin d'éviter les faux positifs.
   * @returns {boolean}
   */
  function pageLooksLikeLogin() {
    const LOGIN_WORDS = /(login|log-in|signin|sign-in|logon|connexion|se[\s-]?connecter|authentif|auth|identifi|ouverture[\s-]?de[\s-]?session|account|mon[\s-]?compte)/i;
    const url = (window.location.href || '').toLowerCase();
    if (LOGIN_WORDS.test(url)) return true;
    if (LOGIN_WORDS.test(document.title || '')) return true;
    // Texte des boutons/soumissions visibles
    const buttons = querySelectorAllDeep(document, 'button, input[type="submit"], [role="button"]');
    const NEXT_WORDS = /(continuer|continue|suivant|next|se[\s-]?connecter|log[\s-]?in|sign[\s-]?in|connexion|valider|submit)/i;
    for (const b of buttons) {
      if (!isElementVisible(b)) continue;
      const t = (b.textContent || b.value || '').trim();
      if (t && NEXT_WORDS.test(t)) return true;
    }
    return false;
  }

  /**
   * Trouve le champ identifiant associé à un champ mot de passe : le candidat
   * identifiant visible qui le précède le plus près. Cherche d'abord dans le même
   * formulaire (ordre du document via form.elements), puis, à défaut de formulaire,
   * dans la liste globale des champs visibles.
   *
   * @param {HTMLInputElement} passwordField
   * @param {HTMLInputElement[]} visibleInputs - champs visibles en ordre de document
   * @returns {HTMLInputElement|null}
   */
  function findUsernameBeforePassword(passwordField, visibleInputs) {
    const form = passwordField.form || passwordField.closest('form');
    if (form) {
      const inForm = Array.from(form.elements).filter(el =>
        el.tagName === 'INPUT' && isElementVisible(el) && isUsernameCandidate(el)
      );
      let best = null;
      for (const el of inForm) {
        // position relative dans le document
        const rel = passwordField.compareDocumentPosition(el);
        if (rel & Node.DOCUMENT_POSITION_PRECEDING) best = el; // el est avant le password
      }
      if (best) return best;
    }
    // Pas de formulaire (ou rien trouvé) : parcourir la liste plate à rebours
    const idx = visibleInputs.indexOf(passwordField);
    for (let i = idx - 1; i >= 0; i--) {
      const cand = visibleInputs[i];
      if ((cand.type || '').toLowerCase() === 'password') break; // autre bloc de connexion
      if (isUsernameCandidate(cand)) return cand;
    }
    return null;
  }

  /**
   * Détecte les champs TOTP/MFA sur la page
   * @returns {HTMLInputElement[]} Champs TOTP détectés triés par confiance
   */
  function detectTotpFields() {
    const totpFields = [];
    const allInputs = querySelectorAllDeep(document, 'input');

    for (const input of allInputs) {
      if (!isElementVisible(input)) continue;

      const type = (input.type || 'text').toLowerCase();
      if (!['text', 'number', 'tel'].includes(type)) continue;

      let score = calculateFieldScore(input, TOTP_PATTERNS);

      // Bonus pour maxlength=6 (format TOTP standard)
      const maxLength = parseInt(input.maxLength) || 0;
      if (maxLength === 6) score += 5;

      // Bonus pour inputmode="numeric"
      if (input.inputMode === 'numeric') score += 3;

      if (score >= MIN_CONFIDENCE_SCORE) {
        totpFields.push({ field: input, score });
      }
    }

    return totpFields.sort((a, b) => b.score - a.score).map(f => f.field);
  }

  // ============================================================================
  // GESTION DE L'INTERFACE UTILISATEUR (shadow root fermé)
  // ============================================================================

  /**
   * Crée (ou ré-attache) le conteneur hôte et son shadow root fermé.
   * Les styles sont injectés dans le shadow root : la page ne peut ni les lire,
   * ni les modifier, ni accéder aux éléments de l'UI.
   *
   * @returns {ShadowRoot} Le shadow root de l'UI
   */
  function ensureUiRoot() {
    const mountPoint = document.documentElement || document.body;

    if (uiHost && uiRoot) {
      if (!uiHost.isConnected && mountPoint) {
        mountPoint.appendChild(uiHost);
      }
      return uiRoot;
    }

    uiHost = document.createElement('div');
    uiHost.style.cssText = 'all: initial; position: static; display: block; width: 0; height: 0; overflow: visible;';
    uiRoot = uiHost.attachShadow({ mode: 'closed' });
    uiRoot.appendChild(createElement('style', {}, STYLES));
    // Région présente dès le départ : un lecteur d'écran n'annonce que ses CHANGEMENTS
    liveRegion = createElement('div', { className: 'vault-autofill-live', role: 'status', 'aria-live': 'polite' });
    uiRoot.appendChild(liveRegion);

    if (mountPoint) {
      mountPoint.appendChild(uiHost);
    }

    return uiRoot;
  }

  /**
   * Annonce un texte aux lecteurs d'écran (région role="status" du shadow root)
   * @param {string} text - Texte à annoncer
   */
  function announce(text) {
    if (!liveRegion) return;
    liveRegion.textContent = '';
    // Vidée puis remplie : le même texte est annoncé à chaque ouverture du menu
    setTimeout(() => { if (liveRegion) liveRegion.textContent = text; }, 50);
  }

  /**
   * Positionne une icône par rapport à son champ
   * @param {HTMLInputElement} field - Champ cible
   * @param {HTMLElement} icon - Icône à positionner
   */
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

  /**
   * Repositionne toutes les icônes actives (scroll / resize)
   */
  function repositionAllIcons() {
    for (const entry of activeIcons) {
      positionIcon(entry.field, entry.icon);
    }
    if (activeDropdown && activeDropdownField) {
      positionDropdown(activeDropdown, activeDropdownField);
    }
  }

  /**
   * Supprime les icônes dont le champ n'est plus dans le DOM
   */
  function cleanupDetachedIcons() {
    for (let i = activeIcons.length - 1; i >= 0; i--) {
      const { field, icon } = activeIcons[i];
      if (!field.isConnected) {
        icon.remove();
        iconByField.delete(field);
        processedFields.delete(field);
        activeIcons.splice(i, 1);

        if (activeDropdownField === field) {
          removeDropdown();
        }
      }
    }
  }

  /**
   * Crée l'icône Vault sur un champ de formulaire
   * @param {HTMLInputElement} field - Champ cible
   * @returns {HTMLElement} L'icône créée
   */
  function createAutofillIcon(field) {
    const existingIcon = iconByField.get(field);
    if (existingIcon && existingIcon.isConnected) {
      return existingIcon;
    }

    const root = ensureUiRoot();

    // Bouton nommé pour les lecteurs d'écran (activable depuis leur mode lecture) ; au clavier,
    // le menu s'ouvre depuis le champ (focus, Alt+Flèche bas)
    const iconLabel = msg('autofillIconTitle', 'Auto-remplir avec RDVAULT');
    const icon = createElement('div', {
      className: 'vault-autofill-icon',
      title: iconLabel,
      role: 'button',
      'aria-label': iconLabel
    }, 'V');

    root.appendChild(icon);
    iconByField.set(field, icon);
    activeIcons.push({ field, icon });
    positionIcon(field, icon);

    // Le listener est attaché UNE SEULE FOIS, à la création de l'icône
    icon.addEventListener('click', async (e) => {
      // SÉCURITÉ: Ignorer les événements synthétiques (dispatchEvent depuis la page)
      if (!e.isTrusted) return;

      e.stopPropagation();
      e.preventDefault();

      // Clic sur l'icône du champ dont le menu est déjà ouvert : fermer
      if (activeDropdown && activeDropdownField === field) {
        removeDropdown();
        return;
      }

      // Clic explicite de l'utilisateur : recharger si la liste en cache est vide
      const credentials = await loadCredentials(credentialsList.length === 0);
      // Échec (RDVAULT verrouillé ou fermé) : le dire, au lieu de « aucun identifiant » (EXT-23)
      createDropdown(field, credentials, credentialsLoadFailed ? credentialsLoadError : '');
    });

    return icon;
  }

  /**
   * Positionne le dropdown sous (ou au-dessus) du champ
   * @param {HTMLElement} dropdown - Dropdown à positionner
   * @param {HTMLInputElement} field - Champ de référence
   */
  function positionDropdown(dropdown, field) {
    const rect = field.getBoundingClientRect();
    dropdown.style.top = `${rect.bottom + 4}px`;
    dropdown.style.left = `${rect.left}px`;
    dropdown.style.minWidth = `${Math.max(rect.width, 280)}px`;

    // Ajustement si débordement
    const dropdownRect = dropdown.getBoundingClientRect();
    if (dropdownRect.bottom > window.innerHeight) {
      dropdown.style.top = `${Math.max(0, rect.top - dropdownRect.height - 4)}px`;
    }
    if (dropdownRect.right > window.innerWidth) {
      dropdown.style.left = `${Math.max(0, window.innerWidth - dropdownRect.width - 8)}px`;
    }
  }

  /**
   * Remplace le contenu du dropdown (hors en-tête) par un message
   * @param {HTMLElement} dropdown - Dropdown cible
   * @param {string} className - Classe CSS du message
   * @param {string} text - Texte du message
   */
  function setDropdownMessage(dropdown, className, text) {
    const header = dropdown.firstChild;
    clearChildren(dropdown);
    if (header) dropdown.appendChild(header);
    // Erreur annoncée immédiatement (alert), chargement poliment (status)
    const role = className === 'vault-autofill-error' ? 'alert' : 'status';
    dropdown.appendChild(createElement('div', { className, role }, text));
  }

  /**
   * Entrées du menu (role="option")
   * @param {HTMLElement} dropdown - Menu
   * @returns {HTMLElement[]}
   */
  function menuItems(dropdown) {
    return dropdown ? Array.from(dropdown.querySelectorAll('.vault-autofill-item')) : [];
  }

  /**
   * Clavier dans le menu (focus sur une entrée) : Flèches / Origine / Fin pour se déplacer,
   * Entrée ou Espace pour choisir, Échap pour fermer et revenir au champ, Tab pour fermer et
   * poursuivre la navigation depuis le champ. Seuls les événements réels (isTrusted) comptent.
   * @param {KeyboardEvent} e - Événement clavier
   * @param {HTMLElement} dropdown - Menu
   * @param {HTMLInputElement} field - Champ d'origine
   * @param {Object[]} credentials - Résumés affichés (même ordre que les entrées)
   */
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

  /**
   * Crée le dropdown de sélection des identifiants
   * @param {HTMLInputElement} field - Champ de référence pour positionnement
   * @param {Object[]} credentials - Liste des résumés {name, engine, username}
   * @returns {HTMLElement} Le dropdown créé
   */
  function createDropdown(field, credentials, errorMessage = '') {
    removeDropdown();

    const root = ensureUiRoot();
    const dropdown = createElement('div', { className: 'vault-autofill-dropdown', ...uiLangAttrs() });
    const headerText = msg('autofillHeader', 'Identifiants RDVAULT');

    // En-tête (repris comme nom de la liste pour les lecteurs d'écran)
    dropdown.appendChild(createElement('div', { className: 'vault-autofill-header', 'aria-hidden': 'true' }, headerText));

    if (errorMessage) {
      // RDVAULT verrouillé, fermé, limite de débit… : message explicite (EXT-23)
      dropdown.appendChild(createElement('div', { className: 'vault-autofill-error', role: 'alert' }, errorMessage));
    } else if (!credentials || credentials.length === 0) {
      dropdown.appendChild(createElement('div', { className: 'vault-autofill-no-results', role: 'status' },
        msg('autofillNoResults', 'Aucun identifiant trouvé pour ce site')
      ));
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
          // SÉCURITÉ: Ignorer les événements synthétiques
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
      announce(msg('autofillMenuAnnounce', 'Identifiants RDVAULT disponibles : $1. Flèche bas pour choisir, Échap pour fermer.', String(credentials.length)));
    }

    root.appendChild(dropdown);
    positionDropdown(dropdown, field);

    activeDropdown = dropdown;
    activeDropdownField = field;
    return dropdown;
  }

  /**
   * Supprime le dropdown actif
   */
  function removeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
      activeDropdownField = null;
    }
  }

  /**
   * Sélection d'une entrée : demande l'identifiant complet au background
   * (SELECT_CREDENTIAL) puis remplit le formulaire.
   *
   * @param {Object} summary - Résumé {name, engine, username}
   * @param {HTMLElement} dropdown - Dropdown d'origine (pour l'état de chargement)
   * @param {HTMLInputElement} originField - Champ depuis lequel le menu a été ouvert
   */
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

    if (activeDropdown === dropdown) {
      removeDropdown();
    }

    await autofillCredentials(response.credential, originField);
  }

  // ============================================================================
  // REMPLISSAGE AUTOMATIQUE
  // ============================================================================

  /**
   * Remplit un champ et déclenche les événements appropriés
   * @param {HTMLInputElement} field - Champ à remplir
   * @param {string} value - Valeur à insérer
   */
  function fillField(field, value) {
    if (!field || !value) return;
    if (!isElementVisible(field)) return;

    field.focus();

    // Utiliser le setter natif pour la compatibilité avec React/Angular/Vue
    const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    const nativeSetter = descriptor ? descriptor.set : null;
    if (nativeSetter) {
      nativeSetter.call(field, value);
    } else {
      field.value = value;
    }

    // Événements pour la compatibilité avec les frameworks JS
    field.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }));
    field.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
    // SÉCURITÉ: Pas de keydown/keyup (fingerprint-able par le site, inutile pour les frameworks)
  }

  /**
   * Remplit automatiquement un formulaire avec un identifiant complet
   * Le mot de passe n'est utilisé que le temps du remplissage et n'est pas conservé.
   *
   * @param {Object} credential - Identifiant {name, engine, username, password}
   * @param {HTMLInputElement} [originField] - Champ à l'origine de la sélection
   */
  async function autofillCredentials(credential, originField) {
    if (!credential || typeof credential !== 'object') return;

    // SÉCURITÉ: Bloquer l'autofill sur les pages non HTTPS
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

    // Laisser le temps aux événements focus/blur de se propager avant de réactiver
    setTimeout(() => { isAutofilling = false; }, 200);

    // Surveillance TOTP immédiate (formulaire en une page)
    const totpKeyName = buildTotpKeyName(credential);
    startTotpWatch(totpKeyName);

    // Mémorisation pour TOTP multi-page — SANS mot de passe
    try {
      if (isExtensionContextValid()) {
        await chrome.runtime.sendMessage({
          type: 'SAVE_LAST_CREDENTIAL',
          credential: {
            name: credential.name,
            engine: credential.engine || '',
            totpKey: totpKeyName
          }
        });
      }
    } catch (err) {
      console.warn('[Vault] Erreur mémorisation identifiant:', err.message);
    }
  }

  // ============================================================================
  // GESTION TOTP
  // ============================================================================

  /**
   * Construit le nom de clé TOTP à partir d'un identifiant
   * @param {Object} credential - Identifiant {name, engine}
   * @returns {string} Nom de la clé TOTP
   */
  function buildTotpKeyName(credential) {
    if (!credential || typeof credential.name !== 'string') return '';

    const engineName = (typeof credential.engine === 'string' && credential.engine)
      ? credential.engine
          .replace(/^users\/[^/]+\//i, '')
          .replace(/\/$/, '')
          .toUpperCase()
      : '';

    return engineName ? `${engineName}-${credential.name}` : credential.name;
  }

  /**
   * Récupère et remplit un code TOTP
   * @param {HTMLInputElement} totpField - Champ TOTP
   * @param {string} totpKeyName - Nom de la clé TOTP
   * @returns {Promise<boolean>} True si succès
   */
  async function fillTotpField(totpField, totpKeyName) {
    if (!totpKeyName) return false;

    try {
      if (!isExtensionContextValid()) return false;

      const response = await chrome.runtime.sendMessage({
        type: 'GET_TOTP_CODE',
        keyName: totpKeyName
      });

      if (response && response.success && response.code) {
        fillField(totpField, response.code);
        return true;
      }
      return false;
    } catch (err) {
      console.warn('[Vault TOTP] Erreur:', err.message);
      return false;
    }
  }

  /**
   * Démarre la surveillance des champs TOTP après login.
   * La détection s'appuie sur l'observer DOM global (pas d'observer dédié).
   *
   * @param {string} totpKeyName - Nom de la clé TOTP
   */
  function startTotpWatch(totpKeyName) {
    stopTotpWatch();
    if (!totpKeyName) return;

    totpWatch = {
      totpKeyName,
      attempts: 0,
      failures: 0,
      inFlight: false,
      timeoutId: setTimeout(stopTotpWatch, TOTP_OBSERVER_TIMEOUT_MS)
    };

    checkForTotpFields();
  }

  /**
   * Arrête la surveillance TOTP
   */
  function stopTotpWatch() {
    if (totpWatch) {
      clearTimeout(totpWatch.timeoutId);
      totpWatch = null;
    }
  }

  /**
   * Tente de détecter et remplir un champ TOTP (appelé par l'observer global)
   */
  async function checkForTotpFields() {
    const watch = totpWatch;
    if (!watch || watch.inFlight) return;

    watch.attempts++;
    const totpFields = detectTotpFields();

    if (totpFields.length > 0) {
      watch.inFlight = true;
      let success = false;
      try {
        success = await fillTotpField(totpFields[0], watch.totpKeyName);
      } finally {
        watch.inFlight = false;
      }
      if (totpWatch !== watch) return;
      if (success) {
        stopTotpWatch();
      } else if (++watch.failures >= TOTP_MAX_FILL_FAILURES || watch.attempts >= TOTP_MAX_ATTEMPTS) {
        // Échecs répétés : abandon (pas une demande de code par changement du DOM)
        stopTotpWatch();
      }
    } else if (watch.attempts >= TOTP_MAX_ATTEMPTS && totpWatch === watch) {
      stopTotpWatch();
    }
  }

  /**
   * Vérifie si on est sur une page TOTP (multi-page) et remplit automatiquement
   * à partir de l'identifiant mémorisé par le background ({name, engine, totpKey, hostname, savedAt})
   */
  async function checkForTotpPage() {
    try {
      if (!isExtensionContextValid()) return;
      if (detectTotpFields().length === 0) return;

      const result = await chrome.runtime.sendMessage({ type: 'GET_LAST_CREDENTIAL' });
      if (!result || !result.success || !result.data) return;

      const data = result.data;

      // Double vérification côté content script (le background applique déjà TTL + hostname)
      if (!data.savedAt || Date.now() - data.savedAt > CREDENTIAL_TTL_MS) return;
      if (data.hostname && data.hostname !== window.location.hostname.toLowerCase()) return;

      const totpKeyName = (typeof data.totpKey === 'string' && data.totpKey)
        ? data.totpKey
        : buildTotpKeyName({ name: data.name, engine: data.engine });
      if (!totpKeyName) return;

      await new Promise(resolve => setTimeout(resolve, 500));

      const totpFields = detectTotpFields();
      if (totpFields.length === 0) return;

      const success = await fillTotpField(totpFields[0], totpKeyName);
      if (success) {
        await chrome.runtime.sendMessage({ type: 'CLEAR_LAST_CREDENTIAL' });
      }
    } catch (err) { /* Silencieux */ }
  }

  // ============================================================================
  // COMMUNICATION AVEC LE BACKGROUND SCRIPT
  // ============================================================================

  /**
   * Valide et normalise un résumé d'identifiant reçu du background
   * @param {Object} item - Résumé brut
   * @returns {Object|null} Résumé {name, engine, username} ou null
   */
  function toCredentialSummary(item) {
    if (!item || typeof item !== 'object') return null;
    if (typeof item.name !== 'string' || !item.name) return null;

    return {
      name: item.name,
      engine: typeof item.engine === 'string' ? item.engine : '',
      username: typeof item.username === 'string' ? item.username : ''
    };
  }

  /** Vrai si la liste en cache est encore valable (chargement récent, réussi ou échec très récent) */
  function isCredentialsCacheFresh() {
    return credentialsLoadedAt > 0 &&
      (Date.now() - credentialsLoadedAt) < CREDENTIALS_REFRESH_INTERVAL_MS;
  }

  /**
   * Charge la liste des identifiants (sans mot de passe) pour le site actuel.
   * Le background utilise l'URL de l'onglet comme source de vérité.
   *
   * La liste est mise en cache : elle n'est rechargée que si elle date de plus
   * de CREDENTIALS_REFRESH_INTERVAL_MS, ou si force = true (focus d'un nouveau champ).
   *
   * @param {boolean} force - Forcer le rechargement
   * @returns {Promise<Object[]>} Liste des résumés
   */
  async function loadCredentials(force = false) {
    if (!isExtensionContextValid()) return credentialsList;

    if (!force && isCredentialsCacheFresh()) {
      return credentialsList;
    }

    if (credentialsLoadPromise) {
      return credentialsLoadPromise;
    }

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
          // Raison de l'échec, traduite par le service worker (RDVAULT verrouillé, fermé…)
          if (response && typeof response.error === 'string') loadError = response.error.slice(0, 300);
        }
      } catch (err) {
        credentialsList = [];
      } finally {
        credentialsLoadError = loaded ? '' : (loadError || msg('bgErrUnavailableOrLocked', 'RDVAULT indisponible ou verrouillé'));
        // Un échec (app fermée ou verrouillée, service worker pas prêt, limite de débit, erreur
        // réseau) n'est PAS mis en cache pendant 60 s : seul un chargement réussi l'est. Un échec
        // est retenté après un court délai (voir scheduleCredentialsRetry).
        credentialsLoadedAt = loaded ? Date.now() : (Date.now() - CREDENTIALS_REFRESH_INTERVAL_MS + 3000);
        credentialsLoadFailed = !loaded;
        if (loaded) credentialsRetryIndex = 0;
        credentialsLoadPromise = null;
      }
      return credentialsList;
    })();

    return credentialsLoadPromise;
  }

  // SÉCURITÉ: Nettoyer la liste en mémoire quand la page n'est plus visible
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

  /**
   * Handler de focus sur un champ username : ouvre le menu de sélection.
   * Recharge la liste au premier focus d'un nouveau champ.
   *
   * @param {FocusEvent} e - Événement focus
   */
  function onUsernameFieldFocus(e) {
    // SÉCURITÉ: Ignorer les événements synthétiques
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

  /**
   * Pré-filtre SANS calcul de mise en page : la page (ou la frame) contient-elle au moins un input
   * pouvant être un champ de connexion ? Sinon RDVAULT n'est pas interrogé. Avec all_frames, chaque
   * frame (encarts, widgets) envoyait sinon une requête à son chargement : requêtes inutiles qui
   * épuisent la limite de débit du serveur de sync de l'app (les vraies pages de connexion
   * recevaient alors une erreur), et l'hôte d'une frame sans formulaire n'a pas à être transmis.
   * @returns {boolean}
   */
  function hasPotentialLoginInput() {
    return querySelectorAllDeep(document, 'input').some(input => {
      const type = (input.type || 'text').toLowerCase();
      return type === 'password' || USERNAME_INPUT_TYPES.includes(type);
    });
  }

  /**
   * Programme une nouvelle tentative après un ÉCHEC de chargement de la liste (délais croissants,
   * bornés par CREDENTIALS_RETRY_DELAYS_MS). Cas typique : page de connexion ouverte avant le
   * déverrouillage de RDVAULT ; sans cela, la page ne proposait rien tant que son DOM ne changeait pas.
   * Onglet masqué : rien n'est chargé en arrière-plan (la liste est purgée quand la page est
   * masquée) ; la tentative est reportée au retour de l'onglet au premier plan.
   */
  function scheduleCredentialsRetry() {
    if (credentialsRetryTimer) return;
    if (credentialsRetryIndex >= CREDENTIALS_RETRY_DELAYS_MS.length) return;
    const delay = CREDENTIALS_RETRY_DELAYS_MS[credentialsRetryIndex++];
    credentialsRetryTimer = setTimeout(() => {
      credentialsRetryTimer = null;
      if (!isExtensionContextValid()) return;
      if (document.hidden) {
        document.addEventListener('visibilitychange', () => {
          if (!document.hidden) addAutofillIcons(true);
        }, { once: true });
        return;
      }
      addAutofillIcons(true);
    }, delay);
  }

  /**
   * Ajoute les icônes Vault aux champs détectés
   * @param {boolean} forceReload - Forcer le rechargement de la liste
   */
  async function addAutofillIcons(forceReload = false) {
    cleanupDetachedIcons();

    // Liste en cache encore valable et vide : rien à faire, sans même parcourir le DOM
    if (!forceReload && isCredentialsCacheFresh() && credentialsList.length === 0) return;

    // Aucun champ de saisie possible dans cette frame : ne pas interroger RDVAULT
    if (!hasPotentialLoginInput()) return;

    const credentials = await loadCredentials(forceReload);
    if (credentials.length === 0) {
      // Échec (≠ « aucun identifiant pour ce site ») : nouvelle tentative différée
      if (credentialsLoadFailed) scheduleCredentialsRetry();
      return;
    }

    const { usernameFields, passwordFields } = detectFormFields();

    // Icônes sur les champs password
    passwordFields.forEach(field => {
      if (processedFields.has(field)) return;
      processedFields.add(field);
      createAutofillIcon(field);
      // Ouvrir aussi le menu au focus du champ mot de passe (page mot de passe seule, 2e étape)
      field.addEventListener("focus", onUsernameFieldFocus);
    });

    // Dropdown au focus sur les champs username.
    // Connexion en deux étapes (aucun champ mot de passe visible) : l'icône est
    // aussi placée sur le champ identifiant pour rendre l'auto-remplissage visible.
    const isUsernameOnlyStep = passwordFields.length === 0;
    usernameFields.forEach(field => {
      if (processedFields.has(field)) return;
      processedFields.add(field);
      field.addEventListener('focus', onUsernameFieldFocus);
      if (isUsernameOnlyStep) {
        createAutofillIcon(field);
      }
    });
  }

  /**
   * Programme une analyse de la page (debounce)
   */
  function scheduleScan() {
    if (observerDebounceTimer) clearTimeout(observerDebounceTimer);
    observerDebounceTimer = setTimeout(onDomChanged, OBSERVER_DEBOUNCE_MS);
  }

  /**
   * Traitement (debouncé) des changements de DOM : icônes + TOTP
   */
  function onDomChanged() {
    observerDebounceTimer = null;

    if (!isExtensionContextValid()) return;

    ensureUiRoot();
    addAutofillIcons(false);

    if (totpWatch) {
      checkForTotpFields();
    }
  }

  /**
   * Point d'entrée principal
   */
  function init() {
    ensureUiRoot();

    // Fermeture du dropdown au clic ailleurs.
    // Les clics dans le shadow root fermé sont retargetés sur l'hôte : on les ignore.
    document.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      if (!activeDropdown) return;
      if (uiHost && e.target === uiHost) return;
      removeDropdown();
    }, true);

    // Clavier depuis la page (EXT-22). Les touches pressées DANS le menu (shadow root fermé,
    // cible retargetée sur l'hôte) sont traitées par onMenuKeydown.
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

    // Focus parti ailleurs dans la page (ni le champ du menu, ni l'UI RDVAULT) : menu fermé,
    // il ne reste pas affiché par-dessus la page pendant la navigation au clavier
    document.addEventListener('focusin', (e) => {
      if (!activeDropdown) return;
      if (uiHost && e.target === uiHost) return;
      const target = typeof e.composedPath === 'function' ? e.composedPath()[0] : e.target;
      if (target === activeDropdownField) return;
      removeDropdown();
    }, true);

    // Repositionnement des icônes + nouvelle analyse (champs entrant dans la fenêtre)
    const onViewportChange = () => {
      repositionAllIcons();
      scheduleScan();
    };
    window.addEventListener('scroll', onViewportChange, { passive: true, capture: true });
    window.addEventListener('resize', onViewportChange, { passive: true });

    // Observer DOM GLOBAL unique (formulaires dynamiques, nettoyage, TOTP)
    const domObserver = new MutationObserver(scheduleScan);

    const start = () => {
      addAutofillIcons(false);
      checkForTotpPage();

      const observed = document.documentElement || document.body;
      if (observed) {
        domObserver.observe(observed, { childList: true, subtree: true });
      }
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', start);
    } else {
      start();
    }
  }

  init();
})();
