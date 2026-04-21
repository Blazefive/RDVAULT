/**
 * content.js - Script de contenu pour Vault Autofill
 *
 * Ce script détecte et remplit automatiquement les formulaires de connexion
 * avec les credentials stockés dans HashiCorp Vault via l'application Desktop.
 *
 * Fonctionnalités :
 * - Détection intelligente des champs (username, password, TOTP)
 * - Scoring de confiance pour une meilleure précision
 * - Support des formulaires dynamiques (SPA)
 * - Support des Shadow DOM
 * - Gestion sécurisée des données sensibles
 *
 * @author Vault Autofill Team
 * @version 2.0.0
 */

(function() {
  'use strict';

  // ============================================================================
  // CONFIGURATION
  // ============================================================================

  /** Délai de debounce pour l'observer DOM (ms) */
  const OBSERVER_DEBOUNCE_MS = 300;

  /** Durée maximale de validité d'un credential sauvegardé pour TOTP (ms) */
  const CREDENTIAL_TTL_MS = 300000; // 5 minutes

  /** Timeout pour la détection TOTP après login (ms) */
  const TOTP_OBSERVER_TIMEOUT_MS = 20000;

  /** Score minimum pour considérer un champ comme valide */
  const MIN_CONFIDENCE_SCORE = 2;

  // ============================================================================
  // ÉTAT GLOBAL
  // ============================================================================

  /** Liste des credentials disponibles pour le site actuel */
  let credentialsList = [];
  let credentialsLoadedAt = 0;
  const CREDENTIALS_MEMORY_TTL_MS = 120000; // 2 minutes max en mémoire

  /** Référence au dropdown actif */
  let activeDropdown = null;
  let isAutofilling = false;

  /** Observer pour la détection TOTP */
  let totpObserver = null;

  /** Timer pour le debounce de l'observer DOM */
  let observerDebounceTimer = null;

  /** Set des champs déjà traités (évite les doublons) */
  const processedFields = new WeakSet();

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
  // STYLES CSS
  // ============================================================================

  /**
   * Styles CSS injectés dans la page
   * Utilise des sélecteurs spécifiques pour éviter les conflits
   */
  const STYLES = `
    .vault-autofill-icon {
      position: fixed !important;
      width: 20px !important;
      height: 20px !important;
      min-width: 20px !important;
      max-width: 20px !important;
      min-height: 20px !important;
      max-height: 20px !important;
      cursor: pointer !important;
      background: #3b82f6 !important;
      border-radius: 4px !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-size: 12px !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      color: white !important;
      font-weight: bold !important;
      z-index: 2147483647 !important;
      user-select: none !important;
      box-shadow: 0 2px 4px rgba(0,0,0,0.2) !important;
      flex-shrink: 0 !important;
      flex-grow: 0 !important;
      pointer-events: auto !important;
      transition: background-color 0.15s ease !important;
    }

    .vault-autofill-icon:hover {
      background: #2563eb !important;
    }

    .vault-autofill-dropdown {
      position: fixed !important;
      background: white !important;
      border: 1px solid #d1d5db !important;
      border-radius: 8px !important;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15) !important;
      z-index: 2147483647 !important;
      min-width: 280px !important;
      max-width: 400px !important;
      max-height: 320px !important;
      overflow-y: auto !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    }

    .vault-autofill-header {
      padding: 10px 12px !important;
      border-bottom: 1px solid #e5e7eb !important;
      background: #f9fafb !important;
      font-size: 11px !important;
      color: #6b7280 !important;
      font-weight: 600 !important;
      text-transform: uppercase !important;
      letter-spacing: 0.5px !important;
    }

    .vault-autofill-item {
      padding: 12px !important;
      cursor: pointer !important;
      border-bottom: 1px solid #f3f4f6 !important;
      transition: background-color 0.1s ease !important;
    }

    .vault-autofill-item:last-child {
      border-bottom: none !important;
    }

    .vault-autofill-item:hover {
      background: #f3f4f6 !important;
    }

    .vault-autofill-item-name {
      font-weight: 600 !important;
      font-size: 14px !important;
      color: #111827 !important;
      margin-bottom: 4px !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
      white-space: nowrap !important;
    }

    .vault-autofill-item-username {
      font-size: 12px !important;
      color: #6b7280 !important;
      overflow: hidden !important;
      text-overflow: ellipsis !important;
      white-space: nowrap !important;
    }

    .vault-autofill-no-results {
      padding: 16px !important;
      text-align: center !important;
      color: #9ca3af !important;
      font-size: 13px !important;
    }

    .vault-autofill-loading {
      padding: 16px !important;
      text-align: center !important;
      color: #3b82f6 !important;
      font-size: 13px !important;
    }
  `;

  // ============================================================================
  // UTILITAIRES DE SÉCURITÉ
  // ============================================================================

  /**
   * Échappe les caractères HTML pour prévenir les attaques XSS
   * @param {string} text - Texte à échapper
   * @returns {string} Texte échappé sécurisé
   */
  function escapeHtml(text) {
    if (!text || typeof text !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
      } else if (key.startsWith('on') && typeof value === 'function') {
        element.addEventListener(key.slice(2).toLowerCase(), value);
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

  // ============================================================================
  // UTILITAIRES DE DÉTECTION
  // ============================================================================

  /**
   * Vérifie si un élément est visible dans le DOM
   * @param {HTMLElement} element - Élément à vérifier
   * @returns {boolean} True si l'élément est visible
   */
  function isElementVisible(element) {
    if (!element) return false;
    if (element.type === 'hidden') return false;
    if (element.disabled) return false;
    if (element.readOnly) return false;

    if (element.offsetParent === null && element.style.position !== 'fixed') {
      return false;
    }

    const rect = element.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;

    const style = window.getComputedStyle(element);
    if (style.display === 'none') return false;
    if (style.visibility === 'hidden') return false;
    if (parseFloat(style.opacity) === 0) return false;

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

    // Label avec attribut 'for'
    if (field.id) {
      try {
        const label = document.querySelector(`label[for="${CSS.escape(field.id)}"]`);
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
      const labelElement = document.getElementById(labelledBy);
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
      current = current.parentElement;
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
  function calculateFieldScore(field, patterns) {
    let score = 0;

    const name = (field.name || '').toLowerCase();
    const id = (field.id || '').toLowerCase();
    const autocomplete = (field.autocomplete || '').toLowerCase();
    const labelText = getFieldLabelText(field);
    const classes = getElementClasses(field);

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

    // Name/ID contient le pattern (score moyen)
    for (const pattern of patterns.nameId || []) {
      if (name.includes(pattern) || id.includes(pattern)) {
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
   * Détermine si un formulaire est de type connexion (vs inscription)
   * @param {HTMLFormElement} form - Formulaire à analyser
   * @returns {boolean} True si c'est un formulaire de connexion
   */
  function isLoginForm(form) {
    if (!form) return true;

    const formText = [
      form.id || '',
      form.name || '',
      form.className || '',
      form.action || ''
    ].join(' ').toLowerCase();

    // Vérifier les indicateurs d'inscription (prioritaire)
    for (const indicator of SIGNUP_FORM_INDICATORS) {
      if (formText.includes(indicator)) return false;
    }

    // Vérifier les indicateurs de connexion
    for (const indicator of LOGIN_FORM_INDICATORS) {
      if (formText.includes(indicator)) return true;
    }

    // Heuristique : plus de 1 champ password = probablement inscription
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 1) return false;

    return true;
  }

  /**
   * Recherche récursivement dans les Shadow DOM
   * @param {Element} root - Élément racine
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
   * Détecte tous les champs de formulaire pertinents sur la page
   * Utilise un système de scoring pour une détection précise
   *
   * @returns {Object} Objet contenant usernameFields et passwordFields
   */
  function detectFormFields() {
    const usernameFields = [];
    const passwordFields = [];

    const allInputs = querySelectorAllDeep(document, 'input');

    for (const input of allInputs) {
      if (!isElementVisible(input)) continue;

      const form = input.closest('form');
      if (form && !isLoginForm(form)) continue;

      const type = (input.type || 'text').toLowerCase();

      // Champs password
      if (type === 'password') {
        const score = calculateFieldScore(input, PASSWORD_PATTERNS);
        // Les champs password sont toujours considérés (type explicite)
        passwordFields.push({ field: input, score: score || 5 });
        continue;
      }

      // Champs username/email
      if (['text', 'email', 'tel'].includes(type)) {
        const score = calculateFieldScore(input, USERNAME_PATTERNS);
        if (score >= MIN_CONFIDENCE_SCORE) {
          usernameFields.push({ field: input, score });
        }
      }
    }

    // Trier par score décroissant
    usernameFields.sort((a, b) => b.score - a.score);
    passwordFields.sort((a, b) => b.score - a.score);

    return {
      usernameFields: usernameFields.map(f => f.field),
      passwordFields: passwordFields.map(f => f.field)
    };
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
  // GESTION DE L'INTERFACE UTILISATEUR
  // ============================================================================

  /**
   * Injecte les styles CSS dans la page (une seule fois)
   */
  function injectStyles() {
    if (document.getElementById('vault-autofill-styles')) return;

    const styleSheet = createElement('style', { id: 'vault-autofill-styles' }, STYLES);
    document.head.appendChild(styleSheet);
  }

  /**
   * Crée l'icône Vault sur un champ de formulaire
   * @param {HTMLInputElement} field - Champ cible
   * @returns {HTMLElement} L'icône créée
   */
  function createAutofillIcon(field) {
    const existingIconId = field.dataset.vaultIconId;
    if (existingIconId) {
      const existingIcon = document.getElementById(existingIconId);
      if (existingIcon) return existingIcon;
    }

    const iconId = `vault-icon-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    const icon = createElement('div', {
      id: iconId,
      className: 'vault-autofill-icon',
      title: 'Auto-remplir avec Vault'
    }, 'V');

    field.dataset.vaultIconId = iconId;
    document.body.appendChild(icon);

    // Fonction de positionnement
    function positionIcon() {
      const rect = field.getBoundingClientRect();

      if (rect.width === 0 || rect.height === 0) {
        icon.style.display = 'none';
        return;
      }

      icon.style.display = 'flex';
      icon.style.top = `${rect.top + (rect.height - 20) / 2}px`;
      icon.style.left = `${rect.right - 28}px`;
    }

    positionIcon();

    // Listeners pour repositionnement
    const scrollHandler = () => positionIcon();
    const resizeHandler = () => positionIcon();

    window.addEventListener('scroll', scrollHandler, { passive: true, capture: true });
    window.addEventListener('resize', resizeHandler, { passive: true });

    // Nettoyage si le champ est supprimé
    const cleanupObserver = new MutationObserver(() => {
      if (!document.contains(field)) {
        icon.remove();
        cleanupObserver.disconnect();
        window.removeEventListener('scroll', scrollHandler, { capture: true });
        window.removeEventListener('resize', resizeHandler);
      }
    });

    cleanupObserver.observe(document.body, { childList: true, subtree: true });

    return icon;
  }

  /**
   * Crée le dropdown de sélection des credentials
   * @param {HTMLInputElement} field - Champ de référence pour positionnement
   * @param {Object[]} credentials - Liste des credentials
   * @returns {HTMLElement} Le dropdown créé
   */
  function createDropdown(field, credentials) {
    removeDropdown();

    const dropdown = createElement('div', { className: 'vault-autofill-dropdown' });

    // En-tête
    const header = createElement('div', { className: 'vault-autofill-header' }, 'Vault Credentials');
    dropdown.appendChild(header);

    if (!credentials || credentials.length === 0) {
      const noResults = createElement('div', { className: 'vault-autofill-no-results' },
        'Aucun identifiant trouvé pour ce site'
      );
      dropdown.appendChild(noResults);
    } else {
      credentials.forEach(cred => {
        const item = createElement('div', { className: 'vault-autofill-item' });

        const name = createElement('div', { className: 'vault-autofill-item-name' },
          cred.name || 'Sans nom'
        );

        const username = createElement('div', { className: 'vault-autofill-item-username' },
          cred.username || '(pas de username)'
        );

        item.appendChild(name);
        item.appendChild(username);

        item.addEventListener('click', async () => {
          removeDropdown();
          await autofillCredentials(cred);
        });

        dropdown.appendChild(item);
      });
    }

    document.body.appendChild(dropdown);

    // Positionnement
    const rect = field.getBoundingClientRect();
    dropdown.style.top = `${rect.bottom + 4}px`;
    dropdown.style.left = `${rect.left}px`;
    dropdown.style.minWidth = `${Math.max(rect.width, 280)}px`;

    // Ajustement si débordement
    const dropdownRect = dropdown.getBoundingClientRect();
    if (dropdownRect.bottom > window.innerHeight) {
      dropdown.style.top = `${rect.top - dropdownRect.height - 4}px`;
    }
    if (dropdownRect.right > window.innerWidth) {
      dropdown.style.left = `${window.innerWidth - dropdownRect.width - 8}px`;
    }

    activeDropdown = dropdown;
    return dropdown;
  }

  /**
   * Supprime le dropdown actif
   */
  function removeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
    }
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

    field.focus();

    // Utiliser le setter natif pour la compatibilité avec React/Angular/Vue
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;
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
   * Remplit automatiquement un formulaire avec des credentials
   * @param {Object} credentials - Credentials à utiliser
   */
  async function autofillCredentials(credentials) {
    if (!credentials) return;

    // SÉCURITÉ: Bloquer l'autofill sur les pages HTTP (credentials en clair sur le réseau)
    if (window.location.protocol !== 'https:') {
      console.warn('[Vault] Autofill bloqué : page non HTTPS');
      return;
    }

    isAutofilling = true;

    const { usernameFields, passwordFields } = detectFormFields();

    if (usernameFields.length > 0 && credentials.username) {
      fillField(usernameFields[0], credentials.username);
    }

    if (passwordFields.length > 0 && credentials.password) {
      fillField(passwordFields[0], credentials.password);
    }

    // Laisser le temps aux événements focus/blur de se propager avant de réactiver
    setTimeout(() => { isAutofilling = false; }, 200);

    // Démarrer l'observer TOTP immédiatement (avant le await) pour ne pas rater le champ
    startTotpObserver(credentials);

    // Sauvegarder pour TOTP multi-page (async, ne bloque pas l'observer)
    try {
      await chrome.runtime.sendMessage({
        type: 'SAVE_LAST_CREDENTIAL',
        credential: credentials,
        url: window.location.hostname
      });
    } catch (err) {
      console.warn('[Vault] Erreur sauvegarde credential:', err.message);
    }
  }

  // ============================================================================
  // GESTION TOTP
  // ============================================================================

  /**
   * Construit le nom de clé TOTP à partir des credentials
   * @param {Object} credentials - Credentials source
   * @returns {string} Nom de la clé TOTP
   */
  function buildTotpKeyName(credentials) {
    const engineName = credentials.engine
      ? credentials.engine
          .replace(/^users\/[^/]+\//i, '')
          .replace(/\/$/, '')
          .toUpperCase()
      : '';

    return engineName ? `${engineName}-${credentials.name}` : credentials.name;
  }

  /**
   * Récupère et remplit un code TOTP
   * @param {HTMLInputElement} totpField - Champ TOTP
   * @param {Object} credentials - Credentials associés
   * @returns {Promise<boolean>} True si succès
   */
  async function fillTotpField(totpField, credentials) {
    const totpKeyName = buildTotpKeyName(credentials);

    try {
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
   * Démarre l'observer pour détecter les champs TOTP dynamiques
   * @param {Object} credentials - Credentials pour le TOTP
   */
  function startTotpObserver(credentials) {
    if (totpObserver) {
      totpObserver.disconnect();
      totpObserver = null;
    }

    let attempts = 0;
    const maxAttempts = 40;

    const checkForTotpFields = async () => {
      attempts++;
      const totpFields = detectTotpFields();

      if (totpFields.length > 0) {
        const success = await fillTotpField(totpFields[0], credentials);
        if (success && totpObserver) {
          totpObserver.disconnect();
          totpObserver = null;
        }
      } else if (attempts >= maxAttempts && totpObserver) {
        totpObserver.disconnect();
        totpObserver = null;
      }
    };

    checkForTotpFields();

    totpObserver = new MutationObserver(() => {
      setTimeout(checkForTotpFields, 100);
    });

    totpObserver.observe(document.body, { childList: true, subtree: true });

    setTimeout(() => {
      if (totpObserver) {
        totpObserver.disconnect();
        totpObserver = null;
      }
    }, TOTP_OBSERVER_TIMEOUT_MS);
  }

  /**
   * Vérifie si on est sur une page TOTP et remplit automatiquement
   */
  async function checkForTotpPage() {
    try {
      const totpFields = detectTotpFields();
      if (totpFields.length === 0) return;

      const result = await chrome.runtime.sendMessage({ type: 'GET_LAST_CREDENTIAL' });

      if (!result || !result.success || !result.data) return;

      const { credential, timestamp, url } = result.data;

      // Vérifier validité
      if (Date.now() - timestamp > CREDENTIAL_TTL_MS) return;
      if (url !== window.location.hostname) return;

      await new Promise(resolve => setTimeout(resolve, 500));
      await fillTotpField(totpFields[0], credential);
      await chrome.runtime.sendMessage({ type: 'CLEAR_LAST_CREDENTIAL' });
    } catch (err) { /* Silencieux */ }
  }

  // ============================================================================
  // COMMUNICATION AVEC LE BACKGROUND SCRIPT
  // ============================================================================

  /**
   * Charge les credentials pour l'URL actuelle
   * @returns {Promise<Object[]>} Liste des credentials
   */
  async function loadCredentials() {
    try {
      if (!chrome.runtime || !chrome.runtime.id) return [];

      const response = await chrome.runtime.sendMessage({
        type: 'GET_CREDENTIALS',
        url: window.location.href
      });

      if (response && response.success) {
        credentialsList = response.credentials || [];
        credentialsLoadedAt = Date.now();
        return credentialsList;
      }
      return [];
    } catch (err) {
      return [];
    }
  }

  // SÉCURITÉ: Nettoyer les credentials en mémoire quand la page n'est plus visible
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      credentialsList = [];
      credentialsLoadedAt = 0;
    }
  });

  // ============================================================================
  // INITIALISATION
  // ============================================================================

  /**
   * Ajoute les icônes Vault aux champs détectés
   */
  async function addAutofillIcons() {
    const { usernameFields, passwordFields } = detectFormFields();
    const credentials = await loadCredentials();

    if (credentials.length === 0) return;

    // Icônes sur les champs password
    passwordFields.forEach(field => {
      if (processedFields.has(field)) return;
      processedFields.add(field);

      const icon = createAutofillIcon(field);
      icon.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        createDropdown(field, credentials);
      });
    });

    // Dropdown au focus sur les champs username
    usernameFields.forEach(field => {
      if (processedFields.has(field)) return;
      processedFields.add(field);

      field.addEventListener('focus', () => {
        if (isAutofilling) return;
        setTimeout(() => {
          if (isAutofilling) return;
          createDropdown(field, credentials);
        }, 50);
      });
    });
  }

  /**
   * Point d'entrée principal
   */
  function init() {
    injectStyles();

    // Fermeture du dropdown au clic ailleurs
    document.addEventListener('click', (e) => {
      if (activeDropdown && !activeDropdown.contains(e.target)) {
        const icon = e.target.closest('.vault-autofill-icon');
        if (!icon) removeDropdown();
      }
    });

    // Fermeture du dropdown avec Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && activeDropdown) {
        removeDropdown();
      }
    });

    // Observer pour formulaires dynamiques (SPA)
    const domObserver = new MutationObserver(() => {
      if (observerDebounceTimer) clearTimeout(observerDebounceTimer);
      observerDebounceTimer = setTimeout(addAutofillIcons, OBSERVER_DEBOUNCE_MS);
    });

    const start = () => {
      addAutofillIcons();
      checkForTotpPage();

      if (document.body) {
        domObserver.observe(document.body, { childList: true, subtree: true });
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
