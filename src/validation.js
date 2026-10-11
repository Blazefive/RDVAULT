// ========================================
// MODULE: Validation et Sanitization
// ========================================
// Fonctions de validation et nettoyage des inputs utilisateur.
//
// Objectifs:
// - Protection contre injections (XSS, Command Injection, Path Traversal)
// - Validation stricte des formats (URLs, emails, paths)
// - Sanitization des données avant affichage/stockage
//
// Sécurité:
// - Whitelist > Blacklist (approche sécuritaire)
// - Validation côté client ET serveur (défense en profondeur)
// - Échappement automatique des caractères dangereux

/**
 * Valide une URL
 *
 * @param {string} url - URL à valider
 * @returns {boolean} true si valide
 */
export function isValidUrl(url) {
  if (!url || typeof url !== 'string') return false;

  // Chemins fichier locaux Windows (ex. C:\dossier, D:/x) et UNC (\\serveur\partage) :
  // supportés par l'UI comme liens (SecretsTable). Un « lettre de lecteur + séparateur »
  // est sans ambiguïté un chemin, pas un schéma dangereux (javascript:, data:…).
  if (/^[a-zA-Z]:[\\/]/.test(url) || /^\\\\/.test(url)) return true;

  try {
    const parsed = new URL(url);
    // Whitelist des protocoles autorisés
    const allowedProtocols = ['http:', 'https:', 'ftp:', 'ftps:', 'ssh:', 'rdp:', 'sftp:'];
    return allowedProtocols.includes(parsed.protocol);
  } catch {
    // Accepter les URLs sans protocole (ex: monserveur.local, 192.168.1.1)
    // SÉCURITÉ: Rejeter si l'input a un schéma non-whitelisté (ex: javascript:)
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
      return false;
    }
    try {
      const parsed = new URL('https://' + url);
      return !!parsed.hostname;
    } catch {
      return false;
    }
  }
}

// ========================================
// MESSAGES TRADUITS (I18N-28)
// ========================================
// Les validateurs dont le message est affiché à l'utilisateur (nom, identifiant, mot de passe)
// renvoient, en plus du texte français historique `error` (conservé tel quel : journaux,
// validateSecret, vaultApi, tests existants), un `code` stable et ses `params`. L'interface
// affiche le message traduit via translateValidationError(résultat, t) : clé `validation.<code>`
// des locales, sauf exceptions ci-dessous (clés qui existaient déjà).
const VALIDATION_MESSAGE_KEYS = {
  nameRequired: 'error.nameRequired',
  notesTooLong: 'error.notesTooLong',
};

/**
 * Clé de traduction d'un code de validation (`validation.<code>`, sauf exceptions ci-dessus).
 * Utilisée aussi par utils/security.js pour traduire les erreurs de validation levées par vaultApi.
 * @param {string} code
 * @returns {string}
 */
export function validationMessageKey(code) {
  return VALIDATION_MESSAGE_KEYS[code] || `validation.${code}`;
}

/** Résultat d'échec : texte historique + code de traduction (+ paramètres éventuels) */
function invalid(error, code, params) {
  return params ? { valid: false, error, code, params } : { valid: false, error, code };
}

/**
 * Message d'erreur d'un résultat de validation dans la langue de l'interface.
 * Repli sur le texte historique `error` si le résultat n'a pas de code ou si la clé manque.
 *
 * @param {Object} result - Résultat d'un validateur ({ valid, error, code?, params? })
 * @param {Function} t - Fonction de traduction (i18n)
 * @returns {string} Message traduit ('' si le résultat est valide)
 */
export function translateValidationError(result, t) {
  if (!result || result.valid) return '';
  if (!result.code || typeof t !== 'function') return result.error || '';
  const key = validationMessageKey(result.code);
  const message = t(key, result.params);
  return message && message !== key ? message : (result.error || '');
}

/**
 * Valide un nom de secret (path Vault)
 *
 * @param {string} name - Nom du secret
 * @returns {Object} { valid: boolean, error?: string, code?: string, params?: Object }
 */
export function validateSecretName(name) {
  if (!name || typeof name !== 'string') {
    return invalid('Le nom est requis', 'nameRequired');
  }

  if (name.length > 512) {
    return invalid('Le nom est trop long (max 512 caractères)', 'nameTooLong', { max: 512 });
  }

  // Interdire les caractères dangereux pour Path Traversal
  // SÉCURITÉ: Vérifier aussi les formes URL-encodées (%2e = '.', %2f = '/', %5c = '\')
  const decoded = (() => {
    try { return decodeURIComponent(name); } catch { return name; }
  })();
  if (decoded.includes('..') || decoded.includes('\\') || name.includes('..') || name.includes('\\')) {
    return invalid('Le nom contient des caractères interdits (.., \\)', 'nameForbiddenChars');
  }

  // Interdire les caractères de contrôle
  // eslint-disable-next-line no-control-regex -- volontaire : détection des caractères de contrôle
  if (/[\x00-\x1F\x7F]/.test(name)) {
    return invalid('Le nom contient des caractères de contrôle', 'nameControlChars');
  }

  return { valid: true };
}

/**
 * Valide un username
 *
 * @param {string} username - Username à valider
 * @returns {Object} { valid: boolean, error?: string, code?: string, params?: Object }
 */
export function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return invalid('Le username est requis', 'usernameRequired');
  }

  if (username.length > 256) {
    return invalid('Le username est trop long (max 256 caractères)', 'usernameTooLong', { max: 256 });
  }

  // Interdire uniquement les caractères de contrôle. Les apostrophes/guillemets sont
  // autorisés : des identifiants légitimes en contiennent (O'Brien, d'Artagnan, certains
  // emails/logins), et la valeur est stockée via requête paramétrée + chiffrée + JSON
  // (aucun risque d'injection), puis saisie telle quelle par l'autofill.
  // eslint-disable-next-line no-control-regex -- volontaire : détection des caractères de contrôle
  if (/[\x00-\x1F\x7F]/.test(username)) {
    return invalid('Le username contient des caractères de contrôle', 'usernameControlChars');
  }

  return { valid: true };
}

/**
 * Valide un password
 *
 * @param {string} password - Password à valider
 * @returns {Object} { valid: boolean, error?: string, code?: string, params?: Object }
 */
export function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return invalid('Le mot de passe est requis', 'passwordRequired');
  }

  if (password.length > 1024) {
    return invalid('Le mot de passe est trop long (max 1024 caractères)', 'passwordTooLong', { max: 1024 });
  }

  // Interdire uniquement les caractères de contrôle (permettre tous les symboles)
  // eslint-disable-next-line no-control-regex -- volontaire : détection des caractères de contrôle
  if (/[\x00-\x1F\x7F]/.test(password)) {
    return invalid('Le mot de passe contient des caractères de contrôle', 'passwordControlChars');
  }

  return { valid: true };
}

/**
 * Valide une adresse email
 *
 * @param {string} email - Email à valider
 * @returns {boolean} true si valide
 */
export function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;

  // Regex simple mais robuste pour emails
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 320;
}

/**
 * Valide une clé TOTP (format base32)
 *
 * @param {string} secret - Clé TOTP à valider
 * @returns {Object} { valid: boolean, error?: string, code?: string, params?: Object }
 */
export function validateTotpSecret(secret) {
  if (!secret || typeof secret !== 'string') {
    return invalid('La clé TOTP est requise', 'totpRequired');
  }

  if (secret.length > 256) {
    return invalid('La clé TOTP est trop longue (max 256 caractères)', 'totpTooLong', { max: 256 });
  }

  // Base32: A-Z, 2-7, padding = optionnel
  if (!/^[A-Z2-7]+=*$/.test(secret)) {
    return invalid('La clé TOTP doit être en format base32 (A-Z, 2-7)', 'totpFormat');
  }

  return { valid: true };
}

/**
 * Valide un hostname (SSH, RDP, etc.)
 *
 * @param {string} host - Hostname ou IP à valider
 * @returns {boolean} true si valide
 */
export function isValidHostname(host) {
  if (!host || typeof host !== 'string') return false;

  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(host)) {
    const parts = host.split('.');
    return parts.every(part => parseInt(part, 10) <= 255);
  }

  // IPv6
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Regex.test(host)) {
    return true;
  }

  // Hostname (DNS)
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return hostnameRegex.test(host) && host.length <= 253;
}

/**
 * Valide un port (1-65535)
 *
 * @param {string|number} port - Port à valider
 * @returns {boolean} true si valide
 */
export function isValidPort(port) {
  const portNum = typeof port === 'string' ? parseInt(port, 10) : port;
  return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
}

/**
 * Nettoie un texte pour affichage (échappe HTML)
 *
 * @param {string} text - Texte à nettoyer
 * @returns {string} Texte nettoyé
 */
export function sanitizeForDisplay(text) {
  if (!text || typeof text !== 'string') return '';

  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Valide un path de fichier (pour audit logs SSH)
 *
 * @param {string} filePath - Path à valider
 * @returns {Object} { valid: boolean, error: string }
 */
export function validateFilePath(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    return { valid: false, error: 'Le chemin de fichier est requis' };
  }

  // Whitelist: uniquement /var/log/vault/*
  if (!filePath.startsWith('/var/log/vault/')) {
    return {
      valid: false,
      error: 'Chemin non autorisé (seuls /var/log/vault/* sont autorisés)'
    };
  }

  // Interdire Path Traversal (y compris formes URL-encodées)
  const decodedPath = (() => {
    try { return decodeURIComponent(filePath); } catch { return filePath; }
  })();
  if (decodedPath.includes('..') || decodedPath.includes('~') || filePath.includes('..') || filePath.includes('~')) {
    return { valid: false, error: 'Le chemin contient des séquences interdites (.., ~)' };
  }

  // Interdire caractères de contrôle et null bytes
  // eslint-disable-next-line no-control-regex -- volontaire : détection des caractères de contrôle et octets nuls
  if (/[\x00-\x1F\x7F]/.test(filePath)) {
    return { valid: false, error: 'Le chemin contient des caractères de contrôle' };
  }

  return { valid: true };
}

/**
 * Valide des credentials SSH
 *
 * @param {Object} config - { host, username, password, port }
 * @returns {Object} { valid: boolean, errors: Object }
 */
export function validateSshConfig(config) {
  const errors = {};

  if (!isValidHostname(config.host)) {
    errors.host = 'Hostname invalide';
  }

  if (!config.username || config.username.length > 256) {
    errors.username = 'Username requis (max 256 caractères)';
  } else if (!/^[a-zA-Z0-9._@-]+$/.test(config.username)) {
    errors.username = 'Username contient des caractères non autorisés';
  }

  if (config.port && !isValidPort(config.port)) {
    errors.port = 'Port invalide (1-65535)';
  }

  return {
    valid: Object.keys(errors).length === 0,
    errors
  };
}

/**
 * Limite la longueur d'une chaîne (truncate)
 *
 * @param {string} str - Chaîne à limiter
 * @param {number} maxLength - Longueur maximale
 * @returns {string} Chaîne tronquée
 */
export function truncate(str, maxLength = 1000) {
  if (!str || typeof str !== 'string') return '';
  return str.length > maxLength ? str.slice(0, maxLength) : str;
}

/**
 * Valide un objet de secret complet
 *
 * @param {Object} secret - Secret à valider
 * @returns {Object} { valid: boolean, errors: Object, codes?: Object }
 *   errors : texte français historique par champ (journaux, tests existants) ;
 *   codes  : (si invalide) { champ: { code, params? } } pour un message traduit (validationMessageKey)
 */
export function validateSecret(secret) {
  const errors = {};
  const codes = {};
  // Enregistre l'échec d'un champ : texte historique + code de traduction
  const fail = (field, result) => {
    errors[field] = result.error;
    if (result.code) codes[field] = result.params ? { code: result.code, params: result.params } : { code: result.code };
  };

  // Nom
  const nameValidation = validateSecretName(secret.name);
  if (!nameValidation.valid) {
    fail('name', nameValidation);
  }

  // Username
  if (secret.username) {
    const usernameValidation = validateUsername(secret.username);
    if (!usernameValidation.valid) {
      fail('username', usernameValidation);
    }
  }

  // Password
  if (secret.password) {
    const passwordValidation = validatePassword(secret.password);
    if (!passwordValidation.valid) {
      fail('password', passwordValidation);
    }
  }

  // URL
  if (secret.url && !isValidUrl(secret.url)) {
    fail('url', invalid('URL invalide', 'urlInvalid'));
  }

  // TOTP Secret
  if (secret.totpSecret) {
    const totpValidation = validateTotpSecret(secret.totpSecret);
    if (!totpValidation.valid) {
      fail('totpSecret', totpValidation);
    }
  }

  // Notes (limiter longueur)
  if (secret.notes && secret.notes.length > 10000) {
    fail('notes', invalid('Notes trop longues (max 10000 caractères)', 'notesTooLong', { max: 10000 }));
  }

  // Forme historique conservée pour un secret valide ({ valid: true, errors: {} })
  return Object.keys(errors).length === 0
    ? { valid: true, errors }
    : { valid: false, errors, codes };
}
