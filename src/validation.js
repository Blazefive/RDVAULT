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

/**
 * Valide un nom de secret (path Vault)
 *
 * @param {string} name - Nom du secret
 * @returns {Object} { valid: boolean, error: string }
 */
export function validateSecretName(name) {
  if (!name || typeof name !== 'string') {
    return { valid: false, error: 'Le nom est requis' };
  }

  if (name.length > 512) {
    return { valid: false, error: 'Le nom est trop long (max 512 caractères)' };
  }

  // Interdire les caractères dangereux pour Path Traversal
  // SÉCURITÉ: Vérifier aussi les formes URL-encodées (%2e = '.', %2f = '/', %5c = '\')
  const decoded = (() => {
    try { return decodeURIComponent(name); } catch { return name; }
  })();
  if (decoded.includes('..') || decoded.includes('\\') || name.includes('..') || name.includes('\\')) {
    return { valid: false, error: 'Le nom contient des caractères interdits (.., \\)' };
  }

  // Interdire les caractères de contrôle
  if (/[\x00-\x1F\x7F]/.test(name)) {
    return { valid: false, error: 'Le nom contient des caractères de contrôle' };
  }

  return { valid: true };
}

/**
 * Valide un username
 *
 * @param {string} username - Username à valider
 * @returns {Object} { valid: boolean, error: string }
 */
export function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Le username est requis' };
  }

  if (username.length > 256) {
    return { valid: false, error: 'Le username est trop long (max 256 caractères)' };
  }

  // Interdire les caractères de contrôle et quotes
  if (/[\x00-\x1F\x7F"'`]/.test(username)) {
    return { valid: false, error: 'Le username contient des caractères interdits' };
  }

  return { valid: true };
}

/**
 * Valide un password
 *
 * @param {string} password - Password à valider
 * @returns {Object} { valid: boolean, error: string }
 */
export function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Le mot de passe est requis' };
  }

  if (password.length > 1024) {
    return { valid: false, error: 'Le mot de passe est trop long (max 1024 caractères)' };
  }

  // Interdire uniquement les caractères de contrôle (permettre tous les symboles)
  if (/[\x00-\x1F\x7F]/.test(password)) {
    return { valid: false, error: 'Le mot de passe contient des caractères de contrôle' };
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
 * @returns {Object} { valid: boolean, error: string }
 */
export function validateTotpSecret(secret) {
  if (!secret || typeof secret !== 'string') {
    return { valid: false, error: 'La clé TOTP est requise' };
  }

  if (secret.length > 256) {
    return { valid: false, error: 'La clé TOTP est trop longue (max 256 caractères)' };
  }

  // Base32: A-Z, 2-7, padding = optionnel
  if (!/^[A-Z2-7]+=*$/.test(secret)) {
    return { valid: false, error: 'La clé TOTP doit être en format base32 (A-Z, 2-7)' };
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
 * @returns {Object} { valid: boolean, errors: Object }
 */
export function validateSecret(secret) {
  const errors = {};

  // Nom
  const nameValidation = validateSecretName(secret.name);
  if (!nameValidation.valid) {
    errors.name = nameValidation.error;
  }

  // Username
  if (secret.username) {
    const usernameValidation = validateUsername(secret.username);
    if (!usernameValidation.valid) {
      errors.username = usernameValidation.error;
    }
  }

  // Password
  if (secret.password) {
    const passwordValidation = validatePassword(secret.password);
    if (!passwordValidation.valid) {
      errors.password = passwordValidation.error;
    }
  }

  // URL
  if (secret.url && !isValidUrl(secret.url)) {
    errors.url = 'URL invalide';
  }

  // TOTP Secret
  if (secret.totpSecret) {
    const totpValidation = validateTotpSecret(secret.totpSecret);
    if (!totpValidation.valid) {
      errors.totpSecret = totpValidation.error;
    }
  }

  // Notes (limiter longueur)
  if (secret.notes && secret.notes.length > 10000) {
    errors.notes = 'Notes trop longues (max 10000 caractères)';
  }

  return {
    valid: Object.keys(errors).length === 0,
    errors
  };
}
