// ========================================
// MODULE: Secure Logging
// ========================================
// Système de logging qui masque automatiquement les données sensibles.
//
// Objectifs:
// - Éviter le logging de tokens, passwords, secrets
// - Permettre le debugging sans compromettre la sécurité
// - Masquer automatiquement les patterns sensibles
//
// Sécurité:
// - Détection automatique de tokens (hvs., Bearer, X-Vault-Token)
// - Masquage des passwords et secrets
// - Troncature des données longues

/**
 * Patterns de données sensibles à masquer
 */
const SENSITIVE_PATTERNS = [
  // Tokens Vault (longueur variable selon la config Vault)
  { regex: /hvs\.[A-Za-z0-9_-]{20,}/g, replacement: 'hvs.***MASKED***' },
  { regex: /hcp\.[A-Za-z0-9_-]{20,}/g, replacement: 'hcp.***MASKED***' },

  // Headers d'authentification
  { regex: /X-Vault-Token:\s*[^\s]+/gi, replacement: 'X-Vault-Token: ***MASKED***' },
  { regex: /Authorization:\s*Bearer\s+[^\s]+/gi, replacement: 'Authorization: Bearer ***MASKED***' },

  // Passwords dans JSON (y compris avec quotes échappées)
  { regex: /"password"\s*:\s*"(?:[^"\\]|\\.)*"/gi, replacement: '"password": "***MASKED***"' },
  { regex: /'password'\s*:\s*'(?:[^'\\]|\\.)*'/gi, replacement: "'password': '***MASKED***'" },

  // Secrets TOTP (base32)
  { regex: /"totpSecret"\s*:\s*"[A-Z2-7]{16,}"/gi, replacement: '"totpSecret": "***MASKED***"' },

  // Clés SSH privées (format PEM natif et JSON-escaped avec \\n)
  { regex: /-----BEGIN [A-Z\s]+ PRIVATE KEY-----(?:\\n|[\s\S])+?-----END [A-Z\s]+ PRIVATE KEY-----/g, replacement: '-----BEGIN PRIVATE KEY-----***MASKED***-----END PRIVATE KEY-----' },

  // URLs avec credentials
  { regex: /([a-z]+:\/\/)([^:]+):([^@]+)@/gi, replacement: '$1***:***@' },

  // Tokens Vault legacy (s.xxx)
  { regex: /\bs\.[A-Za-z0-9_-]{20,}\b/g, replacement: 's.***MASKED***' },

  // Clés AWS (AKIA...)
  { regex: /\bAKIA[A-Z0-9]{16}\b/g, replacement: 'AKIA***MASKED***' },

  // Connection strings avec mots de passe embarqués (mongodb://, postgresql://, mysql://, etc.)
  { regex: /([a-z]+:\/\/[^:]+):([^@\s]+)@[^\s]+/gi, replacement: '$1:***@***MASKED***' },
];

/**
 * Clés d'objet sensibles à masquer
 */
const SENSITIVE_KEYS = [
  'password',
  'token',
  'secret',
  'apiKey',
  'privateKey',
  'clientSecret',
  'totpSecret',
  'sshPrivateKey',
  'auth_token',
  'client_token',
  'accessor',
];

/**
 * Masque les données sensibles dans une chaîne
 *
 * @param {string} text - Texte à masquer
 * @returns {string} Texte masqué
 */
function maskSensitiveData(text) {
  if (typeof text !== 'string') return text;

  let masked = text;

  // Appliquer tous les patterns
  SENSITIVE_PATTERNS.forEach(({ regex, replacement }) => {
    masked = masked.replace(regex, replacement);
  });

  return masked;
}

/**
 * Masque les valeurs sensibles dans un objet
 *
 * @param {any} obj - Objet à masquer
 * @param {number} depth - Profondeur de récursion actuelle
 * @param {number} maxDepth - Profondeur maximale
 * @returns {any} Objet masqué
 */
function maskObject(obj, depth = 0, maxDepth = 5) {
  // Limite de profondeur pour éviter récursion infinie
  if (depth > maxDepth) return '[MAX_DEPTH_REACHED]';

  if (obj === null || obj === undefined) return obj;

  // Primitives
  if (typeof obj === 'string') {
    return maskSensitiveData(obj);
  }

  if (typeof obj === 'number' || typeof obj === 'boolean') {
    return obj;
  }

  // Arrays
  if (Array.isArray(obj)) {
    return obj.map(item => maskObject(item, depth + 1, maxDepth));
  }

  // Objects
  if (typeof obj === 'object') {
    const masked = {};

    for (const [key, value] of Object.entries(obj)) {
      // Masquer complètement les clés sensibles
      if (SENSITIVE_KEYS.some(sk => key.toLowerCase().includes(sk.toLowerCase()))) {
        masked[key] = '***MASKED***';
      } else {
        masked[key] = maskObject(value, depth + 1, maxDepth);
      }
    }

    return masked;
  }

  return obj;
}

/**
 * Tronque les textes très longs
 *
 * @param {any} data - Données à tronquer
 * @param {number} maxLength - Longueur maximale
 * @returns {any} Données tronquées
 */
function truncateData(data, maxLength = 500) {
  if (typeof data === 'string' && data.length > maxLength) {
    return data.slice(0, maxLength) + '... [TRUNCATED]';
  }

  if (typeof data === 'object' && data !== null) {
    const str = JSON.stringify(data);
    if (str.length > maxLength) {
      return JSON.stringify(data, null, 2).slice(0, maxLength) + '... [TRUNCATED]';
    }
  }

  return data;
}

/**
 * Classe SecureLogger pour logging sécurisé
 */
class SecureLogger {
  constructor(enabled = true) {
    this.enabled = enabled;
    this.sensitivePatterns = SENSITIVE_PATTERNS;
    this.sensitiveKeys = SENSITIVE_KEYS;
  }

  /**
   * Prépare les arguments pour le logging
   */
  _prepareArgs(args) {
    return args.map(arg => {
      const masked = maskObject(arg);
      return truncateData(masked);
    });
  }

  /**
   * Log niveau info (sécurisé)
   */
  info(...args) {
    if (!this.enabled) return;
    const safeArgs = this._prepareArgs(args);
    console.info('[INFO]', ...safeArgs);
  }

  /**
   * Log niveau warn (sécurisé)
   */
  warn(...args) {
    if (!this.enabled) return;
    const safeArgs = this._prepareArgs(args);
    console.warn('[WARN]', ...safeArgs);
  }

  /**
   * Log niveau error (sécurisé)
   */
  error(...args) {
    if (!this.enabled) return;
    const safeArgs = this._prepareArgs(args);
    console.error('[ERROR]', ...safeArgs);
  }

  /**
   * Log niveau debug (sécurisé, désactivé en production)
   */
  debug(...args) {
    if (!this.enabled || process.env.NODE_ENV === 'production') return;
    const safeArgs = this._prepareArgs(args);
    console.log('[DEBUG]', ...safeArgs);
  }

  /**
   * Log API call (masque automatiquement les headers sensibles)
   */
  apiCall(method, url, headers, body) {
    if (!this.enabled) return;

    const maskedHeaders = maskObject(headers);
    const maskedBody = body ? maskObject(body) : undefined;

    this.info('API Call:', {
      method,
      url,
      headers: maskedHeaders,
      body: maskedBody
    });
  }

  /**
   * Log API response (masque les données sensibles)
   */
  apiResponse(method, url, status, data) {
    if (!this.enabled) return;

    const maskedData = data ? maskObject(data) : undefined;

    this.info('API Response:', {
      method,
      url,
      status,
      data: maskedData
    });
  }

  /**
   * Désactive le logging
   */
  disable() {
    this.enabled = false;
  }

  /**
   * Active le logging
   */
  enable() {
    this.enabled = true;
  }
}

// Instance singleton
const secureLogger = new SecureLogger(
  process.env.NODE_ENV !== 'production' // Désactivé en production par défaut
);

export default secureLogger;
export { SecureLogger, maskSensitiveData, maskObject };
