// ========================================
// FONCTIONS DE SÉCURITÉ UTILITAIRES
// ========================================
// Extraites de App.jsx pour modularisation

/**
 * Sanitize une chaîne pour affichage sécurisé
 * Protection contre XSS en encodant les caractères dangereux
 */
export const sanitizeForDisplay = (str) => {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * SÉCURITÉ: Construit et valide une URL pour ouverture dans un navigateur/RBI
 * Rejette les protocoles dangereux (javascript:, data:, etc.)
 */
export const buildSafeUrl = (rawUrl) => {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const url = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return url;
  } catch { return null; }
};

/**
 * Encode un chemin d'engine Vault segment par segment
 * Les engine names peuvent contenir des / (ex: users/john) mais chaque segment doit être encodé
 */
export const encodeEnginePath = (name) => {
  return name.replace(/^\/+|\/+$/g, '')
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/');
};

/**
 * Valide un nom de secret/engine
 * Autorise uniquement les caractères alphanumériques, tirets, underscores et slashes
 */
export const validateSecretName = (name) => {
  if (!name || typeof name !== 'string') return false;
  // Autoriser a-z, A-Z, 0-9, -, _, /
  return /^[a-zA-Z0-9\-_\/]+$/.test(name);
};

/**
 * Masque les erreurs techniques sensibles
 */
export const sanitizeError = (err) => {
  const status = err.response?.status;
  const genericMessages = {
    400: 'Requête invalide',
    401: 'Non authentifié',
    403: 'Accès refusé',
    404: 'Ressource introuvable',
    500: 'Erreur serveur',
    502: 'Service temporairement indisponible',
    503: 'Service temporairement indisponible'
  };

  // Retourner un message générique pour éviter l'exposition d'informations sensibles
  return genericMessages[status] || 'Une erreur est survenue';
};

/**
 * Sanitize un message d'erreur avec messages génériques français
 * Plus complet que sanitizeError, avec support réseau
 */
export const sanitizeErrorMessage = (err, fallbackMsg = 'Une erreur est survenue') => {
  // Priorité 1 : status HTTP connu → message générique français
  const status = err?.response?.status;
  const genericMessages = {
    400: 'Requête invalide',
    401: 'Non authentifié',
    403: 'Accès refusé',
    404: 'Ressource introuvable',
    429: 'Trop de requêtes, réessayez plus tard',
    500: 'Erreur serveur',
    502: 'Service temporairement indisponible',
    503: 'Service temporairement indisponible'
  };
  if (status && genericMessages[status]) return genericMessages[status];
  if (err?.response?.status === 404) return 'Ressource introuvable';
  if (err?.response?.status >= 500) return 'Erreur serveur';
  // Priorité 3 : message réseau
  if (err?.code === 'ECONNREFUSED') return 'Connexion au serveur refusée';
  if (err?.code === 'ECONNABORTED' || err?.code === 'ETIMEDOUT') return 'Délai de connexion dépassé';
  // Fallback
  return fallbackMsg;
};

/**
 * Ouvre une URL de manière sécurisée dans un nouvel onglet
 * Vérifie que le protocole est autorisé
 */
export const safeWindowOpen = (url) => {
  try {
    const parsed = new URL(url);
    if (['http:', 'https:', 'ftp:', 'ftps:'].includes(parsed.protocol)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  } catch { /* URL invalide, ignorer */ }
};
