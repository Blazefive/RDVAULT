/**
 * background.js - Service Worker pour Vault Autofill
 *
 * Ce script gère la communication avec l'application Desktop Vault
 * et sert d'intermédiaire entre le content script et l'API locale.
 *
 * Responsabilités :
 * - Authentification via le gestionnaire de tokens
 * - Récupération des secrets depuis l'application Desktop
 * - Filtrage des secrets par URL
 * - Gestion des codes TOTP
 * - Stockage des credentials pour le TOTP multi-page
 *
 * @author Vault Autofill Team
 * @version 2.0.0
 */

'use strict';

// Import du gestionnaire d'authentification
importScripts('auth-manager.js');

// ============================================================================
// CONFIGURATION
// ============================================================================

/** URL de base de l'API Desktop locale */
const DESKTOP_API_BASE = 'http://127.0.0.1:45678';

/** Clé de stockage pour le dernier credential utilisé */
const LAST_CREDENTIAL_KEY = 'vault-last-credential';

/** Flag pour suivre l'initialisation de l'AuthManager */
let isAuthManagerInitialized = false;

// ============================================================================
// UTILITAIRES DE SÉCURITÉ
// ============================================================================

/**
 * Valide qu'une URL est sécurisée et bien formée
 *
 * @param {string} urlString - URL à valider
 * @returns {URL|null} Objet URL si valide, null sinon
 */
function validateUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return null;
  }

  try {
    const url = new URL(urlString);

    // SÉCURITÉ: Accepter uniquement HTTPS pour le matching des secrets
    if (url.protocol !== 'https:') {
      return null;
    }

    return url;
  } catch (e) {
    return null;
  }
}

/**
 * Sanitise une chaîne pour éviter les injections
 *
 * @param {string} input - Chaîne à sanitiser
 * @param {number} maxLength - Longueur maximale autorisée
 * @returns {string} Chaîne sanitisée
 */
function sanitizeString(input, maxLength = 500) {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Limiter la longueur
  let result = input.slice(0, maxLength);

  // Supprimer les caractères de contrôle
  result = result.replace(/[\x00-\x1F\x7F]/g, '');

  return result.trim();
}

/**
 * Valide la structure d'un objet credential
 *
 * @param {Object} credential - Credential à valider
 * @returns {boolean} True si la structure est valide
 */
function isValidCredential(credential) {
  if (!credential || typeof credential !== 'object') {
    return false;
  }

  // Vérifier les champs requis
  if (typeof credential.name !== 'string') {
    return false;
  }

  // Vérifier que les champs optionnels sont du bon type s'ils existent
  if (credential.username !== undefined && typeof credential.username !== 'string') {
    return false;
  }

  if (credential.password !== undefined && typeof credential.password !== 'string') {
    return false;
  }

  return true;
}

// ============================================================================
// GESTION DE L'AUTHENTIFICATION
// ============================================================================

/**
 * S'assure que l'AuthManager est initialisé avant utilisation
 *
 * @returns {Promise<void>}
 * @throws {Error} Si l'initialisation échoue
 */
async function ensureAuthManagerReady() {
  if (isAuthManagerInitialized) {
    return;
  }

  try {
    await authManager.start();
    isAuthManagerInitialized = true;
    console.log('[Vault BG] AuthManager initialisé avec succès');
  } catch (err) {
    console.error('[Vault BG] Erreur initialisation AuthManager:', err.message);
    throw new Error('Impossible d\'initialiser l\'authentification');
  }
}

// ============================================================================
// COMMUNICATION AVEC L'APPLICATION DESKTOP
// ============================================================================

/**
 * Vérifie si l'application Desktop est connectée
 *
 * @returns {Promise<boolean>} True si connectée
 */
async function checkDesktopConnection() {
  try {
    await ensureAuthManagerReady();

    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/sync`);

    if (!response.ok) {
      return false;
    }

    const data = await response.json();
    return data.connected === true;
  } catch (err) {
    console.warn('[Vault BG] Desktop non connecté:', err.message);
    return false;
  }
}

/**
 * Récupère tous les secrets depuis l'application Desktop
 *
 * @returns {Promise<Object[]>} Liste des secrets
 */
async function getSecretsFromDesktop() {
  try {
    await ensureAuthManagerReady();

    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/api/secrets`);

    if (!response.ok) {
      console.warn('[Vault BG] Erreur récupération secrets:', response.status);
      return [];
    }

    const data = await response.json();

    // Valider la réponse
    if (!data || !Array.isArray(data.secrets)) {
      return [];
    }

    // Filtrer les secrets invalides
    return data.secrets.filter(isValidCredential);
  } catch (err) {
    console.warn('[Vault BG] Erreur récupération secrets:', err.message);
    return [];
  }
}

/**
 * Filtre les secrets par correspondance avec une URL
 *
 * Algorithme de correspondance :
 * 1. Correspondance exacte du hostname
 * 2. Correspondance du domaine parent (pour les sous-domaines)
 * 3. Correspondance partielle en fallback
 *
 * @param {Object[]} secrets - Liste des secrets
 * @param {string} targetUrl - URL cible
 * @returns {Object[]} Secrets correspondants
 */
function filterSecretsByUrl(secrets, targetUrl) {
  // Valider l'URL cible
  const url = validateUrl(targetUrl);
  if (!url) {
    return [];
  }

  const targetHostname = url.hostname.toLowerCase();

  const matching = secrets.filter(secret => {
    // Vérifier le champ Website en priorité
    if (secret.website) {
      if (matchesHostname(secret.website, targetHostname)) {
        return true;
      }
    }

    // Vérifier le champ URL en fallback
    if (secret.url) {
      if (matchesHostname(secret.url, targetHostname)) {
        return true;
      }
    }

    return false;
  });

  // Dédupliquer par name + username (même entrée dans plusieurs coffres)
  const seen = new Set();
  return matching.filter(secret => {
    const key = `${secret.name || ''}|${secret.username || ''}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Vérifie si une URL de secret correspond à un hostname cible
 *
 * @param {string} secretUrl - URL du secret
 * @param {string} targetHostname - Hostname cible
 * @returns {boolean} True si correspondance
 */
function matchesHostname(secretUrl, targetHostname) {
  try {
    // Ajouter le protocole si manquant
    const normalizedUrl = secretUrl.startsWith('http')
      ? secretUrl
      : `https://${secretUrl}`;

    const parsedUrl = new URL(normalizedUrl);
    const secretHostname = parsedUrl.hostname.toLowerCase();

    // Correspondance exacte
    if (secretHostname === targetHostname) {
      return true;
    }

    // SÉCURITÉ: Rejeter les domaines trop courts pour éviter le matching trop large
    // (ex: "com", "co.uk" matcherait tous les sites de ce TLD)
    const parts = secretHostname.split('.');
    if (parts.length < 2 || (parts.length === 2 && parts[1].length <= 3)) {
      return false;
    }

    // Correspondance de sous-domaine (ex: app.example.com match example.com dans le secret)
    if (targetHostname.endsWith(`.${secretHostname}`)) {
      return true;
    }

    return false;
  } catch (e) {
    return false;
  }
}

/**
 * Récupère un code TOTP depuis l'application Desktop
 *
 * @param {string} keyName - Nom de la clé TOTP
 * @returns {Promise<Object>} Résultat avec success, code, error
 */
async function getTotpCodeFromDesktop(keyName) {
  // Valider le nom de clé
  const sanitizedKeyName = sanitizeString(keyName, 200);
  if (!sanitizedKeyName) {
    return { success: false, error: 'Nom de clé invalide' };
  }

  try {
    await ensureAuthManagerReady();

    const encodedKeyName = encodeURIComponent(sanitizedKeyName);
    const response = await authManager.authenticatedFetch(
      `${DESKTOP_API_BASE}/api/totp/${encodedKeyName}`
    );

    if (!response.ok) {
      return { success: false, error: `Erreur HTTP ${response.status}` };
    }

    const data = await response.json();

    // Valider le code TOTP (6 chiffres)
    if (data.success && data.code) {
      const code = String(data.code).replace(/\D/g, '');
      if (code.length === 6) {
        return { success: true, code };
      }
    }

    return { success: false, error: data.error || 'Code invalide' };
  } catch (err) {
    console.warn('[Vault BG] Erreur TOTP:', err.message);
    return { success: false, error: 'Erreur TOTP' };
  }
}

// ============================================================================
// GESTION DES MESSAGES
// ============================================================================

/**
 * Handler principal pour les messages du content script
 */
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Valider que le message vient d'une source légitime
    if (!sender || sender.id !== chrome.runtime.id) {
      console.warn('[Vault BG] Message rejeté: source non autorisée');
      return false;
    }
    // SÉCURITÉ: Rejeter les messages sensibles depuis des pages HTTP
    const sensitiveTypes = ['SAVE_LAST_CREDENTIAL', 'FILL_CREDENTIALS', 'LOGOUT', 'GET_TOTP_CODE', 'GET_CREDENTIALS'];
    if (sender.tab && sender.url && sender.url.startsWith('http:') && sensitiveTypes.includes(request?.type)) {
      console.warn('[Vault BG] Message sensible rejeté depuis HTTP');
      sendResponse({ success: false, error: 'Non autorisé depuis HTTP' });
      return true;
    }

    // Router les messages vers les handlers appropriés
    handleMessage(request, sender)
      .then(sendResponse)
      .catch(err => {
        console.error('[Vault BG] Erreur handler:', err.message);
        sendResponse({ success: false, error: 'Erreur interne' });
      });

    // Retourner true pour indiquer une réponse asynchrone
    return true;
  });
}

/**
 * Traite un message et retourne la réponse appropriée
 *
 * @param {Object} request - Message reçu
 * @param {Object} sender - Informations sur l'expéditeur
 * @returns {Promise<Object>} Réponse à envoyer
 */
async function handleMessage(request, sender) {
  const messageType = request.type;

  switch (messageType) {
    // -------------------------------------------------------------------------
    // Vérification de l'authentification
    // -------------------------------------------------------------------------
    case 'CHECK_AUTH':
      return await handleCheckAuth();

    // -------------------------------------------------------------------------
    // Récupération des credentials pour une URL
    // -------------------------------------------------------------------------
    case 'GET_CREDENTIALS':
      // SÉCURITÉ: Utiliser l'URL du tab (source de vérité Chrome) plutôt que celle du message
      return await handleGetCredentials(sender.tab?.url || request.url);

    // -------------------------------------------------------------------------
    // Récupération d'un code TOTP
    // -------------------------------------------------------------------------
    case 'GET_TOTP_CODE':
      return await getTotpCodeFromDesktop(request.keyName);

    // -------------------------------------------------------------------------
    // Sauvegarde du dernier credential (pour TOTP multi-page)
    // -------------------------------------------------------------------------
    case 'SAVE_LAST_CREDENTIAL': {
      // SÉCURITÉ: Toujours utiliser sender.tab.url (source de vérité Chrome)
      if (!sender.tab?.url) {
        sendResponse({ success: false, error: 'Tab URL required' });
        return true;
      }
      let saveHostname;
      try {
        saveHostname = new URL(sender.tab.url).hostname;
      } catch (e) {
        sendResponse({ success: false, error: 'Invalid tab URL' });
        return true;
      }
      return await handleSaveLastCredential(request.credential, saveHostname);
    }

    // -------------------------------------------------------------------------
    // Récupération du dernier credential sauvegardé
    // -------------------------------------------------------------------------
    case 'GET_LAST_CREDENTIAL':
      return await handleGetLastCredential(sender);

    // -------------------------------------------------------------------------
    // Suppression du dernier credential
    // -------------------------------------------------------------------------
    case 'CLEAR_LAST_CREDENTIAL':
      return await handleClearLastCredential();

    // -------------------------------------------------------------------------
    // Message non reconnu
    // -------------------------------------------------------------------------
    default:
      console.warn('[Vault BG] Type de message inconnu:', messageType);
      return { success: false, error: 'Type de message non supporté' };
  }
}

/**
 * Handler pour CHECK_AUTH
 * Vérifie si l'utilisateur est authentifié auprès de l'application Desktop
 *
 * @returns {Promise<Object>} État d'authentification
 */
async function handleCheckAuth() {
  try {
    await ensureAuthManagerReady();

    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/sync`);

    if (!response.ok) {
      return { authenticated: false };
    }

    const data = await response.json();

    if (data.connected && data.vaultUrl && data.username) {
      return {
        authenticated: true,
        username: sanitizeString(data.username, 100),
        vaultUrl: sanitizeString(data.vaultUrl, 500)
      };
    }

    return { authenticated: false };
  } catch (err) {
    console.warn('[Vault BG] Erreur CHECK_AUTH:', err.message);
    return { authenticated: false };
  }
}

/**
 * Handler pour GET_CREDENTIALS
 * Récupère et filtre les credentials pour une URL donnée
 *
 * @param {string} url - URL de la page
 * @returns {Promise<Object>} Credentials correspondants
 */
async function handleGetCredentials(url) {
  try {
    const secrets = await getSecretsFromDesktop();
    const matching = filterSecretsByUrl(secrets, url || '');

    return {
      success: true,
      credentials: matching
    };
  } catch (err) {
    console.warn('[Vault BG] Erreur GET_CREDENTIALS:', err.message);
    return { success: false, credentials: [] };
  }
}

/**
 * Handler pour SAVE_LAST_CREDENTIAL
 * Sauvegarde le credential utilisé pour le remplissage TOTP ultérieur
 *
 * @param {Object} credential - Credential à sauvegarder
 * @param {string} url - Hostname de la page
 * @returns {Promise<Object>} Résultat de l'opération
 */
async function handleSaveLastCredential(credential, url) {
  try {
    // Valider le credential
    if (!isValidCredential(credential)) {
      return { success: false, error: 'Credential invalide' };
    }

    // Valider l'URL (hostname uniquement)
    const sanitizedUrl = sanitizeString(url, 200);
    if (!sanitizedUrl) {
      return { success: false, error: 'URL invalide' };
    }

    // SÉCURITÉ: Ne stocker que les champs connus avec limites de longueur
    const safeCredential = {
      name: sanitizeString(credential.name, 200),
      username: sanitizeString(credential.username || '', 200),
      password: typeof credential.password === 'string' ? credential.password.slice(0, 1024) : '',
      totpKey: sanitizeString(credential.totpKey || '', 200),
      engine: sanitizeString(credential.engine || '', 256),
    };
    await chrome.storage.session.set({
      [LAST_CREDENTIAL_KEY]: {
        credential: safeCredential,
        timestamp: Date.now(),
        url: sanitizedUrl
      }
    });

    return { success: true };
  } catch (err) {
    console.error('[Vault BG] Erreur SAVE_LAST_CREDENTIAL:', err.message);
    return { success: false, error: 'Erreur sauvegarde credential' };
  }
}

/**
 * Handler pour GET_LAST_CREDENTIAL
 * Récupère le dernier credential sauvegardé
 *
 * @returns {Promise<Object>} Credential sauvegardé ou null
 */
async function handleGetLastCredential(sender) {
  try {
    const result = await chrome.storage.session.get(LAST_CREDENTIAL_KEY);
    const data = result[LAST_CREDENTIAL_KEY] || null;

    // SÉCURITÉ: Vérifier le TTL côté background (5 minutes max)
    if (data && data.timestamp && (Date.now() - data.timestamp > 300000)) {
      await chrome.storage.session.remove(LAST_CREDENTIAL_KEY);
      return { success: true, data: null };
    }

    // SÉCURITÉ: Vérifier que le tab appelant est sur le même hostname que le credential sauvegardé
    if (data && data.url && sender?.tab?.url) {
      try {
        const tabHostname = new URL(sender.tab.url).hostname;
        if (tabHostname !== data.url) {
          return { success: true, data: null };
        }
      } catch (e) {
        // SÉCURITÉ: Refuser l'accès si l'URL du tab ne peut pas être parsée
        return { success: true, data: null };
      }
    }

    return { success: true, data };
  } catch (err) {
    console.error('[Vault BG] Erreur GET_LAST_CREDENTIAL:', err.message);
    return { success: false, error: 'Erreur lecture credential' };
  }
}

/**
 * Handler pour CLEAR_LAST_CREDENTIAL
 * Supprime le credential sauvegardé
 *
 * @returns {Promise<Object>} Résultat de l'opération
 */
async function handleClearLastCredential() {
  try {
    await chrome.storage.session.remove(LAST_CREDENTIAL_KEY);
    return { success: true };
  } catch (err) {
    console.error('[Vault BG] Erreur CLEAR_LAST_CREDENTIAL:', err.message);
    return { success: false, error: 'Erreur suppression credential' };
  }
}

// ============================================================================
// INITIALISATION
// ============================================================================

// Log de démarrage
console.log('[Vault BG] Service Worker démarré');
