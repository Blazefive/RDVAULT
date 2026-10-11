/**
 * background.js - Service Worker pour Vault Autofill
 *
 * Ce script gère la communication avec l'application Desktop RDVAULT
 * et sert d'intermédiaire entre le content script et l'API locale.
 *
 * Responsabilités :
 * - Authentification / appairage via le gestionnaire de tokens
 * - Récupération de la liste des identifiants d'un site (sans mot de passe)
 * - Récupération d'un identifiant complet à la sélection (SELECT_CREDENTIAL)
 * - Gestion des codes TOTP
 * - Mémorisation (sans secret) du dernier identifiant utilisé pour le TOTP multi-page
 *
 * Le filtrage des secrets par site est effectué côté Desktop : le hostname
 * transmis au serveur est TOUJOURS celui de l'onglet (sender.tab.url), jamais
 * une valeur fournie par le content script.
 *
 * @author Vault Autofill Team
 * @version 2.1.0
 */

/* eslint-env serviceworker, webextensions */
/* global authManager */
/* eslint-disable strict -- service worker « classique » (importScripts), pas un module : 'use strict' requis */
'use strict';
/* eslint-enable strict */

// Import du gestionnaire d'authentification
importScripts('auth-manager.js');

// ============================================================================
// CONFIGURATION
// ============================================================================

/** URL de base de l'API Desktop locale */
const DESKTOP_API_BASE = 'http://127.0.0.1:45678';

/** Clé de stockage pour le dernier credential utilisé */
const LAST_CREDENTIAL_KEY = 'vault-last-credential';

/** Durée de validité du dernier credential mémorisé (ms) */
const LAST_CREDENTIAL_TTL_MS = 300000; // 5 minutes

/** Temps d'attente max de CHECK_AUTH avant de répondre "appairage en attente" (ms) */
const CHECK_AUTH_WAIT_MS = 1500;

/** Flag pour suivre l'initialisation de l'AuthManager */
let isAuthManagerInitialized = false;

/** Promesse partagée d'initialisation (évite les démarrages concurrents) */
let authReadyPromise = null;

// ============================================================================
// TRADUCTIONS
// ============================================================================

/**
 * Message traduit dans la langue du navigateur (chrome.i18n, _locales/<langue>/messages.json,
 * repli « en »). `fallback` est le texte français d'origine, identique à _locales/fr : il ne
 * sert que hors navigateur (tests en vm sans `chrome`) ; $1… y sont remplacés comme par Chrome.
 *
 * @param {string} key - Nom du message
 * @param {string} fallback - Texte français (repli)
 * @param {string|number|Array} [subs] - Substitutions $1…$9
 * @returns {string}
 */
function i18nMessage(key, fallback, subs) {
  const list = subs === undefined ? [] : [].concat(subs).map(String);
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
      const text = chrome.i18n.getMessage(key, list);
      if (text) return text;
    }
  } catch (e) { /* API indisponible : repli */ }
  return fallback.replace(/\$([1-9])/g, (m, n) => (list[n - 1] !== undefined ? list[n - 1] : ''));
}

// ============================================================================
// UTILITAIRES DE SÉCURITÉ
// ============================================================================

/**
 * Valide qu'une URL est sécurisée (https) et bien formée
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

    // SÉCURITÉ: Accepter uniquement HTTPS pour proposer des identifiants
    if (url.protocol !== 'https:') {
      return null;
    }

    return url;
  } catch (e) {
    return null;
  }
}

/**
 * Retourne le hostname (minuscules) de l'onglet expéditeur, source de vérité Chrome
 *
 * @param {Object} sender - Expéditeur du message
 * @returns {string|null} Hostname ou null si l'onglet n'est pas une page https
 */
function getSenderHostname(sender) {
  if (!sender || !sender.tab) return null;
  // Formulaire dans une iframe (frameId > 0) : l'hôte de référence est celui de la FRAME
  // (sender.url, fourni par Chrome, non falsifiable par la page). Ainsi une iframe tierce
  // n'obtient que les secrets de son propre domaine, jamais ceux de la page hôte.
  const frameUrl = sender.frameId && sender.frameId > 0 && typeof sender.url === 'string' ? sender.url : null;
  const url = validateUrl(frameUrl || sender.tab.url);
  return url ? url.hostname.toLowerCase() : null;
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
  // eslint-disable-next-line no-control-regex -- volontaire : retrait des caractères de contrôle d'un libellé
  result = result.replace(/[\x00-\x1F\x7F]/g, '');

  return result.trim();
}

// Longueurs maximales des identifiants transmis tels quels (mêmes limites que l'application)
const ENTRY_NAME_MAX_LENGTH = 512;   // nom d'entrée (validateSecretName)
const ENGINE_NAME_MAX_LENGTH = 256;  // nom de coffre
const TOTP_KEY_MAX_LENGTH = 256;     // nom de clé TOTP (MAX_TOTP_KEY_LENGTH du serveur de synchronisation)

/**
 * Identifiant (nom d'entrée, de coffre ou de clé TOTP) transmis TEL QUEL (SYNC-29). Le serveur de
 * synchronisation retrouve l'entrée par égalité stricte : un identifiant n'est donc jamais « nettoyé »
 * (ni trim, ni coupe), il est accepté intact ou refusé. sanitizeString reste réservé aux libellés affichés.
 *
 * @param {*} input - Valeur reçue
 * @param {number} maxLength - Longueur maximale
 * @returns {string} La valeur intacte, ou '' si elle est invalide (non textuelle, vide, trop longue,
 *   caractère de contrôle)
 */
function exactIdentifier(input, maxLength) {
  if (typeof input !== 'string' || input.length === 0 || input.length > maxLength) {
    return '';
  }
  // eslint-disable-next-line no-control-regex -- volontaire : identifiant avec caractère de contrôle refusé
  return /[\x00-\x1F\x7F]/.test(input) ? '' : input;
}

/**
 * Valide la structure d'un résumé de secret renvoyé par le Desktop
 *
 * @param {Object} secret - Secret à valider
 * @returns {boolean} True si la structure est valide
 */
function isValidSecretSummary(secret) {
  if (!secret || typeof secret !== 'object') {
    return false;
  }

  // Nom d'entrée transmis tel quel : un nom invalide (vide, > 512, caractère de contrôle) écarte l'entrée
  if (!exactIdentifier(secret.name, ENTRY_NAME_MAX_LENGTH)) {
    return false;
  }

  for (const field of ['engine', 'username', 'url', 'type']) {
    if (secret[field] !== undefined && secret[field] !== null && typeof secret[field] !== 'string') {
      return false;
    }
  }

  return true;
}

/**
 * Construit le résumé transmis au content script : JAMAIS de mot de passe ni de notes
 *
 * @param {Object} secret - Secret brut
 * @returns {Object} Résumé {name, engine, username, url, type}
 */
function toSecretSummary(secret) {
  return {
    // Identifiants (renvoyés tels quels par SELECT_CREDENTIAL) intacts ; libellés affichés nettoyés
    name: exactIdentifier(secret.name, ENTRY_NAME_MAX_LENGTH),
    engine: exactIdentifier(secret.engine || '', ENGINE_NAME_MAX_LENGTH),
    username: sanitizeString(secret.username || '', 200),
    url: sanitizeString(secret.url || '', 500),
    type: sanitizeString(secret.type || '', 50)
  };
}

/**
 * Petite pause asynchrone
 *
 * @param {number} ms - Durée en ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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
function ensureAuthManagerReady() {
  if (isAuthManagerInitialized) {
    return Promise.resolve();
  }

  if (!authReadyPromise) {
    authReadyPromise = authManager.start()
      .then(() => {
        isAuthManagerInitialized = true;
        console.log('[Vault BG] AuthManager initialisé avec succès');
      })
      .catch(err => {
        console.warn('[Vault BG] Erreur initialisation AuthManager:', err.message);
        throw new Error('Impossible d\'initialiser l\'authentification');
      })
      .finally(() => {
        authReadyPromise = null;
      });
  }

  return authReadyPromise;
}

// ============================================================================
// COMMUNICATION AVEC L'APPLICATION DESKTOP
// ============================================================================

/**
 * Récupère la liste des secrets correspondant à un hostname
 * (filtrage effectué côté Desktop, réponse SANS mot de passe)
 *
 * Un ÉCHEC (RDVAULT verrouillé → 401, limite de débit → 429, app injoignable, réponse
 * invalide) renvoie null, à distinguer d'une liste vide (« aucun identifiant pour ce site ») :
 * le content script ne met pas un échec en cache et retente plus tard.
 *
 * @param {string} hostname - Hostname de l'onglet
 * @returns {Promise<Object[]|null>} Liste de résumés {name, engine, username, url, type}, ou null en cas d'échec
 */
async function getSecretsForHost(hostname) {
  try {
    await ensureAuthManagerReady();

    const response = await authManager.authenticatedFetch(
      `${DESKTOP_API_BASE}/api/secrets?host=${encodeURIComponent(hostname)}`
    );

    if (!response.ok) {
      console.warn('[Vault BG] Erreur récupération secrets:', response.status);
      return null;
    }

    const data = await response.json();

    // Valider la réponse
    if (!data || data.success !== true || !Array.isArray(data.secrets)) {
      return null;
    }

    // Ne conserver que les champs non sensibles, même si le serveur en renvoyait d'autres
    return data.secrets.filter(isValidSecretSummary).map(toSecretSummary);
  } catch (err) {
    console.warn('[Vault BG] Erreur récupération secrets:', err.message);
    return null;
  }
}

/**
 * Récupère un secret complet (avec mot de passe) pour un hostname donné
 *
 * @param {string} hostname - Hostname de l'onglet (source de vérité Chrome)
 * @param {string} engine - Engine du secret
 * @param {string} name - Nom du secret
 * @returns {Promise<Object>} {success, credential} ou {success:false, error}
 */
async function getSecretForHost(hostname, engine, name) {
  try {
    await ensureAuthManagerReady();

    const query = `host=${encodeURIComponent(hostname)}` +
      `&engine=${encodeURIComponent(engine)}` +
      `&name=${encodeURIComponent(name)}`;

    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/api/secret?${query}`);

    if (response.status === 404) {
      return { success: false, error: i18nMessage('bgErrNotFound', 'Identifiant introuvable pour ce site') };
    }

    if (!response.ok) {
      return { success: false, error: i18nMessage('bgErrHttp', 'Erreur HTTP $1', response.status) };
    }

    const data = await response.json();

    if (!data || data.success !== true || !data.secret || typeof data.secret !== 'object') {
      return { success: false, error: i18nMessage('bgErrInvalidResponse', 'Réponse invalide') };
    }

    const secret = data.secret;
    const exactName = exactIdentifier(secret.name, ENTRY_NAME_MAX_LENGTH);
    if (!exactName) {
      return { success: false, error: i18nMessage('bgErrInvalidResponse', 'Réponse invalide') };
    }

    return {
      success: true,
      credential: {
        // Nom exact : il sert aussi au nom de la clé TOTP (même convention que l'application)
        name: exactName,
        engine: exactIdentifier(secret.engine || '', ENGINE_NAME_MAX_LENGTH),
        username: sanitizeString(secret.username || '', 200),
        // Le mot de passe est transmis tel quel (limité en longueur), sans altération de caractères
        password: typeof secret.password === 'string' ? secret.password.slice(0, 1024) : '',
        url: sanitizeString(secret.url || '', 500),
        type: sanitizeString(secret.type || '', 50)
      }
    };
  } catch (err) {
    console.warn('[Vault BG] Erreur récupération secret:', err.message);
    return { success: false, error: i18nMessage('bgErrCommunication', 'Erreur de communication avec RDVAULT') };
  }
}

/**
 * Récupère un code TOTP depuis l'application Desktop
 *
 * @param {string} keyName - Nom de la clé TOTP
 * @returns {Promise<Object>} Résultat avec success, code, error
 */
async function getTotpCodeFromDesktop(keyName) {
  // Valider le nom de clé : transmis tel quel (aucune coupe ni trim : une autre clé pourrait être lue)
  const sanitizedKeyName = exactIdentifier(keyName, TOTP_KEY_MAX_LENGTH);
  if (!sanitizedKeyName) {
    return { success: false, error: i18nMessage('bgErrInvalidKeyName', 'Nom de clé invalide') };
  }

  try {
    await ensureAuthManagerReady();

    const encodedKeyName = encodeURIComponent(sanitizedKeyName);
    const response = await authManager.authenticatedFetch(
      `${DESKTOP_API_BASE}/api/totp/${encodedKeyName}`
    );

    if (!response.ok) {
      return { success: false, error: i18nMessage('bgErrHttp', 'Erreur HTTP $1', response.status) };
    }

    const data = await response.json();

    // Valider le code TOTP : 6 à 8 chiffres (le coffre local et Vault génèrent 6 ou 8 chiffres)
    if (data.success && data.code) {
      const code = String(data.code).replace(/\D/g, '');
      if (/^\d{6,8}$/.test(code)) {
        return { success: true, code };
      }
    }

    return { success: false, error: data.error || i18nMessage('bgErrInvalidCode', 'Code invalide') };
  } catch (err) {
    console.warn('[Vault BG] Erreur TOTP:', err.message);
    return { success: false, error: i18nMessage('bgErrTotp', 'Erreur TOTP') };
  }
}

// ============================================================================
// GESTION DES MESSAGES
// ============================================================================

/** Types de messages refusés depuis une page non https */
const SENSITIVE_MESSAGE_TYPES = [
  'GET_CREDENTIALS',
  'SELECT_CREDENTIAL',
  'GET_TOTP_CODE',
  'SAVE_LAST_CREDENTIAL',
  'GET_LAST_CREDENTIAL',
  'PASSKEY_STORE',
  'PASSKEY_LIST',
  'PASSKEY_UPDATE_COUNT'
];

// ========================================
// PASSKEYS — stockées dans le COFFRE RDVAULT chiffré (via le serveur sync → app desktop)
// ========================================
// La clé privée transite chiffrée par safeStorage/HTTPS local puis est stockée par le
// renderer dans le coffre (AES-256-GCM en mode local). Elle n'est renvoyée à l'extension
// qu'au moment de signer (même modèle de confiance que les mots de passe).
//
// SÉCURITÉ: le rpId est validé côté bridge contre l'origine de la frame ; ici on vérifie
// en plus qu'il correspond bien à l'hôte de l'onglet émetteur, avec la MÊME règle que
// resolveRpId (passkey-bridge.js) : un rpId parent n'est admis que s'il est un « registrable
// domain suffix » de l'hôte — jamais pour un hôte IP (IP partielle), un TLD seul ou un
// suffixe public. Listes identiques à passkey-bridge.js (cohérence vérifiée par
// test/passkey/rpid-policy.test.js) : toute modification doit être faite dans les deux fichiers.
const PASSKEY_PUBLIC_SUFFIXES = new Set([
  'github.io', 'gitlab.io', 'bitbucket.io', 'codeberg.page', 'readthedocs.io', 'herokuapp.com',
  'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
  'appspot.com', 'blogspot.com', 'azurewebsites.net', 'azurestaticapps.net', 'cloudfront.net',
  'onrender.com', 'fly.dev', 'glitch.me', 'surge.sh', 'ngrok.io', 'ngrok-free.app', 'myshopify.com'
]);
const PASSKEY_CCTLD_SECOND_LEVEL = /^(?:ac|ad|co|com|ed|edu|gen|go|gob|gov|govt|gr|info|int|lg|ltd|mil|ne|net|nic|nom|or|org|plc|sch)\.[a-z]{2}$/;
const passkeyIsIpHost = (h) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes(':') || h.startsWith('[');

function passkeyRpAllowedForSender(rpId, sender) {
  const host = getSenderHostname(sender);
  if (!host || !rpId) return false;
  const r = String(rpId).toLowerCase();
  if (host === r) return true;
  if (passkeyIsIpHost(host) || !r.includes('.') || PASSKEY_PUBLIC_SUFFIXES.has(r) || PASSKEY_CCTLD_SECOND_LEVEL.test(r)) return false;
  return host.endsWith('.' + r);
}

async function handlePasskeyStore(request, sender) {
  const pk = request.passkey;
  if (!pk || !pk.rpId || !pk.credentialId || !pk.privateKeyJwk) return { success: false, error: i18nMessage('bgErrInvalidPasskey', 'passkey invalide') };
  if (!passkeyRpAllowedForSender(pk.rpId, sender)) return { success: false, error: i18nMessage('bgErrRpIdNotAllowed', 'rpId non autorisé') };
  try {
    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/api/passkey`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passkey: pk })
    });
    const data = await response.json().catch(() => ({}));
    return { success: !!(response.ok && data.success) };
  } catch (err) {
    console.warn('[Vault BG] Passkey store échoué:', err.message);
    return { success: false, error: i18nMessage('bgErrVaultUnavailable', 'Coffre indisponible') };
  }
}
async function handlePasskeyList(request, sender) {
  const rpId = request.rpId;
  if (!passkeyRpAllowedForSender(rpId, sender)) return { success: false, passkeys: [] };
  try {
    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/api/passkeys?rpId=${encodeURIComponent(rpId)}`);
    const data = await response.json().catch(() => ({}));
    return { success: !!(response.ok && data.success), passkeys: Array.isArray(data.passkeys) ? data.passkeys : [] };
  } catch (err) {
    console.warn('[Vault BG] Passkey list échoué:', err.message);
    return { success: false, passkeys: [] };
  }
}
async function handlePasskeyUpdateCount(request, sender) {
  const { rpId, credentialId, signCount } = request;
  if (!passkeyRpAllowedForSender(rpId, sender)) return { success: false };
  try {
    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/api/passkey/count`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rpId, credentialId, signCount })
    });
    // Réservation du compteur (passkey-bridge.js : reserveSignCount) : l'application indique si la
    // valeur demandée a été réservée et, sinon, la valeur déjà stockée. Champs absents avec une
    // application antérieure : seul « success » est relayé (comportement d'origine).
    const data = await response.json().catch(() => ({}));
    const result = { success: response.ok };
    if (response.ok && data && typeof data.reserved === 'boolean') result.reserved = data.reserved;
    if (response.ok && data && Number.isInteger(data.signCount) && data.signCount >= 0) result.signCount = data.signCount;
    return result;
  } catch (err) {
    return { success: false };
  }
}

/**
 * Handler principal pour les messages du content script et du popup
 */
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Valider que le message vient d'une source légitime
    if (!sender || sender.id !== chrome.runtime.id) {
      console.warn('[Vault BG] Message rejeté: source non autorisée');
      return false;
    }

    // SÉCURITÉ: Rejeter les messages sensibles depuis des pages non https
    const messageType = request && request.type;
    if (sender.tab && SENSITIVE_MESSAGE_TYPES.includes(messageType) && !validateUrl(sender.tab.url)) {
      console.warn('[Vault BG] Message sensible rejeté depuis une page non https');
      sendResponse({ success: false, error: i18nMessage('bgErrInsecureSender', 'Non autorisé depuis une page non sécurisée') });
      return false;
    }

    // Router les messages vers les handlers appropriés
    handleMessage(request || {}, sender)
      .then(sendResponse)
      .catch(err => {
        console.error('[Vault BG] Erreur handler:', err.message);
        sendResponse({ success: false, error: i18nMessage('bgErrInternal', 'Erreur interne') });
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
    // Vérification de l'authentification / état d'appairage (popup)
    // -------------------------------------------------------------------------
    case 'CHECK_AUTH':
      return await handleCheckAuth();

    // -------------------------------------------------------------------------
    // Liste des identifiants du site de l'onglet (sans mot de passe)
    // -------------------------------------------------------------------------
    case 'GET_CREDENTIALS':
      return await handleGetCredentials(sender);

    // -------------------------------------------------------------------------
    // Identifiant complet sélectionné par l'utilisateur
    // -------------------------------------------------------------------------
    case 'SELECT_CREDENTIAL':
      return await handleSelectCredential(request, sender);

    // -------------------------------------------------------------------------
    // Récupération d'un code TOTP
    // -------------------------------------------------------------------------
    case 'GET_TOTP_CODE':
      return await getTotpCodeFromDesktop(request.keyName);

    // -------------------------------------------------------------------------
    // Mémorisation du dernier identifiant (pour TOTP multi-page) — sans secret
    // -------------------------------------------------------------------------
    case 'SAVE_LAST_CREDENTIAL': {
      // SÉCURITÉ: Toujours utiliser sender.tab.url (source de vérité Chrome)
      const saveHostname = getSenderHostname(sender);
      if (!saveHostname) {
        return { success: false, error: i18nMessage('bgErrTabUrlRequired', 'URL d\'onglet requise') };
      }
      return await handleSaveLastCredential(request.credential, saveHostname);
    }

    // -------------------------------------------------------------------------
    // Récupération du dernier identifiant mémorisé
    // -------------------------------------------------------------------------
    case 'GET_LAST_CREDENTIAL':
      return await handleGetLastCredential(sender);

    // -------------------------------------------------------------------------
    // Suppression du dernier identifiant mémorisé
    // -------------------------------------------------------------------------
    case 'CLEAR_LAST_CREDENTIAL':
      return await handleClearLastCredential();

    // -------------------------------------------------------------------------
    // Passkeys (WebAuthn) : stockage / liste / compteur
    // -------------------------------------------------------------------------
    case 'PASSKEY_STORE':
      return await handlePasskeyStore(request, sender);
    case 'PASSKEY_LIST':
      return await handlePasskeyList(request, sender);
    case 'PASSKEY_UPDATE_COUNT':
      return await handlePasskeyUpdateCount(request, sender);

    // -------------------------------------------------------------------------
    // Message non reconnu
    // -------------------------------------------------------------------------
    default:
      console.warn('[Vault BG] Type de message inconnu:', messageType);
      return { success: false, error: i18nMessage('bgErrUnsupportedMessage', 'Type de message non supporté') };
  }
}

/**
 * Handler pour CHECK_AUTH
 * Vérifie si l'utilisateur est authentifié auprès de l'application Desktop.
 *
 * Ne bloque jamais le popup pendant l'attente d'approbation (jusqu'à 60 s) :
 * répond {pairing:'pending'} tant que la boîte de dialogue RDVAULT est ouverte,
 * {pairing:'denied'} si l'accès a été refusé.
 *
 * @returns {Promise<Object>} État d'authentification
 */
async function handleCheckAuth() {
  try {
    if (authManager.isPairingDenied()) {
      return { authenticated: false, pairing: 'denied', reachable: true };
    }

    if (authManager.isPairingPending()) {
      return { authenticated: false, pairing: 'pending', reachable: true };
    }

    if (!authManager.getToken()) {
      // Lancer l'initialisation sans bloquer le popup plus de CHECK_AUTH_WAIT_MS
      const ready = ensureAuthManagerReady().then(() => true, () => false);
      await Promise.race([ready, sleep(CHECK_AUTH_WAIT_MS)]);

      if (authManager.isPairingDenied()) {
        return { authenticated: false, pairing: 'denied', reachable: true };
      }

      if (authManager.isPairingPending()) {
        return { authenticated: false, pairing: 'pending', reachable: true };
      }

      if (!authManager.getToken()) {
        return { authenticated: false, pairing: null, reachable: false };
      }
    }

    const response = await authManager.authenticatedFetch(`${DESKTOP_API_BASE}/sync`);

    if (!response.ok) {
      return { authenticated: false, pairing: null, reachable: true };
    }

    const data = await response.json();

    if (data && data.connected && data.vaultUrl && data.username) {
      return {
        authenticated: true,
        username: sanitizeString(data.username, 100),
        vaultUrl: sanitizeString(data.vaultUrl, 500)
      };
    }

    return { authenticated: false, pairing: null, reachable: true };
  } catch (err) {
    console.warn('[Vault BG] Erreur CHECK_AUTH:', err.message);
    return { authenticated: false, pairing: null, reachable: false };
  }
}

/**
 * Handler pour GET_CREDENTIALS
 * Récupère la liste des identifiants (sans mot de passe) pour le site de l'onglet
 *
 * @param {Object} sender - Expéditeur du message
 * @returns {Promise<Object>} {success, credentials}
 */
async function handleGetCredentials(sender) {
  // SÉCURITÉ: Utiliser l'URL du tab (source de vérité Chrome), jamais celle du message
  const hostname = getSenderHostname(sender);
  if (!hostname) {
    return { success: false, credentials: [], error: i18nMessage('bgErrInsecurePage', 'Page non sécurisée') };
  }

  try {
    const credentials = await getSecretsForHost(hostname);
    if (credentials === null) {
      // Échec (app verrouillée, injoignable, limite de débit) : signalé comme tel pour que le
      // content script ne le confonde pas avec « aucun identifiant » et retente
      return { success: false, credentials: [], error: i18nMessage('bgErrUnavailableOrLocked', 'RDVAULT indisponible ou verrouillé') };
    }
    return { success: true, credentials };
  } catch (err) {
    console.warn('[Vault BG] Erreur GET_CREDENTIALS:', err.message);
    return { success: false, credentials: [] };
  }
}

/**
 * Handler pour SELECT_CREDENTIAL
 * Récupère l'identifiant complet (avec mot de passe) choisi par l'utilisateur.
 * Le hostname envoyé au Desktop est celui de l'onglet, jamais celui du message.
 *
 * @param {Object} request - Message {engine, name}
 * @param {Object} sender - Expéditeur du message
 * @returns {Promise<Object>} {success, credential} ou {success:false, error}
 */
async function handleSelectCredential(request, sender) {
  const hostname = getSenderHostname(sender);
  if (!hostname) {
    return { success: false, error: i18nMessage('bgErrInsecurePage', 'Page non sécurisée') };
  }

  // Identifiants exacts : le serveur cherche l'entrée par égalité stricte (SYNC-29)
  const engine = request.engine ? exactIdentifier(request.engine, ENGINE_NAME_MAX_LENGTH) : '';
  const name = exactIdentifier(request.name, ENTRY_NAME_MAX_LENGTH);

  if (!name) {
    return { success: false, error: i18nMessage('bgErrNameRequired', 'Nom de secret requis') };
  }

  return await getSecretForHost(hostname, engine, name);
}

/**
 * Handler pour SAVE_LAST_CREDENTIAL
 * Mémorise l'identifiant utilisé pour le remplissage TOTP ultérieur.
 * SÉCURITÉ: seuls {name, engine, totpKey, hostname, savedAt} sont stockés — jamais le mot de passe.
 *
 * @param {Object} credential - Identifiant {name, engine, totpKey}
 * @param {string} hostname - Hostname de l'onglet
 * @returns {Promise<Object>} Résultat de l'opération
 */
async function handleSaveLastCredential(credential, hostname) {
  try {
    if (!credential || typeof credential !== 'object' || typeof credential.name !== 'string') {
      return { success: false, error: i18nMessage('bgErrInvalidCredential', 'Credential invalide') };
    }

    const name = exactIdentifier(credential.name, ENTRY_NAME_MAX_LENGTH);
    if (!name) {
      return { success: false, error: i18nMessage('bgErrInvalidCredential', 'Credential invalide') };
    }

    await chrome.storage.session.set({
      [LAST_CREDENTIAL_KEY]: {
        name,
        engine: credential.engine ? exactIdentifier(credential.engine, ENGINE_NAME_MAX_LENGTH) : '',
        totpKey: credential.totpKey ? exactIdentifier(credential.totpKey, TOTP_KEY_MAX_LENGTH) : '',
        hostname: sanitizeString(hostname, 253),
        savedAt: Date.now()
      }
    });

    return { success: true };
  } catch (err) {
    console.error('[Vault BG] Erreur SAVE_LAST_CREDENTIAL:', err.message);
    return { success: false, error: i18nMessage('bgErrSaveCredential', 'Erreur sauvegarde credential') };
  }
}

/**
 * Handler pour GET_LAST_CREDENTIAL
 * Récupère le dernier identifiant mémorisé (si même hostname et non expiré)
 *
 * @param {Object} sender - Expéditeur du message
 * @returns {Promise<Object>} {success, data} — data = {name, engine, totpKey, hostname, savedAt} ou null
 */
async function handleGetLastCredential(sender) {
  try {
    const result = await chrome.storage.session.get(LAST_CREDENTIAL_KEY);
    const data = result[LAST_CREDENTIAL_KEY] || null;

    if (!data || typeof data !== 'object') {
      return { success: true, data: null };
    }

    // SÉCURITÉ: Vérifier le TTL côté background (5 minutes max)
    if (!data.savedAt || (Date.now() - data.savedAt > LAST_CREDENTIAL_TTL_MS)) {
      await chrome.storage.session.remove(LAST_CREDENTIAL_KEY);
      return { success: true, data: null };
    }

    // SÉCURITÉ: L'onglet appelant doit être sur le même hostname que l'identifiant mémorisé
    const tabHostname = getSenderHostname(sender);
    if (!tabHostname || tabHostname !== data.hostname) {
      return { success: true, data: null };
    }

    return {
      success: true,
      data: {
        name: data.name,
        engine: data.engine || '',
        totpKey: data.totpKey || '',
        hostname: data.hostname,
        savedAt: data.savedAt
      }
    };
  } catch (err) {
    console.error('[Vault BG] Erreur GET_LAST_CREDENTIAL:', err.message);
    return { success: false, error: i18nMessage('bgErrReadCredential', 'Erreur lecture credential') };
  }
}

/**
 * Handler pour CLEAR_LAST_CREDENTIAL
 * Supprime l'identifiant mémorisé
 *
 * @returns {Promise<Object>} Résultat de l'opération
 */
async function handleClearLastCredential() {
  try {
    await chrome.storage.session.remove(LAST_CREDENTIAL_KEY);
    return { success: true };
  } catch (err) {
    console.error('[Vault BG] Erreur CLEAR_LAST_CREDENTIAL:', err.message);
    return { success: false, error: i18nMessage('bgErrClearCredential', 'Erreur suppression credential') };
  }
}

// ============================================================================
// INITIALISATION
// ============================================================================

// Log de démarrage
console.log('[Vault BG] Service Worker démarré');
