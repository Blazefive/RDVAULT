// ========================================
// ELECTRON MAIN PROCESS - RDVault Desktop Client
// ========================================
// Ce fichier est le point d'entrée de l'application Electron.
// Il gère :
// - La création de la fenêtre principale
// - La communication IPC avec React (renderer process)
// - Le serveur HTTP local pour la synchronisation avec l'extension Chrome
// - Le chiffrement des données de synchronisation
// - Les certificats SSL auto-signés pour Vault
// - L'ouverture de liens externes et connexions SSH/RDP

// Mesure de performance pour suivre le temps de démarrage
const startTime = Date.now();
console.log('[PERF] Electron main.js start');

// ========================================
// IMPORTS - Modules Node.js et Electron
// ========================================
const { app, BrowserWindow, Menu, globalShortcut, dialog, ipcMain, clipboard, shell, safeStorage, powerMonitor } = require('electron');
const path = require('path');      // Manipulation de chemins de fichiers
const fs = require('fs');          // Système de fichiers
const http = require('http');      // Serveur HTTP pour la sync extension Chrome
const https = require('https');    // Support HTTPS (non utilisé actuellement)
const crypto = require('crypto');  // Génération de tokens d'authentification sécurisés
const { spawn } = require('child_process');  // Exécution de commandes système (ouverture navigateurs)
const { copyPasswordWithAutoClear } = require('./secureClipboard');  // Copie sécurisée avec auto-effacement
const { Client } = require('ssh2');  // Client SSH pour lecture de logs distants
const { getTrustedDomains, getConfig, getAppMode } = require('./configLoader');  // Chargement de la configuration
const secureSession = require('./secureSession');  // Sessions navigateur isolées (RBI)
const cliServer = require('./cliServer');  // Serveur CLI local pour accès secrets via ligne de commande

console.log(`[PERF] Modules loaded: ${Date.now() - startTime}ms`);

// Sanitise une valeur destinée à un fichier RDP ou INI pour empêcher l'injection de retours à la ligne
const sanitizeConnectionValue = (val) => typeof val === 'string' ? val.replace(/[\r\n\x00-\x1F]/g, '') : '';

// Valide les paramètres de connexion (host, username, port)
const validateConnectionParams = (host, username, port) => {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253 || /[\x00-\x1F\s;|&`$(){}@#\[\]\/\?%]/.test(host)) {
    return { valid: false, error: 'Nom d\'hôte invalide' };
  }
  if (username !== undefined && username !== null && (typeof username !== 'string' || /[\x00-\x1F;|&`$(){}@]/.test(username))) {
    return { valid: false, error: 'Nom d\'utilisateur invalide' };
  }
  if (port !== undefined && port !== null) {
    const portNum = Number(port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return { valid: false, error: 'Port invalide (1-65535)' };
    }
  }
  return { valid: true };
};

// Valide qu'une URL utilise un schéma autorisé (prévient RCE via protocoles malveillants)
const ALLOWED_URL_SCHEMES = ['http:', 'https:', 'ftp:', 'ftps:', 'ssh:', 'rdp:', 'sftp:', 'vnc:'];
const validateUrlScheme = (url) => {
  try {
    const parsed = new URL(url);
    return ALLOWED_URL_SCHEMES.includes(parsed.protocol);
  } catch {
    return false;
  }
};

// Échappe les caractères HTML pour éviter l'injection dans le presse-papier riche
const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// ========================================
// CONFIGURATION - Constantes centralisées
// ========================================
// Toutes les valeurs de configuration sont regroupées ici pour:
// - Faciliter la maintenance et les audits de sécurité
// - Éviter les "magic numbers" dispersés dans le code
// - Permettre une configuration centralisée
const CONFIG = {
  // ========================================
  // PORTS RÉSEAU
  // ========================================
  SYNC_PORT: 45678,              // Port HTTP pour sync avec extension Chrome
  HTTPS_PORT: 45679,             // Port HTTPS (réservé pour évolution future)

  // ========================================
  // TIMEOUTS (en millisecondes)
  // ========================================
  SYNC_TIMEOUT_MS: 120000,       // 2 minutes - Expiration de l'état de sync
  HEARTBEAT_INTERVAL_MS: 30000,  // 30 secondes - Intervalle de mise à jour du timestamp
  CLIPBOARD_TIMEOUT_MS: 12000,   // 12 secondes - Délai avant effacement presse-papier
  SSH_TIMEOUT_MS: 10000,         // 10 secondes - Timeout connexion SSH
  TOTP_REQUEST_TIMEOUT_MS: 5000, // 5 secondes - Timeout requête TOTP
  FILE_CLEANUP_DELAY_MS: 2000,   // 2 secondes - Délai suppression fichiers temporaires (réduit pour sécurité)

  // ========================================
  // LIMITES DE SÉCURITÉ
  // ========================================
  MAX_TOTP_KEY_LENGTH: 256,      // Longueur max nom clé TOTP
  MAX_LOG_LINES: 1000,           // Nombre max lignes de logs à lire

  // ========================================
  // TOKENS ET SÉCURITÉ
  // ========================================
  AUTH_TOKEN_BYTES: 32,          // 256 bits d'entropie pour le token sync
};

// ========================================
// CHEMINS DE FICHIERS
// ========================================
// Fichier de synchronisation pour l'extension Chrome (chiffré avec Electron safeStorage)
// Contient : token Vault, liste des secrets, état de connexion
const SYNC_FILE = path.join(app.getPath('userData'), 'vault-sync.enc');

// Fichier contenant le token d'authentification pour le serveur sync
// Ce token est généré à chaque démarrage et doit être fourni par l'extension pour accéder aux endpoints protégés
const AUTH_TOKEN_FILE = path.join(app.getPath('userData'), 'sync-auth-token.txt');

// Certificat auto-signé pour le serveur HTTPS local (non utilisé actuellement)
let httpsCredentials = null;

// Token d'authentification pour le serveur sync (généré au démarrage avec crypto.randomBytes)
// Format: 64 caractères hexadécimaux (256 bits de sécurité)
let syncAuthToken = null;

// SÉCURITÉ: Clé HMAC aléatoire pour la comparaison timing-safe (générée au démarrage, pas persistée)
const hmacCompareKey = crypto.randomBytes(32);

// ========================================
// FONCTIONS DE CHIFFREMENT SÉCURISÉ
// ========================================
// Ces fonctions utilisent Electron safeStorage pour chiffrer/déchiffrer le fichier de sync.
// safeStorage utilise le trousseau de clés du système d'exploitation :
// - Windows: Data Protection API (DPAPI)
// - macOS: Keychain
// - Linux: libsecret
//
// Avantages :
// - Le fichier de sync est chiffré au repos
// - La clé de chiffrement est gérée par l'OS (pas dans le code)
// - Un attaquant qui vole le fichier ne peut pas le déchiffrer sans accès au système

/**
 * Génère un certificat auto-signé pour le serveur HTTPS local
 * Non utilisé actuellement - réservé pour évolution future si besoin de HTTPS local
 *
 * @returns {Promise<{key: string, cert: string}>} Certificat et clé privée au format PEM
 */
function generateSelfSignedCert() {
  try {
    const pem = require('pem');
    return new Promise((resolve, reject) => {
      pem.createCertificate({ days: 365, selfSigned: true }, (err, keys) => {
        if (err) {
          console.error('❌ Erreur génération certificat:', err);
          reject(err);
        } else {
          resolve({
            key: keys.serviceKey,
            cert: keys.certificate
          });
        }
      });
    });
  } catch (err) {
    // Fallback : générer un certificat simple avec openssl si pem n'est pas disponible
    console.warn('⚠️ Module pem non disponible, utilisation de certificats en dur');
    // Note: En production, il faudrait générer un vrai certificat
    return Promise.resolve(null);
  }
}

/**
 * Écrit des données chiffrées dans le fichier de sync
 *
 * Utilise Electron safeStorage pour chiffrer les données avant écriture.
 * Le fichier contient l'état de synchronisation : token Vault, secrets, état de connexion.
 *
 * Pourquoi chiffrer ?
 * - Le token Vault donne accès à TOUS les secrets de l'utilisateur
 * - Sans chiffrement, n'importe quel processus peut lire le fichier
 * - Avec safeStorage, seule cette application peut déchiffrer le fichier
 *
 * @param {Object} data - Données à chiffrer et écrire (sera sérialisé en JSON)
 * @throws {Error} Si le chiffrement échoue ou n'est pas disponible
 * @returns {boolean} true si succès
 */
function writeEncryptedSyncFile(data) {
  try {
    // Vérifier que safeStorage est disponible
    if (!safeStorage.isEncryptionAvailable()) {
      console.error('❌ Chiffrement safeStorage non disponible sur ce système');
      throw new Error('Chiffrement non disponible');
    }

    const jsonString = JSON.stringify(data);
    const encryptedBuffer = safeStorage.encryptString(jsonString);

    // Écrire le buffer chiffré (binaire)
    // SÉCURITÉ: Écrire avec permissions restrictives
    fs.writeFileSync(SYNC_FILE, encryptedBuffer, { mode: 0o600 });

    console.log('✅ Fichier sync chiffré écrit avec succès');
    return true;
  } catch (error) {
    console.error('❌ Erreur écriture fichier chiffré:', error);
    throw error;
  }
}

/**
 * Lit et déchiffre le fichier de sync
 *
 * Déchiffre le fichier de synchronisation et retourne les données.
 * Utilisé par le serveur HTTP local pour envoyer l'état à l'extension Chrome.
 *
 * @returns {Object|null} Données déchiffrées ou null si le fichier n'existe pas ou est invalide
 */
function readEncryptedSyncFile() {
  try {
    if (!fs.existsSync(SYNC_FILE)) {
      return null;
    }

    // Vérifier que safeStorage est disponible
    if (!safeStorage.isEncryptionAvailable()) {
      console.error('❌ Déchiffrement safeStorage non disponible');
      return null;
    }

    const encryptedBuffer = fs.readFileSync(SYNC_FILE);
    const decryptedString = safeStorage.decryptString(encryptedBuffer);
    const data = JSON.parse(decryptedString);

    return data;
  } catch (error) {
    console.error('❌ Erreur lecture fichier chiffré:', error);
    return null;
  }
}

/**
 * Génère et sauvegarde un token d'authentification sécurisé
 *
 * Ce token est requis pour accéder aux endpoints protégés du serveur sync (/sync, /api/totp, /api/secrets).
 * Il est généré à chaque démarrage et sauvegardé dans un fichier chiffré que l'extension Chrome peut lire.
 *
 * Sécurité RENFORCÉE :
 * - 256 bits d'entropie (crypto.randomBytes(32))
 * - Format hexadécimal (64 caractères)
 * - Fichier CHIFFRÉ avec safeStorage (DPAPI/Keychain)
 * - Régénéré à chaque démarrage (pas de persistance entre sessions)
 * - Protection contre lecture par malware local
 *
 * @returns {string|null} Token généré ou null si échec
 */
function generateAuthToken() {
  try {
    // Vérifier que safeStorage est disponible
    if (!safeStorage.isEncryptionAvailable()) {
      console.error('❌ Chiffrement safeStorage non disponible pour le token');
      throw new Error('Chiffrement non disponible');
    }

    // Générer un token aléatoire de 64 caractères hexadécimaux (256 bits)
    syncAuthToken = crypto.randomBytes(32).toString('hex');

    // Chiffrer le token avec safeStorage avant écriture
    const encryptedToken = safeStorage.encryptString(syncAuthToken);
    // SÉCURITÉ: Écrire avec permissions restrictives (lecture/écriture propriétaire uniquement)
    fs.writeFileSync(AUTH_TOKEN_FILE, encryptedToken, { mode: 0o600 });

    console.log('🔐 Token d\'authentification sync généré et chiffré');
    return syncAuthToken;
  } catch (err) {
    console.error('❌ Erreur critique génération token:', err);
    // NE PAS utiliser de fallback faible - arrêter le serveur si crypto échoue
    dialog.showErrorBox(
      'Erreur de sécurité',
      'Impossible de générer un token sécurisé. Le serveur sync ne peut pas démarrer.'
    );
    syncAuthToken = null;
    return null;
  }
}

/**
 * Vérifie le token d'authentification dans une requête HTTP
 *
 * Extrait le token du header Authorization (format: "Bearer <token>")
 * et le compare avec le token généré au démarrage.
 *
 * @param {http.IncomingMessage} req - Requête HTTP entrante
 * @returns {boolean} true si le token est valide, false sinon
 */
function verifyAuthToken(req) {
  // SÉCURITÉ: Vérifier que le token sync a été généré (null = serveur pas prêt)
  if (!syncAuthToken) return false;

  const authHeader = req.headers['authorization'];
  if (!authHeader) return false;

  // Format attendu : "Bearer <token>"
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return false;

  const providedToken = match[1];
  // SÉCURITÉ: Comparaison HMAC-based timing-safe (évite l'oracle de longueur)
  const hmacA = crypto.createHmac('sha256', hmacCompareKey).update(providedToken).digest();
  const hmacB = crypto.createHmac('sha256', hmacCompareKey).update(syncAuthToken).digest();
  try {
    return crypto.timingSafeEqual(hmacA, hmacB);
  } catch {
    return false;
  }
}

// ========================================
// CONFIGURATION ELECTRON - Sécurité et performance
// ========================================

// Désactive l'accélération matérielle pour éviter des problèmes de compatibilité GPU
app.disableHardwareAcceleration();

// ========================================
// GESTION DES CERTIFICATS SSL/TLS
// ========================================
// NE PAS désactiver globalement la vérification SSL - sécurité compromise !
// Au lieu de ça, on utilise un handler certificate-error (ligne 223) qui accepte
// UNIQUEMENT les certificats de domaines de confiance explicitement listés.
// Exemple de mauvaise pratique (DÉSACTIVÉ) :
// app.commandLine.appendSwitch('ignore-certificate-errors'); // ❌ N'IMPORTE QUEL certificat serait accepté !

// Force Electron à utiliser le magasin de certificats du système Windows
// Cela permet d'accepter les certificats d'entreprise ajoutés via GPO
app.commandLine.appendSwitch('use-system-ca-store');

/**
 * Handler pour les erreurs de certificat SSL/TLS
 *
 * Permet d'accepter les certificats auto-signés UNIQUEMENT pour des domaines de confiance explicites.
 * Utilisé pour connecter l'application au serveur Vault interne avec certificat auto-signé.
 *
 * Sécurité :
 * - Whitelist de domaines de confiance (pas de wildcard)
 * - Refus explicite des domaines non autorisés (log dans la console)
 * - Alternative sécurisée à ignore-certificate-errors global
 *
 * Domaines de confiance :
 * Configurés dans TRUSTED_DOMAINS (config.cfg)
 * - localhost / 127.0.0.1 : Développement local
 * - Domaines Vault : définis à l'installation
 */
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  // Empêcher l'erreur de bloquer la requête (sinon Electron rejette automatiquement)
  event.preventDefault();

  const parsedUrl = new URL(url);

  // Whitelist de domaines de confiance (chargée depuis la configuration)
  const trustedDomains = getTrustedDomains();

  // Vérifier si le domaine est dans la whitelist
  // Pour les IPs, seule la correspondance exacte est autorisée (pas de subdomain matching)
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(parsedUrl.hostname) || parsedUrl.hostname.includes(':');
  const isTrusted = trustedDomains.some(domain =>
    parsedUrl.hostname === domain ||
    (!isIP && parsedUrl.hostname.endsWith('.' + domain))
  );

  if (isTrusted) {
    // SÉCURITÉ: Rejeter les erreurs de certificat dangereuses même pour les domaines de confiance
    const rejectErrors = [
      'net::ERR_CERT_REVOKED',
      'net::ERR_CERT_COMMON_NAME_INVALID',
      'net::ERR_CERT_INVALID'
    ];
    if (rejectErrors.includes(error)) {
      console.warn(`[SSL] Certificat rejeté pour ${parsedUrl.hostname}: ${error}`);
      callback(false);
      return;
    }
    // Accepter uniquement les erreurs de type self-signed / untrusted CA
    callback(true);
  } else {
    console.warn(`❌ [SSL] Certificat refusé pour ${parsedUrl.hostname} (domaine non autorisé)`);
    callback(false); // Refuser le certificat
  }
});

/**
 * Handler pour la sélection de certificat client (mTLS - mutual TLS)
 *
 * Certains serveurs Vault peuvent demander un certificat client pour l'authentification.
 * Ce handler filtre les certificats disponibles et évite d'envoyer des certificats non pertinents.
 *
 * Problème résolu :
 * - Windows envoie parfois le certificat MS-Organization-Access (Azure AD)
 * - Ce certificat n'est pas valide pour Vault et peut causer des erreurs
 * - On le filtre pour envoyer uniquement les certificats Vault légitimes
 */
app.on('select-client-certificate', (event, webContents, url, list, callback) => {
  event.preventDefault();

  if (list.length > 0) {
    // Chercher un certificat qui N'EST PAS le certificat MS-Organization-Access
    const vaultCert = list.find(cert =>
      !cert.issuerName.includes('MS-Organization-Access') &&
      !cert.subjectName.includes('7a71dd6d-dcb3-4312-b91e-2a6c7b49e8a6')
    );

    if (vaultCert) {
      callback(vaultCert);
    } else {
      // Si tous les certificats sont Microsoft, ne pas envoyer de certificat
      callback();
    }
  } else {
    callback();
  }
});

// ========================================
// SERVEUR DE SYNCHRONISATION HTTP LOCAL
// ========================================
// Serveur HTTP qui écoute sur localhost:45678
// Permet à l'extension Chrome de récupérer l'état de connexion et les secrets
// Architecture : Desktop app (maître) -> Fichier chiffré <- Extension Chrome (lecteur)

let syncServer = null;

/**
 * Démarre le serveur de synchronisation HTTP local
 *
 * Endpoints exposés :
 * - GET /sync : Retourne l'état de connexion Vault (protégé par token)
 * - GET /api/totp/<key> : Génère un code TOTP pour une clé (protégé par token)
 * - GET /api/secrets : Retourne tous les secrets de l'utilisateur (protégé par token)
 *
 * Sécurité :
 * - Écoute UNIQUEMENT sur 127.0.0.1 (pas accessible depuis le réseau)
 * - CORS restreint aux extensions Chrome uniquement
 * - Tous les endpoints protégés par token Bearer
 * - Les données sensibles sont chiffrées dans le fichier de sync
 */
function startSyncServer() {
  const syncStart = Date.now();
  console.log('[PERF] startSyncServer begin');

  // Générer le token d'authentification au démarrage du serveur
  generateAuthToken();

  console.log(`[PERF] Auth token generated: ${Date.now() - syncStart}ms`);

  // Rate limiting simple pour le sync server (60 requêtes/minute par IP)
  const syncRateLimit = new Map();
  const SYNC_RATE_LIMIT = 60;
  const SYNC_RATE_WINDOW = 60000;

  syncServer = http.createServer((req, res) => {
    // SÉCURITÉ: Rejeter les méthodes non-GET (seules les lectures sont supportées)
    if (req.method !== 'GET' && req.method !== 'OPTIONS') {
      res.writeHead(405);
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    // Rate limiting
    const clientIp = req.socket.remoteAddress;
    const now = Date.now();
    const rateEntry = syncRateLimit.get(clientIp);
    if (rateEntry && now - rateEntry.start < SYNC_RATE_WINDOW) {
      rateEntry.count++;
      if (rateEntry.count > SYNC_RATE_LIMIT) {
        res.writeHead(429);
        res.end(JSON.stringify({ error: 'Too many requests' }));
        return;
      }
    } else {
      syncRateLimit.set(clientIp, { start: now, count: 1 });
    }

    // SÉCURITÉ: Nettoyer les entrées expirées du rate limit (évite fuite mémoire)
    if (syncRateLimit.size > 100) {
      for (const [ip, entry] of syncRateLimit) {
        if (now - entry.start > 60000) syncRateLimit.delete(ip);
      }
    }

    // CORS headers - restreint aux extensions Chrome uniquement
    // SÉCURITÉ: Seules les origins chrome-extension:// sont autorisées
    // SÉCURITÉ: Valider l'origin Chrome extension avec un format strict
    const origin = req.headers.origin;
    if (origin && /^chrome-extension:\/\/[a-p]{32}$/.test(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    }
    // Pas de header CORS pour les autres origins → le navigateur bloquera la réponse
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Vault-Extension');
    // Chrome 117+ : Private Network Access — nécessaire pour que les extensions
    // puissent accéder à 127.0.0.1 depuis un service worker
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
      // Répondre au preflight uniquement si l'origin est une extension Chrome
      if (origin && /^chrome-extension:\/\/[a-p]{32}$/.test(origin)) {
        res.writeHead(200);
      } else {
        res.writeHead(403);
      }
      res.end();
      return;
    }

    // 🔐 Endpoint d'obtention du token (AVANT le auth check — pas encore de token côté extension)
    // SÉCURITÉ: Exiger un Origin chrome-extension:// valide pour limiter l'accès aux extensions
    if (req.url === '/auth/token' && req.method === 'GET') {
      // SÉCURITÉ: Vérifier l'Origin chrome-extension:// ET le header X-Vault-Extension
      // Le header custom ne peut pas être envoyé par une page web (CORS preflight bloquerait)
      // et doit être explicitement ajouté par notre extension
      const vaultExtHeader = req.headers['x-vault-extension'];
      // SÉCURITÉ: Exiger un origin chrome-extension:// valide (pas de bypass sans origin)
      const hasValidOrigin = origin && /^chrome-extension:\/\/[a-p]{32}$/.test(origin);
      if (!hasValidOrigin || vaultExtHeader !== 'rdvault') {
        console.warn(`[Sync] /auth/token refusé: origin/header invalide (${origin || 'aucun'})`);
        res.writeHead(403);
        res.end(JSON.stringify({ error: 'Forbidden: Chrome extension origin required' }));
        return;
      }
      if (!syncAuthToken) {
        res.writeHead(503);
        res.end(JSON.stringify({ error: 'Token not ready' }));
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify({ token: syncAuthToken }));
      return;
    }

    // 🔐 Vérifier l'authentification pour tous les autres endpoints
    if (!verifyAuthToken(req)) {
      res.writeHead(401);
      res.end(JSON.stringify({
        error: 'Unauthorized',
        message: 'Token d\'authentification manquant ou invalide. Utilisez: Authorization: Bearer <token>'
      }));
      return;
    }

    if (req.url === '/sync' && req.method === 'GET') {
      try {
        // Lire le fichier chiffré
        const syncData = readEncryptedSyncFile();

        if (!syncData) {
          console.warn('[Sync] /sync → connected: false (fichier sync inexistant)');
          res.writeHead(200);
          res.end(JSON.stringify({ connected: false }));
          return;
        }

        // Vérifier que l'état n'est pas trop vieux (max CONFIG.SYNC_TIMEOUT_MS)
        const age = Date.now() - (syncData.timestamp || 0);
        if (!syncData.timestamp || age > CONFIG.SYNC_TIMEOUT_MS) {
          console.warn(`[Sync] /sync → connected: false (timestamp périmé: ${Math.round(age / 1000)}s, max: ${CONFIG.SYNC_TIMEOUT_MS / 1000}s)`);
          res.writeHead(200);
          res.end(JSON.stringify({ connected: false }));
          return;
        }

        // SÉCURITÉ: Whitelist des champs autorisés (pas de spread aveugle)
        res.writeHead(200);
        res.end(JSON.stringify({
          connected: true,
          vaultUrl: syncData.vaultUrl,
          username: syncData.username,
          timestamp: syncData.timestamp
        }));
      } catch (err) {
        console.error('❌ Erreur endpoint /sync:', err);
        res.writeHead(200);
        res.end(JSON.stringify({ connected: false }));
      }
    } else if (req.url.startsWith('/api/totp/') && req.method === 'GET') {
      // Endpoint pour générer un code TOTP
      try {
        // Lire le fichier chiffré
        const syncData = readEncryptedSyncFile();

        if (!syncData) {
          res.writeHead(401);
          res.end(JSON.stringify({ error: 'Not authenticated' }));
          return;
        }

        // Vérifier que l'état n'est pas trop vieux
        if (!syncData.timestamp || Date.now() - syncData.timestamp > CONFIG.SYNC_TIMEOUT_MS || !syncData.connected) {
          res.writeHead(401);
          res.end(JSON.stringify({ error: 'Not authenticated' }));
          return;
        }

        // Extraire le nom de la clé TOTP de l'URL
        const parsedTotpUrl = new URL(req.url, 'http://localhost');
        const totpKeyName = decodeURIComponent(parsedTotpUrl.pathname.replace('/api/totp/', ''));

        // 🔒 Validation du nom de clé TOTP (sécurité path traversal)
        if (!totpKeyName || totpKeyName.includes('..') || totpKeyName.includes('/') || totpKeyName.includes('\\') || /[\x00-\x1F\x7F]/.test(totpKeyName)) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'Invalid TOTP key name' }));
          return;
        }

        // Limiter la longueur pour éviter les abus
        if (totpKeyName.length > CONFIG.MAX_TOTP_KEY_LENGTH) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: 'TOTP key name too long' }));
          return;
        }

        // Demander au renderer process de générer le code TOTP
        if (mainWindow && mainWindow.webContents) {
          // ID de corrélation pour éviter la race condition entre requêtes TOTP concurrentes
          const requestId = crypto.randomBytes(8).toString('hex');
          mainWindow.webContents.send('get-totp-code', totpKeyName, requestId);

          // Attendre la réponse (avec timeout)
          let responded = false;
          const totpHandler = (event, result) => {
            // SÉCURITÉ: Vérifier que la réponse provient bien de la fenêtre principale
            if (event.sender !== mainWindow?.webContents) return;
            if (responded) return;
            responded = true;
            clearTimeout(timeout);
            if (result.success) {
              res.writeHead(200);
              res.end(JSON.stringify({ success: true, code: result.code }));
            } else {
              res.writeHead(404);
              res.end(JSON.stringify({ error: result.error || 'TOTP not found' }));
            }
          };
          ipcMain.once(`totp-code-response-${requestId}`, totpHandler);
          const timeout = setTimeout(() => {
            if (responded) return;
            responded = true;
            ipcMain.removeListener(`totp-code-response-${requestId}`, totpHandler);
            res.writeHead(500);
            res.end(JSON.stringify({ error: 'Timeout' }));
          }, CONFIG.TOTP_REQUEST_TIMEOUT_MS);
        } else {
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'Desktop app not ready' }));
        }
      } catch (err) {
        console.error('[TOTP] Erreur endpoint:', err);
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Internal error' }));
      }
    } else if (req.url === '/api/secrets' && req.method === 'GET') {
      // Endpoint pour récupérer tous les secrets (appelé par l'extension)
      try {
        // Lire le fichier chiffré
        const syncData = readEncryptedSyncFile();

        if (!syncData) {
          res.writeHead(401);
          res.end(JSON.stringify({ error: 'Not authenticated' }));
          return;
        }

        // Vérifier que l'état n'est pas trop vieux (max 2 minutes)
        if (!syncData.timestamp || Date.now() - syncData.timestamp > CONFIG.SYNC_TIMEOUT_MS || !syncData.connected) {
          res.writeHead(401);
          res.end(JSON.stringify({ error: 'Not authenticated' }));
          return;
        }

        // Lire les secrets depuis le fichier de sync
        // SÉCURITÉ: Filtrer les champs sensibles (ne garder que ce dont l'extension a besoin)
        const rawSecrets = Array.isArray(syncData.secrets) ? syncData.secrets : [];
        const secrets = rawSecrets.map(s => ({
          name: s.name,
          engine: s.engine,
          username: s.username,
          password: s.password,
          url: s.url,
          tags: s.tags,
          notes: s.notes,
          type: s.type
        }));
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, secrets }));
      } catch (err) {
        console.error('❌ Erreur endpoint /api/secrets:', err);
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Internal error' }));
      }
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Not found' }));
    }
  });

  syncServer.listen(CONFIG.SYNC_PORT, '127.0.0.1', () => {
    console.log(`[PERF] Sync server ready: ${Date.now() - syncStart}ms`);
    console.log(`Sync server listening on http://127.0.0.1:${CONFIG.SYNC_PORT}`);
  });

  syncServer.on('error', (err) => {
    console.error('Sync server error:', err);
  });
}

// ========================================
// FENÊTRE PRINCIPALE
// ========================================
let mainWindow;

/**
 * SÉCURITÉ: Vérifie que l'événement IPC provient bien de la fenêtre principale.
 * Empêche un second webContents (devtools, webview, popup) d'appeler les handlers sensibles.
 */
function validateIpcSender(event) {
  return mainWindow && event.sender === mainWindow.webContents;
}

/**
 * Charge l'application React dans la fenêtre Electron
 *
 * Stratégie de chargement :
 * 1. Si build/index.html existe -> Mode production (app packagée)
 * 2. Sinon -> Mode développement (React dev server sur localhost:3000)
 *
 * @param {BrowserWindow} win - Fenêtre Electron dans laquelle charger l'application
 */
function loadApp(win) {
  const buildIndex = path.join(__dirname, '../build/index.html');
  if (fs.existsSync(buildIndex)) {
    win.loadFile(buildIndex).catch(err => {
      console.error('loadFile error:', err);
      dialog.showErrorBox('Chargement échoué', String(err));
    });
  } else {
    // SÉCURITÉ: Valider ELECTRON_START_URL pour n'autoriser que localhost en dev
    let devUrl = 'http://localhost:3000';
    if (process.env.ELECTRON_START_URL) {
      try {
        const parsed = new URL(process.env.ELECTRON_START_URL);
        if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
          devUrl = process.env.ELECTRON_START_URL;
        } else {
          console.warn('[SECURITY] ELECTRON_START_URL non-localhost ignorée');
        }
      } catch {
        console.warn('[SECURITY] ELECTRON_START_URL invalide, utilisation de localhost:3000');
      }
    }
    console.warn('[Electron] build/index.html introuvable. Mode DEV →', devUrl);
    win.loadURL(devUrl).catch(err => {
      console.error('loadURL error:', err);
      dialog.showErrorBox('Chargement échoué (dev)', String(err));
    });
  }
}

/**
 * Crée la fenêtre principale de l'application
 *
 * Configuration de la fenêtre :
 * - Taille fixe : 1280x800 (redimensionnement manuel bloqué, mais maximisation autorisée)
 * - Pas de barre de menu (interface épurée)
 * - Splash screen pendant le chargement (affichage rapide à 500ms)
 * - Context isolation activé (sécurité)
 *
 * Comportement :
 * - L'utilisateur peut maximiser la fenêtre (plein écran) en mode principal
 * - L'utilisateur NE PEUT PAS redimensionner manuellement (drag des bords)
 * - La restauration depuis maximisé revient à la taille du mode courant
 * - Démarre en mode login (480x560, frameless) puis passe en mode principal (1280x800)
 */

// Tailles des deux modes fenêtre
const LOGIN_WIDTH = 540;
const LOGIN_HEIGHT = 820;
const MAIN_WIDTH = 1280;
const MAIN_HEIGHT = 800;

// Mode courant : 'login' ou 'main'
let windowMode = 'login';

function createWindow() {
  const winStart = Date.now();
  console.log('[PERF] createWindow begin');

  mainWindow = new BrowserWindow({
    show: false,
    width: LOGIN_WIDTH,
    height: LOGIN_HEIGHT,
    frame: false,
    transparent: true,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    icon: app.isPackaged
      ? path.join(process.resourcesPath, 'icon.ico')
      : path.join(__dirname, '../public/favicon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
      v8CacheOptions: 'code',
      devTools: !app.isPackaged,
    },
  });

  console.log(`[PERF] BrowserWindow created: ${Date.now() - winStart}ms`);

  // SÉCURITÉ: Désactiver l'ouverture des DevTools en production
  if (app.isPackaged) {
    mainWindow.webContents.on('devtools-opened', () => {
      mainWindow.webContents.closeDevTools();
      console.warn('⚠️ Tentative d\'ouverture des DevTools bloquée (mode production)');
    });
  }

  // SÉCURITÉ: Refuser toutes les demandes de permissions (caméra, micro, géoloc, notifications)
  mainWindow.webContents.session.setPermissionRequestHandler((webContents, permission, callback) => {
    console.warn(`[SECURITY] Permission refusée: ${permission}`);
    callback(false);
  });
  mainWindow.webContents.session.setPermissionCheckHandler(() => false);

  // Gérer la restauration depuis maximisé
  mainWindow.on('unmaximize', () => {
    const w = windowMode === 'login' ? LOGIN_WIDTH : MAIN_WIDTH;
    const h = windowMode === 'login' ? LOGIN_HEIGHT : MAIN_HEIGHT;
    mainWindow.setSize(w, h);
    mainWindow.center();
    mainWindow.webContents.send('window-maximize-changed', false);
  });

  mainWindow.on('maximize', () => {
    mainWindow.webContents.send('window-maximize-changed', true);
  });

  try {
    Menu.setApplicationMenu(null);
    mainWindow.setMenuBarVisibility(false);
    mainWindow.autoHideMenuBar = true;
  } catch {}

  // SÉCURITÉ: Appliquer CSP AVANT le chargement du contenu (pas dans ready-to-show)
  const rawVaultUrl = getConfig().VAULT_URL || '';
  const isLocalMode = getAppMode() === 'local';
  // SÉCURITÉ: Sanitiser VAULT_URL pour éviter l'injection dans le header CSP
  let safeVaultUrl = '';
  if (isLocalMode) {
    // En mode local, autoriser toutes les connexions vers localhost (port dynamique)
    safeVaultUrl = 'http://127.0.0.1:*';
  } else {
    try {
      const parsed = new URL(rawVaultUrl);
      if (['http:', 'https:'].includes(parsed.protocol)) {
        safeVaultUrl = parsed.origin;
      }
    } catch { /* URL invalide, ignorer */ }
  }

  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self';",
          "script-src 'self';",
          "style-src 'self' 'unsafe-inline';",
          "img-src 'self' data:;",
          `connect-src 'self' ${safeVaultUrl} http://127.0.0.1:${CONFIG.SYNC_PORT};`,
          "frame-src 'none';",
          "object-src 'none';",
          "base-uri 'self';",
          "form-action 'self';",
          "frame-ancestors 'none';"
        ].join(' ')
      }
    });
  });
  console.log('🔒 Content Security Policy appliquée');

  // SÉCURITÉ: Bloquer la navigation vers des URLs externes
  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    const parsedUrl = new URL(navigationUrl);
    // Autoriser uniquement localhost (dev) — file:// restreint au dossier app
    if (parsedUrl.protocol === 'file:') {
      const appDir = app.isPackaged ? path.dirname(process.execPath) : path.join(__dirname, '..');
      const normalizedNav = path.normalize(parsedUrl.pathname);
      if (!normalizedNav.startsWith(appDir)) {
        event.preventDefault();
        console.warn(`[SECURITY] Navigation file:// bloquée hors app: ${parsedUrl.pathname}`);
      }
    } else if (parsedUrl.hostname !== 'localhost') {
      event.preventDefault();
      console.warn(`[SECURITY] Navigation bloquée vers: ${parsedUrl.origin}`);
    }
  });

  // SÉCURITÉ: Bloquer l'ouverture de nouvelles fenêtres
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // SÉCURITÉ: Valider le schéma ET le domaine avant d'ouvrir
    if (url.startsWith('http:') || url.startsWith('https:')) {
      if (validateUrlScheme(url)) {
        // Vérifier que l'URL est vers le Vault ou un domaine de confiance
        try {
          const parsedOpenUrl = new URL(url);
          const appConfig = getConfig();
          const vaultHost = new URL(appConfig.VAULT_URL || '').hostname;
          const trustedDomains = (appConfig.TRUSTED_DOMAINS || '').split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
          const targetHost = parsedOpenUrl.hostname.toLowerCase();
          if (targetHost === vaultHost || trustedDomains.some(d => targetHost === d || targetHost.endsWith('.' + d))) {
            shell.openExternal(url);
          } else {
            console.warn('[SECURITY] Ouverture externe bloquée: domaine non autorisé');
          }
        } catch {
          // URL invalide, ne pas ouvrir
        }
      }
    }
    return { action: 'deny' };
  });

  // Charger l'application (APRÈS la mise en place de la CSP)
  loadApp(mainWindow);
  console.log(`[PERF] loadApp called: ${Date.now() - winStart}ms`);

  // Afficher la fenêtre RAPIDEMENT (après un court délai pour éviter le flash)
  setTimeout(() => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      console.log(`[PERF] Window shown (early): ${Date.now() - winStart}ms`);
      mainWindow.show();
      mainWindow.focus();
    }
  }, 500);

  mainWindow.once('ready-to-show', () => {
    console.log(`[PERF] Content ready-to-show: ${Date.now() - winStart}ms`);
    try {
      mainWindow.webContents.focus();
      mainWindow.webContents.setIgnoreMenuShortcuts(true);
    } catch {};
  });

  mainWindow.webContents.on('did-finish-load', () => {
    console.log(`[PERF] Content did-finish-load: ${Date.now() - winStart}ms`);
    try {
      mainWindow.focus();
      mainWindow.webContents.focus();
    } catch {}
  });

  mainWindow.on('focus', () => {
    try {
      mainWindow.webContents.setIgnoreMenuShortcuts(true);
      globalShortcut.unregisterAll();
    } catch {}
  });

  mainWindow.on('closed', () => { mainWindow = null; });
}

// ========================================
// HANDLERS IPC - Communication avec React
// ========================================
// Les handlers IPC permettent à React d'appeler des fonctions Node.js/Electron
// de manière sécurisée via contextBridge et ipcRenderer (défini dans preload.js)

// Stockage des timers de copie sécurisée en cours
let activeClipboardTimers = new Map();

/**
 * Handler IPC : clipboard-copy-secure
 * Copie un texte dans le presse-papier avec auto-effacement après un délai
 *
 * Utilisé pour copier des mots de passe et secrets sensibles.
 * Le presse-papier est automatiquement effacé après le délai spécifié.
 *
 * @param {string} text - Texte à copier
 * @param {number} timeoutMs - Délai avant effacement automatique (défaut: 12s)
 * @returns {Object} {success: boolean, timeoutMs: number}
 */
ipcMain.handle('clipboard-copy-secure', (event, text, timeoutMs = 12000) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Valider les entrées côté main process (défense en profondeur)
    if (typeof text !== 'string' || text.length > 100000) {
      return { success: false, error: 'Texte invalide' };
    }
    if (typeof timeoutMs !== 'number' || timeoutMs < 1000 || timeoutMs > 300000) {
      timeoutMs = 12000;
    }

    // Annuler tout timer précédent
    if (activeClipboardTimers.has('current')) {
      activeClipboardTimers.get('current').cancel();
    }

    // Créer le nouveau timer (copie + auto-effacement après délai)
    const timer = copyPasswordWithAutoClear(text, { timeoutMs });

    activeClipboardTimers.set('current', timer);

    // Nettoyage automatique après le délai
    setTimeout(() => {
      activeClipboardTimers.delete('current');
    }, timeoutMs + 100);

    return { success: true, timeoutMs };
  } catch (error) {
    console.error('Erreur lors de la copie sécurisée');
    return { success: false, error: 'Erreur lors de la copie' };
  }
});

// Gestionnaire IPC pour effacer immédiatement
ipcMain.handle('clipboard-clear-now', (event) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    if (activeClipboardTimers.has('current')) {
      activeClipboardTimers.get('current').clearNow();
      activeClipboardTimers.delete('current');
    } else {
      // Fallback si pas de timer actif
      clipboard.clear();
    }
    return { success: true };
  } catch (error) {
    console.error('Erreur lors de l\'effacement du presse-papier');
    return { success: false, error: 'Erreur lors de l\'effacement' };
  }
});

// Gestionnaire IPC pour effacer le presse-papier (legacy, conservé pour compatibilité)
ipcMain.handle('clipboard-clear', (event) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    clipboard.clear();
    return { success: true };
  } catch (error) {
    console.error('Erreur lors de l\'effacement du presse-papier');
    return { success: false, error: 'Erreur lors de l\'effacement' };
  }
});

// Gestionnaire IPC pour copier un lien au format riche (HTML + texte)
// Permet de coller un lien cliquable dans Outlook, Teams, etc.
ipcMain.handle('clipboard-copy-rich-link', (event, url, label) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Limiter la longueur des paramètres
    if (typeof url !== 'string' || url.length > 2048) return { success: false, error: 'URL trop longue' };
    if (label !== undefined && (typeof label !== 'string' || label.length > 512)) return { success: false, error: 'Label trop long' };
    // SÉCURITÉ: Échapper les caractères HTML pour éviter l'injection XSS via le presse-papier
    const safeUrl = (url && (url.startsWith('https://') || url.startsWith('http://'))) ? url : '';
    clipboard.write({
      text: safeUrl,
      html: `<a href="${escapeHtml(safeUrl)}">${escapeHtml(label || safeUrl)}</a>`
    });
    return { success: true };
  } catch (error) {
    console.error('Erreur copie lien riche');
    return { success: false, error: 'Erreur copie lien' };
  }
});

// Gestionnaire IPC pour écrire l'état de synchronisation (maintenant chiffré)
ipcMain.handle('sync-write-state', (event, state) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    if (!state || typeof state !== 'object') return { success: false, error: 'État invalide' };

    // SÉCURITÉ: Whitelist des champs autorisés (évite la pollution de données)
    const MAX_SECRETS = 5000;
    const syncData = {
      vaultUrl: typeof state.vaultUrl === 'string' ? state.vaultUrl.slice(0, 2048) : '',
      // SÉCURITÉ: Le token Vault n'est PAS stocké dans le fichier sync
      // L'extension obtient son token via le endpoint HTTP /auth/token
      username: typeof state.username === 'string' ? state.username.slice(0, 256) : '',
      connected: Boolean(state.connected),
      secrets: Array.isArray(state.secrets) ? state.secrets.slice(0, MAX_SECRETS).map(s => ({
        name: typeof s.name === 'string' ? s.name.slice(0, 512) : '',
        engine: typeof s.engine === 'string' ? s.engine.slice(0, 256) : '',
        username: typeof s.username === 'string' ? s.username.slice(0, 512) : '',
        password: typeof s.password === 'string' ? s.password.slice(0, 10000) : '',
        url: typeof s.url === 'string' ? s.url.slice(0, 2048) : '',
        website: typeof s.website === 'string' ? s.website.slice(0, 2048) : '',
        tags: typeof s.tags === 'string' ? s.tags.slice(0, 1024) : '',
        notes: typeof s.notes === 'string' ? s.notes.slice(0, 10000) : '',
        type: typeof s.type === 'string' ? s.type.slice(0, 64) : ''
      })) : [],
      timestamp: Date.now()
    };

    // Écrire le fichier chiffré au lieu de JSON en clair
    writeEncryptedSyncFile(syncData);

    return { success: true };
  } catch (error) {
    return { success: false, error: 'Erreur écriture sync' };
  }
});

// Gestionnaire IPC pour lire l'état de synchronisation (maintenant déchiffré)
ipcMain.handle('sync-read-state', (event) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // Lire et déchiffrer le fichier
    const syncData = readEncryptedSyncFile();

    if (!syncData) {
      return { success: true, data: null };
    }

    // Vérifier que l'état n'est pas trop vieux (max 30 secondes)
    if (Date.now() - syncData.timestamp > CONFIG.HEARTBEAT_INTERVAL_MS) {
      return { success: true, data: null };
    }

    // SÉCURITÉ: Ne pas retourner le token Vault au renderer
    const { token: _discarded, ...safeData } = syncData;
    return { success: true, data: safeData };
  } catch (error) {
    return { success: true, data: null };
  }
});

// Gestionnaire IPC pour obtenir le chemin du fichier de sync
ipcMain.handle('sync-get-path', () => {
  // SÉCURITÉ: Ne pas exposer le chemin filesystem en production
  if (app.isPackaged) {
    return { success: false, error: 'Non disponible en production' };
  }
  return { success: true, path: SYNC_FILE };
});

// Gestionnaire IPC pour lire le token d'authentification chiffré (pour l'extension Chrome)
ipcMain.handle('sync-get-auth-token', (event) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    if (!fs.existsSync(AUTH_TOKEN_FILE)) {
      return { success: false, error: 'Token file not found' };
    }

    // Vérifier que safeStorage est disponible
    if (!safeStorage.isEncryptionAvailable()) {
      console.error('❌ Déchiffrement safeStorage non disponible pour le token');
      return { success: false, error: 'Encryption not available' };
    }

    // Lire et déchiffrer le token
    const encryptedBuffer = fs.readFileSync(AUTH_TOKEN_FILE);
    const decryptedToken = safeStorage.decryptString(encryptedBuffer);

    return { success: true, token: decryptedToken };
  } catch (error) {
    console.error('❌ Erreur lecture token chiffré');
    return { success: false, error: 'Erreur lecture token' };
  }
});

// NOTE: Le handler 'create-https-agent' a été supprimé (exposait rejectUnauthorized: false).
// La gestion des certificats auto-signés est faite dans app.on('certificate-error') ci-dessus.

// Gestionnaire IPC pour récupérer la configuration de l'application
// Expose VAULT_URL, LDAP_AUTH_PATH, TRUSTED_DOMAINS et RBI_PROXY_URL à React
ipcMain.handle('get-app-config', (event) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    const config = getConfig();
    const appMode = getAppMode();

    // En mode local, remplacer VAULT_URL par l'adresse du serveur local
    let vaultUrl = config.VAULT_URL;
    if (appMode === 'local') {
      const localVault = require('./localVault/localVaultServer');
      const port = localVault.getPort();
      vaultUrl = port ? `http://127.0.0.1:${port}` : config.VAULT_URL;
    }

    return {
      success: true,
      config: {
        VAULT_URL: vaultUrl,
        LDAP_AUTH_PATH: config.LDAP_AUTH_PATH,
        TRUSTED_DOMAINS: config.TRUSTED_DOMAINS,
        RBI_PROXY_URL: appMode === 'local' ? '' : config.RBI_PROXY_URL,
        APP_MODE: appMode,
        LANG: config.LANG || 'en'
      }
    };
  } catch (error) {
    console.error('Erreur lors de la récupération de la configuration');
    return { success: false, error: 'Erreur chargement configuration' };
  }
});

// Définir les chemins des navigateurs
const browserPaths = {
  'chrome': [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe'
  ],
  'firefox': [
    'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
    'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe'
  ],
  'edge': [
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
  ],
  'brave': [
    'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
    'C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
    process.env.LOCALAPPDATA + '\\BraveSoftware\\Brave-Browser\\Application\\brave.exe'
  ]
};

// Cache pour les navigateurs installés
let installedBrowsersCache = null;

// Gestionnaire IPC pour obtenir la liste des navigateurs installés
ipcMain.handle('get-installed-browsers', async () => {
  try {
    // Retourner le cache si disponible
    if (installedBrowsersCache !== null) {
      return { success: true, browsers: installedBrowsersCache };
    }

    const installed = [];

    // Vérifier chaque navigateur
    for (const [browserName, paths] of Object.entries(browserPaths)) {
      for (const testPath of paths) {
        if (fs.existsSync(testPath)) {
          installed.push(browserName);
          break;
        }
      }
    }

    // Mettre en cache le résultat
    installedBrowsersCache = installed;

    return { success: true, browsers: installed };
  } catch (error) {
    console.error('Erreur lors de la détection des navigateurs:', error);
    return { success: false, browsers: [] };
  }
});

// Gestionnaire IPC pour ouvrir une URL dans un navigateur spécifique
// Gestionnaire pour ouvrir une connexion SSH avec PuTTY
ipcMain.handle('open-ssh-connection', async (event, { host, username, port }) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    const v = validateConnectionParams(host, username, port);
    if (!v.valid) return { success: false, error: v.error };

    // Chemins possibles pour PuTTY
    const puttyPaths = [
      'C:\\Program Files\\PuTTY\\putty.exe',
      'C:\\Program Files (x86)\\PuTTY\\putty.exe',
      path.join(process.env.LOCALAPPDATA || '', 'Programs', 'PuTTY', 'putty.exe'),
      path.join(process.env.PROGRAMFILES || '', 'PuTTY', 'putty.exe'),
      path.join(process.env['PROGRAMFILES(X86)'] || '', 'PuTTY', 'putty.exe')
    ];

    // Trouver PuTTY
    let puttyPath = null;
    for (const testPath of puttyPaths) {
      if (fs.existsSync(testPath)) {
        puttyPath = testPath;
        break;
      }
    }

    if (!puttyPath) {
      return { success: false, error: 'PuTTY non trouvé. Veuillez installer PuTTY.' };
    }

    // Construire la commande
    const portArg = port && port !== '22' ? `-P ${port}` : '';
    const target = username ? `${username}@${host}` : host;

    const args = ['-ssh'];
    if (portArg) args.push('-P', port);
    args.push(target);

    // SÉCURITÉ: Ne pas logger les arguments complets (peuvent contenir des informations sensibles)
    console.log('[SSH] Lancement PuTTY vers', host);

    // Lancer PuTTY
    spawn(puttyPath, args, {
      detached: true,
      stdio: 'ignore'
    }).unref();

    return { success: true };
  } catch (error) {
    console.error('Erreur ouverture SSH');
    return { success: false, error: 'Erreur ouverture connexion SSH' };
  }
});

// Gestionnaire pour ouvrir les liens avec l'application système par défaut (rdp://, ftp://, etc.)
ipcMain.handle('open-external-link', async (event, url) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Valider le schéma URL pour empêcher les protocoles dangereux (file:, ms-msdt:, etc.)
    if (!validateUrlScheme(url)) {
      return { success: false, error: 'Protocole URL non autorisé' };
    }
    await shell.openExternal(url);
    return { success: true };
  } catch (error) {
    return { success: false, error: 'Erreur ouverture lien' };
  }
});

// Gestionnaire pour ouvrir une connexion RDP avec auto-remplissage des credentials
ipcMain.handle('open-rdp-connection', async (event, params) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    const { host, username, password, port } = params;

    const v = validateConnectionParams(host, username, port);
    if (!v.valid) return { success: false, error: v.error };

    // Parser le username pour extraire le domaine (ex: LAB\username ou username@domain)
    let domain = '';
    let user = username || '';

    if (username && username.includes('\\')) {
      // Format: DOMAIN\username
      const parts = username.split('\\');
      domain = parts[0];
      user = parts[1];
    } else if (username && username.includes('@')) {
      // Format: username@domain (UPN)
      const parts = username.split('@');
      user = parts[0];
      domain = parts[1];
    }

    // SÉCURITÉ: Valider le domaine extrait contre l'injection de caractères de contrôle
    if (domain && (/[\x00-\x1F\s;|&`$(){}#\[\]\/\?%]/.test(domain) || domain.length > 253)) {
      return { success: false, error: 'Domaine RDP invalide' };
    }

    // Créer un fichier RDP temporaire
    const tempDir = app.getPath('temp');
    const rdpFileName = `rdvault_${crypto.randomBytes(8).toString('hex')}.rdp`;
    const rdpFilePath = path.join(tempDir, rdpFileName);

    // Contenu du fichier RDP
    const rdpContent = [
      'screen mode id:i:2',
      'use multimon:i:0',
      'desktopwidth:i:1920',
      'desktopheight:i:1080',
      'session bpp:i:32',
      'winposstr:s:0,3,0,0,800,600',
      'compression:i:1',
      'keyboardhook:i:2',
      'audiocapturemode:i:0',
      'videoplaybackmode:i:1',
      'connection type:i:7',
      'networkautodetect:i:1',
      'bandwidthautodetect:i:1',
      'displayconnectionbar:i:1',
      'enableworkspacereconnect:i:0',
      'disable wallpaper:i:0',
      'allow font smoothing:i:0',
      'allow desktop composition:i:0',
      'disable full window drag:i:1',
      'disable menu anims:i:1',
      'disable themes:i:0',
      'disable cursor setting:i:0',
      'bitmapcachepersistenable:i:1',
      `full address:s:${sanitizeConnectionValue(host)}${port && port !== '3389' ? ':' + port : ''}`,
      'audiomode:i:0',
      'redirectprinters:i:1',
      'redirectcomports:i:0',
      'redirectsmartcards:i:1',
      'redirectclipboard:i:1',
      'redirectposdevices:i:0',
      'autoreconnection enabled:i:1',
      'authentication level:i:2',
      'prompt for credentials:i:0',
      'negotiate security layer:i:1',
      `username:s:${sanitizeConnectionValue(user)}`,
      domain ? `domain:s:${sanitizeConnectionValue(domain)}` : '',
      'drivestoredirect:s:',
      'use redirection server name:i:0',
      'loadbalanceinfo:s:',
      'remoteapplicationmode:i:0',
      'alternate shell:s:',
      'shell working directory:s:',
      'gatewayhostname:s:',
      'gatewayusagemethod:i:4',
      'gatewaycredentialssource:i:4',
      'gatewayprofileusagemethod:i:0',
      'promptcredentialonce:i:0',
      'gatewaybrokeringtype:i:0',
      'use redirection server name:i:0',
      'rdgiskdcproxy:i:0',
      'kdcproxyname:s:',
    ].filter(line => line).join('\r\n');

    // Écrire le fichier RDP (permissions restreintes)
    fs.writeFileSync(rdpFilePath, rdpContent, { encoding: 'utf8', mode: 0o600 });

    // Si un mot de passe est fourni, le copier avec auto-effacement
    if (password) {
      copyPasswordWithAutoClear(password, { timeoutMs: CONFIG.CLIPBOARD_TIMEOUT_MS || 12000 });
    }

    // Ouvrir la connexion RDP avec mstsc (chemin complet pour éviter le PATH hijacking)
    const mstscPath = path.join(process.env.SYSTEMROOT || 'C:\\Windows', 'System32', 'mstsc.exe');
    const mstsc = spawn(mstscPath, [rdpFilePath], { detached: true, stdio: 'ignore' });
    mstsc.unref();

    // Supprimer le fichier temporaire après un délai
    setTimeout(() => {
      try {
        if (fs.existsSync(rdpFilePath)) {
          // Overwrite avant suppression pour éviter la récupération
          const size = fs.statSync(rdpFilePath).size;
          fs.writeFileSync(rdpFilePath, Buffer.alloc(size, 0));
          fs.unlinkSync(rdpFilePath);
        }
      } catch (err) {
        // Ignorer les erreurs de suppression
      }
    }, CONFIG.FILE_CLEANUP_DELAY_MS);

    return { success: true };
  } catch (error) {
    console.error('[RDP] Erreur');
    return { success: false, error: 'Erreur ouverture connexion RDP' };
  }
});

// Gestionnaire pour ouvrir une connexion SFTP avec FileZilla ou WinSCP
// SÉCURITÉ: Utilise des fichiers de session temporaires au lieu d'URLs avec credentials
// pour éviter que les mots de passe soient visibles dans les arguments de processus
ipcMain.handle('open-sftp-connection', async (event, params) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    const { host, username, password, port } = params;

    const v = validateConnectionParams(host, username, port);
    if (!v.valid) return { success: false, error: v.error };

    // Chemins possibles pour FileZilla
    const fileZillaPaths = [
      'C:\\Program Files\\FileZilla FTP Client\\filezilla.exe',
      'C:\\Program Files (x86)\\FileZilla FTP Client\\filezilla.exe',
      path.join(process.env.LOCALAPPDATA || '', 'FileZilla\\filezilla.exe'),
    ];

    // Chemins possibles pour WinSCP
    const winScpPaths = [
      'C:\\Program Files\\WinSCP\\WinSCP.exe',
      'C:\\Program Files (x86)\\WinSCP\\WinSCP.exe',
      path.join(process.env.LOCALAPPDATA || '', 'Programs\\WinSCP\\WinSCP.exe'),
    ];

    // Vérifier FileZilla
    let fileZillaPath = null;
    for (const testPath of fileZillaPaths) {
      if (fs.existsSync(testPath)) {
        fileZillaPath = testPath;
        break;
      }
    }

    // Vérifier WinSCP
    let winScpPath = null;
    for (const testPath of winScpPaths) {
      if (fs.existsSync(testPath)) {
        winScpPath = testPath;
        break;
      }
    }

    const sftpPort = port || '22';
    const tempDir = app.getPath('temp');

    if (fileZillaPath) {
      // SÉCURITÉ: Créer un fichier de session XML temporaire pour FileZilla
      // Le mot de passe n'apparaît pas dans les arguments de processus
      const sessionFile = path.join(tempDir, `rdvault_fz_${crypto.randomBytes(8).toString('hex')}.xml`);

      // Échapper les caractères XML dans les valeurs
      const escapeXml = (str) => {
        if (!str) return '';
        return str
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&apos;');
      };

      // Format FileZilla XML pour import de session
      const xmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.0.0">
  <Servers>
    <Server>
      <Host>${escapeXml(host)}</Host>
      <Port>${escapeXml(sftpPort)}</Port>
      <Protocol>1</Protocol>
      <Type>0</Type>
      <User>${escapeXml(username || '')}</User>
      <Pass></Pass>
      <Logontype>${username ? '1' : '0'}</Logontype>
      <EncodingType>Auto</EncodingType>
      <BypassProxy>0</BypassProxy>
      <Name>RDVault Session</Name>
    </Server>
  </Servers>
</FileZilla3>`;

      fs.writeFileSync(sessionFile, xmlContent, { encoding: 'utf8', mode: 0o600 });

      // FileZilla: directement sftp://user@host (sans password)
      const sftpUrl = `sftp://${username ? encodeURIComponent(username) : ''}@${host}:${sftpPort}`;

      // Copier le mot de passe avec auto-effacement
      if (password) {
        copyPasswordWithAutoClear(password, { timeoutMs: CONFIG.CLIPBOARD_TIMEOUT_MS || 12000 });
      }

      spawn(fileZillaPath, [sftpUrl], { detached: true, stdio: 'ignore' }).unref();

      // Supprimer le fichier de session temporaire après un délai
      setTimeout(() => {
        try {
          if (fs.existsSync(sessionFile)) {
            fs.unlinkSync(sessionFile);
          }
        } catch (err) {
          // Ignorer les erreurs de suppression
        }
      }, CONFIG.FILE_CLEANUP_DELAY_MS);

      return { success: true, client: 'filezilla', passwordCopied: !!password };
    } else if (winScpPath) {
      // SÉCURITÉ: Créer un fichier .ini temporaire pour WinSCP
      // Le mot de passe n'apparaît pas dans les arguments de processus
      const sessionFile = path.join(tempDir, `rdvault_winscp_${crypto.randomBytes(8).toString('hex')}.ini`);

      // WinSCP utilise un format INI pour les sessions
      // Note: WinSCP stocke les mots de passe encodés, mais on préfère le presse-papier
      const iniContent = `[Sessions\\RDVault_Session]
HostName=${sanitizeConnectionValue(host)}
PortNumber=${sftpPort}
UserName=${sanitizeConnectionValue(username || '')}
FSProtocol=2
`;

      fs.writeFileSync(sessionFile, iniContent, { encoding: 'utf8', mode: 0o600 });

      // WinSCP: Utiliser l'URL sans mot de passe + copier le mot de passe dans le presse-papier
      const sftpUrl = `sftp://${username ? encodeURIComponent(username) : ''}@${host}:${sftpPort}`;

      // Copier le mot de passe avec auto-effacement
      if (password) {
        copyPasswordWithAutoClear(password, { timeoutMs: CONFIG.CLIPBOARD_TIMEOUT_MS || 12000 });
      }

      spawn(winScpPath, [sftpUrl], { detached: true, stdio: 'ignore' }).unref();

      // Supprimer le fichier de session temporaire après un délai
      setTimeout(() => {
        try {
          if (fs.existsSync(sessionFile)) {
            fs.unlinkSync(sessionFile);
          }
        } catch (err) {
          // Ignorer les erreurs de suppression
        }
      }, CONFIG.FILE_CLEANUP_DELAY_MS);

      return { success: true, client: 'winscp', passwordCopied: !!password };
    } else {
      // Ni FileZilla ni WinSCP n'est installé
      return { success: false, error: 'FileZilla ou WinSCP n\'est pas installé sur ce système' };
    }
  } catch (error) {
    console.error('[SFTP] Erreur');
    return { success: false, error: 'Erreur ouverture connexion SFTP' };
  }
});

ipcMain.handle('open-url-in-browser', async (event, url, browser) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Valider le schéma URL
    if (!validateUrlScheme(url)) {
      return { success: false, error: 'Protocole URL non autorisé' };
    }

    if (browser === 'default') {
      // Ouvrir avec le navigateur par défaut
      await shell.openExternal(url);
      return { success: true };
    }

    const ALLOWED_BROWSERS = ['chrome', 'firefox', 'edge', 'brave'];
    if (browser && browser !== 'default' && !ALLOWED_BROWSERS.includes(browser)) {
      return { success: false, error: 'Navigateur non reconnu' };
    }

    const paths = browserPaths[browser];
    if (!paths) {
      // Si navigateur par défaut ou non dans la liste, ouvrir avec le système
      await shell.openExternal(url);
      return { success: true };
    }

    // Trouver le chemin existant du navigateur
    let browserPath = null;
    for (const testPath of paths) {
      if (fs.existsSync(testPath)) {
        browserPath = testPath;
        break;
      }
    }

    if (!browserPath) {
      // Si le navigateur n'est pas trouvé, utiliser le navigateur par défaut
      await shell.openExternal(url);
      return { success: true, fallback: true };
    }

    // SÉCURITÉ: '--' empêche l'URL d'être interprétée comme un flag du navigateur
    if (url.startsWith('-')) {
      return { success: false, error: 'URL invalide' };
    }
    spawn(browserPath, ['--', url], { detached: true, stdio: 'ignore' }).unref();
    return { success: true };
  } catch (error) {
    console.error('Erreur lors de l\'ouverture de l\'URL:', error.message);
    // Fallback sur le navigateur par défaut
    try {
      await shell.openExternal(url);
      return { success: true, fallback: true };
    } catch {
      return { success: false, error: 'Erreur ouverture URL' };
    }
  }
});

// Gestionnaire IPC pour lire un fichier de logs d'audit
ipcMain.handle('audit-read-log-file', async (event, filePath, maxLines = 1000) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    if (!filePath || typeof filePath !== 'string') {
      return { success: false, error: 'Chemin de fichier invalide' };
    }

    // SÉCURITÉ: Bloquer les traversées de chemin
    if (filePath.includes('..') || filePath.includes('\0')) {
      return { success: false, error: 'Chemin non autorisé.' };
    }
    // Restreindre aux fichiers de logs Vault (Windows: ProgramData\vault\logs)
    // SÉCURITÉ: Utiliser fs.realpathSync pour résoudre les symlinks (prévention TOCTOU)
    const resolved = path.resolve(filePath);
    const winPrefix = path.resolve(process.env.PROGRAMDATA || 'C:\\ProgramData', 'vault', 'logs');
    if (!resolved.startsWith(winPrefix + path.sep) && resolved !== winPrefix) {
      return { success: false, error: 'Chemin non autorisé. Seuls les fichiers de logs Vault sont accessibles.' };
    }

    // Valider maxLines
    const safeMaxLines = Math.min(Math.max(Number(maxLines) || 1000, 1), CONFIG.MAX_LOG_LINES || 10000);

    // Vérifier que le fichier existe et résoudre les symlinks
    let realPath;
    try {
      realPath = fs.realpathSync(resolved);
    } catch {
      return { success: false, error: 'Fichier non trouvé' };
    }
    // Re-vérifier après résolution des symlinks
    if (!realPath.startsWith(winPrefix + path.sep) && realPath !== winPrefix) {
      return { success: false, error: 'Chemin non autorisé (symlink détecté).' };
    }

    // Lire le fichier avec le chemin réel (prévention TOCTOU)
    const content = fs.readFileSync(realPath, 'utf8');
    const lines = content.split('\n').filter(line => line.trim());

    // Limiter le nombre de lignes
    const limitedLines = lines.slice(0, safeMaxLines);

    // Parser les lignes JSON
    const logs = [];
    for (const line of limitedLines) {
      try {
        const logEntry = JSON.parse(line);
        logs.push(logEntry);
      } catch (parseErr) {
        // Ignorer les lignes mal formées
      }
    }

    return {
      success: true,
      logs,
      totalLines: lines.length,
      loadedLines: limitedLines.length
    };
  } catch (error) {
    console.error('Erreur lors de la lecture du fichier de logs');
    return { success: false, error: 'Erreur lors de la lecture du fichier de logs' };
  }
});

// Gestionnaire IPC pour lire les dernières lignes d'un fichier de logs (tail)
ipcMain.handle('audit-tail-log-file', async (event, filePath, lines = 100, sshConfig = null) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    if (!filePath || typeof filePath !== 'string') {
      return { success: false, error: 'Chemin de fichier invalide' };
    }

    // Bloquer les traversées de chemin et caractères dangereux
    if (filePath.includes('..') || filePath.includes('\0')) {
      return { success: false, error: 'Chemin non autorisé.' };
    }

    // Valider le paramètre lines
    const safeLines = Math.min(Math.max(Number(lines) || 100, 1), CONFIG.MAX_LOG_LINES || 10000);

    let content = '';

    // Si sshConfig est fourni, lire via SSH
    if (sshConfig && sshConfig.host) {
      // SÉCURITÉ SSH: Validation du chemin en tant que chemin Unix (pas path.resolve Windows)
      if (!/^\/var\/log\/vault\/[a-zA-Z0-9._\-\/]+$/.test(filePath)) {
        return { success: false, error: 'Chemin SSH non autorisé. Seuls /var/log/vault/* sont accessibles.' };
      }

      // Valider sshConfig: whitelister les champs et restreindre les valeurs
      if (typeof sshConfig.host !== 'string' || sshConfig.host.length > 253 || /[\s;|&`$]/.test(sshConfig.host)) {
        return { success: false, error: 'Hôte SSH invalide' };
      }
      if (sshConfig.username && (typeof sshConfig.username !== 'string' || sshConfig.username.length > 128 || /[\x00-\x1F;|&`$]/.test(sshConfig.username))) {
        return { success: false, error: 'Utilisateur SSH invalide' };
      }
      if (sshConfig.password && (typeof sshConfig.password !== 'string' || sshConfig.password.length > 1024)) {
        return { success: false, error: 'Mot de passe SSH invalide' };
      }
      if (sshConfig.port !== undefined) {
        const sshPort = Number(sshConfig.port);
        if (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) {
          return { success: false, error: 'Port SSH invalide' };
        }
      }
      // Restreindre la clé privée au répertoire ~/.ssh/ (avec résolution de symlinks)
      if (sshConfig.privateKey) {
        if (sshConfig.privateKey.includes('..') || sshConfig.privateKey.includes('\0')) {
          return { success: false, error: 'Chemin de clé SSH non autorisé.' };
        }
        const sshDir = path.resolve(app.getPath('home'), '.ssh');
        let realKeyPath;
        try {
          realKeyPath = fs.realpathSync(path.resolve(sshConfig.privateKey));
        } catch {
          return { success: false, error: 'Clé SSH introuvable.' };
        }
        if (!realKeyPath.startsWith(sshDir + path.sep) && realKeyPath !== sshDir) {
          return { success: false, error: 'Chemin de clé SSH non autorisé. Seules les clés dans ~/.ssh/ sont acceptées.' };
        }
      }

      content = await readFileViaSSH(filePath, sshConfig);
    } else {
      // SÉCURITÉ LOCAL: Valider avec path.resolve et realpathSync (prévention TOCTOU/symlink)
      const resolved = path.resolve(filePath);
      const winPrefix = path.resolve(process.env.PROGRAMDATA || 'C:\\ProgramData', 'vault', 'logs');
      if (!resolved.startsWith(winPrefix + path.sep) && resolved !== winPrefix) {
        return { success: false, error: 'Chemin non autorisé. Seuls les fichiers de logs Vault sont accessibles.' };
      }
      let realPath;
      try {
        realPath = fs.realpathSync(resolved);
      } catch {
        return { success: false, error: 'Fichier non trouvé. Pour lire un fichier distant, activez "Lecture SSH".' };
      }
      if (!realPath.startsWith(winPrefix + path.sep) && realPath !== winPrefix) {
        return { success: false, error: 'Chemin non autorisé (symlink détecté).' };
      }
      content = fs.readFileSync(realPath, 'utf8');
    }

    const allLines = content.split('\n').filter(line => line.trim());

    // Prendre les dernières lignes
    const tailLines = allLines.slice(-safeLines);

    // Parser les lignes JSON
    const logs = [];
    for (const line of tailLines) {
      try {
        const logEntry = JSON.parse(line);
        logs.push(logEntry);
      } catch (parseErr) {
        // Ignorer les lignes mal formées
      }
    }

    return {
      success: true,
      logs,
      totalLines: allLines.length,
      loadedLines: tailLines.length
    };
  } catch (error) {
    console.error('Erreur lors de la lecture du fichier de logs');
    return { success: false, error: 'Erreur lors de la lecture du fichier de logs' };
  }
});

/**
 * Fonction helper pour lire un fichier distant via SSH
 *
 * Utilisée par le gestionnaire IPC 'audit-tail-log-file' pour lire les logs Vault distants.
 * Établit une connexion SSH, exécute 'cat <file>', et retourne le contenu.
 *
 * Sécurité :
 * - Whitelist de chemins autorisés (/var/log/vault/* uniquement)
 * - Protection contre command injection (échappement du chemin avec single quotes)
 * - Timeout de connexion (10 secondes)
 * - Authentification par mot de passe ou clé privée
 *
 * @param {string} filePath - Chemin du fichier à lire (doit commencer par /var/log/vault/)
 * @param {Object} sshConfig - Configuration SSH {host, port, username, password, privateKey}
 * @returns {Promise<string>} Contenu du fichier
 * @throws {Error} Si le chemin est invalide, la connexion échoue, ou le fichier n'existe pas
 */
function readFileViaSSH(filePath, sshConfig) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let fileContent = '';

    // Validation stricte du chemin de fichier pour éviter l'injection de commandes
    if (!filePath || typeof filePath !== 'string') {
      return reject(new Error('Chemin de fichier invalide'));
    }

    // Bloquer les traversées de chemin
    if (filePath.includes('..') || filePath.includes('\0')) {
      return reject(new Error('Chemin de fichier non autorisé.'));
    }

    // Rejeter les doubles slashes et chemins anormaux
    if (/\/\//.test(filePath)) {
      return reject(new Error('Chemin de fichier non autorisé (double slash).'));
    }

    // Whitelist stricte: uniquement /var/log/vault/ avec segments de caractères sûrs
    if (!/^\/var\/log\/vault\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9._\-]+)*$/.test(filePath)) {
      return reject(new Error('Chemin de fichier non autorisé. Seuls les chemins /var/log/vault/* sont autorisés.'));
    }

    // Rejeter les caractères de shell dangereux (défense en profondeur)
    if (/[`$|;&\n\r]/.test(filePath)) {
      return reject(new Error('Chemin de fichier contient des caractères interdits.'));
    }

    // Échapper le chemin pour éviter l'injection de commandes (single quotes)
    const escapedPath = filePath.replace(/'/g, "'\\''");

    conn.on('ready', () => {
      conn.exec(`cat '${escapedPath}'`, (err, stream) => {
        if (err) {
          conn.end();
          return reject(err);
        }

        // SÉCURITÉ: Limite de taille pour éviter l'accumulation mémoire non bornée
        const MAX_SSH_FILE_SIZE = 50 * 1024 * 1024; // 50 MB max
        stream.on('close', (code, signal) => {
          conn.end();
          if (code !== 0) {
            reject(new Error(`Commande SSH échouée avec le code ${code}`));
          } else {
            resolve(fileContent);
          }
        }).on('data', (data) => {
          fileContent += data.toString();
          if (fileContent.length > MAX_SSH_FILE_SIZE) {
            stream.destroy();
            conn.end();
            reject(new Error('Fichier trop volumineux (limite: 50 MB)'));
          }
        }).stderr.on('data', () => {
          console.error('SSH stderr: (contenu masqué)');
        });
      });
    }).on('error', (err) => {
      reject(new Error(`Connexion SSH échouée: ${err.message}`));
    }).connect({
      host: sshConfig.host,
      port: sshConfig.port || 22,
      username: sshConfig.username,
      password: sshConfig.password,
      privateKey: sshConfig.privateKey ? fs.readFileSync(fs.realpathSync(path.resolve(sshConfig.privateKey))) : undefined,
      readyTimeout: CONFIG.SSH_TIMEOUT_MS
    });
  });
}

// ========================================
// HANDLERS IPC - Sessions Sécurisées (RBI)
// ========================================

/**
 * Lance une session navigateur isolée (RBI-like)
 * Le mot de passe est injecté automatiquement, l'utilisateur ne le voit jamais
 */
ipcMain.handle('rbi-launch-session', async (event, options) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Validation stricte des entrées côté main process
    if (!options || typeof options !== 'object') {
      return { success: false, error: 'Options invalides' };
    }
    if (typeof options.url !== 'string' || !options.url) {
      return { success: false, error: 'URL requise' };
    }
    try {
      const u = new URL(options.url);
      if (!['http:', 'https:'].includes(u.protocol)) {
        return { success: false, error: 'Protocole non autorisé' };
      }
    } catch {
      return { success: false, error: 'URL invalide' };
    }
    if (typeof options.username !== 'string' || typeof options.password !== 'string') {
      return { success: false, error: 'Credentials requis' };
    }
    // Construire un objet propre (ne pas passer skipOverlay depuis le renderer)
    const safeOptions = {
      url: options.url,
      username: options.username,
      password: options.password,
      totp: (typeof options.totp === 'string' && options.totp.length <= 16) ? options.totp : undefined,
      selectors: options.selectors && typeof options.selectors === 'object' ? (() => {
        const allowedKeys = ['usernameSelector', 'passwordSelector', 'submitSelector', 'formSelector', 'totpSelector'];
        const safe = {};
        for (const k of allowedKeys) {
          if (typeof options.selectors[k] === 'string' && options.selectors[k].length < 500) {
            safe[k] = options.selectors[k];
          }
        }
        return Object.keys(safe).length > 0 ? safe : undefined;
      })() : undefined,
      skipOverlay: false,
      policies: {
        disableDownloads: Boolean(options.policies?.disableDownloads),
        disableClipboard: true, // SÉCURITÉ: Toujours bloqué — le renderer ne peut pas désactiver le blocage clipboard
        disableNewTabs: Boolean(options.policies?.disableNewTabs),
        ttlMinutes: (typeof options.policies?.ttlMinutes === 'number'
          && options.policies.ttlMinutes > 0
          && options.policies.ttlMinutes <= 480)
          ? options.policies.ttlMinutes : 0
      }
    };
    const result = await secureSession.launchSecureSession(safeOptions);
    return result;
  } catch (error) {
    console.error('[RBI] Erreur IPC launch-session');
    return { success: false, error: 'Erreur lancement session RBI' };
  }
});

/**
 * Ferme une session RBI active
 */
ipcMain.handle('rbi-close-session', async (event, sessionId) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
  // SÉCURITÉ: Valider le sessionId
  if (typeof sessionId !== 'string' || !sessionId || sessionId.length > 128 || /[^a-zA-Z0-9_\-]/.test(sessionId)) {
    return { success: false, error: 'ID de session invalide' };
  }
  try {
    await secureSession.closeSession(sessionId);
    return { success: true };
  } catch (error) {
    return { success: false, error: 'Erreur fermeture session RBI' };
  }
});

/**
 * Liste les sessions RBI actives
 */
ipcMain.handle('rbi-list-sessions', async (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const sessions = secureSession.getActiveSessions();
    return { success: true, sessions };
  } catch (error) {
    return { success: false, error: 'Erreur liste sessions RBI' };
  }
});

/**
 * Vérifie si RBI est disponible (Puppeteer/Chromium)
 */
ipcMain.handle('rbi-check-availability', async (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await secureSession.checkAvailability();
    return result;
  } catch (error) {
    return { available: false, error: 'Vérification RBI échouée' };
  }
});

/**
 * Retourne les sélecteurs connus pour les sites
 */
ipcMain.handle('rbi-get-known-selectors', (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  return { success: true, selectors: secureSession.KNOWN_SELECTORS };
});

// ========================================
// WINDOW CONTROLS - Gestion fenêtre frameless
// ========================================
// Ces handlers permettent au renderer de contrôler la fenêtre
// (minimiser, maximiser, fermer, basculer login/main mode)

ipcMain.handle('window-set-main-mode', (event) => {
  if (!validateIpcSender(event)) return;
  if (!mainWindow || mainWindow.isDestroyed()) return;
  windowMode = 'main';
  mainWindow.setResizable(true);
  mainWindow.setMaximizable(true);
  mainWindow.setSize(MAIN_WIDTH, MAIN_HEIGHT);
  mainWindow.center();
});

ipcMain.handle('window-set-login-mode', (event) => {
  if (!validateIpcSender(event)) return;
  if (!mainWindow || mainWindow.isDestroyed()) return;
  windowMode = 'login';
  if (mainWindow.isMaximized()) mainWindow.unmaximize();
  mainWindow.setMaximizable(false);
  mainWindow.setResizable(false);
  mainWindow.setSize(LOGIN_WIDTH, LOGIN_HEIGHT);
  mainWindow.center();
});

ipcMain.handle('window-close', (event) => {
  if (!validateIpcSender(event)) return;
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.close();
});

ipcMain.handle('window-minimize', (event) => {
  if (!validateIpcSender(event)) return;
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.minimize();
});

ipcMain.handle('window-maximize-toggle', (event) => {
  if (!validateIpcSender(event)) return;
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
  return mainWindow.isMaximized();
});

ipcMain.handle('window-is-maximized', (event) => {
  if (!validateIpcSender(event)) return false;
  if (!mainWindow || mainWindow.isDestroyed()) return false;
  return mainWindow.isMaximized();
});

// ========================================
// EXPORT — Sauvegarde de fichier via dialogue système
// ========================================
ipcMain.handle('export-save-file', async (event, { defaultName, filters, content }) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      defaultPath: defaultName,
      filters: filters || [{ name: 'All Files', extensions: ['*'] }]
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    fs.writeFileSync(result.filePath, content, { encoding: 'utf8', mode: 0o600 });
    return { success: true, filePath: result.filePath };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('import-open-file', async (event, { filters }) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      filters: filters || [{ name: 'All Files', extensions: ['*'] }]
    });
    if (result.canceled || !result.filePaths.length) return { success: false, canceled: true };
    // Limite de taille pour éviter les crash OOM
    const stats = fs.statSync(result.filePaths[0]);
    if (stats.size > 50 * 1024 * 1024) {
      return { success: false, error: 'File too large (max 50 MB)' };
    }
    const content = fs.readFileSync(result.filePaths[0], 'utf8');
    return { success: true, content, filePath: result.filePaths[0] };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// ========================================
// SERVEUR CLI — Lecture de secrets via IPC renderer
// ========================================
// Le serveur CLI (cliServer.js) a besoin de lire des secrets Vault.
// Comme les appels Vault se font depuis React (renderer), on utilise
// un pattern IPC request/response identique au TOTP.

/**
 * Fonction de lecture de secret injectée dans le serveur CLI.
 * Envoie une requête IPC au renderer et attend la réponse.
 */
function cliReadSecret(engine, secretPath) {
  return new Promise((resolve) => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      resolve({ success: false, error: 'Fenêtre principale non disponible' });
      return;
    }

    const requestId = crypto.randomBytes(8).toString('hex');
    let responded = false;

    const handler = (_event, result) => {
      if (responded) return;
      responded = true;
      clearTimeout(timeout);
      resolve(result);
    };

    ipcMain.once(`cli-secret-response-${requestId}`, handler);

    const timeout = setTimeout(() => {
      if (responded) return;
      responded = true;
      ipcMain.removeListener(`cli-secret-response-${requestId}`, handler);
      resolve({ success: false, error: 'Timeout lecture secret' });
    }, 15000);

    mainWindow.webContents.send('cli-read-secret', { engine, path: secretPath, requestId });
  });
}

/**
 * Fonction de listage des engines injectée dans le serveur CLI.
 * Même pattern IPC request/response.
 */
function cliListEngines() {
  return new Promise((resolve) => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      resolve([]);
      return;
    }

    const requestId = crypto.randomBytes(8).toString('hex');
    let responded = false;

    const handler = (_event, result) => {
      if (responded) return;
      responded = true;
      clearTimeout(timeout);
      resolve(result);
    };

    ipcMain.once(`cli-engines-response-${requestId}`, handler);

    const timeout = setTimeout(() => {
      if (responded) return;
      responded = true;
      ipcMain.removeListener(`cli-engines-response-${requestId}`, handler);
      resolve([]);
    }, 10000);

    mainWindow.webContents.send('cli-list-engines', { requestId });
  });
}

/**
 * Fonction de listage des secrets d'un engine injectée dans le serveur CLI.
 * Même pattern IPC request/response.
 */
function cliListSecrets(engine, folderPath) {
  return new Promise((resolve) => {
    if (!mainWindow || mainWindow.isDestroyed()) {
      resolve([]);
      return;
    }

    const requestId = crypto.randomBytes(8).toString('hex');
    let responded = false;

    const handler = (_event, result) => {
      if (responded) return;
      responded = true;
      clearTimeout(timeout);
      resolve(result);
    };

    ipcMain.once(`cli-list-secrets-response-${requestId}`, handler);

    const timeout = setTimeout(() => {
      if (responded) return;
      responded = true;
      ipcMain.removeListener(`cli-list-secrets-response-${requestId}`, handler);
      resolve([]);
    }, 15000);

    mainWindow.webContents.send('cli-list-secrets', { engine, path: folderPath, requestId });
  });
}

// IPC handler pour récupérer les infos de session CLI (appelé par React au montage)
ipcMain.handle('cli-get-session', (event) => {
  if (!validateIpcSender(event)) return null;
  const cliModule = require('./cliServer');
  const fs = require('fs');
  try {
    if (fs.existsSync(cliModule.CLI_SESSION_FILE)) {
      const content = fs.readFileSync(cliModule.CLI_SESSION_FILE, 'utf-8');
      return JSON.parse(content);
    }
  } catch { /* ignore */ }
  return null;
});

// IPC handler pour définir les engines autorisés pour le listing CLI
ipcMain.handle('cli-set-list-secrets-engines', (event, engines) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  cliServer.setListSecretsAllowedEngines(engines);
  return { success: true };
});

// IPC handler pour définir les règles d'auto-approbation CLI
ipcMain.handle('cli-set-auto-approve-rules', (event, rules) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  cliServer.setAutoApproveRules(rules);
  return { success: true };
});

// IPC handler pour révoquer/régénérer le token CLI (appelé au logout)
ipcMain.handle('cli-revoke-session', (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  cliServer.stopCLIServer();
  // Redémarrer avec un nouveau token
  cliServer.startCLIServer(mainWindow, cliReadSecret, cliListEngines, cliListSecrets).then(({ port }) => {
    console.log(`[CLI] Token CLI régénéré, nouveau port ${port}`);
  }).catch(() => {});
  return { success: true };
});

// ========================================
// NETTOYAGE ET HEARTBEAT
// ========================================

/**
 * Nettoyage des fichiers de sync au démarrage
 *
 * Actions :
 * 1. Supprimer l'ancien fichier vault-sync.json (version non chiffrée, migration)
 * 2. Supprimer le fichier vault-sync.enc actuel (réinitialisation à chaque démarrage)
 *
 * Pourquoi réinitialiser à chaque démarrage ?
 * - Évite les états obsolètes (token expiré, secrets périmés)
 * - Force une nouvelle connexion à Vault à chaque lancement
 * - Réduit la fenêtre d'exposition des données sensibles
 */
try {
  // Supprimer l'ancien fichier JSON non chiffré s'il existe
  const OLD_SYNC_FILE = path.join(app.getPath('userData'), 'vault-sync.json');
  if (fs.existsSync(OLD_SYNC_FILE)) {
    fs.unlinkSync(OLD_SYNC_FILE);
    console.log('✅ Ancien fichier vault-sync.json supprimé (migration vers version chiffrée)');
  }

  // Supprimer le fichier chiffré actuel pour repartir à zéro à chaque démarrage
  if (fs.existsSync(SYNC_FILE)) {
    fs.unlinkSync(SYNC_FILE);
    console.log('✅ Fichier sync chiffré nettoyé au démarrage');
  }
} catch (err) {
  console.error('⚠️ Erreur nettoyage fichiers sync:', err);
}

/**
 * Heartbeat pour maintenir le fichier de sync à jour
 *
 * S'exécute dans le process principal (main process), reste actif même quand
 * la session React est verrouillée ou inactive.
 *
 * Rôle :
 * - Met à jour le timestamp du fichier de sync toutes les 30 secondes
 * - Permet à l'extension Chrome de savoir que l'application est toujours connectée
 * - Évite l'expiration de l'état de sync (timeout de 2 minutes)
 *
 * Pourquoi dans le main process ?
 * - Le renderer process (React) peut être bloqué ou inactif
 * - Le main process continue de tourner en arrière-plan
 * - Garantit que l'extension Chrome a toujours un état à jour
 */
let heartbeatInterval = null;

/**
 * Démarre le heartbeat de synchronisation
 * Met à jour le timestamp du fichier de sync toutes les 30 secondes
 */
function startHeartbeat() {
  if (heartbeatInterval) return;

  heartbeatInterval = setInterval(() => {
    try {
      // Lire le fichier chiffré
      const syncData = readEncryptedSyncFile();

      if (!syncData) return;

      // Vérifier si connecté
      if (!syncData.connected) return;

      // Réécrire avec un nouveau timestamp
      syncData.timestamp = Date.now();
      writeEncryptedSyncFile(syncData);
    } catch (err) {
      // Erreur silencieuse
    }
  }, CONFIG.HEARTBEAT_INTERVAL_MS); // Intervalle configurable
}

function stopHeartbeat() {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
}

// ========================================
// DEEP LINK - Protocole rdvault://
// ========================================
// Permet de recevoir des liens rdvault://share/TOKEN pour le partage RBI
// Le token est un Vault Response Wrapping token (usage unique)

// Enregistrer le protocole rdvault:// pour les deep links
if (process.defaultApp) {
  // En dev, enregistrer avec le chemin vers electron
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient('rdvault', process.execPath, [path.resolve(process.argv[1])]);
  }
} else {
  // En production, enregistrer normalement
  app.setAsDefaultProtocolClient('rdvault');
}

// Variable pour stocker un deep link reçu avant que la fenêtre soit prête
let pendingDeepLink = null;

/**
 * Extrait le token de partage d'une URL rdvault://share/TOKEN
 * @param {string} url - URL au format rdvault://share/TOKEN
 * @returns {string|null} Token extrait ou null si format invalide
 */
function extractShareToken(url) {
  if (!url || typeof url !== 'string') return null;
  const match = url.match(/^rdvault:\/\/share\/(.+)$/);
  if (!match) return null;
  const token = match[1];
  // Valider le format du token (alphanumérique, tirets, points, max 512 chars)
  if (!/^[a-zA-Z0-9._\-]{1,128}$/.test(token.trim())) return null;
  return token;
}

/**
 * Envoie le token de partage au renderer process
 * @param {string} token - Token de wrapping Vault
 */
function sendShareTokenToRenderer(shareToken) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    console.log('[DEEP-LINK] Envoi du token de partage au renderer');
    mainWindow.webContents.send('rdvault-share-received', shareToken);
    mainWindow.show();
    mainWindow.focus();
  } else {
    console.log('[DEEP-LINK] Fenêtre non prête, mise en attente du token');
    pendingDeepLink = shareToken;
  }
}

// Single instance lock - empêche l'ouverture de multiples instances
// La seconde instance transmet son deep link à la première
const gotTheLock = app.requestSingleInstanceLock();

if (!gotTheLock) {
  // Une autre instance est déjà en cours d'exécution
  app.quit();
} else {
  // Quand une seconde instance est lancée (avec un deep link)
  app.on('second-instance', (event, commandLine) => {
    // Sur Windows, le deep link est dans les arguments de la ligne de commande
    const deepLinkUrl = commandLine.find(arg => arg.startsWith('rdvault://'));
    if (deepLinkUrl) {
      const shareToken = extractShareToken(deepLinkUrl);
      if (shareToken) {
        sendShareTokenToRenderer(shareToken);
      }
    }

    // Restaurer et focus la fenêtre existante
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

app.whenReady().then(async () => {
  // SÉCURITÉ: Nettoyer le fichier de token d'authentification au démarrage
  // pour éviter qu'un ancien token reste accessible
  try {
    if (fs.existsSync(AUTH_TOKEN_FILE)) {
      fs.unlinkSync(AUTH_TOKEN_FILE);
    }
  } catch { /* ignore */ }

  // En mode local : démarrer le serveur Vault local AVANT la fenêtre
  // pour que React ait le port quand il demande la config
  if (getAppMode() === 'local') {
    try {
      const localVault = require('./localVault/localVaultServer');
      const port = await localVault.start(0);
      console.log(`[LocalVault] Mode local actif sur le port ${port}`);
    } catch (err) {
      console.error('[LocalVault] Erreur démarrage:', err.message);
    }
  }

  // Créer la fenêtre
  createWindow();

  // Vérifier s'il y a un deep link dans les arguments de démarrage (Windows)
  const deepLinkArg = process.argv.find(arg => arg.startsWith('rdvault://'));
  if (deepLinkArg) {
    const shareToken = extractShareToken(deepLinkArg);
    if (shareToken) {
      pendingDeepLink = shareToken;
    }
  }

  // Envoyer le deep link en attente une fois la fenêtre chargée
  if (pendingDeepLink) {
    mainWindow.webContents.once('did-finish-load', () => {
      if (pendingDeepLink) {
        sendShareTokenToRenderer(pendingDeepLink);
        pendingDeepLink = null;
      }
    });
  }

  // Démarrer le serveur de sync et le heartbeat en arrière-plan
  // (ne bloque pas l'affichage de la fenêtre)
  setImmediate(async () => {
    startSyncServer();
    startHeartbeat();
    // Démarrer le serveur CLI pour accès secrets via ligne de commande (mvault)
    cliServer.startCLIServer(mainWindow, cliReadSecret, cliListEngines, cliListSecrets).then(({ port }) => {
      console.log(`[CLI] Serveur CLI prêt sur le port ${port}`);
    }).catch(err => {
      console.error('[CLI] Impossible de démarrer le serveur CLI:', err.message);
    });
  });

  // ========================================
  // SÉCURITÉ: Détecter verrouillage/déverrouillage du système
  // ========================================
  // Permet d'adapter le timeout de session selon l'état de verrouillage:
  // - Session active: 15 minutes d'inactivité avant déconnexion
  // - Session verrouillée: 3 heures avant déconnexion
  powerMonitor.on('lock-screen', () => {
    console.log('🔒 [SÉCURITÉ] Système verrouillé');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('system-lock-screen');
    }
  });

  powerMonitor.on('unlock-screen', () => {
    console.log('🔓 [SÉCURITÉ] Système déverrouillé');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('system-unlock-screen');
    }
  });
});
app.on('browser-window-focus', () => { try { globalShortcut.unregisterAll(); } catch {} });
app.on('will-quit', async () => {
  try {
    globalShortcut.unregisterAll();
    if (syncServer) syncServer.close();
    cliServer.stopCLIServer();
    // Arrêter le serveur local si en mode local
    if (getAppMode() === 'local') {
      try { require('./localVault/localVaultServer').stop(); } catch { /* ignore */ }
    }
    stopHeartbeat();
    // Fermer toutes les sessions RBI actives
    await secureSession.closeAllSessions();
    // Nettoyer le fichier de token d'authentification
    if (fs.existsSync(AUTH_TOKEN_FILE)) {
      fs.unlinkSync(AUTH_TOKEN_FILE);
    }
  } catch {}
});
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
