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

// ========================================
// IMPORTS - Modules Node.js et Electron
// ========================================
const { app, BrowserWindow, Menu, globalShortcut, dialog, ipcMain, clipboard, shell, powerMonitor } = require('electron');
const path = require('path');      // Manipulation de chemins de fichiers
const fs = require('fs');          // Système de fichiers
const http = require('http');      // Serveur HTTP pour la sync extension Chrome
const crypto = require('crypto');  // Génération de tokens d'authentification sécurisés
const { spawn } = require('child_process');  // Exécution de commandes système (ouverture navigateurs)
const { fileURLToPath } = require('url');
const { copyPasswordWithAutoClear } = require('./secureClipboard');  // Copie sécurisée avec auto-effacement
const { Client } = require('ssh2');  // Client SSH pour lecture de logs distants
const { createHostVerifier } = require('./sshBroker');  // Vérification de la clé d'hôte SSH (épinglage / known_hosts / invite)
const { createKnownHosts } = require('./knownHosts');  // Mémoire persistante des clés d'hôte SSH (partagée avec le serveur CLI)
const { getTrustedDomains, getTrustedCertFingerprints, getConfig, getAppMode } = require('./configLoader');  // Chargement de la configuration
const { fingerprintMatches } = require('./certPinning');  // Pinning TLS (logique pure testable)
const log = require('./logger');   // Journalisation centralisée (warn/error seulement en production)
const secureSession = require('./secureSession');  // Sessions navigateur isolées (RBI)
const cliServer = require('./cliServer');  // Serveur CLI local pour accès secrets via ligne de commande
// Textes du processus principal (boîtes de dialogue natives, erreurs IPC affichées en toast) dans la
// langue de l'interface : src/locales n'est pas empaqueté, les traductions vivent dans electron/mainI18n.js
const mainI18n = require('./mainI18n');
const { tm } = mainI18n;

log.info(`[PERF] Modules loaded: ${Date.now() - startTime}ms`);

// ========================================
// INSTANCE UNIQUE — verrou demandé AVANT tout effet de bord (STARTUP-23)
// ========================================
// Une seconde instance (double-clic sur le raccourci, lien rdvault://share/… pendant que l'application tourne)
// transmet sa ligne de commande à la première (évènement 'second-instance', voir plus bas) puis se termine.
// Elle ne doit RIEN démarrer ni nettoyer : Electron émet quand même 'ready' après un app.quit() demandé avant
// 'ready', et 'will-quit' y est émis AVANT 'ready'. Sans garde, elle ouvrait le coffre local, réécrivait la
// session CLI (userData/cli/session.json) avec son propre port, affichait « Chargement échoué », puis supprimait
// cette session en se fermant : mvault ne joignait plus la première instance, pourtant toujours lancée.
// Toutes les étapes de démarrage et de fermeture ci-dessous sont donc conditionnées par gotTheLock.
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  // Profils RBI orphelins (crash, fermeture avant la fin du nettoyage) : supprimés par la SEULE instance qui
  // détient le verrou (une seconde instance ne doit pas toucher aux profils des sessions de la première).
  secureSession.cleanupStaleProfiles();
}

// Sanitise une valeur destinée à un fichier RDP ou INI pour empêcher l'injection de retours à la ligne
// eslint-disable-next-line no-control-regex -- volontaire : retirer les caractères de contrôle (injection RDP/INI)
const sanitizeConnectionValue = (val) => typeof val === 'string' ? val.replace(/[\r\n\x00-\x1F]/g, '') : '';

// Valide les paramètres de connexion (host, username, port) ; message d'erreur dans la langue de l'interface
const validateConnectionParams = (host, username, port) => {
  // eslint-disable-next-line no-control-regex -- volontaire : un hôte contenant un caractère de contrôle est refusé
  if (typeof host !== 'string' || host.length === 0 || host.length > 253 || /[\x00-\x1F\s;|&`$(){}@#[\]/?%]/.test(host)) {
    return { valid: false, error: tm('error.invalidHost') };
  }
  // eslint-disable-next-line no-control-regex -- volontaire : un identifiant contenant un caractère de contrôle est refusé
  if (username !== undefined && username !== null && (typeof username !== 'string' || /[\x00-\x1F;|&`$(){}@]/.test(username))) {
    return { valid: false, error: tm('error.invalidUsername') };
  }
  if (port !== undefined && port !== null) {
    const portNum = Number(port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return { valid: false, error: tm('error.invalidPort') };
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

// Valide la structure des filtres de dialogue fournis par le renderer
const sanitizeDialogFilters = (filters) => {
  const fallback = [{ name: 'All Files', extensions: ['*'] }];
  if (!Array.isArray(filters)) return fallback;
  const safe = filters
    .filter(f => f && typeof f.name === 'string' && Array.isArray(f.extensions))
    .slice(0, 10)
    .map(f => ({
      name: f.name.slice(0, 64),
      extensions: f.extensions.filter(e => typeof e === 'string' && /^[a-z0-9*]{1,10}$/i.test(e)).slice(0, 10)
    }))
    .filter(f => f.extensions.length > 0);
  return safe.length ? safe : fallback;
};

let certWarningShown = false;

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

  // ========================================
  // TIMEOUTS (en millisecondes)
  // ========================================
  SYNC_TIMEOUT_MS: 120000,       // 2 minutes - Expiration de l'état de sync
  HEARTBEAT_INTERVAL_MS: 30000,  // 30 secondes - Intervalle de mise à jour du timestamp
  CLIPBOARD_TIMEOUT_MS: 12000,   // 12 secondes - Délai avant effacement presse-papier
  SSH_TIMEOUT_MS: 10000,         // 10 secondes - Timeout connexion SSH
  SSH_EXEC_TIMEOUT_MS: 120000, // 2 minutes - délai d'exécution de la lecture SSH des logs d'audit
  TOTP_REQUEST_TIMEOUT_MS: 5000, // 5 secondes - Timeout requête TOTP
  FILE_CLEANUP_DELAY_MS: 2000,   // 2 secondes - Délai suppression fichiers temporaires (réduit pour sécurité)

  // ========================================
  // LIMITES DE SÉCURITÉ
  // ========================================
  MAX_TOTP_KEY_LENGTH: 256,      // Longueur max nom clé TOTP
  MAX_LOG_LINES: 1000,           // Nombre max lignes de logs à lire
  MAX_SYNC_SECRETS: 100000,      // Entrées max transmises à l'extension (au-delà : troncature signalée)

  // ========================================
  // TOKENS ET SÉCURITÉ
  // ========================================
  AUTH_TOKEN_BYTES: 32,          // 256 bits d'entropie pour le token sync
};

// ========================================
// ÉTAT DE SYNCHRONISATION (EN MÉMOIRE UNIQUEMENT)
// ========================================
// SÉCURITÉ: l'état de synchronisation (liste des secrets pour l'extension Chrome)
// n'est PLUS écrit sur disque. Il vit uniquement dans la mémoire du main process
// et disparaît à la déconnexion ou à la fermeture de l'application.
// Les anciens fichiers vault-sync.enc / sync-auth-token.txt sont supprimés au démarrage.
let syncState = null;

// Token d'authentification du serveur sync (256 bits, généré au démarrage, jamais persisté)
let syncAuthToken = null;

// SÉCURITÉ: Clé HMAC aléatoire pour la comparaison timing-safe (générée au démarrage, pas persistée)
const hmacCompareKey = crypto.randomBytes(32);

// ========================================
// APPAIRAGE DES EXTENSIONS CHROME
// ========================================
// Le token sync n'est délivré qu'aux extensions dont l'identifiant a été approuvé
// explicitement par l'utilisateur (boîte de dialogue à la première demande).
// Les identifiants approuvés sont conservés dans userData/paired-extensions.json.
// Limite connue : un processus local malveillant peut présenter un faux identifiant.
// Un identifiant INCONNU déclenche une boîte de dialogue visible ; en revanche, un
// identifiant DÉJÀ appairé obtient le jeton sans invite (limite documentée dans
// SECURITY.md / docs/THREAT-MODEL.md). Le remplacement du transport HTTP par Native
// Messaging reste l'étape suivante recommandée.
const PAIRED_EXTENSIONS_FILE = path.join(app.getPath('userData'), 'paired-extensions.json');
const EXTENSION_ID_RE = /^[a-p]{32}$/;
const EXTENSION_ORIGIN_RE = /^chrome-extension:\/\/([a-p]{32})$/;
const PAIRING_TIMEOUT_MS = 60000;
const pairedExtensionIds = new Set();
const pendingPairings = new Map(); // extId -> Promise<boolean>

function loadPairedExtensions() {
  try {
    if (!fs.existsSync(PAIRED_EXTENSIONS_FILE)) return;
    const ids = JSON.parse(fs.readFileSync(PAIRED_EXTENSIONS_FILE, 'utf8'));
    if (Array.isArray(ids)) {
      for (const id of ids) {
        if (typeof id === 'string' && EXTENSION_ID_RE.test(id)) pairedExtensionIds.add(id);
      }
    }
  } catch {
    log.warn('[Pairing] Fichier des extensions appairées illisible, ignoré');
  }
}

function savePairedExtensions() {
  try {
    fs.writeFileSync(PAIRED_EXTENSIONS_FILE, JSON.stringify([...pairedExtensionIds]), { mode: 0o600 });
  } catch {
    log.error('[Pairing] Impossible d\'enregistrer les extensions appairées');
  }
}

/**
 * Demande à l'utilisateur d'approuver une extension Chrome (une seule fois par identifiant).
 * Les demandes concurrentes pour le même identifiant partagent la même boîte de dialogue.
 * @param {string} extId - Identifiant d'extension (32 lettres a-p)
 * @returns {Promise<boolean>} true si approuvée
 */
function requestExtensionPairing(extId) {
  if (pairedExtensionIds.has(extId)) return Promise.resolve(true);
  if (pendingPairings.has(extId)) return pendingPairings.get(extId);

  const pairing = (async () => {
    const win = mainWindow && !mainWindow.isDestroyed() ? mainWindow : null;
    if (!win) return false;
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), PAIRING_TIMEOUT_MS);
    try {
      win.show();
      win.focus();
      // Textes dans la langue de l'interface ; ordre des boutons inchangé (0 = autoriser, 1 = refuser, par défaut)
      const { response } = await dialog.showMessageBox(win, {
        type: 'question',
        buttons: [tm('button.allow'), tm('button.deny')],
        defaultId: 1,
        cancelId: 1,
        title: tm('pairing.title'),
        message: tm('pairing.message'),
        detail: tm('pairing.detail', { extId }),
        noLink: true,
        signal: abort.signal,
      });
      if (response === 0) {
        pairedExtensionIds.add(extId);
        savePairedExtensions();
        log.info('[Pairing] Extension approuvée');
        return true;
      }
      log.warn('[Pairing] Extension refusée par l\'utilisateur (ou délai dépassé)');
      return false;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
      pendingPairings.delete(extId);
    }
  })();

  pendingPairings.set(extId, pairing);
  return pairing;
}

/** Extrait l'identifiant d'extension d'un header Origin strictement formé, ou null */
function extensionIdFromOrigin(origin) {
  const m = typeof origin === 'string' ? origin.match(EXTENSION_ORIGIN_RE) : null;
  return m ? m[1] : null;
}

/**
 * Vérifie le token d'authentification dans une requête HTTP
 * (format "Bearer <token>", comparaison HMAC timing-safe)
 */
function verifyAuthToken(req) {
  if (!syncAuthToken) return false;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return false;
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return false;
  const hmacA = crypto.createHmac('sha256', hmacCompareKey).update(match[1]).digest();
  const hmacB = crypto.createHmac('sha256', hmacCompareKey).update(syncAuthToken).digest();
  try {
    return crypto.timingSafeEqual(hmacA, hmacB);
  } catch {
    return false;
  }
}

// Correspondance secret ↔ hôte : module pur electron/hostMatch.js (testable)
const { isValidHostname, secretMatchesHost, hostnameOf } = require("./hostMatch");

// Renderer de la fenêtre principale FIGÉ (évènement 'unresponsive' : boucle infinie, blocage du thread
// JavaScript) : la déconnexion et le délai d'inactivité, qui vivent dans le renderer, ne s'exécutent plus.
// Tant qu'il ne répond pas, il est traité comme planté (SYNC-28) ; remis à false par 'responsive' ou par
// un nouveau renderer (rechargement, plantage, fermeture de la fenêtre).
let rendererUnresponsive = false;

/**
 * true si l'interface (renderer de la fenêtre principale) qui a écrit l'état de synchronisation est vivante.
 * SÉCURITÉ (SYNC-28) : la déconnexion et le délai d'inactivité vivent dans le renderer ; renderer planté, figé
 * ou fenêtre détruite → l'état ne doit plus être servi ni prolongé (la fenêtre morte ne permet plus de se déconnecter).
 */
function rendererAlive() {
  try {
    return Boolean(mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isCrashed() && !rendererUnresponsive);
  } catch {
    return false;
  }
}

/** Purge l'état de synchronisation (mots de passe servis à l'extension) ; motif journalisé, sans secret */
function purgeSyncState(reason) {
  if (!syncState) return;
  syncState = null;
  log.warn('[Sync] État de synchronisation purgé : ' + reason);
}

/** true si un état de sync connecté et récent est disponible, écrit par une interface toujours vivante */
function syncStateIsFresh() {
  return Boolean(syncState && syncState.connected && syncState.timestamp
    && Date.now() - syncState.timestamp <= CONFIG.SYNC_TIMEOUT_MS
    && rendererAlive());
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

  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {
    callback(false);
    return;
  }

  // Whitelist de domaines de confiance (chargée depuis la configuration)
  // Pour les IPs, seule la correspondance exacte est autorisée (pas de subdomain matching)
  const trustedDomains = getTrustedDomains();
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');
  const isTrusted = trustedDomains.some(domain =>
    hostname === domain || (!isIP && hostname.endsWith('.' + domain))
  );
  if (!isTrusted) {
    log.warn('[SSL] Certificat refusé pour ' + hostname + ' (domaine non autorisé)');
    callback(false);
    return;
  }

  // SÉCURITÉ: erreurs jamais tolérées, même pour un domaine de confiance
  const rejectErrors = ['net::ERR_CERT_REVOKED', 'net::ERR_CERT_COMMON_NAME_INVALID', 'net::ERR_CERT_INVALID'];
  if (rejectErrors.includes(error)) {
    log.warn('[SSL] Certificat rejeté pour ' + hostname + ': ' + error);
    callback(false);
    return;
  }

  // SÉCURITÉ: pinning — si TRUSTED_CERT_FINGERPRINTS est configuré, l'empreinte SHA-256
  // du certificat doit correspondre exactement. Sans pinning, repli (moins sûr) sur la
  // confiance par domaine : tout certificat auto-signé présenté pour ce domaine est accepté.
  const pinned = getTrustedCertFingerprints();
  if (pinned.length > 0) {
    if (fingerprintMatches(certificate, pinned)) {
      callback(true);
    } else {
      log.warn('[SSL] Empreinte de certificat inconnue pour ' + hostname + ' — refusé (pinning actif)');
      callback(false);
    }
    return;
  }
  if (!certWarningShown) {
    certWarningShown = true;
    log.warn('[SSL] Certificat auto-signé accepté par domaine de confiance. Configurez TRUSTED_CERT_FINGERPRINTS pour activer le pinning.');
  }
  callback(true);
});

/** Nom d'hôte comparable (minuscules, sans crochets IPv6 ni point final) */
function normalizeCertHost(host) {
  return String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

/**
 * SÉCURITÉ (REMOTE-3) : épinglage TLS appliqué à CHAQUE vérification de certificat du serveur Vault, pas
 * seulement aux certificats que Chromium juge invalides ('certificate-error' ci-dessus). Avec
 * use-system-ca-store, un certificat qui chaîne vers une autorité du magasin Windows (CA publique, CA
 * d'entreprise, boîtier d'inspection TLS déployé par GPO) ne passait jamais par le contrôle d'empreinte : il
 * était accepté quelle que soit son empreinte, malgré TRUSTED_CERT_FINGERPRINTS.
 * Décision (callback de session.setCertificateVerifyProc) :
 *   -2 (refus)  : hôte de VAULT_URL, épinglage configuré, empreinte absente de la liste ;
 *   -3 (Chromium) sinon : vérification normale, puis 'certificate-error' pour un certificat invalide
 *                (domaines de confiance et empreinte, règles inchangées). Rien n'est jamais accepté ici.
 * @param {{ hostname: string, certificate: object, verificationResult?: string }} request
 * @returns {number}
 */
function vaultCertVerifyDecision(request) {
  let pins;
  try { pins = getTrustedCertFingerprints(); } catch { return -3; }
  if (!Array.isArray(pins) || pins.length === 0) return -3;
  let vaultHost = '';
  try { vaultHost = normalizeCertHost(new URL(getConfig().VAULT_URL || '').hostname); } catch { return -3; }
  const host = normalizeCertHost(request && request.hostname);
  if (!vaultHost || host !== vaultHost) return -3;
  if (fingerprintMatches(request.certificate, pins)) return -3;
  log.warn('[SSL] Empreinte de certificat inconnue pour ' + host + ' — refusé (pinning actif, '
    + String((request && request.verificationResult) || 'vérification système').slice(0, 64) + ')');
  return -2;
}

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
// Serveur HTTP qui écoute sur 127.0.0.1:45678 pour l'extension Chrome appairée.
// Endpoints (GET uniquement) :
// - /auth/token                          : token de session (appairage à la première demande)
// - /sync                                : état de connexion (aucun secret)
// - /api/secrets?host=<hôte>             : secrets de cet hôte, SANS mot de passe ni notes
// - /api/secret?host=&engine=&name=      : un secret avec mot de passe (à la sélection explicite)
// - /api/totp/<clé>                      : code TOTP généré par le renderer
// Sécurité :
// - Origin chrome-extension:// strictement formé et appairé, sur tous les endpoints
// - Bearer token (comparaison timing-safe) sur tous les endpoints sauf /auth/token
// - État en mémoire uniquement, expiré après SYNC_TIMEOUT_MS sans heartbeat

let syncServer = null;
// Échec d'écoute du serveur de synchronisation (code d'erreur, ex. EADDRINUSE) ; null si le serveur écoute
let syncServerError = null;
let syncPortWarningShown = false;

function sendJson(res, status, body) {
  res.writeHead(status);
  res.end(JSON.stringify(body));
}

/**
 * Envoie une requête au renderer (fenêtre principale) et attend sa réponse, via IPC
 * corrélée par requestId. Même motif que le TOTP. Utilisé pour les passkeys (lecture/
 * écriture dans le coffre, qui n'est accessible qu'avec le token Vault du renderer).
 */
function requestFromRenderer(channel, payload, timeoutMs) {
  return new Promise((resolve) => {
    if (!mainWindow || mainWindow.isDestroyed()) return resolve({ success: false, error: 'Desktop app not ready' });
    const requestId = crypto.randomBytes(8).toString('hex');
    let done = false;
    const handler = (event, result) => {
      if (event.sender !== mainWindow?.webContents) return; // SÉCURITÉ: réponse de la fenêtre principale uniquement
      if (done) return; done = true; clearTimeout(t);
      resolve(result || { success: false, error: 'no result' });
    };
    ipcMain.once(channel + '-response-' + requestId, handler);
    const t = setTimeout(() => {
      if (done) return; done = true;
      ipcMain.removeListener(channel + '-response-' + requestId, handler);
      resolve({ success: false, error: 'timeout' });
    }, timeoutMs);
    mainWindow.webContents.send(channel, { ...payload, requestId });
  });
}

/** Lit le corps JSON d'une requête (limite de taille), renvoie null si invalide/trop gros */
function readJsonBody(req, maxBytes) {
  return new Promise((resolve) => {
    // Accumule les Buffers (limite en OCTETS) et ne décode qu'une fois : pas de caractère UTF-8 coupé entre deux chunks
    const chunks = []; let size = 0; let tooBig = false;
    // Trop gros : régler AVANT destroy(), qui n'émet ni 'end' ni 'error' sur un http.IncomingMessage (seulement 'close')
    req.on('data', c => { if (tooBig) return; size += c.length; if (size > maxBytes) { tooBig = true; resolve(null); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => { if (tooBig) return resolve(null); try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve(null); } });
    req.on('error', () => resolve(null));
  });
}

function startSyncServer() {
  const syncStart = Date.now();
  loadPairedExtensions();
  syncAuthToken = crypto.randomBytes(CONFIG.AUTH_TOKEN_BYTES).toString('hex');

  // Rate limiting simple (tout vient de 127.0.0.1 : les limites sont de fait globales).
  // Deux compteurs indépendants par fenêtre d'une minute :
  // - « lecture » : /sync et /api/secrets (état en mémoire, JAMAIS de mot de passe ni de
  //   notes), appelés à chaque onglet par l'extension : une rafale d'onglets ne doit ni
  //   bloquer l'extension ni épuiser la limite des routes sensibles ;
  // - « défaut » : tout le reste (appairage /auth/token, /api/secret avec mot de passe,
  //   TOTP, passkeys, routes inconnues), limite inchangée.
  const syncRateLimit = new Map();
  const SYNC_RATE_LIMIT = 60;
  const SYNC_READ_RATE_LIMIT = 600;
  const SYNC_RATE_WINDOW = 60000;
  const SYNC_READ_ROUTES = new Set(['/sync', '/api/secrets']);

  syncServer = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Frame-Options', 'DENY');

    if (req.method !== 'GET' && req.method !== 'OPTIONS' && req.method !== 'POST') {
      return sendJson(res, 405, { error: 'Method not allowed' });
    }

    const clientIp = req.socket.remoteAddress;
    const now = Date.now();
    let limitedRoute = '';
    try { limitedRoute = new URL(req.url, 'http://127.0.0.1').pathname; } catch { /* compteur par défaut */ }
    const isReadRoute = (req.method === 'GET' || req.method === 'OPTIONS') && SYNC_READ_ROUTES.has(limitedRoute);
    const rateKey = clientIp + (isReadRoute ? '|read' : '|default');
    const rateMax = isReadRoute ? SYNC_READ_RATE_LIMIT : SYNC_RATE_LIMIT;
    const rateEntry = syncRateLimit.get(rateKey);
    if (rateEntry && now - rateEntry.start < SYNC_RATE_WINDOW) {
      rateEntry.count++;
      if (rateEntry.count > rateMax) return sendJson(res, 429, { error: 'Too many requests' });
    } else {
      syncRateLimit.set(rateKey, { start: now, count: 1 });
    }
    if (syncRateLimit.size > 100) {
      for (const [ip, entry] of syncRateLimit) {
        if (now - entry.start > SYNC_RATE_WINDOW) syncRateLimit.delete(ip);
      }
    }

    // SÉCURITÉ: seules les origines chrome-extension:// au format strict sont acceptées
    // Identification de l'extension : header Origin (envoyé par Chrome quand CORS s'applique) ou,
    // à défaut, header X-Vault-Extension-Id (Chrome omet Origin sur les hôtes couverts par host_permissions).
    // Les deux sont forgeables par un processus local : la sécurité repose sur l'approbation explicite
    // de l'identifiant par l'utilisateur et sur le bearer token, pas sur ce header.
    const origin = req.headers.origin;
    let extId = extensionIdFromOrigin(origin);
    if (!extId) {
      const headerId = req.headers['x-vault-extension-id'];
      if (typeof headerId === 'string' && EXTENSION_ID_RE.test(headerId)) extId = headerId;
    }
    if (extId && origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Vault-Extension, X-Vault-Extension-Id');
      // Chrome 117+ : Private Network Access (accès à 127.0.0.1 depuis un service worker)
      res.setHeader('Access-Control-Allow-Private-Network', 'true');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(extId ? 200 : 403);
      return res.end();
    }

    if (!extId) {
      // L'origine est journalisée (tronquée) pour faciliter le diagnostic d'appairage ; ce n'est pas un secret
      log.warn('[Sync] Requête refusée: origin non extension (' + String(origin || 'absent').slice(0, 64) + ')');
      return sendJson(res, 403, { error: 'Forbidden: Chrome extension origin required' });
    }

    const reqUrl = new URL(req.url, 'http://127.0.0.1');
    const route = reqUrl.pathname;

    // Obtention du token : appairage explicite de l'extension à la première demande
    if (route === '/auth/token' && req.method === 'GET') {
      if (req.headers['x-vault-extension'] !== 'rdvault') {
        return sendJson(res, 403, { error: 'Forbidden: Chrome extension origin required' });
      }
      if (!syncAuthToken) return sendJson(res, 503, { error: 'Token not ready' });
      const approved = await requestExtensionPairing(extId);
      if (!approved) return sendJson(res, 403, { error: 'pairing_denied' });
      return sendJson(res, 200, { token: syncAuthToken });
    }

    // Tous les autres endpoints : extension appairée ET bearer valide
    if (!pairedExtensionIds.has(extId)) return sendJson(res, 403, { error: 'pairing_required' });
    if (!verifyAuthToken(req)) {
      return sendJson(res, 401, { error: 'Unauthorized', message: 'Token d\'authentification manquant ou invalide' });
    }

    if (route === '/sync' && req.method === 'GET') {
      if (!syncStateIsFresh()) return sendJson(res, 200, { connected: false });
      return sendJson(res, 200, {
        connected: true,
        vaultUrl: syncState.vaultUrl,
        username: syncState.username,
        timestamp: syncState.timestamp
      });
    }

    if ((route === '/api/secrets' || route === '/api/secret') && req.method === 'GET') {
      if (!syncStateIsFresh()) return sendJson(res, 401, { error: 'Not authenticated' });
      const host = String(reqUrl.searchParams.get('host') || '').toLowerCase();
      if (!isValidHostname(host)) {
        return sendJson(res, 400, { error: 'Missing or invalid host parameter' });
      }
      const matching = syncState.secrets.filter(s => secretMatchesHost(s, host));

      if (route === '/api/secrets') {
        // SÉCURITÉ: jamais de mot de passe ni de notes dans la liste
        return sendJson(res, 200, {
          success: true,
          secrets: matching.map(s => ({ name: s.name, engine: s.engine, username: s.username, url: s.url, type: s.type }))
        });
      }

      const engine = String(reqUrl.searchParams.get('engine') || '');
      const name = String(reqUrl.searchParams.get('name') || '');
      const secret = matching.find(s => s.engine === engine && s.name === name);
      if (!secret) return sendJson(res, 404, { error: 'Secret not found for this host' });
      log.info('[Sync] Mot de passe transmis à l\'extension pour ' + host);
      return sendJson(res, 200, {
        success: true,
        secret: { name: secret.name, engine: secret.engine, username: secret.username, password: secret.password, url: secret.url, type: secret.type }
      });
    }

    if (route.startsWith('/api/totp/') && req.method === 'GET') {
      if (!syncStateIsFresh()) return sendJson(res, 401, { error: 'Not authenticated' });
      let totpKeyName;
      try {
        totpKeyName = decodeURIComponent(route.slice('/api/totp/'.length));
      } catch {
        return sendJson(res, 400, { error: 'Invalid TOTP key name' });
      }
      // « / » accepté (SYNC-27) : une entrée rangée dans un dossier a pour nom son chemin complet (« dossier/compte »),
      // donc une clé TOTP « PRÉFIXE-dossier/compte », créée et servie par l'application ; le renderer encode le nom
      // (encodeURIComponent) avant de l'insérer dans l'URL du coffre. « .. », « \ » et caractères de contrôle restent refusés.
      // eslint-disable-next-line no-control-regex -- volontaire : nom de clé TOTP avec caractère de contrôle refusé
      if (!totpKeyName || totpKeyName.includes('..') || /[\\\x00-\x1F\x7F]/.test(totpKeyName)) {
        return sendJson(res, 400, { error: 'Invalid TOTP key name' });
      }
      if (totpKeyName.length > CONFIG.MAX_TOTP_KEY_LENGTH) return sendJson(res, 400, { error: 'TOTP key name too long' });
      if (!mainWindow || mainWindow.isDestroyed()) return sendJson(res, 500, { error: 'Desktop app not ready' });

      // Demander au renderer de générer le code (ID de corrélation + timeout)
      const requestId = crypto.randomBytes(8).toString('hex');
      let responded = false;
      const totpHandler = (event, result) => {
        // SÉCURITÉ: la réponse doit provenir de la fenêtre principale
        if (event.sender !== mainWindow?.webContents) return;
        if (responded) return;
        responded = true;
        clearTimeout(timeout);
        if (result && result.success) sendJson(res, 200, { success: true, code: result.code });
        else sendJson(res, 404, { error: (result && result.error) || 'TOTP not found' });
      };
      ipcMain.once('totp-code-response-' + requestId, totpHandler);
      const timeout = setTimeout(() => {
        if (responded) return;
        responded = true;
        ipcMain.removeListener('totp-code-response-' + requestId, totpHandler);
        sendJson(res, 500, { error: 'Timeout' });
      }, CONFIG.TOTP_REQUEST_TIMEOUT_MS);
      mainWindow.webContents.send('get-totp-code', totpKeyName, requestId);
      return;
    }

    // ----- Passkeys (WebAuthn) : stockées dans le coffre chiffré via le renderer -----
    if (route === '/api/passkeys' && req.method === 'GET') {
      if (!syncStateIsFresh()) return sendJson(res, 401, { error: 'Not authenticated' });
      const rpId = String(reqUrl.searchParams.get('rpId') || '').toLowerCase();
      if (!isValidHostname(rpId)) return sendJson(res, 400, { error: 'Invalid rpId' });
      const result = await requestFromRenderer('passkey-list', { rpId }, CONFIG.TOTP_REQUEST_TIMEOUT_MS);
      return sendJson(res, result && result.success ? 200 : 500, result || { success: false });
    }
    if (route === '/api/passkey' && req.method === 'POST') {
      if (!syncStateIsFresh()) return sendJson(res, 401, { error: 'Not authenticated' });
      const body = await readJsonBody(req, 16384);
      const pk = body && body.passkey;
      if (!pk || !isValidHostname(String(pk.rpId || '').toLowerCase()) || typeof pk.credentialId !== 'string' || typeof pk.privateKeyJwk !== 'object') {
        return sendJson(res, 400, { error: 'Invalid passkey' });
      }
      log.info('[Sync] Enregistrement d\'une passkey pour ' + String(pk.rpId).toLowerCase());
      const result = await requestFromRenderer('passkey-store', { passkey: pk }, 15000);
      return sendJson(res, result && result.success ? 200 : 500, result || { success: false });
    }
    if (route === '/api/passkey/count' && req.method === 'POST') {
      if (!syncStateIsFresh()) return sendJson(res, 401, { error: 'Not authenticated' });
      const body = await readJsonBody(req, 4096);
      if (!body || !isValidHostname(String(body.rpId || '').toLowerCase()) || typeof body.credentialId !== 'string') {
        return sendJson(res, 400, { error: 'Invalid request' });
      }
      const result = await requestFromRenderer('passkey-update-count', { rpId: String(body.rpId).toLowerCase(), credentialId: body.credentialId, signCount: Number(body.signCount) || 0 }, 10000);
      return sendJson(res, result && result.success ? 200 : 500, result || { success: false });
    }

    return sendJson(res, 404, { error: 'Not found' });
  });

  syncServer.listen(CONFIG.SYNC_PORT, '127.0.0.1', () => {
    syncServerError = null;
    log.info('[Sync] Serveur prêt sur http://127.0.0.1:' + CONFIG.SYNC_PORT + ' (' + (Date.now() - syncStart) + 'ms)');
  });
  syncServer.on('error', (err) => {
    log.error('[Sync] Erreur serveur:', err.message);
    // SYNC-30 : port fixe déjà pris (RDVAULT d'une autre session Windows sur ce poste, autre programme) ou
    // réservé. L'échec n'était que journalisé : l'extension de ce navigateur pouvait alors joindre une autre
    // application que la sienne. Avertissement visible, traduit, une seule fois ; boîte INDÉPENDANTE (sans
    // fenêtre parente) : la fenêtre principale reste utilisable. État exposé par sync-read-state.
    const code = typeof (err && err.code) === 'string' ? err.code.slice(0, 32) : 'UNKNOWN';
    if (!['EADDRINUSE', 'EACCES', 'EADDRNOTAVAIL'].includes(code)) return;
    syncServerError = code;
    if (syncPortWarningShown) return;
    syncPortWarningShown = true;
    dialog.showMessageBox({
      type: 'warning',
      title: tm('syncPort.title'),
      message: tm('syncPort.message', { port: CONFIG.SYNC_PORT }),
      detail: tm('syncPort.detail', { port: CONFIG.SYNC_PORT, code }),
      noLink: true,
    }).catch(() => {});
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
      log.error('loadFile error:', err);
      dialog.showErrorBox(tm('load.failed'), String(err));
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
          log.warn('[SECURITY] ELECTRON_START_URL non-localhost ignorée');
        }
      } catch {
        log.warn('[SECURITY] ELECTRON_START_URL invalide, utilisation de localhost:3000');
      }
    }
    log.warn('[Electron] build/index.html introuvable. Mode DEV →', devUrl);
    win.loadURL(devUrl).catch(err => {
      log.error('loadURL error:', err);
      dialog.showErrorBox(tm('load.failedDev'), String(err));
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
 * - Démarre en mode login (LOGIN_WIDTH×LOGIN_HEIGHT, frameless) puis passe en mode principal (MAIN_WIDTH×MAIN_HEIGHT)
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
  log.info('[PERF] createWindow begin');

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
      webviewTag: false,
      spellcheck: false,
      v8CacheOptions: 'code',
      devTools: !app.isPackaged,
    },
  });

  log.info(`[PERF] BrowserWindow created: ${Date.now() - winStart}ms`);

  // SÉCURITÉ: Désactiver l'ouverture des DevTools en production
  if (app.isPackaged) {
    mainWindow.webContents.on('devtools-opened', () => {
      mainWindow.webContents.closeDevTools();
      log.warn('⚠️ Tentative d\'ouverture des DevTools bloquée (mode production)');
    });
  }

  // SÉCURITÉ: Refuser toutes les demandes de permissions (caméra, micro, géoloc, notifications)
  mainWindow.webContents.session.setPermissionRequestHandler((webContents, permission, callback) => {
    log.warn(`[SECURITY] Permission refusée: ${permission}`);
    callback(false);
  });
  mainWindow.webContents.session.setPermissionCheckHandler(() => false);

  // SÉCURITÉ (REMOTE-3) : épinglage TLS du serveur Vault vérifié pour TOUT certificat présenté, y compris un
  // certificat reconnu par le magasin système (voir vaultCertVerifyDecision)
  try {
    mainWindow.webContents.session.setCertificateVerifyProc((request, callback) => {
      callback(vaultCertVerifyDecision(request));
    });
  } catch (err) {
    log.error('[SSL] Vérification des certificats (épinglage) non installée : ' + (err && err.message));
  }

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
  // REMOTE-4 : proxy RBI (partage de sessions) joint depuis le renderer (ShareRbiModal : /create-share,
  // /unwrap-rbi) : son origine doit figurer dans connect-src. Mode entreprise uniquement (get-app-config ne
  // l'expose pas en mode local), https obligatoire, origine seule (aucun chemin ni caractère injecté).
  let safeRbiOrigin = '';
  if (!isLocalMode) {
    try {
      const rbiProxy = new URL(getConfig().RBI_PROXY_URL || '');
      if (rbiProxy.protocol === 'https:') safeRbiOrigin = rbiProxy.origin;
    } catch { /* non configuré ou invalide : non autorisé */ }
  }
  const connectSources = ["'self'", safeVaultUrl, safeRbiOrigin, `http://127.0.0.1:${CONFIG.SYNC_PORT}`, 'https://api.pwnedpasswords.com']
    .filter(Boolean).join(' ');

  mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self';",
          "script-src 'self';",
          "style-src 'self' 'unsafe-inline';",
          "img-src 'self' data:;",
          `connect-src ${connectSources};`,
          "frame-src 'none';",
          "object-src 'none';",
          "base-uri 'self';",
          "form-action 'self';",
          "frame-ancestors 'none';"
        ].join(' ')
      }
    });
  });
  log.info('🔒 Content Security Policy appliquée');

  // SÉCURITÉ: Bloquer la navigation vers des URLs externes
  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(navigationUrl);
    } catch {
      event.preventDefault();
      return;
    }
    // Autoriser uniquement localhost (dev) — file:// restreint au dossier de l'application
    if (parsedUrl.protocol === 'file:') {
      const appDir = path.resolve(app.isPackaged ? path.dirname(process.execPath) : path.join(__dirname, '..'));
      let navPath = '';
      try { navPath = path.resolve(fileURLToPath(parsedUrl)); } catch { navPath = ''; }
      if (!navPath || !(navPath === appDir || navPath.startsWith(appDir + path.sep))) {
        event.preventDefault();
        log.warn('[SECURITY] Navigation file:// bloquée hors app');
      }
    } else if (parsedUrl.hostname !== 'localhost' || app.isPackaged) {
      event.preventDefault();
      log.warn('[SECURITY] Navigation bloquée vers: ' + parsedUrl.origin);
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
            log.warn('[SECURITY] Ouverture externe bloquée: domaine non autorisé');
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
  log.info(`[PERF] loadApp called: ${Date.now() - winStart}ms`);

  // Mise à jour automatique (no-op en dev ou si electron-updater absent)
  try {
    const { initAutoUpdater } = require('./autoUpdater');
    initAutoUpdater(() => mainWindow, { app, ipcMain });
  } catch (err) {
    log.warn('[Update] init ignorée: ' + (err && err.message));
  }

  // Afficher la fenêtre RAPIDEMENT (après un court délai pour éviter le flash)
  setTimeout(() => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      log.info(`[PERF] Window shown (early): ${Date.now() - winStart}ms`);
      mainWindow.show();
      mainWindow.focus();
    }
  }, 500);

  mainWindow.once('ready-to-show', () => {
    log.info(`[PERF] Content ready-to-show: ${Date.now() - winStart}ms`);
    try {
      mainWindow.webContents.focus();
      mainWindow.webContents.setIgnoreMenuShortcuts(true);
    } catch {};
  });

  mainWindow.webContents.on('did-finish-load', () => {
    log.info(`[PERF] Content did-finish-load: ${Date.now() - winStart}ms`);
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

  // SÉCURITÉ (SYNC-28) : l'état de synchronisation (mots de passe servis à l'extension) n'est vidé que par le
  // renderer (déconnexion, délai d'inactivité) ou à la sortie. Renderer planté (mémoire, GPU, V8) : la fenêtre
  // sans cadre reste affichée mais morte, sans déconnexion possible ; interface rechargée : retour à l'écran de
  // connexion (session perdue). Dans ces cas, l'état est purgé immédiatement.
  const ownWebContents = mainWindow.webContents;
  const ownWindow = mainWindow;
  ownWebContents.on('render-process-gone', (_event, details) => {
    rendererUnresponsive = false; // processus disparu : l'état « planté » (isCrashed) prend le relais
    purgeSyncState('renderer arrêté (' + String((details && details.reason) || 'inconnu').slice(0, 32) + ')');
  });
  ownWebContents.on('did-navigate', () => {
    rendererUnresponsive = false; // nouveau document
    purgeSyncState('interface rechargée');
  });

  // Renderer FIGÉ ('unresponsive', détecté par Chromium après plusieurs secondes sans réponse) : même purge
  // que pour un plantage, et plus aucun état servi ni prolongé tant qu'il ne répond pas (une écriture
  // reçue juste avant le gel ne doit pas être resservie). De nouveau réactif ('responsive') : il est
  // invité à republier son état (useSync, depuis son cache, seulement si sa session est encore ouverte à
  // ce moment ; une déconnexion ou une expiration traitée ensuite purge l'état comme d'habitude).
  ownWindow.on('unresponsive', () => {
    if (mainWindow !== ownWindow) return;
    rendererUnresponsive = true;
    purgeSyncState('interface figée');
  });
  ownWindow.on('responsive', () => {
    if (mainWindow !== ownWindow || !rendererUnresponsive) return;
    rendererUnresponsive = false;
    log.info('[Sync] Interface de nouveau réactive : republication de l\'état demandée');
    try {
      if (!ownWebContents.isDestroyed()) ownWebContents.send('sync-resync-request');
    } catch { /* fenêtre en cours de fermeture : rien à republier */ }
  });

  mainWindow.on('closed', () => {
    if (mainWindow === ownWindow) rendererUnresponsive = false;
    purgeSyncState('fenêtre principale fermée');
    mainWindow = null;
  });
}

// ========================================
// HANDLERS IPC - Communication avec React
// ========================================
// Les handlers IPC permettent à React d'appeler des fonctions Node.js/Electron
// de manière sécurisée via contextBridge et ipcRenderer (défini dans preload.js)

// Stockage des timers de copie sécurisée en cours : la clé 'current' désigne la copie la
// plus récente, celle qu'effacent « Effacer maintenant » et la fermeture (will-quit).
let activeClipboardTimers = new Map();

/**
 * Enregistre une copie sécurisée (clipboard-copy-secure, mot de passe RDP / SFTP) comme
 * copie courante, pour que la fermeture de l'application et « Effacer maintenant »
 * l'effacent (presse-papiers s'il la contient encore + historique Win+V).
 * La copie précédente est annulée : son contenu a été remplacé dans le presse-papiers et
 * l'historique sera vidé par la nouvelle. Après le délai, l'entrée n'est retirée que si
 * elle désigne encore CETTE copie (une copie plus récente ne doit pas être « oubliée »).
 */
function trackSecureClipboardCopy(timer, timeoutMs) {
  const previous = activeClipboardTimers.get('current');
  if (previous && previous !== timer) previous.cancel();
  activeClipboardTimers.set('current', timer);
  setTimeout(() => {
    if (activeClipboardTimers.get('current') === timer) activeClipboardTimers.delete('current');
  }, timeoutMs + 100);
  return timer;
}

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

    // Créer le nouveau timer (copie + auto-effacement après délai), enregistré comme
    // copie courante (nettoyage différé conditionné à son identité)
    trackSecureClipboardCopy(copyPasswordWithAutoClear(text, { timeoutMs }), timeoutMs);

    return { success: true, timeoutMs };
  } catch (error) {
    log.error('Erreur lors de la copie sécurisée');
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
    log.error('Erreur lors de l\'effacement du presse-papier');
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
    log.error('Erreur lors de l\'effacement du presse-papier');
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
    log.error('Erreur copie lien riche');
    return { success: false, error: 'Erreur copie lien' };
  }
});

// Gestionnaire IPC pour écrire l'état de synchronisation (en mémoire uniquement)
ipcMain.handle('sync-write-state', (event, state) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    if (!state || typeof state !== 'object') return { success: false, error: 'État invalide' };

    // Déconnexion : purger immédiatement
    if (!state.connected) {
      syncState = null;
      return { success: true };
    }

    // SÉCURITÉ: Whitelist des champs autorisés (évite la pollution de données)
    // Le renderer envoie TOUTES les entrées de TOUS les coffres (aplaties dans l'ordre des noms) : l'ancien
    // plafond silencieux de 5 000 privait l'autoremplissage des entrées suivantes (souvent les autres coffres).
    // Plafond de défense en profondeur (renderer compromis) très au-delà d'un usage réel, limites de taille
    // par champ conservées ; s'il est atteint, la troncature est SIGNALÉE (réponse, sync-read-state, journal).
    const all = Array.isArray(state.secrets) ? state.secrets : [];
    const kept = all.length > CONFIG.MAX_SYNC_SECRETS ? all.slice(0, CONFIG.MAX_SYNC_SECRETS) : all;
    const truncated = all.length - kept.length;
    const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
    syncState = {
      vaultUrl: str(state.vaultUrl, 2048),
      username: str(state.username, 256),
      connected: true,
      secrets: kept.map(s => ({
        name: str(s.name, 512),
        engine: str(s.engine, 256),
        username: str(s.username, 512),
        password: str(s.password, 10000),
        url: str(s.url, 2048),
        website: str(s.website, 2048),
        type: str(s.type, 64)
      })),
      truncated,
      timestamp: Date.now()
    };
    if (truncated > 0) {
      log.warn(`[Sync] ${truncated} entrée(s) au-delà de ${CONFIG.MAX_SYNC_SECRETS} non transmise(s) à l'extension`);
      return { success: true, stored: kept.length, truncated };
    }
    return { success: true, stored: kept.length };
  } catch {
    return { success: false, error: 'Erreur écriture sync' };
  }
});

// Gestionnaire IPC pour lire l'état de synchronisation (sans mot de passe)
ipcMain.handle('sync-read-state', (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
  // serverError : échec d'écoute du serveur de synchronisation (SYNC-30, ex. EADDRINUSE), sinon null
  // Tolérance de deux intervalles de heartbeat pour éviter la course à la limite
  if (!syncState || Date.now() - syncState.timestamp > 2 * CONFIG.HEARTBEAT_INTERVAL_MS) {
    return { success: true, data: null, serverError: syncServerError };
  }
  return {
    success: true,
    serverError: syncServerError,
    data: {
      vaultUrl: syncState.vaultUrl,
      username: syncState.username,
      connected: syncState.connected,
      timestamp: syncState.timestamp,
      secretCount: syncState.secrets.length,
      truncated: syncState.truncated || 0 // entrées non transmises à l'extension (plafond atteint)
    }
  };
});

// Le fichier de sync n'existe plus : conservé pour compatibilité de l'API preload
ipcMain.handle('sync-get-path', () => ({ success: false, error: 'État de synchronisation en mémoire uniquement' }));

// Token du serveur sync (en mémoire) — pour affichage dans les paramètres
ipcMain.handle('sync-get-auth-token', (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
  if (!syncAuthToken) return { success: false, error: 'Token not ready' };
  return { success: true, token: syncAuthToken };
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
    log.error('Erreur lors de la récupération de la configuration');
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
ipcMain.handle('get-installed-browsers', async (event) => {
  try {
    if (!validateIpcSender(event)) return { success: false, browsers: [] };
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
    log.error('Erreur lors de la détection des navigateurs:', error);
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
      return { success: false, error: tm('error.puttyNotFound') };
    }

    const target = username ? `${username}@${host}` : host;
    const args = ['-ssh'];
    if (port && String(port) !== '22') args.push('-P', String(port));
    args.push(target);

    // SÉCURITÉ: Ne pas logger les arguments complets (peuvent contenir des informations sensibles)
    log.info('[SSH] Lancement PuTTY vers', host);

    // Lancer PuTTY
    spawn(puttyPath, args, {
      detached: true,
      stdio: 'ignore'
    }).unref();

    return { success: true };
  } catch (error) {
    log.error('Erreur ouverture SSH');
    return { success: false, error: tm('error.sshOpen') };
  }
});

// Gestionnaire pour ouvrir les liens avec l'application système par défaut (rdp://, ftp://, etc.)
ipcMain.handle('open-external-link', async (event, url) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Valider le schéma URL pour empêcher les protocoles dangereux (file:, ms-msdt:, etc.)
    if (!validateUrlScheme(url)) {
      return { success: false, error: tm('error.urlSchemeNotAllowed') };
    }
    await shell.openExternal(url);
    return { success: true };
  } catch (error) {
    return { success: false, error: tm('error.linkOpen') };
  }
});

// Gestionnaire pour ouvrir une connexion RDP avec auto-remplissage des credentials
ipcMain.handle('open-rdp-connection', async (event, params) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    const { host, username, password, port } = params;

    const v = validateConnectionParams(host, username, port);
    if (!v.valid) return { success: false, error: v.error };

    // Domaine : format DOMAINE\utilisateur, ou paramètre domain explicite.
    // Le format UPN (utilisateur@domaine) est transmis tel quel : mstsc le gère nativement.
    let domain = typeof params.domain === 'string' ? params.domain : '';
    let user = username || '';
    if (username && username.includes('\\')) {
      const idx = username.indexOf('\\');
      domain = username.slice(0, idx);
      user = username.slice(idx + 1);
    }

    // SÉCURITÉ: Valider le domaine extrait contre l'injection de caractères de contrôle
    // eslint-disable-next-line no-control-regex -- volontaire : détection des caractères de contrôle
    if (domain && (/[\x00-\x1F\s;|&`$(){}#[\]/?%]/.test(domain) || domain.length > 253)) {
      return { success: false, error: tm('error.rdpDomainInvalid') };
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
      // Copie courante : effacée aussi à la fermeture et par « Effacer maintenant »
      trackSecureClipboardCopy(copyPasswordWithAutoClear(password, { timeoutMs: CONFIG.CLIPBOARD_TIMEOUT_MS || 12000 }), CONFIG.CLIPBOARD_TIMEOUT_MS || 12000);
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
    log.error('[RDP] Erreur');
    return { success: false, error: tm('error.rdpOpen') };
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
        // Copie courante : effacée aussi à la fermeture et par « Effacer maintenant »
        trackSecureClipboardCopy(copyPasswordWithAutoClear(password, { timeoutMs: CONFIG.CLIPBOARD_TIMEOUT_MS || 12000 }), CONFIG.CLIPBOARD_TIMEOUT_MS || 12000);
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
        // Copie courante : effacée aussi à la fermeture et par « Effacer maintenant »
        trackSecureClipboardCopy(copyPasswordWithAutoClear(password, { timeoutMs: CONFIG.CLIPBOARD_TIMEOUT_MS || 12000 }), CONFIG.CLIPBOARD_TIMEOUT_MS || 12000);
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
      return { success: false, error: tm('error.sftpClientMissing') };
    }
  } catch (error) {
    log.error('[SFTP] Erreur');
    return { success: false, error: tm('error.sftpOpen') };
  }
});

ipcMain.handle('open-url-in-browser', async (event, url, browser) => {
  try {
    if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
    // SÉCURITÉ: Valider le schéma URL
    if (!validateUrlScheme(url)) {
      return { success: false, error: tm('error.urlSchemeNotAllowed') };
    }

    if (browser === 'default') {
      // Ouvrir avec le navigateur par défaut
      await shell.openExternal(url);
      return { success: true };
    }

    const ALLOWED_BROWSERS = ['chrome', 'firefox', 'edge', 'brave'];
    if (browser && browser !== 'default' && !ALLOWED_BROWSERS.includes(browser)) {
      return { success: false, error: tm('error.browserUnknown') };
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
      return { success: false, error: tm('error.invalidUrl') };
    }
    spawn(browserPath, ['--', url], { detached: true, stdio: 'ignore' }).unref();
    return { success: true };
  } catch (error) {
    log.error('Erreur lors de l\'ouverture de l\'URL:', error.message);
    // Fallback sur le navigateur par défaut
    try {
      await shell.openExternal(url);
      return { success: true, fallback: true };
    } catch {
      return { success: false, error: tm('error.urlOpen') };
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
    log.error('Erreur lors de la lecture du fichier de logs');
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
      if (!/^\/var\/log\/vault\/[a-zA-Z0-9._\-/]+$/.test(filePath)) {
        return { success: false, error: 'Chemin SSH non autorisé. Seuls /var/log/vault/* sont accessibles.' };
      }

      // Valider sshConfig: whitelister les champs et restreindre les valeurs
      if (typeof sshConfig.host !== 'string' || sshConfig.host.length > 253 || /[\s;|&`$]/.test(sshConfig.host)) {
        return { success: false, error: 'Hôte SSH invalide' };
      }
      // eslint-disable-next-line no-control-regex -- volontaire : utilisateur SSH avec caractère de contrôle refusé
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
      // Empreinte de clé d'hôte épinglée (facultative) : « SHA256:<base64> », avec ou sans padding
      if (sshConfig.hostFingerprint !== undefined && sshConfig.hostFingerprint !== null) {
        if (typeof sshConfig.hostFingerprint !== 'string' || !/^(SHA256:)?[A-Za-z0-9+/]{43}=?$/i.test(sshConfig.hostFingerprint.trim())) {
          return { success: false, error: 'Empreinte de clé d\'hôte SSH invalide' };
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
    // Clé d'hôte SSH inconnue/changée/refusée : message explicite (code + empreintes attendue/observée)
    // remonté au renderer. Ces messages ne contiennent ni mot de passe ni contenu de fichier.
    if (error && typeof error.code === 'string' && (error.code.startsWith('HOST_KEY_') || error.code === 'KNOWN_HOSTS_WRITE')) {
      log.warn(`[Audit SSH] Clé d'hôte refusée (${error.code})`);
      return { success: false, error: error.message, code: error.code, expected: error.expected || null, observed: error.observed || null };
    }
    log.error('Erreur lors de la lecture du fichier de logs');
    return { success: false, error: 'Erreur lors de la lecture du fichier de logs' };
  }
});

/**
 * Invite l'utilisateur à accepter (et mémoriser) une clé d'hôte SSH inconnue lors de l'audit SSH.
 * Bouton par défaut : Refuser. Sans fenêtre principale, la clé est refusée.
 * Le signal (facultatif) ferme l'invite comme une annulation quand la connexion meurt pendant l'attente :
 * une invite annulée (ou répondue après l'annulation) renvoie false, rien n'est mémorisé.
 * @param {{ host: string, port: number, fingerprint: string }} info
 * @param {AbortSignal} [signal]
 * @returns {Promise<boolean>}
 */
async function confirmNewHostKey({ host, port, fingerprint }, signal) {
  const win = mainWindow && !mainWindow.isDestroyed() ? mainWindow : null;
  if (!win || (signal && signal.aborted)) return false;
  try {
    // Textes dans la langue de l'interface ; ordre des boutons inchangé (0 = mémoriser, 1 = refuser, par défaut)
    const { response } = await dialog.showMessageBox(win, {
      type: 'warning',
      buttons: [tm('button.rememberContinue'), tm('button.deny')],
      defaultId: 1,
      cancelId: 1,
      title: tm('hostKey.title'),
      message: tm('hostKey.message', { host, port }),
      detail: tm('hostKey.detail', { fingerprint }),
      noLink: true,
      ...(signal ? { signal } : {}),
    });
    return response === 0 && !(signal && signal.aborted);
  } catch {
    return false;
  }
}

/**
 * Fonction helper pour lire un fichier distant via SSH
 *
 * Utilisée par le gestionnaire IPC 'audit-tail-log-file' pour lire les logs Vault distants.
 * Établit une connexion SSH, exécute 'cat <file>', et retourne le contenu.
 *
 * Sécurité :
 * - Whitelist de chemins autorisés (/var/log/vault/* uniquement)
 * - Protection contre command injection (échappement du chemin avec single quotes)
 * - Vérification de la clé d'hôte AVANT l'envoi du mot de passe : empreinte épinglée (sshConfig.hostFingerprint),
 *   sinon mémoire known_hosts.json (userData, partagée avec le serveur CLI), sinon invite utilisateur ;
 *   clé changée/refusée/inconnue → rejet avec err.code HOST_KEY_* (err.expected / err.observed) ;
 *   connexion perdue pendant l'invite → invite fermée, rien mémorisé, err.code HOST_KEY_PROMPT_ABORTED
 * - Timeout de connexion (CONFIG.SSH_TIMEOUT_MS, suspendu pendant l'invite utilisateur)
 * - Timeout d'exécution après « ready » (CONFIG.SSH_EXEC_TIMEOUT_MS, 2 min par défaut) → err.code EXEC_TIMEOUT
 * - Limite de 50 Mo en octets ; contenu décodé une seule fois en UTF-8
 * - Authentification par mot de passe ou clé privée
 *
 * @param {string} filePath - Chemin du fichier à lire (doit commencer par /var/log/vault/)
 * @param {Object} sshConfig - Configuration SSH {host, port, username, password, privateKey, hostFingerprint}
 * @returns {Promise<string>} Contenu du fichier
 * @throws {Error} Si le chemin est invalide, la clé d'hôte est refusée, la connexion échoue, ou le fichier n'existe pas
 */
function readFileViaSSH(filePath, sshConfig) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    // Délai de connexion géré ici (readyTimeout: 0 côté ssh2) afin de le suspendre pendant l'invite utilisateur
    let connTimer = null;
    let execTimer = null;
    let connClosed = false; // connexion terminée : ne plus (ré)armer de délai
    const clearConnTimer = () => { if (connTimer) { clearTimeout(connTimer); connTimer = null; } };
    const clearExecTimer = () => { if (execTimer) { clearTimeout(execTimer); execTimer = null; } };
    const armConnTimer = () => {
      clearConnTimer();
      if (connClosed) return;
      connTimer = setTimeout(() => { reject(new Error('Délai de connexion SSH dépassé')); try { conn.destroy(); } catch { /* ignore */ } }, CONFIG.SSH_TIMEOUT_MS);
    };
    // Invite « clé d'hôte inconnue » en cours : fermée (AbortSignal) si la connexion meurt pendant l'attente
    // (ex. LoginGraceTime du serveur), sinon la boîte resterait affichée pour une lecture déjà échouée.
    let hostKeyPrompt = null;
    const abortHostKeyPrompt = () => {
      if (!hostKeyPrompt) return null;
      hostKeyPrompt.abort();
      // Message affiché tel quel dans un toast (AdminPanel) : langue de l'interface
      return Object.assign(new Error(tm('error.hostKeyPromptAborted')),
        { code: 'HOST_KEY_PROMPT_ABORTED', observed: hv.fingerprint });
    };

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
    // (le point est autorisé dans tous les segments, ex. /var/log/vault/audit.log ; '..' reste exclu ci-dessus et ci-dessous)
    if (!/^\/var\/log\/vault\/[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)*$/.test(filePath) || filePath.split('/').includes('..')) {
      return reject(new Error('Chemin de fichier non autorisé. Seuls les chemins /var/log/vault/* sont autorisés.'));
    }

    // Rejeter les caractères de shell dangereux (défense en profondeur)
    if (/[`$|;&\n\r]/.test(filePath)) {
      return reject(new Error('Chemin de fichier contient des caractères interdits.'));
    }

    // Échapper le chemin pour éviter l'injection de commandes (single quotes)
    const escapedPath = filePath.replace(/'/g, "'\\''");

    // SÉCURITÉ: vérification de la clé d'hôte pendant l'échange de clés (avant l'authentification).
    // Même fichier known_hosts.json que le serveur CLI ; une clé inconnue déclenche l'invite utilisateur.
    const sshHost = sshConfig.host;
    const sshPort = sshConfig.port || 22;
    const hv = createHostVerifier({
      host: sshHost,
      port: sshPort,
      hostFingerprint: sshConfig.hostFingerprint || null,
      knownHosts: createKnownHosts(path.join(app.getPath('userData'), 'known_hosts.json')),
      onNewHostKey: async (info) => {
        clearConnTimer();
        hostKeyPrompt = new AbortController();
        try { return await confirmNewHostKey(info, hostKeyPrompt.signal); } finally { hostKeyPrompt = null; armConnTimer(); }
      },
    });

    conn.on('ready', () => {
      clearConnTimer();
      // Délai d'EXÉCUTION : un canal jamais fermé (FIFO, périphérique, serveur lent ou hostile) ne bloque pas la lecture indéfiniment
      execTimer = setTimeout(() => {
        reject(Object.assign(new Error('Délai d\'exécution SSH dépassé'), { code: 'EXEC_TIMEOUT' }));
        try { conn.destroy(); } catch { /* ignore */ }
      }, CONFIG.SSH_EXEC_TIMEOUT_MS || 120000);
      conn.exec(`cat '${escapedPath}'`, (err, stream) => {
        if (err) {
          clearExecTimer();
          conn.end();
          return reject(err);
        }

        // SÉCURITÉ: Limite de taille (en OCTETS) pour éviter l'accumulation mémoire non bornée
        const MAX_SSH_FILE_SIZE = 50 * 1024 * 1024; // 50 MB max
        // Accumule les Buffers et ne décode qu'une fois : pas de caractère UTF-8 coupé entre deux paquets SSH
        const chunks = []; let size = 0; let tooBig = false;
        stream.on('close', (code, signal) => {
          clearExecTimer();
          conn.end();
          if (code !== 0) {
            reject(new Error(`Commande SSH échouée avec le code ${code}`));
          } else {
            resolve(Buffer.concat(chunks).toString('utf8'));
          }
        }).on('data', (data) => {
          if (tooBig) return;
          size += data.length;
          if (size > MAX_SSH_FILE_SIZE) {
            tooBig = true;
            chunks.length = 0;
            stream.destroy();
            conn.end();
            reject(new Error('Fichier trop volumineux (limite: 50 MB)'));
            return;
          }
          chunks.push(data);
        }).stderr.on('data', () => {
          log.error('SSH stderr: (contenu masqué)');
        });
      });
    }).on('error', (err) => {
      connClosed = true;
      clearConnTimer();
      clearExecTimer();
      // Clé d'hôte refusée : notre erreur (code HOST_KEY_*) remplace l'erreur générique ssh2 « Host denied »
      reject(abortHostKeyPrompt() || hv.error || new Error(`Connexion SSH échouée: ${err.message}`));
    }).on('close', () => {
      connClosed = true;
      clearConnTimer();
      clearExecTimer();
      reject(abortHostKeyPrompt() || hv.error || new Error('Connexion SSH fermée prématurément'));
    }).connect({
      host: sshHost,
      port: sshPort,
      username: sshConfig.username,
      password: sshConfig.password,
      privateKey: sshConfig.privateKey ? fs.readFileSync(fs.realpathSync(path.resolve(sshConfig.privateKey))) : undefined,
      readyTimeout: 0, // délai de connexion géré par connTimer (suspendu pendant l'invite)
      hostVerifier: hv.verifier
    });
    armConnTimer();
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
    // Champ « website » de l'entrée (facultatif) : seconde adresse de référence pour la saisie (RBI-11), comme
    // pour l'extension (url OU website). Seul son nom d'hôte sert (jamais ouvert : l'URL de lancement reste
    // options.url). Texte borné, sans caractère de contrôle, dont un nom d'hôte valide se déduit ; sinon ignoré.
    let website;
    // eslint-disable-next-line no-control-regex -- volontaire : valeur avec caractère de contrôle ignorée
    if (typeof options.website === 'string' && options.website.length <= 2048 && !/[\x00-\x1F\x7F]/.test(options.website)) {
      const host = hostnameOf(options.website);
      if (host && isValidHostname(host)) website = options.website.trim();
    }
    // Construire un objet propre (ne pas passer skipOverlay depuis le renderer)
    const safeOptions = {
      url: options.url,
      ...(website ? { website } : {}),
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
    log.error('[RBI] Erreur IPC launch-session');
    return { success: false, error: tm('rbi.launchError') };
  }
});

/**
 * Ferme une session RBI active
 */
ipcMain.handle('rbi-close-session', async (event, sessionId) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Sender non autorisé' };
  // SÉCURITÉ: Valider le sessionId
  if (typeof sessionId !== 'string' || !sessionId || sessionId.length > 128 || /[^a-zA-Z0-9_-]/.test(sessionId)) {
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
  // Redimensionner AVANT de verrouiller : sous Electron 38, setResizable(false) fige les tailles minimale et
  // maximale sur la taille COURANTE ; un setSize ultérieur ne réduisait plus la largeur (fenêtre transparente
  // restée en 1280 px de large après déconnexion / expiration au lieu de la carte LOGIN_WIDTH×LOGIN_HEIGHT).
  mainWindow.setSize(LOGIN_WIDTH, LOGIN_HEIGHT);
  mainWindow.setResizable(false);
  mainWindow.center();
});

// ========================================
// LANGUE DE L'INTERFACE - Textes du processus principal
// ========================================
// Le preload signale la langue courante de l'interface (attribut lang du document, mis à jour par
// I18nProvider) : boîtes de dialogue natives (appairage, approbations CLI, clé d'hôte SSH) et erreurs IPC
// affichées en toast suivent cette langue. Expéditeur validé, valeur en liste blanche (12 langues) ;
// une valeur inconnue est ignorée. Sans signal : LANG de config.cfg, puis anglais.
ipcMain.on('set-ui-language', (event, lang) => {
  if (!validateIpcSender(event)) return;
  mainI18n.setUiLanguage(lang);
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
// Taille maximale (octets, UTF-8) d'un fichier d'export / d'import : MÊME plafond à l'écriture
// (export-save-file) et à la lecture (import-open-file). Les exports embarquent les pièces jointes
// en base64 : tout export accepté doit pouvoir être réimporté tel quel.
const MAX_EXPORT_IMPORT_FILE_BYTES = 100 * 1024 * 1024;

ipcMain.handle('export-save-file', async (event, { defaultName, filters, content }) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  // Validation des entrées : plafond mesuré en OCTETS écrits (UTF-8), comme stats.size à l'import
  // (content.length compte des unités UTF-16 : un export non ASCII pouvait dépasser le plafond de lecture).
  // content.length ≤ octets UTF-8 : le premier test écarte un contenu démesuré sans le parcourir.
  if (typeof content !== 'string' || content.length > MAX_EXPORT_IMPORT_FILE_BYTES ||
      Buffer.byteLength(content, 'utf8') > MAX_EXPORT_IMPORT_FILE_BYTES) {
    return { success: false, error: 'Invalid or oversized content' };
  }
  if (typeof defaultName !== 'string' || defaultName.length > 256) {
    return { success: false, error: 'Invalid filename' };
  }
  try {
    const result = await dialog.showSaveDialog(mainWindow, {
      // eslint-disable-next-line no-control-regex -- volontaire : caractères de contrôle interdits dans un nom de fichier Windows
      defaultPath: path.basename(defaultName.replace(/[\x00-\x1F<>:"|?*]/g, '_')),
      filters: sanitizeDialogFilters(filters)
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    fs.writeFileSync(result.filePath, content, { encoding: 'utf8', mode: 0o600 });
    return { success: true, filePath: result.filePath };
  } catch {
    return { success: false, error: 'File save error' };
  }
});

ipcMain.handle('import-open-file', async (event, { filters }) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      filters: sanitizeDialogFilters(filters)
    });
    if (result.canceled || !result.filePaths.length) return { success: false, canceled: true };
    const stats = fs.statSync(result.filePaths[0]);
    if (stats.size > MAX_EXPORT_IMPORT_FILE_BYTES) { // même plafond que l'export : un export se réimporte toujours
      return { success: false, error: `File too large (max ${MAX_EXPORT_IMPORT_FILE_BYTES / (1024 * 1024)} MB)` };
    }
    const content = fs.readFileSync(result.filePaths[0], 'utf8');
    return { success: true, content, filePath: result.filePaths[0] };
  } catch {
    return { success: false, error: 'File read error' };
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

    const handler = (event, result) => {
      // SÉCURITÉ: la réponse doit provenir de la fenêtre principale
      if (!validateIpcSender(event)) return;
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

    const handler = (event, result) => {
      // SÉCURITÉ: la réponse doit provenir de la fenêtre principale
      if (!validateIpcSender(event)) return;
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

    const handler = (event, result) => {
      // SÉCURITÉ: la réponse doit provenir de la fenêtre principale
      if (!validateIpcSender(event)) return;
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
  if (!Array.isArray(engines) || engines.length > 500) return { success: false, error: 'Invalid' };
  const safe = engines.filter(e => typeof e === 'string' && e.length <= 256).slice(0, 500);
  cliServer.setListSecretsAllowedEngines(safe);
  return { success: true };
});

// IPC handler pour définir les règles d'auto-approbation CLI
ipcMain.handle('cli-set-auto-approve-rules', (event, rules) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  if (!Array.isArray(rules) || rules.length > 500) return { success: false, error: 'Invalid' };
  const safe = rules.filter(r => typeof r === 'string' && r.length <= 256).slice(0, 500);
  cliServer.setAutoApproveRules(safe);
  return { success: true };
});

// IPC handler pour révoquer/régénérer le token CLI (appelé au logout)
ipcMain.handle('cli-revoke-session', (event) => {
  if (!validateIpcSender(event)) return { success: false, error: 'Unauthorized' };
  cliServer.stopCLIServer();
  // Redémarrer avec un nouveau token
  cliServer.startCLIServer(mainWindow, cliReadSecret, cliListEngines, cliListSecrets).then(({ port }) => {
    log.info(`[CLI] Token CLI régénéré, nouveau port ${port}`);
  }).catch(() => {});
  return { success: true };
});

// ========================================
// NETTOYAGE ET HEARTBEAT
// ========================================

// Migration : les anciennes versions écrivaient l'état de sync (mots de passe inclus) et le
// token sur disque. Ces fichiers sont écrasés puis supprimés ; tout est en mémoire désormais.
// (Instance qui détient le verrou uniquement : une seconde instance ne touche pas au userData.)
for (const legacyFile of gotTheLock ? ['vault-sync.json', 'vault-sync.enc', 'sync-auth-token.txt'] : []) {
  try {
    const legacyPath = path.join(app.getPath('userData'), legacyFile);
    if (fs.existsSync(legacyPath)) {
      const size = fs.statSync(legacyPath).size;
      if (size > 0) fs.writeFileSync(legacyPath, Buffer.alloc(size, 0));
      fs.unlinkSync(legacyPath);
      log.info('[Migration] Ancien fichier ' + legacyFile + ' supprimé');
    }
  } catch {
    log.warn('[Migration] Impossible de supprimer ' + legacyFile);
  }
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
    if (!syncState || !syncState.connected) return;
    // SÉCURITÉ (SYNC-28) : l'état n'est prolongé que si l'interface qui l'a écrit est vivante ; sinon il est
    // purgé (renderer planté sans évènement reçu, fenêtre détruite)
    if (rendererAlive()) syncState.timestamp = Date.now();
    else purgeSyncState('interface indisponible');
  }, CONFIG.HEARTBEAT_INTERVAL_MS);
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

// Enregistrer le protocole rdvault:// pour les deep links (seconde instance : déjà fait par la première)
if (gotTheLock && process.defaultApp) {
  // En dev, enregistrer avec le chemin vers electron
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient('rdvault', process.execPath, [path.resolve(process.argv[1])]);
  }
} else if (gotTheLock) {
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
  const token = match[1].trim();
  // Valider le format du token (alphanumérique, tirets, points, max 128 chars)
  if (!/^[a-zA-Z0-9._-]{1,128}$/.test(token)) return null;
  return token;
}

/**
 * Envoie le token de partage au renderer process
 * @param {string} token - Token de wrapping Vault
 */
function sendShareTokenToRenderer(shareToken) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    log.info('[DEEP-LINK] Envoi du token de partage au renderer');
    mainWindow.webContents.send('rdvault-share-received', shareToken);
    mainWindow.show();
    mainWindow.focus();
  } else {
    log.info('[DEEP-LINK] Fenêtre non prête, mise en attente du token');
    pendingDeepLink = shareToken;
  }
}

// Instance unique (verrou demandé en tête de fichier, gotTheLock) : la seconde instance transmet son deep
// link à la première, qui seule écoute 'second-instance'
if (gotTheLock) {
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
  // Seconde instance (STARTUP-23) : sa fermeture est déjà demandée, rien n'est démarré (ni coffre local, ni
  // fenêtre, ni serveurs de synchronisation et CLI) : les ressources appartiennent à la première instance.
  if (!gotTheLock) return;

  // En mode local : démarrer le serveur Vault local AVANT la fenêtre
  // pour que React ait le port quand il demande la config
  if (getAppMode() === 'local') {
    try {
      const localVault = require('./localVault/localVaultServer');
      const port = await localVault.start(0);
      log.info(`[LocalVault] Mode local actif sur le port ${port}`);
    } catch (err) {
      log.error('[LocalVault] Erreur démarrage:', err.message);
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
      log.info(`[CLI] Serveur CLI prêt sur le port ${port}`);
    }).catch(err => {
      log.error('[CLI] Impossible de démarrer le serveur CLI:', err.message);
    });
  });

  // ========================================
  // SÉCURITÉ: Détecter verrouillage/déverrouillage du système
  // ========================================
  // Permet d'adapter le timeout de session selon l'état de verrouillage:
  // - Session active: 15 minutes d'inactivité avant déconnexion
  // - Session verrouillée: 3 heures avant déconnexion
  powerMonitor.on('lock-screen', () => {
    log.info('🔒 [SÉCURITÉ] Système verrouillé');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('system-lock-screen');
    }
  });

  powerMonitor.on('unlock-screen', () => {
    log.info('🔓 [SÉCURITÉ] Système déverrouillé');
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('system-unlock-screen');
    }
  });
});
app.on('browser-window-focus', () => { try { globalShortcut.unregisterAll(); } catch {} });

// Délai maximal accordé à la fermeture des sessions RBI à la sortie (fermeture de Chromium puis suppression
// du profil, réessais bornés) : au-delà, l'application se termine quand même ; un profil resté verrouillé
// est supprimé au démarrage suivant (cleanupStaleProfiles).
const RBI_QUIT_TIMEOUT_MS = 20000;

app.on('will-quit', (event) => {
  // Seconde instance (STARTUP-23) : 'will-quit' est émis avant 'ready' ; rien ne lui appartient (le serveur
  // CLI, sa session userData/cli/session.json, le coffre local et les sessions RBI sont ceux de la PREMIÈRE
  // instance) : aucun nettoyage, aucune attente.
  if (!gotTheLock) return;
  try {
    globalShortcut.unregisterAll();
    if (syncServer) syncServer.close();
    cliServer.stopCLIServer();
    // Arrêter le serveur local si en mode local
    if (getAppMode() === 'local') {
      try { require('./localVault/localVaultServer').stop(); } catch { /* ignore */ }
    }
    stopHeartbeat();
    syncState = null;
    syncAuthToken = null;
    // Presse-papiers : effacer un mot de passe encore présent
    try { if (activeClipboardTimers.has('current')) activeClipboardTimers.get('current').clearNow(); } catch {}
  } catch {}
  // Sessions RBI : Electron n'attend pas un gestionnaire asynchrone. La sortie est donc suspendue
  // (preventDefault) jusqu'à la fermeture des navigateurs isolés et la suppression de leurs profils
  // (cookies de session), bornée par RBI_QUIT_TIMEOUT_MS, puis l'application se termine (app.exit, qui
  // n'émet plus 'will-quit' mais émet toujours 'quit').
  try { event.preventDefault(); } catch { /* ignore */ }
  let timer = null;
  const bounded = new Promise((resolve) => { timer = setTimeout(resolve, RBI_QUIT_TIMEOUT_MS); });
  Promise.race([Promise.resolve().then(() => secureSession.closeAllSessions()).catch(() => {}), bounded])
    .then(() => {
      clearTimeout(timer);
      try { app.exit(0); } catch { /* ignore */ }
    });
});
app.on('activate', () => { if (gotTheLock && BrowserWindow.getAllWindows().length === 0) createWindow(); });
