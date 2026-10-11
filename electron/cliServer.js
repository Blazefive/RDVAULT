// ========================================
// SERVEUR CLI LOCAL - Accès secrets Vault depuis la ligne de commande
// ========================================
// Serveur HTTP qui écoute sur localhost (port dynamique)
// Permet à la CLI `mvault` de récupérer des secrets via l'app Electron déverrouillée.
//
// Architecture :
//   Electron (session Vault active) ← HTTP local ← CLI mvault ← Claude Code / scripts
//
// Sécurité :
// - Écoute UNIQUEMENT sur 127.0.0.1
// - Token de session généré à chaque démarrage, écrit dans session.json (protégé par les ACL du profil utilisateur)
// - Popup de confirmation optionnelle avant de retourner un secret
// - Règles d'auto-approbation par chemin (ex: users/blaze/* auto-approuvé, prod/* demande confirmation)
// - Clé d'hôte SSH (broker mot de passe) : épinglage ou mémoire known_hosts.json (TOFU), popup
//   à la première connexion, refus si la clé change — jamais auto-approuvé par les règles de chemin
// - Audit log de tous les accès (commandes SSH/WinRM : exécutable + HMAC tronqué, clé propre à l'installation)
// - Client HTTP parti avant la réponse : la connexion SSH en cours est abandonnée (AbortSignal → broker)
// - Shell SSH interactif : la raison de sa fin (fin normale, clé d'hôte changée en cours de session, garde-fou
//   de durée…) reste consultable quelques minutes (POST /ssh/status), uniquement avec le jeton qui l'a ouvert

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { app, dialog, BrowserWindow } = require('electron');
const log = require('./logger');
const { createAgent } = require('./sshAgent');  // Agent SSH (clés) : « utiliser une clé sans la voir »
const { execWithPassword, createShellSession, normalizeFp } = require('./sshBroker');  // Broker SSH (mot de passe)
const { createKnownHosts } = require('./knownHosts');  // Mémoire persistante des clés d'hôte SSH (partagée avec l'audit SSH)
const { execWinRM } = require('./winrmBroker');  // Broker WinRM (Windows) : exécute sans exposer l'identifiant
const { tm } = require('./mainI18n');  // Popups natives dans la langue de l'interface (signalée par le renderer à main.js)

// ========================================
// CONFIGURATION
// ========================================
const CLI_CONFIG = {
  // Port 0 = le système attribue un port libre automatiquement
  PORT: 0,
  // Rate limiting : 30 requêtes/minute (la CLI fait peu d'appels)
  RATE_LIMIT: 30,
  RATE_WINDOW_MS: 60000,
  // Timeout pour la popup de confirmation (30 secondes)
  CONFIRM_TIMEOUT_MS: 30000,
  // Token d'authentification : 256 bits
  TOKEN_BYTES: 32,
  // Burst detection : si plus de N secrets accédés en auto-approve dans la fenêtre,
  // forcer la popup de confirmation (protection contre l'extraction en masse)
  BURST_THRESHOLD: 15,
  BURST_WINDOW_MS: 60000,
  // Durée de vie d'un agent SSH éphémère (la clé est retirée après ce délai)
  SSH_AGENT_TTL_MS: 120000,
  // Délai d'exécution par défaut d'une commande SSH (broker) et plafond accepté du client
  SSH_EXEC_TIMEOUT_MS: 600000,
  SSH_EXEC_TIMEOUT_MAX_MS: 3600000,
  // Taille maximale (octets) du corps d'une requête : couvre le plus gros corps valide
  // (commande de 8192 caractères en UTF-8 ≤ 32 Ko + autres champs)
  BODY_LIMIT_BYTES: 65536,
  // Garde-fou : durée maximale d'une session shell SSH (mot de passe), lue à l'ouverture de chaque session
  SSH_SHELL_MAX_MS: 4 * 60 * 60 * 1000,
  // Raison de fin d'une session shell conservée (POST /ssh/status) : durée et nombre maximal d'entrées
  SSH_SHELL_STATUS_TTL_MS: 5 * 60 * 1000,
  SSH_SHELL_STATUS_MAX: 256,
};

// Agents SSH éphémères actifs : authSock -> { agent, timer }
const activeSshAgents = new Map();
// Sessions shell SSH (mot de passe) actives : sock -> { close, resize, timer, owner, label }
const activeShellSessions = new Map();
// Sessions shell terminées, raison conservée SSH_SHELL_STATUS_TTL_MS : sock -> { owner, end, timer }
const closedShellSessions = new Map();

// Raisons de fin d'une session shell renvoyées par POST /ssh/status. `code` null = fin normale (shell quitté,
// fermeture propre côté serveur distant, client déconnecté) ; sinon coupure côté RDVAULT que mvault signale
// par un message et un code de sortie ≠ 0.
const SHELL_END = {
  CLOSED: { closedReason: 'closed', code: null },
  MAX_DURATION: { closedReason: 'max-duration', code: 'SESSION_MAX_DURATION' },
  CLOSED_BY_REQUEST: { closedReason: 'closed-by-request', code: 'CLOSED_BY_REQUEST' },
  SERVER_STOPPED: { closedReason: 'server-stopped', code: 'SERVER_STOPPED' },
};

/**
 * Code d'erreur normalisé en CHAÎNE (POST /ssh/status, réponses d'erreur de /ssh, audit). ssh2 transmet la
 * raison d'un SSH_MSG_DISCONNECT distant sous forme de NOMBRE (ex. 2 = PROTOCOL_ERROR, 11 = BY_APPLICATION),
 * les erreurs réseau / du broker sous forme de chaîne ('ECONNRESET', 'SSH_CONNECTION_LOST'…).
 * Absent ou vide → `fallback`. Longueur bornée (valeur pouvant venir du pair distant).
 */
function errorCodeString(code, fallback = null) {
  if (code === undefined || code === null || code === '') return fallback;
  return String(code).slice(0, 64);
}

/** Raison de fin d'après l'erreur transmise par le broker (onClose) : null → fin normale */
function shellEndFromError(err) {
  if (!err) return SHELL_END.CLOSED;
  if (err.code === 'HOST_KEY_CHANGED_REKEY') {
    return { closedReason: 'host-key-changed-rekey', code: err.code, message: String(err.message || ''), expected: err.expected || null, observed: err.observed || null };
  }
  return { closedReason: 'error', code: errorCodeString(err.code, 'SESSION_ERROR'), message: String(err.message || '') };
}

// Fichier de session CLI (port + token) — lu par la CLI mvault
const CLI_SESSION_DIR = path.join(app.getPath('userData'), 'cli');
const CLI_SESSION_FILE = path.join(CLI_SESSION_DIR, 'session.json');
const CLI_AUDIT_FILE = path.join(CLI_SESSION_DIR, 'audit.log');
// Clé HMAC des empreintes de commande de l'audit (32 octets aléatoires par installation, jamais journalisée)
const CLI_AUDIT_KEY_FILE = path.join(CLI_SESSION_DIR, 'audit-key');
const AUDIT_KEY_BYTES = 32;

// Mémoire des clés d'hôte SSH (TOFU persistant), même fichier que l'audit SSH de main.js.
// Le fichier n'est créé qu'à la première mémorisation.
const KNOWN_HOSTS_FILE = path.join(app.getPath('userData'), 'known_hosts.json');
let knownHostsRef = null;
function getKnownHosts() {
  if (!knownHostsRef) knownHostsRef = createKnownHosts(KNOWN_HOSTS_FILE);
  return knownHostsRef;
}

// État du serveur
let cliServer = null;
let cliAuthToken = null;
let cliPort = null;

// Clé HMAC pour comparaison timing-safe (non persistée)
const cliHmacKey = crypto.randomBytes(32);

// Règles d'auto-approbation par chemin (configurables)
// Format : tableau de patterns glob-like. Si le chemin matche, pas de popup.
let autoApproveRules = [];

// Burst detection : compteur d'accès auto-approuvés
let burstCounter = 0;
let burstWindowStart = Date.now();

// Référence vers la fenêtre principale (injectée au démarrage)
let mainWindowRef = null;

// Référence vers la fonction de lecture des secrets Vault (injectée depuis main.js)
let vaultReadFn = null;

// Référence vers la fonction de listage des engines (injectée depuis main.js)
let listEnginesFn = null;

// Référence vers la fonction de listage des secrets d'un engine (injectée depuis main.js)
let listSecretsFn = null;

// Liste des engines autorisés pour le listage (contrôlé depuis les paramètres)
let listSecretsAllowedEngines = [];

// ========================================
// FONCTIONS UTILITAIRES
// ========================================

/**
 * Vérifie le token CLI dans une requête HTTP (comparaison timing-safe)
 */
function verifyCLIToken(req) {
  if (!cliAuthToken) return false;
  const authHeader = req.headers['authorization'];
  if (!authHeader) return false;
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return false;

  const provided = match[1];
  try {
    const hmacA = crypto.createHmac('sha256', cliHmacKey).update(provided).digest();
    const hmacB = crypto.createHmac('sha256', cliHmacKey).update(cliAuthToken).digest();
    return crypto.timingSafeEqual(hmacA, hmacB);
  } catch {
    return false;
  }
}

/**
 * Empreinte (HMAC, clé du processus) du jeton présenté par la requête : rattache une session shell au jeton
 * qui l'a ouverte, sans conserver le jeton lui-même. null si l'en-tête est absent ou mal formé.
 */
function tokenTag(req) {
  const match = String(req.headers['authorization'] || '').match(/^Bearer (.+)$/);
  return match ? crypto.createHmac('sha256', cliHmacKey).update(match[1]).digest() : null;
}

/** Même jeton (comparaison timing-safe de deux empreintes tokenTag) */
function sameOwner(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * Neutralise les caractères de contrôle (C0 dont \r \n, DEL, C1) d'un champ d'audit : une valeur
 * venue du client ou du réseau (ex. description d'un SSH_MSG_DISCONNECT, envoyée en clair) ne
 * doit ni forger de ligne, ni injecter de séquence d'échappement ANSI rejouée à l'affichage.
 */
function auditSafe(value, maxLen) {
  // eslint-disable-next-line no-control-regex -- volontaire : neutraliser les caractères de contrôle (injection de journal)
  return String(value).replace(/[\x00-\x1F\x7F-\x9F]/g, '?').slice(0, maxLen);
}

/**
 * Écrit une entrée dans le log d'audit CLI
 */
function auditLog(action, secretPath, approved, details = '') {
  try {
    // Rotation : tronquer si > 5 MB
    try {
      const stats = fs.statSync(CLI_AUDIT_FILE);
      if (stats.size > 5 * 1024 * 1024) {
        const content = fs.readFileSync(CLI_AUDIT_FILE, 'utf8');
        const lines = content.split('\n');
        fs.writeFileSync(CLI_AUDIT_FILE, lines.slice(-500).join('\n') + '\n');
      }
    } catch { /* fichier n'existe pas encore */ }
    // Le chemin est journalisé en clair : le fichier est dans le profil de l'utilisateur (même
    // protection que session.json) et un hash tronqué non salé n'apportait aucune confidentialité
    // réelle tout en rendant le journal inexploitable.
    const safePath = auditSafe(secretPath, 512);
    const entry = `${new Date().toISOString()} | ${action} | ${safePath} | ${approved ? 'APPROVED' : 'DENIED'} | ${auditSafe(details, 512)}\n`;
    fs.appendFileSync(CLI_AUDIT_FILE, entry, { mode: 0o600 });
  } catch (err) {
    log.error('[CLI] Erreur audit log:', err.message);
  }
}

/**
 * Clé HMAC de l'audit, propre à l'installation : 32 octets aléatoires dans cli/audit-key, créés
 * paresseusement (écriture atomique : fichier temporaire puis renommage ; 0600 en meilleur effort,
 * sans effet sous Windows où le profil utilisateur protège le dossier). Relue à chaque usage (pas
 * de cache). Renvoie null si elle ne peut être ni lue ni créée (fichier illisible, taille
 * inattendue, disque en lecture seule…) : un fichier existant mais invalide n'est jamais écrasé.
 * La clé n'est JAMAIS journalisée.
 */
function getAuditKey() {
  try {
    const key = fs.readFileSync(CLI_AUDIT_KEY_FILE);
    if (key.length === AUDIT_KEY_BYTES) return key;
    log.error(`[CLI] Clé d'audit invalide (${key.length} octets au lieu de ${AUDIT_KEY_BYTES}) : empreintes de commande non calculées`);
    return null;
  } catch (err) {
    if (!err || err.code !== 'ENOENT') {
      log.error('[CLI] Clé d\'audit illisible : empreintes de commande non calculées :', (err && err.code) || err);
      return null;
    }
  }
  const key = crypto.randomBytes(AUDIT_KEY_BYTES);
  const tmp = `${CLI_AUDIT_KEY_FILE}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.mkdirSync(CLI_SESSION_DIR, { recursive: true });
    fs.writeFileSync(tmp, key, { mode: 0o600, flag: 'wx' });
    try { fs.chmodSync(tmp, 0o600); } catch { /* meilleur effort */ }
    fs.renameSync(tmp, CLI_AUDIT_KEY_FILE);
    try { fs.chmodSync(CLI_AUDIT_KEY_FILE, 0o600); } catch { /* meilleur effort */ }
    return key;
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* déjà absent */ }
    log.error('[CLI] Création de la clé d\'audit impossible : empreintes de commande non calculées :', (err && err.code) || err);
    return null;
  }
}

/**
 * Référence d'une commande distante pour l'audit : exécutable (premier token, 40 car. max)
 * + HMAC-SHA256 tronqué (12 hex) avec la clé de l'installation, sans jamais journaliser les
 * arguments (qui peuvent contenir des secrets). L'empreinte permet de corréler deux commandes
 * identiques sur la même installation, mais pas de retrouver une commande hors-ligne par
 * dictionnaire (contrairement à un SHA-256 non salé). Clé indisponible → « #? » (jamais de hash
 * non salé). Un premier token « VAR=valeur » (PGPASSWORD=… psql) est une affectation : la valeur est masquée.
 */
function auditCmdRef(command) {
  let exe = String(command).trim().split(/\s+/)[0];
  const eq = exe.indexOf('=');
  if (eq >= 0) exe = exe.slice(0, eq + 1) + '***';
  // eslint-disable-next-line no-control-regex -- volontaire : neutraliser les caractères de contrôle (injection de journal)
  exe = exe.replace(/[\x00-\x1F\x7F-\x9F|]/g, '?').slice(0, 40); // « | » : séparateur des colonnes du journal
  const key = getAuditKey();
  const ref = key ? crypto.createHmac('sha256', key).update(String(command)).digest('hex').slice(0, 12) : '?';
  return 'cmd:' + exe + '#' + ref;
}

/**
 * Vérifie si un chemin de secret correspond à une règle d'auto-approbation.
 * Correspondance par segments : "users/blaze/*" couvre "users/blaze/x" et "users/blaze/a/b",
 * mais pas "users/blazefoo/x" (contrairement à un simple préfixe de chaîne).
 */
function matchesRule(secretPath, rule) {
  const pathSegments = String(secretPath).split('/').filter(Boolean);
  const ruleSegments = String(rule).split('/').filter(Boolean);
  if (ruleSegments.length === 0) return false;
  const wildcard = ruleSegments[ruleSegments.length - 1] === '*';
  const fixed = wildcard ? ruleSegments.slice(0, -1) : ruleSegments;
  if (wildcard ? pathSegments.length <= fixed.length : pathSegments.length !== fixed.length) return false;
  return fixed.every((seg, i) => seg === pathSegments[i]);
}

function isAutoApproved(secretPath) {
  return autoApproveRules.some(rule => matchesRule(secretPath, rule));
}

/**
 * Décide d'autoriser un accès (auto-approbation + détection de rafale + popup) et journalise.
 * Même logique que l'endpoint /secret ; renvoie true si approuvé.
 */
async function requestApproval(action, fullPath) {
  if (isAutoApproved(fullPath)) {
    const now = Date.now();
    if (now - burstWindowStart > CLI_CONFIG.BURST_WINDOW_MS) { burstCounter = 0; burstWindowStart = now; }
    burstCounter++;
    if (burstCounter > CLI_CONFIG.BURST_THRESHOLD) {
      const approved = await showConfirmPopup(fullPath, { count: burstCounter, seconds: Math.round((now - burstWindowStart) / 1000) });
      auditLog(action, fullPath, approved, approved ? 'burst-user-approved' : 'burst-user-denied');
      return approved;
    }
    auditLog(action, fullPath, true, 'auto-approved');
    if (mainWindowRef && !mainWindowRef.isDestroyed()) mainWindowRef.webContents.send('cli-auto-access', fullPath);
    return true;
  }
  const approved = await showConfirmPopup(fullPath);
  auditLog(action, fullPath, approved, approved ? 'user-approved' : 'user-denied');
  return approved;
}

/** Ferme un agent SSH éphémère (retire la clé de la mémoire) */
function closeSshAgent(authSock) {
  const entry = activeSshAgents.get(authSock);
  if (!entry) return;
  try { clearTimeout(entry.timer); } catch { /* ignore */ }
  try { entry.agent.close(); } catch { /* ignore */ }
  activeSshAgents.delete(authSock);
}

/**
 * Ferme une session shell SSH (mot de passe) et sa connexion, en conservant la raison `end` (SHELL_END)
 * pour POST /ssh/status. La session est retirée AVANT close() : le rappel onClose du broker, qui rappelle
 * cette fonction, est alors sans effet et la PREMIÈRE raison est conservée (ex. garde-fou plutôt que fin normale).
 */
function closeShellSession(sock, end = SHELL_END.CLOSED) {
  const entry = activeShellSessions.get(sock);
  if (!entry) return;
  activeShellSessions.delete(sock);
  try { clearTimeout(entry.timer); } catch { /* ignore */ }
  rememberShellEnd(sock, entry, end);
  try { entry.close(); } catch { /* ignore */ }
}

/** Conserve la raison de fin d'une session shell (TTL, nombre d'entrées borné) et la journalise */
function rememberShellEnd(sock, entry, end) {
  // Fin sur erreur : le code (chaîne normalisée, ex. « ECONNRESET », « 2 ») complète la raison dans l'audit
  const detail = end.closedReason === 'error' && end.code ? ':' + end.code : '';
  if (entry.label) auditLog('SSH-SHELL', entry.label, true, 'shell-ferme:' + end.closedReason + detail);
  const previous = closedShellSessions.get(sock);
  if (previous) { clearTimeout(previous.timer); closedShellSessions.delete(sock); }
  while (closedShellSessions.size >= CLI_CONFIG.SSH_SHELL_STATUS_MAX) { // la plus ancienne d'abord (ordre d'insertion)
    const [oldestSock, oldest] = closedShellSessions.entries().next().value;
    clearTimeout(oldest.timer);
    closedShellSessions.delete(oldestSock);
  }
  const timer = setTimeout(() => closedShellSessions.delete(sock), CLI_CONFIG.SSH_SHELL_STATUS_TTL_MS);
  if (timer.unref) timer.unref();
  closedShellSessions.set(sock, { owner: entry.owner, end, timer });
}

/** Extrait une clé privée SSH (PEM/OpenSSH) des données d'un secret */
function extractSshPrivateKey(data, keyField) {
  const PEM_RE = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;
  if (keyField) return (typeof data[keyField] === 'string' && PEM_RE.test(data[keyField])) ? data[keyField] : null;
  for (const v of Object.values(data || {})) {
    if (typeof v === 'string' && PEM_RE.test(v)) return v;
  }
  return null;
}

/** Extrait { username, password } d'un secret (noms de champs usuels, insensible à la casse) */
function extractSshPassword(data) {
  const d = data || {};
  const pick = (names) => { for (const k of Object.keys(d)) { if (names.includes(k.toLowerCase()) && typeof d[k] === 'string' && d[k]) return d[k]; } return null; };
  const password = pick(['password', 'pass', 'pwd', 'motdepasse', 'mdp']);
  if (!password) return null;
  return { password, username: pick(['username', 'user', 'login', 'identifiant']) };
}

/** Validation simple d'un hôte (nom DNS ou IPv4/IPv6) */
function isValidHost(h) {
  // eslint-disable-next-line no-control-regex -- volontaire : un hôte contenant un caractère de contrôle est refusé
  return typeof h === 'string' && h.length > 0 && h.length <= 253 && !/[\x00-\x1F\x7F]/.test(h) && /^[a-zA-Z0-9.\-:_%[\]]+$/.test(h);
}

// File d'attente des confirmations : une seule boîte de dialogue à la fois
let confirmQueue = Promise.resolve();

/**
 * Affiche une popup de confirmation dans Electron (sérialisée, fermée automatiquement au timeout),
 * dans la langue de l'interface (mainI18n). Boutons : 0 = Autoriser, 1 = Refuser (par défaut).
 * @param {string} secretPath - chemin complet du secret
 * @param {{ count: number, seconds: number }} [burst] - rafale d'accès auto-approuvés (confirmation forcée)
 * Retourne true si approuvé, false si refusé ou timeout
 */
function showConfirmPopup(secretPath, burst = null) {
  const run = async () => {
    const win = mainWindowRef || BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0];
    if (!win || win.isDestroyed()) return false;
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), CLI_CONFIG.CONFIRM_TIMEOUT_MS);
    // Textes traduits au moment de l'affichage (langue courante, même si la popup a attendu dans la file)
    const pathLabel = burst ? tm('cliAccess.burst', { path: secretPath, count: burst.count, seconds: burst.seconds }) : secretPath;
    try {
      win.show();
      const { response } = await dialog.showMessageBox(win, {
        type: 'question',
        buttons: [tm('button.allow'), tm('button.deny')],
        defaultId: 1,
        cancelId: 1,
        title: tm('cliAccess.title'),
        message: tm('cliAccess.message'),
        detail: tm('cliAccess.detail', { path: pathLabel }),
        noLink: true,
        signal: abort.signal,
      });
      return response === 0; // 0 = Autoriser
    } catch {
      return false;
    } finally {
      clearTimeout(timeout);
    }
  };
  const result = confirmQueue.then(run, run);
  confirmQueue = result.catch(() => false);
  return result;
}

/**
 * Popup « clé d'hôte SSH inconnue » (première connexion, TOFU) — sérialisée sur la même file
 * que showConfirmPopup. JAMAIS auto-approuvée par les règles de chemin : seule une décision
 * humaine mémorise une clé. Retourne true si l'utilisateur mémorise la clé ; false sinon
 * (refus, timeout, pas de fenêtre).
 */
function showHostKeyPopup({ host, port, fingerprint }) {
  const run = async () => {
    const win = mainWindowRef || BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0];
    if (!win || win.isDestroyed()) return false;
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), CLI_CONFIG.CONFIRM_TIMEOUT_MS);
    try {
      win.show();
      // Langue de l'interface ; boutons : 0 = Mémoriser et continuer, 1 = Refuser (par défaut)
      const { response } = await dialog.showMessageBox(win, {
        type: 'question',
        buttons: [tm('button.rememberContinue'), tm('button.deny')],
        defaultId: 1,
        cancelId: 1,
        title: tm('cliHostKey.title'),
        message: tm('cliHostKey.message'),
        detail: tm('cliHostKey.detail', { host, port, fingerprint }),
        noLink: true,
        signal: abort.signal,
      });
      return response === 0; // 0 = Mémoriser et continuer
    } catch {
      return false;
    } finally {
      clearTimeout(timeout);
    }
  };
  const result = confirmQueue.then(run, run);
  confirmQueue = result.catch(() => false);
  return result;
}

/**
 * Politique de clé d'hôte transmise au broker SSH : épinglage éventuel (hostFingerprint),
 * mémoire known_hosts.json, et popup (journalisée) pour toute clé inconnue.
 * Un épinglage accepté est journalisé au moment où le broker l'enregistre (avant l'authentification) :
 * « pinned-new » s'il mémorise une clé encore inconnue, « pinned » sinon. Il ne remplace jamais une
 * AUTRE clé mémorisée (refus HOST_KEY_CHANGED par le broker, journalisé « changed »).
 * @param {string|null} pinnedFp
 * @param {Function} [isClientGone] - () => boolean : client HTTP parti (popup acceptée trop tard → refus)
 */
function hostKeyPolicy(pinnedFp, isClientGone = () => false) {
  const store = getKnownHosts();
  let knownHosts = store;
  if (pinnedFp) {
    knownHosts = Object.create(store); // check/lookup/… hérités ; seule la mémorisation est observée
    knownHosts.remember = (h, p, fp) => {
      const already = store.lookup(h, p) !== null;
      store.remember(h, p, fp);
      auditLog('SSH-HOSTKEY', `${h}:${p}`, true, (already ? 'pinned:' : 'pinned-new:') + normalizeFp(fp));
    };
  }
  return {
    hostFingerprint: pinnedFp,
    knownHosts,
    onNewHostKey: async (info) => {
      const ok = await showHostKeyPopup(info);
      if (ok && isClientGone()) {
        // Personne n'attend plus la réponse (délai HTTP de mvault dépassé) : ni mémorisation, ni connexion
        auditLog('SSH-HOSTKEY', `${info.host}:${info.port}`, false, 'client-parti');
        return false;
      }
      auditLog('SSH-HOSTKEY', `${info.host}:${info.port}`, ok, ok ? 'new:' + info.fingerprint : 'rejected');
      return ok;
    },
  };
}

// Statut HTTP des autres codes d'erreur explicites du broker SSH
const SSH_ERROR_STATUS = new Map([
  ['KNOWN_HOSTS_READ', 500], ['KNOWN_HOSTS_WRITE', 500], ['CONNECT_TIMEOUT', 504], ['EXEC_TIMEOUT', 504],
]);

/**
 * Répond à une erreur du broker SSH avec un code explicite ({ success:false, error:<code>, code, message }) :
 * 502 HOST_KEY_CHANGED / HOST_KEY_MISMATCH / HOST_KEY_CHANGED_REKEY (clé changée EN COURS de session,
 * known_hosts non modifié) avec expected/observed, 403 HOST_KEY_REJECTED (refus, clé inconnue), 500
 * KNOWN_HOSTS_READ / KNOWN_HOSTS_WRITE (mémoire des clés d'hôte illisible ou impossible à écrire),
 * 504 CONNECT_TIMEOUT / EXEC_TIMEOUT ; sinon 502 générique (code éventuel joint).
 */
function sendSshError(res, e, host, port, prefix) {
  const code = e && e.code;
  if (code === 'HOST_KEY_CHANGED' || code === 'HOST_KEY_MISMATCH' || code === 'HOST_KEY_CHANGED_REKEY') {
    auditLog('SSH-HOSTKEY', `${host}:${port}`, false, code === 'HOST_KEY_CHANGED_REKEY' ? 'changed-rekey' : 'changed');
    res.writeHead(502);
    res.end(JSON.stringify({ success: false, error: code, message: e.message, expected: e.expected || null, observed: e.observed || null }));
    return;
  }
  if (code === 'HOST_KEY_REJECTED' || code === 'HOST_KEY_UNKNOWN') {
    if (code === 'HOST_KEY_UNKNOWN') auditLog('SSH-HOSTKEY', `${host}:${port}`, false, 'rejected'); // (REJECTED déjà journalisé par la popup)
    res.writeHead(403);
    res.end(JSON.stringify({ success: false, error: 'HOST_KEY_REJECTED', message: e.message, observed: e.observed || null }));
    return;
  }
  const status = SSH_ERROR_STATUS.get(code);
  if (status) {
    res.writeHead(status);
    res.end(JSON.stringify({ success: false, error: code, code, message: e.message || code }));
    return;
  }
  res.writeHead(502);
  const codeStr = errorCodeString(code); // raison de déconnexion ssh2 numérique → chaîne, comme /ssh/status
  res.end(JSON.stringify({ error: prefix + (e.message || 'inconnue'), ...(codeStr ? { code: codeStr } : {}) }));
}

/**
 * Parse le body JSON d'une requête POST (limite BODY_LIMIT_BYTES, connexion coupée au-delà).
 * Les morceaux sont accumulés en Buffers et décodés UNE fois : un caractère UTF-8 coupé
 * entre deux morceaux n'est jamais corrompu (U+FFFD).
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    let tooLarge = false;
    req.on('data', chunk => {
      if (tooLarge) return;
      received += chunk.length;
      if (received > CLI_CONFIG.BODY_LIMIT_BYTES) {
        tooLarge = true;
        req.destroy();
        reject(new Error('Body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/** Validation commune d'un nom d'engine ou d'un chemin de secret (pas de traversée, pas de contrôle) */
function isValidVaultPath(value, maxLen) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLen
    // eslint-disable-next-line no-control-regex -- volontaire : un chemin contenant un caractère de contrôle est refusé
    && !value.includes('..') && !/[\x00-\x1F\x7F]/.test(value);
}

// ========================================
// SERVEUR HTTP
// ========================================

/**
 * Démarre le serveur CLI local
 *
 * @param {BrowserWindow} mainWindow - Référence vers la fenêtre principale Electron
 * @param {Function} readSecretFn - Fonction async(engine, path) => { success, data, error }
 * @param {string[]} [autoApprove=[]] - Règles d'auto-approbation par chemin
 * @returns {Promise<{port: number, token: string}>} Port et token de session
 */
function startCLIServer(mainWindow, readSecretFn, listEnginesCallback = null, listSecretsCallback = null, autoApprove = []) {
  mainWindowRef = mainWindow;
  vaultReadFn = readSecretFn;
  listEnginesFn = listEnginesCallback;
  listSecretsFn = listSecretsCallback;
  autoApproveRules = autoApprove;

  return new Promise((resolve, reject) => {
    // Générer le token d'authentification
    cliAuthToken = crypto.randomBytes(CLI_CONFIG.TOKEN_BYTES).toString('hex');

    // Rate limiting
    const rateLimit = new Map();

    cliServer = http.createServer(async (req, res) => {
      // Headers de réponse communs
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');

      // Rate limiting par IP (toutes les instances de mvault partagent 127.0.0.1), avec DEUX compteurs :
      // - requêtes AUTHENTIFIÉES (jeton de session.json valide) ;
      // - requêtes NON authentifiées (GET /health, jeton absent ou faux) : elles restent limitées (pas de
      //   devinette de jeton en rafale) mais ne peuvent plus épuiser le quota des commandes authentifiées — un
      //   processus local sans jeton bloquait sinon /secret, /ssh, /winrm, /list et /engines par des 429.
      // Exemptés : /ssh/resize, /ssh/close et /ssh/status AUTHENTIFIÉS (idempotents, sans secret) — une rafale de
      // redimensionnements ne doit ni bloquer les autres appels CLI, ni empêcher la destruction d'un agent ou
      // d'une session shell, ni masquer à mvault la raison de la fin de son shell.
      const clientIp = req.socket.remoteAddress;
      const now = Date.now();
      const authenticated = verifyCLIToken(req);
      const rateKey = clientIp + (authenticated ? '|auth' : '|anon');
      const entry = rateLimit.get(rateKey);
      const exempt = authenticated && req.method === 'POST' && (req.url === '/ssh/resize' || req.url === '/ssh/close' || req.url === '/ssh/status');
      if (exempt) {
        // non compté
      } else if (entry && now - entry.start < CLI_CONFIG.RATE_WINDOW_MS) {
        entry.count++;
        if (entry.count > CLI_CONFIG.RATE_LIMIT) {
          res.writeHead(429);
          res.end(JSON.stringify({ error: 'Trop de requêtes' }));
          return;
        }
      } else {
        rateLimit.set(rateKey, { start: now, count: 1 });
      }

      // Nettoyage périodique du rate limit
      if (rateLimit.size > 50) {
        for (const [key, e] of rateLimit) {
          if (now - e.start > CLI_CONFIG.RATE_WINDOW_MS) rateLimit.delete(key);
        }
      }

      // ─── GET /health ───
      // Endpoint non authentifié pour vérifier que le serveur tourne (compté avec les requêtes non authentifiées)
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'ok', version: app.getVersion() }));
        return;
      }

      // ─── Authentification requise pour tous les autres endpoints ───
      if (!authenticated) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: 'Token CLI invalide ou manquant' }));
        return;
      }

      // ─── POST /secret ───
      // Récupère un secret depuis Vault via la session Electron active
      if (req.method === 'POST' && req.url === '/secret') {
        try {
          const body = await parseBody(req);
          const { engine, path: secretPath, key } = body;

          // Validation des entrées (engine ET path : pas de traversée ni de caractères de contrôle)
          if (!isValidVaultPath(engine, 256)) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "engine" invalide' }));
            return;
          }
          if (!isValidVaultPath(secretPath, 1024)) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "path" invalide' }));
            return;
          }
          if (key !== undefined && (typeof key !== 'string' || key.length > 256)) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "key" invalide' }));
            return;
          }

          const fullPath = `${engine}/${secretPath}`;

          // Vérifier auto-approbation ou demander confirmation
          let approved = false;
          if (isAutoApproved(fullPath)) {
            // Burst detection : si trop d'accès auto-approuvés en peu de temps, forcer la popup
            const now = Date.now();
            if (now - burstWindowStart > CLI_CONFIG.BURST_WINDOW_MS) {
              burstCounter = 0;
              burstWindowStart = now;
            }
            burstCounter++;
            if (burstCounter > CLI_CONFIG.BURST_THRESHOLD) {
              // Seuil dépassé : forcer la confirmation humaine
              approved = await showConfirmPopup(fullPath, { count: burstCounter, seconds: Math.round((now - burstWindowStart) / 1000) });
              auditLog('GET', fullPath, approved, approved ? 'burst-user-approved' : 'burst-user-denied');
            } else {
              approved = true;
              auditLog('GET', fullPath, true, 'auto-approved');
              // Notifier le renderer (toast discret) pour chaque accès auto-approuvé
              if (mainWindowRef && !mainWindowRef.isDestroyed()) {
                mainWindowRef.webContents.send('cli-auto-access', fullPath);
              }
            }
          } else {
            approved = await showConfirmPopup(fullPath);
            auditLog('GET', fullPath, approved, approved ? 'user-approved' : 'user-denied');
          }

          if (!approved) {
            res.writeHead(403);
            res.end(JSON.stringify({ error: 'Accès refusé par l\'utilisateur' }));
            return;
          }

          // Lire le secret via la fonction injectée
          if (!vaultReadFn) {
            res.writeHead(503);
            res.end(JSON.stringify({ error: 'Session Vault non active' }));
            return;
          }

          const result = await vaultReadFn(engine, secretPath);
          if (!result || !result.success) {
            res.writeHead(404);
            res.end(JSON.stringify({ error: result?.error || 'Secret introuvable' }));
            return;
          }

          // Si une clé spécifique est demandée, ne retourner que cette valeur
          // (propriété PROPRE uniquement : constructor / toString / __proto__ → 404)
          if (key && result.data) {
            const own = typeof result.data === 'object' && Object.hasOwn(result.data, key) && typeof result.data[key] !== 'function';
            const value = own ? result.data[key] : undefined;
            if (value === undefined) {
              res.writeHead(404);
              res.end(JSON.stringify({ error: `Clé "${key}" introuvable dans le secret` }));
              return;
            }
            res.writeHead(200);
            res.end(JSON.stringify({ success: true, value }));
          } else {
            // Retourner toutes les données du secret
            res.writeHead(200);
            res.end(JSON.stringify({ success: true, data: result.data }));
          }
        } catch (err) {
          log.error('[CLI] Erreur /secret:', err.message);
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'Erreur interne' }));
        }
        return;
      }

      // ─── POST /ssh ───
      // Deux modes, décidés CÔTÉ SERVEUR selon le secret (l'appelant ne lit jamais le secret) :
      //  - clé privée → agent ssh-agent éphémère ; renvoie SSH_AUTH_SOCK (jamais la clé).
      //  - mot de passe (+ commande) → broker : RDVAULT exécute la commande via ssh2 avec le
      //    mot de passe du coffre et ne renvoie que la SORTIE (jamais le mot de passe).
      if (req.method === 'POST' && req.url === '/ssh') {
        // Client HTTP parti AVANT la réponse (délai de mvault dépassé, Ctrl+C) : signal d'abandon transmis au
        // broker, qui détruit la connexion SSH en cours — la commande ou le shell n'est jamais lancé si la
        // connexion n'était pas prête. res 'close' sans réponse envoyée = connexion coupée ; req 'close' est
        // aussi émis dès la fin de la lecture du corps, d'où la vérification de la destruction effective.
        const clientAbort = new AbortController();
        const onClientClose = () => {
          if (!res.writableEnded && (res.destroyed || (req.socket && req.socket.destroyed))) clientAbort.abort();
        };
        req.on('close', onClientClose);
        res.on('close', onClientClose);
        const clientGone = () => clientAbort.signal.aborted || res.destroyed || (req.socket && req.socket.destroyed);
        try {
          const body = await parseBody(req);
          const { engine, path: secretPath, keyField, host, user, port, command, hostFingerprint, execTimeoutMs } = body;

          if (!isValidVaultPath(engine, 256)) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "engine" invalide' })); return;
          }
          if (!isValidVaultPath(secretPath, 1024)) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "path" invalide' })); return;
          }
          if (keyField !== undefined && (typeof keyField !== 'string' || keyField.length > 128)) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "keyField" invalide' })); return;
          }
          if (host !== undefined && !isValidHost(host)) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "host" invalide' })); return;
          }
          if (user !== undefined && (typeof user !== 'string' || !/^[a-zA-Z0-9._@-]{1,256}$/.test(user))) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "user" invalide' })); return;
          }
          const portNum = port === undefined || port === null || port === '' ? 22 : parseInt(port, 10);
          if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "port" invalide' })); return;
          }
          // eslint-disable-next-line no-control-regex -- volontaire : commande contenant un octet nul refusée
          if (command !== undefined && (typeof command !== 'string' || command.length > 8192 || /[\x00]/.test(command))) {
            res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "command" invalide' })); return;
          }
          // Empreinte épinglée (optionnelle) : « SHA256:<base64 sans padding> », normalisée
          let pinnedFp = null;
          if (hostFingerprint !== undefined && hostFingerprint !== null && hostFingerprint !== '') {
            if (typeof hostFingerprint !== 'string' || hostFingerprint.length > 128 || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(normalizeFp(hostFingerprint))) {
              res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "hostFingerprint" invalide (attendu SHA256:…)' })); return;
            }
            pinnedFp = normalizeFp(hostFingerprint);
          }
          // Délai d'exécution de la commande (ms, 0 = illimité), distinct du délai de connexion
          let execTimeout = CLI_CONFIG.SSH_EXEC_TIMEOUT_MS;
          if (execTimeoutMs !== undefined && execTimeoutMs !== null && execTimeoutMs !== '') {
            const n = (typeof execTimeoutMs === 'number' || typeof execTimeoutMs === 'string') ? Number(execTimeoutMs) : NaN;
            if (!Number.isInteger(n) || n < 0 || n > CLI_CONFIG.SSH_EXEC_TIMEOUT_MAX_MS) {
              res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "execTimeoutMs" invalide (entier 0..3600000)' })); return;
            }
            execTimeout = n;
          }

          const fullPath = `${engine}/${secretPath}`;
          const approved = await requestApproval('SSH', fullPath);
          if (!approved) {
            res.writeHead(403); res.end(JSON.stringify({ error: 'Accès refusé par l\'utilisateur' })); return;
          }

          if (!vaultReadFn) {
            res.writeHead(503); res.end(JSON.stringify({ error: 'Session Vault non active' })); return;
          }
          const result = await vaultReadFn(engine, secretPath);
          if (!result || !result.success || !result.data) {
            res.writeHead(404); res.end(JSON.stringify({ error: result?.error || 'Secret introuvable' })); return;
          }

          // Client parti pendant la popup (délai HTTP de mvault dépassé, Ctrl+C) : rien n'est ouvert pour
          // personne — ni agent, ni connexion (le mot de passe n'est pas envoyé), ni shell orphelin. Un départ
          // PENDANT la connexion est couvert par clientAbort (broker → ABORTED).
          if (clientGone()) { auditLog('SSH', fullPath, false, 'client-parti'); return; }

          // ── Mode CLÉ : agent ssh-agent (la clé ne sort jamais) ──
          const pem = extractSshPrivateKey(result.data, keyField);
          if (pem) {
            const agent = createAgent();
            try { agent.addKey(pem, fullPath); }
            catch (e) { res.writeHead(400); res.end(JSON.stringify({ error: 'Clé SSH illisible' })); return; }

            const id = crypto.randomBytes(8).toString('hex');
            const authSock = process.platform === 'win32'
              ? `\\\\.\\pipe\\rdvault-ssh-${id}`
              : path.join(os.tmpdir(), `rdvault-ssh-${id}.sock`);
            await agent.listen(authSock);
            const ttlMs = CLI_CONFIG.SSH_AGENT_TTL_MS;
            const timer = setTimeout(() => closeSshAgent(authSock), ttlMs);
            if (timer.unref) timer.unref();
            activeSshAgents.set(authSock, { agent, timer });
            auditLog('SSH', fullPath, true, 'agent-started');

            res.writeHead(200);
            res.end(JSON.stringify({ success: true, mode: 'agent', authSock, ttlMs }));
            return;
          }

          // ── Mode MOT DE PASSE : broker (RDVAULT exécute, ne renvoie que la sortie) ──
          const creds = extractSshPassword(result.data);
          if (creds) {
            const effectiveUser = user || creds.username;
            if (!host || !effectiveUser) {
              res.writeHead(400); res.end(JSON.stringify({ error: 'Mode mot de passe : "host" et un utilisateur (user ou champ du secret) sont requis' })); return;
            }
            if (!command) {
              // Pas de commande → SHELL INTERACTIF proxifié sur une socket locale.
              try {
                let sess = null; // connu après résolution ; onClose n'est appelé que pour une session établie
                sess = await createShellSession({
                  host, port: portNum, username: effectiveUser, password: creds.password,
                  ...hostKeyPolicy(pinnedFp, clientGone),
                  signal: clientAbort.signal, // client parti pendant l'ouverture → ABORTED, shell jamais ouvert
                  onClose: (err) => { // fin distante/erreur → retrait + garde-fou annulé, raison conservée (/ssh/status)
                    if (err && err.code === 'HOST_KEY_CHANGED_REKEY') auditLog('SSH-HOSTKEY', `${host}:${portNum}`, false, 'changed-rekey');
                    if (sess) closeShellSession(sess.sock, shellEndFromError(err));
                  },
                });
                if (clientGone()) { // personne ne branchera la socket : pas de session orpheline jusqu'au garde-fou
                  sess.close(); // (onClose → closeShellSession : sans effet, la session n'est pas inscrite)
                  auditLog('SSH-SHELL', `${fullPath}@${effectiveUser}@${host}`, false, 'client-parti');
                  return;
                }
                const maxDurationMs = CLI_CONFIG.SSH_SHELL_MAX_MS; // garde-fou (4 h)
                const safety = setTimeout(() => closeShellSession(sess.sock, { ...SHELL_END.MAX_DURATION, maxDurationMs }), maxDurationMs);
                if (safety.unref) safety.unref();
                activeShellSessions.set(sess.sock, {
                  close: sess.close, resize: sess.resize, timer: safety,
                  owner: tokenTag(req), label: `${fullPath}@${effectiveUser}@${host}`,
                });
                auditLog('SSH-SHELL', `${fullPath}@${effectiveUser}@${host}`, true, 'shell-ouvert');
                res.writeHead(200);
                res.end(JSON.stringify({ success: true, mode: 'shell', sock: sess.sock, hostFingerprint: sess.hostFingerprint, hostKeyStatus: sess.hostKeyStatus }));
              } catch (e) {
                if (e && e.code === 'ABORTED') { // client parti : personne à qui répondre
                  auditLog('SSH-SHELL', `${fullPath}@${effectiveUser}@${host}`, false, 'client-parti');
                  return;
                }
                auditLog('SSH-SHELL', `${fullPath}@${effectiveUser}@${host}`, false, 'echec:' + (e.message || '').slice(0, 80));
                sendSshError(res, e, host, portNum, 'Ouverture du shell SSH échouée: ');
              }
              return;
            }
            try {
              const out = await execWithPassword({
                host, port: portNum, username: effectiveUser, password: creds.password, command,
                ...hostKeyPolicy(pinnedFp, clientGone),
                execTimeoutMs: execTimeout,
                signal: clientAbort.signal, // client parti pendant la connexion ou l'exécution → ABORTED, connexion détruite
              });
              auditLog('SSH-EXEC', `${fullPath}@${effectiveUser}@${host}`, true, auditCmdRef(command));
              res.writeHead(200);
              res.end(JSON.stringify({ success: true, mode: 'exec', code: out.code, signal: out.signal, stdout: out.stdout, stderr: out.stderr, hostFingerprint: out.hostFingerprint, hostKeyStatus: out.hostKeyStatus }));
            } catch (e) {
              if (e && e.code === 'ABORTED') { // client parti : commande jamais lancée (avant 'ready') ou interrompue
                auditLog('SSH-EXEC', `${fullPath}@${effectiveUser}@${host}`, false, 'client-parti');
                return;
              }
              auditLog('SSH-EXEC', `${fullPath}@${effectiveUser}@${host}`, false, 'echec:' + (e.message || '').slice(0, 80));
              sendSshError(res, e, host, portNum, 'Connexion/commande SSH échouée: ');
            }
            return;
          }

          res.writeHead(404); res.end(JSON.stringify({ error: 'Aucune clé privée ni mot de passe utilisable dans ce secret' }));
        } catch (err) {
          log.error('[CLI] Erreur /ssh:', err.message);
          res.writeHead(500); res.end(JSON.stringify({ error: 'Erreur interne' }));
        }
        return;
      }

      // ─── POST /ssh/resize ───
      // Transmet un redimensionnement de terminal à une session shell (SIGWINCH → window-change)
      if (req.method === 'POST' && req.url === '/ssh/resize') {
        try {
          const body = await parseBody(req);
          const entry = typeof body.authSock === 'string' ? activeShellSessions.get(body.authSock) : null;
          if (entry && entry.resize) entry.resize(body.rows, body.cols);
          res.writeHead(200); res.end(JSON.stringify({ success: true }));
        } catch {
          res.writeHead(200); res.end(JSON.stringify({ success: true }));
        }
        return;
      }

      // ─── POST /ssh/close ───
      // Détruit un agent SSH éphémère (retire la clé de la mémoire) ou ferme une session shell encore ouverte
      if (req.method === 'POST' && req.url === '/ssh/close') {
        try {
          const body = await parseBody(req);
          if (typeof body.authSock === 'string') { closeSshAgent(body.authSock); closeShellSession(body.authSock, SHELL_END.CLOSED_BY_REQUEST); }
          res.writeHead(200); res.end(JSON.stringify({ success: true }));
        } catch {
          res.writeHead(200); res.end(JSON.stringify({ success: true }));
        }
        return;
      }

      // ─── POST /ssh/status ───
      // État d'une session shell (mot de passe) : { open, closedReason, code } (+ message / expected / observed
      // pour une clé d'hôte changée en cours de session, maxDurationMs pour le garde-fou). Interrogé par mvault à
      // la fermeture de sa socket pour expliquer une coupure côté RDVAULT. La raison reste consultable
      // SSH_SHELL_STATUS_TTL_MS. Session inconnue, expirée, sock invalide ou session ouverte avec un AUTRE jeton :
      // même 404 (rien n'indique si la session existe).
      if (req.method === 'POST' && req.url === '/ssh/status') {
        let body = null;
        try { body = await parseBody(req); } catch { /* corps invalide : session inconnue */ }
        const sock = body && typeof body.sock === 'string' && body.sock.length <= 512 ? body.sock : null;
        const owner = tokenTag(req);
        const active = sock ? activeShellSessions.get(sock) : null;
        if (active && sameOwner(active.owner, owner)) {
          res.writeHead(200); res.end(JSON.stringify({ success: true, open: true, closedReason: null, code: null })); return;
        }
        const closed = sock ? closedShellSessions.get(sock) : null;
        if (closed && sameOwner(closed.owner, owner)) {
          res.writeHead(200); res.end(JSON.stringify({ success: true, open: false, ...closed.end })); return;
        }
        res.writeHead(404); res.end(JSON.stringify({ error: 'Session inconnue' }));
        return;
      }

      // ─── POST /winrm ───
      // Exécute une commande sur un hôte Windows via WinRM avec l'identifiant du coffre.
      // RDVAULT exécute et ne renvoie que la SORTIE — l'identifiant n'est jamais renvoyé.
      if (req.method === 'POST' && req.url === '/winrm') {
        try {
          const body = await parseBody(req);
          const { engine, path: secretPath, host, user, command, port, useSSL, authMethod } = body;

          if (!isValidVaultPath(engine, 256)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "engine" invalide' })); return; }
          if (!isValidVaultPath(secretPath, 1024)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "path" invalide' })); return; }
          if (!isValidHost(host)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "host" invalide' })); return; }
          if (user !== undefined && (typeof user !== 'string' || !/^[a-zA-Z0-9._@\\-]{1,256}$/.test(user))) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "user" invalide' })); return; }
          // eslint-disable-next-line no-control-regex -- volontaire : commande contenant un octet nul refusée
          if (typeof command !== 'string' || !command || command.length > 8192 || /[\x00]/.test(command)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "command" requis/invalide' })); return; }
          const portNum = port === undefined || port === null || port === '' ? undefined : parseInt(port, 10);
          if (portNum !== undefined && (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "port" invalide' })); return; }
          const AUTH = ['Default', 'Basic', 'Negotiate', 'Kerberos', 'CredSSP'];
          if (authMethod !== undefined && !AUTH.includes(authMethod)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Paramètre "authMethod" invalide' })); return; }

          const fullPath = `${engine}/${secretPath}`;
          const approved = await requestApproval('WINRM', fullPath);
          if (!approved) { res.writeHead(403); res.end(JSON.stringify({ error: 'Accès refusé par l\'utilisateur' })); return; }

          if (!vaultReadFn) { res.writeHead(503); res.end(JSON.stringify({ error: 'Session Vault non active' })); return; }
          const result = await vaultReadFn(engine, secretPath);
          if (!result || !result.success || !result.data) { res.writeHead(404); res.end(JSON.stringify({ error: result?.error || 'Secret introuvable' })); return; }

          const creds = extractSshPassword(result.data);
          const effectiveUser = user || creds?.username;
          if (!creds || !effectiveUser) { res.writeHead(404); res.end(JSON.stringify({ error: 'Identifiant Windows (utilisateur + mot de passe) introuvable' })); return; }

          try {
            const out = await execWinRM({ host, username: effectiveUser, password: creds.password, command, port: portNum, useSSL: useSSL === true, authMethod });
            auditLog('WINRM', `${fullPath}@${effectiveUser}@${host}`, true, auditCmdRef(command));
            res.writeHead(200);
            res.end(JSON.stringify({ success: true, mode: 'exec', code: out.code, stdout: out.stdout, stderr: out.stderr }));
          } catch (e) {
            auditLog('WINRM', `${fullPath}@${effectiveUser}@${host}`, false, 'echec:' + (e.message || '').slice(0, 80));
            res.writeHead(502); res.end(JSON.stringify({ error: 'WinRM échoué: ' + (e.message || 'inconnue') }));
          }
        } catch (err) {
          log.error('[CLI] Erreur /winrm:', err.message);
          res.writeHead(500); res.end(JSON.stringify({ error: 'Erreur interne' }));
        }
        return;
      }

      // ─── POST /list ───
      // Liste les secrets d'un engine (nécessite l'activation dans les paramètres)
      if (req.method === 'POST' && req.url === '/list') {
        try {
          const body = await parseBody(req);
          const { engine, path: folderPath } = body;

          // Validation AVANT toute utilisation
          if (!isValidVaultPath(engine, 256)) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "engine" invalide' }));
            return;
          }
          if (folderPath !== undefined && folderPath !== '' && !isValidVaultPath(folderPath, 1024)) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "path" invalide' }));
            return;
          }

          // Vérifier que le listing est autorisé pour cet engine
          const engineClean = engine.replace(/\/+$/, '');
          const isListAllowed = listSecretsAllowedEngines.some(allowed =>
            engineClean === allowed || engineClean === allowed.replace(/\/+$/, '')
          );
          if (!isListAllowed) {
            res.writeHead(403);
            res.end(JSON.stringify({ error: 'Listing interdit pour cet engine. Activez-le dans Paramètres > CLI.' }));
            auditLog('LIST', engine, false, 'list-not-allowed');
            return;
          }

          if (!listSecretsFn) {
            res.writeHead(503);
            res.end(JSON.stringify({ error: 'Session Vault non active' }));
            return;
          }

          const fullPath = folderPath ? `${engine}/${folderPath}` : engine;
          auditLog('LIST', fullPath, true, 'list-secrets');

          const result = await listSecretsFn(engine, folderPath || '');
          res.writeHead(200);
          res.end(JSON.stringify({ success: true, keys: result }));
        } catch (err) {
          log.error('[CLI] Erreur /list:', err.message);
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'Erreur listing secrets' }));
        }
        return;
      }

      // ─── GET /engines ───
      // Liste les engines Vault disponibles
      if (req.method === 'GET' && req.url === '/engines') {
        try {
          if (!listEnginesFn) {
            res.writeHead(503);
            res.end(JSON.stringify({ error: 'Session Vault non active' }));
            return;
          }
          const result = await listEnginesFn();
          // Whitelist des champs retournés
          const safeEngines = (Array.isArray(result) ? result : []).map(e => ({
            name: String(e.name || ''),
            version: Number(e.version) || 2,
            type: String(e.type || 'kv')
          }));
          res.writeHead(200);
          res.end(JSON.stringify({ success: true, engines: safeEngines }));
        } catch (err) {
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'Erreur listing engines' }));
        }
        return;
      }

      // ─── GET /rules ───
      // Retourne les règles d'auto-approbation actuelles
      if (req.method === 'GET' && req.url === '/rules') {
        res.writeHead(200);
        res.end(JSON.stringify({ rules: autoApproveRules }));
        return;
      }

      // PUT /rules supprimé pour sécurité — les règles ne sont modifiables que via IPC Electron

      // ─── 404 ───
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Endpoint introuvable' }));
    });

    // Écouter sur un port dynamique, 127.0.0.1 uniquement
    cliServer.listen(0, '127.0.0.1', () => {
      cliPort = cliServer.address().port;
      log.info(`[CLI] Serveur CLI démarré sur http://127.0.0.1:${cliPort}`);

      // Écrire le fichier de session pour la CLI
      try {
        if (!fs.existsSync(CLI_SESSION_DIR)) {
          fs.mkdirSync(CLI_SESSION_DIR, { recursive: true });
        }
        const session = {
          port: cliPort,
          token: cliAuthToken,
          pid: process.pid,
          started: new Date().toISOString(),
        };
        fs.writeFileSync(CLI_SESSION_FILE, JSON.stringify(session, null, 2), { mode: 0o600 });
        log.info(`[CLI] Session écrite dans ${CLI_SESSION_FILE}`);
      } catch (err) {
        log.error('[CLI] Erreur écriture session:', err.message);
      }

      // Envoyer les infos de session au renderer pour que les paramètres puissent communiquer avec le serveur CLI
      if (mainWindowRef && !mainWindowRef.isDestroyed()) {
        mainWindowRef.webContents.send('cli-server-ready', { port: cliPort, token: cliAuthToken });
      }

      resolve({ port: cliPort, token: cliAuthToken });
    });

    cliServer.on('error', (err) => {
      log.error('[CLI] Erreur serveur:', err.message);
      reject(err);
    });
  });
}

/**
 * Arrête le serveur CLI et nettoie les fichiers de session
 */
function stopCLIServer() {
  // Détruire tous les agents SSH éphémères (retire les clés de la mémoire) + sessions shell
  for (const authSock of Array.from(activeSshAgents.keys())) closeSshAgent(authSock);
  for (const sock of Array.from(activeShellSessions.keys())) closeShellSession(sock, SHELL_END.SERVER_STOPPED);
  // Raisons de fin oubliées : le nouveau serveur aura un autre jeton (et un autre port)
  for (const closed of closedShellSessions.values()) clearTimeout(closed.timer);
  closedShellSessions.clear();

  if (cliServer) {
    cliServer.close();
    cliServer = null;
    log.info('[CLI] Serveur CLI arrêté');
  }
  cliAuthToken = null;
  cliPort = null;

  // Supprimer le fichier de session, SEULEMENT s'il a été écrit par ce processus (pid identique). Défense en
  // profondeur (STARTUP-23) : une autre instance qui a réécrit session.json (instance active, ou seconde
  // instance qui se termine sans avoir démarré de serveur) ne prive pas mvault de la session en cours.
  // Fichier illisible ou d'un autre pid : conservé (il sera réécrit au prochain démarrage du serveur).
  try {
    let ownerPid = null;
    try { ownerPid = JSON.parse(fs.readFileSync(CLI_SESSION_FILE, 'utf8'))?.pid ?? null; } catch { /* absent ou illisible */ }
    if (ownerPid === process.pid) fs.unlinkSync(CLI_SESSION_FILE);
  } catch { /* ignore */ }
}

/**
 * Met à jour la référence vers la fonction de lecture Vault
 * (appelé quand l'utilisateur se connecte/déconnecte)
 */
function setVaultReadFunction(fn) {
  vaultReadFn = fn;
}

/**
 * Met à jour les règles d'auto-approbation
 */
function setAutoApproveRules(rules) {
  if (Array.isArray(rules)) {
    autoApproveRules = rules;
  }
}

/**
 * Définit la liste des engines autorisés pour le listing
 * @param {string[]} engines - Noms des engines autorisés
 */
function setListSecretsAllowedEngines(engines) {
  if (Array.isArray(engines)) {
    listSecretsAllowedEngines = engines;
    log.info(`[CLI] Listing autorisé pour: ${engines.length > 0 ? engines.join(', ') : '(aucun)'}`);
  }
}

module.exports = {
  startCLIServer,
  stopCLIServer,
  setVaultReadFunction,
  setAutoApproveRules,
  setListSecretsAllowedEngines,
  matchesRule,
  isValidVaultPath,
  CLI_SESSION_FILE,
  CLI_CONFIG, // exposé pour les tests (durées réduites) ; jamais modifié par l'application
};
