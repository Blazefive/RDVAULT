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
// - Token de session généré à chaque démarrage, écrit dans un fichier chmod 600
// - Popup de confirmation optionnelle avant de retourner un secret
// - Règles d'auto-approbation par chemin (ex: users/blaze/* auto-approuvé, prod/* demande confirmation)
// - Audit log de tous les accès

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { app, dialog, BrowserWindow, safeStorage } = require('electron');

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
};

// Fichier de session CLI (port + token) — lu par la CLI mvault
const CLI_SESSION_DIR = path.join(app.getPath('userData'), 'cli');
const CLI_SESSION_FILE = path.join(CLI_SESSION_DIR, 'session.json');
const CLI_AUDIT_FILE = path.join(CLI_SESSION_DIR, 'audit.log');

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
    // Hash le chemin du secret pour ne pas exposer les noms en clair
    const hashedPath = crypto.createHash('sha256').update(secretPath).digest('hex').slice(0, 16);
    const entry = `${new Date().toISOString()} | ${action} | hash:${hashedPath} | ${approved ? 'APPROVED' : 'DENIED'} | ${details}\n`;
    fs.appendFileSync(CLI_AUDIT_FILE, entry);
  } catch (err) {
    console.error('[CLI] Erreur audit log:', err.message);
  }
}

/**
 * Vérifie si un chemin de secret est auto-approuvé
 */
function isAutoApproved(secretPath) {
  return autoApproveRules.some(rule => {
    // Support du wildcard simple : "users/blaze/*" matche "users/blaze/foo/bar"
    if (rule.endsWith('/*')) {
      const prefix = rule.slice(0, -1); // enlève le *
      return secretPath.startsWith(prefix);
    }
    // Correspondance exacte
    return secretPath === rule;
  });
}

/**
 * Affiche une popup de confirmation dans Electron
 * Retourne true si approuvé, false si refusé ou timeout
 */
async function showConfirmPopup(secretPath) {
  const win = mainWindowRef || BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0];
  if (!win) return false;

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve(false);
    }, CLI_CONFIG.CONFIRM_TIMEOUT_MS);

    dialog.showMessageBox(win, {
      type: 'question',
      buttons: ['Autoriser', 'Refuser'],
      defaultId: 1,
      cancelId: 1,
      title: 'Accès secret — CLI mvault',
      message: `Un processus CLI demande l'accès à un secret Vault.`,
      detail: `Chemin : ${secretPath}\n\nAutoriser l'accès ?`,
      noLink: true,
    }).then(({ response }) => {
      clearTimeout(timeout);
      resolve(response === 0); // 0 = Autoriser
    }).catch(() => {
      clearTimeout(timeout);
      resolve(false);
    });
  });
}

/**
 * Parse le body JSON d'une requête POST
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      // Limite à 10KB pour éviter les abus
      if (body.length > 10240) {
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
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

      // Rate limiting
      const clientIp = req.socket.remoteAddress;
      const now = Date.now();
      const entry = rateLimit.get(clientIp);
      if (entry && now - entry.start < CLI_CONFIG.RATE_WINDOW_MS) {
        entry.count++;
        if (entry.count > CLI_CONFIG.RATE_LIMIT) {
          res.writeHead(429);
          res.end(JSON.stringify({ error: 'Trop de requêtes' }));
          return;
        }
      } else {
        rateLimit.set(clientIp, { start: now, count: 1 });
      }

      // Nettoyage périodique du rate limit
      if (rateLimit.size > 50) {
        for (const [ip, e] of rateLimit) {
          if (now - e.start > CLI_CONFIG.RATE_WINDOW_MS) rateLimit.delete(ip);
        }
      }

      // ─── GET /health ───
      // Endpoint non authentifié pour vérifier que le serveur tourne
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'ok', version: app.getVersion() }));
        return;
      }

      // ─── Authentification requise pour tous les autres endpoints ───
      if (!verifyCLIToken(req)) {
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

          // Validation des entrées
          if (!engine || typeof engine !== 'string' || engine.length > 256) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "engine" invalide' }));
            return;
          }
          if (!secretPath || typeof secretPath !== 'string' || secretPath.length > 1024) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "path" invalide' }));
            return;
          }
          // Prévention path traversal
          if (secretPath.includes('..') || /[\x00-\x1F]/.test(secretPath)) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Chemin interdit' }));
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
              approved = await showConfirmPopup(`${fullPath} [burst: ${burstCounter} accès en ${Math.round((now - burstWindowStart) / 1000)}s]`);
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
          if (key && result.data) {
            const value = result.data[key];
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
          console.error('[CLI] Erreur /secret:', err.message);
          res.writeHead(500);
          res.end(JSON.stringify({ error: 'Erreur interne' }));
        }
        return;
      }

      // ─── POST /list ───
      // Liste les secrets d'un engine (nécessite l'activation dans les paramètres)
      if (req.method === 'POST' && req.url === '/list') {
        try {
          const body = await parseBody(req);
          const { engine, path: folderPath } = body;

          // Vérifier que le listing est autorisé pour cet engine
          const engineClean = engine ? engine.replace(/\/+$/, '') : '';
          const isListAllowed = listSecretsAllowedEngines.some(allowed =>
            engineClean === allowed || engineClean === allowed.replace(/\/+$/, '')
          );
          if (!isListAllowed) {
            res.writeHead(403);
            res.end(JSON.stringify({ error: `Listing interdit pour "${engine}". Activez-le dans Paramètres > CLI.` }));
            auditLog('LIST', engine, false, 'list-not-allowed');
            return;
          }

          if (!engine || typeof engine !== 'string' || engine.length > 256) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "engine" invalide' }));
            return;
          }
          if (folderPath && (typeof folderPath !== 'string' || folderPath.length > 1024 || folderPath.includes('..') || /[\x00-\x1F]/.test(folderPath))) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: 'Paramètre "path" invalide' }));
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
          console.error('[CLI] Erreur /list:', err.message);
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
      console.log(`[CLI] Serveur CLI démarré sur http://127.0.0.1:${cliPort}`);

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
        console.log(`[CLI] Session écrite dans ${CLI_SESSION_FILE}`);
      } catch (err) {
        console.error('[CLI] Erreur écriture session:', err.message);
      }

      // Envoyer les infos de session au renderer pour que les paramètres puissent communiquer avec le serveur CLI
      if (mainWindowRef && !mainWindowRef.isDestroyed()) {
        mainWindowRef.webContents.send('cli-server-ready', { port: cliPort, token: cliAuthToken });
      }

      resolve({ port: cliPort, token: cliAuthToken });
    });

    cliServer.on('error', (err) => {
      console.error('[CLI] Erreur serveur:', err.message);
      reject(err);
    });
  });
}

/**
 * Arrête le serveur CLI et nettoie les fichiers de session
 */
function stopCLIServer() {
  if (cliServer) {
    cliServer.close();
    cliServer = null;
    console.log('[CLI] Serveur CLI arrêté');
  }
  cliAuthToken = null;
  cliPort = null;

  // Supprimer le fichier de session
  try {
    if (fs.existsSync(CLI_SESSION_FILE)) {
      fs.unlinkSync(CLI_SESSION_FILE);
    }
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
    console.log(`[CLI] Listing autorisé pour: ${engines.length > 0 ? engines.join(', ') : '(aucun)'}`);
  }
}

module.exports = {
  startCLIServer,
  stopCLIServer,
  setVaultReadFunction,
  setAutoApproveRules,
  setListSecretsAllowedEngines,
  CLI_SESSION_FILE,
};
