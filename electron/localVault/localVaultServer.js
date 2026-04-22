// ========================================
// LOCAL VAULT SERVER — Serveur HTTP imitant l'API HashiCorp Vault
// ========================================
// Ce serveur répond aux mêmes endpoints que Vault (KV v2).
// React (App.jsx) s'y connecte sans aucune modification via vaultUrl.

'use strict';

const http = require('http');
const database = require('./database');
const authService = require('./authService');
const secretsService = require('./secretsService');
const totpService = require('./totpService');

let server = null;
let serverPort = null;

// Clés de chiffrement dérivées en mémoire (token -> { encKey: Buffer, salt: string })
// Le mot de passe brut n'est JAMAIS stocké — seule la clé AES-256 dérivée est conservée
const sessionKeys = new Map();

// ========================================
// HELPERS
// ========================================

// Rate limiting pour le login (5 tentatives / 5 min)
const loginAttempts = new Map();
function checkLoginRateLimit(username) {
  const key = username.toLowerCase();
  const now = Date.now();
  // Nettoyage périodique des entrées expirées
  if (loginAttempts.size > 50) {
    for (const [k, e] of loginAttempts) {
      if (now - e.first > 300000) loginAttempts.delete(k);
    }
  }
  const entry = loginAttempts.get(key);
  if (entry && now - entry.first < 300000) {
    if (entry.count >= 5) return false;
    entry.count++;
    return true;
  }
  loginAttempts.set(key, { first: now, count: 1 });
  return true;
}
function resetLoginRateLimit(username) {
  loginAttempts.delete(username.toLowerCase());
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => {
      body += c;
      if (body.length > 1048576) reject(new Error('Body too large'));
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function getToken(req) {
  return req.headers['x-vault-token'] || null;
}

function authenticate(req) {
  const token = getToken(req);
  if (!token) return null;
  return authService.validateToken(token);
}

/** Récupère la clé de chiffrement dérivée depuis la session */
function getSessionKey(token) {
  return sessionKeys.get(token) || null;
}

/** Extrait le chemin de l'URL, décode les segments */
function parsePath(url) {
  const [pathPart] = url.split('?');
  // Ne PAS décoder ici — les segments sont décodés individuellement après split
  return pathPart;
}

/** Parse les query params */
function parseQuery(url) {
  const idx = url.indexOf('?');
  if (idx === -1) return {};
  const params = {};
  new URLSearchParams(url.substring(idx)).forEach((v, k) => { params[k] = v; });
  return params;
}

// ========================================
// ROUTE HANDLERS
// ========================================

async function handleAuth(req, res, pathParts) {
  // POST /v1/auth/ldap/login/:user
  if (req.method === 'POST' && pathParts[2] === 'ldap' && pathParts[3] === 'login' && pathParts[4]) {
    const username = pathParts[4];

    // Rate limiting : 5 tentatives / 5 min
    if (!checkLoginRateLimit(username)) {
      sendJson(res, 429, { errors: ['Too many login attempts. Try again in 5 minutes.'] });
      return;
    }

    const body = await parseBody(req);
    const password = body.password;

    // Premier démarrage : si aucun utilisateur, en créer un automatiquement
    if (database.isEmpty()) {
      const createResult = authService.createUser(username, password, true);
      if (!createResult.success) {
        sendJson(res, 400, { errors: [createResult.error] });
        return;
      }
      // Créer un engine personnel par défaut
      secretsService.createEngine(`users/${username}/Mes-Secrets`, username, 'Coffre personnel');
      console.log(`[LocalVault] Premier utilisateur créé: ${username} (admin)`);
    }

    const result = authService.login(username, password);
    if (!result.success) {
      sendJson(res, 400, { errors: [result.error] });
      return;
    }

    // Dériver la clé AES-256 et la stocker (le mot de passe brut n'est PAS conservé)
    const { deriveKey } = require('./crypto');
    const salt = authService.getEncryptionSalt(username);
    const encKey = deriveKey(password, salt);
    sessionKeys.set(result.token, { encKey, salt });
    resetLoginRateLimit(username);

    sendJson(res, 200, {
      auth: {
        client_token: result.token,
        accessor: '',
        policies: ['default'],
        token_policies: ['default'],
        metadata: { username },
        lease_duration: 2764800,
        renewable: true
      }
    });
    return;
  }

  // GET /v1/auth/token/lookup-self
  if (req.method === 'GET' && pathParts[2] === 'token' && pathParts[3] === 'lookup-self') {
    const session = authenticate(req);
    if (!session) { sendJson(res, 403, { errors: ['permission denied'] }); return; }

    sendJson(res, 200, {
      data: {
        accessor: '',
        creation_time: Math.floor(session.createdAt / 1000),
        display_name: `ldap-${session.username}`,
        entity_name: session.username,
        policies: ['default'],
        ttl: 2764800
      }
    });
    return;
  }

  // POST /v1/auth/token/revoke-self
  if (req.method === 'POST' && pathParts[2] === 'token' && pathParts[3] === 'revoke-self') {
    const token = getToken(req);
    if (token) {
      authService.revokeToken(token);
      sessionKeys.delete(token);
    }
    sendJson(res, 204, {});
    return;
  }

  sendJson(res, 404, { errors: ['endpoint not found'] });
}

async function handleSys(req, res, pathParts, query) {
  const session = authenticate(req);
  if (!session) { sendJson(res, 403, { errors: ['permission denied'] }); return; }

  const subPath = pathParts.slice(2).join('/');

  // GET /v1/sys/internal/ui/mounts ou /v1/sys/mounts
  if (req.method === 'GET' && (subPath.startsWith('internal/ui/mounts') || subPath === 'mounts')) {
    const engines = secretsService.listEngines();
    const mounts = {};
    for (const e of engines) {
      const key = e.name.endsWith('/') ? e.name : e.name + '/';
      mounts[key] = {
        type: 'kv',
        description: e.description || '',
        options: { version: String(e.version) },
        accessor: `kv_${e.name}`
      };
    }
    // Format identique à sys/mounts pour compatibilité avec parseFromSysMounts
    sendJson(res, 200, mounts);
    return;
  }

  // POST /v1/sys/mounts/:path — créer un engine
  if (req.method === 'POST' && subPath.startsWith('mounts/')) {
    const engineName = subPath.substring('mounts/'.length).replace(/\/+$/, '');
    const body = await parseBody(req);
    const result = secretsService.createEngine(engineName, session.username, body.description || '');
    if (!result.success) { sendJson(res, 400, { errors: [result.error] }); return; }
    sendJson(res, 204, {});
    return;
  }

  // DELETE /v1/sys/mounts/:path — supprimer un engine
  if (req.method === 'DELETE' && subPath.startsWith('mounts/')) {
    const engineName = subPath.substring('mounts/'.length).replace(/\/+$/, '');
    const result = secretsService.deleteEngine(engineName);
    if (!result.success) { sendJson(res, 400, { errors: [result.error] }); return; }
    sendJson(res, 204, {});
    return;
  }

  // POST /v1/sys/capabilities-self
  if (req.method === 'POST' && subPath === 'capabilities-self') {
    const body = await parseBody(req);
    const caps = {};
    const paths = Array.isArray(body.paths) ? body.paths : [body.path];
    for (const p of paths) {
      caps[p] = ['create', 'read', 'update', 'delete', 'list', 'sudo'];
    }
    sendJson(res, 200, { data: caps });
    return;
  }

  // GET /v1/sys/policies/acl/:name
  if (req.method === 'GET' && subPath.startsWith('policies/acl/')) {
    sendJson(res, 200, { data: { name: 'default', policy: 'path "*" { capabilities = ["create","read","update","delete","list"] }' } });
    return;
  }

  // POST /v1/sys/wrapping/unwrap
  if (req.method === 'POST' && subPath === 'wrapping/unwrap') {
    sendJson(res, 400, { errors: ['wrapping non disponible en mode local'] });
    return;
  }

  sendJson(res, 404, { errors: ['endpoint not found'] });
}

async function handleKV(req, res, pathParts, query) {
  const session = authenticate(req);
  if (!session) { sendJson(res, 403, { errors: ['permission denied'] }); return; }

  const token = getToken(req);
  const sessionKey = getSessionKey(token);
  if (!sessionKey) { sendJson(res, 403, { errors: ['session key not found'] }); return; }

  // Trouver l'engine : tester du plus long au plus court
  const engines = secretsService.listEngines();
  const sortedEngines = engines.sort((a, b) => b.name.length - a.name.length);

  // Le path complet après /v1/
  const fullPath = pathParts.slice(1).join('/');

  let engine = null;
  let operation = null; // data, metadata, delete, undelete
  let secretKey = '';

  for (const e of sortedEngines) {
    const eName = e.name;
    // KV v2: /v1/{engine}/data/{key}, /v1/{engine}/metadata/{key}, etc.
    for (const op of ['data', 'metadata', 'delete', 'undelete']) {
      const prefix = `${eName}/${op}`;
      if (fullPath === prefix || fullPath.startsWith(prefix + '/') || fullPath === eName + '/' + op) {
        engine = secretsService.getEngine(eName);
        operation = op;
        secretKey = fullPath.substring(prefix.length + 1) || '';
        // Décoder chaque segment individuellement (pas de double-decode)
        secretKey = secretKey.split('/').map(s => decodeURIComponent(s)).join('/');
        break;
      }
    }
    if (engine) break;

    // KV v2 sans opération : /v1/{engine}/metadata?list=true (quand key est vide)
    // Fallback: /v1/{engine}?list=true (compatibilité)
    if (fullPath === eName || fullPath === eName + '/') {
      if (query.list === 'true') {
        engine = secretsService.getEngine(eName);
        operation = 'metadata';
        secretKey = '';
        break;
      }
    }
  }

  if (!engine) {
    sendJson(res, 404, { errors: ['engine not found'] });
    return;
  }

  // ─── METADATA ───
  if (operation === 'metadata') {
    // GET — list ou get metadata
    if (req.method === 'GET') {
      if (query.list === 'true') {
        const keys = secretsService.listKeys(engine.id, secretKey);
        sendJson(res, 200, { data: { keys } });
        return;
      }
      // Get metadata d'un secret spécifique
      const meta = secretsService.getSecretMetadata(engine.id, secretKey);
      if (!meta) { sendJson(res, 404, { errors: ['secret not found'] }); return; }
      sendJson(res, 200, { data: meta });
      return;
    }
    // DELETE — supprimer toutes les versions (destroy)
    if (req.method === 'DELETE') {
      secretsService.destroySecret(engine.id, secretKey);
      sendJson(res, 204, {});
      return;
    }
  }

  // ─── DATA ───
  if (operation === 'data') {
    // GET — lire un secret
    if (req.method === 'GET') {
      const version = query.version ? parseInt(query.version) : null;
      const result = secretsService.readSecret(engine.id, secretKey, sessionKey.encKey, version);
      if (!result.success) { sendJson(res, 404, { errors: [result.error] }); return; }
      sendJson(res, 200, {
        data: {
          data: result.data,
          metadata: result.metadata
        }
      });
      return;
    }
    // POST — écrire un secret
    if (req.method === 'POST') {
      const body = await parseBody(req);
      const data = body.data || body;
      const result = secretsService.writeSecret(engine.id, secretKey, data, sessionKey.encKey);
      if (!result.success) { sendJson(res, 400, { errors: [result.error] }); return; }
      sendJson(res, 200, {
        data: {
          created_time: new Date().toISOString(),
          version: result.version,
          deletion_time: '',
          destroyed: false
        }
      });
      return;
    }
  }

  // ─── DELETE (soft) ───
  if (operation === 'delete' && req.method === 'POST') {
    const body = await parseBody(req);
    const versions = body.versions || [];
    secretsService.deleteSecretVersions(engine.id, secretKey, versions);
    sendJson(res, 204, {});
    return;
  }

  // ─── UNDELETE ───
  if (operation === 'undelete' && req.method === 'POST') {
    const body = await parseBody(req);
    const versions = body.versions || [];
    secretsService.undeleteSecretVersions(engine.id, secretKey, versions);
    sendJson(res, 204, {});
    return;
  }

  sendJson(res, 404, { errors: ['not found'] });
}

async function handleTotp(req, res, pathParts) {
  const session = authenticate(req);
  if (!session) { sendJson(res, 403, { errors: ['permission denied'] }); return; }

  const token = getToken(req);
  const sessionKey = getSessionKey(token);
  if (!sessionKey) { sendJson(res, 403, { errors: ['session error'] }); return; }

  // /v1/TOTP/keys/:name
  if (pathParts[2] === 'keys' && pathParts[3]) {
    const name = decodeURIComponent(pathParts[3]);
    // SÉCURITÉ: Valider le nom de la clé TOTP
    if (!name || name.length > 512 || /[\x00-\x1F]/.test(name)) {
      sendJson(res, 400, { errors: ['Invalid TOTP key name'] });
      return;
    }
    if (req.method === 'POST') {
      const body = await parseBody(req);
      const secret = body.url || body.key || '';
      // Extraire le secret depuis otpauth:// URL si fourni
      let secretBase32 = secret;
      if (secret.startsWith('otpauth://')) {
        const match = secret.match(/secret=([A-Z2-7]+)/i);
        if (match) secretBase32 = match[1];
      }
      totpService.createKey(name, secretBase32, sessionKey.encKey, body);
      sendJson(res, 204, {});
      return;
    }
    if (req.method === 'GET') {
      const key = totpService.getKey(name);
      if (!key) { sendJson(res, 404, { errors: ['not found'] }); return; }
      sendJson(res, 200, { data: key });
      return;
    }
    if (req.method === 'DELETE') {
      totpService.deleteKey(name);
      sendJson(res, 204, {});
      return;
    }
  }

  // /v1/TOTP/code/:name
  if (pathParts[2] === 'code' && pathParts[3]) {
    if (req.method === 'GET') {
      const result = totpService.getCode(pathParts[3], sessionKey.encKey);
      if (!result.success) { sendJson(res, 404, { errors: [result.error] }); return; }
      sendJson(res, 200, { data: { code: result.code } });
      return;
    }
  }

  sendJson(res, 404, { errors: ['not found'] });
}

// ========================================
// SERVEUR HTTP
// ========================================

/**
 * Démarre le serveur local Vault
 * @param {number} port - Port d'écoute (0 = dynamique)
 * @returns {Promise<number>} Port réel utilisé
 */
function start(port = 0) {
  return new Promise((resolve, reject) => {
    // Initialiser la base de données
    database.init();

    server = http.createServer(async (req, res) => {
      // CORS restreint au renderer Electron uniquement (file:// ou dev server exact)
      const reqOrigin = req.headers.origin;
      if (reqOrigin && (reqOrigin === 'file://' || reqOrigin === 'http://localhost:3000')) {
        res.setHeader('Access-Control-Allow-Origin', reqOrigin);
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, LIST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Vault-Token, X-Vault-Request, X-Vault-Namespace');
      res.setHeader('Content-Type', 'application/json');

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      try {
        const path = parsePath(req.url);
        const query = parseQuery(req.url);
        const pathParts = path.split('/').filter(Boolean); // ['v1', 'auth', 'ldap', ...]

        if (pathParts[0] !== 'v1') {
          sendJson(res, 404, { errors: ['not found'] });
          return;
        }

        const section = pathParts[1];

        if (section === 'auth') {
          await handleAuth(req, res, pathParts);
        } else if (section === 'sys') {
          await handleSys(req, res, pathParts, query);
        } else if (section === 'TOTP' || section === 'totp') {
          await handleTotp(req, res, pathParts);
        } else {
          // Tout le reste = opération KV sur un engine
          await handleKV(req, res, pathParts, query);
        }
      } catch (err) {
        console.error('[LocalVault] Erreur serveur:', err.message);
        sendJson(res, 500, { errors: ['internal error'] });
      }
    });

    server.listen(port, '127.0.0.1', () => {
      serverPort = server.address().port;
      console.log(`[LocalVault] Serveur démarré sur http://127.0.0.1:${serverPort}`);
      resolve(serverPort);
    });

    server.on('error', reject);
  });
}

/**
 * Arrête le serveur et ferme la base
 */
function stop() {
  if (server) {
    server.close();
    server = null;
  }
  sessionKeys.clear();
  database.close();
  console.log('[LocalVault] Serveur arrêté');
}

/**
 * Retourne le port actuel du serveur
 */
function getPort() {
  return serverPort;
}

module.exports = { start, stop, getPort };
