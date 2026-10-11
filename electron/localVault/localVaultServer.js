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
const { deriveKeyWithKdf } = require('./crypto');
const log = require('../logger');

let server = null;

/** SÉCURITÉ: un engine ou une clé TOTP n'est accessible qu'à son propriétaire ou à un administrateur */
function canAccess(ownedObject, session) {
  if (!ownedObject) return false;
  if (session.isAdmin) return true;
  return !ownedObject.owner || ownedObject.owner === session.username;
}
let serverPort = null;

// Réponse (500) d'une donnée présente mais indéchiffrable (intégrité GCM/AAD, mauvaise clé) : distincte du 404
// « introuvable » et volontairement générique (aucun détail sur la cause) — LOCALVAULT-3
const DECRYPTION_FAILED = 'decryption failed';

// Clés de chiffrement dérivées en mémoire (token -> { encKey: Buffer, salt: string })
// Le mot de passe brut n'est JAMAIS stocké — seule la clé AES-256 dérivée est conservée
const sessionKeys = new Map();

// ========================================
// HELPERS
// ========================================

// Rate limiting pour le login (5 tentatives / 5 min). Vérification + comptage synchrones : à appeler
// uniquement pour une vraie tentative (corps JSON avec mot de passe), avant tout await (requêtes parallèles comptées)
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

// AUTH-14 : création du PREMIER compte (base vide) en cours. Elle est sérialisée : deux requêtes simultanées
// sur une base vide ne créent plus deux administrateurs ; la seconde attend la fin de la première puis suit
// le chemin de connexion normal (même compte → connexion, autre nom → identifiants invalides).
let firstAccountCreation = null;

/**
 * AUTH-14 : la création du premier compte exige la confirmation du mot de passe maître (`confirm`, envoyée
 * par l'écran de création). Une faute de frappe deviendrait sinon le mot de passe de chiffrement du coffre.
 * @returns {string|null} message d'erreur (400), ou null si la confirmation est présente et identique
 */
function firstAccountConfirmError(body, password) {
  if (typeof body.confirm !== 'string') return 'password confirmation required';
  if (body.confirm !== password) return 'password confirmation does not match';
  return null;
}

/**
 * Lit le paramètre check-and-set d'une écriture KV v2 (`options.cas`, sémantique Vault : la version courante
 * du secret doit valoir cas ; 0 = le secret ne doit pas exister). Vault accepte un entier ou sa forme texte.
 * @returns {{ cas: number|null, error?: string }} cas null = écriture sans contrôle
 */
function parseCasOption(body) {
  const options = body && typeof body.options === 'object' && body.options !== null && !Array.isArray(body.options)
    ? body.options : null;
  if (!options || !Object.prototype.hasOwnProperty.call(options, 'cas')) return { cas: null };
  const raw = options.cas;
  const cas = typeof raw === 'string' && /^\d{1,15}$/.test(raw.trim()) ? Number(raw.trim()) : raw;
  if (!Number.isSafeInteger(cas) || cas < 0) return { cas: null, error: 'error parsing check-and-set parameter' };
  return { cas };
}

// Limite de taille du corps des requêtes. Relevée à 10 Mio pour couvrir les secrets
// avec pièces jointes (l'UI autorise plusieurs Mo) ; borne une utilisation mémoire abusive.
const MAX_BODY_BYTES = 10 * 1024 * 1024;

function parseBody(req) {
  return new Promise((resolve, reject) => {
    // Accumuler les Buffers bruts et ne décoder l'UTF-8 qu'une seule fois à la fin : un caractère
    // multi-octets coupé entre deux chunks deviendrait sinon U+FFFD (et serait chiffré ainsi)
    const chunks = [];
    let bytes = 0;
    let rejected = false;
    req.on('data', c => {
      if (rejected) return; // on a atteint la limite : on cesse d'accumuler (mémoire bornée)
      bytes += c.length;
      if (bytes > MAX_BODY_BYTES) {
        rejected = true;
        const e = new Error('Body too large'); e.statusCode = 413;
        reject(e); // pas de req.destroy() : laisse le 413 partir vers le client
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (rejected) return;
      const body = Buffer.concat(chunks).toString('utf8');
      let parsed;
      try { parsed = body ? JSON.parse(body) : {}; }
      catch { const e = new Error('Invalid JSON'); e.statusCode = 400; reject(e); return; }
      // Toutes les routes attendent un objet (format API Vault) : null, chaîne, nombre ou tableau → 400 (pas 500)
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        const e = new Error('Invalid JSON body: object expected'); e.statusCode = 400; reject(e); return;
      }
      resolve(parsed);
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'X-Frame-Options': 'DENY'
  });
  res.end(JSON.stringify(data));
}

function getToken(req) {
  return req.headers['x-vault-token'] || null;
}

function authenticate(req) {
  const token = getToken(req);
  if (!token) return null;
  const session = authService.validateToken(token);
  // Si le token a expiré, nettoyer aussi la clé de session
  if (!session && token) {
    sessionKeys.delete(token);
  }
  return session;
}

/** Récupère la clé de chiffrement dérivée depuis la session */
function getSessionKey(token) {
  return sessionKeys.get(token) || null;
}

/** Extrait le chemin de l'URL (non décodé) */
function parsePath(url) {
  const [pathPart] = url.split('?');
  // Ne PAS décoder ici — les segments sont décodés individuellement (une seule fois) après split
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

async function handleAuth(req, res, pathParts, rawParts) {
  // POST /v1/auth/ldap/login/:user
  if (req.method === 'POST' && pathParts[2] === 'ldap' && pathParts[3] === 'login' && pathParts[4]) {
    let username = pathParts[4];

    const body = await parseBody(req);
    const password = body.password;
    if (typeof password !== 'string' || password.length === 0 || password.length > 1024) {
      sendJson(res, 400, { errors: ['password requis'] });
      return;
    }

    // Compatibilité ascendante : avant le décodage des segments d'URL, le nom était stocké tel que reçu
    // (ex. « jean%40exemple.fr »). Si le nom décodé est inconnu mais que la forme brute existe, on l'utilise.
    const rawUsername = rawParts[4];
    if (rawUsername !== username && !authService.getUserInfo(username) && authService.getUserInfo(rawUsername)) {
      username = rawUsername;
    }

    // AUTH-14 : base vide → cette requête crée le compte administrateur ; la confirmation du mot de passe est
    // exigée. Contrôle placé AVANT le quota anti-force brute (aucun compte à deviner : une requête incomplète
    // ne bloque pas la création pendant 5 minutes) ; une requête refusée ici ne crée rien.
    if (database.isEmpty() && !firstAccountCreation) {
      const confirmError = firstAccountConfirmError(body, password);
      if (confirmError) {
        sendJson(res, 400, { errors: [confirmError] });
        return;
      }
    }

    // Rate limiting : 5 tentatives / 5 min. Placé APRÈS la validation du corps : une requête sans mot de
    // passe (POST vide depuis une origine opaque, JSON invalide…) ne consomme pas le quota de l'utilisateur.
    if (!checkLoginRateLimit(username)) {
      sendJson(res, 429, { errors: ['Too many login attempts. Try again in 5 minutes.'] });
      return;
    }

    // Premier démarrage : si aucun utilisateur, en créer un automatiquement (compte administrateur).
    // Cette auto-création reste protégée par les deux barrières anti cross-site du serveur (origine
    // web tierce → 403, corps non JSON → 415) : une page web ne peut pas créer l'admin à la place de l'utilisateur.
    // Une création déjà en cours est attendue d'abord (voir firstAccountCreation).
    while (firstAccountCreation) {
      try { await firstAccountCreation; } catch { /* l'échec de l'autre requête lui a déjà été répondu */ }
    }
    let personalEngineCreated = null;
    if (database.isEmpty()) {
      // Confirmation revérifiée : la base a pu redevenir « vide » pendant l'attente (création concurrente échouée)
      const confirmError = firstAccountConfirmError(body, password);
      if (confirmError) {
        sendJson(res, 400, { errors: [confirmError] });
        return;
      }
      const creation = (async () => {
        const createResult = await authService.createUser(username, password, true);
        if (!createResult.success) return createResult;
        // Créer un engine personnel par défaut
        const engineName = `users/${username}/Mes-Secrets`;
        secretsService.createEngine(engineName, username, 'Coffre personnel');
        log.info('[LocalVault] Premier utilisateur créé (admin)');
        return { success: true, engineName };
      })();
      firstAccountCreation = creation;
      let createResult;
      try { createResult = await creation; } finally { firstAccountCreation = null; }
      if (!createResult.success) {
        sendJson(res, 400, { errors: [createResult.error] });
        return;
      }
      personalEngineCreated = createResult.engineName;
    }

    // Dériver la clé AES-256 (asynchrone) selon le KDF du compte (scrypt pour les nouveaux,
    // PBKDF2 pour les comptes hérités) — le mot de passe brut n'est PAS conservé. Dérivée une seule fois,
    // au besoin pendant le login (vérification LOCALVAULT-1) sinon juste après.
    const salt = authService.getEncryptionSalt(username);
    const kdf = authService.getKdfDescriptor(username);
    let encKey = null;
    const deriveSessionKey = async () => {
      if (!encKey) encKey = await deriveKeyWithKdf(password, salt, kdf);
      return encKey;
    };

    // LOCALVAULT-1 : mot de passe de plus de 72 octets UTF-8 (bcrypt n'en compare que le début) → le login
    // n'aboutit que si la clé dérivée du mot de passe ENTIER déchiffre les données du compte (ou s'il n'en a pas)
    const result = await authService.login(username, password, {
      verifyFullPassword: async (user) => secretsService.keyMatchesAccountData(user.username, await deriveSessionKey())
    });
    if (!result.success) {
      sendJson(res, 400, { errors: [result.error] });
      return;
    }

    await deriveSessionKey();
    sessionKeys.set(result.token, { encKey, salt });
    resetLoginRateLimit(username);

    // Nouveau compte au mot de passe de plus de 72 octets : témoin de clé caché, pour que la vérification
    // ci-dessus s'applique dès le login suivant, avant même la première donnée
    if (personalEngineCreated && authService.passwordExceedsBcryptLimit(password)) {
      try { secretsService.writeKeyCheck(personalEngineCreated, encKey); }
      catch (err) { log.warn('[LocalVault] Témoin de clé non écrit:', err && err.message); }
    }

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
    // SÉCURITÉ: Vérifier que l'utilisateur est propriétaire ou admin
    const engineInfo = secretsService.getEngine(engineName);
    if (engineInfo) {
      const isOwner = engineInfo.owner === session.username;
      if (!isOwner && !session.isAdmin) {
        sendJson(res, 403, { errors: ['Permission denied: not the owner'] });
        return;
      }
    }
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
        // Segments déjà décodés une fois par le dispatcher (pas de double-decode)
        secretKey = fullPath.substring(prefix.length + 1) || '';
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

  // SÉCURITÉ: contrôle de propriété (lecture, écriture, suppression)
  if (!canAccess(engine, session)) {
    sendJson(res, 403, { errors: ['permission denied'] });
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
      if (!result.success) {
        // Format Vault KV v2 pour une version supprimée : 404 avec data null + metadata (deletion_time)
        if (result.deleted) { sendJson(res, 404, { data: { data: null, metadata: result.metadata } }); return; }
        // LOCALVAULT-3 : la version existe mais ne se déchiffre pas (intégrité GCM/AAD, mauvaise clé) → erreur
        // distincte de « introuvable », pour qu'un client ne la prenne pas pour une entrée absente et ne
        // l'écrase pas. Message fixe, sans détail cryptographique.
        if (result.integrityError) { sendJson(res, 500, { errors: [DECRYPTION_FAILED] }); return; }
        sendJson(res, 404, { errors: [result.error] });
        return;
      }
      sendJson(res, 200, {
        data: {
          data: result.data,
          metadata: result.metadata
        }
      });
      return;
    }
    // POST — écrire un secret. options.cas (check-and-set, comme Vault KV v2) : l'écriture n'a lieu que si
    // la version courante vaut cas (0 = secret inexistant) ; sinon 400 avec le message de Vault, rien n'est écrit.
    if (req.method === 'POST') {
      const body = await parseBody(req);
      const data = body.data || body;
      const { cas, error: casError } = body.data ? parseCasOption(body) : { cas: null };
      if (casError) { sendJson(res, 400, { errors: [casError] }); return; }
      const result = secretsService.writeSecret(engine.id, secretKey, data, sessionKey.encKey, { cas });
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
    const name = pathParts[3]; // déjà décodé par le dispatcher
    // SÉCURITÉ: Valider le nom de la clé TOTP
    // eslint-disable-next-line no-control-regex -- volontaire : nom de clé TOTP avec caractère de contrôle refusé
    if (!name || name.length > 512 || /[\x00-\x1F]/.test(name)) {
      sendJson(res, 400, { errors: ['Invalid TOTP key name'] });
      return;
    }
    // SÉCURITÉ: une clé existante n'est modifiable/lisible que par son propriétaire ou un admin
    const existing = totpService.getKey(name);
    if (existing && !canAccess(existing, session)) {
      sendJson(res, 403, { errors: ['permission denied'] });
      return;
    }
    if (req.method === 'POST') {
      const body = await parseBody(req);
      const secret = typeof body.url === 'string' ? body.url : (typeof body.key === 'string' ? body.key : '');
      // Extraire le secret depuis otpauth:// URL si fourni
      let secretBase32 = secret;
      if (secret.startsWith('otpauth://')) {
        const match = secret.match(/secret=([A-Z2-7]+)/i);
        if (match) secretBase32 = match[1];
      }
      const owner = existing ? existing.owner : session.username;
      const created = totpService.createKey(name, secretBase32, sessionKey.encKey, body, owner);
      if (!created.success) { sendJson(res, 400, { errors: [created.error] }); return; }
      sendJson(res, 204, {});
      return;
    }
    if (req.method === 'GET') {
      if (!existing) { sendJson(res, 404, { errors: ['not found'] }); return; }
      const { owner: _owner, ...publicKey } = existing;
      sendJson(res, 200, { data: publicKey });
      return;
    }
    if (req.method === 'DELETE') {
      totpService.deleteKey(name);
      sendJson(res, 204, {});
      return;
    }
  }

  // /v1/TOTP/code/:name (le nom est décodé par le dispatcher, comme pour /keys/:name)
  if (pathParts[2] === 'code' && pathParts[3]) {
    if (req.method === 'GET') {
      const name = pathParts[3];
      const existing = totpService.getKey(name);
      if (existing && !canAccess(existing, session)) { sendJson(res, 403, { errors: ['permission denied'] }); return; }
      const result = totpService.getCode(name, sessionKey.encKey);
      if (!result.success) {
        // LOCALVAULT-3 : clé présente mais graine indéchiffrable → erreur distincte de « introuvable »
        if (existing) { sendJson(res, 500, { errors: [DECRYPTION_FAILED] }); return; }
        sendJson(res, 404, { errors: [result.error] });
        return;
      }
      sendJson(res, 200, { data: { code: result.code } });
      return;
    }
  }

  sendJson(res, 404, { errors: ['not found'] });
}

// ========================================
// SERVEUR HTTP
// ========================================

// SÉCURITÉ (anti cross-site) : une page web tierce ouverte dans un navigateur partage 127.0.0.1 avec
// ce serveur. Une Origin http(s)://<hôte non local> est refusée. Le renderer Electron (file://,
// Origin « null » ou absente), le dev server (http://localhost:3000) et les outils locaux restent admis.
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
function isForbiddenOrigin(origin) {
  if (!origin || !/^https?:\/\//i.test(origin)) return false;
  try { return !LOCAL_HOSTS.has(new URL(origin).hostname.toLowerCase()); }
  catch { return true; } // Origin http(s) inanalysable : on refuse
}

/** Vrai si la requête transporte un corps (Content-Length > 0 ou Transfer-Encoding) */
function hasRequestBody(req) {
  return parseInt(req.headers['content-length'], 10) > 0 || !!req.headers['transfer-encoding'];
}

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
      // CORS restreint au renderer Electron uniquement
      const reqOrigin = req.headers.origin;
      const { app } = require('electron');
      const allowDev = !app.isPackaged;
      if (reqOrigin && (reqOrigin === 'file://' || (allowDev && reqOrigin === 'http://localhost:3000'))) {
        res.setHeader('Access-Control-Allow-Origin', reqOrigin);
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, LIST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Vault-Token, X-Vault-Request, X-Vault-Namespace');
      res.setHeader('Content-Type', 'application/json');

      // SÉCURITÉ (anti cross-site) : (a) origine web tierce → 403 ; (b) un corps doit être du JSON
      // (une page tierce ne peut émettre sans pré-vol que text/plain ou un formulaire) → 415.
      // Un POST sans corps (revoke-self du renderer, data null) n'est pas concerné par (b).
      // Ces deux barrières protègent notamment l'auto-création du premier compte admin (handleAuth).
      if (isForbiddenOrigin(reqOrigin)) {
        sendJson(res, 403, { errors: ['forbidden origin'] });
        return;
      }
      if ((req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') && hasRequestBody(req)
        && !String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
        sendJson(res, 415, { errors: ['unsupported media type'] });
        return;
      }

      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      try {
        const path = parsePath(req.url);
        const query = parseQuery(req.url);
        const rawParts = path.split('/').filter(Boolean); // ['v1', 'auth', 'ldap', ...]
        // Chaque segment est décodé UNE seule fois ici (le client encode username, engine, clé, nom TOTP
        // par segment) : les noms sont ainsi créés, listés et retrouvés sous la même forme. Encodage invalide → 400.
        let pathParts;
        try { pathParts = rawParts.map(s => decodeURIComponent(s)); }
        catch { sendJson(res, 400, { errors: ['invalid path encoding'] }); return; }

        if (pathParts[0] !== 'v1') {
          sendJson(res, 404, { errors: ['not found'] });
          return;
        }

        const section = pathParts[1];

        if (section === 'auth') {
          await handleAuth(req, res, pathParts, rawParts);
        } else if (section === 'sys' && req.method === 'GET' && pathParts[2] === 'init' && pathParts.length === 3) {
          // AUTH-14 : GET /v1/sys/init, non authentifiée comme dans Vault ({ initialized }) : l'écran de
          // connexion passe en mode « création du compte administrateur » tant qu'aucun compte n'existe.
          // Aucune autre information ; les barrières anti cross-site ci-dessus s'appliquent.
          sendJson(res, 200, { initialized: !database.isEmpty() });
        } else if (section === 'sys') {
          await handleSys(req, res, pathParts, query);
        } else if (section === 'TOTP' || section === 'totp') {
          await handleTotp(req, res, pathParts);
        } else {
          // Tout le reste = opération KV sur un engine
          await handleKV(req, res, pathParts, query);
        }
      } catch (err) {
        // Erreurs d'entrée client (corps invalide/trop gros) : code 4xx, pas 500
        const code = err && err.statusCode;
        if (code === 400 || code === 413) {
          sendJson(res, code, { errors: [err.message] });
          return;
        }
        log.error('[LocalVault] Erreur serveur:', err.message);
        sendJson(res, 500, { errors: ['internal error'] });
      }
    });

    server.listen(port, '127.0.0.1', () => {
      serverPort = server.address().port;
      log.info(`[LocalVault] Serveur démarré sur http://127.0.0.1:${serverPort}`);
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
  log.info('[LocalVault] Serveur arrêté');
}

/**
 * Retourne le port actuel du serveur
 */
function getPort() {
  return serverPort;
}

module.exports = { start, stop, getPort };
