// ========================================
// AUTH SERVICE — Gestion des utilisateurs et tokens locaux
// ========================================

'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb } = require('./database');
const { generateToken, generateSalt, DEFAULT_KDF } = require('./crypto');
const log = require('../logger');

// Clé HMAC pour comparaison timing-safe des tokens (non persistée)
const hmacKey = crypto.randomBytes(32);

// Tokens actifs en mémoire : token -> { username, isAdmin, encryptionSalt, createdAt }
const activeSessions = new Map();

const BCRYPT_ROUNDS = 12;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24h

// SÉCURITÉ: hash factice VALIDE (60 caractères, coût 12) généré au chargement du module.
// Il est comparé quand l'utilisateur n'existe pas, pour que la durée de la tentative soit
// identique à celle d'un utilisateur existant (pas d'énumération par timing).
// Un hash malformé ferait retourner bcrypt immédiatement, ce qui annulerait cette protection.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_ROUNDS);

/**
 * Crée un nouvel utilisateur
 * @returns {Promise<{ success: boolean, error?: string }>}
 */
async function createUser(username, password, isAdmin = false) {
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return { success: false, error: 'Nom d\'utilisateur et mot de passe requis' };
  }
  if (username.length < 2 || username.length > 64) {
    return { success: false, error: 'Nom d\'utilisateur: 2-64 caractères' };
  }
  // SÉCURITÉ: refuser les caractères de contrôle (C0, DEL, C1) — sinon le coffre personnel
  // `users/<nom>/Mes-Secrets` serait refusé par createEngine et jamais créé.
  for (let i = 0; i < username.length; i++) {
    const c = username.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) {
      return { success: false, error: 'Nom d\'utilisateur invalide (caractères de contrôle)' };
    }
  }
  if (password.length < 8) {
    return { success: false, error: 'Password: 8 characters minimum' };
  }

  const db = getDb();
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return { success: false, error: 'Cet utilisateur existe déjà' };
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const encryptionSalt = generateSalt();

  // Nouveaux comptes : KDF scrypt (mémoire-dur). Les comptes existants gardent kdf = NULL (PBKDF2).
  db.prepare('INSERT INTO users (username, password_hash, encryption_salt, is_admin, kdf) VALUES (?, ?, ?, ?, ?)')
    .run(username, passwordHash, encryptionSalt, isAdmin ? 1 : 0, DEFAULT_KDF);

  log.info('[LocalVault] Utilisateur créé');
  return { success: true };
}

/**
 * Vrai si bcrypt ignore une partie du mot de passe : seuls ses 72 premiers octets UTF-8 sont comparés.
 * @param {string} password
 * @returns {boolean}
 */
function passwordExceedsBcryptLimit(password) {
  if (typeof password !== 'string') return false;
  if (typeof bcrypt.truncates === 'function') return bcrypt.truncates(password);
  return Buffer.byteLength(password, 'utf8') > 72;
}

/**
 * Authentifie un utilisateur et retourne un token
 * @param {string} username
 * @param {string} password
 * @param {{ verifyFullPassword?: (user: object) => Promise<boolean>|boolean }} [options]
 *   verifyFullPassword : appelé (avant toute émission de token) seulement si bcrypt a tronqué le mot de
 *   passe ; doit confirmer que le mot de passe ENTIER est le bon (ex. la clé dérivée déchiffre les données).
 * @returns {Promise<{ success: boolean, token?: string, error?: string }>}
 */
async function login(username, password, options = {}) {
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return { success: false, error: 'Identifiants requis' };
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  // SÉCURITÉ: Toujours exécuter bcrypt (hash factice valide si l'utilisateur n'existe pas)
  const hash = user ? user.password_hash : DUMMY_HASH;
  const valid = await bcrypt.compare(password, hash);
  if (!user || !valid) {
    return { success: false, error: 'Identifiants invalides' };
  }

  // SÉCURITÉ (LOCALVAULT-1) : au-delà de 72 octets UTF-8, bcrypt ne voit pas la fin du mot de passe, alors que
  // la clé de chiffrement est dérivée du mot de passe ENTIER. Le hachage stocké reste inchangé (comptes
  // existants) : la fin est vérifiée par l'appelant. Refus = même réponse qu'un mauvais mot de passe, et pas
  // de journal dédié (il révélerait que les 72 premiers octets étaient justes).
  const verifyFullPassword = options && options.verifyFullPassword;
  if (typeof verifyFullPassword === 'function' && passwordExceedsBcryptLimit(password)) {
    let fullPasswordOk = false;
    try { fullPasswordOk = (await verifyFullPassword(user)) === true; } catch { fullPasswordOk = false; }
    if (!fullPasswordOk) {
      return { success: false, error: 'Identifiants invalides' };
    }
  }

  const token = generateToken();
  activeSessions.set(token, {
    username: user.username,
    isAdmin: user.is_admin === 1,
    encryptionSalt: user.encryption_salt,
    createdAt: Date.now()
  });

  log.info('[LocalVault] Connexion réussie');
  return { success: true, token };
}

function tokensEqual(a, b) {
  try {
    const hmacA = crypto.createHmac('sha256', hmacKey).update(a).digest();
    const hmacB = crypto.createHmac('sha256', hmacKey).update(b).digest();
    return crypto.timingSafeEqual(hmacA, hmacB);
  } catch {
    return false;
  }
}

/**
 * Valide un token et retourne la session
 * @returns {{ username: string, isAdmin: boolean, encryptionSalt: string } | null}
 */
function validateToken(token) {
  if (!token || typeof token !== 'string') return null;
  // Comparaison timing-safe via HMAC pour chaque token stocké
  for (const [storedToken, session] of activeSessions) {
    if (tokensEqual(token, storedToken)) {
      if (Date.now() - session.createdAt > TOKEN_TTL_MS) {
        activeSessions.delete(storedToken);
        return null;
      }
      return session;
    }
  }
  // Nettoyage opportuniste des tokens expirés
  if (activeSessions.size > 20) {
    const now = Date.now();
    for (const [t, s] of activeSessions) {
      if (now - s.createdAt > TOKEN_TTL_MS) activeSessions.delete(t);
    }
  }
  return null;
}

/** Révoque un token (déconnexion) */
function revokeToken(token) {
  if (!token || typeof token !== 'string') return;
  for (const [storedToken] of activeSessions) {
    if (tokensEqual(token, storedToken)) {
      activeSessions.delete(storedToken);
      log.info('[LocalVault] Déconnexion');
      return;
    }
  }
}

/** Infos d'un utilisateur (pour token/lookup-self) */
function getUserInfo(username) {
  const user = getDb().prepare('SELECT username, is_admin, created_at FROM users WHERE username = ?').get(username);
  if (!user) return null;
  return { username: user.username, isAdmin: user.is_admin === 1, createdAt: user.created_at };
}

/** Salt de chiffrement d'un utilisateur (pour dériver la clé) */
function getEncryptionSalt(username) {
  const user = getDb().prepare('SELECT encryption_salt FROM users WHERE username = ?').get(username);
  return user ? user.encryption_salt : null;
}

/** Descripteur de KDF d'un utilisateur (NULL = PBKDF2 hérité) */
function getKdfDescriptor(username) {
  const user = getDb().prepare('SELECT kdf FROM users WHERE username = ?').get(username);
  return user ? (user.kdf || null) : null;
}

module.exports = {
  createUser,
  login,
  passwordExceedsBcryptLimit,
  validateToken,
  revokeToken,
  getUserInfo,
  getEncryptionSalt,
  getKdfDescriptor,
};
