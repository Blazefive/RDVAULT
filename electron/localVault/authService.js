// ========================================
// AUTH SERVICE — Gestion des utilisateurs et tokens locaux
// ========================================

'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb } = require('./database');
const { generateToken, generateSalt } = require('./crypto');

// Clé HMAC pour comparaison timing-safe des tokens (non persistée)
const hmacKey = crypto.randomBytes(32);

// Tokens actifs en mémoire : token -> { username, createdAt }
const activeSessions = new Map();

const BCRYPT_ROUNDS = 12;

/**
 * Crée un nouvel utilisateur
 * @param {string} username
 * @param {string} password
 * @param {boolean} isAdmin
 * @returns {{ success: boolean, error?: string }}
 */
function createUser(username, password, isAdmin = false) {
  if (!username || !password) {
    return { success: false, error: 'Nom d\'utilisateur et mot de passe requis' };
  }
  if (username.length < 2 || username.length > 64) {
    return { success: false, error: 'Nom d\'utilisateur: 2-64 caractères' };
  }
  if (password.length < 8) {
    return { success: false, error: 'Password: 8 characters minimum' };
  }

  const db = getDb();
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return { success: false, error: 'Cet utilisateur existe déjà' };
  }

  const passwordHash = bcrypt.hashSync(password, BCRYPT_ROUNDS);
  const encryptionSalt = generateSalt();

  db.prepare('INSERT INTO users (username, password_hash, encryption_salt, is_admin) VALUES (?, ?, ?, ?)')
    .run(username, passwordHash, encryptionSalt, isAdmin ? 1 : 0);

  console.log(`[LocalVault] Utilisateur créé: ${username}`);
  return { success: true };
}

/**
 * Authentifie un utilisateur et retourne un token
 * @param {string} username
 * @param {string} password
 * @returns {{ success: boolean, token?: string, error?: string }}
 */
function login(username, password) {
  if (!username || !password) {
    return { success: false, error: 'Identifiants requis' };
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  // SÉCURITÉ: Toujours exécuter bcrypt même si l'utilisateur n'existe pas (timing-safe)
  const DUMMY_HASH = '$2a$12$000000000000000000000uGWDOlC2oyzVNZ2N0V/KIpDaxHOnXa';
  const hash = user ? user.password_hash : DUMMY_HASH;
  const valid = bcrypt.compareSync(password, hash);
  if (!user || !valid) {
    return { success: false, error: 'Identifiants invalides' };
  }

  const token = generateToken();
  activeSessions.set(token, {
    username: user.username,
    isAdmin: user.is_admin === 1,
    encryptionSalt: user.encryption_salt,
    createdAt: Date.now()
  });

  console.log(`[LocalVault] Connexion: ${username}`);
  return { success: true, token };
}

/**
 * Valide un token et retourne la session
 * @param {string} token
 * @returns {{ username: string, isAdmin: boolean, encryptionSalt: string } | null}
 */
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24h

function validateToken(token) {
  if (!token || typeof token !== 'string') return null;
  // Comparaison timing-safe via HMAC pour chaque token stocké
  for (const [storedToken, session] of activeSessions) {
    try {
      const hmacA = crypto.createHmac('sha256', hmacKey).update(token).digest();
      const hmacB = crypto.createHmac('sha256', hmacKey).update(storedToken).digest();
      if (crypto.timingSafeEqual(hmacA, hmacB)) {
        if (Date.now() - session.createdAt > TOKEN_TTL_MS) {
          activeSessions.delete(storedToken);
          return null;
        }
        return session;
      }
    } catch { continue; }
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

/**
 * Révoque un token (déconnexion)
 * @param {string} token
 */
function revokeToken(token) {
  const session = activeSessions.get(token);
  if (session) {
    console.log(`[LocalVault] Déconnexion: ${session.username}`);
    activeSessions.delete(token);
  }
}

/**
 * Retourne les infos d'un utilisateur (pour token/lookup-self)
 * @param {string} username
 * @returns {object|null}
 */
function getUserInfo(username) {
  const db = getDb();
  const user = db.prepare('SELECT username, is_admin, created_at FROM users WHERE username = ?').get(username);
  if (!user) return null;
  return {
    username: user.username,
    isAdmin: user.is_admin === 1,
    createdAt: user.created_at
  };
}

/**
 * Liste tous les utilisateurs (pour admin)
 * @returns {Array}
 */
function listUsers() {
  return getDb().prepare('SELECT username, is_admin, created_at FROM users').all();
}

/**
 * Supprime un utilisateur
 * @param {string} username
 * @returns {{ success: boolean, error?: string }}
 */
function deleteUser(username) {
  const db = getDb();
  const result = db.prepare('DELETE FROM users WHERE username = ?').run(username);
  if (result.changes === 0) {
    return { success: false, error: 'Utilisateur introuvable' };
  }
  // Révoquer tous les tokens de cet utilisateur
  for (const [token, session] of activeSessions) {
    if (session.username === username) activeSessions.delete(token);
  }
  return { success: true };
}

/**
 * Retourne le salt de chiffrement d'un utilisateur (pour dériver la clé)
 * @param {string} username
 * @returns {string|null}
 */
function getEncryptionSalt(username) {
  const db = getDb();
  const user = db.prepare('SELECT encryption_salt FROM users WHERE username = ?').get(username);
  return user ? user.encryption_salt : null;
}

module.exports = {
  createUser,
  login,
  validateToken,
  revokeToken,
  getUserInfo,
  listUsers,
  deleteUser,
  getEncryptionSalt,
};
