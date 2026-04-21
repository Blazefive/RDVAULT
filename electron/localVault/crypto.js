// ========================================
// CRYPTO — Chiffrement AES-256-GCM + dérivation de clé PBKDF2
// ========================================
// Utilisé par le mode local pour chiffrer les secrets dans SQLite.
// Chaque valeur est chiffrée individuellement avec un IV unique.

'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // NIST SP 800-38D recommended for GCM
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 210000; // OWASP 2024 recommendation for SHA-512
const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 32;

/**
 * Dérive une clé AES-256 depuis un mot de passe maître + salt
 * @param {string} password - Mot de passe maître
 * @param {string} salt - Salt en hex
 * @returns {Buffer} Clé de 32 octets
 */
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
}

/**
 * Génère un salt aléatoire
 * @returns {string} Salt en hex (32 octets)
 */
function generateSalt() {
  return crypto.randomBytes(SALT_LENGTH).toString('hex');
}

/**
 * Chiffre une chaîne avec AES-256-GCM
 * @param {string} plaintext - Texte à chiffrer
 * @param {Buffer} key - Clé de 32 octets
 * @returns {{ encrypted: string, iv: string }} Données chiffrées en hex + IV en hex
 */
function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return {
    encrypted: encrypted + ':' + authTag,
    iv: iv.toString('hex')
  };
}

/**
 * Déchiffre une chaîne chiffrée avec AES-256-GCM
 * @param {string} encryptedData - Données chiffrées (encrypted:authTag en hex)
 * @param {string} ivHex - IV en hex
 * @param {Buffer} key - Clé de 32 octets
 * @returns {string} Texte déchiffré
 */
function decrypt(encryptedData, ivHex, key) {
  const [encrypted, authTagHex] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Génère un token aléatoire (pour les sessions)
 * @returns {string} Token de 64 caractères hex
 */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  deriveKey,
  generateSalt,
  encrypt,
  decrypt,
  generateToken,
};
