// ========================================
// CRYPTO — Chiffrement AES-256-GCM + dérivation de clé (scrypt par défaut, PBKDF2 hérité)
// ========================================
// Utilisé par le mode local pour chiffrer les secrets dans SQLite.
// Chaque valeur est chiffrée individuellement avec un IV unique.
// La dérivation de clé passe par deriveKeyWithKdf(Sync) et le descripteur de KDF
// stocké avec chaque utilisateur (voir DEFAULT_KDF) ; PBKDF2 n'est conservé que
// pour les coffres créés par les versions précédentes.
//
// Données authentifiées additionnelles (AAD) : chaque valeur est liée à son
// contexte (engine/clé/version, ou nom de clé TOTP). Un blob chiffré déplacé
// vers une autre ligne de la base ne se déchiffre plus. Les valeurs écrites
// par les versions précédentes (sans AAD) restent lisibles et sont re-chiffrées
// avec AAD à la première lecture (voir secretsService / totpService).

'use strict';

const crypto = require('crypto');
const { promisify } = require('util');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // NIST SP 800-38D recommended for GCM
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 210000; // OWASP recommendation for PBKDF2-HMAC-SHA512
const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 32;

// scrypt (mémoire-dur) : bien plus résistant au cassage par GPU/ASIC que PBKDF2.
// N=65536, r=8, p=1 ≈ 64 Mio de mémoire par dérivation (~0,2–0,4 s sur un poste de bureau).
const SCRYPT_N = 65536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
// scrypt exige maxmem > 128*N*r (≈ 67 Mio ici) ; on laisse une marge.
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

// Descripteur de KDF stocké avec chaque utilisateur. Les nouveaux comptes utilisent scrypt ;
// les comptes existants (champ kdf absent/NULL) restent en PBKDF2 — AUCUNE migration forcée,
// donc aucun risque de verrouiller un coffre déjà créé.
const DEFAULT_KDF = `scrypt:N=${SCRYPT_N},r=${SCRYPT_R},p=${SCRYPT_P}`;

const pbkdf2 = promisify(crypto.pbkdf2);
const scryptAsync = promisify(crypto.scrypt);

/**
 * Analyse un descripteur de KDF ("pbkdf2:i=210000,h=sha512" ou "scrypt:N=65536,r=8,p=1").
 * Un descripteur absent/NULL/vide = PBKDF2 hérité (comportement des versions précédentes).
 * @param {string|null|undefined} descriptor
 * @returns {{ algo: string, params: object }}
 */
function parseKdf(descriptor) {
  if (!descriptor || typeof descriptor !== 'string') {
    return { algo: 'pbkdf2', params: { iterations: PBKDF2_ITERATIONS, hash: 'sha512' } };
  }
  const [algo, paramStr = ''] = descriptor.split(':');
  const p = {};
  for (const pair of paramStr.split(',')) {
    const [k, v] = pair.split('=');
    if (k) p[k.trim()] = v != null ? v.trim() : '';
  }
  if (algo === 'pbkdf2') {
    return { algo: 'pbkdf2', params: { iterations: Number(p.i || p.iterations) || PBKDF2_ITERATIONS, hash: p.h || p.hash || 'sha512' } };
  }
  if (algo === 'scrypt') {
    return { algo: 'scrypt', params: { N: Number(p.N) || SCRYPT_N, r: Number(p.r) || SCRYPT_R, p: Number(p.p) || SCRYPT_P } };
  }
  throw new Error('KDF inconnu: ' + algo);
}

/**
 * Dérive une clé AES-256 selon le descripteur de KDF de l'utilisateur (asynchrone).
 * @param {string} password - Mot de passe maître
 * @param {string} salt - Salt en hex
 * @param {string|null} [descriptor] - Descripteur de KDF (DEFAULT_KDF pour les nouveaux comptes)
 * @returns {Promise<Buffer>} Clé de 32 octets
 */
function deriveKeyWithKdf(password, salt, descriptor) {
  const { algo, params } = parseKdf(descriptor);
  const saltBuf = Buffer.from(salt, 'hex');
  if (algo === 'scrypt') {
    return scryptAsync(password, saltBuf, KEY_LENGTH, { N: params.N, r: params.r, p: params.p, maxmem: SCRYPT_MAXMEM });
  }
  return pbkdf2(password, saltBuf, params.iterations, KEY_LENGTH, params.hash);
}

/** Variante synchrone de deriveKeyWithKdf (tests / scripts). */
function deriveKeyWithKdfSync(password, salt, descriptor) {
  const { algo, params } = parseKdf(descriptor);
  const saltBuf = Buffer.from(salt, 'hex');
  if (algo === 'scrypt') {
    return crypto.scryptSync(password, saltBuf, KEY_LENGTH, { N: params.N, r: params.r, p: params.p, maxmem: SCRYPT_MAXMEM });
  }
  return crypto.pbkdf2Sync(password, saltBuf, params.iterations, KEY_LENGTH, params.hash);
}

/** Génère un salt aléatoire (hex, 32 octets) */
function generateSalt() {
  return crypto.randomBytes(SALT_LENGTH).toString('hex');
}

/**
 * Chiffre une chaîne avec AES-256-GCM
 * @param {string} plaintext
 * @param {Buffer} key - Clé de 32 octets
 * @param {string} [aad] - Contexte authentifié (recommandé)
 * @returns {{ encrypted: string, iv: string }} "cipher:tag" en hex + IV en hex
 */
function encrypt(plaintext, key, aad) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  if (aad) cipher.setAAD(Buffer.from(String(aad), 'utf8'));
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return { encrypted: encrypted + ':' + authTag, iv: iv.toString('hex') };
}

function decryptRaw(encryptedData, ivHex, key, aad) {
  const [encrypted, authTagHex] = String(encryptedData).split(':');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'), { authTagLength: AUTH_TAG_LENGTH });
  if (aad) decipher.setAAD(Buffer.from(String(aad), 'utf8'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Déchiffre une chaîne chiffrée avec AES-256-GCM.
 * Si un AAD est fourni et que le déchiffrement échoue, tente le format hérité (sans AAD)
 * et signale `legacy: true` pour permettre une re-chiffrement transparente.
 * @returns {{ plaintext: string, legacy: boolean }}
 * @throws si la clé est mauvaise ou les données altérées
 */
function decryptDetailed(encryptedData, ivHex, key, aad) {
  if (!aad) return { plaintext: decryptRaw(encryptedData, ivHex, key), legacy: false };
  try {
    return { plaintext: decryptRaw(encryptedData, ivHex, key, aad), legacy: false };
  } catch (err) {
    // Format hérité (écrit sans AAD par une version précédente)
    return { plaintext: decryptRaw(encryptedData, ivHex, key), legacy: true };
  }
}

/** Déchiffre et retourne le texte (voir decryptDetailed) */
function decrypt(encryptedData, ivHex, key, aad) {
  return decryptDetailed(encryptedData, ivHex, key, aad).plaintext;
}

/** Génère un token aléatoire (64 caractères hex) */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  deriveKeyWithKdf,
  deriveKeyWithKdfSync,
  parseKdf,
  generateSalt,
  encrypt,
  decrypt,
  decryptDetailed,
  generateToken,
  DEFAULT_KDF,
};
