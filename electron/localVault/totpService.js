// ========================================
// TOTP SERVICE — Gestion des clés TOTP et génération de codes
// ========================================

'use strict';

const crypto = require('crypto');
const { getDb } = require('./database');
const { encrypt, decryptDetailed } = require('./crypto');
// Point de contrôle WAL après un effacement définitif (même règle que les secrets détruits)
const { checkpointWal } = require('./secretsService');

const ALGORITHMS = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

/** Contexte authentifié (AAD) d'une clé TOTP */
const aadFor = (name) => `totp:${name}`;

/** Décode un secret Base32 en Buffer */
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(str).replace(/[= ]/g, '').toUpperCase();
  let bits = '';
  for (const char of cleaned) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

/**
 * Génère un code TOTP (RFC 6238)
 * @param {string} secretBase32
 * @param {number} period - Période en secondes (défaut 30)
 * @param {number} digits - Nombre de chiffres (défaut 6)
 * @param {string} algorithm - SHA1, SHA256, SHA512
 */
function generateCode(secretBase32, period = 30, digits = 6, algorithm = 'SHA1') {
  const secret = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / period);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter & 0xFFFFFFFF, 4);

  const hmac = crypto.createHmac(ALGORITHMS[algorithm] || 'sha1', secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0F;
  const code = (
    ((hmac[offset] & 0x7F) << 24) |
    ((hmac[offset + 1] & 0xFF) << 16) |
    ((hmac[offset + 2] & 0xFF) << 8) |
    (hmac[offset + 3] & 0xFF)
  ) % Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

/** Bornes acceptées : la période suit l'interface (TotpConfigModal : 10 à 120 s) */
const PERIOD_MIN = 10;
const PERIOD_MAX = 120;
const DIGITS_MIN = 6;
const DIGITS_MAX = 8;

/** Vrai si l'option n'a pas été fournie (la valeur par défaut s'applique alors) */
const isAbsent = (v) => v === undefined || v === null || v === '';

/** Valide et normalise les options d'une clé TOTP (valeur absente ou hors bornes → valeur par défaut) */
function sanitizeOptions(options = {}) {
  const period = Number(options.period);
  const digits = Number(options.digits);
  const algorithm = String(options.algorithm || 'SHA1').toUpperCase();
  return {
    issuer: typeof options.issuer === 'string' ? options.issuer.slice(0, 256) : '',
    account: typeof options.account === 'string' ? options.account.slice(0, 256) : '',
    period: Number.isInteger(period) && period >= PERIOD_MIN && period <= PERIOD_MAX ? period : 30,
    digits: Number.isInteger(digits) && digits >= DIGITS_MIN && digits <= DIGITS_MAX ? digits : 6,
    algorithm: ALGORITHMS[algorithm] ? algorithm : 'SHA1',
  };
}

/**
 * Refuse une option FOURNIE mais invalide (au lieu de la remplacer en silence par la valeur par
 * défaut : la clé produirait alors des codes toujours faux pour le service, ex. période 12 s → 30 s).
 * @returns {string|null} Message d'erreur, ou null si les options sont acceptables
 */
function validateOptions(options = {}) {
  if (!isAbsent(options.period)) {
    const period = Number(options.period);
    if (!Number.isInteger(period) || period < PERIOD_MIN || period > PERIOD_MAX) {
      return `Période TOTP invalide (entier de ${PERIOD_MIN} à ${PERIOD_MAX} s attendu)`;
    }
  }
  if (!isAbsent(options.digits)) {
    const digits = Number(options.digits);
    if (!Number.isInteger(digits) || digits < DIGITS_MIN || digits > DIGITS_MAX) {
      return `Nombre de chiffres TOTP invalide (${DIGITS_MIN} à ${DIGITS_MAX} attendu)`;
    }
  }
  if (!isAbsent(options.algorithm) && !ALGORITHMS[String(options.algorithm).toUpperCase()]) {
    return 'Algorithme TOTP invalide (SHA1, SHA256 ou SHA512 attendu)';
  }
  return null;
}

/**
 * Crée (ou remplace) une clé TOTP
 * @returns {{ success: boolean, error?: string }}
 */
function createKey(name, secretBase32, encKey, options = {}, owner = null) {
  if (typeof secretBase32 !== 'string' || !/^[A-Z2-7= ]{8,256}$/i.test(secretBase32)) {
    return { success: false, error: 'Secret TOTP invalide (Base32 attendu)' };
  }
  const optionsError = validateOptions(options || {});
  if (optionsError) return { success: false, error: optionsError };
  const opts = sanitizeOptions(options || {});
  const { encrypted, iv } = encrypt(secretBase32, encKey, aadFor(name));

  const db = getDb();
  // Remplacement d'une clé existante : l'ancienne graine est effacée (REPLACE), elle ne doit pas survivre
  // dans le journal WAL
  const replaced = !!db.prepare('SELECT 1 FROM totp_keys WHERE name = ?').get(name);
  db.prepare(`
    INSERT OR REPLACE INTO totp_keys (name, secret_encrypted, iv, issuer, account, period, digits, algorithm, owner)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(name, encrypted, iv, opts.issuer, opts.account, opts.period, opts.digits, opts.algorithm, owner);
  if (replaced) checkpointWal(db);

  return { success: true };
}

/** Lit une clé TOTP (config sans le secret, avec propriétaire) */
function getKey(name) {
  const row = getDb().prepare('SELECT * FROM totp_keys WHERE name = ?').get(name);
  if (!row) return null;
  return {
    name: row.name,
    issuer: row.issuer,
    account: row.account,
    period: row.period,
    digits: row.digits,
    algorithm: row.algorithm,
    owner: row.owner || null,
  };
}

/** Génère un code TOTP pour une clé */
function getCode(name, encKey) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM totp_keys WHERE name = ?').get(name);
  if (!row) return { success: false, error: 'Clé TOTP introuvable' };

  try {
    const { plaintext: secretBase32, legacy } = decryptDetailed(row.secret_encrypted, row.iv, encKey, aadFor(name));
    if (legacy) {
      // Migration transparente : re-chiffrer avec AAD
      const re = encrypt(secretBase32, encKey, aadFor(name));
      db.prepare('UPDATE totp_keys SET secret_encrypted = ?, iv = ? WHERE id = ?').run(re.encrypted, re.iv, row.id);
    }
    const code = generateCode(secretBase32, row.period, row.digits, row.algorithm);
    return { success: true, code };
  } catch {
    return { success: false, error: 'Erreur déchiffrement TOTP' };
  }
}

/** Supprime une clé TOTP. Effacement physique : point de contrôle WAL si une graine a été supprimée */
function deleteKey(name) {
  const db = getDb();
  const result = db.prepare('DELETE FROM totp_keys WHERE name = ?').run(name);
  if (result.changes > 0) checkpointWal(db);
  return { success: result.changes > 0 };
}

module.exports = { createKey, getKey, getCode, deleteKey, generateCode, sanitizeOptions, validateOptions };
