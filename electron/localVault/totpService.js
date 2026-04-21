// ========================================
// TOTP SERVICE — Gestion des clés TOTP et génération de codes
// ========================================

'use strict';

const crypto = require('crypto');
const { getDb } = require('./database');
const { encrypt, decrypt } = require('./crypto');

/**
 * Décode un secret Base32 en Buffer
 */
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = str.replace(/[= ]/g, '').toUpperCase();
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
 * @param {string} secretBase32 - Secret en Base32
 * @param {number} period - Période en secondes (défaut 30)
 * @param {number} digits - Nombre de chiffres (défaut 6)
 * @param {string} algorithm - SHA1, SHA256, SHA512
 * @returns {string} Code TOTP
 */
function generateCode(secretBase32, period = 30, digits = 6, algorithm = 'SHA1') {
  const secret = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / period);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter & 0xFFFFFFFF, 4);

  const algoMap = { 'SHA1': 'sha1', 'SHA256': 'sha256', 'SHA512': 'sha512' };
  const hmac = crypto.createHmac(algoMap[algorithm] || 'sha1', secret).update(counterBuf).digest();

  const offset = hmac[hmac.length - 1] & 0x0F;
  const code = (
    ((hmac[offset] & 0x7F) << 24) |
    ((hmac[offset + 1] & 0xFF) << 16) |
    ((hmac[offset + 2] & 0xFF) << 8) |
    (hmac[offset + 3] & 0xFF)
  ) % Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

/**
 * Crée une clé TOTP
 */
function createKey(name, secretBase32, encKey, options = {}) {
  const db = getDb();
  const { encrypted, iv } = encrypt(secretBase32, encKey);

  db.prepare(`
    INSERT OR REPLACE INTO totp_keys (name, secret_encrypted, iv, issuer, account, period, digits, algorithm)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    encrypted,
    iv,
    options.issuer || '',
    options.account || '',
    options.period || 30,
    options.digits || 6,
    options.algorithm || 'SHA1'
  );

  return { success: true };
}

/**
 * Lit une clé TOTP (retourne la config sans le secret)
 */
function getKey(name) {
  const row = getDb().prepare('SELECT * FROM totp_keys WHERE name = ?').get(name);
  if (!row) return null;
  return {
    name: row.name,
    issuer: row.issuer,
    account: row.account,
    period: row.period,
    digits: row.digits,
    algorithm: row.algorithm
  };
}

/**
 * Génère un code TOTP pour une clé
 */
function getCode(name, encKey) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM totp_keys WHERE name = ?').get(name);
  if (!row) return { success: false, error: 'Clé TOTP introuvable' };

  try {
    const secretBase32 = decrypt(row.secret_encrypted, row.iv, encKey);
    const code = generateCode(secretBase32, row.period, row.digits, row.algorithm);
    return { success: true, code };
  } catch {
    return { success: false, error: 'Erreur déchiffrement TOTP' };
  }
}

/**
 * Supprime une clé TOTP
 */
function deleteKey(name) {
  const result = getDb().prepare('DELETE FROM totp_keys WHERE name = ?').run(name);
  return { success: result.changes > 0 };
}

module.exports = { createKey, getKey, getCode, deleteKey };
