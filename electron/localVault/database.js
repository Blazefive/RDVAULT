// ========================================
// DATABASE — Initialisation et gestion SQLite
// ========================================

'use strict';

const Database = require('better-sqlite3');
const path = require('path');
const { app } = require('electron');

let db = null;

/**
 * Initialise la base de données SQLite
 * Crée le fichier et les tables si nécessaire
 * @returns {Database} Instance SQLite
 */
function init() {
  if (db) return db;

  const dbPath = path.join(app.getPath('userData'), 'local-vault.db');
  db = new Database(dbPath);
  // Permissions restrictives sur le fichier DB
  try { require('fs').chmodSync(dbPath, 0o600); } catch { /* Windows ignore chmod */ }

  // Optimisations SQLite
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Créer les tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      encryption_salt TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      is_admin INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS engines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      version INTEGER DEFAULT 2,
      description TEXT DEFAULT '',
      owner TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      engine_id INTEGER NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      data TEXT NOT NULL,
      iv TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      deletion_time TEXT,
      destroyed INTEGER DEFAULT 0,
      UNIQUE(engine_id, key, version)
    );

    CREATE TABLE IF NOT EXISTS totp_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      secret_encrypted TEXT NOT NULL,
      iv TEXT NOT NULL,
      issuer TEXT DEFAULT '',
      account TEXT DEFAULT '',
      period INTEGER DEFAULT 30,
      digits INTEGER DEFAULT 6,
      algorithm TEXT DEFAULT 'SHA1'
    );

    CREATE INDEX IF NOT EXISTS idx_secrets_engine_key ON secrets(engine_id, key);
    CREATE INDEX IF NOT EXISTS idx_secrets_engine_key_version ON secrets(engine_id, key, version);
  `);

  console.log('[LocalVault] Base de données initialisée:', dbPath);
  return db;
}

/**
 * Retourne l'instance de base de données (init si nécessaire)
 */
function getDb() {
  if (!db) init();
  return db;
}

/**
 * Ferme la base de données proprement
 */
function close() {
  if (db) {
    db.close();
    db = null;
    console.log('[LocalVault] Base de données fermée');
  }
}

/**
 * Vérifie si la base est vide (premier démarrage)
 * @returns {boolean}
 */
function isEmpty() {
  const row = getDb().prepare('SELECT COUNT(*) as count FROM users').get();
  return row.count === 0;
}

module.exports = { init, getDb, close, isEmpty };
