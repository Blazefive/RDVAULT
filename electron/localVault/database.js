// ========================================
// DATABASE — Initialisation et gestion SQLite
// ========================================

'use strict';

const Database = require('better-sqlite3');
const path = require('path');
const { app } = require('electron');
const log = require('../logger');

// Version du schéma (PRAGMA user_version) — incrémenter à chaque migration
const SCHEMA_VERSION = 3;

let db = null;

/** Migrations incrémentales : chaque entrée fait passer de (version-1) à version */
const MIGRATIONS = {
  // v1 : schéma initial (tables créées par CREATE IF NOT EXISTS ci-dessous)
  1: () => {},
  // v2 : propriétaire des clés TOTP (contrôle d'accès par utilisateur)
  2: (database) => {
    const cols = database.prepare('PRAGMA table_info(totp_keys)').all().map(c => c.name);
    if (!cols.includes('owner')) database.exec('ALTER TABLE totp_keys ADD COLUMN owner TEXT');
  },
  // v3 : descripteur de KDF par utilisateur (NULL = PBKDF2 hérité ; nouveaux comptes = scrypt).
  // Colonne nullable sans valeur par défaut : les comptes existants restent lisibles tels quels.
  3: (database) => {
    const cols = database.prepare('PRAGMA table_info(users)').all().map(c => c.name);
    if (!cols.includes('kdf')) database.exec('ALTER TABLE users ADD COLUMN kdf TEXT');
  },
};

/**
 * Initialise la base de données SQLite
 * Crée le fichier et les tables si nécessaire, puis applique les migrations
 * @returns {Database} Instance SQLite
 */
function init() {
  if (db) return db;

  const dbPath = path.join(app.getPath('userData'), 'local-vault.db');
  db = new Database(dbPath);
  // Permissions restrictives sur le fichier DB (sans effet sur Windows : ACL du profil utilisateur)
  try { require('fs').chmodSync(dbPath, 0o600); } catch { /* Windows ignore chmod */ }

  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  // SÉCURITÉ: écraser les données supprimées au lieu de les laisser dans les pages libres
  db.pragma('secure_delete = ON');

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
      algorithm TEXT DEFAULT 'SHA1',
      owner TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_secrets_engine_key ON secrets(engine_id, key);
    CREATE INDEX IF NOT EXISTS idx_secrets_engine_key_version ON secrets(engine_id, key, version);
  `);

  // Migrations
  let current = db.pragma('user_version', { simple: true });
  if (current < SCHEMA_VERSION) {
    const migrate = db.transaction(() => {
      for (let v = current + 1; v <= SCHEMA_VERSION; v++) {
        if (MIGRATIONS[v]) MIGRATIONS[v](db);
        db.pragma(`user_version = ${v}`);
      }
    });
    migrate();
    log.info(`[LocalVault] Schéma migré v${current} → v${SCHEMA_VERSION}`);
  }

  log.info('[LocalVault] Base de données initialisée');
  return db;
}

/** Retourne l'instance de base de données (init si nécessaire) */
function getDb() {
  if (!db) init();
  return db;
}

/** Ferme la base de données proprement */
function close() {
  if (db) {
    db.close();
    db = null;
    log.info('[LocalVault] Base de données fermée');
  }
}

/** Vérifie si la base est vide (premier démarrage) */
function isEmpty() {
  const row = getDb().prepare('SELECT COUNT(*) as count FROM users').get();
  return row.count === 0;
}

module.exports = { init, getDb, close, isEmpty, SCHEMA_VERSION };
