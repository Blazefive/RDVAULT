// ========================================
// SECRETS SERVICE — CRUD engines et secrets (KV v2)
// ========================================

'use strict';

const { getDb } = require('./database');
const { encrypt, decrypt } = require('./crypto');

// ========================================
// ENGINES
// ========================================

/**
 * Liste tous les engines
 * @returns {Array<{ name: string, version: number, description: string, owner: string }>}
 */
function listEngines() {
  return getDb().prepare('SELECT name, version, description, owner FROM engines ORDER BY name').all();
}

/**
 * Crée un engine
 * @param {string} name - Nom (chemin) de l'engine
 * @param {string} owner - Propriétaire (username)
 * @param {string} description
 * @returns {{ success: boolean, error?: string }}
 */
function createEngine(name, owner, description = '') {
  const cleanName = name.replace(/\/+$/, '').replace(/^\/+/, '');
  if (!cleanName) return { success: false, error: 'Nom invalide' };

  const db = getDb();
  const existing = db.prepare('SELECT id FROM engines WHERE name = ?').get(cleanName);
  if (existing) return { success: false, error: 'Ce coffre existe déjà' };

  db.prepare('INSERT INTO engines (name, version, description, owner) VALUES (?, 2, ?, ?)')
    .run(cleanName, description, owner);

  return { success: true };
}

/**
 * Supprime un engine et tous ses secrets
 * @param {string} name
 * @returns {{ success: boolean, error?: string }}
 */
function deleteEngine(name) {
  const cleanName = name.replace(/\/+$/, '').replace(/^\/+/, '');
  const db = getDb();
  const engine = db.prepare('SELECT id FROM engines WHERE name = ?').get(cleanName);
  if (!engine) return { success: false, error: 'Coffre introuvable' };
  // SÉCURITÉ: Nettoyer les clés TOTP orphelines avant suppression (exact match, pas LIKE)
  const secretKeys = db.prepare('SELECT DISTINCT key FROM secrets WHERE engine_id = ?').all(engine.id);
  const totpStmt = db.prepare('DELETE FROM totp_keys WHERE name = ?');
  for (const { key } of secretKeys) {
    // Les clés TOTP sont nommées avec le format ENGINE-SECRETNAME
    totpStmt.run(key);
    totpStmt.run(`${cleanName}-${key}`);
  }
  db.prepare('DELETE FROM engines WHERE id = ?').run(engine.id);
  return { success: true };
}

/**
 * Trouve un engine par nom
 * @param {string} name
 * @returns {{ id: number, name: string, version: number } | null}
 */
function getEngine(name) {
  const cleanName = name.replace(/\/+$/, '').replace(/^\/+/, '');
  return getDb().prepare('SELECT id, name, version FROM engines WHERE name = ?').get(cleanName) || null;
}

// ========================================
// SECRETS — KV v2
// ========================================

/**
 * Liste les clés d'un engine (avec support des sous-dossiers)
 * @param {number} engineId
 * @param {string} prefix - Préfixe du chemin (dossier)
 * @returns {string[]} Liste des clés et dossiers (dossiers terminés par /)
 */
function listKeys(engineId, prefix = '') {
  const db = getDb();

  // Récupérer toutes les clés actives (dernière version non supprimée)
  // Échapper les métacaractères LIKE pour éviter l'injection de patterns
  const escapeLike = (s) => s.replace(/[%_\\]/g, '\\$&');
  const likePattern = prefix ? escapeLike(prefix) + '%' : '%';
  const rows = db.prepare(`
    SELECT DISTINCT s.key FROM secrets s
    WHERE s.engine_id = ? AND s.key LIKE ? ESCAPE '\\' AND s.destroyed = 0
    ORDER BY s.key
  `).all(engineId, likePattern);

  // Transformer en vue "dossier" : si prefix = "Serveur/", retourner les entrées immédiates
  const keys = new Set();
  for (const row of rows) {
    let relative = prefix ? row.key.substring(prefix.length) : row.key;
    if (relative.startsWith('/')) relative = relative.substring(1);
    if (!relative) continue;

    const slashIdx = relative.indexOf('/');
    if (slashIdx === -1) {
      // C'est un secret direct
      keys.add(relative);
    } else {
      // C'est un dossier — retourner le nom du dossier avec /
      keys.add(relative.substring(0, slashIdx + 1));
    }
  }

  return Array.from(keys).sort();
}

/**
 * Écrit un secret (crée une nouvelle version)
 * @param {number} engineId
 * @param {string} key - Chemin du secret
 * @param {object} data - Données du secret
 * @param {Buffer} encKey - Clé AES-256 pré-dérivée
 * @returns {{ success: boolean, version?: number, error?: string }}
 */
function writeSecret(engineId, key, data, encKey) {
  const db = getDb();

  // Chiffrer les données
  const jsonData = JSON.stringify(data);
  const { encrypted, iv } = encrypt(jsonData, encKey);

  // Transaction atomique pour éviter les race conditions sur le numéro de version
  const insertTx = db.transaction(() => {
    const latest = db.prepare(
      'SELECT MAX(version) as maxVer FROM secrets WHERE engine_id = ? AND key = ?'
    ).get(engineId, key);
    const nextVersion = (latest?.maxVer || 0) + 1;

    db.prepare(
      'INSERT INTO secrets (engine_id, key, version, data, iv) VALUES (?, ?, ?, ?, ?)'
    ).run(engineId, key, nextVersion, encrypted, iv);

    return nextVersion;
  });

  const nextVersion = insertTx();
  return { success: true, version: nextVersion };
}

/**
 * Lit un secret (dernière version active ou version spécifique)
 * @param {number} engineId
 * @param {string} key
 * @param {Buffer} encKey - Clé AES-256 pré-dérivée
 * @param {number|null} version - Version spécifique (null = dernière)
 * @returns {{ success: boolean, data?: object, version?: number, metadata?: object, error?: string }}
 */
function readSecret(engineId, key, encKey, version = null) {
  const db = getDb();

  let row;
  if (version) {
    row = db.prepare(
      'SELECT * FROM secrets WHERE engine_id = ? AND key = ? AND version = ?'
    ).get(engineId, key, version);
  } else {
    row = db.prepare(
      'SELECT * FROM secrets WHERE engine_id = ? AND key = ? AND destroyed = 0 ORDER BY version DESC LIMIT 1'
    ).get(engineId, key);
  }

  if (!row) return { success: false, error: 'Secret introuvable' };

  try {
    const jsonData = decrypt(row.data, row.iv, encKey);
    const data = JSON.parse(jsonData);

    return {
      success: true,
      data,
      version: row.version,
      metadata: {
        created_time: row.created_at,
        deletion_time: row.deletion_time || '',
        destroyed: row.destroyed === 1,
        version: row.version
      }
    };
  } catch (err) {
    return { success: false, error: 'Erreur déchiffrement' };
  }
}

/**
 * Récupère les métadonnées d'un secret (toutes les versions)
 * @param {number} engineId
 * @param {string} key
 * @returns {object|null}
 */
function getSecretMetadata(engineId, key) {
  const db = getDb();
  const rows = db.prepare(
    'SELECT version, created_at, deletion_time, destroyed FROM secrets WHERE engine_id = ? AND key = ? ORDER BY version'
  ).all(engineId, key);

  if (rows.length === 0) return null;

  const versions = {};
  for (const row of rows) {
    versions[row.version] = {
      created_time: row.created_at,
      deletion_time: row.deletion_time || '',
      destroyed: row.destroyed === 1
    };
  }

  return {
    key,
    versions,
    current_version: Math.max(...rows.map(r => r.version)),
    oldest_version: Math.min(...rows.map(r => r.version))
  };
}

/**
 * Soft-delete des versions spécifiques
 * @param {number} engineId
 * @param {string} key
 * @param {number[]} versions
 */
function deleteSecretVersions(engineId, key, versions) {
  if (!Array.isArray(versions)) return { success: false };
  const safeVersions = versions.filter(v => Number.isInteger(v) && v > 0);
  const db = getDb();
  const stmt = db.prepare(
    'UPDATE secrets SET deletion_time = datetime(\'now\') WHERE engine_id = ? AND key = ? AND version = ?'
  );
  const tx = db.transaction(() => {
    for (const v of safeVersions) {
      stmt.run(engineId, key, v);
    }
  });
  tx();
  return { success: true };
}

/**
 * Restaure des versions soft-deleted
 * @param {number} engineId
 * @param {string} key
 * @param {number[]} versions
 */
function undeleteSecretVersions(engineId, key, versions) {
  if (!Array.isArray(versions)) return { success: false };
  const safeVersions = versions.filter(v => Number.isInteger(v) && v > 0);
  const db = getDb();
  const stmt = db.prepare(
    'UPDATE secrets SET deletion_time = NULL WHERE engine_id = ? AND key = ? AND version = ?'
  );
  const tx = db.transaction(() => {
    for (const v of safeVersions) {
      stmt.run(engineId, key, v);
    }
  });
  tx();
  return { success: true };
}

/**
 * Supprime définitivement un secret (toutes les versions)
 * @param {number} engineId
 * @param {string} key
 */
function destroySecret(engineId, key) {
  getDb().prepare('DELETE FROM secrets WHERE engine_id = ? AND key = ?').run(engineId, key);
  return { success: true };
}

module.exports = {
  listEngines,
  createEngine,
  deleteEngine,
  getEngine,
  listKeys,
  writeSecret,
  readSecret,
  getSecretMetadata,
  deleteSecretVersions,
  undeleteSecretVersions,
  destroySecret,
};
