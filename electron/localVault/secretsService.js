// ========================================
// SECRETS SERVICE — CRUD engines et secrets (KV v2)
// ========================================

'use strict';

const { getDb } = require('./database');
const { encrypt, decryptDetailed } = require('./crypto');

/** Contexte authentifié (AAD) d'une version de secret : un blob déplacé ne se déchiffre plus */
const aadFor = (engineId, key, version) => `${engineId}:${key}:${version}`;

/** AAD d'une graine TOTP : format figé, IDENTIQUE à totpService (aadFor) */
const totpAadFor = (name) => `totp:${name}`;

/**
 * Secret témoin caché (nom réservé, comme le stockage des passkeys : masqué par l'interface, exclu de
 * l'export, refusé à l'import). Écrit à la création d'un compte dont le mot de passe dépasse 72 octets :
 * il permet de vérifier la clé dès le premier login, avant toute autre donnée (LOCALVAULT-1).
 */
const KEYCHECK_SECRET_KEY = '.rdvault-keycheck';

/** Blob interne des passkeys (clés privées incluses), IDENTIQUE à src/utils/passkeyEngine.js (PASSKEY_SECRET_KEY) */
const PASSKEYS_SECRET_KEY = '.rdvault-passkeys';

/**
 * Blobs internes cachés, par nom EXACT à la racine du coffre (COMPAT-2, même liste que INTERNAL_SECRET_KEYS
 * de src/utils/passkeyEngine.js). Pour eux SEULS, l'écriture ne conserve que la dernière version (PURGE-35) :
 * le blob des passkeys contient toutes les clés privées et est réécrit à chaque signature ; garder l'historique
 * laisserait lisible (GET ?version=N) la clé privée d'une passkey supprimée et ferait grossir la base à chaque
 * signature. Toutes les autres entrées gardent leur historique, y compris une entrée utilisateur dont le nom
 * commence par « .rdvault » (« .rdvault-notes », permise en 1.5.0 et affichée par l'interface) ou le contient.
 */
const HIDDEN_BLOB_KEYS = Object.freeze([PASSKEYS_SECRET_KEY, KEYCHECK_SECRET_KEY]);
const isHiddenBlobKey = (key) => typeof key === 'string' && HIDDEN_BLOB_KEYS.includes(key);

// Horodatage SQLite datetime('now') : UTC sans indicateur de fuseau (« YYYY-MM-DD HH:MM:SS[.SSS] »)
const SQLITE_UTC_DATETIME = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/;

/**
 * Convertit un horodatage stocké (UTC au format SQLite, sans fuseau) en ISO 8601 UTC « …Z », comme Vault
 * (RFC 3339). Sans fuseau, un client (new Date) le lirait en heure LOCALE, donc décalé (LOCALVAULT-4).
 * Seules les réponses sont converties : la base garde son format. Toute autre valeur est renvoyée telle quelle.
 * @param {string|null|undefined} value
 * @returns {string|null|undefined}
 */
function toIsoUtc(value) {
  if (typeof value !== 'string') return value;
  const m = SQLITE_UTC_DATETIME.exec(value);
  return m ? `${m[1]}T${m[2]}Z` : value;
}

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
 * Indique si une chaîne contient un caractère de contrôle (C0 U+0000-U+001F, DEL U+007F,
 * C1 U+0080-U+009F). Boucle explicite plutôt qu'une regex (règle ESLint no-control-regex).
 * @param {string} s
 * @returns {boolean}
 */
function hasControlChars(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x1F || (c >= 0x7F && c <= 0x9F)) return true;
  }
  return false;
}

/**
 * Crée un engine
 * @param {string} name - Nom (chemin) de l'engine
 * @param {string} owner - Propriétaire (username)
 * @param {string} description
 * @returns {{ success: boolean, error?: string }}
 */
function createEngine(name, owner, description = '') {
  if (typeof name !== 'string') return { success: false, error: 'Nom invalide' };
  const cleanName = name.replace(/\/+$/, '').replace(/^\/+/, '');
  // SÉCURITÉ: refuser un nom vide (après trim) ou contenant des caractères de contrôle
  // (retour à la ligne, NUL, DEL, C1…) : ils fausseraient l'affichage, les journaux et les
  // règles CLI. L'appelant HTTP (localVaultServer) répond 400 sur { success: false }.
  if (!cleanName || !cleanName.trim() || hasControlChars(cleanName)) {
    return { success: false, error: 'Nom invalide' };
  }

  const db = getDb();
  const existing = db.prepare('SELECT id FROM engines WHERE name = ?').get(cleanName);
  if (existing) return { success: false, error: 'Ce coffre existe déjà' };

  db.prepare('INSERT INTO engines (name, version, description, owner) VALUES (?, 2, ?, ?)')
    .run(cleanName, description, owner);

  return { success: true };
}

/**
 * Préfixe des noms de clés TOTP d'un coffre, IDENTIQUE à l'interface (src/hooks/useTotp.js,
 * totpKeyPrefix) et à l'extension : nom du coffre sans « users/<u>/ » ni « / » final, en majuscules.
 * Une clé TOTP s'appelle `${préfixe}-${clé de l'entrée}`. Convention historique conservée telle
 * quelle (clés existantes, policies Vault « TOTP/keys/PRÉFIXE-* »), donc non injective :
 * « Banque » et « users/x/Banque » partagent le même préfixe, et le tiret est ambigu
 * (« Prod » + « EU-db » et « Prod-EU » + « db » donnent tous deux PROD-EU-db).
 * @param {string} engineName
 * @returns {string}
 */
function totpKeyPrefix(engineName) {
  return String(engineName).replace(/^users\/[^/]+\//i, '').replace(/\/$/, '').toUpperCase();
}

/**
 * Supprime un engine et tous ses secrets
 * @param {string} name
 * @returns {{ success: boolean, error?: string }}
 */
function deleteEngine(name) {
  const cleanName = name.replace(/\/+$/, '').replace(/^\/+/, '');
  const db = getDb();
  const engine = db.prepare('SELECT id, owner FROM engines WHERE name = ?').get(cleanName);
  if (!engine) return { success: false, error: 'Coffre introuvable' };

  // SÉCURITÉ: nettoyer les clés TOTP des entrées du coffre (correspondance exacte, pas LIKE), nommées
  // comme dans l'interface. Une clé n'est supprimée que si elle appartient sans ambiguïté à ce coffre :
  // - jamais une clé dont le nom égale seulement le nom d'une entrée (TOTP d'un autre coffre) ;
  // - pas si une entrée d'un AUTRE coffre revendique exactement ce nom de clé (LOCALVAULT-2). Le nommage
  //   `${PRÉFIXE}-${entrée}` est ambigu : « Prod » + « EU-db » et « Prod-EU » + « db » donnent tous deux
  //   PROD-EU-db, comme « Banque » et « users/x/Banque » (même préfixe) avec une entrée du même nom ;
  // - seulement si elle appartient au propriétaire du coffre (ou n'a pas de propriétaire).
  const prefix = totpKeyPrefix(cleanName);
  const otherEngines = db.prepare('SELECT id, name FROM engines WHERE id != ?').all(engine.id)
    .map(e => ({ id: e.id, keyPrefix: totpKeyPrefix(e.name) + '-' }));
  const hasEntryStmt = db.prepare('SELECT 1 FROM secrets WHERE engine_id = ? AND key = ? LIMIT 1');
  /** Vrai si une entrée (toute version, même supprimée mais restaurable) d'un autre coffre porte ce nom de clé TOTP */
  const claimedElsewhere = (totpName) => otherEngines.some(o =>
    totpName.startsWith(o.keyPrefix) && !!hasEntryStmt.get(o.id, totpName.slice(o.keyPrefix.length)));
  const totpStmt = engine.owner
    ? db.prepare('DELETE FROM totp_keys WHERE name = ? AND (owner IS NULL OR owner = ?)')
    : db.prepare('DELETE FROM totp_keys WHERE name = ?');
  const secretKeys = db.prepare('SELECT DISTINCT key FROM secrets WHERE engine_id = ?').all(engine.id);

  const tx = db.transaction(() => {
    for (const { key } of secretKeys) {
      const totpName = `${prefix}-${key}`;
      if (claimedElsewhere(totpName)) continue; // clé revendiquée par un autre coffre : conservée
      if (engine.owner) totpStmt.run(totpName, engine.owner);
      else totpStmt.run(totpName);
    }
    db.prepare('DELETE FROM engines WHERE id = ?').run(engine.id);
  });
  tx();
  // Effacement physique : les secrets du coffre (supprimés en cascade) et ses graines TOTP ne doivent pas
  // survivre dans le journal WAL (voir checkpointWal)
  checkpointWal(db);
  return { success: true };
}

/**
 * Trouve un engine par nom
 * @param {string} name
 * @returns {{ id: number, name: string, version: number } | null}
 */
function getEngine(name) {
  const cleanName = name.replace(/\/+$/, '').replace(/^\/+/, '');
  return getDb().prepare('SELECT id, name, version, owner FROM engines WHERE name = ?').get(cleanName) || null;
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

  // Listage d'un DOSSIER (sémantique Vault) : le dispatcher retire le « / » final de l'URL, on le
  // rétablit pour ne pas renvoyer les frères qui partagent le début du nom (« prod-old/ », « prod2 »).
  const folder = prefix ? String(prefix).replace(/\/+$/, '') + '/' : '';

  // Récupérer toutes les clés actives (dernière version non supprimée)
  // Échapper les métacaractères LIKE pour éviter l'injection de patterns. LIKE n'est qu'un
  // pré-filtre (insensible à la casse ASCII) : la comparaison exacte est faite ci-dessous.
  const escapeLike = (s) => s.replace(/[%_\\]/g, '\\$&');
  const likePattern = folder ? escapeLike(folder) + '%' : '%';
  const rows = db.prepare(`
    SELECT DISTINCT s.key FROM secrets s
    WHERE s.engine_id = ? AND s.key LIKE ? ESCAPE '\\' AND s.destroyed = 0
    ORDER BY s.key
  `).all(engineId, likePattern);

  // Transformer en vue "dossier" : si prefix = "Serveur/", retourner les entrées immédiates
  const keys = new Set();
  for (const row of rows) {
    // Préfixe exact, sensible à la casse (« PROD/api » n'appartient pas à « prod/ »)
    if (folder && !row.key.startsWith(folder)) continue;
    let relative = folder ? row.key.substring(folder.length) : row.key;
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
 * Recopie le journal WAL dans la base puis le vide (best effort). Appelé après tout effacement définitif
 * (anciennes versions d'un blob caché, destruction d'un secret, suppression d'un coffre ou d'une clé TOTP) :
 * secure_delete a remis à zéro les octets effacés dans les pages modifiées, mais le fichier WAL garde les
 * images précédentes de ces pages (anciens chiffrés) jusqu'à ce qu'elles soient écrasées, et le fichier de
 * base garde l'ancienne page tant qu'aucun point de contrôle ne l'a remplacée.
 * Un échec (base occupée) est sans conséquence sur les données : le point de contrôle automatique suivra.
 * @param {import('better-sqlite3').Database} [db]
 */
function checkpointWal(db = getDb()) {
  try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch { /* best effort */ }
}

/** Message de Vault (KV v2) quand la version courante ne correspond pas au paramètre check-and-set */
const CAS_MISMATCH = 'check-and-set parameter did not match the current version';

/**
 * Écrit un secret (crée une nouvelle version). Blob interne caché (« .rdvault-passkeys », « .rdvault-keycheck ») :
 * les versions précédentes sont effacées dans la même transaction (PURGE-35, voir HIDDEN_BLOB_KEYS).
 * @param {number} engineId
 * @param {string} key - Chemin du secret
 * @param {object} data - Données du secret
 * @param {Buffer} encKey - Clé AES-256 pré-dérivée
 * @param {{ cas?: number|null }} [options] - cas : check-and-set comme Vault KV v2 ; l'écriture n'a lieu que si
 *   la version courante (plus grand numéro, versions supprimées ou détruites comprises) vaut cas, 0 désignant
 *   un secret sans aucune version. Vérifié dans la même transaction que l'écriture (aucune fenêtre de course).
 * @returns {{ success: boolean, version?: number, error?: string, casMismatch?: boolean }}
 */
function writeSecret(engineId, key, data, encKey, options = {}) {
  const db = getDb();
  const jsonData = JSON.stringify(data);
  const purgeHistory = isHiddenBlobKey(key);
  const cas = options && Number.isSafeInteger(options.cas) && options.cas >= 0 ? options.cas : null;

  // Transaction atomique pour éviter les race conditions sur le numéro de version
  const insertTx = db.transaction(() => {
    const latest = db.prepare(
      'SELECT MAX(version) as maxVer FROM secrets WHERE engine_id = ? AND key = ?'
    ).get(engineId, key);
    const currentVersion = latest?.maxVer || 0;
    if (cas !== null && cas !== currentVersion) return { casMismatch: true };
    const nextVersion = currentVersion + 1;

    // Chiffrer avec le contexte (engine, clé, version) comme données authentifiées
    const { encrypted, iv } = encrypt(jsonData, encKey, aadFor(engineId, key, nextVersion));

    db.prepare(
      'INSERT INTO secrets (engine_id, key, version, data, iv) VALUES (?, ?, ?, ?, ?)'
    ).run(engineId, key, nextVersion, encrypted, iv);

    // Blob caché : seule la version qui vient d'être écrite est conservée (numérotation inchangée,
    // la suivante sera nextVersion + 1). Avec secure_delete, les octets effacés sont remis à zéro.
    const purged = purgeHistory
      ? db.prepare('DELETE FROM secrets WHERE engine_id = ? AND key = ? AND version < ?').run(engineId, key, nextVersion).changes
      : 0;

    return { nextVersion, purged };
  });

  const { nextVersion, purged, casMismatch } = insertTx();
  if (casMismatch) return { success: false, casMismatch: true, error: CAS_MISMATCH };
  if (purged > 0) checkpointWal(db);
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

  // Compatibilité Vault KV v2 : la lecture d'une version supprimée (soft-delete) échoue en 404 ;
  // les données ne sont pas renvoyées tant que la version n'est pas restaurée (undelete).
  if (row.deletion_time) {
    return {
      success: false,
      deleted: true,
      error: 'Secret supprimé',
      metadata: { created_time: toIsoUtc(row.created_at), deletion_time: toIsoUtc(row.deletion_time), destroyed: row.destroyed === 1, version: row.version }
    };
  }

  try {
    const { plaintext: jsonData, legacy } = decryptDetailed(row.data, row.iv, encKey, aadFor(engineId, key, row.version));
    if (legacy) {
      // Migration transparente des données écrites sans AAD : re-chiffrer en place
      const re = encrypt(jsonData, encKey, aadFor(engineId, key, row.version));
      db.prepare('UPDATE secrets SET data = ?, iv = ? WHERE id = ?').run(re.encrypted, re.iv, row.id);
    }
    const data = JSON.parse(jsonData);

    return {
      success: true,
      data,
      version: row.version,
      metadata: {
        created_time: toIsoUtc(row.created_at),
        deletion_time: toIsoUtc(row.deletion_time) || '',
        destroyed: row.destroyed === 1,
        version: row.version
      }
    };
  } catch (err) {
    // La ligne EXISTE mais son intégrité (GCM/AAD) n'est pas vérifiée : mauvaise clé, blob déplacé ou altéré.
    // Signalé à part (integrityError) pour ne pas être confondu avec un secret absent (LOCALVAULT-3).
    return { success: false, integrityError: true, error: 'Erreur déchiffrement' };
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
      created_time: toIsoUtc(row.created_at),
      deletion_time: toIsoUtc(row.deletion_time) || '',
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
 * Supprime définitivement un secret (toutes les versions). Les chiffrés effacés ne survivent pas dans le
 * journal WAL : point de contrôle TRUNCATE dès qu'une ligne a été supprimée (voir checkpointWal).
 * @param {number} engineId
 * @param {string} key
 */
function destroySecret(engineId, key) {
  const db = getDb();
  const { changes } = db.prepare('DELETE FROM secrets WHERE engine_id = ? AND key = ?').run(engineId, key);
  if (changes > 0) checkpointWal(db);
  return { success: true };
}

// ========================================
// VÉRIFICATION DE LA CLÉ D'UN COMPTE (LOCALVAULT-1)
// ========================================

/**
 * Vrai si `encKey` déchiffre au moins une donnée chiffrée du compte, ou si le compte n'en a aucune.
 * Appelé au login quand bcrypt a ignoré une partie du mot de passe (au-delà de 72 octets UTF-8) : la clé
 * AES est dérivée du mot de passe ENTIER, une faute de frappe après le 72e octet donnerait une autre clé.
 * Candidats : les versions de secrets des coffres du compte (ou sans propriétaire), témoin « .rdvault-keycheck »
 * en premier, puis les graines TOTP du compte. Lecture seule (aucune migration AAD ici). Une seule ligne
 * déchiffrée suffit : un compte dont des données existent déjà sous deux clés (défaut antérieur au correctif)
 * ne perd l'accès à aucune d'elles. Seuls les identifiants sont triés (pas les blobs) ; arrêt au premier succès.
 * @param {string} username - Nom du compte (tel que stocké)
 * @param {Buffer} encKey - Clé dérivée du mot de passe saisi
 * @returns {boolean}
 */
function keyMatchesAccountData(username, encKey) {
  const db = getDb();
  const opens = (data, iv, aad) => {
    try { decryptDetailed(data, iv, encKey, aad); return true; } catch { return false; }
  };
  let candidates = 0;

  const secretIds = db.prepare(`
    SELECT s.id FROM secrets s JOIN engines e ON e.id = s.engine_id
    WHERE e.owner = ? COLLATE NOCASE OR e.owner IS NULL
    ORDER BY (s.key = ?) DESC, s.id ASC
  `).pluck().all(username, KEYCHECK_SECRET_KEY);
  const secretRow = db.prepare('SELECT engine_id, key, version, data, iv FROM secrets WHERE id = ?');
  for (const id of secretIds) {
    const row = secretRow.get(id);
    if (!row) continue;
    candidates++;
    if (opens(row.data, row.iv, aadFor(row.engine_id, row.key, row.version))) return true;
  }

  const totpRows = db.prepare('SELECT name, secret_encrypted, iv FROM totp_keys WHERE owner = ? COLLATE NOCASE').all(username);
  for (const row of totpRows) {
    candidates++;
    if (opens(row.secret_encrypted, row.iv, totpAadFor(row.name))) return true;
  }

  // Aucune donnée chiffrée : rien à comparer, le compte reste utilisable
  return candidates === 0;
}

/**
 * Écrit le témoin de clé caché dans un coffre (création d'un compte au mot de passe de plus de 72 octets).
 * Contenu sans valeur secrète : seule compte la possibilité de le déchiffrer avec la bonne clé.
 * @param {string} engineName
 * @param {Buffer} encKey
 * @returns {boolean} vrai si le témoin a été écrit
 */
function writeKeyCheck(engineName, encKey) {
  const engine = getEngine(engineName);
  if (!engine) return false;
  writeSecret(engine.id, KEYCHECK_SECRET_KEY, { purpose: 'rdvault-key-check' }, encKey);
  return true;
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
  keyMatchesAccountData,
  writeKeyCheck,
  toIsoUtc,
  checkpointWal,
  KEYCHECK_SECRET_KEY,
  CAS_MISMATCH,
};
