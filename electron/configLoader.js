// ========================================
// CONFIG LOADER - Chargement de la configuration
// ========================================
// Ce module gère le chargement de la configuration de l'application.
// La configuration peut provenir de (ordre de priorité, mode packagé) :
// 1. %PROGRAMDATA%\RDVAULT\config.cfg / config.json  (déploiement machine, ACL admin)
// 2. config.cfg / config.json dans le dossier d'installation
// 3. config.cfg / config.json dans le dossier userData
// 4. config.default.json embarqué dans l'application (fallback)
//
// Formats supportés :
// - .cfg : Format clé=valeur avec commentaires # (voir config.example.cfg)
// - .json : Format JSON standard
//
// Paramètres configurables :
// - VAULT_URL                 : URL https du serveur HashiCorp Vault
// - LDAP_AUTH_PATH            : Chemin d'authentification LDAP (ex: auth/ldap)
// - TRUSTED_DOMAINS           : Domaines/IP pour lesquels un certificat auto-signé est toléré
// - TRUSTED_CERT_FINGERPRINTS : Empreintes SHA-256 des certificats acceptés (pinning, recommandé)
// - RBI_PROXY_URL             : URL https du proxy RBI (partage de sessions)
// - APP_MODE                  : enterprise | local
// - LANG                      : langue par défaut
//
// SÉCURITÉ: chaque valeur est validée ; une valeur invalide est remplacée par le défaut
// et journalisée, pour qu'un fichier de configuration altéré ne puisse pas rediriger
// l'application vers un faux serveur ou élargir la confiance TLS.

const fs = require('fs');
const path = require('path');
const { app } = require('electron');
const log = require('./logger');

const KNOWN_KEYS = ['VAULT_URL', 'LDAP_AUTH_PATH', 'TRUSTED_DOMAINS', 'TRUSTED_CERT_FINGERPRINTS', 'RBI_PROXY_URL', 'APP_MODE', 'LANG'];
const SUPPORTED_LANGS = ['en', 'fr', 'es', 'de', 'ru', 'zh', 'pt', 'it', 'ja', 'ko', 'ar', 'tr'];

// Configuration par défaut (utilisée si aucun fichier trouvé)
// SÉCURITÉ: Les valeurs par défaut ne contiennent pas d'IPs/hostnames internes
const DEFAULT_CONFIG = {
  VAULT_URL: 'https://vault.example.com:8200',
  LDAP_AUTH_PATH: 'auth/ldap',
  TRUSTED_DOMAINS: 'localhost,127.0.0.1',
  TRUSTED_CERT_FINGERPRINTS: '',
  RBI_PROXY_URL: '',
  APP_MODE: 'enterprise',  // 'enterprise' (Vault distant) ou 'local' (base locale)
  LANG: 'en'
};

// Cache de la configuration chargée
let loadedConfig = null;

/** Copie d'un tampon UTF-16 BE convertie en UTF-16 LE (octets de chaque paire inversés ; octet impair final ignoré) */
function utf16beToLe(buf) {
  const even = Buffer.from(buf.subarray(0, buf.length - (buf.length % 2)));
  return even.swap16();
}

/**
 * UTF-16 SANS BOM : un fichier de configuration est essentiellement de l'ASCII (clés, URL), donc un octet
 * nul sur deux. Examine le début du fichier : nuls aux positions impaires seulement → LE, paires seulement → BE.
 * @param {Buffer} buf
 * @returns {'utf16le'|'utf16be'|null}
 */
function guessBomlessUtf16(buf) {
  const n = Math.min(buf.length - (buf.length % 2), 512);
  if (n < 4) return null;
  let evenNul = 0;
  let oddNul = 0;
  for (let i = 0; i < n; i++) {
    if (buf[i] === 0) { if (i % 2 === 0) evenNul++; else oddNul++; }
  }
  const pairs = n / 2;
  if (oddNul >= pairs * 0.6 && evenNul === 0) return 'utf16le';
  if (evenNul >= pairs * 0.6 && oddNul === 0) return 'utf16be';
  return null;
}

/**
 * STARTUP-25 : décode un fichier de configuration selon son encodage réel. Le Bloc-notes (« Unicode ») et
 * PowerShell 5 (Out-File, redirection >) écrivent en UTF-16 ; d'autres éditeurs ajoutent un BOM UTF-8.
 * Lus comme de l'UTF-8 brut, un config.cfg UTF-16 ne donnait AUCUNE clé (l'application démarrait en silence
 * avec les valeurs par défaut, mode entreprise) et un config.json avec BOM était rejeté (JSON invalide).
 * Reconnaît : BOM UTF-8, BOM UTF-16 LE ou BE, UTF-16 LE ou BE sans BOM ; sinon UTF-8.
 * @param {Buffer} buf - contenu brut du fichier
 * @returns {{ text: string, encoding: 'utf8'|'utf8-bom'|'utf16le'|'utf16be', bom: boolean }}
 */
function decodeConfigBuffer(buf) {
  let decoded;
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    decoded = { text: buf.subarray(3).toString('utf8'), encoding: 'utf8-bom', bom: true };
  } else if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) {
    decoded = { text: buf.subarray(2).toString('utf16le'), encoding: 'utf16le', bom: true };
  } else if (buf.length >= 2 && buf[0] === 0xFE && buf[1] === 0xFF) {
    decoded = { text: utf16beToLe(buf.subarray(2)).toString('utf16le'), encoding: 'utf16be', bom: true };
  } else {
    const utf16 = guessBomlessUtf16(buf);
    if (utf16 === 'utf16le') decoded = { text: buf.toString('utf16le'), encoding: 'utf16le', bom: false };
    else if (utf16 === 'utf16be') decoded = { text: utf16beToLe(buf).toString('utf16le'), encoding: 'utf16be', bom: false };
    else decoded = { text: buf.toString('utf8'), encoding: 'utf8', bom: false };
  }
  // BOM résiduel (fichier enregistré deux fois avec BOM, par ex.) : jamais une partie de la première clé
  decoded.text = decoded.text.replace(/^﻿+/, '');
  return decoded;
}

/**
 * Lit et analyse un fichier de configuration (.cfg ou .json), quel que soit son encodage (decodeConfigBuffer).
 * Avertissements clairs (sans aucune valeur de configuration) : fichier UTF-16 (lu, UTF-8 recommandé) et
 * fichier .cfg non vide dont aucune clé n'est reconnue (format ou encodage inattendu : valeurs par défaut).
 * @param {string} filePath
 * @param {'cfg'|'json'} type
 * @returns {object} configuration brute (JSON.parse lève une erreur sur un JSON invalide)
 */
function readConfigFile(filePath, type) {
  const { text, encoding, bom } = decodeConfigBuffer(fs.readFileSync(filePath));
  if (encoding === 'utf16le' || encoding === 'utf16be') {
    log.warn(`[CONFIG] ${filePath} : encodage ${encoding === 'utf16le' ? 'UTF-16 LE' : 'UTF-16 BE'}${bom ? '' : ' sans BOM'} détecté et converti (UTF-8 recommandé)`);
  } else if (encoding === 'utf8-bom') {
    log.info(`[CONFIG] ${filePath} : BOM UTF-8 ignoré`);
  }
  if (type !== 'cfg') return JSON.parse(text);
  const config = parseCfgFile(text);
  if (Object.keys(config).length === 0 && /\S/.test(text.replace(/^\s*#.*$/gm, ''))) {
    log.warn(`[CONFIG] ${filePath} : aucune clé reconnue (format CLÉ=valeur en UTF-8 attendu), valeurs par défaut appliquées`);
  }
  return config;
}

/**
 * Parse un fichier de configuration au format .cfg
 * Format: clé=valeur, lignes commençant par # sont des commentaires
 */
function parseCfgFile(content) {
  const config = {};
  for (const line of content.split('\n')) {
    const trimmedLine = line.trim();
    if (!trimmedLine || trimmedLine.startsWith('#')) continue;
    const equalIndex = trimmedLine.indexOf('=');
    if (equalIndex > 0) {
      const key = trimmedLine.substring(0, equalIndex).trim();
      const value = trimmedLine.substring(equalIndex + 1).trim();
      if (KNOWN_KEYS.includes(key)) config[key] = value;
    }
  }
  return config;
}

// ========================================
// VALIDATEURS
// ========================================

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RE = /^\[?[0-9a-f:]+\]?$/i;

/** Ne conserve que les entrées qui sont des noms d'hôte ou des IP valides */
function sanitizeTrustedDomains(value) {
  const entries = String(value || '').split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
  const valid = [];
  for (const entry of entries) {
    if (entry.length <= 253 && (HOSTNAME_RE.test(entry) || IPV4_RE.test(entry) || IPV6_RE.test(entry))) {
      valid.push(entry);
    } else {
      log.warn('[CONFIG] Entrée TRUSTED_DOMAINS invalide ignorée');
    }
  }
  return valid.join(',');
}

/**
 * Normalise une empreinte de certificat en hex minuscule (64 caractères).
 * Accepte "sha256/<base64>" (format Electron/Chrome), l'hex avec ou sans ":", ou le base64 nu.
 */
function normalizeFingerprint(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (/^sha256\//i.test(s)) s = s.slice(7);
  const hexCandidate = s.replace(/[:\s]/g, '').toLowerCase();
  if (/^[0-9a-f]{64}$/.test(hexCandidate)) return hexCandidate;
  try {
    const buf = Buffer.from(s, 'base64');
    if (buf.length === 32) return buf.toString('hex');
  } catch { /* ignore */ }
  return null;
}

/** Liste d'empreintes normalisées (hex minuscule) ; les entrées invalides sont ignorées et journalisées une fois (nombre seulement) */
function sanitizeFingerprints(value) {
  const raw = String(value || '').split(',').map(s => s.trim()).filter(Boolean);
  const list = raw.map(normalizeFingerprint);
  const invalidCount = list.filter(v => v === null).length;
  if (invalidCount > 0) {
    // SÉCURITÉ: ne pas journaliser les valeurs de configuration (seul le nombre d'entrées rejetées est tracé)
    log.warn(`[CONFIG] ${invalidCount} empreinte(s) TRUSTED_CERT_FINGERPRINTS invalide(s) ignorée(s)`);
  }
  return list.filter(Boolean);
}

/**
 * REMOTE-7 : forme de base d'une URL de service, prête pour la concaténation `${url}/v1/…`
 * (ou `${url}/create-share` pour le proxy RBI). Une barre finale produisait « //v1/… » : Vault
 * répond alors 307 vers une URL relative au protocole (« //v1/auth/… ») que le navigateur suit,
 * mot de passe compris, vers l'hôte « v1 ». Règles :
 * - origine canonique (hôte en minuscules, port par défaut retiré) + chemin sans barre finale ;
 * - un préfixe de chemin (proxy inverse) est conservé ;
 * - VAULT_URL : le suffixe d'API « /v1 » collé par erreur est retiré (l'application l'ajoute) ;
 * - paramètres (?…) et fragment (#…) retirés : ils casseraient la concaténation.
 * Les valeurs ne sont jamais journalisées (seule la nature de la correction l'est).
 */
function normalizeServiceUrl(parsed, label) {
  if (parsed.search || parsed.hash) {
    log.warn(`[CONFIG] ${label} : paramètres ou fragment d'URL ignorés`);
  }
  let pathname = parsed.pathname.replace(/\/+$/, '');
  if (label === 'VAULT_URL' && /\/v1$/i.test(pathname)) {
    pathname = pathname.slice(0, -3).replace(/\/+$/, '');
    log.warn(`[CONFIG] ${label} : suffixe d'API /v1 retiré (ajouté par l'application)`);
  }
  return parsed.origin + pathname;
}

/** URL https sans identifiants, normalisée (voir normalizeServiceUrl), ou null */
function sanitizeHttpsUrl(value, label) {
  if (!value) return null;
  try {
    const parsed = new URL(String(value).trim());
    if (parsed.protocol === 'https:' && parsed.hostname && !parsed.username && !parsed.password) {
      return normalizeServiceUrl(parsed, label);
    }
    log.warn(`[CONFIG] ${label} rejetée (https:// obligatoire, sans identifiants dans l'URL)`);
  } catch {
    log.warn(`[CONFIG] ${label} invalide`);
  }
  return null;
}

/**
 * Charge la configuration depuis les fichiers disponibles (voir ordre de priorité en tête de fichier)
 */
function loadConfig() {
  if (loadedConfig !== null) return loadedConfig;

  const configPaths = [];
  if (app.isPackaged) {
    const programData = process.env.PROGRAMDATA || 'C:\\ProgramData';
    // 1. Déploiement machine (dossier protégé par ACL administrateur)
    configPaths.push({ path: path.join(programData, 'RDVAULT', 'config.cfg'), type: 'cfg' });
    configPaths.push({ path: path.join(programData, 'RDVAULT', 'config.json'), type: 'json' });
    // 2. Dossier d'installation
    configPaths.push({ path: path.join(path.dirname(process.execPath), 'config.cfg'), type: 'cfg' });
    configPaths.push({ path: path.join(path.dirname(process.execPath), 'config.json'), type: 'json' });
    // 3. userData
    configPaths.push({ path: path.join(app.getPath('userData'), 'config.cfg'), type: 'cfg' });
    configPaths.push({ path: path.join(app.getPath('userData'), 'config.json'), type: 'json' });
    // 4. Défaut embarqué
    configPaths.push({ path: path.join(process.resourcesPath, 'config.default.json'), type: 'json' });
  } else {
    configPaths.push({ path: path.join(__dirname, '..', 'config.cfg'), type: 'cfg' });
    configPaths.push({ path: path.join(__dirname, '..', 'config.json'), type: 'json' });
    configPaths.push({ path: path.join(__dirname, '..', 'config.default.json'), type: 'json' });
  }

  loadedConfig = loadConfigFromPaths(configPaths);
  return loadedConfig;
}

/**
 * Charge la configuration depuis le premier fichier lisible de la liste (ordre de priorité), valeurs validées ;
 * à défaut, la configuration par défaut. Sans cache ni dépendance à Electron (testable sous Node).
 * @param {Array<{ path: string, type: 'cfg'|'json' }>} configPaths
 * @returns {object}
 */
function loadConfigFromPaths(configPaths) {
  for (const configEntry of configPaths) {
    try {
      if (!fs.existsSync(configEntry.path)) continue;
      // STARTUP-25 : encodage détecté (UTF-8 avec ou sans BOM, UTF-16 LE/BE), voir readConfigFile
      const config = readConfigFile(configEntry.path, configEntry.type);
      if (!config || typeof config !== 'object') continue;

      // APP_MODE : 'local' ou 'enterprise' (défaut)
      const appMode = (config.APP_MODE === 'local') ? 'local' : 'enterprise';

      // SÉCURITÉ: VAULT_URL doit être une URL https:// sans identifiants
      const validVaultUrl = sanitizeHttpsUrl(config.VAULT_URL, 'VAULT_URL') || DEFAULT_CONFIG.VAULT_URL;

      // SÉCURITÉ: LDAP_AUTH_PATH (prévention path traversal)
      let safeLdapPath = String(config.LDAP_AUTH_PATH || DEFAULT_CONFIG.LDAP_AUTH_PATH).replace(/^\/+|\/+$/g, '');
      if (!/^[a-zA-Z0-9\-_/]+$/.test(safeLdapPath) || safeLdapPath.includes('..')) {
        log.warn('[CONFIG] LDAP_AUTH_PATH invalide, utilisation du défaut');
        safeLdapPath = DEFAULT_CONFIG.LDAP_AUTH_PATH;
      }

      // SÉCURITÉ: RBI_PROXY_URL — https obligatoire (le proxy transporte des identifiants)
      const safeRbiUrl = sanitizeHttpsUrl(config.RBI_PROXY_URL, 'RBI_PROXY_URL') || '';

      // SÉCURITÉ: TRUSTED_DOMAINS validé entrée par entrée
      const trustedDomains = config.TRUSTED_DOMAINS !== undefined
        ? sanitizeTrustedDomains(config.TRUSTED_DOMAINS)
        : DEFAULT_CONFIG.TRUSTED_DOMAINS;

      // LANG : liste blanche
      const lang = SUPPORTED_LANGS.includes(String(config.LANG || '').toLowerCase())
        ? String(config.LANG).toLowerCase()
        : DEFAULT_CONFIG.LANG;

      const result = {
        VAULT_URL: appMode === 'local' ? 'http://127.0.0.1:0' : validVaultUrl,
        LDAP_AUTH_PATH: safeLdapPath,
        TRUSTED_DOMAINS: trustedDomains,
        TRUSTED_CERT_FINGERPRINTS: sanitizeFingerprints(config.TRUSTED_CERT_FINGERPRINTS).join(','),
        RBI_PROXY_URL: safeRbiUrl,
        APP_MODE: appMode,
        LANG: lang
      };

      // SÉCURITÉ: Ne pas logger les valeurs de configuration (IPs/domaines internes)
      log.info(`[CONFIG] Configuration chargée depuis: ${configEntry.path} (format: ${configEntry.type})`);
      return result;
    } catch (err) {
      log.warn(`[CONFIG] Erreur lecture ${configEntry.path}:`, err.message);
    }
  }

  log.info('[CONFIG] Aucun fichier de configuration trouvé, utilisation des valeurs par défaut');
  return { ...DEFAULT_CONFIG };
}

/** Liste des domaines de confiance */
function getTrustedDomains() {
  return loadConfig().TRUSTED_DOMAINS.split(',').map(d => d.trim()).filter(d => d.length > 0);
}

/** Empreintes SHA-256 (hex minuscule) des certificats épinglés */
function getTrustedCertFingerprints() {
  return loadConfig().TRUSTED_CERT_FINGERPRINTS.split(',').map(f => f.trim()).filter(f => f.length > 0);
}

function getVaultUrl() { return loadConfig().VAULT_URL; }
function getLdapAuthPath() { return loadConfig().LDAP_AUTH_PATH; }
function getRbiProxyUrl() { return loadConfig().RBI_PROXY_URL; }
function getAppMode() { return loadConfig().APP_MODE || 'enterprise'; }
function getConfig() { return loadConfig(); }

/** Recharge la configuration depuis le disque (utile pour les tests) */
function reloadConfig() {
  loadedConfig = null;
  return loadConfig();
}

module.exports = {
  loadConfig,
  getConfig,
  getTrustedDomains,
  getTrustedCertFingerprints,
  getVaultUrl,
  getLdapAuthPath,
  getRbiProxyUrl,
  getAppMode,
  reloadConfig,
  parseCfgFile,
  decodeConfigBuffer,
  readConfigFile,
  loadConfigFromPaths,
  normalizeFingerprint,
  sanitizeTrustedDomains,
  sanitizeHttpsUrl,
  sanitizeFingerprints,
  DEFAULT_CONFIG
};
