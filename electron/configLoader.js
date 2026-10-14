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
 * Accepte "sha256/<base64>" (format Electron/Chrome), l'hex avec ou sans ":", le base64 nu, et (CONFIG-3)
 * la ligne complète de la commande documentée `openssl x509 -noout -fingerprint -sha256` :
 * « sha256 Fingerprint=AB:CD:… » (OpenSSL 3) ou « SHA256 Fingerprint=AB:CD:… » (OpenSSL 1.1).
 */
function normalizeFingerprint(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  s = s.replace(/^(?:sha-?256\s*)?fingerprint\s*=\s*/i, '');
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

// CONFIG-3 : empreinte « sentinelle » qui ne correspond à aucun certificat (aucun SHA-256 réel n'est nul).
// Quand TRUSTED_CERT_FINGERPRINTS est renseigné mais qu'AUCUNE entrée n'est valide, l'épinglage reste
// actif avec cette seule valeur : tout certificat de l'hôte de VAULT_URL est refusé (main.js,
// vaultCertVerifyDecision et 'certificate-error'), au lieu de désactiver l'épinglage en silence.
const PIN_FAIL_CLOSED = '0'.repeat(64);

/**
 * Valeur finale de TRUSTED_CERT_FINGERPRINTS : empreintes valides, ou la sentinelle PIN_FAIL_CLOSED si la
 * clé est renseignée sans aucune entrée valide (épinglage voulu mais inutilisable : on refuse, on ne
 * désactive pas).
 * @param {unknown} value - valeur brute du fichier de configuration
 * @returns {{ fingerprints: string, pinningInvalid: boolean }}
 */
function resolvePinnedFingerprints(value) {
  const valid = sanitizeFingerprints(value);
  const hasEntries = String(value || '').split(',').some(s => s.trim());
  if (valid.length === 0 && hasEntries) {
    log.error('[CONFIG] TRUSTED_CERT_FINGERPRINTS renseigné mais aucune empreinte valide : épinglage maintenu, '
      + 'connexions au serveur Vault REFUSÉES jusqu\'à correction (formats : hex SHA-256, « sha256/<base64> », '
      + 'ou la sortie de « openssl x509 -noout -fingerprint -sha256 »)');
    return { fingerprints: PIN_FAIL_CLOSED, pinningInvalid: true };
  }
  return { fingerprints: valid.join(','), pinningInvalid: false };
}

// ========================================
// CONFIG-8 : PROTECTION DE %PROGRAMDATA%\RDVAULT
// ========================================
// Ce dossier est lu en PRIORITÉ (déploiement machine) ; or l'ACL par défaut de C:\ProgramData laisse tout
// utilisateur y créer un sous-dossier, en devenir propriétaire et y écrire config.cfg (VAULT_URL vers un faux
// serveur : vol des identifiants des autres utilisateurs du poste). L'installeur (assets/installer.nsh) crée
// le dossier et y pose propriétaire + ACL ; en défense en profondeur, un fichier de ce dossier n'est accepté
// que si NI le dossier NI le fichier ne sont modifiables par un non-administrateur.
// Lecture : descripteur de sécurité au format SDDL (PowerShell Get-Acl), indépendant de la langue de
// Windows (icacls affiche des noms traduits — « BUILTIN\Utilisateurs », « VORDEFINIERT\Benutzer »… — et
// jamais le propriétaire, or un propriétaire peut réécrire l'ACL à sa guise).

const SID_ADMINISTRATORS = 'S-1-5-32-544';
const SID_SYSTEM = 'S-1-5-18';
const SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
// Alias SDDL utiles (les autres alias restent tels quels et sont traités comme non administrateurs)
const SDDL_SID_ALIASES = {
  BA: SID_ADMINISTRATORS, SY: SID_SYSTEM, BU: 'S-1-5-32-545', AU: 'S-1-5-11', WD: 'S-1-1-0',
  IU: 'S-1-5-4', BG: 'S-1-5-32-546', PU: 'S-1-5-32-547', AN: 'S-1-5-7', NU: 'S-1-5-2', RD: 'S-1-5-32-555',
  CO: 'S-1-3-0', OW: 'S-1-3-4',
};
// Comptes autorisés à modifier (et à posséder) le dossier et le fichier : Administrateurs, SYSTEM,
// TrustedInstaller, compte Administrateur intégré (-500), Admins du domaine (-512), Administrateurs de
// l'entreprise (-519). CREATOR OWNER / OWNER RIGHTS désignent le propriétaire, lui-même contrôlé.
const ADMIN_SIDS = new Set([SID_ADMINISTRATORS, SID_SYSTEM, SID_TRUSTED_INSTALLER, 'LA', 'DA', 'EA']);
const ADMIN_DOMAIN_SID_RE = /^S-1-5-21-\d+-\d+-\d+-(500|512|519)$/;
const OWNER_PLACEHOLDER_SIDS = new Set(['S-1-3-0', 'S-1-3-4']);
// Droits d'accès SDDL (fichiers et dossiers) → masque
const SDDL_RIGHTS = {
  GA: 0x10000000, GR: 0x80000000, GW: 0x40000000, GX: 0x20000000,
  FA: 0x1F01FF, FR: 0x120089, FW: 0x120116, FX: 0x1200A0,
  KA: 0xF003F, KR: 0x20019, KW: 0x20006, KX: 0x20019,
  RC: 0x20000, SD: 0x10000, WD: 0x40000, WO: 0x80000,
  CC: 0x1, DC: 0x2, LC: 0x4, SW: 0x8, RP: 0x10, WP: 0x20, DT: 0x40, LO: 0x80, CR: 0x100,
};
// Droits qui permettent de remplacer ou de créer la configuration : écriture / ajout de fichier (0x2),
// ajout / création de sous-dossier (0x4), suppression d'enfant (0x40), suppression (DELETE), WRITE_DAC,
// WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE, MAXIMUM_ALLOWED. Attributs et attributs étendus (0x10, 0x100)
// ne suffisent pas.
const DANGEROUS_RIGHTS = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000 | 0x02000000;
const ALLOW_ACE_TYPES = new Set(['A', 'OA', 'XA', 'ZA']);

/** SID complet d'un SID SDDL (alias à deux lettres traduit quand il est connu) */
function sddlSid(raw) {
  const s = String(raw || '').trim().toUpperCase();
  return SDDL_SID_ALIASES[s] || s;
}

function isAdminSid(sid) {
  return ADMIN_SIDS.has(sid) || ADMIN_DOMAIN_SID_RE.test(sid);
}

/** Masque d'accès d'un champ de droits SDDL (« FA », « 0x1200a9 », « DCLCRPCR »…), ou null s'il est inconnu */
function sddlRightsMask(field) {
  const s = String(field || '').trim();
  if (/^0x[0-9a-f]+$/i.test(s)) return Number.parseInt(s.slice(2), 16) >>> 0;
  if (!/^([A-Z]{2})*$/.test(s)) return null;
  let mask = 0;
  for (let i = 0; i < s.length; i += 2) {
    const bits = SDDL_RIGHTS[s.slice(i, i + 2)];
    if (bits === undefined) return null;
    mask = (mask | bits) >>> 0;
  }
  return mask;
}

/**
 * Analyse un descripteur de sécurité SDDL (propriétaire et DACL ; la SACL éventuelle est ignorée).
 * @param {string} sddl
 * @returns {{ owner: string, nullDacl: boolean, aces: Array<{ type: string, flags: string[], mask: number|null, sid: string }> }|null}
 *   null si la chaîne n'est pas un SDDL exploitable
 */
function parseSddl(sddl) {
  const s = String(sddl || '').trim();
  const ownerMatch = /^O:([A-Z]{2}|S-1-[0-9-]+)/i.exec(s);
  if (!ownerMatch) return null;
  const dStart = s.indexOf('D:');
  if (dStart < 0) return null;
  let i = dStart + 2;
  const flagsMatch = /^[A-Z_]*/.exec(s.slice(i));
  const daclFlags = flagsMatch[0];
  i += daclFlags.length;
  const aces = [];
  while (i < s.length && s[i] === '(') {
    // ACE entre parenthèses équilibrées (les ACE conditionnelles contiennent elles-mêmes des parenthèses)
    let depth = 0;
    let j = i;
    for (; j < s.length; j++) {
      if (s[j] === '(') depth++;
      else if (s[j] === ')') { depth--; if (depth === 0) break; }
    }
    if (depth !== 0) return null;
    const inner = s.slice(i + 1, j);
    const fields = [];
    let level = 0;
    let start = 0;
    for (let k = 0; k <= inner.length; k++) {
      const c = inner[k];
      if (c === '(') level++;
      else if (c === ')') level--;
      else if ((c === ';' && level === 0) || k === inner.length) { fields.push(inner.slice(start, k)); start = k + 1; }
    }
    if (fields.length < 6) return null;
    aces.push({
      type: fields[0].toUpperCase(),
      flags: fields[1].toUpperCase().match(/.{1,2}/g) || [],
      mask: sddlRightsMask(fields[2]),
      sid: sddlSid(fields[5]),
    });
    i = j + 1;
  }
  // Après la DACL : rien, ou la SACL (« S: »)
  if (i < s.length && !s.startsWith('S:', i)) return null;
  return { owner: sddlSid(ownerMatch[1]), nullDacl: daclFlags.includes('NO_ACCESS_CONTROL'), aces };
}

/**
 * Verdict « modifiable uniquement par des administrateurs » d'un descripteur SDDL : propriétaire
 * administrateur (Administrateurs, SYSTEM, TrustedInstaller…) et aucune ACE d'autorisation, applicable à
 * l'objet lui-même (hors « IO », héritage seul), qui donne un droit d'écriture à un autre compte
 * (Utilisateurs, Utilisateurs authentifiés, Tout le monde, un utilisateur nommé…). Les ACE de refus ne
 * sont pas prises en compte (vérification plus stricte, jamais plus permissive).
 * @param {string} sddl
 * @returns {{ ok: boolean, reason?: string }}
 */
function adminOnlyAclVerdict(sddl) {
  const parsed = parseSddl(sddl);
  if (!parsed) return { ok: false, reason: 'descripteur de sécurité illisible' };
  if (!isAdminSid(parsed.owner)) return { ok: false, reason: `propriétaire non administrateur (${parsed.owner})` };
  if (parsed.nullDacl) return { ok: false, reason: 'DACL nulle (accès total pour tous)' };
  for (const ace of parsed.aces) {
    if (!ALLOW_ACE_TYPES.has(ace.type) || ace.flags.includes('IO')) continue;
    if (ace.mask === null) return { ok: false, reason: 'droits d\'accès non reconnus' };
    if ((ace.mask & DANGEROUS_RIGHTS) === 0) continue;
    if (isAdminSid(ace.sid) || OWNER_PLACEHOLDER_SIDS.has(ace.sid)) continue;
    return { ok: false, reason: `écriture accordée à un non-administrateur (${ace.sid})` };
  }
  return { ok: true };
}

/**
 * Lit les descripteurs SDDL des chemins (lecture seule : Get-Acl). Chemins passés par variables
 * d'environnement (aucune interprétation par le shell). Lève une erreur si la lecture échoue.
 * @param {string[]} paths
 * @returns {string[]} un SDDL par chemin, dans l'ordre
 */
function readSddlWithPowerShell(paths) {
  const { execFileSync } = require('child_process');
  const systemRoot = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
  const exe = path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const env = { ...process.env };
  const lines = [];
  paths.forEach((p, n) => {
    env[`RDV_ACL_PATH_${n}`] = p;
    lines.push(`(Get-Acl -LiteralPath $env:RDV_ACL_PATH_${n}).Sddl`);
  });
  const out = execFileSync(exe, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    `$ErrorActionPreference='Stop'; ${lines.join('; ')}`], {
    env, encoding: 'utf8', windowsHide: true, timeout: 20000, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const sddls = out.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (sddls.length !== paths.length) throw new Error('sortie Get-Acl inattendue');
  return sddls;
}

/**
 * true si le fichier ET son dossier ne sont modifiables que par des administrateurs, sans lien
 * symbolique ni jonction (voir adminOnlyAclVerdict).
 * @param {string} filePath
 * @param {{ readSddl?: (paths: string[]) => string[], lstat?: (p: string) => fs.Stats }} [deps] - injectables (tests)
 * @returns {{ ok: boolean, reason?: string }}
 */
function checkAdminOnlyConfigFile(filePath, deps = {}) {
  const readSddl = deps.readSddl || readSddlWithPowerShell;
  const lstat = deps.lstat || fs.lstatSync;
  const dir = path.dirname(filePath);
  try {
    for (const p of [dir, filePath]) {
      if (lstat(p).isSymbolicLink()) return { ok: false, reason: `lien symbolique ou jonction (${p})` };
    }
  } catch (err) {
    return { ok: false, reason: `état du fichier illisible (${err.code || err.message})` };
  }
  let sddls;
  try {
    sddls = readSddl([dir, filePath]);
  } catch (err) {
    // Première ligne utile : erreur de Get-Acl (stderr), sinon code (ENOENT : PowerShell absent ou bloqué)
    const detail = String((err && (String(err.stderr || '').trim() || err.code || err.message)) || err);
    return { ok: false, reason: `ACL illisibles (${detail.split(/\r?\n/)[0].slice(0, 160)})` };
  }
  const names = ['dossier', 'fichier'];
  for (let n = 0; n < 2; n++) {
    const verdict = adminOnlyAclVerdict(sddls[n]);
    if (!verdict.ok) return { ok: false, reason: `${names[n]} : ${verdict.reason}` };
  }
  return { ok: true };
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
    // 1. Déploiement machine : accepté seulement si dossier et fichier sont réservés aux administrateurs
    //    (CONFIG-8 : sinon n'importe quel utilisateur du poste pourrait y imposer sa configuration)
    configPaths.push({ path: path.join(programData, 'RDVAULT', 'config.cfg'), type: 'cfg', adminOnly: true });
    configPaths.push({ path: path.join(programData, 'RDVAULT', 'config.json'), type: 'json', adminOnly: true });
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
 * Une entrée `adminOnly` (%PROGRAMDATA%\RDVAULT) n'est lue que si checkAdminOnlyConfigFile l'accepte ;
 * sinon elle est ignorée (avertissement journalisé) au profit du fichier suivant.
 * @param {Array<{ path: string, type: 'cfg'|'json', adminOnly?: boolean }>} configPaths
 * @param {{ checkAdminOnly?: (filePath: string) => { ok: boolean, reason?: string } }} [options] - injectable (tests)
 * @returns {object}
 */
function loadConfigFromPaths(configPaths, options = {}) {
  const checkAdminOnly = options.checkAdminOnly || checkAdminOnlyConfigFile;
  for (const configEntry of configPaths) {
    try {
      if (!fs.existsSync(configEntry.path)) continue;
      if (configEntry.adminOnly) {
        const verdict = checkAdminOnly(configEntry.path);
        if (!verdict || !verdict.ok) {
          // SÉCURITÉ (CONFIG-8) : jamais lu ; seule la raison (SID, pas de valeur de configuration) est tracée
          log.warn(`[CONFIG] ${configEntry.path} IGNORÉ : modifiable par des non-administrateurs `
            + `(${(verdict && verdict.reason) || 'vérification impossible'}). Réservez le dossier aux administrateurs `
            + '(réinstallation de RDVAULT, ou icacls "<dossier>" /setowner *S-1-5-32-544 puis /inheritance:r '
            + '/grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX)');
          continue;
        }
      }
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

      // SÉCURITÉ (CONFIG-3) : épinglage renseigné mais inutilisable → refus (sentinelle), jamais désactivé
      const pins = resolvePinnedFingerprints(config.TRUSTED_CERT_FINGERPRINTS);

      const result = {
        VAULT_URL: appMode === 'local' ? 'http://127.0.0.1:0' : validVaultUrl,
        LDAP_AUTH_PATH: safeLdapPath,
        TRUSTED_DOMAINS: trustedDomains,
        TRUSTED_CERT_FINGERPRINTS: pins.fingerprints,
        RBI_PROXY_URL: safeRbiUrl,
        APP_MODE: appMode,
        LANG: lang
      };
      if (pins.pinningInvalid) result.PINNING_INVALID = true;

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
  resolvePinnedFingerprints,
  PIN_FAIL_CLOSED,
  parseSddl,
  adminOnlyAclVerdict,
  checkAdminOnlyConfigFile,
  readSddlWithPowerShell,
  DEFAULT_CONFIG
};
