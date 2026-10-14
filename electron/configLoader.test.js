// Tests des validateurs de configuration (electron/configLoader.js) — node --test, sans Electron.
// Hors Electron, require('electron') renvoie le chemin du binaire : `app` vaut undefined,
// ce qui n'affecte pas les validateurs testés ici (loadConfig n'est pas appelé).
const { test, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const log = require('./logger');
const {
  sanitizeFingerprints, normalizeFingerprint, sanitizeHttpsUrl, sanitizeTrustedDomains, parseCfgFile,
  decodeConfigBuffer, readConfigFile, loadConfigFromPaths, resolvePinnedFingerprints, PIN_FAIL_CLOSED,
  parseSddl, adminOnlyAclVerdict, checkAdminOnlyConfigFile, readSddlWithPowerShell,
} = require('./configLoader');

// Capture des avertissements : configLoader appelle log.warn via l'objet module partagé
// (log.info aussi capturé : pas de bruit dans la sortie des tests)
const warnings = [];
const infos = [];
const originalWarn = log.warn;
const originalInfo = log.info;
log.warn = (...args) => { warnings.push(args.map(String).join(' ')); };
log.info = (...args) => { infos.push(args.map(String).join(' ')); };
// Dossier jetable des fichiers de configuration de test (STARTUP-25), supprimé à la fin
const cfgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-cfgenc-'));
after(() => {
  log.warn = originalWarn;
  log.info = originalInfo;
  fs.rmSync(cfgDir, { recursive: true, force: true });
});
beforeEach(() => { warnings.length = 0; infos.length = 0; });

const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);

// ── sanitizeFingerprints ──

test('sanitizeFingerprints : valeur vide / absente → [] sans avertissement', () => {
  assert.deepEqual(sanitizeFingerprints(''), []);
  assert.deepEqual(sanitizeFingerprints(undefined), []);
  assert.deepEqual(sanitizeFingerprints(null), []);
  assert.deepEqual(sanitizeFingerprints(' , ,'), [], 'virgules et espaces seuls → []');
  assert.equal(warnings.length, 0, 'aucun warn pour une liste vide (BUG-4)');
});

test('sanitizeFingerprints : formats valides normalisés en hex minuscule', () => {
  const digest = nodeCrypto.randomBytes(32);
  const hex = digest.toString('hex');
  const hexColons = hex.toUpperCase().match(/.{2}/g).join(':');
  const value = [HEX_A, ` ${hexColons} `, 'sha256/' + digest.toString('base64'), digest.toString('base64')].join(',');
  assert.deepEqual(sanitizeFingerprints(value), [HEX_A, hex, hex, hex]);
  assert.equal(warnings.length, 0);
});

test('sanitizeFingerprints : entrée invalide → un seul warn avec le nombre seulement, entrée filtrée', () => {
  const result = sanitizeFingerprints(`${HEX_A}, pas-une-empreinte ,${HEX_B},zz`);
  assert.deepEqual(result, [HEX_A, HEX_B]);
  assert.equal(warnings.length, 1, 'un seul avertissement pour toute la liste');
  assert.match(warnings[0], /TRUSTED_CERT_FINGERPRINTS/);
  assert.match(warnings[0], /\b2 empreinte\(s\)/, 'le nombre d\'entrées rejetées est tracé');
  // SÉCURITÉ: les valeurs de configuration (valides ou non) ne sont jamais journalisées
  assert.doesNotMatch(warnings[0], /pas-une-empreinte/, 'les entrées invalides ne sont pas listées');
  assert.doesNotMatch(warnings[0], /\bzz\b/, 'les entrées invalides ne sont pas listées');
  assert.doesNotMatch(warnings[0], new RegExp(HEX_A), 'les entrées valides ne sont pas listées');
});

test('normalizeFingerprint : rejets', () => {
  assert.equal(normalizeFingerprint(''), null);
  assert.equal(normalizeFingerprint('a'.repeat(63)), null, 'hex trop court');
  assert.equal(normalizeFingerprint('sha1/' + 'a'.repeat(40)), null);
  assert.equal(normalizeFingerprint(nodeCrypto.randomBytes(20).toString('base64')), null, 'base64 de 20 octets (SHA-1)');
});

// ── sanitizeHttpsUrl ──

test('sanitizeHttpsUrl : https sans identifiants accepté tel quel', () => {
  assert.equal(sanitizeHttpsUrl('https://vault.example.com:8200', 'VAULT_URL'), 'https://vault.example.com:8200');
  assert.equal(sanitizeHttpsUrl('https://rbi-proxy.example.com:3001', 'RBI_PROXY_URL'), 'https://rbi-proxy.example.com:3001');
  assert.equal(warnings.length, 0);
});

// REMOTE-7 : l'application concatène `${VAULT_URL}/v1/…` (et `${RBI_PROXY_URL}/create-share`). Une barre
// finale donnait « https://vault:8200//v1/auth/… » : Vault répond 307 vers « //v1/auth/… », que le
// navigateur suit (mot de passe compris) vers l'hôte « v1 ». La valeur est donc normalisée.
test('sanitizeHttpsUrl : barre(s) finale(s) retirée(s) (REMOTE-7)', () => {
  assert.equal(sanitizeHttpsUrl('https://vault.example.com:8200/', 'VAULT_URL'), 'https://vault.example.com:8200');
  assert.equal(sanitizeHttpsUrl('https://vault.example.com:8200///', 'VAULT_URL'), 'https://vault.example.com:8200');
  assert.equal(sanitizeHttpsUrl('https://rbi-proxy.example.com:3001/', 'RBI_PROXY_URL'), 'https://rbi-proxy.example.com:3001');
  assert.equal(sanitizeHttpsUrl('https://Vault.Example.com:443/', 'VAULT_URL'), 'https://vault.example.com', 'forme canonique (hôte en minuscules, port par défaut retiré)');
  assert.equal(warnings.length, 0, 'une barre finale est une saisie courante : pas d\'avertissement');
});

test('sanitizeHttpsUrl : suffixe d\'API « /v1 » collé par erreur → ramené à l\'origine, avec avertissement', () => {
  assert.equal(sanitizeHttpsUrl('https://10.0.0.1/v1/', 'VAULT_URL'), 'https://10.0.0.1');
  assert.equal(sanitizeHttpsUrl('https://10.0.0.1:8200/v1', 'VAULT_URL'), 'https://10.0.0.1:8200');
  assert.equal(warnings.length, 2);
  assert.match(warnings[0], /VAULT_URL/);
  assert.doesNotMatch(warnings[0], /10\.0\.0\.1/, 'la valeur n\'est jamais journalisée');
});

test('sanitizeHttpsUrl : préfixe de chemin d\'un proxy inverse conservé (sans barre finale)', () => {
  assert.equal(sanitizeHttpsUrl('https://passerelle.example.com/vault/', 'VAULT_URL'), 'https://passerelle.example.com/vault');
  assert.equal(sanitizeHttpsUrl('https://passerelle.example.com/rbi', 'RBI_PROXY_URL'), 'https://passerelle.example.com/rbi');
  assert.equal(warnings.length, 0);
});

test('sanitizeHttpsUrl : paramètres et fragment retirés (ils casseraient la concaténation), avec avertissement', () => {
  assert.equal(sanitizeHttpsUrl('https://vault.example.com:8200/?x=1', 'VAULT_URL'), 'https://vault.example.com:8200');
  assert.equal(sanitizeHttpsUrl('https://vault.example.com:8200#ui', 'VAULT_URL'), 'https://vault.example.com:8200');
  assert.equal(warnings.length, 2);
  assert.doesNotMatch(warnings.join(' '), /vault\.example\.com|x=1/, 'la valeur n\'est jamais journalisée');
});

test('sanitizeHttpsUrl : chaque valeur normalisée produit des URL Vault bien formées', () => {
  for (const raw of ['https://vault:8200', 'https://vault:8200/', 'https://vault:8200/v1/', 'https://vault:8200/?a=b']) {
    const base = sanitizeHttpsUrl(raw, 'VAULT_URL');
    const loginUrl = new URL(`${base}/v1/auth/ldap/login/alice`);
    assert.equal(loginUrl.host, 'vault:8200', raw);
    assert.equal(loginUrl.pathname, '/v1/auth/ldap/login/alice', raw);
  }
});

test('sanitizeHttpsUrl : vide → null sans avertissement', () => {
  assert.equal(sanitizeHttpsUrl('', 'VAULT_URL'), null);
  assert.equal(sanitizeHttpsUrl(undefined, 'VAULT_URL'), null);
  assert.equal(warnings.length, 0);
});

test('sanitizeHttpsUrl : http, identifiants ou URL invalide → null + warn', () => {
  assert.equal(sanitizeHttpsUrl('http://vault.example.com', 'VAULT_URL'), null);
  assert.equal(sanitizeHttpsUrl('https://user:pass@vault.example.com', 'VAULT_URL'), null);
  assert.equal(sanitizeHttpsUrl('ftp://vault.example.com', 'RBI_PROXY_URL'), null);
  assert.equal(sanitizeHttpsUrl('pas une url', 'RBI_PROXY_URL'), null);
  assert.equal(warnings.length, 4);
  assert.match(warnings[0], /VAULT_URL/);
  assert.match(warnings[3], /RBI_PROXY_URL/);
});

// ── sanitizeTrustedDomains ──

test('sanitizeTrustedDomains : hôtes et IP valides conservés (minuscules, espaces retirés)', () => {
  assert.equal(sanitizeTrustedDomains(' Localhost , 127.0.0.1,Vault.Example.COM, [::1] ,fe80::1'), 'localhost,127.0.0.1,vault.example.com,[::1],fe80::1');
  assert.equal(warnings.length, 0);
});

test('sanitizeTrustedDomains : vide → chaîne vide', () => {
  assert.equal(sanitizeTrustedDomains(''), '');
  assert.equal(sanitizeTrustedDomains(undefined), '');
  assert.equal(warnings.length, 0);
});

test('sanitizeTrustedDomains : entrées invalides ignorées avec avertissement', () => {
  const tooLong = 'b'.repeat(254); // > 253 caractères
  assert.equal(sanitizeTrustedDomains(`ok.example.com,*.example.com,-bad.example,https://x.example,a,${tooLong}`), 'ok.example.com,a');
  assert.equal(warnings.length, 4, 'un warn par entrée rejetée');
  assert.match(warnings[0], /TRUSTED_DOMAINS/);
});

// ── parseCfgFile ──

test('parseCfgFile : clé=valeur, commentaires, clés inconnues ignorées', () => {
  const content = [
    '# commentaire',
    '',
    'VAULT_URL = https://vault.example.com:8200 ',
    'TRUSTED_CERT_FINGERPRINTS=' + HEX_A + ',' + HEX_B,
    'INCONNUE=valeur',
    'LDAP_AUTH_PATH=auth/ldap=special',
    'ligne sans égal',
  ].join('\n');
  assert.deepEqual(parseCfgFile(content), {
    VAULT_URL: 'https://vault.example.com:8200',
    TRUSTED_CERT_FINGERPRINTS: HEX_A + ',' + HEX_B,
    LDAP_AUTH_PATH: 'auth/ldap=special',
  });
});

// ── STARTUP-25 : encodage des fichiers de configuration ──
// Le Bloc-notes (« Unicode ») et PowerShell 5 (Out-File, >) écrivent en UTF-16 ; d'autres éditeurs ajoutent un
// BOM UTF-8. Avant correction : config.cfg UTF-16 → aucune clé reconnue, démarrage silencieux en mode
// entreprise ; config.json avec BOM → « JSON invalide », fichier ignoré au profit du suivant.

const CFG_TEXT = '# Configuration RDVAULT — déploiement été\r\nAPP_MODE=local\r\nLANG=fr\r\nTRUSTED_DOMAINS=vault.interne.example\r\n';
const JSON_TEXT = JSON.stringify({ APP_MODE: 'local', LANG: 'de' });
const BOM_UTF8 = Buffer.from([0xEF, 0xBB, 0xBF]);
const BOM_LE = Buffer.from([0xFF, 0xFE]);
const BOM_BE = Buffer.from([0xFE, 0xFF]);
const utf16le = (s) => Buffer.from(s, 'utf16le');
const utf16be = (s) => Buffer.from(s, 'utf16le').swap16();
const DEFAULT_JSON = { path: path.join(__dirname, '..', 'config.default.json'), type: 'json' };
let fileSeq = 0;
/** Écrit un fichier de configuration de test et renvoie son entrée { path, type } */
function cfgFile(name, buf) {
  const p = path.join(cfgDir, `${fileSeq++}-${name}`);
  fs.writeFileSync(p, buf);
  return { path: p, type: name.endsWith('.json') ? 'json' : 'cfg' };
}

test('decodeConfigBuffer : UTF-8 sans BOM inchangé (accents compris)', () => {
  assert.deepEqual(decodeConfigBuffer(Buffer.from(CFG_TEXT, 'utf8')), { text: CFG_TEXT, encoding: 'utf8', bom: false });
  assert.deepEqual(decodeConfigBuffer(Buffer.alloc(0)), { text: '', encoding: 'utf8', bom: false });
});

test('decodeConfigBuffer : BOM UTF-8, UTF-16 LE et UTF-16 BE avec BOM', () => {
  assert.deepEqual(decodeConfigBuffer(Buffer.concat([BOM_UTF8, Buffer.from(CFG_TEXT)])), { text: CFG_TEXT, encoding: 'utf8-bom', bom: true });
  assert.deepEqual(decodeConfigBuffer(Buffer.concat([BOM_LE, utf16le(CFG_TEXT)])), { text: CFG_TEXT, encoding: 'utf16le', bom: true });
  assert.deepEqual(decodeConfigBuffer(Buffer.concat([BOM_BE, utf16be(CFG_TEXT)])), { text: CFG_TEXT, encoding: 'utf16be', bom: true });
});

test('decodeConfigBuffer : UTF-16 LE et BE SANS BOM reconnus (octets nuls alternés)', () => {
  assert.deepEqual(decodeConfigBuffer(utf16le(CFG_TEXT)), { text: CFG_TEXT, encoding: 'utf16le', bom: false });
  assert.deepEqual(decodeConfigBuffer(utf16be(CFG_TEXT)), { text: CFG_TEXT, encoding: 'utf16be', bom: false });
  // Un texte UTF-8 ordinaire (ou presque vide) n'est jamais pris pour de l'UTF-16
  assert.equal(decodeConfigBuffer(Buffer.from('LANG=fr\n')).encoding, 'utf8');
  assert.equal(decodeConfigBuffer(Buffer.from('ab')).encoding, 'utf8');
});

test('decodeConfigBuffer : UTF-16 BE de longueur impaire (octet final tronqué ignoré) et BOM doublé', () => {
  const odd = Buffer.concat([BOM_BE, utf16be('LANG=fr\n'), Buffer.from([0x00])]);
  assert.equal(decodeConfigBuffer(odd).text, 'LANG=fr\n');
  const doubled = Buffer.concat([BOM_LE, utf16le('\uFEFFLANG=fr\n')]);
  assert.equal(decodeConfigBuffer(doubled).text, 'LANG=fr\n', 'second BOM retiré : la première clé reste reconnue');
});

for (const [label, buf] of [
  ['UTF-16 LE avec BOM (Bloc-notes « Unicode », PowerShell 5)', Buffer.concat([BOM_LE, utf16le(CFG_TEXT)])],
  ['UTF-16 BE avec BOM', Buffer.concat([BOM_BE, utf16be(CFG_TEXT)])],
  ['UTF-16 LE sans BOM', utf16le(CFG_TEXT)],
]) {
  test(`loadConfigFromPaths : config.cfg ${label} → lu (mode local, langue), avertissement clair sans valeur`, () => {
    const cfg = loadConfigFromPaths([cfgFile('config.cfg', buf), DEFAULT_JSON]);
    assert.equal(cfg.APP_MODE, 'local', 'mode local lu (avant : mode entreprise par défaut, en silence)');
    assert.equal(cfg.LANG, 'fr');
    assert.equal(cfg.TRUSTED_DOMAINS, 'vault.interne.example');
    assert.equal(warnings.length, 1, warnings.join(' | '));
    assert.match(warnings[0], /UTF-16 (LE|BE).*converti.*UTF-8 recommandé/);
    assert.doesNotMatch(warnings.join(' '), /vault\.interne|local|LANG/, 'aucune valeur de configuration journalisée');
  });
}

test('loadConfigFromPaths : config.cfg avec BOM UTF-8 → lu sans avertissement', () => {
  const cfg = loadConfigFromPaths([cfgFile('config.cfg', Buffer.concat([BOM_UTF8, Buffer.from(CFG_TEXT)])), DEFAULT_JSON]);
  assert.equal(cfg.APP_MODE, 'local');
  assert.equal(cfg.LANG, 'fr');
  assert.equal(warnings.length, 0);
});

test('loadConfigFromPaths : config.json avec BOM UTF-8 → lu (avant : JSON invalide, fichier suivant utilisé)', () => {
  const cfg = loadConfigFromPaths([cfgFile('config.json', Buffer.concat([BOM_UTF8, Buffer.from(JSON_TEXT)])), DEFAULT_JSON]);
  assert.equal(cfg.APP_MODE, 'local');
  assert.equal(cfg.LANG, 'de');
  assert.equal(warnings.length, 0, warnings.join(' | '));
});

test('loadConfigFromPaths : config.json UTF-16 LE avec BOM → lu, avertissement', () => {
  const cfg = loadConfigFromPaths([cfgFile('config.json', Buffer.concat([BOM_LE, utf16le(JSON_TEXT)])), DEFAULT_JSON]);
  assert.equal(cfg.APP_MODE, 'local');
  assert.equal(cfg.LANG, 'de');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /UTF-16 LE/);
});

test('loadConfigFromPaths : config.cfg UTF-8 ordinaire inchangé, premier fichier présent prioritaire', () => {
  const first = cfgFile('config.cfg', Buffer.from('APP_MODE=local\nLANG=fr\n'));
  const second = cfgFile('config.cfg', Buffer.from('APP_MODE=enterprise\nLANG=en\n'));
  const cfg = loadConfigFromPaths([{ path: path.join(cfgDir, 'absent.cfg'), type: 'cfg' }, first, second]);
  assert.deepEqual([cfg.APP_MODE, cfg.LANG, cfg.VAULT_URL], ['local', 'fr', 'http://127.0.0.1:0']);
  assert.equal(warnings.length, 0);
});

test('readConfigFile : .cfg non vide sans aucune clé reconnue (encodage inattendu, ex. UTF-32) → avertissement clair', () => {
  // UTF-32 LE : non pris en charge, mais signalé au lieu d'un démarrage silencieux avec les valeurs par défaut
  const utf32 = Buffer.alloc(CFG_TEXT.length * 4);
  for (let i = 0; i < CFG_TEXT.length; i++) utf32.writeUInt32LE(CFG_TEXT.charCodeAt(i), i * 4);
  const entry = cfgFile('config.cfg', Buffer.concat([Buffer.from([0xFF, 0xFE, 0x00, 0x00]), utf32]));
  assert.deepEqual(readConfigFile(entry.path, 'cfg'), {});
  assert.ok(warnings.some(w => /aucune clé reconnue/.test(w)), warnings.join(' | '));
  assert.doesNotMatch(warnings.join(' '), /vault\.interne/, 'aucune valeur journalisée');
});

test('readConfigFile : .cfg vide ou fait de commentaires → aucun avertissement', () => {
  assert.deepEqual(readConfigFile(cfgFile('config.cfg', Buffer.from('')).path, 'cfg'), {});
  assert.deepEqual(readConfigFile(cfgFile('config.cfg', Buffer.from('# rien\r\n\r\n   # toujours rien\n')).path, 'cfg'), {});
  assert.equal(warnings.length, 0, warnings.join(' | '));
});

// ── CONFIG-3 : empreinte copiée depuis la commande openssl documentée ──
// `openssl x509 -in vault.crt -noout -fingerprint -sha256` affiche « sha256 Fingerprint=AB:… » (OpenSSL 3)
// ou « SHA256 Fingerprint=AB:… » (OpenSSL 1.1). Avant : entrée rejetée, TRUSTED_CERT_FINGERPRINTS vide,
// épinglage DÉSACTIVÉ en silence (boîtier d'inspection TLS / CA d'entreprise acceptés sur VAULT_URL).

const OPENSSL_DIGEST = nodeCrypto.createHash('sha256').update('certificat de test').digest('hex');
const OPENSSL_COLONS = OPENSSL_DIGEST.toUpperCase().match(/.{2}/g).join(':');

test('normalizeFingerprint : sortie openssl 3 et 1.1 (« sha256 Fingerprint= », « SHA256 Fingerprint= ») acceptée', () => {
  assert.equal(normalizeFingerprint(`sha256 Fingerprint=${OPENSSL_COLONS}`), OPENSSL_DIGEST);
  assert.equal(normalizeFingerprint(`SHA256 Fingerprint=${OPENSSL_COLONS}`), OPENSSL_DIGEST);
  assert.equal(normalizeFingerprint(`  SHA256 Fingerprint = ${OPENSSL_COLONS} `), OPENSSL_DIGEST);
  assert.equal(normalizeFingerprint(`SHA-256 Fingerprint=${OPENSSL_COLONS}`), OPENSSL_DIGEST);
  // Une empreinte SHA-1 reste refusée, préfixe ou non
  assert.equal(normalizeFingerprint(`SHA1 Fingerprint=${'AB:'.repeat(19)}AB`), null);
});

test('loadConfigFromPaths : TRUSTED_CERT_FINGERPRINTS = ligne openssl → épinglage actif sur cette empreinte', () => {
  const entry = cfgFile('config.cfg', Buffer.from(`VAULT_URL=https://vault.corp.example:8200\r\nTRUSTED_CERT_FINGERPRINTS=sha256 Fingerprint=${OPENSSL_COLONS}\r\n`));
  const cfg = loadConfigFromPaths([entry, DEFAULT_JSON]);
  assert.equal(cfg.TRUSTED_CERT_FINGERPRINTS, OPENSSL_DIGEST);
  assert.equal(cfg.PINNING_INVALID, undefined);
  assert.equal(warnings.length, 0, warnings.join(' | '));
});

test('loadConfigFromPaths : TRUSTED_CERT_FINGERPRINTS renseigné sans aucune entrée valide → refus (sentinelle), jamais désactivé', () => {
  const errors = [];
  const originalError = log.error;
  log.error = (...args) => { errors.push(args.map(String).join(' ')); };
  try {
    const entry = cfgFile('config.cfg', Buffer.from('VAULT_URL=https://vault.corp.example:8200\nTRUSTED_CERT_FINGERPRINTS=empreinte-mal-copiee,zz\n'));
    const cfg = loadConfigFromPaths([entry, DEFAULT_JSON]);
    assert.equal(cfg.TRUSTED_CERT_FINGERPRINTS, PIN_FAIL_CLOSED, 'épinglage maintenu (avant : chaîne vide = épinglage désactivé)');
    assert.equal(cfg.PINNING_INVALID, true);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /REFUSÉES/);
    assert.doesNotMatch(errors.join(' ') + warnings.join(' '), /empreinte-mal-copiee|vault\.corp/, 'aucune valeur journalisée');
    // La sentinelle ne correspond à aucun certificat réel (main.js refuse alors l'hôte de VAULT_URL)
    const { fingerprintMatches } = require('./certPinning');
    assert.equal(fingerprintMatches({ data: nodeCrypto.randomBytes(64).toString('base64') }, cfg.TRUSTED_CERT_FINGERPRINTS.split(',')), false);
  } finally {
    log.error = originalError;
  }
});

test('resolvePinnedFingerprints : vide → pas d\'épinglage ; une entrée valide parmi d\'autres → épinglage sur la valide', () => {
  assert.deepEqual(resolvePinnedFingerprints(''), { fingerprints: '', pinningInvalid: false });
  assert.deepEqual(resolvePinnedFingerprints(' , '), { fingerprints: '', pinningInvalid: false });
  assert.deepEqual(resolvePinnedFingerprints(`${HEX_A},faute`), { fingerprints: HEX_A, pinningInvalid: false });
});

// ── CONFIG-8 : %PROGRAMDATA%\RDVAULT modifiable par un utilisateur standard ──
// Descripteurs SDDL tels que les renvoie (Get-Acl).Sddl : identiques quelle que soit la langue de Windows
// (icacls afficherait « BUILTIN\Utilisateurs » en français, « BUILTIN\Users » en anglais, « VORDEFINIERT\Benutzer »
// en allemand… et jamais le propriétaire).
const USER_SID = 'S-1-5-21-2121457121-1760029516-3411856435-1001';
const SDDL = {
  // C:\ProgramData (relevé sur un poste) : Utilisateurs peuvent créer fichiers et dossiers (DC, LC)
  programData: 'O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)',
  // Dossier créé par l'installeur : propriétaire Administrateurs, héritage coupé, Utilisateurs en lecture
  protectedDir: 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)',
  protectedFile: 'O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)',
  fileBySystem: 'O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)',
  // Dossier créé par « mkdir C:\ProgramData\RDVAULT » d'un utilisateur standard (ACL héritée de ProgramData)
  userCreatedDir: `O:${USER_SID}G:${USER_SID}D:AI(A;OICIIOID;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)`,
  // Dossier créé par un administrateur SANS l'ACL de l'installeur : hérite « Utilisateurs : ajout de fichier »
  adminDirInherited: 'O:BAG:SYD:AI(A;OICIIOID;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)',
  // Fichier de l'attaquant : propriétaire utilisateur, ACL « maquillée » en administrateurs seuls
  attackerOwnedFile: `O:${USER_SID}G:${USER_SID}D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)`,
  everyoneModify: 'O:BAG:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;WD)',
  authUsersWrite: 'O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FRFW;;;AU)',
  namedUserFull: `O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;${USER_SID})`,
  usersGenericWrite: 'O:BAG:SYD:PAI(A;;FA;;;BA)(A;;GW;;;S-1-5-32-545)',
  usersWriteDac: 'O:BAG:SYD:PAI(A;;FA;;;BA)(A;;RCWD;;;BU)',
  nullDacl: 'O:BAG:SYD:NO_ACCESS_CONTROL',
  // ACE d'héritage seul (IO) et ACE de refus : sans effet sur l'objet lui-même
  inheritOnlyUsersWrite: 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICIIO;GW;;;BU)(D;;FA;;;WD)',
  // Domaine : Admins du domaine et TrustedInstaller sont des administrateurs
  domainAdmins: 'O:S-1-5-21-1-2-3-512G:SYD:PAI(A;;FA;;;S-1-5-21-1-2-3-512)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;DA)',
  // ACE conditionnelle (parenthèses imbriquées) puis SACL
  conditional: 'O:BAG:SYD:PAI(A;;FA;;;BA)(XA;;FR;;;AU;(@User.dept == "it"))S:AI(AU;SA;FA;;;WD)',
};

test('adminOnlyAclVerdict : dossier et fichier posés par l\'installeur (ou SYSTEM, ou domaine) acceptés', () => {
  for (const name of ['protectedDir', 'protectedFile', 'fileBySystem', 'inheritOnlyUsersWrite', 'domainAdmins', 'conditional']) {
    assert.deepEqual(adminOnlyAclVerdict(SDDL[name]), { ok: true }, name);
  }
});

test('adminOnlyAclVerdict : écriture possible par un non-administrateur, ou propriétaire non administrateur → refus', () => {
  const cases = {
    programData: /S-1-5-32-545/,
    userCreatedDir: /propriétaire non administrateur \(S-1-5-21-.*-1001\)/,
    adminDirInherited: /écriture accordée à un non-administrateur \(S-1-5-32-545\)/,
    attackerOwnedFile: /propriétaire non administrateur/,
    everyoneModify: /S-1-1-0/,
    authUsersWrite: /S-1-5-11/,
    namedUserFull: /S-1-5-21-.*-1001/,
    usersGenericWrite: /S-1-5-32-545/,
    usersWriteDac: /S-1-5-32-545/,
    nullDacl: /DACL nulle/,
  };
  for (const [name, reason] of Object.entries(cases)) {
    const verdict = adminOnlyAclVerdict(SDDL[name]);
    assert.equal(verdict.ok, false, name);
    assert.match(verdict.reason, reason, name);
  }
  for (const junk of ['', 'pas un sddl', 'O:BAD:(A;;FA;;;BA', 'O:BAD:(A;;ZZ;;;BA)']) {
    assert.equal(adminOnlyAclVerdict(junk).ok, false, `SDDL illisible ou droits inconnus refusés : ${junk}`);
  }
});

test('parseSddl : propriétaire, drapeaux d\'héritage, masques hex et alias traduits', () => {
  const parsed = parseSddl(SDDL.programData);
  assert.equal(parsed.owner, 'S-1-5-18');
  assert.equal(parsed.aces.length, 5);
  assert.deepEqual(parsed.aces[0], { type: 'A', flags: ['OI', 'CI', 'IO'], mask: 0x10000000, sid: 'S-1-3-0' });
  assert.deepEqual(parsed.aces[3], { type: 'A', flags: ['OI', 'CI'], mask: 0x1200a9, sid: 'S-1-5-32-545' });
  assert.equal(parsed.aces[4].mask, 0x2 | 0x4 | 0x10 | 0x100, 'DCLCRPCR = WD,AD,WEA,WA d\'icacls');
});

test('checkAdminOnlyConfigFile : lit le dossier PUIS le fichier, refuse lien/jonction et ACL illisible', () => {
  const file = path.join('C:\\ProgramData', 'RDVAULT', 'config.cfg');
  const notLink = { isSymbolicLink: () => false };
  let asked = null;
  const ok = checkAdminOnlyConfigFile(file, { lstat: () => notLink, readSddl: (paths) => { asked = paths; return [SDDL.protectedDir, SDDL.protectedFile]; } });
  assert.deepEqual(ok, { ok: true });
  assert.deepEqual(asked, [path.dirname(file), file]);
  const badDir = checkAdminOnlyConfigFile(file, { lstat: () => notLink, readSddl: () => [SDDL.adminDirInherited, SDDL.protectedFile] });
  assert.equal(badDir.ok, false);
  assert.match(badDir.reason, /^dossier : /);
  const badFile = checkAdminOnlyConfigFile(file, { lstat: () => notLink, readSddl: () => [SDDL.protectedDir, SDDL.attackerOwnedFile] });
  assert.match(badFile.reason, /^fichier : propriétaire/);
  const link = checkAdminOnlyConfigFile(file, { lstat: (p) => ({ isSymbolicLink: () => p === path.dirname(file) }), readSddl: () => { throw new Error('ne doit pas être lu'); } });
  assert.match(link.reason, /jonction/);
  const unreadable = checkAdminOnlyConfigFile(file, { lstat: () => notLink, readSddl: () => { throw new Error('powershell.exe bloqué\nligne 2'); } });
  assert.deepEqual(unreadable, { ok: false, reason: 'ACL illisibles (powershell.exe bloqué)' });
});

test('loadConfigFromPaths : config %PROGRAMDATA% modifiable par un utilisateur → IGNORÉE, fichier suivant (admin) utilisé', () => {
  const attacker = { ...cfgFile('config.cfg', Buffer.from('VAULT_URL=https://vault-corp.attaquant.example\nTRUSTED_CERT_FINGERPRINTS=\nTRUSTED_DOMAINS=vault-corp.attaquant.example\n')), adminOnly: true };
  const admin = cfgFile('config.cfg', Buffer.from(`VAULT_URL=https://vault.corp.example:8200\nTRUSTED_CERT_FINGERPRINTS=${HEX_A}\n`));
  const checked = [];
  const cfg = loadConfigFromPaths([attacker, admin, DEFAULT_JSON], {
    checkAdminOnly: (p) => { checked.push(p); return { ok: false, reason: `dossier : propriétaire non administrateur (${USER_SID})` }; },
  });
  assert.deepEqual(checked, [attacker.path]);
  assert.equal(cfg.VAULT_URL, 'https://vault.corp.example:8200', 'avant : VAULT_URL de l\'attaquant');
  assert.equal(cfg.TRUSTED_CERT_FINGERPRINTS, HEX_A);
  assert.ok(warnings.some(w => w.includes(attacker.path) && /IGNORÉ/.test(w) && /S-1-5-32-544/.test(w)), warnings.join(' | '));
  assert.doesNotMatch(warnings.join(' '), /attaquant\.example/, 'aucune valeur de configuration journalisée');
});

test('loadConfigFromPaths : config %PROGRAMDATA% réservée aux administrateurs → lue en priorité', () => {
  const machine = { ...cfgFile('config.cfg', Buffer.from('APP_MODE=local\nLANG=ja\n')), adminOnly: true };
  const installed = cfgFile('config.cfg', Buffer.from('APP_MODE=enterprise\nLANG=en\n'));
  const cfg = loadConfigFromPaths([machine, installed], { checkAdminOnly: () => ({ ok: true }) });
  assert.deepEqual([cfg.APP_MODE, cfg.LANG], ['local', 'ja']);
  // Les autres emplacements (dossier d'installation, userData) ne sont jamais soumis au contrôle
  let calls = 0;
  loadConfigFromPaths([installed], { checkAdminOnly: () => { calls++; return { ok: false }; } });
  assert.equal(calls, 0);
});

test('checkAdminOnlyConfigFile (Windows, lecture réelle via Get-Acl) : fichier temporaire de l\'utilisateur refusé', { skip: process.platform !== 'win32' }, () => {
  // Dossier temporaire de l'utilisateur courant : propriétaire = l'utilisateur, jamais un administrateur
  const entry = cfgFile('config.cfg', Buffer.from('LANG=fr\n'));
  const sddls = readSddlWithPowerShell([path.dirname(entry.path), entry.path]);
  assert.equal(sddls.length, 2);
  for (const s of sddls) assert.ok(parseSddl(s), `SDDL exploitable : ${s}`);
  const verdict = checkAdminOnlyConfigFile(entry.path);
  assert.equal(verdict.ok, false);
  assert.match(verdict.reason, /non administrateur|non-administrateur/);
});
