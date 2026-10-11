// Tests de la mémoire des clés d'hôte SSH (electron/knownHosts.js) — node --test, sans Electron.
// Vérifie lookup/remember/forget/check/entries, la tolérance au fichier absent, l'échec FERMÉ
// (KNOWN_HOSTS_READ) d'un fichier illisible ou corrompu, l'écriture atomique, la normalisation
// des empreintes et la cohérence entre deux instances.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createKnownHosts, hostKey, normalizeFp } = require('./knownHosts');

const FP_A = 'SHA256:' + Buffer.alloc(32, 0x41).toString('base64').replace(/=+$/, '');
const FP_B = 'SHA256:' + Buffer.alloc(32, 0x42).toString('base64').replace(/=+$/, '');

// Dossiers temporaires de test (%TEMP%\rdvault-kh-*) : tous supprimés en fin de fichier
// (auparavant jamais nettoyés : 13 dossiers restaient à chaque exécution de test:electron)
const khTmpDirs = [];
test.after(() => {
  for (const dir of khTmpDirs) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ }
  }
});

function tmpFile(name = 'known_hosts.json') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-kh-'));
  khTmpDirs.push(dir);
  return { dir, file: path.join(dir, name) };
}

test('hostKey : casse, espaces et port par défaut', () => {
  assert.equal(hostKey('Serveur.Example.COM', 22), 'serveur.example.com:22');
  assert.equal(hostKey('  Host  ', undefined), 'host:22');
  assert.equal(hostKey('host', '2222'), 'host:2222');
  assert.equal(hostKey('host', 'abc'), 'host:22');
  assert.equal(hostKey('host', 0), 'host:22');
  assert.equal(hostKey('::1', 22), '::1:22');
});

test('normalizeFp : préfixe, casse du préfixe, padding', () => {
  const raw = Buffer.alloc(32, 0x41).toString('base64'); // se termine par '='
  assert.equal(normalizeFp('SHA256:' + raw), FP_A);
  assert.equal(normalizeFp('sha256:' + raw), FP_A);
  assert.equal(normalizeFp(raw), FP_A);
  assert.equal(normalizeFp('  ' + FP_A + '  '), FP_A);
  assert.equal(normalizeFp(FP_A), FP_A);
});

test('fichier absent → mémoire vide, aucune exception', () => {
  const { file } = tmpFile();
  const kh = createKnownHosts(file);
  assert.equal(kh.path, file);
  assert.equal(kh.lookup('h', 22), null);
  assert.deepEqual(kh.entries(), []);
  assert.deepEqual(kh.check('h', 22, FP_A), { status: 'new', expected: null });
  assert.equal(kh.forget('h', 22), false);
  assert.equal(fs.existsSync(file), false, 'rien n\'est créé à la lecture');
});

test('remember crée le fichier (dossier inclus) au bon format, lookup/entries/check cohérents', () => {
  const { dir } = tmpFile();
  const file = path.join(dir, 'sous', 'dossier', 'known_hosts.json'); // mkdir -p
  const kh = createKnownHosts(file);
  kh.remember('Srv.Example.com', 2222, FP_A);
  assert.ok(fs.existsSync(file));
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(json.version, 1);
  assert.deepEqual(Object.keys(json.hosts), ['srv.example.com:2222']);
  assert.equal(json.hosts['srv.example.com:2222'].fingerprint, FP_A);
  assert.match(json.hosts['srv.example.com:2222'].firstSeen, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(json.hosts['srv.example.com:2222'].lastSeen, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(kh.lookup('SRV.example.COM', '2222'), FP_A);
  assert.equal(kh.lookup('srv.example.com', 22), null, 'le port fait partie de la clé');
  assert.deepEqual(kh.check('srv.example.com', 2222, FP_A), { status: 'known', expected: FP_A });
  assert.deepEqual(kh.check('srv.example.com', 2222, 'sha256:' + FP_A.slice(7) + '='), { status: 'known', expected: FP_A }, 'comparaison normalisée');
  assert.deepEqual(kh.check('srv.example.com', 2222, FP_B), { status: 'mismatch', expected: FP_A });
  const entries = kh.entries();
  assert.equal(entries.length, 1);
  assert.equal(entries[0].host, 'srv.example.com');
  assert.equal(entries[0].port, 2222);
  assert.equal(entries[0].fingerprint, FP_A);
  assert.ok(entries[0].firstSeen && entries[0].lastSeen);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'permissions 0600');
  }
});

test('remember : lastSeen mis à jour, firstSeen conservé pour la même clé, réinitialisé si la clé change', async () => {
  const { file } = tmpFile();
  const kh = createKnownHosts(file);
  kh.remember('h', 22, FP_A);
  const e1 = kh.entries()[0];
  await new Promise((r) => setTimeout(r, 15));
  kh.remember('h', 22, FP_A);
  const e2 = kh.entries()[0];
  assert.equal(e2.firstSeen, e1.firstSeen, 'firstSeen conservé');
  assert.ok(e2.lastSeen > e1.lastSeen, 'lastSeen avancé');
  await new Promise((r) => setTimeout(r, 15));
  kh.remember('h', 22, FP_B);
  const e3 = kh.entries()[0];
  assert.equal(e3.fingerprint, FP_B);
  assert.ok(e3.firstSeen > e1.firstSeen, 'nouvelle clé → nouveau firstSeen');
  assert.equal(kh.entries().length, 1);
});

test('remember : empreinte normalisée à l\'enregistrement ; hôte ou empreinte vides refusés', () => {
  const { file } = tmpFile();
  const kh = createKnownHosts(file);
  kh.remember('h', 22, Buffer.alloc(32, 0x41).toString('base64'));
  assert.equal(kh.lookup('h', 22), FP_A);
  assert.throws(() => kh.remember('', 22, FP_A), /hôte requis/);
  assert.throws(() => kh.remember('h', 22, ''), /empreinte requise/);
});

test('forget : supprime l\'entrée et renvoie true, puis false', () => {
  const { file } = tmpFile();
  const kh = createKnownHosts(file);
  kh.remember('a', 22, FP_A);
  kh.remember('b', 22, FP_B);
  assert.equal(kh.forget('A', 22), true);
  assert.equal(kh.forget('a', 22), false);
  assert.equal(kh.lookup('a', 22), null);
  assert.equal(kh.lookup('b', 22), FP_B, 'les autres entrées sont conservées');
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(file, 'utf8')).hosts), ['b:22']);
});

/** Vérifie qu'une opération échoue de façon FERMÉE (code KNOWN_HOSTS_READ) avec le chemin du fichier. */
const readFails = (fn, file) => assert.throws(fn, (e) => {
  assert.equal(e.code, 'KNOWN_HOSTS_READ');
  assert.ok(e.message.includes(file), 'le message indique le fichier en cause');
  return true;
});

test('SSHCORE-52 : fichier corrompu → KNOWN_HOSTS_READ (échec fermé), le fichier n\'est jamais réécrit', () => {
  const { file } = tmpFile();
  fs.writeFileSync(file, '{ pas du json');
  const kh = createKnownHosts(file);
  readFails(() => kh.lookup('h', 22), file);
  readFails(() => kh.entries(), file);
  readFails(() => kh.check('h', 22, FP_A), file);
  readFails(() => kh.remember('h', 22, FP_A), file);
  readFails(() => kh.forget('h', 22), file);
  assert.equal(fs.readFileSync(file, 'utf8'), '{ pas du json', 'contenu laissé intact (rien n\'est effacé)');
});

test('fichier de forme inattendue → KNOWN_HOSTS_READ ; entrées invalides ignorées sans exception', () => {
  const { file } = tmpFile();
  fs.writeFileSync(file, JSON.stringify([1, 2, 3]));
  readFails(() => createKnownHosts(file).entries(), file);
  readFails(() => createKnownHosts(file).remember('h', 22, FP_A), file);
  assert.equal(fs.readFileSync(file, 'utf8'), '[1,2,3]', 'fichier de forme inconnue non écrasé');
  fs.writeFileSync(file, JSON.stringify({ version: 1, hosts: { 'ok:22': { fingerprint: FP_A }, 'bad:22': { fingerprint: 42 }, 'nul:22': null } }));
  const kh = createKnownHosts(file);
  assert.equal(kh.lookup('ok', 22), FP_A);
  assert.equal(kh.lookup('bad', 22), null);
  assert.equal(kh.entries().length, 1);
});

test('SSHCORE-56 : empreinte vide après normalisation (« sha256: », « = »…) → entrée ignorée, clé « new »', () => {
  const { file } = tmpFile();
  fs.writeFileSync(file, JSON.stringify({ version: 1, hosts: {
    'vide:22': { fingerprint: 'sha256:' }, 'pad:22': { fingerprint: '=' }, 'pref:22': { fingerprint: ' SHA256:== ' }, 'ok:22': { fingerprint: FP_A },
  } }));
  const kh = createKnownHosts(file);
  for (const h of ['vide', 'pad', 'pref']) {
    assert.equal(kh.lookup(h, 22), null, `${h} : entrée invalide ignorée`);
    assert.deepEqual(kh.check(h, 22, FP_B), { status: 'new', expected: null });
  }
  assert.deepEqual(kh.entries().map((e) => e.host), ['ok']);
});

test('SSHCORE-52 : erreur de lecture transitoire (EBUSY) → KNOWN_HOSTS_READ, aucune entrée effacée', (t) => {
  const { file } = tmpFile();
  const kh = createKnownHosts(file);
  kh.remember('srv', 22, FP_A);
  kh.remember('autre', 22, FP_B);
  const original = fs.readFileSync(file, 'utf8');
  const realRead = fs.readFileSync;
  t.mock.method(fs, 'readFileSync', function (p, ...rest) {
    if (path.resolve(String(p)) === path.resolve(file)) throw Object.assign(new Error('EBUSY: resource busy or locked'), { code: 'EBUSY' });
    return realRead.call(this, p, ...rest);
  });
  readFails(() => kh.check('srv', 22, FP_B), file); // jamais « new » à la place de « mismatch »
  readFails(() => kh.lookup('srv', 22), file);
  readFails(() => kh.remember('nouveau', 22, FP_A), file);
  readFails(() => kh.forget('autre', 22), file);
  t.mock.restoreAll();
  assert.equal(fs.readFileSync(file, 'utf8'), original, 'fichier inchangé');
  assert.deepEqual(kh.check('srv', 22, FP_B), { status: 'mismatch', expected: FP_A });
  assert.equal(kh.lookup('autre', 22), FP_B);
});

test('SSHCORE-52 : known_hosts.json est un dossier (EISDIR) → KNOWN_HOSTS_READ', () => {
  const { file } = tmpFile();
  fs.mkdirSync(file);
  const kh = createKnownHosts(file);
  readFails(() => kh.lookup('h', 22), file);
  readFails(() => kh.remember('h', 22, FP_A), file);
});

test('écriture atomique : pas de fichier temporaire résiduel, contenu complet', () => {
  const { dir, file } = tmpFile();
  const kh = createKnownHosts(file);
  for (let i = 0; i < 20; i++) kh.remember('h' + i, 22, FP_A);
  assert.deepEqual(fs.readdirSync(dir), ['known_hosts.json'], 'seul le fichier final subsiste');
  assert.equal(kh.entries().length, 20);
});

test('erreur d\'écriture propagée (le dossier parent est un fichier)', () => {
  const { dir } = tmpFile();
  const blocker = path.join(dir, 'fichier');
  fs.writeFileSync(blocker, 'x');
  const kh = createKnownHosts(path.join(blocker, 'known_hosts.json'));
  assert.equal(kh.lookup('h', 22), null, 'chemin impossible (ENOENT/ENOTDIR) = fichier absent = mémoire vide');
  assert.throws(() => kh.remember('h', 22, FP_A));
});

test('relecture entre deux instances (pas de cache) : les écritures de l\'une sont vues par l\'autre', () => {
  const { file } = tmpFile();
  const a = createKnownHosts(file);
  const b = createKnownHosts(file);
  assert.equal(b.lookup('h', 22), null);
  a.remember('h', 22, FP_A);
  assert.equal(b.lookup('h', 22), FP_A);
  assert.deepEqual(b.check('h', 22, FP_B), { status: 'mismatch', expected: FP_A });
  assert.equal(b.forget('h', 22), true);
  assert.equal(a.lookup('h', 22), null);
  fs.writeFileSync(file, JSON.stringify({ version: 1, hosts: { 'x:22': { fingerprint: FP_B } } })); // modification externe
  assert.equal(a.lookup('x', 22), FP_B);
});

test('createKnownHosts sans chemin → erreur claire', () => {
  assert.throws(() => createKnownHosts(''), /chemin de fichier requis/);
});
