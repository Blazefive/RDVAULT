// ========================================
// TESTS (node --test) : route de lecture groupée du coffre local (POST /v1/{coffre}/rdvault-batch-read)
// ========================================
// Serveur local RÉEL (localVaultServer, authService, secretsService, crypto) sur 127.0.0.1, port dynamique,
// base SQLite JETABLE dans un dossier temporaire. better-sqlite3 étant compilé pour Electron, il est
// remplacé ici par un adaptateur minimal au-dessus de node:sqlite (même SQL, mêmes résultats) ; le module
// « electron » est simulé (userData = dossier temporaire, application « packagée »). Jamais le vrai coffre.
// Vérifie que chaque clé est servie EXACTEMENT comme par GET /v1/{coffre}/data/{clé} (données, version
// supprimée, absente, intégrité GCM « decryption failed »), avec les mêmes contrôles (jeton, propriété du
// coffre, origine, corps JSON), sans jamais servir les blobs cachés ni écrire quoi que ce soit.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-batch-'));

// ── Adaptateur better-sqlite3 → node:sqlite (sous-ensemble utilisé par electron/localVault) ──
const { DatabaseSync } = require('node:sqlite');
function wrapStatement(st, pluck = false) {
  const first = (row) => (row ? Object.values(row)[0] : undefined);
  return {
    get: (...a) => { const r = st.get(...a); return pluck ? first(r) : (r ? { ...r } : r); },
    all: (...a) => st.all(...a).map(r => (pluck ? first(r) : { ...r })),
    run: (...a) => { const r = st.run(...a); return { changes: Number(r.changes), lastInsertRowid: r.lastInsertRowid }; },
    pluck: () => wrapStatement(st, true),
  };
}
class FakeBetterSqlite {
  constructor(file) { this.db = new DatabaseSync(file); this.depth = 0; }
  pragma(text, opts) {
    const rows = this.db.prepare(`PRAGMA ${text}`).all();
    if (opts && opts.simple) return rows[0] ? Object.values(rows[0])[0] : undefined;
    return rows;
  }
  exec(sql) { this.db.exec(sql); }
  prepare(sql) { return wrapStatement(this.db.prepare(sql)); }
  transaction(fn) {
    return (...args) => {
      const sp = `sp${++this.depth}`;
      this.db.exec(`SAVEPOINT ${sp}`);
      try {
        const r = fn(...args);
        this.db.exec(`RELEASE ${sp}`);
        return r;
      } catch (e) {
        this.db.exec(`ROLLBACK TO ${sp}`);
        this.db.exec(`RELEASE ${sp}`);
        throw e;
      } finally {
        this.depth--;
      }
    };
  }
  close() { this.db.close(); }
}

const fakeElectron = { app: { getPath: () => TMP, isPackaged: true } };
const originalLoad = Module._load;
Module._load = function load(request, parent, isMain) {
  if (request === 'electron') return fakeElectron;
  if (request === 'better-sqlite3') return FakeBetterSqlite;
  return originalLoad.call(this, request, parent, isMain);
};

const localVault = require('./localVaultServer');
const authService = require('./authService');
const { getDb } = require('./database');

let port;
const ADMIN = 'alice';
const OTHER = 'bob';
const PASSWORD = 'Motdepasse-maitre-1';
const ENGINE = `users/${ADMIN}/Mes-Secrets`;
const enc = (s) => s.split('/').map(encodeURIComponent).join('/');

function request(method, p, { token, body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const h = { ...headers };
    if (data !== null) {
      if (!h['Content-Type']) h['Content-Type'] = 'application/json';
      h['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) h['X-Vault-Token'] = token;
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers: h }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { json = null; }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    if (data !== null) req.write(data);
    req.end();
  });
}

const batchPath = (engine = ENGINE) => `/v1/${enc(engine)}/rdvault-batch-read`;
const dataPath = (key, engine = ENGINE) => `/v1/${enc(engine)}/data/${encodeURIComponent(key)}`;
const batch = (token, keys, engine) => request('POST', batchPath(engine), { token, body: { keys } });

async function login(user, extra = {}) {
  const r = await request('POST', `/v1/auth/ldap/login/${encodeURIComponent(user)}`, { body: { password: PASSWORD, ...extra } });
  assert.equal(r.status, 200, `connexion de ${user}`);
  return r.json.auth.client_token;
}

let tokenA;
let tokenB;

test.before(async () => {
  port = await localVault.start(0);
  // Premier compte (administrateur) : confirmation exigée, coffre personnel créé
  tokenA = await login(ADMIN, { confirm: PASSWORD });
  const created = await authService.createUser(OTHER, PASSWORD, false);
  assert.equal(created.success, true);
  tokenB = await login(OTHER);

  const write = async (key, data) => {
    const r = await request('POST', dataPath(key), { token: tokenA, body: { data } });
    assert.equal(r.status, 200, `écriture de ${key}`);
  };
  await write('banque', { Username: 'alice', Password: 'p-banque', Tags: 'perso' });
  await write('dossier/vpn', { Username: 'a.vpn', Password: 'p-vpn', CustomFields: [{ key: 'Port', value: '443' }] });
  await write('supprimee', { Password: 'p-old' });
  await write('corrompue', { Password: 'p-corrompue' });
  await write('.rdvault-passkeys', { blob: 'clés privées' });
  // Suppression douce de « supprimee » (comme l'interface : métadonnées puis delete des versions)
  const del = await request('POST', `/v1/${enc(ENGINE)}/delete/supprimee`, { token: tokenA, body: { versions: [1] } });
  assert.equal(del.status, 204);
  // Blob altéré : l'intégrité GCM échoue (comme un fichier de base modifié)
  const row = getDb().prepare('SELECT id, data FROM secrets WHERE key = ?').get('corrompue');
  const tampered = (row.data[0] === 'a' ? 'b' : 'a') + row.data.slice(1);
  getDb().prepare('UPDATE secrets SET data = ? WHERE id = ?').run(tampered, row.id);
});

test.after(() => {
  Module._load = originalLoad;
  try { localVault.stop(); } catch { /* déjà arrêté */ }
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* dossier temporaire */ }
});

test('chaque clé est servie comme par GET …/data/{clé} : données, supprimée, absente, illisible', async () => {
  const keys = ['banque', 'dossier/vpn', 'supprimee', 'absente', 'corrompue'];
  const r = await batch(tokenA, keys);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.data.remaining, []);
  const results = r.json.data.results;
  assert.deepEqual(results.map(x => x.key), keys, 'ordre des clés demandées');

  for (const [i, key] of keys.entries()) {
    // eslint-disable-next-line no-await-in-loop
    const unit = await request('GET', dataPath(key), { token: tokenA });
    const b = results[i];
    assert.equal(b.status, unit.status, `statut de ${key}`);
    if (unit.status === 200) {
      assert.deepEqual(b.data, unit.json.data.data, `données de ${key}`);
      assert.equal(b.metadata.version, unit.json.data.metadata.version);
    }
  }
  assert.equal(results[2].deleted, true, 'version courante supprimée en douceur');
  assert.ok(results[2].metadata.deletion_time, 'horodatage de suppression');
  assert.equal(results[3].deleted, undefined, 'absente : jamais prise pour supprimée');
  assert.equal(results[4].status, 500, 'intégrité : erreur distincte de « introuvable »');
  assert.equal(results[4].error, 'decryption failed');
  assert.equal(results[4].data, undefined);
});

test('blob caché (passkeys) jamais servi par la lecture groupée ; la lecture unitaire reste inchangée', async () => {
  const r = await batch(tokenA, ['.rdvault-passkeys', 'banque']);
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.data.results[0], { key: '.rdvault-passkeys', status: 403 });
  assert.equal(r.json.data.results[1].status, 200);
  const unit = await request('GET', dataPath('.rdvault-passkeys'), { token: tokenA });
  assert.equal(unit.status, 200);
});

test('mêmes contrôles d\'accès : sans jeton, jeton invalide, coffre d\'un autre utilisateur, coffre inconnu', async () => {
  assert.equal((await batch(null, ['banque'])).status, 403);
  assert.equal((await batch('jeton-invalide', ['banque'])).status, 403);
  const other = await batch(tokenB, ['banque']);
  assert.equal(other.status, 403, 'coffre d\'alice refusé à bob');
  assert.equal((await request('GET', dataPath('banque'), { token: tokenB })).status, 403, 'comme la lecture unitaire');
  assert.equal((await batch(tokenA, ['banque'], 'inconnu')).status, 404);
});

test('barrières communes : origine web tierce, corps non JSON, méthode, clés invalides', async () => {
  const foreign = await request('POST', batchPath(), { token: tokenA, body: { keys: ['banque'] }, headers: { Origin: 'https://evil.example' } });
  assert.equal(foreign.status, 403);
  const textPlain = await request('POST', batchPath(), { token: tokenA, body: JSON.stringify({ keys: ['banque'] }), headers: { 'Content-Type': 'text/plain' } });
  assert.equal(textPlain.status, 415);
  assert.equal((await request('GET', batchPath(), { token: tokenA })).status, 405);
  for (const body of [{}, { keys: 'banque' }, { keys: [] }, { keys: [42] }, { keys: [''] }, { keys: ['x'.repeat(5000)] },
    { keys: Array.from({ length: 1001 }, (_, i) => `k${i}`) }]) {
    // eslint-disable-next-line no-await-in-loop
    const r = await request('POST', batchPath(), { token: tokenA, body });
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 60));
  }
});

test('réponse bornée en taille : clés suivantes renvoyées dans « remaining », au moins une traitée', async () => {
  const big = 'x'.repeat(2.5 * 1024 * 1024);
  for (const key of ['gros-1', 'gros-2']) {
    // eslint-disable-next-line no-await-in-loop
    const w = await request('POST', dataPath(key), { token: tokenA, body: { data: { Notes: big } } });
    assert.equal(w.status, 200);
  }
  const first = await batch(tokenA, ['gros-1', 'gros-2', 'banque']);
  assert.equal(first.status, 200);
  assert.deepEqual(first.json.data.results.map(x => x.key), ['gros-1', 'gros-2']);
  assert.deepEqual(first.json.data.remaining, ['banque']);
  const rest = await batch(tokenA, first.json.data.remaining);
  assert.deepEqual(rest.json.data.results.map(x => [x.key, x.status]), [['banque', 200]]);
  // Une seule entrée plus grosse que la borne : servie quand même (progrès garanti)
  const single = await batch(tokenA, ['gros-1']);
  assert.equal(single.json.data.results.length, 1);
  assert.deepEqual(single.json.data.remaining, []);
});

test('lecture seule : aucune version créée, aucune suppression levée', async () => {
  const before = getDb().prepare('SELECT key, version, deletion_time FROM secrets ORDER BY id').all();
  await batch(tokenA, ['banque', 'dossier/vpn', 'supprimee', 'corrompue']);
  const after = getDb().prepare('SELECT key, version, deletion_time FROM secrets ORDER BY id').all();
  assert.deepEqual(after, before);
});

test('les routes KV standard restent inchangées (aucune clé « rdvault-batch-read » interceptée en lecture)', async () => {
  // Une entrée nommée comme l'opération reste lisible et inscriptible par l'API KV v2 standard
  const w = await request('POST', dataPath('rdvault-batch-read'), { token: tokenA, body: { data: { Password: 'nom-piège' } } });
  assert.equal(w.status, 200);
  const r = await request('GET', dataPath('rdvault-batch-read'), { token: tokenA });
  assert.equal(r.json.data.data.Password, 'nom-piège');
  const list = await request('GET', `/v1/${enc(ENGINE)}/metadata?list=true`, { token: tokenA });
  assert.ok(list.json.data.keys.includes('rdvault-batch-read'));
});
