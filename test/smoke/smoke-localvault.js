// Test de fumée Electron (sans fenêtre) : coffre local + helpers CLI.
// Lancement : npx electron test/smoke/smoke-localvault.js
const { app } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');

const ROOT = path.resolve(__dirname, '..', '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-smoke-'));
app.setPath('userData', tmp);
process.env.RDVAULT_LOG_LEVEL = 'warn';
// Fuseau non UTC imposé : une date « YYYY-MM-DD HH:MM:SS » sans fuseau serait lue en heure locale
// (décalée), ce que vérifient les contrôles d'horodatage LOCALVAULT-4 ci-dessous
process.env.TZ = 'Europe/Paris';

// Horodatage ISO 8601 UTC (format Vault / RFC 3339 avec « Z »)
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const isRecentIso = (s) => typeof s === 'string' && ISO_UTC.test(s) && Math.abs(Date.parse(s) - Date.now()) < 120000;

let failures = 0;
function check(cond, label) {
  console.log((cond ? 'PASS ' : 'FAIL ') + label);
  if (!cond) failures++;
}

// `headers` : en-têtes ajoutés (ex. Origin)
function req(port, method, p, { token, body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'X-Vault-Token': token } : {}),
      ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      ...(headers || {})
    } }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch {} resolve({ status: res.statusCode, json }); });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

app.whenReady().then(async () => {
  try {
    // ---- helpers CLI (fonctions pures exportées)
    const cli = require(path.join(ROOT, 'electron/cliServer.js'));
    check(cli.matchesRule('users/blaze/x', 'users/blaze/*') === true, 'rule wildcard match');
    check(cli.matchesRule('users/blaze/a/b', 'users/blaze/*') === true, 'rule wildcard deep match');
    check(cli.matchesRule('users/blazefoo/x', 'users/blaze/*') === false, 'rule no prefix-string match');
    check(cli.matchesRule('users/blaze', 'users/blaze/*') === false, 'rule wildcard needs child');
    check(cli.matchesRule('prod/db', 'prod/db') === true, 'rule exact');
    check(cli.isValidVaultPath('a/../b', 256) === false, 'path traversal rejected');
    check(cli.isValidVaultPath('a\nb', 256) === false, 'control char rejected');

    // ---- coffre local
    const lv = require(path.join(ROOT, 'electron/localVault/localVaultServer.js'));
    const port = await lv.start(0);
    check(typeof port === 'number' && port > 0, 'local vault started on port ' + port);

    // mot de passe non-string → 400 (pas 500)
    let r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 12345 } });
    check(r.status === 400, 'login non-string password → 400');

    // AUTH-14 : premier démarrage. GET /v1/sys/init (sans jeton, comme Vault) indique s'il reste à créer le
    // compte administrateur ; cette création exige la confirmation du mot de passe (champ « confirm »)
    r = await req(port, 'GET', '/v1/sys/init');
    check(r.status === 200 && r.json?.initialized === false && Object.keys(r.json || {}).length === 1,
      'AUTH-14: GET /v1/sys/init without token on an empty vault → { initialized: false } (' + r.status + ' ' + JSON.stringify(r.json) + ')');
    r = await req(port, 'GET', '/v1/sys/init', { headers: { Origin: 'https://evil.example' } });
    check(r.status === 403, 'AUTH-14: GET /v1/sys/init from a third-party web origin → 403 (status=' + r.status + ')');
    r = await req(port, 'POST', '/v1/sys/init', { body: {} });
    check(r.status === 403, 'AUTH-14: POST /v1/sys/init (initialisation Vault) not exposed without a token → 403');
    r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'correct-horse-battery' } });
    check(r.status === 400 && r.json?.errors?.[0] === 'password confirmation required' && !r.json?.auth,
      'AUTH-14: first account without confirm → 400, no token (status=' + r.status + ')');
    r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'correct-horse-battery', confirm: 'correct-horse-batterz' } });
    check(r.status === 400 && r.json?.errors?.[0] === 'password confirmation does not match' && !r.json?.auth,
      'AUTH-14: first account with a mismatched confirm → 400, no token');
    r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'correct-horse-battery', confirm: 12345 } });
    check(r.status === 400 && !r.json?.auth, 'AUTH-14: non-string confirm → 400');
    // Ces refus ne consomment pas le quota anti-force brute (5 / 5 min) : la création reste possible
    for (let i = 0; i < 6; i++) await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'correct-horse-battery' } });
    r = await req(port, 'GET', '/v1/sys/init');
    check(r.status === 200 && r.json?.initialized === false, 'AUTH-14: refused creations create nothing (still not initialized)');

    // premier login = création admin (avec confirmation)
    r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'correct-horse-battery', confirm: 'correct-horse-battery' } });
    check(r.status === 200 && r.json?.auth?.client_token, 'first login creates admin and returns token (confirm sent, after refused attempts)');
    const tokenA = r.json.auth.client_token;
    r = await req(port, 'GET', '/v1/sys/init');
    check(r.status === 200 && r.json?.initialized === true, 'AUTH-14: GET /v1/sys/init → { initialized: true } once the account exists');
    r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'correct-horse-battery' } });
    check(r.status === 200 && r.json?.auth?.client_token, 'AUTH-14: later logins need no confirm');

    // mauvais mot de passe → 400 ; utilisateur inexistant → 400 (même code)
    r = await req(port, 'POST', '/v1/auth/ldap/login/alice', { body: { password: 'wrong' } });
    check(r.status === 400, 'wrong password → 400');
    const t0 = Date.now();
    r = await req(port, 'POST', '/v1/auth/ldap/login/nobody', { body: { password: 'wrong' } });
    const dtUnknown = Date.now() - t0;
    check(r.status === 400, 'unknown user → 400');
    check(dtUnknown > 80, 'unknown user login takes bcrypt time (' + dtUnknown + 'ms)');

    // engine par défaut + écriture/lecture
    r = await req(port, 'GET', '/v1/sys/mounts', { token: tokenA });
    const mounts = Object.keys(r.json || {});
    check(mounts.some(m => m.startsWith('users/alice/')), 'default personal engine exists');
    const engine = mounts.find(m => m.startsWith('users/alice/')).replace(/\/$/, '');

    r = await req(port, 'POST', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA, body: { data: { username: 'root', password: 'p@ss' } } });
    check(r.status === 200 && r.json?.data?.version === 1, 'write secret v1');
    r = await req(port, 'POST', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA, body: { data: { username: 'root', password: 'p@ss2' } } });
    check(r.status === 200 && r.json?.data?.version === 2, 'write secret v2');
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA });
    check(r.status === 200 && r.json?.data?.data?.password === 'p@ss2', 'read latest secret');
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb?version=1`, { token: tokenA });
    check(r.json?.data?.data?.password === 'p@ss', 'read version 1');
    r = await req(port, 'GET', `/v1/${engine}/metadata?list=true`, { token: tokenA });
    check(Array.isArray(r.json?.data?.keys) && r.json.data.keys.includes('serveur/'), 'list keys shows folder');
    check(!r.json?.data?.keys?.includes('.rdvault-keycheck'), 'LOCALVAULT-1: no key-check witness for a password of 72 bytes or less');

    // LOCALVAULT-4 : horodatages des versions renvoyés en ISO 8601 UTC (« …Z »), la base garde son format SQLite
    check(new Date(2026, 0, 15).getTimezoneOffset() === -60, 'TZ Europe/Paris applied to the test process');
    r = await req(port, 'GET', `/v1/${engine}/metadata/serveur%2Fdb`, { token: tokenA });
    check(isRecentIso(r.json?.data?.versions?.[1]?.created_time) && isRecentIso(r.json?.data?.versions?.[2]?.created_time),
      'LOCALVAULT-4: metadata created_time in ISO 8601 UTC and close to now (' + r.json?.data?.versions?.[1]?.created_time + ')');
    check(r.json?.data?.versions?.[1]?.deletion_time === '', 'LOCALVAULT-4: deletion_time stays « » when not deleted');
    {
      const { toIsoUtc } = require(path.join(ROOT, 'electron/localVault/secretsService.js'));
      check(toIsoUtc('2026-10-10 12:00:00') === '2026-10-10T12:00:00Z' && new Date(toIsoUtc('2026-10-10 12:00:00')).getHours() === 14,
        'LOCALVAULT-4: toIsoUtc converts SQLite UTC to ISO « Z » (12:00 UTC = 14:00 Paris)');
      check(toIsoUtc('2026-10-10 12:00:00.123') === '2026-10-10T12:00:00.123Z', 'LOCALVAULT-4: toIsoUtc keeps fractional seconds');
      check(toIsoUtc('2026-10-10T12:00:00Z') === '2026-10-10T12:00:00Z' && toIsoUtc('') === '' && toIsoUtc(null) === null && toIsoUtc('n/a') === 'n/a',
        'LOCALVAULT-4: toIsoUtc leaves ISO, empty, null and unknown values unchanged');
    }
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA });
    check(isRecentIso(r.json?.data?.metadata?.created_time) && r.json?.data?.metadata?.deletion_time === '',
      'LOCALVAULT-4: data read metadata.created_time in ISO 8601 UTC (' + r.json?.data?.metadata?.created_time + ')');

    // AAD : permuter deux blobs chiffrés dans la base → lecture doit échouer
    const db = require(path.join(ROOT, 'electron/localVault/database.js')).getDb();
    check(db.prepare('SELECT created_at FROM secrets').all().every(x => /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(x.created_at)),
      'LOCALVAULT-4: stored created_at unchanged (SQLite « YYYY-MM-DD HH:MM:SS »)');
    const rows = db.prepare('SELECT id, data, iv FROM secrets ORDER BY version').all();
    db.prepare('UPDATE secrets SET data = ?, iv = ? WHERE id = ?').run(rows[1].data, rows[1].iv, rows[0].id);
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb?version=1`, { token: tokenA });
    // LOCALVAULT-3 : un échec d'intégrité (GCM/AAD) n'est PAS présenté comme « introuvable » (404)
    check(r.status === 500 && r.json?.errors?.[0] === 'decryption failed' && r.json?.data === undefined,
      'LOCALVAULT-3: swapped ciphertext rejected (AAD) → 500 « decryption failed », not 404 (status=' + r.status + ')');
    db.prepare('UPDATE secrets SET data = ?, iv = ? WHERE id = ?').run(rows[0].data, rows[0].iv, rows[0].id);
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb?version=1`, { token: tokenA });
    check(r.status === 200 && r.json?.data?.data?.password === 'p@ss', 'restored ciphertext readable again');
    r = await req(port, 'GET', `/v1/${engine}/data/absent`, { token: tokenA });
    check(r.status === 404, 'LOCALVAULT-3: a really missing secret still answers 404');
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb?version=99`, { token: tokenA });
    check(r.status === 404, 'LOCALVAULT-3: a missing version still answers 404');

    // Soft-delete (KV v2) : la lecture de la version courante supprimée renvoie 404, la restauration la rend lisible
    r = await req(port, 'POST', `/v1/${engine}/delete/serveur%2Fdb`, { token: tokenA, body: { versions: [2] } });
    check(r.status === 204, 'soft-delete v2');
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA });
    check(r.status === 404 && r.json?.data?.data === null && !!r.json?.data?.metadata?.deletion_time, 'read deleted current version → 404 with metadata');
    check(isRecentIso(r.json?.data?.metadata?.deletion_time) && isRecentIso(r.json?.data?.metadata?.created_time),
      'LOCALVAULT-4: deleted-version metadata timestamps in ISO 8601 UTC (' + r.json?.data?.metadata?.deletion_time + ')');
    r = await req(port, 'GET', `/v1/${engine}/metadata/serveur%2Fdb`, { token: tokenA });
    check(r.status === 200 && !!r.json?.data?.versions?.[2]?.deletion_time && r.json?.data?.current_version === 2, 'metadata shows deletion_time on current version');
    check(isRecentIso(r.json?.data?.versions?.[2]?.deletion_time), 'LOCALVAULT-4: metadata deletion_time in ISO 8601 UTC');
    check(db.prepare('SELECT deletion_time FROM secrets WHERE deletion_time IS NOT NULL').all().every(x => /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(x.deletion_time)),
      'LOCALVAULT-4: stored deletion_time unchanged (SQLite format)');
    r = await req(port, 'POST', `/v1/${engine}/undelete/serveur%2Fdb`, { token: tokenA, body: { versions: [2] } });
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA });
    check(r.status === 200 && r.json?.data?.data?.password === 'p@ss2', 'undelete restores read');

    // SECRETS-36 : check-and-set (options.cas) comme Vault KV v2 — l'écriture n'a lieu que si la version
    // courante vaut cas (0 = secret inexistant) ; sinon 400 avec le message de Vault et rien n'est écrit
    {
      const CAS_MSG = 'check-and-set parameter did not match the current version';
      const casPath = `/v1/${engine}/data/cas-test`;
      const casWrite = (cas, password) => req(port, 'POST', casPath, { token: tokenA, body: { options: { cas }, data: { password } } });
      r = await casWrite(0, 'c1');
      check(r.status === 200 && r.json?.data?.version === 1, 'cas=0 on a new key → written (v1)');
      r = await casWrite(0, 'concurrent');
      check(r.status === 400 && r.json?.errors?.[0] === CAS_MSG, 'cas=0 on an existing key → 400 « ' + CAS_MSG + ' »');
      r = await req(port, 'GET', casPath, { token: tokenA });
      check(r.json?.data?.data?.password === 'c1' && r.json?.data?.metadata?.version === 1, 'refused cas write left the entry untouched (v1, c1)');
      r = await casWrite(1, 'c2');
      check(r.status === 200 && r.json?.data?.version === 2, 'cas=1 matching the current version → written (v2)');
      r = await casWrite(1, 'stale');
      check(r.status === 400 && r.json?.errors?.[0] === CAS_MSG, 'stale cas (1 while current is 2) → 400');
      r = await casWrite('2', 'c3');
      check(r.status === 200 && r.json?.data?.version === 3, 'cas given as a numeric string (« 2 ») accepted like Vault');
      for (const bad of [-1, 1.5, 'abc', null, true, {}]) {
        r = await casWrite(bad, 'bad');
        check(r.status === 400 && r.json?.errors?.[0] === 'error parsing check-and-set parameter', 'invalid cas ' + JSON.stringify(bad) + ' → 400 (nothing written)');
      }
      r = await req(port, 'GET', `/v1/${engine}/metadata/cas-test`, { token: tokenA });
      check(r.json?.data?.current_version === 3, 'no version written by refused cas requests (current_version=' + r.json?.data?.current_version + ')');
      // Version courante supprimée en douceur : elle compte toujours (comme Vault) ; après destruction, cas=0 recrée
      await req(port, 'POST', `/v1/${engine}/delete/cas-test`, { token: tokenA, body: { versions: [3] } });
      r = await casWrite(0, 'x');
      check(r.status === 400, 'soft-deleted current version still counts: cas=0 → 400');
      r = await casWrite(3, 'c4');
      check(r.status === 200 && r.json?.data?.version === 4, 'cas=3 after a soft delete → written (v4)');
      r = await req(port, 'DELETE', `/v1/${engine}/metadata/cas-test`, { token: tokenA });
      r = await casWrite(0, 'fresh');
      check(r.status === 200 && r.json?.data?.version === 1, 'after DELETE metadata (destroy), cas=0 recreates the entry (v1)');
      r = await req(port, 'POST', casPath, { token: tokenA, body: { data: { password: 'no-cas' } } });
      check(r.status === 200 && r.json?.data?.version === 2, 'write without options.cas unchanged (v2)');
    }

    // PURGE-35 : blobs internes cachés « .rdvault-* » (passkeys, témoin de clé) — seule la DERNIÈRE version
    // est conservée. Séquence de l'écran « Mes passkeys » : 2 créations, 3 signatures, suppression de PK1.
    // La clé privée de PK1 ne doit plus être lisible par ?version=N ni présente sur disque (base + WAL),
    // et chaque signature ne doit plus ajouter une copie complète du blob. Les entrées normales gardent
    // leur historique.
    {
      const pkPath = `/v1/${engine}/data/${encodeURIComponent('.rdvault-passkeys')}`;
      const pkMetaPath = `/v1/${engine}/metadata/${encodeURIComponent('.rdvault-passkeys')}`;
      const blobOf = (ids, signCount = 0) => ({ items: { 'site.example': ids.map(id => ({
        rpId: 'site.example', credentialId: id, privateKeyJwk: { kty: 'EC', d: 'PRIVATE-D-OF-' + id }, signCount })) } });
      const writePk = (ids, signCount) => req(port, 'POST', pkPath, { token: tokenA, body: { data: blobOf(ids, signCount) } });
      // Extraits du chiffré d'une version, cherchés tels quels dans les fichiers de la base (texte hexadécimal)
      const cipherSlices = (version) => {
        const row = db.prepare('SELECT data FROM secrets WHERE key = ? AND version = ?').get('.rdvault-passkeys', version);
        const hex = row ? row.data : '';
        const slices = [];
        for (let o = 0; o + 40 <= hex.length; o += 80) slices.push(Buffer.from(hex.slice(o, o + 40), 'utf8'));
        return slices;
      };
      const onDisk = (slices) => ['local-vault.db', 'local-vault.db-wal'].map(f => path.join(tmp, f)).filter(f => fs.existsSync(f))
        .some(f => { const buf = fs.readFileSync(f); return slices.some(s => buf.includes(s)); });

      r = await writePk(['PK1']);
      check(r.status === 200 && r.json?.data?.version === 1, 'PURGE-35: passkey blob v1 (PK1 created)');
      const v1Slices = cipherSlices(1);
      r = await writePk(['PK1', 'PK2']);
      const v2Slices = cipherSlices(2);
      for (let s = 1; s <= 3; s++) r = await writePk(['PK1', 'PK2'], s); // 3 signatures (passkey-update-count)
      check(r.status === 200 && r.json?.data?.version === 5, 'PURGE-35: version numbering continues across signatures (v5)');
      r = await writePk(['PK2']); // « Mes passkeys » › Supprimer PK1
      check(r.status === 200 && r.json?.data?.version === 6, 'PURGE-35: deletion of PK1 written as v6');
      check(v1Slices.length >= 2 && v2Slices.length >= 2, 'PURGE-35: precondition, old ciphertexts captured');

      const leaked = [];
      for (let v = 1; v <= 5; v++) {
        r = await req(port, 'GET', `${pkPath}?version=${v}`, { token: tokenA });
        if (r.status !== 404 || JSON.stringify(r.json || {}).includes('PRIVATE-D-OF-PK1')) leaked.push(v + ':' + r.status);
      }
      check(leaked.length === 0, 'PURGE-35: old versions of .rdvault-passkeys unreadable (404) — deleted private key gone (leaks: ' + leaked.join(',') + ')');
      r = await req(port, 'GET', pkPath, { token: tokenA });
      const items = r.json?.data?.data?.items?.['site.example'] || [];
      check(r.status === 200 && r.json?.data?.metadata?.version === 6 && items.length === 1 && items[0].credentialId === 'PK2',
        'PURGE-35: latest version (v6, PK2 only) still readable');
      r = await req(port, 'GET', pkMetaPath, { token: tokenA });
      check(r.status === 200 && JSON.stringify(Object.keys(r.json?.data?.versions || {})) === '["6"]'
        && r.json?.data?.current_version === 6 && r.json?.data?.oldest_version === 6,
        'PURGE-35: metadata lists only the latest version (' + JSON.stringify(Object.keys(r.json?.data?.versions || {})) + ')');
      check(db.prepare('SELECT COUNT(*) AS n FROM secrets WHERE key = ?').get('.rdvault-passkeys').n === 1, 'PURGE-35: a single row left in the database');
      check(!onDisk(v1Slices) && !onDisk(v2Slices), 'PURGE-35: old ciphertexts no longer present on disk (database + WAL)');

      // Croissance bornée : 40 signatures → toujours une seule version conservée
      for (let s = 4; s < 44; s++) await writePk(['PK2'], s);
      r = await req(port, 'GET', pkMetaPath, { token: tokenA });
      check(Object.keys(r.json?.data?.versions || {}).length === 1 && r.json?.data?.current_version === 46,
        'PURGE-35: 40 more signatures → still one version kept (current ' + r.json?.data?.current_version + ')');

      // Témoin de clé (autre blob caché) : même règle
      const kc = encodeURIComponent('.rdvault-keycheck');
      await req(port, 'POST', `/v1/${engine}/data/${kc}`, { token: tokenA, body: { data: { purpose: 'a' } } });
      await req(port, 'POST', `/v1/${engine}/data/${kc}`, { token: tokenA, body: { data: { purpose: 'b' } } });
      r = await req(port, 'GET', `/v1/${engine}/metadata/${kc}`, { token: tokenA });
      check(JSON.stringify(Object.keys(r.json?.data?.versions || {})) === '["2"]', 'PURGE-35: .rdvault-keycheck keeps only its latest version');

      // Entrées normales (y compris un nom qui CONTIENT « .rdvault- » sans commencer par lui, ou dans un dossier) :
      // historique intégralement conservé. COMPAT-2 : seuls les deux noms internes EXACTS sont purgés ; une
      // entrée utilisateur « .rdvault-notes » (permise en 1.5.0, affichée et modifiable) ou un nom qui ne fait
      // que commencer par un nom interne garde aussi son historique (avant : purgée à chaque écriture).
      for (const key of ['historique', 'notes.rdvault-x', 'dossier/.rdvault-y', '.rdvault-notes', '.rdvault-passkeys-old', 'dossier/.rdvault-passkeys']) {
        for (let i = 1; i <= 3; i++) await req(port, 'POST', `/v1/${engine}/data/${encodeURIComponent(key)}`, { token: tokenA, body: { data: { password: 'v' + i } } });
        r = await req(port, 'GET', `/v1/${engine}/data/${encodeURIComponent(key)}?version=1`, { token: tokenA });
        const meta = await req(port, 'GET', `/v1/${engine}/metadata/${encodeURIComponent(key)}`, { token: tokenA });
        check(r.status === 200 && r.json?.data?.data?.password === 'v1' && Object.keys(meta.json?.data?.versions || {}).length === 3,
          'PURGE-35: normal entry « ' + key + ' » keeps its 3 versions');
      }
      r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb?version=1`, { token: tokenA });
      check(r.status === 200 && r.json?.data?.data?.password === 'p@ss', 'PURGE-35: existing entry history untouched (serveur/db v1)');
    }

    // TOTP : création, code, nom encodé
    r = await req(port, 'POST', '/v1/TOTP/keys/mon%20compte', { token: tokenA, body: { key: 'JBSWY3DPEHPK3PXP', period: 30, digits: 6 } });
    check(r.status === 204, 'totp key created');
    r = await req(port, 'GET', '/v1/TOTP/code/mon%20compte', { token: tokenA });
    check(r.status === 200 && /^\d{6}$/.test(r.json?.data?.code || ''), 'totp code with encoded name');
    r = await req(port, 'GET', '/v1/TOTP/keys/mon%20compte', { token: tokenA });
    check(r.status === 200 && r.json?.data?.owner === undefined, 'totp key read hides owner');
    r = await req(port, 'POST', '/v1/TOTP/keys/bad', { token: tokenA, body: { key: 'not base32!!' } });
    check(r.status === 400, 'invalid base32 rejected');

    // TOTP : bornes des paramètres (DATA-21) — l'interface propose 10 à 120 s ; une valeur hors bornes
    // est refusée (400) au lieu d'être remplacée en silence par 30 s ; une valeur absente prend le défaut.
    const totpWith = (name, extra) => req(port, 'POST', `/v1/TOTP/keys/${name}`, { token: tokenA, body: { key: 'JBSWY3DPEHPK3PXP', ...extra } });
    r = await totpWith('p10', { period: 10 });
    check(r.status === 204, 'totp period 10 s accepted (UI minimum)');
    r = await req(port, 'GET', '/v1/TOTP/keys/p10', { token: tokenA });
    check(r.json?.data?.period === 10, 'totp period 10 s stored as 10 (not 30)');
    r = await totpWith('pdef', {});
    r = await req(port, 'GET', '/v1/TOTP/keys/pdef', { token: tokenA });
    check(r.json?.data?.period === 30 && r.json?.data?.digits === 6 && r.json?.data?.algorithm === 'SHA1', 'totp defaults when options absent');
    r = await totpWith('pstr', { period: '60', digits: '8', algorithm: 'sha256' });
    check(r.status === 204, 'totp numeric strings / lowercase algorithm accepted');
    r = await req(port, 'GET', '/v1/TOTP/keys/pstr', { token: tokenA });
    check(r.json?.data?.period === 60 && r.json?.data?.digits === 8 && r.json?.data?.algorithm === 'SHA256', 'totp normalized options stored');
    for (const [label, extra] of [['period 5', { period: 5 }], ['period 121', { period: 121 }], ['period 30.5', { period: 30.5 }],
      ['period abc', { period: 'abc' }], ['digits 9', { digits: 9 }], ['digits 5', { digits: 5 }], ['algorithm MD5', { algorithm: 'MD5' }]]) {
      r = await totpWith('pbad', extra);
      check(r.status === 400, `totp ${label} rejected (400)`);
    }
    r = await req(port, 'GET', '/v1/TOTP/keys/pbad', { token: tokenA });
    check(r.status === 404, 'rejected totp options create no key');

    // LOCALVAULT-3 (TOTP) : graine dont l'intégrité GCM/AAD échoue (blob d'une autre clé) → erreur distincte de 404
    {
      const tk = db.prepare('SELECT name, secret_encrypted, iv FROM totp_keys WHERE name IN (?, ?) ORDER BY name').all('p10', 'pdef');
      db.prepare('UPDATE totp_keys SET secret_encrypted = ?, iv = ? WHERE name = ?').run(tk[1].secret_encrypted, tk[1].iv, tk[0].name);
      r = await req(port, 'GET', `/v1/TOTP/code/${tk[0].name}`, { token: tokenA });
      check(r.status === 500 && r.json?.errors?.[0] === 'decryption failed' && r.json?.data === undefined,
        'LOCALVAULT-3: TOTP seed failing integrity → 500 « decryption failed », not 404 (status=' + r.status + ')');
      db.prepare('UPDATE totp_keys SET secret_encrypted = ?, iv = ? WHERE name = ?').run(tk[0].secret_encrypted, tk[0].iv, tk[0].name);
      r = await req(port, 'GET', `/v1/TOTP/code/${tk[0].name}`, { token: tokenA });
      check(r.status === 200 && /^\d{6}$/.test(r.json?.data?.code || ''), 'restored TOTP seed gives a code again');
      r = await req(port, 'GET', '/v1/TOTP/code/inexistante', { token: tokenA });
      check(r.status === 404, 'LOCALVAULT-3: missing TOTP key still answers 404');
    }

    // Listage d'un dossier (DATA-11) : préfixe exact « dossier/ », sensible à la casse, métacaractères LIKE neutres
    const mount = (name) => req(port, 'POST', `/v1/sys/mounts/${name.split('/').map(encodeURIComponent).join('/')}`, { token: tokenA, body: { type: 'kv', options: { version: '2' } } });
    const put = (engineName, key, data) => req(port, 'POST', `/v1/${engineName.split('/').map(encodeURIComponent).join('/')}/data/${encodeURIComponent(key)}`, { token: tokenA, body: { data } });
    const listOf = async (engineName, folder) => {
      const res = await req(port, 'GET', `/v1/${engineName}/metadata/${folder.split('/').map(encodeURIComponent).join('/')}?list=true`, { token: tokenA });
      return JSON.stringify(res.json?.data?.keys);
    };
    r = await mount('listing');
    check(r.status === 204, 'engine « listing » created');
    for (const k of ['prod/db', 'prod-old/db', 'prod2', 'PROD/api', 'prod/sub/x', 'a_b/x', 'aXb/y', '50%/z', '50x/w']) await put('listing', k, { Password: k });
    check(await listOf('listing', 'prod/') === '["db","sub/"]', 'list prod/ → only its children (' + await listOf('listing', 'prod/') + ')');
    check(await listOf('listing', 'prod') === '["db","sub/"]', 'list prod (no trailing slash) → same children');
    check(await listOf('listing', 'PROD/') === '["api"]', 'list PROD/ is case-sensitive');
    check(await listOf('listing', 'prod/sub/') === '["x"]', 'list nested folder');
    check(await listOf('listing', 'a_b/') === '["x"]', 'list folder with « _ » (LIKE wildcard neutralized)');
    check(await listOf('listing', '50%/') === '["z"]', 'list folder with « % » (LIKE wildcard neutralized)');
    r = await req(port, 'GET', '/v1/listing/metadata?list=true', { token: tokenA });
    check(JSON.stringify(r.json?.data?.keys) === '["50%/","50x/","PROD/","aXb/","a_b/","prod-old/","prod/","prod2"]', 'list engine root unchanged');

    // Suppression d'un coffre et clés TOTP (DATA-8) : les clés TOTP de ses entrées (nommage de l'UI :
    // PRÉFIXE-DU-COFFRE-EN-MAJUSCULES-entrée) sont effacées, sauf si un autre coffre de même préfixe
    // contient une entrée du même nom ; jamais une clé dont le nom égale seulement le nom d'une entrée.
    const totpExists = async (name) => (await req(port, 'GET', `/v1/TOTP/keys/${encodeURIComponent(name)}`, { token: tokenA })).status === 200;
    const unmount = (name) => req(port, 'DELETE', `/v1/sys/mounts/${name.split('/').map(encodeURIComponent).join('/')}`, { token: tokenA });
    await mount('Solo'); await put('Solo', 'compte', { Password: 'p' }); await put('Solo', 'dossier/carte', { Password: 'p' });
    await totpWith('SOLO-compte', {}); await totpWith(encodeURIComponent('SOLO-dossier/carte'), {});
    await mount('Banque'); await mount('users/alice/Banque');
    await put('Banque', 'github', { Password: 'q' }); await put('users/alice/Banque', 'github', { Password: 'p' });
    await totpWith('BANQUE-github', {});
    await mount('autre'); await put('autre', 'github', { Password: 'o' }); await totpWith('AUTRE-github', {});
    await mount('hx'); await put('hx', 'AUTRE-github', { Password: 'note' });
    r = await unmount('Solo');
    check(r.status === 204, 'engine Solo deleted');
    check(!(await totpExists('SOLO-compte')) && !(await totpExists('SOLO-dossier/carte')), 'deleting an engine removes the TOTP keys of its entries (UI naming)');
    await mount('Solo'); await put('Solo', 'compte', { Password: 'nouveau' });
    check(!(await totpExists('SOLO-compte')), 're-created engine does not inherit the old TOTP');
    await unmount('Banque');
    check(await totpExists('BANQUE-github'), 'TOTP shared with users/alice/Banque/github kept when deleting Banque');
    await unmount('hx');
    check(await totpExists('AUTRE-github'), 'TOTP of autre/github kept when deleting an engine holding an entry named AUTRE-github');
    await unmount('users/alice/Banque');
    check(!(await totpExists('BANQUE-github')), 'last engine using BANQUE-github deleted → key removed');

    // LOCALVAULT-2 : nommage ambigu par tiret — « Prod » + « EU-db » et « Prod-EU » + « db » donnent tous deux
    // PROD-EU-db. Supprimer l'un des coffres ne doit pas effacer la graine encore revendiquée par l'autre.
    await mount('Prod'); await mount('Prod-EU');
    await put('Prod', 'EU-db', { Password: 'a' });
    await put('Prod-EU', 'db', { Password: 'b' });
    await totpWith('PROD-EU-db', {});
    r = await unmount('Prod-EU');
    check(r.status === 204, 'engine Prod-EU deleted');
    check(await totpExists('PROD-EU-db'), 'LOCALVAULT-2: deleting Prod-EU keeps PROD-EU-db (claimed by Prod/EU-db)');
    r = await req(port, 'GET', '/v1/TOTP/code/PROD-EU-db', { token: tokenA });
    check(r.status === 200 && /^\d{6}$/.test(r.json?.data?.code || ''), 'LOCALVAULT-2: PROD-EU-db still serves a code');
    await mount('Prod-EU'); await put('Prod-EU', 'db', { Password: 'b' });
    await unmount('Prod');
    check(await totpExists('PROD-EU-db'), 'LOCALVAULT-2: deleting Prod keeps PROD-EU-db (claimed by Prod-EU/db)');
    await unmount('Prod-EU');
    check(!(await totpExists('PROD-EU-db')), 'LOCALVAULT-2: last claimant deleted → PROD-EU-db removed');
    // Une entrée seulement SUPPRIMÉE (soft-delete, encore restaurable) revendique toujours sa clé
    await mount('Ops'); await mount('Ops-B');
    await put('Ops', 'B-x', { Password: 'a' }); await put('Ops-B', 'x', { Password: 'b' });
    await totpWith('OPS-B-x', {});
    await req(port, 'POST', `/v1/Ops/delete/B-x`, { token: tokenA, body: { versions: [1] } });
    await unmount('Ops-B');
    check(await totpExists('OPS-B-x'), 'LOCALVAULT-2: soft-deleted Ops/B-x (restorable) still claims OPS-B-x');
    await unmount('Ops');
    check(!(await totpExists('OPS-B-x')), 'LOCALVAULT-2: OPS-B-x removed with its last engine');

    // Effacement physique en mode WAL : après une suppression DÉFINITIVE (destruction d'un secret, suppression
    // d'un coffre, suppression ou remplacement d'une graine TOTP), les chiffrés effacés ne doivent plus figurer
    // ni dans local-vault.db ni dans local-vault.db-wal (secure_delete ne réécrit que les pages courantes ;
    // le WAL garde les images précédentes jusqu'au point de contrôle)
    {
      // Extraits du texte hexadécimal stocké (chiffré ou IV), cherchés tels quels dans les fichiers de la base
      const slicesOf = (hex) => {
        const s = String(hex || '');
        if (s.length < 80) return s ? [Buffer.from(s, 'utf8')] : [];
        const out = [];
        for (let o = 0; o + 40 <= s.length; o += 80) out.push(Buffer.from(s.slice(o, o + 40), 'utf8'));
        return out;
      };
      const onDisk = (slices) => ['local-vault.db', 'local-vault.db-wal'].map(f => path.join(tmp, f)).filter(f => fs.existsSync(f))
        .some(f => { const buf = fs.readFileSync(f); return slices.some(s => buf.includes(s)); });
      const secretSlices = (engineName, key) => db.prepare('SELECT s.data FROM secrets s JOIN engines e ON e.id = s.engine_id WHERE e.name = ? AND s.key = ?')
        .all(engineName, key).flatMap(row => slicesOf(row.data));
      const totpSlices = (name) => {
        const row = db.prepare('SELECT secret_encrypted FROM totp_keys WHERE name = ?').get(name);
        return row ? slicesOf(row.secret_encrypted) : [];
      };
      const bigNotes = 'N'.repeat(6000); // plusieurs pages (débordement) en plus de la page de la ligne

      // a) destruction d'un secret (DELETE /metadata, toutes les versions)
      await put(engine, 'efface/secret', { Password: 'a-detruire-1', Notes: bigNotes });
      await put(engine, 'efface/secret', { Password: 'a-detruire-2', Notes: bigNotes });
      const destroyed = secretSlices(engine, 'efface/secret');
      check(destroyed.length >= 10 && onDisk(destroyed), 'WAL: precondition, ciphertexts of efface/secret are on disk');
      r = await req(port, 'DELETE', `/v1/${engine}/metadata/${encodeURIComponent('efface/secret')}`, { token: tokenA });
      check(r.status === 204 && secretSlices(engine, 'efface/secret').length === 0, 'WAL: efface/secret destroyed (204, no row left)');
      check(!onDisk(destroyed), 'WAL: destroyed secret no longer present on disk (database + WAL)');

      // b) suppression d'un coffre : ses secrets (cascade) et la graine TOTP de son entrée
      await mount('Efface'); await put('Efface', 'compte', { Password: 'coffre-supprime', Notes: bigNotes });
      await totpWith('EFFACE-compte', {});
      const engineSlices = secretSlices('Efface', 'compte');
      const engineTotp = totpSlices('EFFACE-compte');
      check(engineSlices.length >= 5 && engineTotp.length === 1 && onDisk(engineSlices) && onDisk(engineTotp), 'WAL: precondition, engine data and TOTP seed on disk');
      r = await unmount('Efface');
      check(r.status === 204 && !(await totpExists('EFFACE-compte')), 'WAL: engine Efface deleted with its TOTP key');
      check(!onDisk(engineSlices) && !onDisk(engineTotp), 'WAL: deleted engine secrets and TOTP seed no longer present on disk');

      // c) suppression d'une clé TOTP
      await totpWith('efface-totp', {});
      const deletedSeed = totpSlices('efface-totp');
      check(deletedSeed.length === 1 && onDisk(deletedSeed), 'WAL: precondition, TOTP seed on disk');
      r = await req(port, 'DELETE', '/v1/TOTP/keys/efface-totp', { token: tokenA });
      check(r.status === 204 && !(await totpExists('efface-totp')), 'WAL: TOTP key deleted');
      check(!onDisk(deletedSeed), 'WAL: deleted TOTP seed no longer present on disk');

      // d) remplacement d'une graine TOTP (nouvelle clé sous le même nom) : l'ancienne disparaît, la nouvelle sert
      await totpWith('remplace-totp', {});
      const oldSeed = totpSlices('remplace-totp');
      r = await req(port, 'POST', '/v1/TOTP/keys/remplace-totp', { token: tokenA, body: { key: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' } });
      check(r.status === 204 && oldSeed.length === 1 && !totpSlices('remplace-totp')[0]?.equals(oldSeed[0]), 'WAL: TOTP seed replaced');
      check(!onDisk(oldSeed), 'WAL: replaced TOTP seed no longer present on disk');
      r = await req(port, 'GET', '/v1/TOTP/code/remplace-totp', { token: tokenA });
      check(r.status === 200 && /^\d{6}$/.test(r.json?.data?.code || ''), 'WAL: new TOTP seed serves a code');

      // Rien d'autre n'est effacé : une entrée normale garde toutes ses versions lisibles
      r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb?version=1`, { token: tokenA });
      check(r.status === 200 && r.json?.data?.data?.password === 'p@ss', 'WAL: other entries and their history untouched (serveur/db v1)');
    }

    // capacités et déconnexion
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb`, {});
    check(r.status === 403, 'no token → 403');
    r = await req(port, 'POST', '/v1/auth/token/revoke-self', { token: tokenA });
    check(r.status === 204, 'revoke-self');
    r = await req(port, 'GET', `/v1/${engine}/data/serveur%2Fdb`, { token: tokenA });
    check(r.status === 403, 'revoked token → 403');

    // schéma versionné
    check(db.pragma('user_version', { simple: true }) === 3, 'schema user_version = 3');
    check(db.prepare('PRAGMA table_info(totp_keys)').all().some(c => c.name === 'owner'), 'totp_keys.owner column exists');
    check(db.prepare('PRAGMA table_info(users)').all().some(c => c.name === 'kdf'), 'users.kdf column exists');

    // KDF : nouveau compte créé avec scrypt (mémoire-dur), et déverrouillage fonctionnel (prouvé par les lectures ci-dessus)
    const kdfRow = db.prepare('SELECT kdf FROM users WHERE username = ?').get('alice');
    check(/^scrypt:/.test(kdfRow?.kdf || ''), 'new account uses scrypt KDF (' + (kdfRow?.kdf || 'NULL') + ')');

    // Rétro-compatibilité : un compte « hérité » (kdf NULL) doit pouvoir se connecter en PBKDF2.
    // On insère un utilisateur dont la clé est dérivée en PBKDF2 (comme les versions précédentes).
    {
      const bcrypt = require(path.join(ROOT, 'node_modules/bcryptjs'));
      const { generateSalt } = require(path.join(ROOT, 'electron/localVault/crypto.js'));
      const legacySalt = generateSalt();
      db.prepare('INSERT INTO users (username, password_hash, encryption_salt, is_admin, kdf) VALUES (?, ?, ?, 0, NULL)')
        .run('legacy', bcrypt.hashSync('legacy-pass-123', 12), legacySalt);
      let lr = await req(port, 'POST', '/v1/auth/ldap/login/legacy', { body: { password: 'legacy-pass-123' } });
      check(lr.status === 200 && lr.json?.auth?.client_token, 'legacy (PBKDF2, kdf NULL) account logs in');
    }

    lv.stop();

    // ---- LOCALVAULT-1 : mot de passe de plus de 72 octets UTF-8. bcrypt n'en compare que les 72 premiers ;
    // la clé AES est dérivée du mot de passe ENTIER. Une faute de frappe après le 72e octet doit être refusée
    // dès que le compte a des données chiffrées (ou un témoin de clé), sans toucher au hachage bcrypt stocké.
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-smoke-long-'));
    try {
      app.setPath('userData', tmp2);
      const port2 = await lv.start(0);
      const bcrypt = require(path.join(ROOT, 'node_modules/bcryptjs'));
      const lvCrypto = require(path.join(ROOT, 'electron/localVault/crypto.js'));
      const secretsService = require(path.join(ROOT, 'electron/localVault/secretsService.js'));
      const authService = require(path.join(ROOT, 'electron/localVault/authService.js'));
      const db2 = require(path.join(ROOT, 'electron/localVault/database.js')).getDb();
      const login2 = (user, password) => req(port2, 'POST', `/v1/auth/ldap/login/${encodeURIComponent(user)}`, { body: { password } });
      const encE = (name) => name.split('/').map(encodeURIComponent).join('/');

      const base72 = 'correct horse battery staple '.repeat(3).slice(0, 72);
      const LONG = base72 + 'zebra-42';
      const TYPO = base72 + 'zebrz-42'; // diffère uniquement après le 72e octet
      check(Buffer.byteLength(base72, 'utf8') === 72 && bcrypt.compareSync(TYPO, bcrypt.hashSync(LONG, 4)), 'precondition: bcrypt alone accepts the typo after byte 72');

      // 1) Premier compte (création, avec la confirmation exigée par AUTH-14) : un témoin de clé caché est
      //    écrit, la faute est refusée d'emblée
      r = await req(port2, 'POST', '/v1/auth/ldap/login/longue', { body: { password: LONG, confirm: LONG } });
      check(r.status === 200 && r.json?.auth?.client_token, 'LOCALVAULT-1: first account with a long password created');
      let tLong = r.json?.auth?.client_token;
      const hashBefore = db2.prepare('SELECT password_hash FROM users WHERE username = ?').get('longue').password_hash;
      const personal = 'users/longue/Mes-Secrets';
      r = await req(port2, 'GET', `/v1/${encE(personal)}/metadata?list=true`, { token: tLong });
      check(r.status === 200 && (r.json?.data?.keys || []).includes('.rdvault-keycheck'), 'LOCALVAULT-1: hidden key-check witness written at creation (.rdvault*)');
      r = await login2('longue', TYPO);
      check(r.status === 400 && !r.json?.auth && r.json?.errors?.[0] === 'Identifiants invalides',
        'LOCALVAULT-1: typo after byte 72 rejected on a new account (status=' + r.status + ')');
      r = await login2('longue', 'X' + LONG.slice(1));
      check(r.status === 400, 'typo inside the first 72 bytes still rejected (bcrypt)');

      // 2) Avec des données : le bon mot de passe ouvre, la faute est refusée, rien n'est écrit avec une mauvaise clé
      r = await login2('longue', LONG);
      check(r.status === 200, 'LOCALVAULT-1: correct long password accepted');
      tLong = r.json?.auth?.client_token;
      r = await req(port2, 'POST', `/v1/${encE(personal)}/data/web`, { token: tLong, body: { data: { Password: 'v1' } } });
      check(r.status === 200, 'write with the correct long password');
      r = await login2('longue', TYPO);
      check(r.status === 400 && !r.json?.auth, 'LOCALVAULT-1: typo after byte 72 rejected once data exists');
      r = await login2('longue', LONG);
      tLong = r.json?.auth?.client_token;
      r = await req(port2, 'GET', `/v1/${encE(personal)}/data/web`, { token: tLong });
      check(r.status === 200 && r.json?.data?.data?.Password === 'v1', 'LOCALVAULT-1: data written with the correct password still readable');
      check(db2.prepare('SELECT password_hash FROM users WHERE username = ?').get('longue').password_hash === hashBefore, 'LOCALVAULT-1: stored bcrypt hash unchanged');

      // 3) Compte hérité PBKDF2 (kdf NULL), sans témoin, mot de passe CJK (26 idéogrammes = 78 octets) et une
      //    ligne héritée chiffrée SANS AAD : la vérification s'appuie sur les données existantes du compte
      const CJK = '密'.repeat(24) + '码码';
      const CJK_TYPO = '密'.repeat(24) + '码马';
      const saltA = lvCrypto.generateSalt();
      db2.prepare('INSERT INTO users (username, password_hash, encryption_salt, is_admin, kdf) VALUES (?, ?, ?, 0, NULL)')
        .run('ancien', bcrypt.hashSync(CJK, 10), saltA);
      check(bcrypt.compareSync(CJK_TYPO, db2.prepare('SELECT password_hash FROM users WHERE username = ?').get('ancien').password_hash), 'precondition: bcrypt alone accepts the CJK typo');
      r = await login2('ancien', CJK);
      check(r.status === 200, 'LOCALVAULT-1: account without any encrypted data stays usable (long password)');
      secretsService.createEngine('users/ancien/Perso', 'ancien', '');
      const engA = db2.prepare('SELECT id FROM engines WHERE name = ?').get('users/ancien/Perso').id;
      const keyA = lvCrypto.deriveKeyWithKdfSync(CJK, saltA, null);
      const legacyBlob = lvCrypto.encrypt(JSON.stringify({ Password: 'ancien' }), keyA); // sans AAD (format hérité)
      db2.prepare('INSERT INTO secrets (engine_id, key, version, data, iv) VALUES (?, ?, 1, ?, ?)').run(engA, 'site', legacyBlob.encrypted, legacyBlob.iv);
      r = await login2('ancien', CJK_TYPO);
      check(r.status === 400 && !r.json?.auth, 'LOCALVAULT-1: CJK typo after byte 72 rejected (legacy PBKDF2 account, legacy row without AAD)');
      r = await login2('ancien', CJK);
      check(r.status === 200, 'LOCALVAULT-1: legacy PBKDF2 account with long CJK password logs in');
      const tAnc = r.json?.auth?.client_token;
      r = await req(port2, 'GET', `/v1/${encE('users/ancien/Perso')}/data/site`, { token: tAnc });
      check(r.status === 200 && r.json?.data?.data?.Password === 'ancien', 'legacy row readable (and migrated to AAD)');
      r = await login2('ancien', CJK_TYPO);
      check(r.status === 400, 'LOCALVAULT-1: CJK typo still rejected after the AAD migration');

      // 4) Compte dont des données existent déjà sous DEUX clés (victime du défaut avant correctif) :
      //    aucune donnée existante n'est rendue inaccessible (chaque mot de passe qui déchiffre une ligne ouvre)
      await authService.createUser('mixte', LONG, false);
      const um = db2.prepare('SELECT encryption_salt, kdf FROM users WHERE username = ?').get('mixte');
      secretsService.createEngine('users/mixte/Perso', 'mixte', '');
      const engM = db2.prepare('SELECT id FROM engines WHERE name = ?').get('users/mixte/Perso').id;
      secretsService.writeSecret(engM, 'a', { Password: 'K' }, lvCrypto.deriveKeyWithKdfSync(LONG, um.encryption_salt, um.kdf));
      secretsService.writeSecret(engM, 'b', { Password: 'K2' }, lvCrypto.deriveKeyWithKdfSync(TYPO, um.encryption_salt, um.kdf));
      r = await login2('mixte', LONG);
      check(r.status === 200, 'LOCALVAULT-1: mixed-key account, original password accepted');
      r = await login2('mixte', TYPO);
      check(r.status === 200, 'LOCALVAULT-1: mixed-key account, data already written under the other key stays reachable (no lockout)');
      r = await login2('mixte', base72 + 'autre-99');
      check(r.status === 400, 'LOCALVAULT-1: mixed-key account, a third variant matching no data rejected');

      // 5) Le refus consomme le quota anti-force brute (5 tentatives / 5 min), comme un mauvais mot de passe
      let all400 = true;
      for (let i = 0; i < 5; i++) { r = await login2('longue', TYPO); if (r.status !== 400) all400 = false; }
      r = await login2('longue', LONG);
      check(all400 && r.status === 429, 'LOCALVAULT-1: rejected long-password attempts count toward the rate limit (status=' + r.status + ')');

      lv.stop();
    } finally {
      try { fs.rmSync(tmp2, { recursive: true, force: true }); } catch {}
    }
  } catch (err) {
    console.log('FAIL exception: ' + ((err && err.stack) || err));
    failures++;
  }
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  console.log(failures === 0 ? 'SMOKE OK' : `SMOKE FAILURES: ${failures}`);
  app.exit(failures === 0 ? 0 : 1);
});
