// Tests ADVERSARIAUX du coffre local : entrées hostiles, concurrence, injection SQL,
// traversée de chemin, unicode, gros volumes, isolation multi-utilisateurs.
// Lancement : electron test/smoke/smoke-adversarial.js   (userData temporaire, JAMAIS le vrai coffre)
// Script CommonJS exécuté par Electron (pas un module ES) : le mode strict y garde tout son sens
'use strict'; // eslint-disable-line strict
const { app } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');

const ROOT = path.resolve(__dirname, '..', '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-adv-'));
app.setPath('userData', tmp);
process.env.RDVAULT_LOG_LEVEL = 'error';

let failures = 0;
function check(cond, label) { console.log((cond ? 'PASS ' : 'FAIL ') + label); if (!cond) failures++; }

// `headers` : en-têtes ajoutés/écrasés (une valeur `undefined` supprime l'en-tête, ex. Content-Type)
function req(port, method, p, { token, body, raw, headers } = {}) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? (raw ? body : JSON.stringify(body)) : null;
    const h = {
      'Content-Type': 'application/json',
      ...(token ? { 'X-Vault-Token': token } : {}),
      ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      ...(headers || {})
    };
    for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: h }, (res) => {
      // setEncoding : décodage UTF-8 correct même si un caractère est coupé entre deux chunks de réponse
      let buf = ''; res.setEncoding('utf8'); res.on('data', c => buf += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch {} resolve({ status: res.statusCode, json }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

// Envoie un corps déjà sérialisé (Buffer) en tranches espacées dans le temps → chunks TCP distincts côté serveur
function reqChunked(port, method, p, token, buf, chunkSize) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: {
      'Content-Type': 'application/json', 'X-Vault-Token': token, 'Content-Length': buf.length
    } }, (res) => {
      let b = ''; res.setEncoding('utf8'); res.on('data', c => b += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch {} resolve({ status: res.statusCode, json }); });
    });
    r.on('error', reject);
    (async () => {
      for (let off = 0; off < buf.length; off += chunkSize) {
        r.write(buf.subarray(off, off + chunkSize));
        await new Promise(k => setTimeout(k, 2));
      }
      r.end();
    })().catch(reject);
  });
}
const enc = (e) => e.split('/').map(encodeURIComponent).join('/');

app.whenReady().then(async () => {
  try {
    const lv = require(path.join(ROOT, 'electron/localVault/localVaultServer.js'));
    const authService = require(path.join(ROOT, 'electron/localVault/authService.js'));
    const port = await lv.start(0);

    // admin (premier login : création du compte, confirmation exigée — AUTH-14)
    let r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123', confirm: 'Admin-pass-123' } });
    const tok = r.json.auth.client_token;
    const ENGINE = 'users/admin/Mes-Secrets';

    // ---- 1. Injection SQL dans la clé et la valeur ----
    const sqlKey = "x'; DROP TABLE secrets;--";
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent(sqlKey)}`, { token: tok, body: { data: { username: "a'; DROP TABLE users;--", password: 'p' } } });
    check(r.status === 200, 'injection SQL dans la clé : écriture acceptée sans crash');
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/normal`, { token: tok, body: { data: { username: 'u', password: 'p' } } });
    check(r.status === 200 && r.json?.data?.version === 1, 'tables toujours là après tentative d\'injection');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent(sqlKey)}`, { token: tok });
    check(r.status === 200 && r.json?.data?.data?.username === "a'; DROP TABLE users;--", 'valeur avec SQL lue exactement');

    // ---- 2. Unicode / emoji dans clé et valeurs ----
    const uniKey = 'dossier/é à ✓ 🔐/clé spéciale';
    const uniVal = { username: 'üser🙂', password: '  côté  ', notes: 'ligne1\nligne2\t<xml>&"' };
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent(uniKey)}`, { token: tok, body: { data: uniVal } });
    check(r.status === 200, 'clé unicode : écriture');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent(uniKey)}`, { token: tok });
    check(r.json?.data?.data?.password === '  côté  ' && r.json?.data?.data?.username === 'üser🙂', 'valeurs unicode + espaces de bord préservés');

    // ---- 3. Écritures CONCURRENTES sur la même clé (course sur le numéro de version) ----
    const N = 25;
    await Promise.all(Array.from({ length: N }, (_, i) =>
      req(port, 'POST', `/v1/${enc(ENGINE)}/data/concurrent`, { token: tok, body: { data: { username: 'u', password: 'v' + i } } })
    ));
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/metadata/concurrent`, { token: tok });
    const versions = Object.keys(r.json?.data?.versions || {}).map(Number).sort((a, b) => a - b);
    const sequential = versions.length === N && versions.every((v, i) => v === i + 1);
    check(sequential, `${N} écritures concurrentes → versions 1..${N} séquentielles sans trou ni doublon (eu: ${versions.length})`);

    // ---- 3b. PURGE-35 : écritures concurrentes d'un blob caché « .rdvault-* » (signatures de passkeys en
    //      rafale) → toutes acceptées, numérotation continue, UNE seule version conservée (la dernière) ----
    const hiddenKey = encodeURIComponent('.rdvault-passkeys');
    const hiddenRes = await Promise.all(Array.from({ length: N }, (_, i) =>
      req(port, 'POST', `/v1/${enc(ENGINE)}/data/${hiddenKey}`, { token: tok, body: { data: { items: { 'a.example': [{ credentialId: 'C', signCount: i }] } } } })
    ));
    check(hiddenRes.every(x => x.status === 200), `PURGE-35 : ${N} écritures concurrentes du blob caché acceptées (statuts ${[...new Set(hiddenRes.map(x => x.status))].join(',')})`);
    const hiddenVersions = hiddenRes.map(x => x.json?.data?.version).sort((a, b) => a - b);
    check(hiddenVersions.every((v, i) => v === i + 1), 'PURGE-35 : numéros de version 1..' + N + ' sans doublon malgré la purge');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/metadata/${hiddenKey}`, { token: tok });
    check(JSON.stringify(Object.keys(r.json?.data?.versions || {})) === JSON.stringify([String(N)]) && r.json?.data?.current_version === N,
      'PURGE-35 : une seule version conservée, la dernière (' + JSON.stringify(Object.keys(r.json?.data?.versions || {})) + ')');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/${hiddenKey}?version=1`, { token: tok });
    check(r.status === 404, 'PURGE-35 : ancienne version du blob caché → 404');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/${hiddenKey}`, { token: tok });
    check(r.status === 200 && r.json?.data?.metadata?.version === N, 'PURGE-35 : dernière version lisible');

    // ---- 3c. SECRETS-36 : créations CONCURRENTES d'une même entrée avec options.cas = 0 (deux clients) →
    //      une seule écriture acceptée, les autres refusées (400, message de Vault), aucune n'écrase la première ----
    const casRes = await Promise.all(Array.from({ length: N }, (_, i) =>
      req(port, 'POST', `/v1/${enc(ENGINE)}/data/cas-course`, { token: tok, body: { options: { cas: 0 }, data: { username: 'u', password: 'client-' + i } } })
    ));
    const casOk = casRes.filter(x => x.status === 200);
    const casRefused = casRes.filter(x => x.status === 400 && x.json?.errors?.[0] === 'check-and-set parameter did not match the current version');
    check(casOk.length === 1 && casRefused.length === N - 1,
      `SECRETS-36 : ${N} créations concurrentes cas=0 → 1 acceptée, ${N - 1} refusées (eu ${casOk.length} / ${casRefused.length})`);
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/metadata/cas-course`, { token: tok });
    check(r.json?.data?.current_version === 1 && Object.keys(r.json?.data?.versions || {}).length === 1, 'SECRETS-36 : une seule version écrite');

    // ---- 4. Gros volume (~1,5 Mo, pièce jointe typique) : doit passer (limite relevée à 10 Mio) ----
    const big = 'A'.repeat(1_500_000);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/big`, { token: tok, body: { data: { username: 'u', password: big } } });
    check(r.status === 200, 'gros secret (~1,5 Mo) : écriture acceptée');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/big`, { token: tok });
    check(r.json?.data?.data?.password?.length === big.length, 'gros secret relu intégralement');

    // ---- 5. Corps JSON malformé → 400 (erreur client, pas 500) ----
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/badjson`, { token: tok, body: '{ not json', raw: true });
    check(r.status === 400, 'JSON malformé → 400 (pas 500), status=' + r.status);

    // ---- 6. Corps réellement trop volumineux (> 10 Mio) → rejeté (413 ou reset), jamais stocké ----
    const huge = JSON.stringify({ data: { password: 'B'.repeat(11 * 1024 * 1024) } });
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/toobig`, { token: tok, body: huge, raw: true }).catch(() => ({ status: -1 }));
    check(r.status === 413 || r.status === -1, 'corps > 10 Mio rejeté (413 ou reset), status=' + r.status);
    const chk = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/toobig`, { token: tok });
    check(chk.status === 404, 'corps trop volumineux non stocké (secret toobig absent)');
    // le serveur doit survivre et répondre normalement ensuite
    const alive = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/normal`, { token: tok });
    check(alive.status === 200, 'serveur toujours opérationnel après le corps surdimensionné');

    // ---- 7. Token invalide / absent ----
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/normal`, { token: 'deadbeef'.repeat(8) });
    check(r.status === 403, 'token invalide → 403');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/normal`, {});
    check(r.status === 403, 'sans token → 403');

    // ---- 8. Isolation multi-utilisateurs (non-admin ne lit pas le coffre d'un autre) ----
    // Garde serveur : un nom avec caractère de contrôle est refusé à la création
    for (const bad of ['eve\nadmin', 'eve\u0000', 'eve\u007F', 'eve\u0085']) {
      const cu = await authService.createUser(bad, 'Eve-pass-1234', false);
      check(cu && cu.success === false, `createUser refuse un nom avec caractère de contrôle (${JSON.stringify(bad)})`);
    }
    await authService.createUser('bob', 'Bob-pass-123', false);
    await authService.createUser('carol', 'Carol-pass-123', false);
    const rb = await req(port, 'POST', '/v1/auth/ldap/login/bob', { body: { password: 'Bob-pass-123' } });
    const tbob = rb.json.auth.client_token;
    const rc = await req(port, 'POST', '/v1/auth/ldap/login/carol', { body: { password: 'Carol-pass-123' } });
    const tcarol = rc.json.auth.client_token;
    await req(port, 'POST', '/v1/sys/mounts/users/bob/Perso', { token: tbob, body: { description: 'bob' } });
    r = await req(port, 'POST', `/v1/${enc('users/bob/Perso')}/data/secret1`, { token: tbob, body: { data: { username: 'bob', password: 'bobpass' } } });
    check(r.status === 200, 'bob écrit dans son coffre');
    r = await req(port, 'GET', `/v1/${enc('users/bob/Perso')}/data/secret1`, { token: tcarol });
    check(r.status === 403, 'carol (non-admin) ne lit PAS le coffre de bob → 403');
    // PROPRIÉTÉ DE SÉCURITÉ (mode local) : chaque utilisateur chiffre avec SA clé, dérivée de son
    // mot de passe. L'admin a l'accès ACL mais ne détient pas la clé de bob → il NE PEUT PAS
    // déchiffrer ses secrets (déchiffrement échoue → 404). L'admin ne lit donc jamais les mots de
    // passe des autres en mode local. (La lecture inter-utilisateurs n'a de sens qu'en mode Vault.)
    // LOCALVAULT-3 : cet échec de déchiffrement n'est plus présenté comme « introuvable » (404) mais comme
    // une erreur distincte (500 « decryption failed »), sans aucune donnée ni détail cryptographique.
    r = await req(port, 'GET', `/v1/${enc('users/bob/Perso')}/data/secret1`, { token: tok });
    check(r.status === 500 && r.json?.errors?.length === 1 && r.json.errors[0] === 'decryption failed' && r.json?.data === undefined,
      'admin NE PEUT PAS déchiffrer le secret de bob (chiffrement par-utilisateur) → 500 « decryption failed », status=' + r.status);
    r = await req(port, 'GET', `/v1/${enc('users/bob/Perso')}/data/secret1`, { token: tbob });
    check(r.status === 200 && r.json?.data?.data?.password === 'bobpass', 'bob relit son propre secret → 200');

    // ---- 9. Carol ne peut pas écrire dans le coffre de bob ----
    r = await req(port, 'POST', `/v1/${enc('users/bob/Perso')}/data/pirate`, { token: tcarol, body: { data: { username: 'x', password: 'y' } } });
    check(r.status === 403, 'carol ne peut pas écrire dans le coffre de bob → 403');

    // ---- 10. Confusion de routage : clé ressemblant à une opération (data/metadata) ----
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('metadata/evil')}`, { token: tok, body: { data: { username: 'u', password: 'p' } } });
    const okRoute = r.status === 200;
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('metadata/evil')}`, { token: tok });
    check(okRoute && r.status === 200 && r.json?.data?.data?.password === 'p', 'clé contenant « metadata/ » traitée comme une clé, pas comme une opération');

    // ---- 11. LIKE metacharacters dans un préfixe de liste (pas d'injection de pattern) ----
    await req(port, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('dossierA/s1')}`, { token: tok, body: { data: { password: 'p' } } });
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/metadata/${encodeURIComponent('%')}?list=true`, { token: tok });
    // Le préfixe « % » ne doit pas lister toutes les clés (il est échappé) : aucune clé réelle ne commence par « % »
    const keys = r.json?.data?.keys || [];
    check(Array.isArray(keys) && keys.length === 0, 'préfixe LIKE « % » échappé (ne liste pas tout), n=' + keys.length);

    // ---- 12. Lecture d'une version inexistante → 404 ----
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/normal?version=999`, { token: tok });
    check(r.status === 404, 'version inexistante → 404');

    // ---- 13. TOTP : base32 invalide et nom avec caractères de contrôle ----
    r = await req(port, 'POST', '/v1/TOTP/keys/' + encodeURIComponent('compte\u0001ctrl'), { token: tok, body: { key: 'JBSWY3DPEHPK3PXP' } });
    check(r.status === 400, 'nom TOTP avec caractère de contrôle → 400');

    // ---- 14. CLI : règles d'auto-approbation et validation de chemin (fonctions pures) ----
    const cli = require(path.join(ROOT, 'electron/cliServer.js'));
    check(cli.matchesRule('users/blaze/x', 'users/blaze/*') === true, 'CLI matchesRule wildcard');
    check(cli.matchesRule('users/blazefoo/x', 'users/blaze/*') === false, 'CLI matchesRule ne matche pas un préfixe de chaîne');
    check(cli.matchesRule('users/blaze', 'users/blaze/*') === false, 'CLI matchesRule wildcard exige un enfant');
    check(cli.matchesRule('x/y/z', '*') === true, 'CLI matchesRule « * » couvre tout');
    check(cli.matchesRule('x', '') === false, 'CLI matchesRule règle vide ne matche rien');
    check(cli.matchesRule('a/b/c', 'a/b/c/*') === false, 'CLI matchesRule enfant requis plus profond');
    check(cli.isValidVaultPath('a/../b', 256) === false, 'CLI isValidVaultPath rejette ..');
    check(cli.isValidVaultPath('a\u007Fb', 256) === false, 'CLI isValidVaultPath rejette DEL (0x7F)');
    check(cli.isValidVaultPath('', 256) === false, 'CLI isValidVaultPath rejette vide');
    check(cli.isValidVaultPath('a'.repeat(257), 256) === false, 'CLI isValidVaultPath rejette trop long');
    check(cli.isValidVaultPath('users/blaze/db', 256) === true, 'CLI isValidVaultPath accepte un chemin normal');

    // ---- 15. Config sécurité : enforcement https du proxy RBI (transporte des identifiants) ----
    const cfg = require(path.join(ROOT, 'electron/configLoader.js'));
    check(cfg.sanitizeHttpsUrl('https://proxy.example.com', 'RBI') === 'https://proxy.example.com', 'RBI: https accepté');
    check(cfg.sanitizeHttpsUrl('http://proxy.example.com', 'RBI') === null, 'RBI: http refusé (identifiants en clair)');
    check(cfg.sanitizeHttpsUrl('https://user:pass@proxy.example.com', 'RBI') === null, 'RBI: identifiants dans l\'URL refusés');
    check(cfg.sanitizeHttpsUrl('ftp://proxy', 'RBI') === null, 'RBI: schéma non-https refusé');
    check(cfg.sanitizeHttpsUrl('pas une url', 'RBI') === null, 'RBI: URL invalide refusée');
    check(cfg.sanitizeHttpsUrl('', 'RBI') === null, 'RBI: vide → null');

    // ---- 16. Config sécurité : normalisation des empreintes + domaines de confiance ----
    const crypto = require('crypto');
    const digest = crypto.randomBytes(32);
    check(cfg.normalizeFingerprint('sha256/' + digest.toString('base64')) === digest.toString('hex'), 'empreinte sha256/base64 → hex');
    const hex = digest.toString('hex');
    check(cfg.normalizeFingerprint(hex.replace(/(..)/g, '$1:').slice(0, -1).toUpperCase()) === hex, 'empreinte hex avec « : » et majuscules → normalisée');
    check(cfg.normalizeFingerprint('pas-une-empreinte') === null, 'empreinte invalide → null');
    check(cfg.normalizeFingerprint('ab'.repeat(20)) === null, 'empreinte de mauvaise longueur → null');
    const td = cfg.sanitizeTrustedDomains('localhost, 127.0.0.1, evil .com, , ' + 'a'.repeat(254));
    const tdList = td.split(',').filter(Boolean);
    check(tdList.includes('localhost') && tdList.includes('127.0.0.1'), 'domaines valides conservés');
    check(!tdList.some(d => d.includes(' ')) && !tdList.some(d => d.length > 253), 'domaines invalides/trop longs écartés');

    // ---- 17. Corps > 64 Kio reçu en chunks coupant des caractères UTF-8 multi-octets ----
    // Le serveur doit concaténer les octets AVANT de décoder : aucun U+FFFD ne doit être chiffré.
    const notes = 'éàü😀中文'.repeat(5000); // motif de 16 octets → ~80 Kio
    const utfBody = Buffer.from(JSON.stringify({ data: { username: 'u', password: 'p', notes } }), 'utf8');
    check(utfBody.length > 64 * 1024, 'corps UTF-8 > 64 Kio (' + utfBody.length + ' octets)');
    const CHUNK = 4099; // taille première : des frontières de tranche tombent au milieu de caractères
    let cuts = 0;
    for (let off = CHUNK; off < utfBody.length; off += CHUNK) if ((utfBody[off] & 0xC0) === 0x80) cuts++;
    check(cuts > 0, 'au moins une frontière de chunk coupe un caractère UTF-8 (n=' + cuts + ')');
    r = await reqChunked(port, 'POST', `/v1/${enc(ENGINE)}/data/utf8chunks`, tok, utfBody, CHUNK);
    check(r.status === 200, 'corps UTF-8 en chunks : écriture acceptée, status=' + r.status);
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/utf8chunks`, { token: tok });
    const relu = r.json?.data?.data?.notes;
    check(relu === notes && !relu.includes('�'), 'notes relues strictement identiques (aucun U+FFFD)');

    // ---- 18. Encodage d'URL invalide (%E0%A4%A) → 400, jamais 500 ----
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/%E0%A4%A`, { token: tok });
    check(r.status === 400, 'KV GET : segment %E0%A4%A invalide → 400, status=' + r.status);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/%E0%A4%A`, { token: tok, body: { data: { password: 'p' } } });
    check(r.status === 400, 'KV POST : segment %E0%A4%A invalide → 400, status=' + r.status);
    r = await req(port, 'GET', '/v1/TOTP/keys/%E0%A4%A', { token: tok });
    check(r.status === 400, 'TOTP /keys : nom %E0%A4%A invalide → 400, status=' + r.status);

    // ---- 19. Origine web tierce (http/https non locale) → 403 ; renderer / dev server acceptés ----
    r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' }, headers: { Origin: 'https://evil.example' } });
    check(r.status === 403 && r.json?.errors?.[0] === 'forbidden origin', 'login avec Origin https://evil.example → 403, status=' + r.status);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/evil`, { token: tok, body: { data: { password: 'p' } }, headers: { Origin: 'http://evil.example:8080' } });
    check(r.status === 403, 'écriture KV avec Origin http tierce (même avec token) → 403, status=' + r.status);
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/evil`, { token: tok });
    check(r.status === 404, 'rien n\'a été écrit depuis l\'origine tierce');
    for (const o of ['null', 'file://', 'http://localhost:3000', `http://127.0.0.1:${port}`]) {
      r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' }, headers: { Origin: o } });
      check(r.status === 200, `login avec Origin « ${o} » → 200 (status=${r.status})`);
    }
    r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' } });
    check(r.status === 200, 'login sans en-tête Origin → 200, status=' + r.status);

    // ---- 20. Corps sans Content-Type JSON → 415 ; POST sans corps (revoke-self du renderer) toujours accepté ----
    r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' }, headers: { 'Content-Type': undefined } });
    check(r.status === 415 && r.json?.errors?.[0] === 'unsupported media type', 'login sans Content-Type → 415, status=' + r.status);
    r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' }, headers: { 'Content-Type': 'text/plain' } });
    check(r.status === 415, 'login en text/plain (requête « simple » cross-site) → 415, status=' + r.status);
    r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' }, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
    check(r.status === 200, 'login en application/json; charset=utf-8 → 200, status=' + r.status);
    // Le renderer envoie revoke-self sans corps ni Content-Type (axios, data null) : doit rester accepté
    const rl = await req(port, 'POST', '/v1/auth/ldap/login/carol', { body: { password: 'Carol-pass-123' } });
    r = await req(port, 'POST', '/v1/auth/token/revoke-self', { token: rl.json.auth.client_token, headers: { 'Content-Type': undefined } });
    check(r.status === 204, 'revoke-self sans corps ni Content-Type → 204, status=' + r.status);
    r = await req(port, 'GET', '/v1/auth/token/lookup-self', { token: rl.json.auth.client_token });
    check(r.status === 403, 'token effectivement révoqué → 403');

    // ---- 21. Anti brute-force : seules les vraies tentatives (corps JSON avec mot de passe) comptent ----
    // POST sans corps depuis une origine opaque (Origin « null », formulaire vide) : ne doit PAS verrouiller bob
    const emptyPost = { headers: { Origin: 'null', 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': '0' } };
    let emptyAll400 = true;
    for (let i = 0; i < 6; i++) {
      r = await req(port, 'POST', '/v1/auth/ldap/login/bob', emptyPost);
      if (r.status !== 400) emptyAll400 = false;
    }
    check(emptyAll400, '6 POST login sans corps (Origin null) → 400 chacun');
    r = await req(port, 'POST', '/v1/auth/ldap/login/bob', { body: { password: 'Bob-pass-123' } });
    check(r.status === 200, 'login légitime de bob après 6 POST sans corps → 200 (pas de verrouillage), status=' + r.status);
    // Corps JSON sans mot de passe / mot de passe non-string : 400 et non comptés non plus
    for (let i = 0; i < 6; i++) await req(port, 'POST', '/v1/auth/ldap/login/bob', { body: { password: 42 } });
    r = await req(port, 'POST', '/v1/auth/ldap/login/bob', { body: { password: 'Bob-pass-123' } });
    check(r.status === 200, 'login de bob après 6 corps sans mot de passe string → 200, status=' + r.status);
    // Les vrais échecs restent limités : 5 mauvais mots de passe puis le bon → 429
    await authService.createUser('dave', 'Dave-pass-123', false);
    for (let i = 0; i < 5; i++) await req(port, 'POST', '/v1/auth/ldap/login/dave', { body: { password: 'mauvais-' + i } });
    r = await req(port, 'POST', '/v1/auth/ldap/login/dave', { body: { password: 'Dave-pass-123' } });
    check(r.status === 429, '5 mauvais mots de passe puis le bon → 429 (limiteur actif), status=' + r.status);
    // Tentatives PARALLÈLES : le comptage reste atomique (au plus 5 passent la barrière)
    await authService.createUser('erin', 'Erin-pass-123', false);
    const par = await Promise.all(Array.from({ length: 9 }, (_, i) =>
      req(port, 'POST', '/v1/auth/ldap/login/erin', { body: { password: 'faux-' + i } })));
    const par429 = par.filter(x => x.status === 429).length;
    check(par429 === 4, '9 tentatives parallèles → exactement 4 en 429 (eu: ' + par429 + ')');

    // ---- 22. Corps JSON valide mais non-objet (null, chaîne, tableau) → 400, jamais 500 ni stocké ----
    r = await req(port, 'POST', '/v1/auth/ldap/login/carol', { body: 'null', raw: true });
    check(r.status === 400, 'login corps « null » → 400, status=' + r.status);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/nul`, { token: tok, body: 'null', raw: true });
    check(r.status === 400, 'KV POST corps « null » → 400, status=' + r.status);
    r = await req(port, 'POST', '/v1/TOTP/keys/k1', { token: tok, body: 'null', raw: true });
    check(r.status === 400, 'TOTP POST corps « null » → 400, status=' + r.status);
    r = await req(port, 'POST', '/v1/sys/mounts/coffre-x', { token: tok, body: 'null', raw: true });
    check(r.status === 400, 'sys/mounts POST corps « null » → 400, status=' + r.status);
    r = await req(port, 'POST', '/v1/sys/capabilities-self', { token: tok, body: 'null', raw: true });
    check(r.status === 400, 'capabilities-self corps « null » → 400, status=' + r.status);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/delete/normal`, { token: tok, body: 'null', raw: true });
    check(r.status === 400, 'KV delete corps « null » → 400, status=' + r.status);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/str`, { token: tok, body: '"juste une chaine"', raw: true });
    check(r.status === 400, 'KV POST corps chaîne JSON → 400, status=' + r.status);
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/arr`, { token: tok, body: '[1,2]', raw: true });
    check(r.status === 400, 'KV POST corps tableau JSON → 400, status=' + r.status);
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/str`, { token: tok });
    const rArr = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/arr`, { token: tok });
    check(r.status === 404 && rArr.status === 404, 'corps non-objet non stockés (str/arr absents)');
    r = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/normal`, { token: tok });
    check(r.status === 200, 'serveur toujours opérationnel après les corps non-objet');

    // ---- 23. Noms d'utilisateur / d'engine avec @, espace, accent : décodés UNE fois de bout en bout ----
    const secretsService = require(path.join(ROOT, 'electron/localVault/secretsService.js'));
    const emilie = 'Émilie Dupont@example.com';
    await authService.createUser(emilie, 'Emilie-pass-123', false);
    r = await req(port, 'POST', '/v1/auth/ldap/login/' + encodeURIComponent(emilie), { body: { password: 'Emilie-pass-123' } });
    check(r.status === 200 && r.json?.auth?.metadata?.username === emilie, 'login « Émilie Dupont@example.com » encodé → 200, username décodé, status=' + r.status);
    const temi = r.json?.auth?.client_token;
    r = await req(port, 'GET', '/v1/auth/token/lookup-self', { token: temi });
    check(r.json?.data?.entity_name === emilie, 'lookup-self : entity_name décodé (' + r.json?.data?.entity_name + ')');
    r = await req(port, 'POST', `/v1/sys/mounts/${enc(`users/${emilie}/Perso`)}`, { token: temi, body: { description: 'perso' } });
    check(r.status === 204, 'création d\'engine users/<émilie>/Perso → 204, status=' + r.status);
    r = await req(port, 'GET', '/v1/sys/mounts', { token: temi });
    const emiMount = Object.keys(r.json || {}).find(m => m === `users/${emilie}/Perso/`);
    check(!!emiMount, 'engine listé sous son nom décodé (users/Émilie Dupont@example.com/Perso/)');
    const emiEngine = (emiMount || '').replace(/\/$/, '');
    r = await req(port, 'POST', `/v1/${enc(emiEngine)}/data/site1`, { token: temi, body: { data: { username: 'e', password: 'p1' } } });
    check(r.status === 200, 'écriture via le nom listé ré-encodé (comme vaultApi) → 200, status=' + r.status);
    r = await req(port, 'GET', `/v1/${enc(emiEngine)}/data/site1`, { token: temi });
    check(r.status === 200 && r.json?.data?.data?.password === 'p1', 'lecture via le nom listé ré-encodé → 200');
    r = await req(port, 'GET', `/v1/${enc(emiEngine)}/metadata?list=true`, { token: temi });
    check(r.status === 200 && (r.json?.data?.keys || []).includes('site1'), 'listing de l\'engine → site1 présent');
    // Engine avec espace créé par l'admin : même nom à la création, au listing et à l'écriture
    r = await req(port, 'POST', `/v1/sys/mounts/${enc('Mes Secrets')}`, { token: tok, body: {} });
    check(r.status === 204, 'création d\'engine « Mes Secrets » → 204');
    r = await req(port, 'GET', '/v1/sys/mounts', { token: tok });
    check(Object.keys(r.json || {}).includes('Mes Secrets/'), 'engine « Mes Secrets » listé décodé');
    r = await req(port, 'POST', `/v1/${enc('Mes Secrets')}/data/x`, { token: tok, body: { data: { password: 'x' } } });
    const rx = await req(port, 'GET', `/v1/${enc('Mes Secrets')}/data/x`, { token: tok });
    check(r.status === 200 && rx.status === 200, 'écriture/lecture dans « Mes Secrets » → 200');
    // Pas de double décodage : un « % » littéral dans une clé KV ou un nom TOTP reste valide
    r = await req(port, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('taux 100%')}`, { token: tok, body: { data: { password: 'pc' } } });
    const rpc = await req(port, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('taux 100%')}`, { token: tok });
    check(r.status === 200 && rpc.json?.data?.data?.password === 'pc', 'clé KV « taux 100% » écrite/relue (pas de double décodage)');
    r = await req(port, 'POST', '/v1/TOTP/keys/' + encodeURIComponent('compte 100%'), { token: tok, body: { key: 'JBSWY3DPEHPK3PXP' } });
    const rtc = await req(port, 'GET', '/v1/TOTP/code/' + encodeURIComponent('compte 100%'), { token: tok });
    check(r.status === 204 && rtc.status === 200, 'nom TOTP « compte 100% » créé et lu (pas de double décodage)');
    // Encodage invalide dans un nom d'engine ou d'utilisateur → 400 (rien n'est créé)
    r = await req(port, 'POST', '/v1/sys/mounts/%E0%A4%A', { token: tok, body: {} });
    check(r.status === 400, 'création d\'engine au nom mal encodé → 400, status=' + r.status);
    r = await req(port, 'GET', '/v1/sys/mounts', { token: tok });
    check(!Object.keys(r.json || {}).some(m => m.includes('%E0')), 'aucun engine mal encodé créé');
    r = await req(port, 'POST', '/v1/auth/ldap/login/%E0%A4%A', { body: { password: 'xxxxxxxx' } });
    check(r.status === 400, 'login avec username mal encodé → 400, status=' + r.status);

    // ---- 24. Compatibilité ascendante : compte et engines créés AVANT le décodage (noms stockés encodés) ----
    const legacyName = 'legacy%40example.com'; // nom tel que stocké par les versions précédentes
    await authService.createUser(legacyName, 'Legacy-pass-123', false);
    secretsService.createEngine(`users/${legacyName}/Mes-Secrets`, legacyName, 'Coffre personnel');
    secretsService.createEngine('Ancien%20Coffre', 'admin', '');
    r = await req(port, 'POST', '/v1/auth/ldap/login/' + encodeURIComponent('legacy@example.com'), { body: { password: 'Legacy-pass-123' } });
    check(r.status === 200 && r.json?.auth?.metadata?.username === legacyName, 'compte hérité « legacy%40example.com » : login via la saisie « legacy@example.com » → 200, status=' + r.status);
    const tleg = r.json?.auth?.client_token;
    r = await req(port, 'GET', '/v1/auth/token/lookup-self', { token: tleg });
    check(r.json?.data?.entity_name === legacyName, 'compte hérité : entity_name inchangé (nom stocké)');
    r = await req(port, 'POST', `/v1/${enc(`users/${legacyName}/Mes-Secrets`)}/data/site1`, { token: tleg, body: { data: { password: 'lp' } } });
    const rleg = await req(port, 'GET', `/v1/${enc(`users/${legacyName}/Mes-Secrets`)}/data/site1`, { token: tleg });
    check(r.status === 200 && rleg.json?.data?.data?.password === 'lp', 'engine hérité au nom encodé accessible via le nom listé ré-encodé → 200');
    r = await req(port, 'POST', `/v1/${enc('Ancien%20Coffre')}/data/y`, { token: tok, body: { data: { password: 'y' } } });
    check(r.status === 200, 'engine hérité « Ancien%20Coffre » accessible via le nom listé ré-encodé → 200, status=' + r.status);
    r = await req(port, 'POST', '/v1/auth/ldap/login/admin', { body: { password: 'Admin-pass-123' } });
    check(r.status === 200 && r.json?.auth?.metadata?.username === 'admin', 'username ASCII simple inchangé (admin)');

    // ---- 26. Nom d'engine avec caractères de contrôle (C0, DEL, C1) ou vide après trim → 400, rien créé ----
    r = await req(port, 'POST', '/v1/sys/mounts/Nom%0AEvil', { token: tok, body: {} });
    check(r.status === 400, 'création d\'engine « Nom\\nEvil » (%0A) → 400, status=' + r.status);
    for (const [seg, label] of [['Nom%00Nul', 'NUL (C0)'], ['Tab%09Nom', 'tabulation (C0)'], ['Del%7FNom', 'DEL'], ['Nel%C2%85Nom', 'NEL U+0085 (C1)'], ['%20%20%20', 'espaces seuls']]) {
      r = await req(port, 'POST', '/v1/sys/mounts/' + seg, { token: tok, body: {} });
      check(r.status === 400, `création d'engine avec ${label} → 400, status=${r.status}`);
    }
    r = await req(port, 'GET', '/v1/sys/mounts', { token: tok });
    const ctlMounts = Object.keys(r.json || {}).filter(m => /[\u0000-\u001F\u007F-\u009F]/.test(m) || !m.replace(/\/$/, '').trim()); // eslint-disable-line no-control-regex
    check(r.status === 200 && ctlMounts.length === 0, 'aucun engine au nom avec caractère de contrôle ou vide créé (n=' + ctlMounts.length + ')');
    check(secretsService.createEngine('Abc\u009Bdef', 'admin', '').success === false, 'secretsService.createEngine rejette un caractère C1 (U+009B) en appel direct');
    // Nom normal (accents, espaces) : toujours accepté
    const normalName = 'Coffre Équipe été';
    r = await req(port, 'POST', `/v1/sys/mounts/${enc(normalName)}`, { token: tok, body: {} });
    check(r.status === 204, 'création d\'engine « Coffre Équipe été » (accents, espaces) → 204, status=' + r.status);
    r = await req(port, 'GET', '/v1/sys/mounts', { token: tok });
    check(Object.keys(r.json || {}).includes(normalName + '/'), 'engine « Coffre Équipe été » listé sous son nom exact');

    lv.stop();

    // ---- 25. Premier lancement (base vide) avec un e-mail comme identifiant : coffre personnel utilisable ----
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-adv2-'));
    try {
      app.setPath('userData', tmp2);
      const port2 = await lv.start(0);
      const jean = 'jean.dupont@example.com';
      r = await req(port2, 'POST', '/v1/auth/ldap/login/' + encodeURIComponent(jean), { body: { password: 'Jean-pass-123', confirm: 'Jean-pass-123' } });
      check(r.status === 200 && r.json?.auth?.metadata?.username === jean, 'premier login « jean.dupont@example.com » → admin créé sous le nom décodé, status=' + r.status);
      const tjean = r.json?.auth?.client_token;
      r = await req(port2, 'GET', '/v1/sys/mounts', { token: tjean });
      const jm = Object.keys(r.json || {});
      check(jm.length === 1 && jm[0] === `users/${jean}/Mes-Secrets/`, 'engine personnel listé « users/jean.dupont@example.com/Mes-Secrets/ » (' + jm.join(',') + ')');
      const jEngine = (jm[0] || '').replace(/\/$/, '');
      r = await req(port2, 'GET', `/v1/${enc(jEngine)}/metadata?list=true`, { token: tjean });
      check(r.status === 200, 'listing du coffre personnel (URL de vaultApi) → 200, status=' + r.status);
      r = await req(port2, 'POST', `/v1/${enc(jEngine)}/data/site1`, { token: tjean, body: { data: { username: 'j', password: 'jp' } } });
      const rj = await req(port2, 'GET', `/v1/${enc(jEngine)}/data/site1`, { token: tjean });
      check(r.status === 200 && rj.json?.data?.data?.password === 'jp', 'écriture/lecture dans le coffre personnel → 200');
      lv.stop();
    } finally {
      try { fs.rmSync(tmp2, { recursive: true, force: true }); } catch {}
    }

    // ---- 27. AUTH-14 : créations SIMULTANÉES du premier compte (base vide) → un seul compte créé ----
    //      (double clic sur « Créer », ou un autre processus local) : jamais deux administrateurs ni d'erreur 500.
    //      La requête du même nom, en attente, se connecte ; celle d'un autre nom reçoit « identifiants invalides ».
    const tmp3 = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-adv3-'));
    try {
      app.setPath('userData', tmp3);
      const port3 = await lv.start(0);
      const create = (user, pw) => req(port3, 'POST', '/v1/auth/ldap/login/' + user, { body: { password: pw, confirm: pw } });
      const race = await Promise.all([create('alice', 'Alice-pass-123'), create('alice', 'Alice-pass-123'), create('bob', 'Bob-pass-1234'), create('carol', 'Carol-pass-123')]);
      const statuses = race.map(x => x.status);
      const users = require(path.join(ROOT, 'electron/localVault/database.js')).getDb().prepare('SELECT username, is_admin FROM users').all();
      check(users.length === 1 && users[0].is_admin === 1, 'AUTH-14 : 4 créations simultanées → un seul compte (administrateur) créé (' + users.map(u => u.username).join(',') + ')');
      check(!statuses.includes(500), 'AUTH-14 : aucune erreur 500 (statuts ' + statuses.join(',') + ')');
      const winner = users[0] ? users[0].username : '';
      const names = ['alice', 'alice', 'bob', 'carol'];
      check(names.every((n, i) => (n === winner ? statuses[i] === 200 : statuses[i] === 400)),
        'AUTH-14 : requêtes du compte créé (« ' + winner + ' ») → 200, autres noms → 400 (statuts ' + statuses.join(',') + ')');
      r = await req(port3, 'GET', '/v1/sys/mounts', { token: race[names.indexOf(winner)]?.json?.auth?.client_token });
      check(r.status === 200 && Object.keys(r.json || {}).length === 1, 'AUTH-14 : un seul coffre personnel créé (' + Object.keys(r.json || {}).join(',') + ')');
      lv.stop();
    } finally {
      try { fs.rmSync(tmp3, { recursive: true, force: true }); } catch {}
    }
  } catch (err) {
    console.log('FAIL exception: ' + ((err && err.stack) || err));
    failures++;
  }
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  console.log(failures === 0 ? 'ADVERSARIAL OK' : `ADVERSARIAL FAILURES: ${failures}`);
  app.exit(failures === 0 ? 0 : 1);
});
