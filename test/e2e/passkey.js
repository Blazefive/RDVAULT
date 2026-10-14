// Test de bout en bout des passkeys STOCKÉES DANS LE COFFRE : app RDVAULT réelle
// (coffre local temporaire) + extension + page WebAuthn locale. Création puis
// authentification, avec vérification de la signature dans la page, et contrôle que
// la passkey a bien été écrite dans le coffre chiffré (et pas dans le navigateur).
// Puis plusieurs comptes pour le même rpId : sélecteur de compte (flux « discoverable »
// sans allowCredentials), choix du second compte, assertion signée avec SA clé.
// Robustesse / sécurité : coffre indisponible → create() rejeté (aucune attestation orpheline) ;
// anti-clickjacking (clic trop tôt, fenêtre rendue invisible, recouverte ou masquée par la page) ;
// médiation « conditional » laissée au navigateur ; challenge / allowCredentials en sous-vue
// typée ; iframe cross-origin sans délégation Permissions-Policy.
// Drapeau UV (décision produit : coffre déverrouillé par le mot de passe maître = utilisateur vérifié) :
// « serveur exigeant UV » — userVerification « required » servi par RDVAULT, enregistrement puis
// authentification contrôlés côté test comme le ferait un serveur (@simplewebauthn, réglage par défaut
// requireUserVerification) : challenge, origine, rpIdHash, UP + UV, signature, compteur.
// PURGE-35 : le blob .rdvault-passkeys ne garde qu'une version après créations et signatures.
// EXT-26 : coffre indisponible → fenêtre explicite, bouton RDVAULT désactivé. EXT-21 : AbortSignal et délai
// du site (authentificateur virtuel CDP) → fenêtre fermée, aucune passkey orpheline. EXT-24 : fenêtre au clavier
// (focus, Tab bouclé, Échap, focus rendu) et dans l'arbre d'accessibilité.
// Lancement : E2E_BROWSER=<chrome> node test/e2e/passkey.js
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES
/* global rawId, pubKey, bufToB64u, b64uToBuf, derToRaw */ // globales de test/e2e/site/passkey.html, utilisées dans page.evaluate
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const net = require('net');
const nodeCrypto = require('crypto');
const { spawn } = require('child_process');
const { appWrapperPath, loginInApp, removeTempDir, portFree, waitSyncPortFree, assertSyncPortOwner, SYNC_PORT } = require('./app-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const E2E = __dirname;
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const CHROME = process.env.E2E_BROWSER;
if (!CHROME) { console.error('E2E_BROWSER manquant'); process.exit(2); }
const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
const electronPath = require(path.join(ROOT, 'node_modules/electron'));
const SITE_PORT = 8443, APP_DEBUG_PORT = 9338;
// Nom avec « . » (PASSKEYS-16) : l'ancien code l'assainissait (« e2edupont ») et écrivait les
// passkeys dans le premier coffre « users/… » de la liste — ici OTHER_ENGINE, créé avant la connexion
const USER = 'e2e.dupont', PASS = 'E2e-password-123', ENGINE = `users/${USER}/Mes-Secrets`;
const OTHER_ENGINE = 'users/aaa/Perso';

let failures = 0;
const log = (s) => process.stdout.write(s + '\n');
const check = (c, l) => { log((c ? 'PASS ' : 'FAIL ') + l); if (!c) failures++; };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const enc = (e) => e.split('/').map(encodeURIComponent).join('/');
// Fenêtre RDVAULT « armée » : visible depuis ≥ 500 ms (anti-clickjacking) — marge incluse
const ARM_WAIT = 1000;

function waitPort(p, t = 30000) { const s = Date.now(); return new Promise((res, rej) => { (function tr() { const c = net.connect(p, '127.0.0.1'); c.once('connect', () => { c.destroy(); res(); }); c.once('error', () => { c.destroy(); Date.now() - s > t ? rej(new Error('port ' + p)) : setTimeout(tr, 300); }); })(); }); }
function vreq(port, method, p, token, body) { return new Promise((res, rej) => { const d = body ? JSON.stringify(body) : null; const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Vault-Token': token } : {}), ...(d ? { 'Content-Length': Buffer.byteLength(d) } : {}) } }, x => { let b = ''; x.on('data', c => b += c); x.on('end', () => { let j = null; try { j = JSON.parse(b); } catch {} res({ status: x.statusCode, json: j }); }); }); r.on('error', rej); if (d) r.write(d); r.end(); }); }

// Nœuds d'une classe donnée (y compris dans les shadow roots FERMÉS via CDP pierce), avec leur texte
async function shadowHits(cdp, cls) {
  const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
  const hits = [];
  const txt = (n) => (n.nodeType === 3 ? (n.nodeValue || '') : '') + (n.children || []).map(txt).join('');
  (function w(n) { const a = n.attributes || []; for (let i = 0; i < a.length; i += 2) if (a[i] === 'class' && a[i + 1].split(/\s+/).includes(cls)) { hits.push({ nodeId: n.nodeId, text: txt(n) }); return; } (n.children || []).forEach(w); (n.shadowRoots || []).forEach(w); })(root);
  return hits;
}
// Centre du premier nœud de la classe (ou de celui contenant `text`), null si absent avant le délai
async function findShadow(page, cls, t = 8000, text = null, poll = 300) {
  const s = Date.now();
  while (Date.now() - s < t) {
    const cdp = await page.createCDPSession();
    try {
      const hits = await shadowHits(cdp, cls);
      const hit = text ? hits.find(h => h.text.includes(text)) : hits[0];
      if (hit) { const { model } = await cdp.send('DOM.getBoxModel', { nodeId: hit.nodeId }); const q = model.content; return { x: (q[0] + q[4]) / 2, y: (q[1] + q[5]) / 2 }; }
    } catch {} finally { try { await cdp.detach(); } catch {} }
    await sleep(poll);
  }
  return null;
}
// Clic RÉEL (événement isTrusted) sur le premier nœud de la classe, ou sur celui contenant `text`,
// une fois la fenêtre armée (comme un utilisateur qui lit avant de cliquer)
async function clickShadow(page, cls, t = 8000, text = null) {
  if (!await findShadow(page, cls, t, text)) return false;
  await sleep(ARM_WAIT);
  const p = await findShadow(page, cls, 2000, text);
  if (!p) return false;
  await page.mouse.click(p.x, p.y);
  return true;
}
// Texte du premier nœud de la classe (contenant `text` si donné), null si absent avant le délai
async function shadowText(page, cls, t = 8000, text = null) {
  const s = Date.now();
  while (Date.now() - s < t) {
    const cdp = await page.createCDPSession();
    try {
      const hits = await shadowHits(cdp, cls);
      const hit = text ? hits.find(h => h.text.includes(text)) : hits[0];
      if (hit) return hit.text;
    } catch {} finally { try { await cdp.detach(); } catch {} }
    await sleep(300);
  }
  return null;
}
// Valeur d'un attribut du premier nœud de la classe (null si absent)
async function shadowAttr(page, cls, attr) {
  const cdp = await page.createCDPSession();
  try {
    const hits = await shadowHits(cdp, cls);
    if (!hits[0]) return null;
    const { attributes } = await cdp.send('DOM.getAttributes', { nodeId: hits[0].nodeId });
    const i = attributes.indexOf(attr);
    return i >= 0 && i % 2 === 0 ? attributes[i + 1] : null;
  } catch { return null; } finally { try { await cdp.detach(); } catch {} }
}
/** Arbre d'accessibilité de Chrome (shadow roots fermés compris), à plat */
async function axNodes(page) {
  const out = [];
  (function walk(n) { if (!n) return; out.push(n); (n.children || []).forEach(walk); })(await page.accessibility.snapshot({ interestingOnly: false }));
  return out;
}
// Nombre de nœuds de la classe une fois qu'au moins un est affiché (0 si rien avant le délai)
async function countShadow(page, cls, t = 8000) {
  const s = Date.now();
  while (Date.now() - s < t) {
    const cdp = await page.createCDPSession();
    try { const n = (await shadowHits(cdp, cls)).length; if (n) return n; } catch {} finally { try { await cdp.detach(); } catch {} }
    await sleep(300);
  }
  return 0;
}
const result = (page) => page.$eval('#result', el => el.textContent);
// get() lancé dans la page sans attendre (la fenêtre bloque la promesse) ; état lu dans window[key]
const startGet = (page, key, opts = {}) => page.evaluate((key, opts) => {
  window[key] = 'pending';
  const publicKey = { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: window.location.hostname, timeout: 60000 };
  if (opts.alice) publicKey.allowCredentials = [{ type: 'public-key', id: rawId }]; // rawId : passkey créée par #reg
  navigator.credentials.get({ publicKey }).then(a => { window[key] = 'resolved ' + a.id; }, e => { window[key] = 'rejected ' + e.name; });
}, key, opts);
async function waitState(page, key, t = 8000) {
  let st = 'pending';
  for (const s = Date.now(); Date.now() - s < t; await sleep(200)) { st = await page.evaluate((k) => window[k], key); if (st !== 'pending') break; }
  return st;
}

// ---------- Partie « serveur » (relying party) du cas « serveur exigeant UV » ----------
// Vérifications d'un serveur WebAuthn qui impose la vérification de l'utilisateur, comme
// @simplewebauthn/server avec son réglage par défaut (requireUserVerification: true).
function cborDecode(bytes) {
  let i = 0;
  function read() {
    const b = bytes[i++]; const major = b >> 5; let n = b & 0x1f;
    if (n === 24) n = bytes[i++];
    else if (n === 25) { n = (bytes[i++] << 8) | bytes[i++]; }
    else if (n === 26) { n = ((bytes[i++] << 24) | (bytes[i++] << 16) | (bytes[i++] << 8) | bytes[i++]) >>> 0; }
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2) { const v = bytes.slice(i, i + n); i += n; return v; }
    if (major === 3) { const v = bytes.slice(i, i + n); i += n; return new TextDecoder().decode(v); }
    if (major === 5) { const m = new Map(); for (let k = 0; k < n; k++) { const key = read(); m.set(key, read()); } return m; }
    throw new Error('cbor major ' + major);
  }
  return read();
}
const b64uBuf = (s) => Buffer.from(String(s || ''), 'base64url');
const sha256 = (b) => nodeCrypto.createHash('sha256').update(b).digest();
// Contrôles communs : clientDataJSON (type, challenge, origine) et authenticatorData (rpIdHash, UP, UV)
function rpCheckCommon(errors, cdBuf, ad, type, { challenge, origin, rpId }) {
  let cd = {};
  try { cd = JSON.parse(cdBuf.toString('utf8')); } catch { errors.push('clientDataJSON illisible'); }
  if (cd.type !== type) errors.push('type ' + cd.type);
  if (cd.challenge !== challenge) errors.push('challenge');
  if (cd.origin !== origin) errors.push('origine ' + cd.origin);
  if (ad.length < 37 || !ad.subarray(0, 32).equals(sha256(rpId))) errors.push('rpIdHash');
  if (!(ad[32] & 0x01)) errors.push('UP absent');
  if (!(ad[32] & 0x04)) errors.push('UV absent (vérification de l\'utilisateur exigée)');
}
function rpVerifyRegistration(json, expected) {
  const errors = [];
  try {
    const att = cborDecode(new Uint8Array(b64uBuf(json.response.attestationObject)));
    const ad = Buffer.from(att.get('authData'));
    rpCheckCommon(errors, b64uBuf(json.response.clientDataJSON), ad, 'webauthn.create', expected);
    if (!(ad[32] & 0x40)) errors.push('AT absent');
    const credIdLen = ad.readUInt16BE(53);
    const credentialId = ad.subarray(55, 55 + credIdLen).toString('base64url');
    if (credentialId !== json.id) errors.push('credentialId');
    const cose = cborDecode(new Uint8Array(ad.subarray(55 + credIdLen)));
    if (cose.get(3) !== -7) errors.push('alg ' + cose.get(3));
    const publicKey = nodeCrypto.createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
      x: Buffer.from(cose.get(-2)).toString('base64url'), y: Buffer.from(cose.get(-3)).toString('base64url') } });
    return { ok: errors.length === 0, errors, flags: ad[32], credentialId, publicKey, counter: ad.readUInt32BE(33) };
  } catch (e) { errors.push('exception ' + (e && e.message)); return { ok: false, errors, flags: -1 }; }
}
function rpVerifyAuthentication(json, expected) {
  const errors = [];
  try {
    if (json.id !== expected.credentialId) errors.push('credentialId');
    const cdBuf = b64uBuf(json.response.clientDataJSON);
    const ad = b64uBuf(json.response.authenticatorData);
    rpCheckCommon(errors, cdBuf, ad, 'webauthn.get', expected);
    const counter = ad.readUInt32BE(33);
    if (!(counter > expected.prevCounter)) errors.push('compteur ' + counter);
    const signed = Buffer.concat([ad, sha256(cdBuf)]);
    if (!nodeCrypto.verify('sha256', signed, { key: expected.publicKey, dsaEncoding: 'der' }, b64uBuf(json.response.signature))) errors.push('signature');
    return { ok: errors.length === 0, errors, flags: ad[32], counter };
  } catch (e) { errors.push('exception ' + (e && e.message)); return { ok: false, errors, flags: -1 }; }
}

async function main() {
  // SITES-22 : le port de synchronisation doit être libre AVANT tout lancement (3 nouveaux essais à 60 s,
  // hors délai global) : une autre instance RDVAULT (instance réelle appairée, autre test en parallèle)
  // servirait l'extension de test, fausserait le cas « coffre indisponible » et pourrait recevoir ses passkeys.
  try { await waitSyncPortFree({ log }); } catch (e) { log('FAIL ' + e.message); log('PASSKEY FAILURES: 1'); process.exit(1); }
  const t0 = Date.now();
  const tmp =fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-pk-'));
  const portFile = path.join(tmp, 'port.txt');
  const cfg = path.join(ROOT, 'config.cfg'); const had = fs.existsSync(cfg);
  // config.cfg n'est réécrit (avec sauvegarde) que s'il diffère de la config de test : aucun fichier de
  // sauvegarde ni course avec d'autres harnais lancés en parallèle (même règle que run.js)
  const WANTED_CFG = 'APP_MODE=local\nLANG=fr\n';
  let rewroteConfig = false;
  let site, app, browser, appBrowser;
  // Nettoyage commun (fin normale, exception OU timeout global) : config.cfg restauré d'abord,
  // puis processus arrêtés — un timeout ne doit jamais laisser le projet modifié
  let finished = false;
  const finish = async () => {
    if (finished) return; finished = true;
    try { if (rewroteConfig) { if (had) fs.renameSync(cfg + '.pk-backup', cfg); else fs.unlinkSync(cfg); } } catch {}
    try { if (appBrowser) appBrowser.disconnect(); } catch {}
    try { if (app) app.kill(); } catch {}
    try { if (site) site.kill(); } catch {}
    try { if (browser) await Promise.race([browser.close(), sleep(10000)]); } catch {}
    // Dossier temporaire (profil Chrome, coffre de test) supprimé une fois l'application arrêtée ;
    // ré-essais le temps que Windows libère les fichiers des processus terminés
    await removeTempDir(tmp, app);
    log((failures === 0 ? 'PASSKEY OK' : 'PASSKEY FAILURES: ' + failures) + ' (' + Math.round((Date.now() - t0) / 1000) + ' s)');
    process.exit(failures === 0 ? 0 : 1);
  };
  setTimeout(() => { log('FAIL timeout global 300s'); failures++; finish(); }, 300000).unref();
  try {
    if (!had || fs.readFileSync(cfg, 'utf8') !== WANTED_CFG) {
      if (had) fs.copyFileSync(cfg, cfg + '.pk-backup');
      fs.writeFileSync(cfg, WANTED_CFG);
      rewroteConfig = true;
    }
    site = spawn(process.execPath, [path.join(E2E, 'server.js')], { stdio: 'ignore' });
    await waitPort(SITE_PORT);
    browser = await puppeteer.launch({ executablePath: CHROME, headless: false, userDataDir: path.join(tmp, 'chrome'), defaultViewport: null, ignoreDefaultArgs: ['--disable-extensions', '--enable-automation'], args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT, '--ignore-certificate-errors', '--no-first-run', '--no-default-browser-check', '--window-size=900,700'] });
    const sw = await browser.waitForTarget(t => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 });
    const extId = new URL(sw.url()).hostname;

    // 0. Coffre INDISPONIBLE (app RDVAULT pas encore lancée) : la clé privée ne peut être stockée
    //    nulle part → jamais une attestation renvoyée au site pour une passkey perdue. EXT-26 : la
    //    fenêtre le dit (« RDVAULT est fermé ou verrouillé… ») et n'active pas « Créer dans RDVAULT »
    //    (le clic aboutissait à un NotAllowedError muet) ; Annuler → NotAllowedError standard.
    const page0 = await browser.newPage();
    await page0.goto('https://localhost:8443/passkey.html', { waitUntil: 'load' });
    await sleep(1000);
    // Seule étape où l'extension de test tourne sans l'application de test : le port doit être encore libre,
    // sinon la passkey partirait vers l'instance qui vient de l'ouvrir (son coffre, pas celui du test)
    if (!(await portFree(SYNC_PORT))) throw new Error('port ' + SYNC_PORT + ' ouvert par une autre instance RDVAULT pendant la préparation — test interrompu');
    await page0.click('#reg');
    const closedMsg = await shadowText(page0, 'er', 15000, 'RDVAULT est fermé ou verrouillé');
    check(!!closedMsg, 'coffre indisponible : la fenêtre explique « RDVAULT est fermé ou verrouillé… » (' + (closedMsg || 'absent').slice(0, 60) + ')');
    const okDisabled = await shadowAttr(page0, 'ok', 'disabled');
    check(okDisabled !== null, 'coffre indisponible : « Créer dans RDVAULT » désactivé');
    const okPos = await findShadow(page0, 'ok', 3000);
    if (okPos) await page0.mouse.click(okPos.x, okPos.y); // clic réel sur le bouton désactivé : sans effet
    await sleep(1500);
    let res0 = await result(page0);
    check(!/REG_OK|REG_FAIL/.test(res0), 'coffre indisponible : clic sur le bouton désactivé sans effet, fenêtre toujours ouverte (' + res0.slice(0, 40) + ')');
    check(await clickShadow(page0, 'ca'), 'coffre indisponible : Annuler cliqué');
    for (let i = 0; i < 30; i++) { res0 = await result(page0); if (/REG_OK|REG_FAIL/.test(res0)) break; await sleep(300); }
    check(/^REG_FAIL/.test(res0) && /not allowed/i.test(res0), 'coffre indisponible : create() rejeté en NotAllowedError, aucune attestation (' + res0.slice(0, 70) + ')');
    const storeFailedAt = Date.now(); // l'extension observe ensuite 10 s de carence avant de redemander un token
    await page0.close();

    // E2E_APP_WRAPPER (facultatif) : autre script de lancement, p. ex. pour tester un renderer
    // reconstruit ailleurs que dans build/ ; par défaut test/e2e/app-wrapper.js (voir app-helpers.js)
    app = spawn(electronPath, [appWrapperPath(), '--remote-debugging-port=' + APP_DEBUG_PORT], { env: { ...process.env, E2E_USERDATA: path.join(tmp, 'app'), E2E_EXT_ID: extId, E2E_PORT_FILE: portFile, RDVAULT_LOG_LEVEL: 'warn' }, stdio: ['ignore', 'ignore', 'ignore'] });
    const s0 = Date.now(); while (!fs.existsSync(portFile) && Date.now() - s0 < 40000) await sleep(300);
    if (!fs.existsSync(portFile)) throw new Error('coffre local non démarré');
    const vaultPort = Number(fs.readFileSync(portFile, 'utf8'));
    await waitPort(SYNC_PORT); await waitPort(APP_DEBUG_PORT);
    // SITES-22 : le port de synchronisation est tenu par l'application lancée ici, et par elle seule
    // (attendre qu'il réponde ne suffit pas : une instance ouverte entre-temps répondrait aussi)
    assertSyncPortOwner(app.pid);
    check(true, 'préparation : port ' + SYNC_PORT + ' tenu par l\'application de test (PID ' + app.pid + ')');

    // Créer le compte (premier compte : confirmation du mot de passe exigée, AUTH-14) + se connecter dans
    // l'app (coffre et sync actifs)
    let r = await vreq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS, confirm: PASS });
    check(r.status === 200, 'préparation : compte créé via API (avec confirmation)');
    const vtoken = r.json.auth.client_token;
    // Coffre d'un autre utilisateur, trié AVANT le coffre personnel (vue administrateur)
    r = await vreq(vaultPort, 'POST', '/v1/sys/mounts/' + enc(OTHER_ENGINE), vtoken, { type: 'kv', options: { version: '2' } });
    check(r.status === 204, 'préparation : coffre ' + OTHER_ENGINE + ' créé (' + r.status + ')');
    appBrowser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + APP_DEBUG_PORT, defaultViewport: null });
    let appPage = null; for (let i = 0; i < 40 && !appPage; i++) { const ps = await appBrowser.pages(); appPage = ps.find(p => /index\.html/.test(p.url())) || null; if (!appPage) await sleep(500); }
    if (!appPage) throw new Error('page de l\'app introuvable');
    // Formulaire de connexion habituel (écran de création rechargé s'il était affiché avant le compte, AUTH-14)
    await loginInApp(appPage, USER, PASS); await sleep(3000);

    const page = await browser.newPage();
    page.on('pageerror', e => log('  [pageerror] ' + String(e.message || e).slice(0, 140)));
    await page.goto('https://localhost:8443/passkey.html', { waitUntil: 'load' });
    await sleep(1500);
    const cooldown = 11000 - (Date.now() - storeFailedAt);
    if (cooldown > 0) await sleep(cooldown);

    // 1. Création (stockée dans le coffre)
    await page.click('#reg');
    check(await clickShadow(page, 'ok'), 'création : pop-up de confirmation cliquée');
    let res = ''; for (let i = 0; i < 25; i++) { res = await result(page); if (/REG_OK|REG_FAIL/.test(res)) break; await sleep(300); }
    check(/^REG_OK/.test(res), 'création : attestation produite (' + res + ')');

    // La passkey doit être dans le COFFRE (secret interne .rdvault-passkeys).
    // Lecture avec ré-essais (l'écriture traverse extension→sync→renderer→coffre).
    let blob = null, hasLocalhost = false;
    for (let i = 0; i < 20; i++) {
      r = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
      blob = r.json?.data?.data;
      hasLocalhost = !!(blob && blob.items && Array.isArray(blob.items.localhost) && blob.items.localhost.length > 0);
      if (hasLocalhost) break;
      await sleep(300);
    }
    if (!hasLocalhost) {
      // DIAGNOSTIC : où la passkey a-t-elle réellement atterri ?
      log('  [diag] lecture ' + ENGINE + '/.rdvault-passkeys status=' + r.status + ' body=' + JSON.stringify(r.json).slice(0, 200));
      const m = await vreq(vaultPort, 'GET', '/v1/sys/mounts', vtoken);
      const engines = Object.keys(m.json || {}).map(k => k.replace(/\/$/, ''));
      log('  [diag] coffres: ' + JSON.stringify(engines));
      for (const eng of engines) {
        const rr = await vreq(vaultPort, 'GET', `/v1/${enc(eng)}/data/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
        if (rr.status === 200) log('  [diag] .rdvault-passkeys TROUVÉ dans ' + eng + ' → items=' + JSON.stringify(Object.keys(rr.json?.data?.data?.items || {})));
      }
    }
    check(hasLocalhost, 'coffre : passkey écrite dans .rdvault-passkeys du coffre personnel ' + ENGINE + ' (chiffrée)');
    check(hasLocalhost && typeof blob.items.localhost[0].privateKeyJwk === 'object', 'coffre : la clé privée est stockée dans le coffre');
    r = await vreq(vaultPort, 'GET', `/v1/${enc(OTHER_ENGINE)}/data/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
    check(r.status === 404, 'coffre : rien écrit dans le coffre d\'un autre utilisateur ' + OTHER_ENGINE + ' (' + r.status + ')');

    r = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/metadata?list=true`, vtoken);
    const keys = r.json?.data?.keys || [];
    check(keys.includes('.rdvault-passkeys'), 'coffre : secret interne présent dans le listing brut');

    // 2. Authentification (lit la clé privée depuis le coffre et signe)
    await page.click('#auth');
    check(await clickShadow(page, 'ok'), 'authentification : pop-up de confirmation cliquée');
    for (let i = 0; i < 25; i++) { res = await result(page); if (/AUTH_/.test(res)) break; await sleep(300); }
    check(/^AUTH_OK/.test(res), 'authentification : signature VÉRIFIÉE par la page (' + res + ')');

    // 3. Annulation propre
    await page.evaluate(() => { document.getElementById('result').textContent = 'reset'; });
    await page.click('#auth');
    check(await clickShadow(page, 'ca'), 'annulation : bouton Annuler cliqué');
    await sleep(800);
    res = await result(page);
    check(/AUTH_FAIL|NotAllowed|not allowed/i.test(res), 'annulation : erreur standard, sans blocage');

    // 3b. EXT-21 : la PAGE annule sa cérémonie (AbortController, comme SimpleWebAuthn avant d'en lancer
    //     une autre) → AbortError immédiat, fenêtre RDVAULT fermée, et un clic ultérieur n'enregistre rien
    const countVault = async () => {
      const rr = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
      return (rr.json?.data?.data?.items?.localhost || []).length;
    };
    const nBeforeAbort = await countVault();
    await page.evaluate(() => {
      window.__ab = 'pending'; window.__abAc = new AbortController();
      navigator.credentials.create({ signal: window.__abAc.signal, publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: window.location.hostname, name: 'Test RDVAULT' },
        user: { id: new TextEncoder().encode('user-abort'), name: 'abort@test', displayName: 'Abort' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 60000
      } }).then(c => { window.__ab = 'resolved ' + c.id; }, e => { window.__ab = 'rejected ' + e.name; });
    });
    const abShown = await findShadow(page, 'ok', 8000);
    await sleep(ARM_WAIT);
    const abortT0 = Date.now();
    await page.evaluate(() => window.__abAc.abort());
    const abSt = await waitState(page, '__ab', 3000);
    const abortMs = Date.now() - abortT0;
    const abStill = await countShadow(page, 'ok', 800);
    check(!!abShown && abSt === 'rejected AbortError' && abortMs < 2000, 'AbortSignal : create() rejeté en AbortError dès l\'annulation (' + abSt + ', ' + abortMs + ' ms)');
    check(abStill === 0, 'AbortSignal : fenêtre RDVAULT fermée (' + abStill + ' bouton restant)');
    if (abShown) await page.mouse.click(abShown.x, abShown.y); // là où était « Créer dans RDVAULT »
    await sleep(1500);
    check(await countVault() === nBeforeAbort, 'AbortSignal : aucune passkey orpheline dans le coffre (' + nBeforeAbort + ')');

    // 3c. EXT-21 : délai du site écoulé (publicKey.timeout, borné à 10 s) → fenêtre RDVAULT fermée AVANT que
    //     l'authentificateur du navigateur (virtuel ici, CDP) prenne le relais ; rien dans le coffre
    const wa = await page.createCDPSession();
    await wa.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await wa.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await page.evaluate(() => {
      window.__to = 'pending';
      navigator.credentials.create({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: window.location.hostname, name: 'Test RDVAULT' },
        user: { id: new TextEncoder().encode('user-timeout'), name: 'timeout@test', displayName: 'Timeout' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 1000
      } }).then(c => { window.__to = 'resolved ' + c.id; }, e => { window.__to = 'rejected ' + e.name; });
    });
    // Nœuds lus par la MÊME session CDP : détacher une autre session (findShadow, countShadow)
    // désactive l'environnement d'authentificateur virtuel de la page
    const okCount = async () => { try { return (await shadowHits(wa, 'ok')).length; } catch { return 0; } };
    let toShown = 0;
    for (let i = 0; i < 25 && !toShown; i++) { toShown = await okCount(); if (!toShown) await sleep(200); }
    check(toShown === 1, 'délai écoulé : fenêtre RDVAULT affichée');
    const toSt = await waitState(page, '__to', 20000);
    const toStill = await okCount();
    // Diagnostic en cas d'échec : la requête native a-t-elle atteint l'authentificateur virtuel ?
    const toDiag = /^resolved /.test(toSt) ? '' : ' ; ' + JSON.stringify({
      vaCreds: await wa.send('WebAuthn.getCredentials', { authenticatorId }).then(r => r.credentials.length, e => 'err ' + e.message),
      page: await page.evaluate(() => ({ focus: document.hasFocus(), vis: document.visibilityState })),
    });
    check(/^resolved /.test(toSt) && toStill === 0, 'délai écoulé (10 s) : authentificateur du navigateur, fenêtre RDVAULT fermée (' + toSt.slice(0, 30) + ', ' + toStill + toDiag + ')');
    check(await countVault() === nBeforeAbort, 'délai écoulé : aucune seconde passkey envoyée au coffre');
    try { await wa.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }); await wa.send('WebAuthn.disable'); } catch {}    try { await wa.detach(); } catch {}

    // 3d. EXT-24 : clavier et lecteurs d'écran. Entrée sur « S'authentifier » : la fenêtre (role dialog,
    //     nom « RDVAULT ») prend le focus, jamais un bouton qui signe ; Tab reste dans la fenêtre ;
    //     Échap annule et rend le focus au bouton de la page ; Tab + Entrée confirment (clic clavier armé)
    await page.evaluate(() => { document.getElementById('result').textContent = 'reset'; });
    await page.focus('#auth');
    await page.keyboard.press('Enter');
    await findShadow(page, 'ok', 8000);
    await sleep(300);
    let axn = await axNodes(page);
    const dlg = axn.find(n => n.role === 'dialog');
    const focusedAx = axn.find(n => n.focused);
    check(!!dlg && dlg.name === 'RDVAULT' && /Utiliser votre passkey pour localhost/.test(dlg.description || ''), 'clavier : fenêtre exposée (dialog « RDVAULT », description) (' + JSON.stringify(dlg && { n: dlg.name, d: dlg.description }) + ')');
    check(!!focusedAx && focusedAx.role === 'dialog', 'clavier : focus déplacé dans la fenêtre, pas sur un bouton qui signe (' + (focusedAx && focusedAx.role + ':' + focusedAx.name) + ')');
    const tabbed = [];
    for (let i = 0; i < 4; i++) { await page.keyboard.press('Tab'); axn = await axNodes(page); const fn = axn.find(n => n.focused); tabbed.push(fn ? fn.name : '?'); }
    check(JSON.stringify(tabbed) === JSON.stringify(['Utiliser ma passkey RDVAULT', 'Utiliser un autre appareil', 'Annuler', 'Utiliser ma passkey RDVAULT']), 'clavier : Tab bouclé dans la fenêtre ' + JSON.stringify(tabbed));
    await page.keyboard.press('Escape');
    for (let i = 0; i < 20; i++) { res = await result(page); if (/AUTH_/.test(res)) break; await sleep(200); }
    const backFocus = await page.evaluate(() => document.activeElement && document.activeElement.id);
    check(/AUTH_FAIL/.test(res) && backFocus === 'auth' && await countShadow(page, 'ok', 600) === 0, 'clavier : Échap → annulation standard, fenêtre fermée, focus rendu au bouton de la page (' + res.slice(0, 40) + ', ' + backFocus + ')');
    await page.evaluate(() => { document.getElementById('result').textContent = 'reset'; });
    await page.keyboard.press('Enter');
    await findShadow(page, 'ok', 8000);
    await sleep(ARM_WAIT);
    await page.keyboard.press('Tab'); // → « Utiliser ma passkey RDVAULT »
    await page.keyboard.press('Enter');
    for (let i = 0; i < 25; i++) { res = await result(page); if (/AUTH_/.test(res)) break; await sleep(300); }
    check(/^AUTH_OK/.test(res), 'clavier : Tab + Entrée sur « Utiliser ma passkey RDVAULT » → signature vérifiée (' + res + ')');

    // 4. Plusieurs comptes pour le même rpId (BUG-11). Seconde passkey « bob » créée via
    //    l'API WebAuthn de la page (relayée par l'extension), puis flux « discoverable »
    //    (get SANS allowCredentials) → sélecteur de compte, choix du SECOND compte, assertion
    //    signée avec SON credentialId et vérifiée avec SA clé publique. Les appels WebAuthn
    //    sont lancés sans attendre (la pop-up bloque la promesse) puis cliqués par CDP.
    const aliceId = hasLocalhost ? blob.items.localhost[0].credentialId : '';
    const regBob = page.evaluate(async () => {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const cred = await navigator.credentials.create({ publicKey: {
        challenge, rp: { id: window.location.hostname, name: 'Test RDVAULT' },
        user: { id: new TextEncoder().encode('user-456'), name: 'bob@test', displayName: 'Bob' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 60000, attestation: 'none'
      } });
      // cbor / bufToB64u / derToRaw : utilitaires globaux de passkey.html
      const ad = window.cbor(new Uint8Array(cred.response.attestationObject)).get('authData');
      const credIdLen = (ad[53] << 8) | ad[54];
      const cose = window.cbor(ad.slice(55 + credIdLen));
      const jwk = { kty: 'EC', crv: 'P-256', x: window.bufToB64u(cose.get(-2)), y: window.bufToB64u(cose.get(-3)) };
      // Conformité de l'objet renvoyé (PASSKEYS-22/23) et du clientDataJSON en page principale (PASSKEYS-20)
      const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
      const spki = await crypto.subtle.importKey('spki', cred.response.getPublicKey(), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
      const spkiJwk = await crypto.subtle.exportKey('jwk', spki);
      const json = cred.toJSON();
      const cdj = JSON.parse(new TextDecoder().decode(cred.response.clientDataJSON));
      const conform = {
        authData: sameBytes(new Uint8Array(cred.response.getAuthenticatorData()), ad),
        publicKey: spkiJwk.x === jwk.x && spkiJwk.y === jwk.y,
        flags: ad[32],
        transports: cred.response.getTransports().join(','),
        json: !!json.clientExtensionResults && json.response.authenticatorData === window.bufToB64u(ad) && json.response.publicKeyAlgorithm === -7,
        crossOrigin: cdj.crossOrigin === false && !('topOrigin' in cdj),
      };
      return { id: cred.id, jwk, conform };
    }).catch(e => ({ error: String((e && e.message) || e) }));
    check(await clickShadow(page, 'ok'), 'multi-comptes : création de la seconde passkey (bob) confirmée');
    const bob = await regBob;
    check(!!(bob && bob.id && bob.jwk), 'multi-comptes : seconde passkey créée pour le même rpId (' + (bob.error || bob.id.slice(0, 12)) + ')');
    const cf = (bob && bob.conform) || {};
    check(cf.authData === true && cf.publicKey === true && cf.transports === 'internal' && cf.json === true,
      'create() conforme : getAuthenticatorData = authData, getPublicKey = SPKI de la clé, transports, toJSON (' + JSON.stringify(cf) + ')');
    check(cf.flags === 0x5d, 'create() : drapeaux UP|UV|BE|BS|AT (coffre déverrouillé = utilisateur vérifié, passkey sauvegardée avec le coffre) (0x' + Number(cf.flags).toString(16) + ')');
    check(cf.crossOrigin === true, 'create() en page principale : clientData.crossOrigin = false, sans topOrigin');
    let nVault = 0;
    for (let i = 0; i < 20 && nVault < 2; i++) {
      r = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
      nVault = (r.json?.data?.data?.items?.localhost || []).length;
      if (nVault < 2) await sleep(300);
    }
    check(nVault === 2, 'multi-comptes : coffre avec 2 passkeys pour localhost (' + nVault + ')');

    const getBob = page.evaluate(async (jwk) => {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const asrt = await navigator.credentials.get({ publicKey: { challenge, rpId: window.location.hostname, timeout: 60000 } }); // sans allowCredentials
      const ad = new Uint8Array(asrt.response.authenticatorData);
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', asrt.response.clientDataJSON));
      const signed = new Uint8Array(ad.length + h.length); signed.set(ad); signed.set(h, ad.length);
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, window.derToRaw(new Uint8Array(asrt.response.signature)), signed);
      return { id: asrt.id, ok, userHandle: asrt.response.userHandle ? new TextDecoder().decode(asrt.response.userHandle) : null };
    }, bob.jwk).catch(e => ({ error: String((e && e.message) || e) }));
    const nAc = await countShadow(page, 'ac');
    check(nAc === 2, 'multi-comptes : sélecteur affiché avec un bouton par compte (' + nAc + ')');
    check(await clickShadow(page, 'ac', 8000, 'Bob'), 'multi-comptes : second compte (Bob) cliqué');
    const asrtBob = await getBob;
    check(asrtBob.id === bob.id && asrtBob.id !== aliceId, 'multi-comptes : assertion avec le credentialId de bob, pas celui d\'alice (' + (asrtBob.error || asrtBob.id.slice(0, 12)) + ')');
    check(asrtBob.ok === true, 'multi-comptes : signature VÉRIFIÉE avec la clé publique de bob');
    check(asrtBob.userHandle === 'user-456', 'multi-comptes : userHandle = identifiant de bob');

    // Un seul candidat (allowCredentials ciblé sur alice) : confirmation simple inchangée
    await page.evaluate(() => { document.getElementById('result').textContent = 'reset'; });
    await page.click('#auth');
    check(await clickShadow(page, 'ok'), 'multi-comptes : allowCredentials ciblé → confirmation simple (un seul candidat)');
    for (let i = 0; i < 25; i++) { res = await result(page); if (/AUTH_/.test(res)) break; await sleep(300); }
    check(/^AUTH_OK/.test(res) && res.includes(aliceId.slice(0, 12)), 'multi-comptes : alice signe toujours avec sa propre passkey (' + res + ')');

    // Fermeture du sélecteur → NotAllowedError standard
    const getCancel = page.evaluate(async () => {
      try { await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: window.location.hostname } }); return 'resolved'; }
      catch (e) { return e.name + ': ' + e.message; }
    }).catch(e => String((e && e.message) || e));
    check(await countShadow(page, 'ac') === 2 && await clickShadow(page, 'ca'), 'multi-comptes : annulation du sélecteur cliquée');
    check(/NotAllowedError/.test(await getCancel), 'multi-comptes : annulation du sélecteur → NotAllowedError');

    // 4b. excludeCredentials (PASSKEYS-21) : le site redemande une passkey pour alice en excluant celle
    //     qu'il connaît déjà (rawId, créée par #reg) → fenêtre (consentement) puis InvalidStateError
    const regDup = page.evaluate(async () => {
      try {
        await navigator.credentials.create({ publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: window.location.hostname, name: 'Test RDVAULT' },
          user: { id: new TextEncoder().encode('user-123'), name: 'alice@test', displayName: 'Alice' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ type: 'public-key', id: rawId }], timeout: 60000
        } });
        return 'resolved';
      } catch (e) { return e.name; }
    }).catch(e => String((e && e.message) || e));
    check(await clickShadow(page, 'ok'), 'excludeCredentials : fenêtre de création affichée et confirmée');
    const dup = await regDup;
    check(dup === 'InvalidStateError', 'excludeCredentials : passkey déjà enregistrée → InvalidStateError (' + dup + ')');
    r = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
    nVault = (r.json?.data?.data?.items?.localhost || []).length;
    check(nVault === 2, 'excludeCredentials : aucune passkey ajoutée au coffre (' + nVault + ')');

    // 5. Anti-clickjacking. Les boutons qui signent ne sont armés que si la fenêtre est visible
    //    entière, non recouverte, depuis ≥ 500 ms. Clics RÉELS (isTrusted) dans tous les cas.
    // 5a. Clic immédiat (double-clic / tapjacking) : ignoré, puis accepté une fois armée
    await page.evaluate(() => { document.getElementById('result').textContent = 'reset'; });
    await page.click('#auth');
    const early = await findShadow(page, 'ok', 8000, null, 30);
    if (early) await page.mouse.click(early.x, early.y);
    await sleep(400);
    const earlyStill = await countShadow(page, 'ok', 1000);
    res = await result(page);
    check(!!early && earlyStill === 1 && res === 'reset', 'clickjacking : clic immédiat (fenêtre pas encore armée) ignoré (' + res + ')');
    check(await clickShadow(page, 'ok'), 'clickjacking : même fenêtre cliquée une fois armée');
    for (let i = 0; i < 25; i++) { res = await result(page); if (/AUTH_/.test(res)) break; await sleep(300); }
    check(/^AUTH_OK/.test(res), 'clickjacking : clic armé accepté, signature vérifiée (' + res + ')');

    // 5b. La page rend la fenêtre invisible (CSS !important sur l'hôte) et place un leurre :
    //     le clic réel sur « Bob » ne doit produire aucune assertion
    await page.evaluate(() => { const s = document.createElement('style'); s.id = 'cj-style'; s.textContent = 'html > div[style*="2147483647"] { opacity: 0 !important; }'; document.head.appendChild(s); });
    await startGet(page, '__cjHidden');
    check(await clickShadow(page, 'ac', 8000, 'Bob'), 'clickjacking (fenêtre invisible) : clic réel sur « Bob »');
    await sleep(800);
    let st = await page.evaluate(() => window.__cjHidden);
    check(st === 'pending', 'clickjacking (fenêtre invisible) : aucune assertion renvoyée (' + st + ')');
    await clickShadow(page, 'ca'); // Annuler n'est pas conditionné : ne produit aucune signature
    st = await waitState(page, '__cjHidden');
    check(/NotAllowedError/.test(st), 'clickjacking (fenêtre invisible) : Annuler reste possible → NotAllowedError (' + st + ')');
    await page.evaluate(() => document.getElementById('cj-style').remove());

    // 5c. Élément de la page posé PAR-DESSUS la fenêtre avec pointer-events:none (le clic le
    //     traverse) : refusé ; une fois le recouvrement retiré, la fenêtre se ré-arme
    await startGet(page, '__cjCover');
    check(!!await findShadow(page, 'ac'), 'clickjacking (recouvrement) : sélecteur affiché');
    await page.evaluate(() => { const c = document.createElement('div'); c.id = 'cj-cover'; c.textContent = 'Cliquez sur « Continuer »'; c.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:#fff;pointer-events:none;font:20px sans-serif;display:flex;align-items:center;justify-content:center'; document.documentElement.appendChild(c); });
    check(await clickShadow(page, 'ac', 8000, 'Bob'), 'clickjacking (recouvrement) : clic réel sur « Bob » à travers le leurre');
    await sleep(800);
    st = await page.evaluate(() => window.__cjCover);
    check(st === 'pending', 'clickjacking (recouvrement) : aucune assertion renvoyée (' + st + ')');
    await page.evaluate(() => document.getElementById('cj-cover').remove());
    check(await clickShadow(page, 'ac', 8000, 'Bob'), 'clickjacking (recouvrement retiré) : « Bob » cliqué après ré-armement');
    st = await waitState(page, '__cjCover');
    check(st === 'resolved ' + bob.id, 'clickjacking (recouvrement retiré) : assertion de Bob renvoyée (' + st.slice(0, 30) + ')');

    // 5d. Masque CSS sur l'hôte (non vu par IntersectionObserver v2) : refusé
    await page.evaluate(() => { const s = document.createElement('style'); s.id = 'cj-mask'; s.textContent = 'html > div[style*="2147483647"] { -webkit-mask-image: linear-gradient(transparent, transparent) !important; mask-image: linear-gradient(transparent, transparent) !important; }'; document.head.appendChild(s); });
    await startGet(page, '__cjMask', { alice: true });
    check(await clickShadow(page, 'ok'), 'clickjacking (masque CSS) : clic réel sur « Utiliser ma passkey »');
    await sleep(800);
    st = await page.evaluate(() => window.__cjMask);
    check(st === 'pending', 'clickjacking (masque CSS) : aucune assertion renvoyée (' + st + ')');
    await clickShadow(page, 'ca');
    st = await waitState(page, '__cjMask');
    check(/NotAllowedError/.test(st), 'clickjacking (masque CSS) : annulation → NotAllowedError (' + st + ')');
    await page.evaluate(() => document.getElementById('cj-mask').remove());

    // 6. Médiation « conditional » (autofill silencieux, appelée au chargement par de nombreux
    //    sites) : aucune fenêtre RDVAULT ; la requête reste au navigateur et s'annule proprement
    await page.evaluate(() => {
      window.__cond = 'pending'; window.__condAc = new AbortController();
      navigator.credentials.get({ mediation: 'conditional', signal: window.__condAc.signal, publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: window.location.hostname } })
        .then(a => { window.__cond = 'resolved ' + a.id; }, e => { window.__cond = 'rejected ' + e.name; });
    });
    const nCond = await countShadow(page, 'ac', 2500) + await countShadow(page, 'ok', 300);
    check(nCond === 0, 'médiation conditional : aucune fenêtre RDVAULT affichée (' + nCond + ')');
    if (nCond) await clickShadow(page, 'ca');
    await page.evaluate(() => window.__condAc.abort());
    st = await waitState(page, '__cond');
    check(!/^resolved/.test(st), 'médiation conditional : requête laissée au navigateur, annulable (' + st + ')');

    // 7. challenge et allowCredentials passés en SOUS-VUE typée (subarray / vue décalée) : seuls
    //    les octets de la vue comptent → passkey retrouvée, challenge signé identique
    await page.evaluate(() => {
      window.__sub = 'pending'; window.__subAc = new AbortController();
      const big = crypto.getRandomValues(new Uint8Array(64));
      const challenge = big.subarray(8, 40);
      const pool = new Uint8Array(rawId.length + 16); pool.set(rawId, 8);
      const idView = new Uint8Array(pool.buffer, 8, rawId.length);
      const expected = bufToB64u(challenge);
      navigator.credentials.get({ signal: window.__subAc.signal, publicKey: { challenge, rpId: window.location.hostname, timeout: 60000, allowCredentials: [{ type: 'public-key', id: idView }] } }).then(async (a) => {
        const cdj = JSON.parse(new TextDecoder().decode(a.response.clientDataJSON));
        const ad = new Uint8Array(a.response.authenticatorData);
        const h = new Uint8Array(await crypto.subtle.digest('SHA-256', a.response.clientDataJSON));
        const signed = new Uint8Array(ad.length + h.length); signed.set(ad); signed.set(h, ad.length);
        const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, derToRaw(new Uint8Array(a.response.signature)), signed);
        window.__sub = (ok && cdj.challenge === expected ? 'OK' : 'KO') + ' sig=' + ok + ' challenge=' + (cdj.challenge === expected);
      }, e => { window.__sub = 'rejected ' + e.name; });
    });
    const subOk = await clickShadow(page, 'ok', 5000);
    check(subOk, 'sous-vue typée : passkey RDVAULT retrouvée via allowCredentials (confirmation simple)');
    if (!subOk) await page.evaluate(() => window.__subAc.abort());
    st = await waitState(page, '__sub');
    check(/^OK/.test(st), 'sous-vue typée : signature vérifiée et challenge identique (' + st + ')');

    // 7b. SERVEUR EXIGEANT UV (réglage par défaut de nombreux serveurs, ex. @simplewebauthn) :
    //     userVerification « required » à la création ET à l'authentification. RDVAULT sert la cérémonie
    //     (coffre déverrouillé = utilisateur vérifié) ; les réponses sont vérifiées ici comme par le serveur.
    const RP = { origin: 'https://localhost:8443', rpId: 'localhost' };
    const uvChallenge1 = nodeCrypto.randomBytes(32).toString('base64url');
    const regUv = page.evaluate(async (challenge) => {
      window.__uvAc = new AbortController();
      try {
        const cred = await navigator.credentials.create({ signal: window.__uvAc.signal, publicKey: {
          challenge: b64uToBuf(challenge), rp: { id: window.location.hostname, name: 'RP exigeant UV' },
          user: { id: new TextEncoder().encode('user-789'), name: 'carol@test', displayName: 'Carol' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 60000, attestation: 'none',
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
        } });
        return { json: cred.toJSON() };
      } catch (e) { return { error: e.name + ': ' + e.message }; }
    }, uvChallenge1).catch(e => ({ error: String((e && e.message) || e) }));
    const uvRegClicked = await clickShadow(page, 'ok');
    check(uvRegClicked, 'serveur exigeant UV : création « required » servie par RDVAULT (fenêtre affichée et confirmée)');
    if (!uvRegClicked) await page.evaluate(() => window.__uvAc.abort()).catch(() => {});
    const uvReg = await regUv;
    const uvRegV = uvReg.json ? rpVerifyRegistration(uvReg.json, { ...RP, challenge: uvChallenge1 }) : { ok: false, errors: [uvReg.error], flags: -1 };
    check(uvRegV.ok && uvRegV.flags === 0x5d, 'serveur exigeant UV : enregistrement accepté par le serveur (UP+UV+BE+BS, challenge, origine, rpIdHash) (0x'
      + Number(uvRegV.flags).toString(16) + (uvRegV.errors.length ? ' ; ' + uvRegV.errors.join(', ') : '') + ')');
    if (uvRegV.ok) {
      const uvChallenge2 = nodeCrypto.randomBytes(32).toString('base64url');
      const getUv = page.evaluate(async (challenge, credId) => {
        window.__uvAc2 = new AbortController();
        try {
          const a = await navigator.credentials.get({ signal: window.__uvAc2.signal, publicKey: {
            challenge: b64uToBuf(challenge), rpId: window.location.hostname, timeout: 60000, userVerification: 'required',
            allowCredentials: [{ type: 'public-key', id: b64uToBuf(credId) }]
          } });
          return { json: a.toJSON() };
        } catch (e) { return { error: e.name + ': ' + e.message }; }
      }, uvChallenge2, uvRegV.credentialId).catch(e => ({ error: String((e && e.message) || e) }));
      const uvGetClicked = await clickShadow(page, 'ok');
      check(uvGetClicked, 'serveur exigeant UV : authentification « required » servie par RDVAULT (fenêtre affichée et confirmée)');
      if (!uvGetClicked) await page.evaluate(() => window.__uvAc2.abort()).catch(() => {});
      const uvGet = await getUv;
      const uvGetV = uvGet.json
        ? rpVerifyAuthentication(uvGet.json, { ...RP, challenge: uvChallenge2, credentialId: uvRegV.credentialId, publicKey: uvRegV.publicKey, prevCounter: uvRegV.counter })
        : { ok: false, errors: [uvGet.error], flags: -1 };
      check(uvGetV.ok && uvGetV.flags === 0x1d, 'serveur exigeant UV : authentification acceptée (UP+UV+BE+BS, signature vérifiée, compteur croissant) (0x'
        + Number(uvGetV.flags).toString(16) + (uvGetV.errors.length ? ' ; ' + uvGetV.errors.join(', ') : '') + ')');
    }

    // PURGE-35 : après les créations, signatures et réservations de compteur ci-dessus, le blob caché
    // .rdvault-passkeys ne garde que sa dernière version (clé privée d'une passkey supprimée non conservée)
    r = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/metadata/${encodeURIComponent('.rdvault-passkeys')}`, vtoken);
    const pkVersions = Object.keys(r.json?.data?.versions || {});
    const pkCurrent = r.json?.data?.current_version;
    check(r.status === 200 && pkVersions.length === 1 && Number(pkVersions[0]) === pkCurrent && pkCurrent > 5,
      'PURGE-35 : .rdvault-passkeys ne garde qu\'une version (versions ' + JSON.stringify(pkVersions) + ', courante ' + pkCurrent + ')');
    r = await vreq(vaultPort, 'GET', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('.rdvault-passkeys')}?version=1`, vtoken);
    check(r.status === 404, 'PURGE-35 : version 1 du blob des passkeys illisible (' + r.status + ')');

    // 8. Iframe CROSS-ORIGIN (page 127.0.0.1, iframe localhost) : Permissions-Policy respectée
    const topPage = await browser.newPage();
    await topPage.goto('https://127.0.0.1:8443/passkey.html', { waitUntil: 'load' });
    const addFrame = (allow) => topPage.evaluate((allow) => new Promise((res) => {
      const f = document.createElement('iframe');
      if (allow) f.setAttribute('allow', allow);
      f.style.cssText = 'position:fixed;left:0;top:0;width:800px;height:600px;border:0;background:#fff';
      f.src = 'https://localhost:8443/passkey.html?' + (allow ? 'allow' : 'deny'); f.onload = () => res(); document.body.appendChild(f);
    }), allow);
    const frameOf = (tag) => topPage.frames().find(f => f.url().startsWith('https://localhost:8443/passkey.html?' + tag));
    const rdvHostIn = (frame) => frame.evaluate(() => !!document.querySelector('html > div[style*="2147483647"]'));
    // 8a. Sans attribut allow : le navigateur refuse create() ; RDVAULT ne s'affiche pas dans la frame
    await addFrame(null); await sleep(1000);
    let fr = frameOf('deny');
    const pol = fr ? await fr.evaluate(() => document.featurePolicy ? document.featurePolicy.allowsFeature('publickey-credentials-create') : 'n/a') : 'pas de frame';
    if (fr) await fr.evaluate(() => {
      window.__ifr = 'pending';
      navigator.credentials.create({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: window.location.hostname, name: 'Iframe' }, user: { id: new TextEncoder().encode('u-ifr'), name: 'ifr@test', displayName: 'Ifr' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 60000 } })
        .then(c => { window.__ifr = 'resolved ' + c.id; }, e => { window.__ifr = 'rejected ' + e.name; });
    });
    st = fr ? await waitState(fr, '__ifr', 5000) : 'pas de frame';
    const hostDeny = fr ? await rdvHostIn(fr) : true;
    check(pol === false && /^rejected NotAllowedError/.test(st) && !hostDeny, 'iframe cross-origin sans allow : pas de fenêtre RDVAULT, refus standard du navigateur (politique=' + pol + ', ' + st + ', fenêtre=' + hostDeny + ')');
    // 8b. Avec allow="publickey-credentials-get" : délégation explicite → RDVAULT propose ses passkeys
    await addFrame('publickey-credentials-get'); await sleep(1000);
    fr = frameOf('allow');
    if (fr) await fr.evaluate(() => {
      window.__ifrAc = new AbortController();
      navigator.credentials.get({ signal: window.__ifrAc.signal, publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: window.location.hostname, timeout: 60000 } }).catch(() => {});
    });
    let hostAllow = false;
    for (let i = 0; fr && i < 25 && !hostAllow; i++) { hostAllow = await rdvHostIn(fr); if (!hostAllow) await sleep(200); }
    check(hostAllow, 'iframe avec allow="publickey-credentials-get" : fenêtre RDVAULT proposée dans la frame');
    try { if (fr) await fr.evaluate(() => window.__ifrAc.abort()); } catch {}
    await Promise.race([topPage.close(), sleep(5000)]);
  } catch (e) { log('FAIL exception: ' + ((e && e.stack) || e)); failures++; }
  finally { await finish(); }
}
main();
