// Test de bout en bout : app RDVAULT réelle (mode local) + extension Chrome enrichie + site HTTPS local.
// Lancement : node test/e2e/run.js   (nécessite build/index.html ; E2E_APP_WRAPPER facultatif, voir app-helpers.js)
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES
/* global chrome, globalThis, trap_user, trap_pass, trap_pass2 */ // globales du service worker de l'extension (globalThis = sa portée globale) et de test/e2e/site/hidden.html, utilisées dans worker.evaluate / page.evaluate
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { appWrapperPath, loginInApp, removeTempDir, waitSyncPortFree, assertSyncPortOwner, SYNC_PORT } = require('./app-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const E2E = __dirname;
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const CHROME = process.env.E2E_BROWSER;
if (!CHROME) { console.error('E2E_BROWSER manquant : chemin vers chrome.exe de Chrome for Testing (npx @puppeteer/browsers install chrome@stable). Google Chrome ≥ 137 refuse --load-extension.'); process.exit(2); }
const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
const electronPath = require(path.join(ROOT, 'node_modules/electron'));

const SITE_PORT = 8443;
const APP_DEBUG_PORT = 9333;
const USER = 'e2e';
const PASS = 'E2e-password-123';
const SECRETS = {
  'classic-site': { Username: 'alice@example.com', Password: 'P@ss-classic-1', URL: 'https://localhost:8443/classic.html' },
  'localhost-admin': { Username: 'admin', Password: 'Adm1n-pass-2', Website: 'localhost' },
  'other-site': { Username: 'bob', Password: 'Should-Never-Appear', URL: 'https://other.example.com' },
};

let failures = 0;
const log = (...a) => console.log('[E2E]', ...a);
function check(cond, label) { console.log((cond ? 'PASS ' : 'FAIL ') + label); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function waitPort(port, timeoutMs = 30000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    (function tryOnce() {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(); });
      s.once('error', () => { s.destroy(); if (Date.now() - start > timeoutMs) reject(new Error('port ' + port + ' timeout')); else setTimeout(tryOnce, 300); });
    })();
  });
}

function request(mod, opts, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = mod.request({ ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}), ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let buf = ''; res.on('data', c => buf += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch {} resolve({ status: res.statusCode, json, text: buf }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}
const vaultReq = (port, method, p, token, body) => request(http, { host: '127.0.0.1', port, method, path: p, headers: token ? { 'X-Vault-Token': token } : {} }, body);
const syncReq = (p, extId, token) => request(http, { host: '127.0.0.1', port: 45678, method: 'GET', path: p, headers: { Origin: 'chrome-extension://' + extId, 'X-Vault-Extension': 'rdvault', ...(token ? { Authorization: 'Bearer ' + token } : {}) } });
const siteReq = (p) => request(https, { host: 'localhost', port: SITE_PORT, method: 'GET', path: p, rejectUnauthorized: false });

/** Trouve les éléments d'une classe donnée, y compris dans les shadow roots FERMÉS (via CDP pierce) */
async function shadowNodes(page, className) {
  const cdp = await page.createCDPSession();
  const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
  const found = [];
  (function walk(n) {
    if (!n) return;
    const attrs = n.attributes || [];
    for (let i = 0; i < attrs.length; i += 2) {
      if (attrs[i] === 'class' && attrs[i + 1].split(/\s+/).includes(className)) found.push(n);
    }
    (n.children || []).forEach(walk);
    (n.shadowRoots || []).forEach(walk);
    if (n.contentDocument) walk(n.contentDocument);
  })(root);
  const out = [];
  for (const n of found) {
    try {
      const { model } = await cdp.send('DOM.getBoxModel', { nodeId: n.nodeId });
      const q = model.content;
      const { outerHTML } = await cdp.send('DOM.getOuterHTML', { nodeId: n.nodeId });
      out.push({ x: (q[0] + q[2] + q[4] + q[6]) / 4, y: (q[1] + q[3] + q[5] + q[7]) / 4, w: model.width, h: model.height, html: outerHTML });
    } catch { /* nœud sans boîte (invisible) */ }
  }
  await cdp.detach();
  return out;
}

async function waitShadowNodes(page, className, minCount = 1, timeoutMs = 6000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const nodes = await shadowNodes(page, className);
    if (nodes.filter(n => n.w > 0 && n.h > 0).length >= minCount) return nodes.filter(n => n.w > 0 && n.h > 0);
    await sleep(250);
  }
  return [];
}

/** Ouvre le menu via un clic RÉEL sur le champ, choisit l'entrée contenant `text` */
async function pickCredential(page, fieldSelector, text) {
  await page.click(fieldSelector);
  const items = await waitShadowNodes(page, 'vault-autofill-item', 1);
  const item = items.find(i => i.html.includes(text));
  if (!item) return { ok: false, items: items.length };
  await page.mouse.click(item.x, item.y);
  await sleep(700);
  return { ok: true, items: items.length };
}

async function fieldValue(page, selector) {
  return page.$eval(selector, el => el.value);
}

/** TOTP RFC 6238 (SHA1, période 30 s, `digits` chiffres) pour calculer le code attendu */
function totp(b32, digits, t = Date.now()) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of b32.replace(/=+$/, '').toUpperCase()) { const i = alpha.indexOf(c); if (i >= 0) bits += i.toString(2).padStart(5, '0'); }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const counter = Math.floor(t / 1000 / 30);
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0); buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', Buffer.from(bytes)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % (10 ** digits);
  return String(n).padStart(digits, '0');
}

/** Attend qu'un champ ait une valeur non vide (ou expiration) et la renvoie */
async function waitFieldValue(page, selector, timeoutMs) {
  const start = Date.now();
  let v = '';
  while (Date.now() - start < timeoutMs) {
    v = await fieldValue(page, selector);
    if (v) return v;
    await sleep(250);
  }
  return v;
}

/**
 * Extension « simple » (chrome-extension/content.js, sans app) chargée dans la page avec un
 * chrome.runtime simulé : son background réel parle directement à un serveur Vault. Le script est
 * exécuté tel quel ; seuls GET_CREDENTIALS / SELECT_CREDENTIAL sont simulés (identifiant alice).
 */
const SIMPLE_CONTENT_SRC = fs.readFileSync(path.join(ROOT, 'chrome-extension/content.js'), 'utf8');
const SIMPLE_MOCK = `
  const chrome = { runtime: { id: 'e2e-simple', sendMessage: async (m) => {
    const cred = { name: 'classic-site', engine: 'kv', username: ${JSON.stringify(SECRETS['classic-site'].Username)} };
    if (m && m.type === 'GET_CREDENTIALS') return { success: true, credentials: [cred] };
    if (m && m.type === 'SELECT_CREDENTIAL') return { success: true, credential: { ...cred, password: ${JSON.stringify(SECRETS['classic-site'].Password)} } };
    return { success: false };
  } } };`;
async function loadSimpleExtension(page, url) {
  await page.goto(url, { waitUntil: 'load' });
  await page.addScriptTag({ content: '(function () {' + SIMPLE_MOCK + '\n' + SIMPLE_CONTENT_SRC + '\n})();' });
  await sleep(1200);
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-e2e-'));
  const chromeProfile = path.join(tmp, 'chrome');
  const appUserData = path.join(tmp, 'app');
  const portFile = path.join(tmp, 'vault-port.txt');
  const appLog = fs.createWriteStream(path.join(tmp, 'app.log'));
  const configCfg = path.join(ROOT, 'config.cfg');
  const hadConfig = fs.existsSync(configCfg);
  // config.cfg n'est réécrit (avec sauvegarde) que s'il diffère de la config de test : évite
  // tout fichier de sauvegarde et toute course avec d'autres harnais lancés en parallèle.
  const WANTED_CFG = 'APP_MODE=local\nLANG=fr\n';
  let rewroteConfig = false;
  let siteProc, appProc, browser, appBrowser;

  try {
    if (!fs.existsSync(path.join(ROOT, 'build/index.html'))) throw new Error('build/index.html manquant : lancer le build React avant');
    // SITES-22 : port de synchronisation 45678 libre avant tout lancement (une autre instance RDVAULT
    // répondrait à l'extension de test avec ses propres identifiants) ; 3 nouvelles tentatives à 60 s
    await waitSyncPortFree({ log });
    if (!hadConfig || fs.readFileSync(configCfg, 'utf8') !== WANTED_CFG) {
      if (hadConfig) fs.copyFileSync(configCfg, configCfg + '.e2e-backup');
      fs.writeFileSync(configCfg, WANTED_CFG);
      rewroteConfig = true;
    }

    // 1. Site de test
    siteProc = spawn(process.execPath, [path.join(E2E, 'server.js')], { stdio: 'ignore' });
    await waitPort(SITE_PORT);
    log('site prêt');

    // 2. Chrome + extension
    browser = await puppeteer.launch({
      executablePath: CHROME,
      headless: false,
      userDataDir: chromeProfile,
      defaultViewport: null,
      ignoreDefaultArgs: ['--disable-extensions', '--enable-automation'],
      args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT, '--ignore-certificate-errors',
        '--no-first-run', '--no-default-browser-check', '--window-size=1200,900', '--window-position=0,0'],
    });
    const sw = await browser.waitForTarget(t => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 });
    const extId = new URL(sw.url()).hostname;
    check(/^[a-p]{32}$/.test(extId), 'extension chargée, id ' + extId);
    // Attachement immédiat au service worker : sinon Chrome peut l'arrêter pendant les attentes
    // (inactivité) et la cible initiale n'existe plus quand on veut l'inspecter (étape 7)
    const worker = await sw.worker();
    worker.on('console', m => { if (process.env.E2E_DEBUG) console.log('[sw]', m.type(), m.text().slice(0, 300)); });

    // 3. App RDVAULT (mode local, userData temporaire, extension pré-appairée)
    appProc = spawn(electronPath, [appWrapperPath(), '--remote-debugging-port=' + APP_DEBUG_PORT], {
      env: { ...process.env, E2E_USERDATA: appUserData, E2E_EXT_ID: extId, E2E_PORT_FILE: portFile, RDVAULT_LOG_LEVEL: 'info' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    appProc.stdout.pipe(appLog); appProc.stderr.pipe(appLog);
    const start = Date.now();
    while (!fs.existsSync(portFile) && Date.now() - start < 40000) await sleep(300);
    if (!fs.existsSync(portFile)) throw new Error('coffre local non démarré (voir ' + path.join(tmp, 'app.log') + ')');
    const vaultPort = Number(fs.readFileSync(portFile, 'utf8'));
    await waitPort(SYNC_PORT);
    await waitPort(APP_DEBUG_PORT);
    // SITES-22 : le port de synchronisation est tenu par l'application lancée ici, et par elle seule
    assertSyncPortOwner(appProc.pid);
    check(true, 'port ' + SYNC_PORT + ' tenu par l\'application de test (PID ' + appProc.pid + ')');
    log('app prête, coffre local sur ' + vaultPort);

    // 4. Compte + secrets via l'API du coffre local (avant le login UI pour que la sync les voie).
    //    Création du premier compte : confirmation du mot de passe exigée (AUTH-14)
    let r = await vaultReq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS, confirm: PASS });
    check(r.status === 200, 'création du compte via API');
    const vtoken = r.json.auth.client_token;
    const engine = `users/${USER}/Mes-Secrets`;
    for (const [name, data] of Object.entries(SECRETS)) {
      r = await vaultReq(vaultPort, 'POST', `/v1/${engine}/data/${encodeURIComponent(name)}`, vtoken, { data });
      check(r.status === 200, 'secret créé: ' + name);
    }

    // 4b. Page de connexion ouverte AVANT le déverrouillage de RDVAULT : le premier chargement des
    // identifiants échoue (401 « Not authenticated »). Cet échec ne doit pas être mis en cache comme
    // « aucun identifiant » : de nouvelles tentatives doivent faire apparaître l'icône une fois l'app
    // déverrouillée, sans rechargement ni interaction (vérifié après le login, étape 5).
    const earlyPage = await browser.newPage();
    await earlyPage.setViewport({ width: 1180, height: 800 });
    await earlyPage.goto('https://localhost:8443/classic.html', { waitUntil: 'load' });
    await sleep(2500);
    check((await shadowNodes(earlyPage, 'vault-autofill-icon')).length === 0, 'app verrouillée: aucune icône (identifiants inaccessibles)');

    // 5. Login dans l'interface React de l'app (pilotée par DevTools)
    appBrowser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + APP_DEBUG_PORT, defaultViewport: null });
    let appPage = null;
    for (let i = 0; i < 40 && !appPage; i++) {
      const pages = await appBrowser.pages();
      appPage = pages.find(p => /index\.html|localhost:3000/.test(p.url())) || null;
      if (!appPage) await sleep(500);
    }
    if (!appPage) throw new Error('page de l\'app introuvable');
    // Formulaire de connexion habituel (écran de création rechargé s'il était affiché avant le compte, AUTH-14)
    await loginInApp(appPage, USER, PASS);
    check(true, 'login UI réussi (mode principal affiché)');
    await sleep(3000); // sync des secrets vers le main process

    // 4b (suite) : la page ouverte avant le déverrouillage, ni rechargée ni touchée, doit proposer l'icône
    const lateIcons = await waitShadowNodes(earlyPage, 'vault-autofill-icon', 1, 45000);
    check(lateIcons.length >= 1, 'page ouverte avant le déverrouillage: icône apparue après le login, sans rechargement');
    await earlyPage.close();

    // 6. Serveur de sync vu par l'extension
    r = await syncReq('/auth/token', extId);
    check(r.status === 200 && r.json?.token, 'token sync obtenu sans boîte de dialogue (pré-appairé)');
    const stoken = r.json.token;
    r = await syncReq('/sync', extId, stoken);
    check(r.status === 200 && r.json?.connected === true, '/sync connected:true après login');
    r = await syncReq('/api/secrets?host=localhost', extId, stoken);
    const names = (r.json?.secrets || []).map(s => s.name).sort();
    check(r.status === 200 && names.join(',') === 'classic-site,localhost-admin', '/api/secrets filtré par hôte: ' + names.join(','));
    check((r.json?.secrets || []).every(s => s.password === undefined), 'liste sans mot de passe');
    r = await syncReq('/api/secret?host=localhost&engine=' + encodeURIComponent(engine) + '&name=classic-site', extId, stoken);
    check(r.status === 200 && r.json?.secret?.password === SECRETS['classic-site'].Password, '/api/secret renvoie le mot de passe à la sélection');
    r = await syncReq('/api/secret?host=localhost&engine=' + encodeURIComponent(engine) + '&name=other-site', extId, stoken);
    check(r.status === 404, '/api/secret refuse un secret d\'un autre hôte');

    // 7. Scénarios d'autofill dans Chrome
    const page = await browser.newPage();
    await page.setViewport({ width: 1180, height: 800 });
    page.on('console', m => { if (process.env.E2E_DEBUG) console.log('[page]', m.type(), m.text().slice(0, 300)); });
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)));
    if (process.env.E2E_DEBUG) {
      await page.goto('https://localhost:8443/classic.html', { waitUntil: 'load' });
      await sleep(1500);
      const d1 = await page.evaluate(() => ({ hosts: document.querySelectorAll('div[style*="all: initial"]').length, inputs: document.querySelectorAll('input').length }));
      console.log('[diag] avant clic', JSON.stringify(d1));
      await page.click('#email'); await sleep(1200);
      const d2 = await page.evaluate(() => ({ hosts: document.querySelectorAll('div[style*="all: initial"]').length, active: document.activeElement && document.activeElement.id }));
      console.log('[diag] après clic', JSON.stringify(d2));
      const cdp = await page.createCDPSession();
      const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
      let closed = 0; const classes = [];
      (function w(n) { (n.shadowRoots || []).forEach(sr => { if (sr.shadowRootType === 'closed') closed++; w(sr); }); const a = n.attributes || []; for (let i = 0; i < a.length; i += 2) if (a[i] === 'class' && /vault-autofill/.test(a[i + 1])) classes.push(a[i + 1]); (n.children || []).forEach(w); })(root);
      await cdp.detach();
      console.log('[diag] closed roots', closed, 'classes', JSON.stringify(classes.slice(0, 10)));
      const swState = await worker.evaluate(async () => {
        const s = await chrome.storage.session.get(null);
        const l = await chrome.storage.local.get(null);
        const out = { sessionKeys: Object.keys(s), localKeys: Object.keys(l) };
        try { const r = await fetch('http://127.0.0.1:45678/auth/token', { headers: { 'X-Vault-Extension': 'rdvault' } }); out.tokenStatus = r.status; out.tokenBody = (await r.text()).slice(0, 200); } catch (e) { out.tokenErr = e.message; }
        return out;
      });
      console.log('[diag] sw', JSON.stringify(swState));
    }

    // 7a. Page sans formulaire : aucune icône
    await page.goto('https://localhost:8443/index.html', { waitUntil: 'load' });
    await sleep(1200);
    check((await shadowNodes(page, 'vault-autofill-icon')).length === 0, 'aucune icône sur une page sans formulaire');

    // 7b. Classique
    await page.goto('https://localhost:8443/classic.html', { waitUntil: 'load' });
    await sleep(1200);
    let pick = await pickCredential(page, '#email', 'alice');
    check(pick.ok && pick.items === 2, 'classique: menu avec 2 entrées, sélection alice (' + pick.items + ' entrées)');
    check(await fieldValue(page, '#email') === 'alice@example.com', 'classique: email rempli');
    check(await fieldValue(page, '#password') === 'P@ss-classic-1', 'classique: mot de passe rempli');
    await page.click('#submit'); await sleep(800);
    let subs = (await siteReq('/__submissions')).json || [];
    let last = subs[subs.length - 1] || {};
    check(last.page === 'classic' && last.password === 'P@ss-classic-1', 'classique: formulaire soumis avec les bonnes valeurs');

    // 7c. Deux étapes
    await page.goto('https://localhost:8443/twostep.html', { waitUntil: 'load' });
    await sleep(1200);
    pick = await pickCredential(page, '#login', 'admin');
    check(pick.ok, 'deux étapes: sélection admin à l\'étape 1');
    check(await fieldValue(page, '#login') === 'admin', 'deux étapes: identifiant rempli');
    await page.click('#next'); await sleep(800);
    // Étape 2 : le champ mot de passe reçoit le focus ; cliquer sur son icône puis choisir l'entrée
    let pwdVal = await fieldValue(page, '#pwd');
    if (pwdVal !== 'Adm1n-pass-2') {
      await page.click('#pwd');
      const icons = await waitShadowNodes(page, 'vault-autofill-icon', 1);
      const pwdBox = await page.$eval('#pwd', el => { const b = el.getBoundingClientRect(); return { x: b.x, y: b.y, w: b.width, h: b.height }; });
      const icon = icons.find(i => Math.abs(i.y - (pwdBox.y + pwdBox.h / 2)) < 40) || icons[0];
      if (icon) { await page.mouse.click(icon.x, icon.y); }
      const items = await waitShadowNodes(page, 'vault-autofill-item', 1);
      const item = items.find(i => i.html.includes('admin'));
      if (item) { await page.mouse.click(item.x, item.y); await sleep(700); }
      pwdVal = await fieldValue(page, '#pwd');
    }
    check(pwdVal === 'Adm1n-pass-2', 'deux étapes: mot de passe rempli à l\'étape 2 (' + (pwdVal ? 'rempli' : 'vide') + ')');
    await page.click('#go'); await sleep(800);
    subs = (await siteReq('/__submissions')).json || []; last = subs[subs.length - 1] || {};
    check(last.page === 'twostep' && last.login === 'admin' && last.password === 'Adm1n-pass-2', 'deux étapes: soumission correcte');

    // 7d. SPA à inputs contrôlés (rendu différé)
    await page.goto('https://localhost:8443/spa.html', { waitUntil: 'load' });
    await sleep(1500);
    pick = await pickCredential(page, '#u', 'alice');
    check(pick.ok, 'SPA: sélection alice');
    await page.click('#b'); await sleep(800);
    subs = (await siteReq('/__submissions')).json || []; last = subs[subs.length - 1] || {};
    check(last.page === 'spa' && last.user === 'alice@example.com' && last.password === 'P@ss-classic-1', 'SPA: état interne mis à jour (événements input)');

    // 7e. Shadow DOM ouvert
    await page.goto('https://localhost:8443/shadow.html', { waitUntil: 'load' });
    await sleep(1200);
    pick = await pickCredential(page, 'pierce/#su', 'admin');
    check(pick.ok, 'shadow DOM: sélection admin');
    check(await page.$eval('pierce/#sp', el => el.value) === 'Adm1n-pass-2', 'shadow DOM: mot de passe rempli');
    await page.click('pierce/#sb'); await sleep(800);
    subs = (await siteReq('/__submissions')).json || []; last = subs[subs.length - 1] || {};
    check(last.page === 'shadow' && last.password === 'Adm1n-pass-2', 'shadow DOM: soumission correcte');

    // 7f. Champs pièges invisibles
    await page.goto('https://localhost:8443/hidden.html', { waitUntil: 'load' });
    await sleep(1200);
    const iconsHidden = await shadowNodes(page, 'vault-autofill-icon');
    check(iconsHidden.length <= 2, 'pièges: pas d\'icône sur les champs invisibles (' + iconsHidden.length + ' icônes)');
    pick = await pickCredential(page, '#vu', 'alice');
    check(pick.ok, 'pièges: sélection alice sur le champ visible');
    check(await fieldValue(page, '#vp') === 'P@ss-classic-1', 'pièges: champ visible rempli');
    const traps = await page.evaluate(() => [trap_user.value, trap_pass.value, trap_pass2.value]);
    check(traps.every(v => v === ''), 'pièges: champs invisibles NON remplis ' + JSON.stringify(traps));

    // 7g. Champs aux attributs illisibles : détection par ancrage sur le champ mot de passe
    await page.goto('https://localhost:8443/obfuscated.html', { waitUntil: 'load' });
    await sleep(1200);
    pick = await pickCredential(page, '#a9b2c1', 'admin');
    check(pick.ok, 'illisibles: menu ouvert au focus du champ identifiant');
    check(await fieldValue(page, '#a9b2c1') === 'admin', 'illisibles: identifiant rempli (ancrage)');
    check(await fieldValue(page, '#d4e8f0') === 'Adm1n-pass-2', 'illisibles: mot de passe rempli');
    await page.click('#go'); await sleep(800);
    subs = (await siteReq('/__submissions')).json || []; last = subs[subs.length - 1] || {};
    check(last.page === 'obfuscated' && last.user === 'admin' && last.password === 'Adm1n-pass-2', 'illisibles: soumission correcte');

    // 7h. Page d'inscription (new-password) : aucune proposition d'identifiant de connexion
    await page.goto('https://localhost:8443/signup.html', { waitUntil: 'load' });
    await sleep(1200);
    check((await shadowNodes(page, 'vault-autofill-icon')).length === 0, 'inscription: aucune icône sur un formulaire new-password');

    // 7i. Événement synthétique : un script de page ne doit pas pouvoir ouvrir le menu
    await page.goto('https://localhost:8443/classic.html', { waitUntil: 'load' });
    await sleep(1200);
    await page.evaluate(() => { document.getElementById('email').dispatchEvent(new FocusEvent('focus', { bubbles: false })); });
    await sleep(800);
    const itemsSynthetic = await shadowNodes(page, 'vault-autofill-item');
    check(itemsSynthetic.length === 0, 'sécurité: focus synthétique n\'ouvre pas le menu');

    // 7j. Étiquette flottante (motif relevé sur login.orange.fr) : l'input vide et sans focus est
    // transparent (opacity:0) mais reste la cible du clic. Il doit être détecté et rempli ; les
    // pièges transparents NON atteignables (pointer-events:none, recouverts, minuscules) jamais.
    await page.goto('https://localhost:8443/floating.html', { waitUntil: 'load' });
    await sleep(1200);
    check(await page.$eval('#login', el => getComputedStyle(el).opacity) === '0', 'étiquette flottante: champ transparent avant focus (fixture conforme)');
    const floatIcons = await waitShadowNodes(page, 'vault-autofill-icon', 1, 4000);
    check(floatIcons.length === 1, 'étiquette flottante: une icône, sur le champ identifiant transparent (' + floatIcons.length + ' icône(s))');
    pick = await pickCredential(page, '#login', 'alice');
    check(pick.ok, 'étiquette flottante: menu ouvert au clic dans le champ');
    check(await fieldValue(page, '#login') === 'alice@example.com', 'étiquette flottante: identifiant rempli');
    const floatTraps = await page.evaluate(() => ['trap_pe', 'trap_cov', 'trap_tiny'].map(id => document.getElementById(id).value));
    check(floatTraps.every(v => v === ''), 'étiquette flottante: pièges transparents non atteignables NON remplis ' + JSON.stringify(floatTraps));

    // 7k. Page + 4 iframes SANS champ de connexion : aucune requête /api/secrets vers RDVAULT
    // (avec all_frames, chaque frame interrogeait l'app à son chargement : requêtes inutiles, qui
    // épuisent la limite de débit du serveur de sync et privent ensuite les vraies pages de connexion)
    await worker.evaluate(() => {
      globalThis.__rdvSecretsCalls = 0;
      globalThis.__rdvTotpCalls = 0;
      if (!globalThis.__rdvFetchWrapped) {
        const orig = globalThis.fetch;
        globalThis.fetch = function (u, o) {
          const s = String(u);
          if (s.includes('/api/secrets')) globalThis.__rdvSecretsCalls++;
          if (s.includes('/api/totp/')) globalThis.__rdvTotpCalls++;
          return orig.call(this, u, o);
        };
        globalThis.__rdvFetchWrapped = true;
      }
    });
    await page.goto('https://localhost:8443/frames-noform.html', { waitUntil: 'load' });
    await sleep(2500);
    const noformCalls = await worker.evaluate(() => globalThis.__rdvSecretsCalls);
    check(page.frames().length === 5, 'frames sans formulaire: page + 4 iframes chargées (' + page.frames().length + ')');
    check(noformCalls === 0, 'frames sans formulaire: aucune requête /api/secrets (' + noformCalls + ')');
    // Contre-épreuve : une vraie page de connexion interroge bien RDVAULT (le compteur fonctionne)
    await page.goto('https://localhost:8443/classic.html', { waitUntil: 'load' });
    await waitShadowNodes(page, 'vault-autofill-icon', 1);
    const loginCalls = await worker.evaluate(() => globalThis.__rdvSecretsCalls);
    check(loginCalls >= 1, 'page de connexion: requête /api/secrets émise (' + loginCalls + ')');

    // 7l. Pots de miel : des champs mot de passe CACHÉS (hors écran, section repliée) dans un vrai
    // formulaire de connexion ne doivent pas le faire passer pour une inscription (« plus d'un mot
    // de passe ») : le formulaire est reconnu et rempli, les champs cachés jamais.
    await page.goto('https://localhost:8443/honeypot.html', { waitUntil: 'load' });
    await sleep(1200);
    const hpIcons = await waitShadowNodes(page, 'vault-autofill-icon', 1, 4000);
    check(hpIcons.length === 1, 'pot de miel: une icône sur le formulaire de connexion (' + hpIcons.length + ' icône(s))');
    pick = await pickCredential(page, '#hu', 'alice');
    check(pick.ok, 'pot de miel: menu ouvert au clic dans le champ identifiant');
    check(await fieldValue(page, '#hu') === 'alice@example.com' && await fieldValue(page, '#hp') === 'P@ss-classic-1', 'pot de miel: identifiant et mot de passe visibles remplis');
    const hpTraps = await page.evaluate(() => ['hp_offscreen', 'hp_hidden'].map(id => document.getElementById(id).value));
    check(hpTraps.every(v => v === ''), 'pot de miel: champs mot de passe cachés NON remplis ' + JSON.stringify(hpTraps));

    // 7l bis. Pots de miel « sr-only » : champs de 1×1 px et/ou découpés par clip / clip-path
    // (Tailwind sr-only, WordPress screen-reader-text), sur le champ ou sur un conteneur. Comptés à
    // tort, ils faisaient passer le formulaire pour une inscription (aucune icône) ; l'identifiant
    // piège, placé entre l'identifiant et le mot de passe, était rempli à la place du vrai champ.
    await page.goto('https://localhost:8443/honeypot-sronly.html', { waitUntil: 'load' });
    await sleep(1200);
    const srFixture = await page.evaluate(() => Array.from(document.querySelectorAll('[data-trap]')).map(el => {
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden' && s.opacity === '1';
    }));
    check(srFixture.length === 9 && srFixture.every(Boolean), 'pot de miel sr-only: 9 pièges avec une boîte non nulle, ni display:none ni transparents (fixture conforme)');
    const srIcons = await waitShadowNodes(page, 'vault-autofill-icon', 1, 4000);
    check(srIcons.length === 1, 'pot de miel sr-only: une seule icône, sur le mot de passe visible (' + srIcons.length + ' icône(s))');
    pick = await pickCredential(page, '#su', 'alice');
    check(pick.ok, 'pot de miel sr-only: menu ouvert au clic dans le champ identifiant');
    check(await fieldValue(page, '#su') === 'alice@example.com' && await fieldValue(page, '#sp') === 'P@ss-classic-1', 'pot de miel sr-only: identifiant et mot de passe visibles remplis');
    const srTraps = await page.evaluate(() => Array.from(document.querySelectorAll('[data-trap]')).filter(el => el.value).map(el => el.id));
    check(srTraps.length === 0, 'pot de miel sr-only: champs 1×1 px / découpés NON remplis ' + JSON.stringify(srTraps));

    // 7m. Garde-fou : « mot de passe + confirmation » (sans aucun indicateur), confirmation hors de
    // la fenêtre mais présente : toujours une inscription, aucune proposition
    await page.goto('https://localhost:8443/pw-confirm.html', { waitUntil: 'load' });
    await sleep(1500);
    check((await shadowNodes(page, 'vault-autofill-icon')).length === 0, 'mot de passe + confirmation: aucune icône (inscription)');
    await page.click('#se'); await sleep(800);
    check((await shadowNodes(page, 'vault-autofill-item')).length === 0, 'mot de passe + confirmation: aucun menu au focus');

    // 7m bis. SITES-24 : mots d'inscription dans la CHAÎNE DE REQUÊTE et le fragment de l'action (motif
    // d'accounts.ikea.com, Auth0 : « …/login?state=…&registration=%7B%7D ») : ignorés, la connexion est
    // reconnue et remplie. Garde-fou : le CHEMIN de l'action (/account/register) reste un indicateur.
    await page.goto('https://localhost:8443/login-action-query.html', { waitUntil: 'load' });
    await sleep(1200);
    const aqIcons = await waitShadowNodes(page, 'vault-autofill-icon', 1, 4000);
    check(aqIcons.length === 1, 'action avec query d\'inscription: une icône, connexion reconnue (' + aqIcons.length + ' icône(s))');
    pick = await pickCredential(page, '#qu', 'alice');
    check(pick.ok, 'action avec query d\'inscription: menu ouvert au clic dans le champ identifiant');
    check(await fieldValue(page, '#qu') === 'alice@example.com' && await fieldValue(page, '#qp') === 'P@ss-classic-1', 'action avec query d\'inscription: identifiant et mot de passe remplis');
    await page.click('#go'); await sleep(800);
    subs = (await siteReq('/__submissions')).json || []; last = subs[subs.length - 1] || {};
    check(last.page === 'login-action-query' && last.user === 'alice@example.com' && last.password === 'P@ss-classic-1', 'action avec query d\'inscription: soumission correcte');
    await page.goto('https://localhost:8443/action-path.html', { waitUntil: 'load' });
    await sleep(1500);
    check((await shadowNodes(page, 'vault-autofill-icon')).length === 0, 'chemin d\'action /account/register: aucune icône (inscription)');
    await page.click('#ae'); await sleep(800);
    check((await shadowNodes(page, 'vault-autofill-item')).length === 0, 'chemin d\'action /account/register: aucun menu au focus');

    // 7n. TOTP sans clé, DOM en mouvement continu : chaque changement relançait une demande de code
    // vouée à l'échec pendant 20 s (limite de 10 codes/min partagée avec l'app épuisée). Abandon
    // attendu après quelques échecs.
    await page.goto('https://localhost:8443/totp-nokey.html', { waitUntil: 'load' });
    await sleep(1500); // laisse passer la vérification « page TOTP » du chargement
    await worker.evaluate(() => { globalThis.__rdvTotpCalls = 0; });
    pick = await pickCredential(page, '#u', 'admin');
    check(pick.ok, 'TOTP sans clé: sélection admin (aucune clé TOTP)');
    await sleep(7000);
    const nokeyCalls = await worker.evaluate(() => globalThis.__rdvTotpCalls);
    check(nokeyCalls >= 1 && nokeyCalls <= 3, 'TOTP sans clé: abandon après quelques échecs, pas une demande par changement du DOM (' + nokeyCalls + ' demandes en 7 s)');
    check(await fieldValue(page, '#otp') === '', 'TOTP sans clé: champ code laissé vide');

    // 7o. TOTP à 8 chiffres (proposé par l'app et généré par le coffre local) : rempli automatiquement
    const TOTP8_B32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    r = await vaultReq(vaultPort, 'POST', '/v1/TOTP/keys/' + encodeURIComponent('MES-SECRETS-classic-site'), vtoken, { key: TOTP8_B32, period: 30, digits: 8 });
    check(r.status === 204, 'clé TOTP à 8 chiffres créée pour classic-site');
    await page.goto('https://localhost:8443/totp8.html', { waitUntil: 'load' });
    await sleep(1500);
    pick = await pickCredential(page, '#u', 'alice');
    check(pick.ok, 'TOTP 8 chiffres: sélection alice');
    const otp8 = await waitFieldValue(page, '#otp', 6000);
    check(/^\d{8}$/.test(otp8), 'TOTP 8 chiffres: code à 8 chiffres saisi automatiquement (' + (otp8 || 'vide') + ')');
    check(otp8 === totp(TOTP8_B32, 8) || otp8 === totp(TOTP8_B32, 8, Date.now() - 30000), 'TOTP 8 chiffres: code saisi conforme à la RFC 6238');

    await page.close();

    // 8. Extension « simple » (chrome-extension/content.js) : mêmes règles de détection. Contexte de
    // navigation séparé, où l'extension enrichie n'est pas injectée (vérifié), chrome.runtime simulé.
    const simpleCtx = await browser.createBrowserContext();
    const simplePage = await simpleCtx.newPage();
    await simplePage.setViewport({ width: 1180, height: 800 });
    simplePage.on('pageerror', e => console.log('[pageerror simple]', String(e).slice(0, 300)));
    await simplePage.goto('https://localhost:8443/classic.html', { waitUntil: 'load' });
    await sleep(1500);
    check((await shadowNodes(simplePage, 'vault-autofill-icon')).length === 0, 'simple: contexte isolé, extension enrichie absente');
    await loadSimpleExtension(simplePage, 'https://localhost:8443/classic.html');
    pick = await pickCredential(simplePage, '#email', 'alice');
    check(pick.ok && await fieldValue(simplePage, '#password') === 'P@ss-classic-1', 'simple: formulaire classique rempli (contrôle du harnais)');

    // 8a. Étiquette flottante (login.orange.fr) : champ transparent mais atteignable
    await loadSimpleExtension(simplePage, 'https://localhost:8443/floating.html');
    const sFloatIcons = await waitShadowNodes(simplePage, 'vault-autofill-icon', 1, 4000);
    check(sFloatIcons.length === 1, 'simple, étiquette flottante: une icône sur le champ transparent (' + sFloatIcons.length + ' icône(s))');
    pick = await pickCredential(simplePage, '#login', 'alice');
    check(pick.ok && await fieldValue(simplePage, '#login') === 'alice@example.com', 'simple, étiquette flottante: identifiant rempli');
    const sFloatTraps = await simplePage.evaluate(() => ['trap_pe', 'trap_cov', 'trap_tiny'].map(id => document.getElementById(id).value));
    check(sFloatTraps.every(v => v === ''), 'simple, étiquette flottante: pièges transparents NON remplis ' + JSON.stringify(sFloatTraps));

    // 8b. Pots de miel mot de passe cachés dans un formulaire de connexion
    await loadSimpleExtension(simplePage, 'https://localhost:8443/honeypot.html');
    const sHpIcons = await waitShadowNodes(simplePage, 'vault-autofill-icon', 1, 4000);
    check(sHpIcons.length === 1, 'simple, pot de miel: une icône (' + sHpIcons.length + ' icône(s))');
    pick = await pickCredential(simplePage, '#hu', 'alice');
    check(pick.ok && await fieldValue(simplePage, '#hu') === 'alice@example.com' && await fieldValue(simplePage, '#hp') === 'P@ss-classic-1', 'simple, pot de miel: identifiant et mot de passe remplis');
    const sHpTraps = await simplePage.evaluate(() => ['hp_offscreen', 'hp_hidden'].map(id => document.getElementById(id).value));
    check(sHpTraps.every(v => v === ''), 'simple, pot de miel: champs cachés NON remplis ' + JSON.stringify(sHpTraps));

    // 8b bis. Pots de miel « sr-only » (1×1 px, clip / clip-path) : même règle que la version enrichie
    await loadSimpleExtension(simplePage, 'https://localhost:8443/honeypot-sronly.html');
    const sSrIcons = await waitShadowNodes(simplePage, 'vault-autofill-icon', 1, 4000);
    check(sSrIcons.length === 1, 'simple, pot de miel sr-only: une seule icône (' + sSrIcons.length + ' icône(s))');
    pick = await pickCredential(simplePage, '#su', 'alice');
    check(pick.ok && await fieldValue(simplePage, '#su') === 'alice@example.com' && await fieldValue(simplePage, '#sp') === 'P@ss-classic-1', 'simple, pot de miel sr-only: identifiant et mot de passe visibles remplis');
    const sSrTraps = await simplePage.evaluate(() => Array.from(document.querySelectorAll('[data-trap]')).filter(el => el.value).map(el => el.id));
    check(sSrTraps.length === 0, 'simple, pot de miel sr-only: champs 1×1 px / découpés NON remplis ' + JSON.stringify(sSrTraps));

    // 8c. Garde-fou inscription « mot de passe + confirmation »
    await loadSimpleExtension(simplePage, 'https://localhost:8443/pw-confirm.html');
    check((await shadowNodes(simplePage, 'vault-autofill-icon')).length === 0, 'simple, mot de passe + confirmation: aucune icône (inscription)');

    // 8d. SITES-24 : chaîne de requête / fragment de l'action ignorés, chemin toujours pris en compte
    await loadSimpleExtension(simplePage, 'https://localhost:8443/login-action-query.html');
    const sAqIcons = await waitShadowNodes(simplePage, 'vault-autofill-icon', 1, 4000);
    check(sAqIcons.length === 1, 'simple, action avec query d\'inscription: une icône (' + sAqIcons.length + ' icône(s))');
    pick = await pickCredential(simplePage, '#qu', 'alice');
    check(pick.ok && await fieldValue(simplePage, '#qu') === 'alice@example.com' && await fieldValue(simplePage, '#qp') === 'P@ss-classic-1', 'simple, action avec query d\'inscription: identifiant et mot de passe remplis');
    await loadSimpleExtension(simplePage, 'https://localhost:8443/action-path.html');
    check((await shadowNodes(simplePage, 'vault-autofill-icon')).length === 0, 'simple, chemin d\'action /account/register: aucune icône (inscription)');

    await simpleCtx.close();
  } catch (err) {
    console.log('FAIL exception: ' + ((err && err.stack) || err));
    failures++;
  } finally {
    try { if (appBrowser) appBrowser.disconnect(); } catch {}
    try { if (appProc) appProc.kill(); } catch {}
    try { if (browser) await browser.close(); } catch {}
    try { if (siteProc) siteProc.kill(); } catch {}
    try { if (rewroteConfig) { if (hadConfig) fs.renameSync(configCfg + '.e2e-backup', configCfg); else fs.unlinkSync(configCfg); } } catch {}
    await sleep(500);
    // Dossier temporaire (profil Chrome, coffre de test, journal) supprimé si tout a réussi ; conservé en cas
    // d'échec pour le diagnostic (app.log)
    try { if (appProc) { appProc.stdout.unpipe(appLog); appProc.stderr.unpipe(appLog); } } catch {}
    appLog.on('error', () => {});
    await new Promise((r) => appLog.end(r));
    if (failures === 0) await removeTempDir(tmp, appProc);
    else console.log('app.log: ' + path.join(tmp, 'app.log'));
    console.log(failures === 0 ? 'E2E OK' : `E2E FAILURES: ${failures}`);
    process.exit(failures === 0 ? 0 : 1);
  }
}

main();
