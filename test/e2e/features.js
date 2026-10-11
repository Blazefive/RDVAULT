// Tests ciblés : (1) login en DEUX PAGES distinctes (identifiant puis mot de passe sur une autre URL),
// (2) saisie automatique du code TOTP. App réelle (coffre local temporaire) + extension + site local.
// Lancement : E2E_BROWSER=<chrome> node test/e2e/features.js   (E2E_APP_WRAPPER facultatif, voir app-helpers.js)
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { appWrapperPath, loginInApp, removeTempDir, waitSyncPortFree, assertSyncPortOwner, SYNC_PORT } = require('./app-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const E2E = __dirname;
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const CHROME = process.env.E2E_BROWSER;
if (!CHROME) { console.error('E2E_BROWSER manquant'); process.exit(2); }
const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
const electronPath = require(path.join(ROOT, 'node_modules/electron'));
const SITE_PORT = 8443, APP_DEBUG_PORT = 9337;
const USER = 'e2e', PASS = 'E2e-password-123', ENGINE = `users/${USER}/Mes-Secrets`;
const SECRET = { name: 'localhost-admin', Username: 'admin', Password: 'Adm1n-pass-2', Website: 'localhost' };
const TOTP_B32 = 'JBSWY3DPEHPK3PXP';
const TOTP_KEY = 'MES-SECRETS-localhost-admin'; // = engine (users/e2e/ retiré, majuscules) + '-' + nom du secret

let failures = 0;
const check = (c, l) => { console.log((c ? 'PASS ' : 'FAIL ') + l); if (!c) failures++; };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const enc = (e) => e.split('/').map(encodeURIComponent).join('/');

// TOTP RFC 6238 (SHA1, 6 chiffres, période 30) pour calculer le code attendu
function totp(b32, t = Date.now()) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = ''; for (const c of b32.replace(/=+$/,'').toUpperCase()) { const i = alpha.indexOf(c); if (i >= 0) bits += i.toString(2).padStart(5, '0'); }
  const bytes = []; for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  const key = Buffer.from(bytes);
  const counter = Math.floor(t / 1000 / 30);
  const buf = Buffer.alloc(8); buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0); buf.writeUInt32BE(counter >>> 0, 4);
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const n = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6;
  return String(n).padStart(6, '0');
}

function waitPort(port, t = 30000) { const s = Date.now(); return new Promise((res, rej) => { (function tr() { const c = net.connect(port, '127.0.0.1'); c.once('connect', () => { c.destroy(); res(); }); c.once('error', () => { c.destroy(); Date.now() - s > t ? rej(new Error('port ' + port)) : setTimeout(tr, 300); }); })(); }); }
function vreq(port, method, p, token, body) { return new Promise((res, rej) => { const d = body ? JSON.stringify(body) : null; const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Vault-Token': token } : {}), ...(d ? { 'Content-Length': Buffer.byteLength(d) } : {}) } }, x => { let b = ''; x.on('data', c => b += c); x.on('end', () => { let j = null; try { j = JSON.parse(b); } catch {} res({ status: x.statusCode, json: j }); }); }); r.on('error', rej); if (d) r.write(d); r.end(); }); }

async function shadowNodes(page, cls) {
  const cdp = await page.createCDPSession();
  try {
    const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const found = [];
    (function w(n) { if (!n) return; const a = n.attributes || []; for (let i = 0; i < a.length; i += 2) if (a[i] === 'class' && a[i + 1].split(/\s+/).includes(cls)) found.push(n); (n.children || []).forEach(w); (n.shadowRoots || []).forEach(w); })(root);
    const out = [];
    for (const n of found) { try { const { model } = await cdp.send('DOM.getBoxModel', { nodeId: n.nodeId }); const q = model.content; const { outerHTML } = await cdp.send('DOM.getOuterHTML', { nodeId: n.nodeId }); if (model.width > 0) out.push({ x: (q[0] + q[4]) / 2, y: (q[1] + q[5]) / 2, html: outerHTML }); } catch {} }
    return out;
  } finally { await cdp.detach().catch(() => {}); }
}
async function waitNodes(page, cls, t = 6000) { const s = Date.now(); while (Date.now() - s < t) { const n = await shadowNodes(page, cls); if (n.length) return n; await sleep(300); } return []; }
async function pick(page, selector, text) {
  if (selector) await page.click(selector);
  let items = await waitNodes(page, 'vault-autofill-item', 3000);
  if (items.length === 0) {
    // Pas de menu au focus (ex. champ mot de passe seul) : cliquer l'icône de l'extension
    const icons = await waitNodes(page, 'vault-autofill-icon', 4000);
    if (icons.length === 0) return false;
    await page.mouse.click(icons[0].x, icons[0].y);
    items = await waitNodes(page, 'vault-autofill-item', 4000);
  }
  const it = items.find(i => i.html.includes(text)) || items[0];
  if (!it) return false;
  await page.mouse.click(it.x, it.y); await sleep(800); return true;
}
const val = (page, s) => page.$eval(s, el => el.value);

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-feat-'));
  const portFile = path.join(tmp, 'port.txt');
  const cfg = path.join(ROOT, 'config.cfg'); const had = fs.existsSync(cfg);
  // config.cfg n'est réécrit (avec sauvegarde) que s'il diffère de la config de test : aucun fichier de
  // sauvegarde ni course avec d'autres harnais lancés en parallèle (même règle que run.js)
  const WANTED_CFG = 'APP_MODE=local\nLANG=fr\n';
  let rewroteConfig = false;
  let site, app, browser, appBrowser;
  try {
    // SITES-22 : port de synchronisation libre AVANT le lancement du navigateur (l'extension de test l'interroge
    // dès son démarrage) : une instance RDVAULT réelle lui servirait ses identifiants. Refus sinon (app-helpers.js)
    await waitSyncPortFree();
    if (!had || fs.readFileSync(cfg, 'utf8') !== WANTED_CFG) {
      if (had) fs.copyFileSync(cfg, cfg + '.feat-backup');
      fs.writeFileSync(cfg, WANTED_CFG);
      rewroteConfig = true;
    }
    site = spawn(process.execPath, [path.join(E2E, 'server.js')], { stdio: 'ignore' });
    await waitPort(SITE_PORT);
    browser = await puppeteer.launch({ executablePath: CHROME, headless: false, userDataDir: path.join(tmp, 'chrome'), defaultViewport: null, ignoreDefaultArgs: ['--disable-extensions', '--enable-automation'], args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT, '--ignore-certificate-errors', '--no-first-run', '--no-default-browser-check', '--window-size=1100,850'] });
    const sw = await browser.waitForTarget(t => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 });
    const extId = new URL(sw.url()).hostname;
    app = spawn(electronPath, [appWrapperPath(), '--remote-debugging-port=' + APP_DEBUG_PORT], { env: { ...process.env, E2E_USERDATA: path.join(tmp, 'app'), E2E_EXT_ID: extId, E2E_PORT_FILE: portFile, RDVAULT_LOG_LEVEL: 'warn' }, stdio: ['ignore', 'ignore', 'ignore'] });
    const s0 = Date.now(); while (!fs.existsSync(portFile) && Date.now() - s0 < 40000) await sleep(300);
    if (!fs.existsSync(portFile)) throw new Error('coffre local non démarré');
    const vaultPort = Number(fs.readFileSync(portFile, 'utf8'));
    await waitPort(SYNC_PORT); await waitPort(APP_DEBUG_PORT);
    // SITES-22 : le port de synchronisation est tenu par l'application lancée ici, et par elle seule
    assertSyncPortOwner(app.pid);
    check(true, 'port ' + SYNC_PORT + ' tenu par l\'application de test (PID ' + app.pid + ')');

    // Création du premier compte : confirmation du mot de passe exigée (AUTH-14)
    let r = await vreq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS, confirm: PASS });
    check(r.status === 200, 'compte créé via API (avec confirmation)');
    const vtoken = r.json.auth.client_token;
    r = await vreq(vaultPort, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent(SECRET.name)}`, vtoken, { data: { Username: SECRET.Username, Password: SECRET.Password, Website: SECRET.Website } });
    check(r.status === 200, 'secret localhost créé');
    r = await vreq(vaultPort, 'POST', `/v1/TOTP/keys/${encodeURIComponent(TOTP_KEY)}`, vtoken, { key: TOTP_B32, period: 30, digits: 6 });
    check(r.status === 204, 'clé TOTP créée (' + TOTP_KEY + ')');

    appBrowser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + APP_DEBUG_PORT, defaultViewport: null });
    let appPage = null; for (let i = 0; i < 40 && !appPage; i++) { const ps = await appBrowser.pages(); appPage = ps.find(p => /index\.html/.test(p.url())) || null; if (!appPage) await sleep(500); }
    if (!appPage) throw new Error('page de l\'app introuvable');
    // Formulaire de connexion habituel (écran de création rechargé s'il était affiché avant le compte, AUTH-14)
    await loginInApp(appPage, USER, PASS); await sleep(3000);

    const page = await browser.newPage(); await page.setViewport({ width: 1050, height: 800 });

    // ===== 1. Login en DEUX PAGES distinctes =====
    await page.goto('https://localhost:8443/step1.html', { waitUntil: 'load' }); await sleep(1200);
    check(await pick(page, '#u', 'admin'), '2 pages — étape 1 : menu ouvert et entrée choisie');
    check(await val(page, '#u') === 'admin', '2 pages — étape 1 : identifiant rempli');
    await page.click('#next'); // navigation vers step2.html (page séparée)
    await page.waitForFunction(() => window.location.pathname.endsWith('step2.html'), { timeout: 10000 });
    await sleep(1500);
    // Sur la page 2, le champ mot de passe doit recevoir l'icône ; on l'ouvre et on choisit
    check(await pick(page, '#p', 'admin'), '2 pages — étape 2 (URL séparée) : menu proposé sur le mot de passe');
    check(await val(page, '#p') === 'Adm1n-pass-2', '2 pages — étape 2 : mot de passe rempli');

    // ===== 2. TOTP automatique =====
    await page.goto('https://localhost:8443/totp.html', { waitUntil: 'load' }); await sleep(1200);
    check(await pick(page, '#u', 'admin'), 'TOTP — identifiant choisi');
    check(await val(page, '#u') === 'admin' && await val(page, '#p') === 'Adm1n-pass-2', 'TOTP — identifiant et mot de passe remplis');
    // Attendre le remplissage automatique du champ TOTP (watch post-login)
    let otp = ''; const s1 = Date.now();
    while (Date.now() - s1 < 8000) { otp = await val(page, '#otp'); if (/^\d{6}$/.test(otp)) break; await sleep(500); }
    const expected = totp(TOTP_B32);
    const expectedPrev = totp(TOTP_B32, Date.now() - 30000); // tolérance limite de période
    check(/^\d{6}$/.test(otp), 'TOTP — un code à 6 chiffres a été saisi automatiquement (' + (otp || 'vide') + ')');
    check(otp === expected || otp === expectedPrev, 'TOTP — le code saisi correspond au code attendu (' + otp + ' vs ' + expected + ')');

    await page.close();
  } catch (e) { console.log('FAIL exception: ' + ((e && e.stack) || e)); failures++; }
  finally {
    try { if (appBrowser) appBrowser.disconnect(); } catch {}
    try { if (app) app.kill(); } catch {}
    try { if (browser) await browser.close(); } catch {}
    try { if (site) site.kill(); } catch {}
    try { if (rewroteConfig) { if (had) fs.renameSync(cfg + '.feat-backup', cfg); else fs.unlinkSync(cfg); } } catch {}
    // Dossier temporaire (profil Chrome, coffre de test) supprimé une fois l'application arrêtée
    await removeTempDir(tmp, app);
    console.log(failures === 0 ? 'FEATURES OK' : 'FEATURES FAILURES: ' + failures);
    process.exit(failures === 0 ? 0 : 1);
  }
}
main();
