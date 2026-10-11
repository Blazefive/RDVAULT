// Diagnostic : pour chaque site, dumpe tous les champs input (toutes frames) avec leurs
// attributs, et indique si le content script de l'extension y a injecté son hôte d'UI.
// But : comprendre pourquoi la détection échoue, sans rien remplir.
// Même garde que real-sites.js : refus de démarrer si le port 45678 est déjà pris (SITES-22), puis contrôle
// que l'application lancée ici le tient ; dossier temporaire supprimé à la fin ; code 1 en cas d'erreur.
// Lancement : E2E_BROWSER=<chrome> node test/e2e/diag-fields.js github,yahoo,ameli
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const net = require('net');
const http = require('http');
const { appWrapperPath, loginInApp, removeTempDir, waitSyncPortFree, assertSyncPortOwner, SYNC_PORT } = require('./app-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const CHROME = process.env.E2E_BROWSER;
if (!CHROME) { console.error('E2E_BROWSER manquant'); process.exit(2); }
const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
const electronPath = require(path.join(ROOT, 'node_modules/electron'));
const APP_DEBUG_PORT = 9336;
const USER = 'e2e', PASS = 'E2e-password-123', ENGINE = `users/${USER}/Mes-Secrets`;

const ALL = {
  yahoo: 'https://login.yahoo.com/',
  orange: 'https://login.orange.fr/',
  ameli: 'https://assure.ameli.fr/PortailAS/appmanager/PortailAS/assure',
  notion: 'https://www.notion.so/login',
  zoho: 'https://accounts.zoho.com/signin',
  github: 'https://github.com/login',
};
const ids = (process.argv[2] || Object.keys(ALL).join(',')).split(',');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const enc = (e) => e.split('/').map(encodeURIComponent).join('/');

function waitPort(port, t = 30000) { const s = Date.now(); return new Promise((res, rej) => { (function tr() { const c = net.connect(port, '127.0.0.1'); c.once('connect', () => { c.destroy(); res(); }); c.once('error', () => { c.destroy(); Date.now() - s > t ? rej(new Error('port')) : setTimeout(tr, 300); }); })(); }); }
function vreq(port, method, p, token, body) { return new Promise((res, rej) => { const d = body ? JSON.stringify(body) : null; const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Vault-Token': token } : {}), ...(d ? { 'Content-Length': Buffer.byteLength(d) } : {}) } }, x => { let b = ''; x.on('data', c => b += c); x.on('end', () => { let j = null; try { j = JSON.parse(b); } catch {} res({ status: x.statusCode, json: j }); }); }); r.on('error', rej); if (d) r.write(d); r.end(); }); }

const DUMP = () => {
  const out = [];
  const seen = new Set();
  function describe(i) {
    const r = i.getBoundingClientRect(); const cs = getComputedStyle(i);
    const vis = r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) > 0;
    const data = {};
    for (const a of i.getAttributeNames()) if (a.startsWith('data-') || a === 'formcontrolname') data[a] = i.getAttribute(a).slice(0, 30);
    return { type: i.type, name: i.name || '', id: (i.id || '').slice(0, 40), ac: i.getAttribute('autocomplete') || '', ph: (i.placeholder || '').slice(0, 30), aria: (i.getAttribute('aria-label') || '').slice(0, 30), role: i.getAttribute('role') || '', vis, form: !!i.form, data };
  }
  function walk(root, where) {
    root.querySelectorAll('input').forEach(i => { if (!seen.has(i)) { seen.add(i); const t = (i.type || 'text').toLowerCase(); if (['text', 'email', 'tel', 'password', 'search', 'number', ''].includes(t)) out.push({ where, ...describe(i) }); } });
    root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) walk(el.shadowRoot, where + '>shadow'); });
  }
  walk(document, 'doc');
  const uiHost = document.querySelectorAll('div[style*="all: initial"]').length;
  const icons = (() => { try { return document.querySelectorAll('div[style*="all: initial"]').length; } catch { return -1; } })();
  return { host: window.location.hostname, inputs: out, uiHost, icons };
};

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-diag-'));
  const configCfg = path.join(ROOT, 'config.cfg');
  const had = fs.existsSync(configCfg);
  // config.cfg n'est réécrit (avec sauvegarde) que s'il diffère de la config de test (comme real-sites.js)
  const WANTED_CFG = 'APP_MODE=local\nLANG=fr\n';
  let rewroteConfig = false;
  let appProc, browser, appBrowser;
  let failed = false;
  try {
    // SITES-22 : port de synchronisation libre avant tout lancement (sinon refus : voir app-helpers.js)
    await waitSyncPortFree();
    if (!had || fs.readFileSync(configCfg, 'utf8') !== WANTED_CFG) {
      if (had) fs.copyFileSync(configCfg, configCfg + '.diag-backup');
      fs.writeFileSync(configCfg, WANTED_CFG);
      rewroteConfig = true;
    }
    const portFile = path.join(tmp, 'port.txt');
    browser = await puppeteer.launch({ executablePath: CHROME, headless: false, userDataDir: path.join(tmp, 'chrome'), defaultViewport: null, ignoreDefaultArgs: ['--disable-extensions', '--enable-automation'], args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT, '--no-first-run', '--no-default-browser-check', '--window-size=1280,960', '--lang=fr-FR'] });
    const sw = await browser.waitForTarget(t => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 });
    const extId = new URL(sw.url()).hostname;
    appProc = spawn(electronPath, [appWrapperPath(), '--remote-debugging-port=' + APP_DEBUG_PORT], { env: { ...process.env, E2E_USERDATA: path.join(tmp, 'app'), E2E_EXT_ID: extId, E2E_PORT_FILE: portFile, RDVAULT_LOG_LEVEL: 'warn' }, stdio: ['ignore', 'ignore', 'ignore'] });
    const s = Date.now(); while (!fs.existsSync(portFile) && Date.now() - s < 40000) await sleep(300);
    if (!fs.existsSync(portFile)) throw new Error('coffre local non démarré');
    const vaultPort = Number(fs.readFileSync(portFile, 'utf8'));
    await waitPort(SYNC_PORT); await waitPort(APP_DEBUG_PORT);
    assertSyncPortOwner(appProc.pid);
    // Création du premier compte : confirmation du mot de passe exigée (AUTH-14)
    let r = await vreq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS, confirm: PASS });
    if (r.status !== 200 || !r.json || !r.json.auth) throw new Error('création du compte de test refusée (HTTP ' + r.status + ')');
    const vtoken = r.json.auth.client_token;
    for (const id of ids) { const url = ALL[id]; await vreq(vaultPort, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('site-' + id)}`, vtoken, { data: { Username: `rdvault-${id}@example.com`, Password: `Pw-${id}`, URL: url } }); }
    appBrowser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + APP_DEBUG_PORT, defaultViewport: null });
    let appPage = null; for (let i = 0; i < 40 && !appPage; i++) { const ps = await appBrowser.pages(); appPage = ps.find(p => /index\.html/.test(p.url())) || null; if (!appPage) await sleep(500); }
    if (!appPage) throw new Error('page de l\'app introuvable');
    // Formulaire de connexion habituel (écran de création rechargé s'il était affiché avant le compte, AUTH-14)
    await loginInApp(appPage, USER, PASS); await sleep(2500);

    for (const id of ids) {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 900 });
      try {
        await page.goto(ALL[id], { waitUntil: 'domcontentloaded', timeout: 45000 });
        await sleep(3500);
        // fermer bannières cookies
        await page.evaluate(() => { const re = /^(tout accepter|accepter|j'accepte|accept all|accept|agree|ok|continuer sans accepter)$/i; const b = Array.from(document.querySelectorAll('button,[role=button],a')).find(x => re.test((x.textContent || '').trim()) && x.offsetParent); if (b) b.click(); }).catch(() => {});
        await sleep(1500);
        console.log('\n===== ' + id + ' (' + ALL[id] + ') =====');
        // Sonde du monde isolé (content script) de la frame principale
        try {
          const cdp = await page.createCDPSession();
          const contexts = [];
          cdp.on('Runtime.executionContextCreated', e => contexts.push(e.context));
          await cdp.send('Runtime.enable'); await sleep(600);
          // Monde isolé de l'EXTENSION (origine chrome-extension://) : puppeteer crée aussi le sien, sans chrome.runtime
          const iso = contexts.filter(c => c.auxData && c.auxData.type === 'isolated' && String(c.origin || '').startsWith('chrome-extension://'));
          let probe = 'aucun monde isolé de l\'extension';
          if (iso.length) {
            const r = await cdp.send('Runtime.evaluate', { contextId: iso[iso.length - 1].id, expression: "(async()=>{try{const r=await chrome.runtime.sendMessage({type:'GET_CREDENTIALS'});return JSON.stringify({ok:!!r&&r.success,n:(r&&r.credentials||[]).length,host:location.hostname});}catch(e){return 'ERR '+e.message;}})()", awaitPromise: true, returnByValue: true });
            probe = r.result && r.result.value;
          }
          console.log('  [content script frame principale] ' + probe);
          await cdp.detach();
        } catch (e) { console.log('  [probe err] ' + e.message); }
        for (const fr of page.frames()) {
          try {
            const d = await fr.evaluate(DUMP);
            const relevant = d.inputs.filter(i => i.vis && ['text', 'email', 'tel', 'password', ''].includes(i.type));
            if (relevant.length === 0 && d.uiHost === 0 && fr !== page.mainFrame()) continue;
            console.log(`  [frame ${d.host}] uiHost=${d.uiHost}`);
            for (const i of relevant) console.log('    ' + JSON.stringify(i));
          } catch (e) { console.log('  [frame cross-origin inaccessible]'); }
        }
      } catch (e) { console.log('===== ' + id + ' ERREUR: ' + e.message); }
      await page.close().catch(() => {});
    }
  } catch (err) {
    failed = true;
    console.log('ERREUR GLOBALE: ' + ((err && err.stack) || err));
  } finally {
    try { if (appBrowser) appBrowser.disconnect(); } catch {}
    try { if (appProc) appProc.kill(); } catch {}
    try { if (browser) await browser.close(); } catch {}
    try { if (rewroteConfig) { if (had) fs.renameSync(configCfg + '.diag-backup', configCfg); else fs.unlinkSync(configCfg); } } catch {}
    // Dossier temporaire (profil Chrome, coffre de test) supprimé une fois l'application arrêtée
    await removeTempDir(tmp, appProc);
    process.exit(failed ? 1 : 0);
  }
}
main();
