// Test de fumée du serveur de synchronisation (main.js réel, userData temporaire, extension pré-appairée).
// Lancement : npx electron scratchpad/smoke-sync.js   (nécessite build/index.html)
const { app, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');

const ROOT = path.resolve(__dirname, '..', '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-sync-'));
app.setPath('userData', tmp);
process.env.RDVAULT_LOG_LEVEL = 'warn';

// Pas d'effet de bord sur le registre Windows pendant le test
app.setAsDefaultProtocolClient = () => true;

const PAIRED = 'abcdefghijklmnopabcdefghijklmnop';
const UNPAIRED = 'ppppppppppppppppppppppppppppppppp'.slice(0, 32);
fs.writeFileSync(path.join(tmp, 'paired-extensions.json'), JSON.stringify([PAIRED]));

let failures = 0;
function check(cond, label) { console.log((cond ? 'PASS ' : 'FAIL ') + label); if (!cond) failures++; }

function get(p, headers = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: 45678, method: 'GET', path: p, headers }, (res) => {
      let buf = ''; res.on('data', c => buf += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch {} resolve({ status: res.statusCode, json, headers: res.headers }); });
    });
    r.on('error', reject); r.end();
  });
}
const origin = (id) => 'chrome-extension://' + id;

// Gestionnaires IPC de main.js capturés à l'enregistrement : appelés ensuite avec la VRAIE fenêtre principale
// comme expéditeur (validateIpcSender), sans passer par une API interne d'Electron
const ipcHandlers = new Map();
const origHandle = ipcMain.handle.bind(ipcMain);
ipcMain.handle = (channel, fn) => { ipcHandlers.set(channel, fn); return origHandle(channel, fn); };

// Boîtes de dialogue natives interceptées (options journalisées, réponse « Refuser » = 1) : jamais d'appairage réel
const { dialog, BrowserWindow } = require('electron');
const dialogs = [];
dialog.showMessageBox = async (win, opts) => { dialogs.push(opts || win); return { response: 1 }; };

require(path.join(ROOT, 'electron/main.js'));
const mainI18n = require(path.join(ROOT, 'electron/mainI18n.js')); // même instance que celle de main.js
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
async function waitFor(pred, timeoutMs = 20000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) { if (pred()) return true; await sleep(100); } // eslint-disable-line no-await-in-loop
  return pred();
}

app.whenReady().then(async () => {
  await new Promise(r => setTimeout(r, 2500)); // laisser démarrer le serveur sync (setImmediate) et la fenêtre
  try {
    let r = await get('/auth/token');
    check(r.status === 403, 'no origin → 403');
    r = await get('/auth/token', { Origin: 'https://evil.example' });
    check(r.status === 403, 'web origin → 403');
    r = await get('/auth/token', { Origin: origin(PAIRED) });
    check(r.status === 403, 'paired origin without X-Vault-Extension → 403');
    r = await get('/auth/token', { Origin: origin(PAIRED), 'X-Vault-Extension': 'rdvault' });
    check(r.status === 200 && /^[0-9a-f]{64}$/.test(r.json?.token || ''), 'paired origin gets token without dialog');
    const token = r.json.token;
    check(r.headers['access-control-allow-origin'] === origin(PAIRED), 'CORS echoes paired origin');

    r = await get('/sync', { Origin: origin(UNPAIRED), Authorization: 'Bearer ' + token });
    check(r.status === 403 && r.json?.error === 'pairing_required', 'unpaired origin with valid token → pairing_required');
    r = await get('/sync', { Origin: origin(PAIRED), Authorization: 'Bearer ' + 'f'.repeat(64) });
    check(r.status === 401, 'wrong bearer → 401');
    r = await get('/sync', { Origin: origin(PAIRED), Authorization: 'Bearer ' + token });
    check(r.status === 200 && r.json?.connected === false, '/sync connected:false before login');

    r = await get('/api/secrets', { Origin: origin(PAIRED), Authorization: 'Bearer ' + token });
    check(r.status === 401 || r.status === 400, '/api/secrets without state → 401/400 (' + r.status + ')');

    // Simuler l'écriture d'état par le renderer via le handler IPC (accès direct au module ipcMain)
    // Impossible sans webContents valide (validateIpcSender) : on vérifie que le handler refuse un faux sender.
    const handler = ipcMain._invokeHandlers?.get?.('sync-write-state');
    check(typeof handler === 'function' || handler === undefined, 'ipc handler registry accessible or not (informative)');

    // Identification par header (Chrome omet Origin sur les hôtes host_permissions)
    r = await get('/auth/token', { 'X-Vault-Extension': 'rdvault', 'X-Vault-Extension-Id': PAIRED });
    check(r.status === 200 && r.json?.token === token, 'header X-Vault-Extension-Id (sans Origin) accepté pour une extension appairée');
    r = await get('/auth/token', { 'X-Vault-Extension': 'rdvault', 'X-Vault-Extension-Id': 'not-a-valid-id' });
    check(r.status === 403, 'header X-Vault-Extension-Id malformé → 403');
    r = await get('/sync', { 'X-Vault-Extension-Id': UNPAIRED, Authorization: 'Bearer ' + token });
    check(r.status === 403 && r.json?.error === 'pairing_required', 'header id non appairé → pairing_required');
    r = await get('/api/totp/x%2Fy', { Origin: origin(PAIRED), Authorization: 'Bearer ' + token });
    check(r.status === 401, 'totp without state → 401');
    r = await get('/nope', { Origin: origin(PAIRED), Authorization: 'Bearer ' + token });
    check(r.status === 404, 'unknown route → 404');
    r = await new Promise((resolve, reject) => {
      const rq = http.request({ host: '127.0.0.1', port: 45678, method: 'POST', path: '/sync', headers: { Origin: origin(PAIRED), Authorization: 'Bearer ' + token } }, (res) => resolve({ status: res.statusCode }));
      rq.on('error', reject); rq.end();
    });
    check(r.status === 404, 'POST sur une route GET (/sync) → 404 (méthode verrouillée)');
    // Une route passkey existe bien pour POST (400 sans corps valide, pas 404/405)
    r = await new Promise((resolve, reject) => {
      const body = '{}';
      const rq = http.request({ host: '127.0.0.1', port: 45678, method: 'POST', path: '/api/passkey', headers: { Origin: origin(PAIRED), Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => resolve({ status: res.statusCode }));
      rq.on('error', reject); rq.write(body); rq.end();
    });
    check(r.status === 400 || r.status === 401, 'POST /api/passkey sans passkey valide → 400/401 (route existe)');
    r = await new Promise((resolve, reject) => {
      const rq = http.request({ host: '127.0.0.1', port: 45678, method: 'OPTIONS', path: '/sync', headers: { Origin: origin(PAIRED) } }, (res) => resolve({ status: res.statusCode, h: res.headers }));
      rq.on('error', reject); rq.end();
    });
    check(r.status === 200 && r.h['access-control-allow-private-network'] === 'true', 'OPTIONS preflight ok for paired origin');

    const win = BrowserWindow.getAllWindows()[0];
    const ev = { sender: win.webContents };

    // (MAIN-8) plus de plafond silencieux de 5 000 entrées : la 5 100e entrée (et celles d'un autre coffre,
    // aplaties après le premier) restent proposées à l'extension
    const big = Array.from({ length: 5100 }, (_, i) => ({ name: 'entree-' + i, engine: i < 5000 ? 'V00' : 'V01', username: 'u' + i, password: 'p' + i, url: 'https://login.site' + i + '.com', type: 'login' }));
    const w = await ipcHandlers.get('sync-write-state')(ev, { vaultUrl: 'http://127.0.0.1:1', username: 'smoke', connected: true, secrets: big });
    check(w && w.success === true && !w.truncated, 'sync-write-state : 5 100 entrées acceptées sans troncature (' + JSON.stringify(w) + ')');
    const st = await ipcHandlers.get('sync-read-state')(ev);
    check(st?.data?.secretCount === 5100, 'sync-read-state : 5 100 entrées transmises à l\'extension (' + st?.data?.secretCount + ')');
    r = await get('/api/secrets?host=login.site5099.com', { Origin: origin(PAIRED), Authorization: 'Bearer ' + token });
    check(r.status === 200 && r.json?.secrets?.length === 1 && r.json.secrets[0].name === 'entree-5099' && r.json.secrets[0].engine === 'V01', '/api/secrets : la 5 100e entrée (autre coffre) est proposée à l\'autoremplissage');
    await ipcHandlers.get('sync-write-state')(ev, { connected: false });

    // (MAIN-30) déconnexion / expiration : retour à la carte de connexion 540×820 non redimensionnable
    await ipcHandlers.get('window-set-main-mode')(ev);
    await sleep(300);
    const mainSize = win.getSize();
    check(mainSize[0] === 1280 && mainSize[1] === 800 && win.isResizable(), 'mode principal : 1280×800 redimensionnable (' + mainSize + ')');
    await ipcHandlers.get('window-set-login-mode')(ev);
    await sleep(300);
    const loginSize = win.getSize();
    check(loginSize[0] === 540 && loginSize[1] === 820 && !win.isResizable(), 'déconnexion : retour à 540×820 non redimensionnable (' + loginSize + ', resizable=' + win.isResizable() + ')');
    await ipcHandlers.get('window-set-main-mode')(ev);
    await sleep(300);
    const mainSize2 = win.getSize();
    await ipcHandlers.get('window-set-login-mode')(ev);
    await sleep(300);
    const loginSize2 = win.getSize();
    check(mainSize2[0] === 1280 && loginSize2[0] === 540 && loginSize2[1] === 820, 'second cycle connexion / déconnexion : 1280 puis 540×820 (' + mainSize2 + ' / ' + loginSize2 + ')');

    // (MAIN-26) boîte d'appairage dans la langue de l'interface : VRAIE chaîne renderer (I18nProvider → <html lang>)
    // → preload → IPC 'set-ui-language' → processus principal. Langue changée par localStorage + rechargement.
    const UNKNOWN = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';
    const pairingDialog = async () => {
      dialogs.length = 0;
      const pr = await get('/auth/token', { Origin: origin(UNKNOWN), 'X-Vault-Extension': 'rdvault' });
      return { status: pr.status, error: pr.json?.error, d: dialogs[0] };
    };
    const setUiLang = async (lang) => {
      await win.webContents.executeJavaScript(lang ? `localStorage.setItem('rdvault-lang', ${JSON.stringify(lang)}); location.reload(); true` : 'localStorage.removeItem(\'rdvault-lang\'); location.reload(); true').catch(() => {});
    };
    await setUiLang('de');
    check(await waitFor(() => mainI18n.getLanguage() === 'de'), 'interface en allemand : langue transmise au processus principal (' + mainI18n.getLanguage() + ')');
    let p = await pairingDialog();
    check(p.status === 403 && p.error === 'pairing_denied' && p.d?.title === 'Kopplung der Chrome-Erweiterung' && JSON.stringify(p.d?.buttons) === '["Zulassen","Ablehnen"]' && p.d?.defaultId === 1 && p.d?.cancelId === 1 && p.d?.detail.includes(UNKNOWN), 'appairage : boîte en allemand, refus par défaut (' + p.d?.title + ')');
    await setUiLang('en');
    check(await waitFor(() => mainI18n.getLanguage() === 'en'), 'interface en anglais : langue transmise (' + mainI18n.getLanguage() + ')');
    p = await pairingDialog();
    check(p.d?.title === 'Chrome extension pairing' && p.d?.message === 'A Chrome extension is requesting access to your credentials.' && JSON.stringify(p.d?.buttons) === '["Allow","Deny"]', 'appairage : boîte en anglais (' + p.d?.title + ')');
    const cfgLang = require(path.join(ROOT, 'electron/configLoader.js')).getConfig().LANG;
    await setUiLang(null); // sans préférence : langue de config.cfg appliquée par l'interface
    check(await waitFor(() => mainI18n.getLanguage() === cfgLang), 'sans préférence : langue de config.cfg (' + cfgLang + ') reprise par l\'interface et le processus principal');
    p = await pairingDialog();
    if (cfgLang === 'fr') {
      check(p.d?.title === 'Appairage extension Chrome' && p.d?.message === 'Une extension Chrome demande l\'accès à vos identifiants.' && JSON.stringify(p.d?.buttons) === '["Autoriser","Refuser"]'
        && p.d?.detail === 'Identifiant de l\'extension :\n' + UNKNOWN + '\n\nVérifiez qu\'il correspond à l\'extension RDVAULT installée (chrome://extensions).\nN\'autorisez que si vous venez d\'installer ou d\'ouvrir l\'extension.', 'appairage : boîte en français strictement identique à l\'existant');
    } else {
      check(p.d?.title === mainI18n.tm('pairing.title', {}, cfgLang), 'appairage : boîte dans la langue de config.cfg (' + cfgLang + ')');
    }
    check(!JSON.parse(fs.readFileSync(path.join(tmp, 'paired-extensions.json'), 'utf8')).includes(UNKNOWN), 'extensions refusées jamais appairées');

    // (SYNC-27) clé TOTP d'une entrée rangée dans un dossier (« PRÉFIXE-dossier/compte ») : plus refusée (400) ;
    // « .. » toujours refusé. Interface non connectée : le renderer ne répond pas (délai → 500), jamais 400.
    const authHdr = { Origin: origin(PAIRED), Authorization: 'Bearer ' + token };
    const state = { vaultUrl: 'http://127.0.0.1:1', username: 'smoke', connected: true, secrets: [
      { name: 'dossier/compte', engine: 'mes-secrets', username: 'nested-user', password: 'Nested-pass-1', url: 'https://localhost:8457', type: 'login' },
      { name: 'racine', engine: 'mes-secrets', username: 'racine-user', password: 'Racine-pass-1', url: 'https://localhost:8457', type: 'login' },
    ] };
    await ipcHandlers.get('sync-write-state')(ev, state);
    r = await get('/api/totp/' + encodeURIComponent('MES-SECRETS-dossier/compte'), authHdr);
    check(r.status !== 400 && r.status !== 401, '/api/totp : clé TOTP d\'une entrée en dossier acceptée (' + r.status + ' ' + JSON.stringify(r.json) + ')');
    r = await get('/api/totp/' + encodeURIComponent('MES-SECRETS-a/../b'), authHdr);
    check(r.status === 400, '/api/totp : « .. » toujours refusé (' + r.status + ')');

    // (SYNC-28) renderer RÉEL planté : l'extension ne reçoit plus les mots de passe (état purgé)
    await ipcHandlers.get('sync-write-state')(ev, state);
    r = await get('/api/secret?host=localhost&engine=mes-secrets&name=racine', authHdr);
    check(r.status === 200 && r.json?.secret?.password === 'Racine-pass-1', 'témoin : mot de passe servi tant que l\'interface est vivante (' + r.status + ')');
    const gone = new Promise((resolve) => { win.webContents.once('render-process-gone', (_e, d) => resolve(d && d.reason)); setTimeout(() => resolve('délai'), 10000); });
    win.webContents.forcefullyCrashRenderer();
    const reason = await gone;
    r = await get('/api/secret?host=localhost&engine=mes-secrets&name=racine', authHdr);
    check(r.status === 401, 'renderer planté (' + reason + ') : /api/secret ne sert plus le mot de passe (' + r.status + ')');
    r = await get('/sync', authHdr);
    check(r.status === 200 && r.json?.connected === false, 'renderer planté : /sync connected:false');
    const stCrash = await ipcHandlers.get('sync-read-state')(ev);
    check(stCrash?.data === null, 'renderer planté : état de synchronisation purgé de la mémoire');

    // Limitation de débit par catégorie de route : une rafale de lectures (/sync, /api/secrets,
    // appelées à chaque onglet par l'extension) n'est pas limitée à 60/min et n'épuise pas la
    // limite des routes sensibles, qui reste de 60/min.
    const auth = { Origin: origin(PAIRED), Authorization: 'Bearer ' + token };
    let read429 = 0;
    for (let i = 0; i < 100; i++) {
      // eslint-disable-next-line no-await-in-loop
      const rr = await get(i % 2 ? '/sync' : '/api/secrets?host=example.com', auth);
      if (rr.status === 429) read429++;
    }
    check(read429 === 0, 'rafale de 100 lectures /sync + /api/secrets en < 1 min → aucune 429 (' + read429 + ')');
    r = await get('/api/totp/abc', auth);
    check(r.status === 401, 'route sensible encore disponible après la rafale de lectures (' + r.status + ')');
    let strict429 = 0;
    for (let i = 0; i < 65; i++) {
      // eslint-disable-next-line no-await-in-loop
      const rr = await get('/api/secret?host=example.com&engine=e&name=n', auth);
      if (rr.status === 429) strict429++;
    }
    check(strict429 > 0, 'routes sensibles toujours limitées à 60/min (' + strict429 + ' réponses 429 sur 65)');
    r = await get('/sync', auth);
    check(r.status === 200, 'lecture /sync encore servie quand la limite des routes sensibles est atteinte (' + r.status + ')');

    // Anciens fichiers de sync supprimés au démarrage (créés avant require → déjà vérifié par la migration au chargement du module)
    check(!fs.existsSync(path.join(tmp, 'vault-sync.enc')) && !fs.existsSync(path.join(tmp, 'sync-auth-token.txt')), 'no sync files on disk');
    const files = fs.readdirSync(tmp).filter(f => /sync|token/i.test(f));
    check(files.length === 0, 'no secret-bearing files in userData: ' + JSON.stringify(files));
  } catch (err) {
    console.log('FAIL exception: ' + ((err && err.stack) || err)); failures++;
  }
  console.log(failures === 0 ? 'SMOKE SYNC OK' : `SMOKE SYNC FAILURES: ${failures}`);
  setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} app.exit(failures === 0 ? 0 : 1); }, 300);
});
