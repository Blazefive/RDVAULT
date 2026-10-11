// Test UI de l'application : export CSV/XML puis import via la vraie interface (dialogues natifs remplacés),
// vérification de l'aller-retour exact, et captures d'écran pour contrôle visuel.
// AUTH-14 : premier démarrage (écran de création du compte administrateur, confirmation du mot de passe).
// Lancement : node test/e2e/app-ui.js   (nécessite build/index.html ; E2E_APP_WRAPPER facultatif, voir app-helpers.js)
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const net = require('net');
const { spawn } = require('child_process');
const { appWrapperPath, loginInApp, isSetupForm, removeTempDir, waitSyncPortFree, assertSyncPortOwner, SYNC_PORT } = require('./app-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const SHOTS = path.join(os.tmpdir(), 'rdvault-e2e-shots');
const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
const electronPath = require(path.join(ROOT, 'node_modules/electron'));
const APP_DEBUG_PORT = 9334;
const USER = 'e2e';
const PASS = 'E2e-password-123';
const ENGINE_A = `users/${USER}/Mes-Secrets`;
const ENGINE_B = `users/${USER}/Import-Test`;

// Valeurs piégeuses : guillemets, séparateurs, sauts de ligne, formules, apostrophes, unicode, espaces
const SECRETS = {
  'srv-simple': { Username: 'root', Password: 'P@ss,word;1', URL: 'https://a.example.com', Notes: 'note simple', Tags: 'prod,linux' },
  'Dossier/srv-nested': { Username: 'admin', Password: 'quote"inside"', URL: 'https://b.example.com/x?y=1&z=2', Notes: 'ligne1\nligne2\n"citée"', Tags: 'dev' },
  'srv espace': { Username: 'user name', Password: '=formule()', URL: 'c.example.com', Notes: "'apostrophe & <xml>", Tags: '' },
  'srv-unicode': { Username: 'été', Password: '  espaces  ', URL: 'https://d.example.com', Notes: 'ünïcödé ✓ — «guillemets»', Tags: 'a;b' },
  'srv-port': { Username: 'pi', Password: '-tiret', URL: 'https://e.example.com', Notes: '', Tags: 'iot', CustomFields: [{ key: 'Port', value: '2222' }] },
};

let failures = 0;
const log = (...a) => console.log('[UI]', ...a);
function check(cond, label) { console.log((cond ? 'PASS ' : 'FAIL ') + label); if (!cond) failures++; }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
// Capture d'écran NON bloquante : purement visuelle, ne doit jamais faire échouer le test fonctionnel.
async function shot(page, file) { try { await page.screenshot({ path: file }); } catch (e) { console.log('[shot] ignorée:', (e.message||'').slice(0,60)); } }

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
function vaultReq(port, method, p, token, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Vault-Token': token } : {}), ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let buf = ''; res.on('data', c => buf += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch {} resolve({ status: res.statusCode, json }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}
const enc = (engine) => engine.split('/').map(encodeURIComponent).join('/');

async function listAllKeys(port, token, engine, prefix = '') {
  const r = await vaultReq(port, 'GET', `/v1/${enc(engine)}/metadata/${prefix ? prefix.split('/').map(encodeURIComponent).join('/') : ''}?list=true`, token);
  const keys = r.json?.data?.keys || [];
  const out = [];
  for (const k of keys) {
    if (k.endsWith('/')) out.push(...await listAllKeys(port, token, engine, prefix + k));
    else out.push(prefix + k);
  }
  return out;
}
async function readAll(port, token, engine) {
  const keys = await listAllKeys(port, token, engine);
  const out = {};
  for (const k of keys) {
    const r = await vaultReq(port, 'GET', `/v1/${enc(engine)}/data/${encodeURIComponent(k)}`, token);
    out[k] = r.json?.data?.data || null;
  }
  return out;
}


async function rowTexts(page) {
  return page.evaluate(() => Array.from(document.querySelectorAll('.secrets-table tbody tr')).map(t => t.textContent.replace(/\s+/g, ' ').trim()));
}
async function fillLabeled(page, labelRe, value) {
  const groups = await page.$$('.form-group-vertical');
  for (const g of groups) {
    const label = await g.$eval('.modal-label', el => el.textContent.trim()).catch(() => null);
    if (label && labelRe.test(label)) {
      const input = await g.$('input.modal-input, textarea.modal-textarea, input:not([type=checkbox]):not([type=radio]), textarea');
      if (input) { await input.click({ clickCount: 3 }); await input.press('Backspace'); await input.type(value); return true; }
    }
  }
  return false;
}

async function clickByText(page, selector, re) {
  const handles = await page.$$(selector);
  for (const h of handles) {
    const txt = (await h.evaluate(el => el.textContent || '')).trim();
    if (re.test(txt)) { await h.click(); return txt; }
  }
  return null;
}

async function openSettingsExportTab(appPage) {
  await appPage.click('.user-menu-trigger');
  await sleep(300);
  const clicked = await clickByText(appPage, '.user-menu-item:not(.user-menu-item-admin):not(.user-menu-item-logout)', /param|setting|réglage/i);
  if (!clicked) throw new Error('entrée Paramètres introuvable dans le menu utilisateur');
  await sleep(500);
  const tab = await clickByText(appPage, '.tab-button', /export|import/i);
  if (!tab) throw new Error('onglet Export introuvable');
  await sleep(400);
}

// Clé i18n brute (ex. « passwordHealth.title ») ou variable non substituée (« {{count}} ») visible dans une modale.
// On ne contrôle PAS le texte exact des libellés (traductions susceptibles d'évoluer), seulement l'absence de clé brute.
const RAW_I18N_RE = /\b(?:passwordHealth|passkeysView|passwordGenerator|common)\.[A-Za-z]+|\{\{\w+\}\}/g;
// Libellés de chargement des modales (FR/EN), remplacés par le contenu une fois la lecture du coffre terminée
const MODAL_LOADING_RE = /chargement…|analyse du coffre|loading…|analyzing your vault/i;

// Ouvre une modale depuis le menu utilisateur (entrée dont le libellé matche `re`), attend la fin du chargement
// et retourne le texte visible du panneau (null si l'entrée est introuvable).
async function openUserMenuModal(appPage, re, label) {
  await appPage.click('.user-menu-trigger');
  await sleep(300);
  const clicked = await clickByText(appPage, '.user-menu-item:not(.user-menu-item-admin):not(.user-menu-item-logout)', re);
  check(!!clicked, `${label}: entrée du menu utilisateur (${clicked})`);
  if (!clicked) { await appPage.click('.user-menu-trigger'); return null; } // refermer le menu (pas de fermeture par Escape)
  await appPage.waitForSelector('.modal-panel', { timeout: 10000 });
  await appPage.waitForFunction((src) => { const p = document.querySelector('.modal-panel'); return !!p && !new RegExp(src, 'i').test(p.innerText || ''); }, { timeout: 20000 }, MODAL_LOADING_RE.source).catch(() => {});
  return appPage.$eval('.modal-panel', el => el.innerText || '');
}
async function modalClosed(appPage) {
  return appPage.waitForSelector('.modal-panel', { hidden: true, timeout: 10000 }).then(() => true).catch(() => false);
}
function rawI18nKeys(text) { return text.match(RAW_I18N_RE) || []; }

async function runExportImport(appPage, vaultPort, vtoken, format, exportPath) {
  log('--- format', format, '---');
  await openSettingsExportTab(appPage);
  const selects = await appPage.$$('select');
  if (selects.length < 2) throw new Error('selects export/import introuvables (' + selects.length + ')');
  await selects[0].select(ENGINE_A);
  await appPage.click(`input[name="exportFormat"][value="${format}"]`);
  await sleep(200);
  try { fs.unlinkSync(exportPath); } catch {}
  const exportBtn = await clickByText(appPage, 'button.btn-primary', /^export/i);
  check(!!exportBtn, `${format}: bouton export cliqué`);
  const start = Date.now();
  while (!fs.existsSync(exportPath) && Date.now() - start < 20000) await sleep(300);
  check(fs.existsSync(exportPath), `${format}: fichier exporté écrit`);
  if (format === 'csv') await shot(appPage, path.join(SHOTS, 'settings-export.png'));
  const content = fs.existsSync(exportPath) ? fs.readFileSync(exportPath, 'utf8') : '';
  check(content.length > 100, `${format}: contenu non vide (${content.length} octets)`);
  check(Object.keys(SECRETS).every(n => content.includes(n.replace(/"/g, '""'))), `${format}: tous les noms présents dans le fichier`);

  // Import dans l'engine B (vide)
  await selects[1].select(ENGINE_B);
  const fileBtn = await clickByText(appPage, 'button.btn-secondary', /fichier|file|parcourir|choisir/i);
  check(!!fileBtn, `${format}: bouton de sélection de fichier cliqué`);
  await sleep(600);
  await appPage.click('input[type="radio"][value="overwrite"], input[type="radio"]:nth-of-type(2)').catch(() => {});
  const importBtn = await clickByText(appPage, 'button.btn-primary', /^import/i);
  check(!!importBtn, `${format}: bouton import cliqué`);
  let imported = {};
  const s2 = Date.now();
  while (Date.now() - s2 < 30000) {
    imported = await readAll(vaultPort, vtoken, ENGINE_B);
    if (Object.keys(imported).length >= Object.keys(SECRETS).length) break;
    await sleep(500);
  }
  check(Object.keys(imported).length === Object.keys(SECRETS).length, `${format}: ${Object.keys(imported).length}/${Object.keys(SECRETS).length} secrets importés`);
  for (const [name, expected] of Object.entries(SECRETS)) {
    const got = imported[name];
    if (!got) { check(false, `${format}: secret "${name}" absent après import`); continue; }
    const fields = ['Username', 'Password', 'URL', 'Notes', 'Tags'];
    const diffs = fields.filter(f => (got[f] || '') !== (expected[f] || ''));
    const port = (got.CustomFields || []).find(c => c.key === 'Port')?.value || '';
    const expPort = (expected.CustomFields || []).find(c => c.key === 'Port')?.value || '';
    if (port !== expPort) diffs.push('Port');
    check(diffs.length === 0, `${format}: "${name}" identique après aller-retour` + (diffs.length ? ' — différences: ' + diffs.map(f => `${f}=${JSON.stringify(got[f] ?? port)} attendu ${JSON.stringify(expected[f] ?? expPort)}`).join(' | ') : ''));
  }
  // Nettoyer B pour le format suivant
  for (const k of Object.keys(imported)) await vaultReq(vaultPort, 'DELETE', `/v1/${enc(ENGINE_B)}/metadata/${encodeURIComponent(k)}`, vtoken);
  // Fermer la modale (ESC)
  await appPage.keyboard.press('Escape');
  await sleep(400);
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-ui-'));
  const appUserData = path.join(tmp, 'app');
  const portFile = path.join(tmp, 'vault-port.txt');
  const exportPath = path.join(tmp, 'export-file');
  const appLog = fs.createWriteStream(path.join(tmp, 'app.log'));
  const configCfg = path.join(ROOT, 'config.cfg');
  const hadConfig = fs.existsSync(configCfg);
  // config.cfg n'est réécrit (avec sauvegarde) que s'il diffère de la config de test : aucun fichier de
  // sauvegarde ni course avec d'autres harnais lancés en parallèle (même règle que run.js)
  const WANTED_CFG = 'APP_MODE=local\nLANG=fr\n';
  let rewroteConfig = false;
  fs.mkdirSync(SHOTS, { recursive: true });
  let appProc, appBrowser;
  try {
    if (!fs.existsSync(path.join(ROOT, 'build/index.html'))) throw new Error('build manquant');
    // SITES-22 : port de synchronisation libre avant le lancement (refus sinon, voir app-helpers.js). Aucune
    // extension ici, mais l'application de test démarre son serveur de synchronisation : face à une instance
    // RDVAULT déjà ouverte, elle afficherait l'avertissement « port occupé » et ne testerait pas sa propre écoute.
    await waitSyncPortFree({ log: (m) => log(m.trim()) });
    if (!hadConfig || fs.readFileSync(configCfg, 'utf8') !== WANTED_CFG) {
      if (hadConfig) fs.copyFileSync(configCfg, configCfg + '.ui-backup');
      fs.writeFileSync(configCfg, WANTED_CFG);
      rewroteConfig = true;
    }

    appProc = spawn(electronPath, [appWrapperPath(), '--remote-debugging-port=' + APP_DEBUG_PORT], {
      env: { ...process.env, E2E_USERDATA: appUserData, E2E_PORT_FILE: portFile, E2E_EXPORT_PATH: exportPath, E2E_IMPORT_PATH: exportPath, RDVAULT_LOG_LEVEL: 'info' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    appProc.stdout.pipe(appLog); appProc.stderr.pipe(appLog);
    const start = Date.now();
    while (!fs.existsSync(portFile) && Date.now() - start < 40000) await sleep(300);
    if (!fs.existsSync(portFile)) throw new Error('coffre local non démarré');
    const vaultPort = Number(fs.readFileSync(portFile, 'utf8'));
    await waitPort(SYNC_PORT);
    await waitPort(APP_DEBUG_PORT);
    // SITES-22 : le port de synchronisation est tenu par l'application lancée ici, et par elle seule
    assertSyncPortOwner(appProc.pid);
    check(true, 'port ' + SYNC_PORT + ' tenu par l\'application de test (PID ' + appProc.pid + ')');
    log('app prête, coffre local sur ' + vaultPort);

    appBrowser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + APP_DEBUG_PORT, defaultViewport: null, protocolTimeout: 180000 });
    let appPage = null;
    for (let i = 0; i < 40 && !appPage; i++) {
      const pages = await appBrowser.pages();
      appPage = pages.find(p => /index\.html/.test(p.url())) || null;
      if (!appPage) await sleep(500);
    }
    if (!appPage) throw new Error('page app introuvable');
    appPage.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)));
    appPage.on('console', m => { if (m.type() === 'error') console.log('[console.error]', m.text().slice(0, 300)); });
    await appPage.waitForSelector('.form-input-vertical', { timeout: 30000 });

    // AUTH-14 : premier démarrage du coffre local (aucun compte). GET /v1/sys/init répond { initialized: false }
    // et l'écran de connexion passe en mode « création du compte administrateur » (confirmation du mot de passe)
    let r = await vaultReq(vaultPort, 'GET', '/v1/sys/init');
    check(r.status === 200 && r.json?.initialized === false, 'AUTH-14 : GET /v1/sys/init → { initialized: false } avant tout compte');
    let setupShown = false;
    for (let i = 0; i < 40 && !setupShown; i++) { setupShown = await isSetupForm(appPage); if (!setupShown) await sleep(250); }
    check(setupShown, 'AUTH-14 : premier démarrage → écran de création du compte administrateur (champ de confirmation)');
    await shot(appPage, path.join(SHOTS, 'login-setup.png'));
    if (setupShown) {
      const fields = await appPage.$$('.form-input-vertical');
      check(fields.length === 3, 'AUTH-14 : identifiant, mot de passe et confirmation (' + fields.length + ' champs)');
      await fields[0].click(); await fields[0].type(USER);
      await fields[1].click(); await fields[1].type(PASS);
      await fields[2].click(); await fields[2].type(PASS + '-faute');
      check(!!(await appPage.$('[role="alert"]')), 'AUTH-14 : confirmation différente signalée sous le champ');
      await appPage.click('.btn-login');
      await sleep(1500);
      r = await vaultReq(vaultPort, 'GET', '/v1/sys/init');
      check(!(await appPage.$('.toolbar')) && r.json?.initialized === false, 'AUTH-14 : confirmation différente → aucun compte créé');
      await fields[2].click({ clickCount: 3 }); await fields[2].type(PASS);
      await appPage.click('.btn-login');
      await appPage.waitForSelector('.toolbar', { timeout: 30000 });
      r = await vaultReq(vaultPort, 'GET', '/v1/sys/init');
      check(r.json?.initialized === true, 'AUTH-14 : compte administrateur créé par l\'écran de création (confirmation acceptée par le serveur), session ouverte');
    } else {
      // Renderer sans écran de création (build ancien) : compte créé par l'API pour poursuivre la suite
      r = await vaultReq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS, confirm: PASS });
      check(r.status === 200, 'compte créé via API (repli)');
    }

    // Données via API (connexion au compte existant : aucune confirmation)
    r = await vaultReq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS });
    check(r.status === 200, 'connexion API au compte créé');
    const vtoken = r.json.auth.client_token;
    r = await vaultReq(vaultPort, 'POST', '/v1/sys/mounts/' + ENGINE_B, vtoken, { description: 'cible import' });
    check(r.status === 204, 'engine cible créé');
    for (const [name, data] of Object.entries(SECRETS)) {
      r = await vaultReq(vaultPort, 'POST', `/v1/${enc(ENGINE_A)}/data/${encodeURIComponent(name)}`, vtoken, { data });
      check(r.status === 200, 'secret source créé: ' + name);
    }

    // Login UI : après la création, déconnexion puis connexion habituelle (coffres et entrées de l'API chargés)
    if (setupShown) {
      await appPage.click('.user-menu-trigger'); await sleep(300);
      check(!!(await clickByText(appPage, '.user-menu-item-logout', /./)), 'AUTH-14 : déconnexion après la création du compte');
      await appPage.waitForSelector('.form-input-vertical', { timeout: 15000 });
      await sleep(1500);
      check(!(await isSetupForm(appPage)), 'AUTH-14 : compte existant → formulaire de connexion habituel (sans confirmation)');
    }
    await shot(appPage, path.join(SHOTS, 'login.png'));
    await loginInApp(appPage, USER, PASS);
    await sleep(2500);
    check(true, 'login UI');
    await shot(appPage, path.join(SHOTS, 'main.png'));

    // Sélectionner le coffre source dans la barre latérale (le premier coffre, vide, est sélectionné par défaut)
    const sideClicked = await clickByText(appPage, '.sidebar-content *', /^Mes-Secrets$/);
    check(!!sideClicked, 'barre latérale: coffre Mes-Secrets sélectionné');
    await sleep(1500);
    await shot(appPage, path.join(SHOTS, 'main-secrets.png'));
    // Vérifier que le tableau affiche les secrets de l'engine A (navigation dossier)
    const rowsText = await appPage.evaluate(() => Array.from(document.querySelectorAll('.secrets-table tbody tr, .secrets-table .secret-row, .secrets-table [role="row"]')).map(r => r.textContent.trim().slice(0, 80)));
    log('lignes tableau:', JSON.stringify(rowsText.slice(0, 8)));
    check(rowsText.some(t => /srv-simple/.test(t)), 'tableau: secret racine visible');
    check(rowsText.some(t => /srv-nested/.test(t)), 'tableau: secret dans un dossier visible (vue liste)');

    await runExportImport(appPage, vaultPort, vtoken, 'csv', exportPath);
    await runExportImport(appPage, vaultPort, vtoken, 'xml', exportPath);

    // --- Résilience UI ---
    // 1. Vue arborescence, navigation dans un dossier, fil d'Ariane
    let clicked = await clickByText(appPage, 'button', /arborescence|tree view/i);
    check(!!clicked, 'arborescence: bouton trouvé');
    await sleep(900);
    let rows = await rowTexts(appPage);
    check(rows.some(t => /Dossier/.test(t)) && !rows.some(t => /srv-nested/.test(t)), 'arborescence: dossier affiché à la racine, secret imbriqué masqué (' + rows.length + ' lignes)');
    await shot(appPage, path.join(SHOTS, 'tree.png'));
    clicked = await clickByText(appPage, '.secrets-table tbody tr', /Dossier/);
    await sleep(900);
    rows = await rowTexts(appPage);
    check(rows.length === 1 && /srv-nested/.test(rows[0]), 'arborescence: contenu du dossier affiché (' + JSON.stringify(rows) + ')');
    clicked = await clickByText(appPage, 'button', /^Racine$|^Root$/);
    check(!!clicked, "fil d'Ariane: bouton racine");
    await sleep(700);
    rows = await rowTexts(appPage);
    check(rows.some(t => /Dossier/.test(t)) && rows.length === 5, 'arborescence: retour à la racine (' + rows.length + ' lignes)');
    clicked = await clickByText(appPage, 'button', /vue liste|list view/i);
    await sleep(700);
    rows = await rowTexts(appPage);
    check(rows.length === 5 && rows.some(t => /Dossier\/srv-nested/.test(t)), 'vue liste: chemin complet affiché pour le secret imbriqué');

    // 2. Recherche locale
    const searchInput = await appPage.$('.toolbar input[placeholder]');
    check(!!searchInput, 'recherche: champ trouvé');
    await searchInput.click(); await searchInput.type('unicode');
    await sleep(600);
    rows = await rowTexts(appPage);
    check(rows.length === 1 && /srv-unicode/.test(rows[0]), 'recherche: filtre appliqué (' + rows.length + ' ligne)');
    await searchInput.click({ clickCount: 3 }); await appPage.keyboard.press('Backspace');
    await sleep(500);
    rows = await rowTexts(appPage);
    check(rows.length === 5, 'recherche: effacement restaure la liste');

    // 3. Création d'une entrée via l'interface
    clicked = await clickByText(appPage, 'button', /nouvelle entr|new entry/i);
    check(!!clicked, 'création: bouton Nouvelle entrée');
    await appPage.waitForSelector('input[placeholder="ex. github/projet-x"]', { timeout: 10000 });
    await appPage.type('input[placeholder="ex. github/projet-x"]', 'ui-created');
    check(await fillLabeled(appPage, /^Identifiant$|^Username$/i, 'ui-user'), 'création: identifiant saisi');
    check(await fillLabeled(appPage, /^Mot de passe$|^Password$/i, 'Ui-P@ss "1"'), 'création: mot de passe saisi');
    check(await fillLabeled(appPage, /^URL$/i, 'https://ui.example.com'), 'création: URL saisie');
    const notes = await appPage.$('.modal-textarea');
    if (notes) { await notes.click(); await notes.type('note ui\nligne 2'); }
    await shot(appPage, path.join(SHOTS, 'edit.png'));
    clicked = await clickByText(appPage, 'button.btn-primary', /^enregistrer$|^save$/i);
    check(!!clicked, 'création: bouton Enregistrer');
    await sleep(1800);
    let created = (await readAll(vaultPort, vtoken, ENGINE_A))['ui-created'];
    check(!!created && created.Username === 'ui-user' && created.Password === 'Ui-P@ss "1"' && created.URL === 'https://ui.example.com' && /note ui\nligne 2/.test(created.Notes || ''), 'création: secret écrit dans le coffre avec les bonnes valeurs ' + JSON.stringify(created));
    rows = await rowTexts(appPage);
    check(rows.some(t => /ui-created/.test(t)), 'création: nouvelle ligne visible sans rechargement');

    // 4. Édition via l'interface (double-clic)
    clicked = await clickByText(appPage, '.secrets-table tbody tr', /ui-created/);
    const target = await appPage.evaluateHandle(() => Array.from(document.querySelectorAll('.secrets-table tbody tr')).find(tr => /ui-created/.test(tr.textContent)));
    // L'édition passe par le menu contextuel (clic droit → Modifier)
    await target.click({ button: 'right' });
    await sleep(500);
    await shot(appPage, path.join(SHOTS, 'context-menu.png'));
    clicked = await clickByText(appPage, '[class*="context-menu"] *', /^(\S+\s)?(Modifier|Edit)$/i);
    check(!!clicked, 'édition: entrée Modifier du menu contextuel');
    await appPage.waitForSelector('input[placeholder="ex. github/projet-x"]', { timeout: 10000 });
    check(await fillLabeled(appPage, /^Mot de passe$|^Password$/i, 'Changed-2'), 'édition: nouveau mot de passe saisi');
    clicked = await clickByText(appPage, 'button.btn-primary', /^enregistrer$|^save$/i);
    await sleep(1800);
    created = (await readAll(vaultPort, vtoken, ENGINE_A))['ui-created'];
    check(created && created.Password === 'Changed-2' && created.Username === 'ui-user', 'édition: mot de passe mis à jour, autres champs conservés');

    // 5. Suppression douce (API) + case « Afficher les supprimés »
    await vaultReq(vaultPort, 'POST', '/v1/' + enc(ENGINE_A) + '/delete/srv-port', vtoken, { versions: [1] });
    clicked = await clickByText(appPage, '.toolbar label', /supprim|deleted/i);
    check(!!clicked, 'supprimés: case cochée');
    await sleep(1500);
    rows = await rowTexts(appPage);
    check(rows.some(t => /srv-port/.test(t)), 'supprimés: secret supprimé visible avec la case cochée');
    clicked = await clickByText(appPage, '.toolbar label', /supprim|deleted/i);
    await sleep(1500);
    rows = await rowTexts(appPage);
    check(!rows.some(t => /srv-port/.test(t)) && rows.length === 5, 'supprimés: secret masqué une fois la case décochée (' + rows.length + ' lignes)');

    // 6. Recherche multi-coffres
    clicked = await clickByText(appPage, '.toolbar label', /tous les coffres|all vaults/i);
    check(!!clicked, 'multi-coffres: case cochée');
    await sleep(500);
    const searchAll = await appPage.$('.toolbar input[placeholder]');
    await searchAll.click(); await searchAll.type('srv-simple');
    await sleep(2500);
    rows = await rowTexts(appPage);
    check(rows.some(t => /srv-simple/.test(t)), 'multi-coffres: résultat trouvé (' + rows.length + ')');
    await searchAll.click({ clickCount: 3 }); await appPage.keyboard.press('Backspace');
    clicked = await clickByText(appPage, '.toolbar label', /tous les coffres|all vaults/i);
    await sleep(800);

    // 7. Modales du menu utilisateur : « Santé des mots de passe » puis « Mes passkeys »
    //    (titre présent, aucune clé i18n brute, fermeture propre, toolbar de nouveau interactif)
    let modalText = await openUserMenuModal(appPage, /santé|health/i, 'santé');
    if (modalText !== null) {
      await sleep(400); await shot(appPage, path.join(SHOTS, 'password-health.png')); // pause : fin de l'animation d'ouverture
      const h2 = await appPage.$eval('.modal-panel h2', el => el.textContent.trim()).catch(() => null);
      check(!!h2 && /santé|health/i.test(h2), 'santé: titre h2 présent (' + h2 + ')');
      const raw = rawI18nKeys(modalText);
      check(raw.length === 0, 'santé: aucune clé i18n brute ni variable non substituée' + (raw.length ? ' — trouvé: ' + raw.join(', ') : ''));
      // Le coffre contient des mots de passe : score global et entrées listées (ou état vide si rien à analyser)
      check((/\/100/.test(modalText) && /srv-simple/.test(modalText)) || /aucune entrée|no entries/i.test(modalText), 'santé: rapport affiché (score + entrées, ou état vide)');
      clicked = await clickByText(appPage, '.modal-footer button.btn-secondary', /fermer|close/i);
      check(!!clicked, 'santé: bouton Fermer');
      check(await modalClosed(appPage), 'santé: modale fermée (bouton)');
    }
    modalText = await openUserMenuModal(appPage, /passkey/i, 'passkeys');
    if (modalText !== null) {
      await sleep(400); await shot(appPage, path.join(SHOTS, 'passkeys.png'));
      const h2 = await appPage.$eval('.modal-panel h2', el => el.textContent.trim()).catch(() => null);
      check(!!h2 && /passkey/i.test(h2), 'passkeys: titre h2 présent (' + h2 + ')');
      const raw = rawI18nKeys(modalText);
      check(raw.length === 0, 'passkeys: aucune clé i18n brute ni variable non substituée' + (raw.length ? ' — trouvé: ' + raw.join(', ') : ''));
      // Aucune passkey n'a été enregistrée : libellé d'état vide attendu (sinon, liste avec boutons Supprimer)
      const hasList = (await appPage.$$('.modal-panel .modal-body .btn-sm')).length > 0;
      check(/aucune passkey|no passkeys?/i.test(modalText) || hasList, 'passkeys: état vide ou liste affiché');
      await appPage.keyboard.press('Escape');
      check(await modalClosed(appPage), 'passkeys: modale fermée (Escape)');
    }
    const searchAfter = await appPage.$('.toolbar input[placeholder]');
    if (searchAfter) await searchAfter.click();
    check(await appPage.evaluate(() => !document.querySelector('.modal-overlay') && !!document.activeElement && document.activeElement.matches('.toolbar input')), 'modales: toolbar de nouveau interactif (focus sur la recherche)');

    // 8. Déconnexion / reconnexion
    await appPage.click('.user-menu-trigger'); await sleep(300);
    clicked = await clickByText(appPage, '.user-menu-item-logout', /./);
    check(!!clicked, 'déconnexion: entrée du menu');
    await appPage.waitForSelector('.form-input-vertical', { timeout: 15000 });
    check(true, 'déconnexion: formulaire de login affiché');
    const inputs2 = await appPage.$$('.form-input-vertical');
    await inputs2[0].click({ clickCount: 3 }); await inputs2[0].type(USER);
    await inputs2[1].click(); await inputs2[1].type(PASS);
    await appPage.click('.btn-login');
    await appPage.waitForSelector('.toolbar', { timeout: 30000 });
    check(true, 'reconnexion réussie');

    // Ouvrir la modale d'édition d'un secret pour capture (double-clic sur la 1re ligne)
    try {
      const row = await appPage.$('.secrets-table tbody tr');
      if (row) { await row.click({ clickCount: 2 }); await sleep(800); await shot(appPage, path.join(SHOTS, 'edit.png')); await appPage.keyboard.press('Escape'); }
    } catch {}
  } catch (err) {
    console.log('FAIL exception: ' + ((err && err.stack) || err)); failures++;
  } finally {
    try { if (appBrowser) appBrowser.disconnect(); } catch {}
    try { if (appProc) appProc.kill(); } catch {}
    try { if (rewroteConfig) { if (hadConfig) fs.renameSync(configCfg + '.ui-backup', configCfg); else fs.unlinkSync(configCfg); } } catch {}
    await sleep(500);
    // Dossier temporaire (coffre de test, fichier d'export, journal) supprimé si tout a réussi ; conservé en cas
    // d'échec pour le diagnostic (app.log), sauf si l'application n'a jamais été lancée (refus de démarrer :
    // port 45678 occupé, build manquant ; app.log vide). Les captures restent dans rdvault-e2e-shots.
    try { if (appProc) { appProc.stdout.unpipe(appLog); appProc.stderr.unpipe(appLog); } } catch {}
    appLog.on('error', () => {});
    await new Promise((r) => appLog.end(r));
    if (failures === 0 || !appProc) await removeTempDir(tmp, appProc);
    else console.log('app.log: ' + path.join(tmp, 'app.log'));
    console.log(failures === 0 ? 'UI OK' : `UI FAILURES: ${failures}`);
    process.exit(failures === 0 ? 0 : 1);
  }
}
main();
