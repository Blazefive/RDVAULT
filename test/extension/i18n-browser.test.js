// Internationalisation des extensions dans un VRAI Chrome (EXTI18N-35) : Chrome for Testing lancé
// avec --lang=en, fr puis ar, les deux extensions chargées. Vérifie, pour chaque langue, ce que
// voit l'utilisateur :
//  - popup de l'extension enrichie (état « connecté »), lang / dir de la page ;
//  - menu d'autoremplissage sur une page de connexion (infobulle de l'icône, en-tête) et erreur
//    renvoyée par le service worker (identifiant introuvable) : chrome.i18n dans le service worker ;
//  - fenêtre passkey affichée sur le site (monde isolé), sens d'écriture rtl en arabe ;
//  - popup de l'extension simple (libellés, indications des champs, bouton).
// En français, les textes doivent être exactement ceux d'avant l'internationalisation.
// Aucune application RDVAULT n'est nécessaire ni contactée : les requêtes du service worker vers
// 127.0.0.1:45678 sont interceptées par le protocole DevTools (Fetch) et simulées ; une requête
// de contrôle vérifie l'interception AVANT toute page (sinon le test échoue sans rien envoyer).
// Site de test : serveur HTTPS local sur un port libre (certificat test/e2e/cert.pem).
// Lancement : E2E_BROWSER=<chrome.exe de Chrome for Testing> node --test test/extension/i18n-browser.test.js
// Sans E2E_BROWSER, le test est ignoré (skip).
/* global chrome */ // fonctions évaluées dans le service worker de l'extension (page.evaluate / worker.evaluate)
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');

const ROOT = path.resolve(__dirname, '..', '..');
const CHROME = process.env.E2E_BROWSER;
const ENRICHED = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const SIMPLE = path.join(ROOT, 'chrome-extension');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- Messages attendus (lus dans _locales, espaces réservés résolus comme Chrome) ----------
function messages(dir, loc) {
  const read = (l) => JSON.parse(fs.readFileSync(path.join(dir, '_locales', l, 'messages.json'), 'utf8'));
  return { ...read('en'), ...read(loc) };
}
function expected(dir, loc, key, subs = []) {
  const e = messages(dir, loc)[key];
  assert.ok(e, `message ${key} absent`);
  const ph = e.placeholders || {};
  const text = e.message.replace(/\$([A-Za-z0-9_]+)\$/g, (m, n) => ph[n.toLowerCase()].content);
  return text.replace(/\$([1-9])/g, (m, i) => (subs[i - 1] !== undefined ? String(subs[i - 1]) : ''));
}

// ---------- Site HTTPS local ----------
const PAGES = {
  '/login': '<!doctype html><html><head><title>Sign in</title></head><body style="font:16px sans-serif;padding:40px">'
    + '<form action="/login" method="post"><p><input id="user" type="email" name="username" autocomplete="username" style="width:300px;height:32px"></p>'
    + '<p><input id="pass" type="password" name="password" autocomplete="current-password" style="width:300px;height:32px"></p>'
    + '<button type="submit">Sign in</button></form></body></html>',
  '/blank': '<!doctype html><html><head><title>Passkey</title></head><body><p>passkey</p></body></html>',
};
function startSite() {
  const server = https.createServer({
    key: fs.readFileSync(path.join(ROOT, 'test/e2e/key.pem')),
    cert: fs.readFileSync(path.join(ROOT, 'test/e2e/cert.pem')),
  }, (req, res) => {
    const body = PAGES[req.url.split('?')[0]];
    res.writeHead(body ? 200 : 404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(body || 'not found');
  });
  return new Promise((resolve) => server.listen(0, 'localhost', () => resolve(server)));
}

// ---------- Application RDVAULT simulée (requêtes du service worker interceptées) ----------
const APP_REPLIES = {
  '/__probe': [418, {}],
  '/auth/token': [200, { token: 'tok-i18n-test' }],
  '/sync': [200, { connected: true, vaultUrl: 'https://vault.i18n.test', username: 'alice' }],
  '/api/secrets': [200, { success: true, secrets: [{ name: 'i18n-site', engine: 'users/alice/Mes-Secrets', username: 'alice@example.com', url: 'https://localhost' }] }],
  '/api/secret': [404, { error: 'not found' }],
};
async function interceptApp(swTarget) {
  const session = await swTarget.createCDPSession();
  session.on('Fetch.requestPaused', async ({ requestId, request }) => {
    const p = new URL(request.url).pathname;
    const [code, body] = APP_REPLIES[p] || [404, {}];
    try {
      await session.send('Fetch.fulfillRequest', {
        requestId, responseCode: code,
        responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
        body: Buffer.from(JSON.stringify(body)).toString('base64'),
      });
    } catch { /* requête annulée */ }
  });
  await session.send('Fetch.enable', { patterns: [{ urlPattern: 'http://127.0.0.1:45678/*' }] });
  return session;
}

// ---------- Nœuds des shadow roots FERMÉS (CDP pierce) : texte, attributs, centre ----------
async function shadowNode(page, cls, timeoutMs = 10000, filter = null) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const cdp = await page.createCDPSession();
    try {
      const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
      const hits = [];
      const txt = (n) => (n.nodeType === 3 ? (n.nodeValue || '') : '') + (n.children || []).map(txt).join('');
      (function walk(n) {
        const a = n.attributes || [];
        const attrs = {};
        for (let i = 0; i < a.length; i += 2) attrs[a[i]] = a[i + 1];
        if ((attrs.class || '').split(/\s+/).includes(cls)) hits.push({ nodeId: n.nodeId, text: txt(n), attrs });
        (n.children || []).forEach(walk);
        (n.shadowRoots || []).forEach(walk);
      })(root);
      const hit = hits.find((h) => !filter || filter(h));
      if (hit) {
        let x = null; let y = null;
        try {
          const { model } = await cdp.send('DOM.getBoxModel', { nodeId: hit.nodeId });
          const q = model.content; x = (q[0] + q[4]) / 2; y = (q[1] + q[5]) / 2;
        } catch { /* nœud sans boîte (masqué) */ }
        return { text: hit.text, attrs: hit.attrs, x, y };
      }
    } catch { /* document en cours de chargement */ } finally { try { await cdp.detach(); } catch { /* déjà détachée */ } }
    await sleep(250);
  }
  return null;
}

// Textes français d'origine (avant l'internationalisation) : doivent rester identiques
const FR_ORIGINAL = {
  popupDesktopConnected: 'Desktop connecté',
  popupInfo: 'Cette extension nécessite que l\'application Desktop Vault soit lancée et connectée.',
  details: ['Utilisateur: alice', 'Serveur: https://vault.i18n.test', '✓ Auto-remplissage actif'],
  iconTitle: 'Auto-remplir avec RDVAULT',
  header: 'Identifiants RDVAULT',
  notFound: 'Identifiant introuvable pour ce site',
  pkTitle: 'Créer une passkey pour localhost — alice@test',
  pkOk: 'Créer dans RDVAULT',
  pkOther: 'Utiliser un autre appareil',
  pkCancel: 'Annuler',
  pkWarning: 'Action bloquée : la fenêtre RDVAULT est masquée ou recouverte par la page. Utilisez « Utiliser un autre appareil » ou « Annuler ».',
  simpleLabels: ['URL Vault', 'Namespace (optionnel)', 'Utilisateur LDAP', 'Mot de passe'],
  simpleButton: 'Se connecter',
  simplePlaceholder: 'Laisser vide si non utilisé',
};

const CASES = [
  { lang: 'en', loc: 'en', dir: 'ltr' },
  { lang: 'fr', loc: 'fr', dir: 'ltr' },
  { lang: 'ar', loc: 'ar', dir: 'rtl' },
];

test('extensions traduites dans Chrome selon la langue du navigateur (en, fr, ar)', {
  skip: CHROME ? false : 'E2E_BROWSER non défini (chemin de chrome.exe de Chrome for Testing)',
  timeout: 240000,
}, async (t) => {
  const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
  const site = await startSite();
  const port = site.address().port;
  t.after(() => site.close());

  for (const c of CASES) {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-ext-i18n-'));
    const browser = await puppeteer.launch({
      executablePath: CHROME, headless: false, userDataDir: profile, defaultViewport: null,
      ignoreDefaultArgs: ['--disable-extensions', '--enable-automation'],
      args: ['--disable-extensions-except=' + ENRICHED + ',' + SIMPLE, '--load-extension=' + ENRICHED + ',' + SIMPLE,
        '--ignore-certificate-errors', '--no-first-run', '--no-default-browser-check', '--lang=' + c.lang,
        '--window-size=1000,800', '--window-position=0,0'],
    });
    let session = null;
    try {
      // Deux service workers : version 1.2.0 = extension enrichie, 1.1.0 = extension simple
      const ids = {};
      const deadline = Date.now() + 20000;
      while ((!ids.enriched || !ids.simple) && Date.now() < deadline) {
        for (const target of browser.targets().filter((x) => x.type() === 'service_worker' && x.url().startsWith('chrome-extension://'))) {
          const id = new URL(target.url()).hostname;
          if (Object.values(ids).some((v) => v.id === id)) continue;
          const w = await target.worker();
          const version = await w.evaluate(() => chrome.runtime.getManifest().version);
          ids[version === '1.2.0' ? 'enriched' : 'simple'] = { id, target, worker: w };
        }
        if (!ids.enriched || !ids.simple) await sleep(300);
      }
      assert.ok(ids.enriched && ids.simple, `${c.lang} : service workers introuvables`);
      session = await interceptApp(ids.enriched.target);
      const probe = await ids.enriched.worker.evaluate(() => fetch('http://127.0.0.1:45678/__probe').then((r) => r.status, () => 0));
      assert.equal(probe, 418, `${c.lang} : interception des requêtes vers 127.0.0.1:45678 inactive`);

      const E = (key, subs) => expected(ENRICHED, c.loc, key, subs);
      const S = (key, subs) => expected(SIMPLE, c.loc, key, subs);
      // chrome.i18n dans le service worker
      assert.equal(await ids.enriched.worker.evaluate(() => chrome.i18n.getUILanguage().split('-')[0]), c.loc, `${c.lang} : langue de l'interface`);

      // 1. Popup de l'extension enrichie (état connecté)
      const popup = await browser.newPage();
      await popup.goto(`chrome-extension://${ids.enriched.id}/popup.html`, { waitUntil: 'load' });
      await popup.waitForFunction((v) => document.getElementById('statusText').textContent === v, { timeout: 15000 }, E('popupDesktopConnected'));
      const pop = await popup.evaluate(() => ({
        lang: document.documentElement.lang, dir: document.documentElement.dir,
        info: document.querySelector('.info-box').textContent.replace(/\s+/g, ' ').trim(),
        details: [...document.querySelectorAll('#statusDetails p')].map((p) => p.textContent),
      }));
      assert.equal(pop.dir, c.dir, `${c.lang} : dir de la popup`);
      assert.equal(pop.lang.split('-')[0], c.loc, `${c.lang} : lang de la popup`);
      assert.equal(pop.info, E('popupInfoRequiresDesktop'));
      assert.deepEqual(pop.details, [E('popupUserLabel') + ' alice', E('popupServerLabel') + ' https://vault.i18n.test', E('popupAutofillActive')]);
      if (c.loc === 'fr') {
        assert.equal(E('popupDesktopConnected'), FR_ORIGINAL.popupDesktopConnected);
        assert.equal(pop.info, FR_ORIGINAL.popupInfo);
        assert.deepEqual(pop.details, FR_ORIGINAL.details);
      }
      await popup.close();

      // 2. Menu d'autoremplissage + erreur traduite par le service worker
      const page = await browser.newPage();
      await page.goto(`https://localhost:${port}/login`, { waitUntil: 'load' });
      const icon = await shadowNode(page, 'vault-autofill-icon', 15000);
      assert.ok(icon, `${c.lang} : icône d'autoremplissage absente`);
      assert.equal(icon.attrs.title, E('autofillIconTitle'));
      await page.click('#user');
      const header = await shadowNode(page, 'vault-autofill-header');
      assert.ok(header, `${c.lang} : menu non ouvert`);
      assert.equal(header.text, E('autofillHeader'));
      const dropdown = await shadowNode(page, 'vault-autofill-dropdown');
      assert.equal(dropdown.attrs.dir, c.dir, `${c.lang} : dir du menu`);
      const item = await shadowNode(page, 'vault-autofill-item');
      assert.ok(item && item.text.includes('alice@example.com'));
      await page.mouse.click(item.x, item.y);
      const err = await shadowNode(page, 'vault-autofill-error');
      assert.ok(err, `${c.lang} : erreur non affichée`);
      assert.equal(err.text, E('bgErrNotFound'));
      if (c.loc === 'fr') {
        assert.equal(icon.attrs.title, FR_ORIGINAL.iconTitle);
        assert.equal(header.text, FR_ORIGINAL.header);
        assert.equal(err.text, FR_ORIGINAL.notFound);
      }
      await page.close();

      // 3. Fenêtre passkey sur le site (aucun coffre consulté avant la fenêtre ; « Annuler » à la fin)
      const pk = await browser.newPage();
      await pk.goto(`https://localhost:${port}/blank`, { waitUntil: 'load' });
      await pk.evaluate(() => {
        window.__pk = 'pending';
        navigator.credentials.create({ publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: 'i18n' },
          user: { id: new Uint8Array([1, 2, 3, 4]), name: 'alice@test', displayName: 'Alice' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        } }).then(() => { window.__pk = 'resolved'; }, (e) => { window.__pk = e.name; });
      });
      const ok = await shadowNode(pk, 'ok');
      assert.ok(ok, `${c.lang} : fenêtre passkey absente`);
      const dt = await shadowNode(pk, 'dt');
      const fb = await shadowNode(pk, 'fb');
      const ca = await shadowNode(pk, 'ca');
      const wn = await shadowNode(pk, 'wn');
      const ov = await shadowNode(pk, 'ov');
      assert.equal(dt.text, E('pkCreateTitle', ['localhost']) + ' — alice@test');
      assert.equal(ok.text, E('pkCreateOk'));
      assert.equal(fb.text, E('pkUseAnotherDevice'));
      assert.equal(ca.text, E('pkCancel'));
      assert.equal(wn.text, E('pkBlockedWarning', [fb.text, ca.text]));
      assert.equal(ov.attrs.dir, c.dir, `${c.lang} : dir de la fenêtre passkey`);
      if (c.loc === 'fr') {
        assert.deepEqual([dt.text, ok.text, fb.text, ca.text, wn.text],
          [FR_ORIGINAL.pkTitle, FR_ORIGINAL.pkOk, FR_ORIGINAL.pkOther, FR_ORIGINAL.pkCancel, FR_ORIGINAL.pkWarning]);
      }
      await pk.mouse.click(ca.x, ca.y);
      await pk.waitForFunction(() => window.__pk !== 'pending', { timeout: 10000 });
      assert.equal(await pk.evaluate(() => window.__pk), 'NotAllowedError');
      await pk.close();

      // 4. Popup de l'extension simple (aucun réseau : état lu dans storage.session)
      const sp = await browser.newPage();
      await sp.goto(`chrome-extension://${ids.simple.id}/popup.html`, { waitUntil: 'load' });
      await sp.waitForFunction(() => !document.getElementById('loginForm').classList.contains('hidden'), { timeout: 10000 });
      const simple = await sp.evaluate(() => ({
        dir: document.documentElement.dir,
        labels: [...document.querySelectorAll('#loginForm label')].map((l) => l.textContent),
        button: document.getElementById('loginBtn').textContent,
        placeholder: document.getElementById('vaultNamespace').placeholder,
      }));
      assert.equal(simple.dir, c.dir);
      assert.deepEqual(simple.labels, ['popupVaultUrlLabel', 'popupNamespaceLabel', 'popupUsernameLabel', 'popupPassword'].map((k) => S(k)));
      assert.equal(simple.button, S('popupLoginButton'));
      assert.equal(simple.placeholder, S('popupNamespacePlaceholder'));
      if (c.loc === 'fr') {
        assert.deepEqual(simple.labels, FR_ORIGINAL.simpleLabels);
        assert.equal(simple.button, FR_ORIGINAL.simpleButton);
        assert.equal(simple.placeholder, FR_ORIGINAL.simplePlaceholder);
      } else {
        assert.notDeepEqual(simple.labels, FR_ORIGINAL.simpleLabels, `${c.lang} : popup simple restée en français`);
      }
      await sp.close();
      t.diagnostic(`${c.lang} : popup, menu, erreur du service worker, fenêtre passkey et popup simple traduits (dir=${c.dir}) — `
        + `« ${header.text} » / « ${err.text} » / « ${dt.text} » / « ${simple.button} »`);
    } finally {
      try { if (session) await session.detach(); } catch { /* navigateur fermé */ }
      await Promise.race([browser.close(), sleep(10000)]);
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* fichiers verrouillés */ }
    }
  }
});
