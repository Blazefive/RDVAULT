// Menu d'autoremplissage au clavier et pour les lecteurs d'écran (EXT-22), et message explicite
// quand RDVAULT (ou Vault) est verrouillé / fermé au lieu de « Aucun identifiant » (EXT-23), dans
// les DEUX content scripts (chrome-extension/content.js et vault-autofill-extension/content.js).
// Chaque script est exécuté tel quel dans une vraie page HTTPS de Chrome for Testing, avec un
// chrome.runtime simulé ; les touches sont de vrais événements clavier (CDP, isTrusted) et
// l'arbre d'accessibilité est celui de Chrome (shadow root fermé compris). Vérifié :
//  - rôles listbox / option, nom accessible de la liste et des entrées, annonce role="status" ;
//  - Tab vers le champ → menu ; Flèche bas / haut dans la liste ; Entrée → identifiant et mot de
//    passe remplis SANS soumettre le formulaire vide ; Échap → menu fermé, focus rendu au champ ;
//    Alt+Flèche bas → menu rouvert ; focus parti ailleurs (Tab) → menu fermé ;
//  - icône nommée (role="button") ; RDVAULT verrouillé : « RDVAULT est verrouillé… » (role="alert").
// Le parcours avec la vraie extension et l'application est couvert par test/e2e/run.js.
// Lancement : E2E_BROWSER=<chrome.exe de Chrome for Testing> node --test test/extension/menu-a11y.test.js
// Sans E2E_BROWSER, le test est ignoré (skip).
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const https = require('node:https');

const ROOT = path.resolve(__dirname, '..', '..');
const CHROME = process.env.E2E_BROWSER;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const SCRIPTS = {
  enrichie: { file: path.join(ROOT, 'chrome-extension/vault-autofill-extension/content.js'), header: 'Identifiants RDVAULT', locked: 'RDVAULT est verrouillé : déverrouillez l\'application, puis réessayez.' },
  simple: { file: path.join(ROOT, 'chrome-extension/content.js'), header: 'Identifiants Vault', locked: 'Non connecté à Vault : ouvrez la fenêtre de l\'extension pour vous connecter.' },
};

const PAGE = '<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head><body style="font:16px sans-serif;padding:40px">'
  + '<input id="q" type="search" placeholder="search" style="width:200px"><br><br>'
  + '<form id="f" action="/login" method="post"><p><input id="user" type="email" name="username" autocomplete="username" style="width:300px;height:32px"></p>'
  + '<p><input id="pass" type="password" name="password" autocomplete="current-password" style="width:300px;height:32px"></p>'
  + '<button id="go" type="submit">Sign in</button></form><a id="forgot" href="#">forgot</a>'
  + '<script>window.__submits = 0; document.getElementById("f").addEventListener("submit", (e) => { e.preventDefault(); window.__submits++; });</script>'
  + '</body></html>';

function startSite() {
  const server = https.createServer({
    key: fs.readFileSync(path.join(ROOT, 'test/e2e/key.pem')),
    cert: fs.readFileSync(path.join(ROOT, 'test/e2e/cert.pem')),
  }, (req, res) => { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(PAGE); });
  return new Promise((resolve) => server.listen(0, 'localhost', () => resolve(server)));
}

// chrome.runtime simulé (le mode « verrouillé » se bascule par window.__rdvLocked)
function mockSource(lockedMessage) {
  return `
  const chrome = { runtime: { id: 'menu-a11y', sendMessage: async (m) => {
    const creds = [{ name: 'kbd-site', engine: 'kv', username: 'alice@example.com' }, { name: 'second', engine: 'kv', username: 'bob@example.com' }];
    if (window.__rdvLocked) return { success: false, credentials: [], error: ${JSON.stringify(lockedMessage)} };
    if (m && m.type === 'GET_CREDENTIALS') return { success: true, credentials: creds };
    if (m && m.type === 'SELECT_CREDENTIAL') {
      const c = creds.find((x) => x.name === m.name);
      return { success: true, credential: { ...c, password: 'P@ss-' + c.name } };
    }
    return { success: false };
  } } };`;
}

/** Arbre d'accessibilité de Chrome (shadow roots fermés compris), à plat */
async function axNodes(page) {
  const out = [];
  (function walk(n) { if (!n) return; out.push(n); (n.children || []).forEach(walk); })(await page.accessibility.snapshot({ interestingOnly: false }));
  return out;
}
async function waitAx(page, pred, timeoutMs = 4000) {
  const start = Date.now();
  let nodes = [];
  while (Date.now() - start < timeoutMs) {
    nodes = await axNodes(page);
    if (pred(nodes)) return nodes;
    await sleep(100);
  }
  return nodes;
}
const activeId = (page) => page.evaluate(() => (document.activeElement && document.activeElement.id) || document.activeElement.tagName);

test('menu d\'autoremplissage : clavier et lecteurs d\'écran, RDVAULT verrouillé expliqué (deux extensions)', {
  skip: CHROME ? false : 'E2E_BROWSER non défini (chemin de chrome.exe de Chrome for Testing)',
  timeout: 180000,
}, async (t) => {
  const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
  const site = await startSite();
  const url = `https://localhost:${site.address().port}/login`;
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-menu-a11y-'));
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: true, userDataDir: profile,
    args: ['--ignore-certificate-errors', '--no-first-run', '--no-default-browser-check', '--force-renderer-accessibility'],
  });
  t.after(async () => {
    await Promise.race([browser.close(), sleep(10000)]);
    site.close();
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* fichiers verrouillés */ }
  });

  for (const [name, spec] of Object.entries(SCRIPTS)) {
    await t.test(`extension ${name}`, async () => {
      const page = await browser.newPage();
      await page.setViewport({ width: 1000, height: 700 });
      const errors = [];
      page.on('pageerror', (e) => errors.push(String(e)));
      await page.goto(url, { waitUntil: 'load' });
      await page.addScriptTag({ content: '(function () {' + mockSource(spec.locked) + '\n' + fs.readFileSync(spec.file, 'utf8') + '\n})();' });
      await sleep(1200);

      // 1. Tab jusqu'au champ identifiant : menu ouvert, liste nommée, entrées nommées
      await page.focus('#q');
      await page.keyboard.press('Tab');
      assert.equal(await activeId(page), 'user');
      let nodes = await waitAx(page, (ns) => ns.some((n) => n.role === 'option'));
      const listbox = nodes.find((n) => n.role === 'listbox');
      assert.ok(listbox, 'liste role=listbox exposée');
      assert.equal(listbox.name, spec.header, 'nom accessible de la liste');
      const options = nodes.filter((n) => n.role === 'option').map((n) => n.name);
      assert.deepEqual(options, ['kbd-site, alice@example.com', 'second, bob@example.com'], 'entrées nommées « nom, identifiant »');
      nodes = await waitAx(page, (ns) => ns.some((n) => /disponibles : 2/.test(n.name || '')), 2000);
      assert.ok(nodes.some((n) => /disponibles : 2\. Flèche bas pour choisir, Échap pour fermer\./.test(n.name || '')), 'ouverture annoncée (role=status)');
      const icon = nodes.find((n) => n.role === 'button' && /^Auto-remplir avec/.test(n.name || ''));
      assert.ok(icon, 'icône exposée comme bouton nommé');

      // 2. Flèches : le focus entre dans la liste et s'y déplace
      await page.keyboard.press('ArrowDown');
      nodes = await waitAx(page, (ns) => ns.some((n) => n.role === 'option' && n.focused));
      assert.equal((nodes.find((n) => n.role === 'option' && n.focused) || {}).name, 'kbd-site, alice@example.com', 'Flèche bas : première entrée');
      await page.keyboard.press('ArrowDown');
      nodes = await waitAx(page, (ns) => ns.some((n) => n.role === 'option' && n.focused && /second/.test(n.name)));
      assert.ok(nodes.some((n) => n.role === 'option' && n.focused && /second/.test(n.name)), 'Flèche bas : deuxième entrée');
      await page.keyboard.press('ArrowUp');
      nodes = await waitAx(page, (ns) => ns.some((n) => n.role === 'option' && n.focused && /kbd-site/.test(n.name)));
      assert.ok(nodes.some((n) => n.role === 'option' && n.focused && /kbd-site/.test(n.name)), 'Flèche haut : retour à la première');

      // 3. Entrée : identifiant et mot de passe remplis, formulaire NON soumis vide
      await page.keyboard.press('Enter');
      await sleep(800);
      assert.equal(await page.$eval('#user', (el) => el.value), 'alice@example.com');
      assert.equal(await page.$eval('#pass', (el) => el.value), 'P@ss-kbd-site');
      assert.equal(await page.evaluate(() => window.__submits), 0, 'Entrée n\'a pas soumis le formulaire');

      // 4. Échap dans la liste : menu fermé, focus rendu au champ ; Alt+Flèche bas : menu rouvert
      await page.$eval('#user', (el) => { el.value = ''; });
      await page.focus('#q');
      await page.keyboard.press('Tab');
      await waitAx(page, (ns) => ns.some((n) => n.role === 'option'));
      await page.keyboard.press('ArrowDown');
      await waitAx(page, (ns) => ns.some((n) => n.role === 'option' && n.focused));
      await page.keyboard.press('Escape');
      nodes = await waitAx(page, (ns) => !ns.some((n) => n.role === 'option'));
      assert.ok(!nodes.some((n) => n.role === 'option'), 'Échap : menu fermé');
      assert.equal(await activeId(page), 'user', 'Échap : focus rendu au champ');
      await page.keyboard.down('Alt'); await page.keyboard.press('ArrowDown'); await page.keyboard.up('Alt');
      nodes = await waitAx(page, (ns) => ns.some((n) => n.role === 'option'));
      assert.ok(nodes.some((n) => n.role === 'option'), 'Alt+Flèche bas : menu rouvert');

      // 5. Tab dans la liste : menu fermé, la navigation reprend APRÈS le champ ; plus loin, aucun menu
      await page.keyboard.press('ArrowDown');
      await waitAx(page, (ns) => ns.some((n) => n.role === 'option' && n.focused));
      await page.keyboard.press('Tab');
      await sleep(300);
      assert.equal(await activeId(page), 'pass', 'Tab depuis la liste : focus sur le champ suivant');
      await page.keyboard.press('Tab');
      await sleep(400);
      assert.equal(await activeId(page), 'go');
      nodes = await axNodes(page);
      assert.ok(!nodes.some((n) => n.role === 'option' || n.role === 'listbox'), 'focus sur la page : menu fermé (ne masque plus la page)');

      // 6. RDVAULT verrouillé : l'icône explique au lieu de « Aucun identifiant trouvé »
      await page.evaluate(() => {
        window.__rdvLocked = true;
        // Onglet masqué puis revenu : liste purgée (comportement réel de visibilitychange)
        Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
        document.dispatchEvent(new Event('visibilitychange'));
        delete document.hidden;
      });
      const box = await page.$eval('#pass', (el) => { const r = el.getBoundingClientRect(); return { x: r.right - 18, y: r.top + r.height / 2 }; });
      await page.mouse.click(box.x, box.y);
      nodes = await waitAx(page, (ns) => ns.some((n) => (n.name || '').includes(spec.locked)));
      assert.ok(nodes.some((n) => (n.name || '').includes(spec.locked)), 'message « verrouillé / non connecté » affiché : ' + nodes.filter((n) => n.role === 'alert' || /Aucun/.test(n.name || '')).map((n) => n.role + ':' + n.name).join(' | '));
      assert.ok(!nodes.some((n) => /Aucun identifiant trouvé/.test(n.name || '')), 'plus de « Aucun identifiant trouvé pour ce site »');
      assert.ok(nodes.some((n) => n.role === 'alert'), 'erreur annoncée (role=alert)');
      assert.deepEqual(errors, [], 'aucune erreur de script');
      await page.close();
    });
  }
});
