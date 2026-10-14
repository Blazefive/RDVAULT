// Internationalisation des deux extensions (EXTI18N-35) : chrome.i18n avec
// _locales/<langue>/messages.json pour les 12 langues de l'application et « default_locale » « en ».
//  - manifest : default_locale « en », nom et description en __MSG_…__ définis dans chaque langue ;
//  - parité stricte : mêmes clés et mêmes espaces réservés (placeholders) dans les 12 langues,
//    messages non vides, $1… cohérents ;
//  - code : chaque clé utilisée (msg / i18nMessage, data-i18n*) existe, chaque clé est utilisée,
//    et le texte de repli écrit dans le code (= le texte français affiché jusqu'ici) est
//    identique à _locales/fr : le français reste inchangé ;
//  - comportement (jsdom / vm, chrome.i18n simulé à partir des vrais messages.json) : fenêtre
//    passkey (textes, dir="rtl" en arabe), popups des deux extensions, erreurs des service
//    workers affichées dans le menu d'autoremplissage ; sans chrome.i18n, français d'origine.
// Le parcours dans un vrai Chrome (--lang) est couvert par test/extension/i18n-browser.test.js.
// Lancement : node --test test/extension/i18n-locales.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..', '..');
const { JSDOM } = require(path.join(ROOT, 'node_modules/jsdom'));
const idl = require(path.join(ROOT, 'node_modules/jsdom/lib/jsdom/living/generated/utils.js'));

// Codes Chrome des 12 langues de l'application (pt : pt_BR et pt_PT ; zh : chinois simplifié)
const LOCALES = ['ar', 'de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'pt', 'ru', 'tr', 'zh_CN'];
const ENRICHED = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const SIMPLE = path.join(ROOT, 'chrome-extension');
const EXTENSIONS = {
  enrichie: { dir: ENRICHED, js: ['background.js', 'content.js', 'passkey-bridge.js', 'popup.js'], html: ['popup.html'] },
  simple: { dir: SIMPLE, js: ['background.js', 'content.js', 'popup.js'], html: ['popup.html'] },
};

// ---------- Lecture des messages ----------
const localesDir = (dir) => path.join(dir, '_locales');
function readMessages(dir, loc) {
  const file = path.join(localesDir(dir), loc, 'messages.json');
  assert.ok(fs.existsSync(file), `${path.relative(ROOT, file)} manquant`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
/** Message avec ses espaces réservés nommés résolus ($NOM$ → $1…), comme le fait Chrome */
function resolveMessage(entry) {
  const ph = entry.placeholders || {};
  return entry.message.replace(/\$([A-Za-z0-9_@]+)\$/g, (m, name) => {
    const p = ph[name.toLowerCase()] || ph[Object.keys(ph).find((k) => k.toLowerCase() === name.toLowerCase())];
    assert.ok(p, `espace réservé $${name}$ non défini`);
    return p.content;
  });
}
const positional = (s) => [...new Set((s.match(/\$[1-9]/g) || []))].sort().join(',');

/** chrome.i18n simulé à partir des vrais messages.json (repli « en », comme Chrome) */
function fakeI18n(dir, loc) {
  const msgs = { ...readMessages(dir, 'en'), ...readMessages(dir, loc) };
  return {
    getMessage(key, subs) {
      if (key === '@@bidi_dir') return loc === 'ar' ? 'rtl' : 'ltr';
      if (key === '@@ui_locale') return loc;
      const e = msgs[key];
      if (!e) return '';
      const list = subs === undefined ? [] : [].concat(subs).map(String);
      return resolveMessage(e).replace(/\$([1-9])/g, (m, n) => (list[n - 1] !== undefined ? list[n - 1] : ''));
    },
    getUILanguage: () => loc.replace('_', '-'),
  };
}
const tr = (dir, loc, key, subs) => fakeI18n(dir, loc).getMessage(key, subs);

// ---------- Appels de traduction dans le code ----------
const CALL_RE = /\b(?:msg|i18nMessage)\(\s*(['"])([A-Za-z0-9_@]+)\1\s*,\s*(['"])((?:\\.|(?!\3)[^\\])*)\3/g;
function codeCalls(file) {
  const src = fs.readFileSync(file, 'utf8');
  const out = [];
  for (const m of src.matchAll(CALL_RE)) out.push({ key: m[2], fallback: m[4].replace(/\\(.)/g, '$1') });
  return out;
}
function htmlKeys(file) {
  const dom = new JSDOM(fs.readFileSync(file, 'utf8'));
  const d = dom.window.document;
  const out = [];
  d.querySelectorAll('[data-i18n]').forEach((el) => out.push({ key: el.getAttribute('data-i18n'), fallback: el.textContent.replace(/\s+/g, ' ').trim() }));
  d.querySelectorAll('[data-i18n-placeholder]').forEach((el) => out.push({ key: el.getAttribute('data-i18n-placeholder'), fallback: el.getAttribute('placeholder') }));
  d.querySelectorAll('[data-i18n-title]').forEach((el) => out.push({ key: el.getAttribute('data-i18n-title'), fallback: el.getAttribute('title') }));
  return out;
}

for (const [label, ext] of Object.entries(EXTENSIONS)) {
  test(`${label} : manifest — default_locale « en », nom et description traduits`, () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(ext.dir, 'manifest.json'), 'utf8'));
    assert.equal(manifest.default_locale, 'en');
    assert.match(manifest.name, /^__MSG_\w+__$/);
    assert.match(manifest.description, /^__MSG_\w+__$/);
    const refs = [manifest.name, manifest.description].map((v) => /^__MSG_(\w+)__$/.exec(v)[1]);
    for (const loc of LOCALES) {
      const msgs = readMessages(ext.dir, loc);
      for (const r of refs) assert.ok(msgs[r] && msgs[r].message, `${loc} : ${r} absent`);
      // Limites du Chrome Web Store : nom ≤ 75 caractères, description ≤ 132
      assert.ok(msgs[refs[0]].message.length <= 75, `${loc} : nom trop long`);
      assert.ok(msgs[refs[1]].message.length <= 132, `${loc} : description trop longue (${msgs[refs[1]].message.length})`);
    }
  });

  test(`${label} : 12 langues, mêmes clés et mêmes espaces réservés partout`, () => {
    const present = fs.readdirSync(localesDir(ext.dir)).filter((d) => fs.statSync(path.join(localesDir(ext.dir), d)).isDirectory()).sort();
    assert.deepEqual(present, [...LOCALES].sort());
    const ref = readMessages(ext.dir, 'en');
    const refKeys = Object.keys(ref).sort();
    for (const loc of LOCALES) {
      const msgs = readMessages(ext.dir, loc);
      assert.deepEqual(Object.keys(msgs).sort(), refKeys, `${loc} : clés différentes de en`);
      for (const k of refKeys) {
        const e = msgs[k];
        assert.equal(typeof e.message, 'string', `${loc}.${k}`);
        assert.ok(e.message.trim().length > 0, `${loc}.${k} vide`);
        assert.ok(/^[A-Za-z0-9_]+$/.test(k) && !k.startsWith('@@'), `nom de message invalide : ${k}`);
        assert.deepEqual(Object.keys(e.placeholders || {}).sort(), Object.keys(ref[k].placeholders || {}).sort(), `${loc}.${k} : espaces réservés`);
        assert.equal(positional(resolveMessage(e)), positional(resolveMessage(ref[k])), `${loc}.${k} : $1… différents de en`);
        // Aucun « $ » isolé (Chrome l'interpréterait) : uniquement $NOM$ déclarés
        assert.ok(!/\$(?![A-Za-z0-9_]+\$)/.test(e.message.replace(/\$[A-Za-z0-9_]+\$/g, '')), `${loc}.${k} : « $ » isolé`);
      }
    }
  });

  test(`${label} : chaque clé du code existe, chaque clé est utilisée, repli = _locales/fr`, () => {
    const fr = readMessages(ext.dir, 'fr');
    const manifest = fs.readFileSync(path.join(ext.dir, 'manifest.json'), 'utf8');
    const used = new Set([...manifest.matchAll(/__MSG_(\w+)__/g)].map((m) => m[1]));
    const calls = [
      ...ext.js.flatMap((f) => codeCalls(path.join(ext.dir, f)).map((c) => ({ ...c, file: f }))),
      ...ext.html.flatMap((f) => htmlKeys(path.join(ext.dir, f)).map((c) => ({ ...c, file: f }))),
    ];
    assert.ok(calls.length > 10, 'aucun appel de traduction trouvé');
    for (const c of calls) {
      if (c.key.startsWith('@@')) continue; // messages prédéfinis de Chrome (@@bidi_dir…)
      used.add(c.key);
      assert.ok(fr[c.key], `${c.file} : clé ${c.key} absente de _locales`);
      assert.equal(c.fallback, resolveMessage(fr[c.key]), `${c.file} : repli de ${c.key} ≠ _locales/fr`);
    }
    const unused = Object.keys(fr).filter((k) => !used.has(k));
    assert.deepEqual(unused, [], 'clés inutilisées');
    // Tout passe par le helper (repli français hors navigateur) : pas d'appel direct ailleurs
    for (const f of ext.js) {
      const n = (fs.readFileSync(path.join(ext.dir, f), 'utf8').match(/chrome\.i18n\.getMessage\(/g) || []).length;
      assert.ok(n <= 1, `${f} : chrome.i18n.getMessage appelé hors du helper (${n})`);
    }
  });
}

// ---------- Fenêtre passkey (passkey-bridge.js, monde isolé) ----------
const core = require(path.join(ENRICHED, 'passkey-core.js'));
const BRIDGE_SRC = fs.readFileSync(path.join(ENRICHED, 'passkey-bridge.js'), 'utf8');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function loadBridge({ locale = null, passkeys = [] } = {}) {
  const dom = new JSDOM('<!doctype html><html><head></head><body></body></html>', { url: 'https://site-a.com/login', pretendToBeVisual: true });
  const w = dom.window;
  OPEN_WINDOWS.push(w);
  const roots = [];
  const origAttach = w.Element.prototype.attachShadow;
  w.Element.prototype.attachShadow = function (o) { const r = origAttach.call(this, o); roots.push(r); return r; };
  const listeners = []; const responses = [];
  const location = { origin: 'https://site-a.com', hostname: 'site-a.com', href: 'https://site-a.com/login' };
  const win = { location, isSecureContext: true, postMessage: (m) => responses.push(m), addEventListener: (t, fn) => { if (t === 'message') listeners.push(fn); } };
  win.top = win;
  const chrome = { runtime: { sendMessage: async (m) => (m.type === 'PASSKEY_LIST' ? { success: true, passkeys } : { success: false }) } };
  if (locale) chrome.i18n = fakeI18n(ENRICHED, locale);
  // Monde isolé simulé : globalThis du contexte = { window, document, chrome, RDVaultPasskeyCore… }
  vm.runInNewContext(BRIDGE_SRC, {
    window: win, document: w.document, chrome, RDVaultPasskeyCore: core,
    getComputedStyle: () => ({}), performance, console, setTimeout, clearTimeout,
  }, { filename: path.join(ENRICHED, 'passkey-bridge.js') });
  let seq = 0;
  const send = (op, data) => listeners.forEach((fn) => fn({ source: win, data: { source: 'rdvault-passkey', dir: 'req', id: 'r' + (++seq), op, data } }));
  // Clic réel (isTrusted) : « Annuler » ne dépend d'aucune condition de visibilité
  const cancel = (root) => {
    const ev = new w.MouseEvent('click', { bubbles: true, cancelable: true, composed: true });
    idl.implForWrapper(ev).isTrusted = true;
    idl.implForWrapper(root.querySelector('.ca'))._dispatch(idl.implForWrapper(ev));
  };
  return { roots, send, responses, cancel };
}
const dialogText = (root) => ({
  dt: root.querySelector('.dt').textContent,
  ok: root.querySelector('.ok') ? root.querySelector('.ok').textContent : null,
  fb: root.querySelector('.fb').textContent,
  ca: root.querySelector('.ca').textContent,
  wn: root.querySelector('.wn').textContent,
  accounts: [...root.querySelectorAll('.ac')].map((b) => b.textContent),
  dir: root.querySelector('.ov').getAttribute('dir'),
  lang: root.querySelector('.ov').getAttribute('lang'),
});
const createData = { rpId: 'site-a.com', challenge: 'AAAA', userId: 'dTE', userName: 'alice@test', userDisplayName: 'Alice', attestation: 'none', algs: [-7], excludeCredentials: [], userVerification: 'preferred' };
const twoPasskeys = [
  { rpId: 'site-a.com', credentialId: 'c1', userName: 'bob@test', userDisplayName: 'Bob', createdAt: Date.UTC(2026, 0, 2) },
  { rpId: 'site-a.com', credentialId: 'c2', createdAt: Date.UTC(2026, 0, 3) },
];

test('fenêtre passkey sans chrome.i18n : textes français d\'origine, à l\'identique', async () => {
  const b = loadBridge();
  b.send('create', createData);
  const t = dialogText(b.roots[0]);
  assert.equal(t.dt, 'Créer une passkey pour site-a.com — alice@test');
  assert.equal(t.ok, 'Créer dans RDVAULT');
  assert.equal(t.fb, 'Utiliser un autre appareil');
  assert.equal(t.ca, 'Annuler');
  assert.equal(t.wn, 'Action bloquée : la fenêtre RDVAULT est masquée ou recouverte par la page. Utilisez « Utiliser un autre appareil » ou « Annuler ».');
  b.cancel(b.roots[0]);
  await sleep(10);
  assert.equal(b.responses.at(-1).error, 'RDVAULT_CANCELLED');

  const g = loadBridge({ passkeys: twoPasskeys });
  g.send('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [], userVerification: 'preferred' });
  await sleep(20);
  const tg = dialogText(g.roots[0]);
  assert.equal(tg.dt, 'Utiliser votre passkey pour site-a.com — choisissez le compte');
  assert.equal(tg.ok, null, 'plusieurs comptes : bouton unique remplacé');
  assert.equal(tg.accounts.length, 2);
  assert.ok(tg.accounts[0].startsWith('Bobbob@test · créée le '), tg.accounts[0]);
  assert.ok(tg.accounts[1].startsWith('Compte sans nomcréée le '), tg.accounts[1]);
  g.cancel(g.roots[0]);

  const s = loadBridge({ passkeys: twoPasskeys.slice(0, 1) });
  s.send('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [], userVerification: 'preferred' });
  await sleep(20);
  const ts = dialogText(s.roots[0]);
  assert.equal(ts.dt, 'Utiliser votre passkey pour site-a.com — bob@test');
  assert.equal(ts.ok, 'Utiliser ma passkey RDVAULT');
  s.cancel(s.roots[0]);
});

test('fenêtre passkey : textes fournis par chrome.i18n (anglais, japonais, arabe en rtl)', async () => {
  for (const loc of ['en', 'ja', 'ar']) {
    const b = loadBridge({ locale: loc });
    b.send('create', createData);
    const t = dialogText(b.roots[0]);
    assert.equal(t.dt, tr(ENRICHED, loc, 'pkCreateTitle', 'site-a.com') + ' — alice@test', loc);
    assert.equal(t.ok, tr(ENRICHED, loc, 'pkCreateOk'), loc);
    assert.equal(t.fb, tr(ENRICHED, loc, 'pkUseAnotherDevice'), loc);
    assert.equal(t.ca, tr(ENRICHED, loc, 'pkCancel'), loc);
    assert.equal(t.wn, tr(ENRICHED, loc, 'pkBlockedWarning', [t.fb, t.ca]), loc);
    assert.equal(t.dir, loc === 'ar' ? 'rtl' : 'ltr', loc);
    assert.equal(t.lang, loc, loc);
    // (les guillemets « » sont aussi ceux de l'arabe : seuls des mots français sont recherchés)
    assert.ok(!/[éèàç]|Créer|Annuler|Utiliser/.test(Object.values(t).join(' ')), `${loc} : reste du français : ${JSON.stringify(t)}`);
    b.cancel(b.roots[0]);

    const g = loadBridge({ locale: loc, passkeys: twoPasskeys });
    g.send('get', { rpId: 'site-a.com', challenge: 'AAAA', allowCredentials: [], userVerification: 'preferred' });
    await sleep(20);
    const tg = dialogText(g.roots[0]);
    assert.equal(tg.dt, tr(ENRICHED, loc, 'pkGetTitle', 'site-a.com') + ' — ' + tr(ENRICHED, loc, 'pkChooseAccount'), loc);
    const created = (ts) => tr(ENRICHED, loc, 'pkCreatedOn', new Date(ts).toLocaleDateString());
    assert.equal(tg.accounts[0], 'Bobbob@test · ' + created(twoPasskeys[0].createdAt), loc); // nom + sous-ligne
    assert.equal(tg.accounts[1], tr(ENRICHED, loc, 'pkUnnamedAccount') + created(twoPasskeys[1].createdAt), loc);
    g.cancel(g.roots[0]);
  }
  assert.equal(tr(ENRICHED, 'en', 'pkCreateOk'), 'Create in RDVAULT');
});

// ---------- Popups ----------
/** Charge une popup (HTML réel + script réel) avec un chrome simulé ; renvoie le document */
async function loadPopup(dir, { locale = null, reply }) {
  const html = fs.readFileSync(path.join(dir, 'popup.html'), 'utf8');
  const src = fs.readFileSync(path.join(dir, 'popup.js'), 'utf8');
  const sent = [];
  const dom = new JSDOM(html.replace('<script src="popup.js"></script>', ''), {
    runScripts: 'outside-only', pretendToBeVisual: true,
  });
  const chrome = { runtime: { sendMessage: async (m) => { sent.push(m); return reply(m); } } };
  if (locale) chrome.i18n = fakeI18n(dir, locale);
  dom.window.chrome = chrome;
  OPEN_WINDOWS.push(dom.window);
  dom.window.eval(src); // écouteur DOMContentLoaded enregistré avant la fin de l'analyse (readyState « loading »)
  if (dom.window.document.readyState === 'loading') {
    await new Promise((r) => dom.window.document.addEventListener('DOMContentLoaded', r));
  }
  await sleep(30);
  return { dom, d: dom.window.document, sent };
}
const norm = (s) => String(s).replace(/\s+/g, ' ').trim();
const paragraphs = (d) => [...d.querySelectorAll('#statusDetails p')].map((p) => p.textContent);
// Fenêtres jsdom ouvertes : fermées après chaque test, même en échec (minuteries de rafraîchissement)
const OPEN_WINDOWS = [];
test.afterEach(() => { while (OPEN_WINDOWS.length) { try { OPEN_WINDOWS.pop().close(); } catch { /* déjà fermée */ } } });

test('popup de l\'extension enrichie : textes traduits, français d\'origine sans chrome.i18n', async () => {
  const states = [
    { reply: { authenticated: true, username: 'alice', vaultUrl: 'https://v' }, key: 'popupDesktopConnected', fr: 'Desktop connecté' },
    { reply: { authenticated: false, pairing: 'pending' }, key: 'popupPairingPendingTitle', fr: 'Confirmez l\'accès dans l\'application RDVAULT' },
    { reply: { authenticated: false, pairing: 'denied' }, key: 'popupPairingDeniedTitle', fr: 'Accès refusé dans RDVAULT' },
    { reply: { authenticated: false, reachable: false }, key: 'popupDesktopUnavailable', fr: 'Desktop non disponible' },
    { reply: { authenticated: false, reachable: true }, key: 'popupDesktopNotConnected', fr: 'Desktop démarré mais non connecté' },
  ];
  for (const s of states) {
    const fr = await loadPopup(ENRICHED, { reply: () => s.reply });
    assert.equal(fr.d.getElementById('statusText').textContent, s.fr);
    assert.equal(norm(fr.d.querySelector('.info-box').textContent), 'Cette extension nécessite que l\'application RDVAULT soit lancée et déverrouillée.');
    if (s.key === 'popupDesktopConnected') {
      assert.deepEqual(paragraphs(fr.d), ['Utilisateur: alice', 'Serveur: https://v', '✓ Auto-remplissage actif']);
    }
    fr.dom.window.close();
    const en = await loadPopup(ENRICHED, { locale: 'en', reply: () => s.reply });
    assert.equal(en.d.getElementById('statusText').textContent, tr(ENRICHED, 'en', s.key));
    assert.equal(norm(en.d.querySelector('.info-box').textContent), tr(ENRICHED, 'en', 'popupInfoRequiresDesktop'));
    assert.equal(en.d.documentElement.lang, 'en');
    if (s.key === 'popupDesktopConnected') {
      assert.deepEqual(paragraphs(en.d), ['User: alice', 'Server: https://v', '✓ Autofill active']);
    }
    assert.ok(!/[éèàç]/.test(en.d.body.textContent), 'reste du français : ' + norm(en.d.body.textContent));
    en.dom.window.close();
  }
  const ar = await loadPopup(ENRICHED, { locale: 'ar', reply: () => ({ authenticated: false, reachable: false }) });
  assert.equal(ar.d.documentElement.dir, 'rtl');
  assert.equal(ar.d.documentElement.lang, 'ar');
  ar.dom.window.close();
});

test('popup de l\'extension simple : libellés, champs et messages traduits', async () => {
  const reply = (m) => (m.type === 'CHECK_AUTH' ? { authenticated: false } : { success: false, error: 'x' });
  const fr = await loadPopup(SIMPLE, { reply });
  const frText = norm(fr.d.getElementById('loginForm').textContent);
  assert.equal(frText, 'URL Vault Namespace (optionnel) Utilisateur LDAP Mot de passe Se connecter');
  assert.equal(fr.d.getElementById('vaultNamespace').placeholder, 'Laisser vide si non utilisé');
  fr.d.getElementById('loginBtn').click();
  await sleep(10);
  assert.equal(fr.d.getElementById('status').textContent, 'Veuillez remplir tous les champs obligatoires');
  fr.dom.window.close();

  const en = await loadPopup(SIMPLE, { locale: 'en', reply });
  const d = en.d;
  assert.equal(norm(d.getElementById('loginForm').textContent), ['popupVaultUrlLabel', 'popupNamespaceLabel', 'popupUsernameLabel', 'popupPassword', 'popupLoginButton'].map((k) => tr(SIMPLE, 'en', k)).join(' '));
  assert.equal(d.getElementById('vaultNamespace').placeholder, tr(SIMPLE, 'en', 'popupNamespacePlaceholder'));
  assert.equal(d.getElementById('username').placeholder, tr(SIMPLE, 'en', 'popupUsernamePlaceholder'));
  assert.equal(d.getElementById('password').placeholder, tr(SIMPLE, 'en', 'popupPassword'));
  assert.equal(norm(d.getElementById('authenticatedView').textContent), [tr(SIMPLE, 'en', 'popupConnectedAs'), tr(SIMPLE, 'en', 'popupRefreshButton'), tr(SIMPLE, 'en', 'popupLogoutButton')].join(' '));
  d.getElementById('loginBtn').click();
  await sleep(10);
  assert.equal(d.getElementById('status').textContent, tr(SIMPLE, 'en', 'popupFillRequired'));
  // Erreur renvoyée par le service worker : préfixe traduit
  d.getElementById('vaultUrl').value = 'https://v'; d.getElementById('username').value = 'u'; d.getElementById('password').value = 'p';
  d.getElementById('loginBtn').click();
  await sleep(20);
  assert.equal(d.getElementById('status').textContent, tr(SIMPLE, 'en', 'popupError', 'x'));
  assert.equal(d.getElementById('loginBtn').textContent, tr(SIMPLE, 'en', 'popupLoginButton'));
  assert.ok(!/[éèàç]/.test(d.body.textContent), 'reste du français : ' + norm(d.body.textContent));
  en.dom.window.close();
});

// ---------- Erreurs des service workers (affichées dans le menu d'autoremplissage) ----------
test('service worker enrichi : erreurs de SELECT_CREDENTIAL traduites, français sans chrome.i18n', async () => {
  const BG = path.join(ENRICHED, 'background.js');
  const bgSrc = fs.readFileSync(BG, 'utf8');
  const load = (status, chrome) => {
    const ctx = {
      console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
      URL, URLSearchParams, setTimeout, clearTimeout, setInterval, clearInterval,
      importScripts() { ctx.authManager = { start: async () => {}, authenticatedFetch: async () => ({ ok: status < 300, status, json: async () => ({}) }) }; },
    };
    if (chrome) ctx.chrome = chrome;
    vm.createContext(ctx);
    vm.runInContext(bgSrc, ctx, { filename: BG });
    return vm.runInContext('getSecretForHost', ctx);
  };
  assert.equal((await load(404)('site-a.com', 'e', 'n')).error, 'Identifiant introuvable pour ce site');
  assert.equal((await load(500)('site-a.com', 'e', 'n')).error, 'Erreur HTTP 500');
  const en = { i18n: fakeI18n(ENRICHED, 'en') };
  assert.equal((await load(404, en)('site-a.com', 'e', 'n')).error, tr(ENRICHED, 'en', 'bgErrNotFound'));
  assert.equal((await load(500, en)('site-a.com', 'e', 'n')).error, tr(ENRICHED, 'en', 'bgErrHttp', '500'));
  assert.equal(tr(ENRICHED, 'en', 'bgErrHttp', '500'), 'HTTP error 500');
});

test('service worker simple : erreurs traduites', async () => {
  const BG = path.join(SIMPLE, 'background.js');
  const src = fs.readFileSync(BG, 'utf8');
  for (const loc of [null, 'en', 'de']) {
    let handler = null;
    const chrome = {
      runtime: { id: 'ext', onMessage: { addListener: (fn) => { handler = fn; } }, onStartup: { addListener() {} } },
      alarms: { create() {}, onAlarm: { addListener() {} } },
      storage: { session: { get: async () => ({}), set: async () => {}, clear: async () => {} }, local: { remove: async () => {} } },
    };
    if (loc) chrome.i18n = fakeI18n(SIMPLE, loc);
    const ctx = { console: { log() {}, info() {}, warn() {}, error() {} }, URL, setTimeout, clearTimeout, chrome, importScripts() { ctx.VaultClient = function () {}; } };
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: BG });
    const call = (req, sender) => new Promise((resolve) => handler(req, { id: 'ext', ...sender }, resolve));
    const tab = { tab: { url: 'https://site-a.com/login' } };
    const exp = (key) => (loc ? tr(SIMPLE, loc, key) : { bgErrNameRequired: 'Nom de secret requis', bgErrInsecurePage: 'Page non sécurisée', bgErrInvalidVaultUrl: 'URL Vault invalide (https obligatoire)' }[key]);
    assert.equal((await call({ type: 'SELECT_CREDENTIAL', name: '' }, tab)).error, exp('bgErrNameRequired'), String(loc));
    assert.equal((await call({ type: 'SELECT_CREDENTIAL', name: 'x' }, { tab: { url: 'http://site-a.com/' } })).error, exp('bgErrInsecurePage'), String(loc));
    assert.equal((await call({ type: 'LOGIN', vaultUrl: 'http://vault' }, {})).error, exp('bgErrInvalidVaultUrl'), String(loc));
  }
});

// ---------- EXT-29 : noms des deux extensions ----------
test('EXT-29 : l\'extension enrichie s\'appelle « RDVAULT » partout, la simple a un nom distinct qui commence par RDVAULT', () => {
  for (const loc of LOCALES) {
    const e = readMessages(ENRICHED, loc);
    const s = readMessages(SIMPLE, loc);
    assert.equal(e.extName.message, 'RDVAULT', `${loc} : nom de l'extension enrichie`);
    assert.ok(/^RDVAULT\b/.test(s.extName.message) && s.extName.message !== 'RDVAULT', `${loc} : nom de l'extension simple (${s.extName.message})`);
    assert.ok(!/Vault Autofill/.test(e.extName.message + s.extName.message), `${loc} : ancien nom « Vault Autofill »`);
    assert.ok(!/Desktop Vault|Vault desktop|Vault-Desktop|Vault 桌面|Vault デスクトップ|Vault 데스크톱|Vault لسطح/.test(e.popupInfoRequiresDesktop.message), `${loc} : la popup parle encore de l'application « Vault »`);
    assert.ok(e.popupInfoRequiresDesktop.message.includes('RDVAULT'), `${loc} : popup sans « RDVAULT »`);
  }
  assert.equal(readMessages(SIMPLE, 'fr').extName.message, 'RDVAULT (Vault direct)');
  assert.equal(readMessages(ENRICHED, 'fr').extDescription.message, 'Auto-remplissage de formulaires et passkeys avec RDVAULT (nécessite l\'application de bureau RDVAULT)');
  // Popups : titre RDVAULT (plus « Vault Autofill »)
  for (const dir of [ENRICHED, SIMPLE]) {
    const html = fs.readFileSync(path.join(dir, 'popup.html'), 'utf8');
    assert.ok(!html.includes('Vault Autofill'), path.relative(ROOT, dir) + ' : popup encore titrée « Vault Autofill »');
  }
});

// ---------- EXT-23 : RDVAULT verrouillé / fermé, messages explicites ----------
/** background.js de l'extension enrichie dans un contexte vm ; `fetchImpl(url)` simule authenticatedFetch */
function loadEnrichedBackground(fetchImpl, { locale = null, pairingDenied = false } = {}) {
  const BG = path.join(ENRICHED, 'background.js');
  const ctx = {
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    URL, URLSearchParams, setTimeout, clearTimeout, setInterval, clearInterval,
    importScripts() {
      ctx.authManager = { start: async () => {}, authenticatedFetch: async (url) => fetchImpl(url), isPairingDenied: () => pairingDenied };
    },
  };
  if (locale) ctx.chrome = { i18n: fakeI18n(ENRICHED, locale) };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(BG, 'utf8'), ctx, { filename: BG });
  return (name) => vm.runInContext(name, ctx);
}
const httpReply = (status, body = {}) => async () => ({ ok: status < 300, status, json: async () => body });
const refused = async () => { throw new TypeError('Failed to fetch'); };
const LOCKED_FR = 'RDVAULT est verrouillé : déverrouillez l\'application, puis réessayez.';
const CLOSED_FR = 'RDVAULT est fermé ou injoignable : ouvrez l\'application, puis réessayez.';

test('EXT-23 : identifiant choisi avec RDVAULT verrouillé (401) ou fermé → « RDVAULT est verrouillé / fermé », plus « Erreur HTTP 401 »', async () => {
  const sender = { tab: { url: 'https://site-a.com/login' }, frameId: 0 };
  assert.equal((await loadEnrichedBackground(httpReply(401))('getSecretForHost')('site-a.com', 'e', 'n')).error, LOCKED_FR);
  assert.equal((await loadEnrichedBackground(refused)('getSecretForHost')('site-a.com', 'e', 'n')).error, CLOSED_FR);
  assert.equal((await loadEnrichedBackground(httpReply(429))('getSecretForHost')('site-a.com', 'e', 'n')).error, 'Trop de demandes envoyées à RDVAULT : réessayez dans un instant.');
  assert.equal((await loadEnrichedBackground(refused, { pairingDenied: true })('getSecretForHost')('site-a.com', 'e', 'n')).error, 'Accès refusé dans RDVAULT');
  // Liste du site : échec signalé comme tel, avec la raison (le menu ne dit plus « aucun identifiant »)
  const locked = await loadEnrichedBackground(httpReply(401))('handleGetCredentials')(sender);
  assert.equal(locked.success, false);
  assert.equal(locked.error, LOCKED_FR);
  const closed = await loadEnrichedBackground(refused)('handleGetCredentials')(sender);
  assert.equal(closed.success, false);
  assert.equal(closed.error, CLOSED_FR);
  // Traduit (anglais)
  assert.equal((await loadEnrichedBackground(httpReply(401), { locale: 'en' })('getSecretForHost')('site-a.com', 'e', 'n')).error, tr(ENRICHED, 'en', 'bgErrVaultLocked'));
  assert.equal(tr(ENRICHED, 'en', 'bgErrVaultLocked'), 'RDVAULT is locked: unlock the app, then try again.');
});

test('EXT-26 : PASSKEY_STATUS (fenêtre passkey) → prêt seulement si RDVAULT est ouvert ET déverrouillé', async () => {
  const status = async (impl) => JSON.parse(JSON.stringify(await loadEnrichedBackground(impl)('handlePasskeyStatus')()));
  assert.deepEqual(await status(httpReply(200, { connected: true, vaultUrl: 'v', username: 'u' })), { success: true, ready: true });
  assert.deepEqual(await status(httpReply(200, { connected: false })), { success: true, ready: false }, 'verrouillé');
  assert.deepEqual(await status(refused), { success: true, ready: false }, 'fermé');
  assert.deepEqual(await status(httpReply(401)), { success: true, ready: false });
});

test('EXT-23 : extension simple — non connectée à Vault ou Vault injoignable → échec explicite, plus une liste vide', async () => {
  const BG = path.join(SIMPLE, 'background.js');
  const src = fs.readFileSync(BG, 'utf8');
  const load = (client) => {
    let handler = null;
    const chrome = {
      runtime: { id: 'ext', onMessage: { addListener: (fn) => { handler = fn; } }, onStartup: { addListener() {} } },
      alarms: { create() {}, onAlarm: { addListener() {} } },
      storage: { session: { get: async () => (client ? { vaultUrl: 'https://vault', vaultToken: 't' } : {}), set: async () => {}, clear: async () => {} }, local: { remove: async () => {} } },
    };
    const ctx = { console: { log() {}, info() {}, warn() {}, error() {} }, URL, setTimeout, clearTimeout, chrome, importScripts() { ctx.VaultClient = client || function () {}; } };
    vm.createContext(ctx);
    vm.runInContext(src, ctx, { filename: BG });
    return (req) => new Promise((resolve) => handler(req, { id: 'ext', tab: { url: 'https://site-a.com/login' } }, resolve));
  };
  const notLogged = await load(null)({ type: 'GET_CREDENTIALS' });
  assert.equal(notLogged.success, false);
  assert.equal(notLogged.error, 'Non connecté à Vault : ouvrez la fenêtre de l\'extension pour vous connecter.');
  function Failing() { this.getAllSecrets = async () => { throw new Error('403'); }; }
  const unreachable = await load(Failing)({ type: 'GET_CREDENTIALS' });
  assert.equal(unreachable.success, false);
  assert.equal(unreachable.error, 'Vault injoignable ou session expirée : reconnectez-vous depuis la fenêtre de l\'extension.');
  const sel = await load(Failing)({ type: 'SELECT_CREDENTIAL', name: 'x', engine: '' });
  assert.equal(sel.error, unreachable.error, 'sélection : même explication, plus « identifiant introuvable »');
  function Working() { this.getAllSecrets = async () => [{ name: 'a', engine: 'kv', username: 'u', password: 'p', url: 'https://site-a.com' }]; }
  const ok = await load(Working)({ type: 'GET_CREDENTIALS' });
  assert.equal(ok.success, true);
  assert.deepEqual(JSON.parse(JSON.stringify(ok.credentials)), [{ name: 'a', engine: 'kv', username: 'u' }]);
});

// ---------- EXT-25 : appairage annoncé seulement s'il est réellement en attente ----------
function loadAuthManager(fetchImpl) {
  const FILE = path.join(ENRICHED, 'auth-manager.js');
  const ctx = {
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    setTimeout, clearTimeout, setInterval, clearInterval, AbortController, Error, Promise, Date,
    fetch: fetchImpl,
    chrome: {
      runtime: { id: 'ext', getPlatformInfo() {} },
      storage: { session: { get: async () => ({}), set: async () => {}, remove: async () => {} } },
      alarms: { create: async () => {}, clear: async () => {}, onAlarm: { addListener() {} } },
    },
    module: { exports: {} },
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(FILE, 'utf8'), ctx, { filename: FILE });
  return ctx.module.exports.authManager || vm.runInContext('authManager', ctx);
}

test('EXT-25 : RDVAULT fermé (connexion refusée) → jamais « demande d\'appairage envoyée » ; boîte d\'appairage ouverte (> 1 s) → en attente', { timeout: 20000 }, async () => {
  const closed = loadAuthManager(async () => { throw new TypeError('Failed to fetch'); });
  const states = new Set();
  const sampler = setInterval(() => states.add(closed.getPairingState()), 20);
  const ok = await closed._fetchNewToken();
  clearInterval(sampler);
  assert.equal(ok, false);
  assert.ok(!states.has('pending'), 'jamais « en attente d\'appairage » : ' + [...states].join(', '));
  assert.ok(states.has('unavailable'), 'indisponible entre deux tentatives');
  assert.equal(closed.getPairingState(), 'unavailable');

  // Boîte d'appairage affichée dans RDVAULT : la requête reste ouverte → « en attente » après ~1 s
  const pairing = loadAuthManager(() => new Promise((resolve) => setTimeout(() => resolve({ ok: true, status: 200, json: async () => ({ token: 'tok' }) }), 1600)));
  const p = pairing._fetchNewToken();
  await sleep(300);
  assert.equal(pairing.getPairingState(), 'connecting', 'connexion en cours');
  assert.equal(pairing.isPairingPending(), false);
  await sleep(1000);
  assert.equal(pairing.isPairingPending(), true, 'requête toujours ouverte après 1 s : appairage en attente');
  assert.equal(await p, true);
  assert.equal(pairing.getPairingState(), 'ok');
});

test('EXT-25 / EXT-27 : popup enrichie — état « connexion en cours », région annoncée (role=status), pas de réannonce sans changement', { timeout: 15000 }, async () => {
  let reply = { authenticated: false, pairing: 'pending', reachable: true };
  const p = await loadPopup(ENRICHED, { reply: () => reply });
  const card = p.d.getElementById('statusCard');
  assert.equal(card.getAttribute('role'), 'status');
  assert.equal(card.getAttribute('aria-live'), 'polite');
  assert.equal(card.getAttribute('aria-atomic'), 'true');
  assert.equal(p.d.querySelector('h1').textContent, 'RDVAULT');
  assert.equal(p.d.title, 'RDVAULT');
  assert.equal(p.d.getElementById('statusText').textContent, 'Confirmez l\'accès dans l\'application RDVAULT');
  // Même état au rafraîchissement suivant (2 s pendant l'appairage) : contenu non réécrit, rien de réannoncé
  let mutations = 0;
  new p.dom.window.MutationObserver((list) => { mutations += list.length; }).observe(card, { childList: true, subtree: true, characterData: true, attributes: true });
  await sleep(2200);
  assert.equal(mutations, 0, 'aucune mutation de la région annoncée sans changement d\'état');
  // Demande de token sans réponse encore : « Vérification... », pas « demande d'appairage envoyée »
  reply = { authenticated: false, pairing: 'connecting', reachable: null };
  await sleep(2200);
  assert.equal(p.d.getElementById('statusText').textContent, 'Vérification...');
  assert.equal(p.d.getElementById('statusDetails').textContent, '');
});

test('EXT-27 : popup simple — erreur annoncée (role=alert) et conservée jusqu\'à l\'action suivante, succès (role=status) masqué après 3 s', { timeout: 15000 }, async () => {
  const reply = (m) => (m.type === 'CHECK_AUTH' ? { authenticated: false } : { success: false, error: 'x' });
  const p = await loadPopup(SIMPLE, { reply });
  const d = p.d;
  assert.equal(d.querySelector('h1').textContent, 'RDVAULT (Vault direct)');
  d.getElementById('loginBtn').click();
  await sleep(10);
  const status = d.getElementById('status');
  assert.equal(status.getAttribute('role'), 'alert');
  assert.equal(status.textContent, 'Veuillez remplir tous les champs obligatoires');
  await sleep(3300);
  assert.equal(status.classList.contains('hidden'), false, 'erreur toujours affichée après 3 s');
});
