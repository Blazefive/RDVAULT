// Noms d'entrée transmis tels quels par le service worker de l'extension enrichie (SYNC-29)
// background.js : sanitizeString (trim + coupe à 200) servait aussi aux NOMS d'entrée, que le serveur de
// synchronisation cherche par égalité stricte. Une entrée « Gmail␠ » (espace final, fréquent dans les exports
// d'autres gestionnaires), « ␠Banque » ou un nom de plus de 200 caractères était proposée dans le menu mais
// impossible à remplir (« Identifiant introuvable pour ce site »), et sa clé TOTP était altérée de même.
// Attendu : nom d'entrée et nom de clé TOTP transmis sans altération (refusés s'ils sont invalides : vides,
// trop longs, caractères de contrôle), libellés affichés toujours nettoyés.
// background.js est chargé tel quel dans un contexte vm ; auth-manager.js est remplacé par un double qui
// journalise les URL demandées au serveur de synchronisation.
// Lancement : node --test test/extension/entry-name.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const BG_FILE = path.resolve(__dirname, '..', '..', 'chrome-extension/vault-autofill-extension/background.js');
const bgSrc = fs.readFileSync(BG_FILE, 'utf8');

const LONG = 'x'.repeat(250);
const SECRETS = [
  { name: 'espace-fin ', engine: 'mes-secrets', username: '  user-a  ', url: 'https://localhost:8457', type: 'login' },
  { name: ' Banque', engine: 'mes-secrets', username: 'user-b', url: 'https://localhost:8457', type: 'login' },
  { name: LONG, engine: 'mes-secrets', username: 'user-c', url: 'https://localhost:8457', type: 'login' },
  { name: 'ctrl\u0001nom', engine: 'mes-secrets', username: 'user-d', url: 'https://localhost:8457', type: 'login' },
  { name: 'dossier/compte', engine: 'mes-secrets', username: 'user-e', url: 'https://localhost:8457', type: 'login' },
];

/** Charge background.js ; le serveur simulé renvoie la liste ou l'entrée demandée (égalité stricte du nom) */
function loadBackground() {
  const requested = [];
  const stored = {};
  const respond = (url) => {
    const u = new URL(url);
    if (u.pathname === '/api/secrets') return { ok: true, status: 200, json: async () => ({ success: true, secrets: SECRETS }) };
    if (u.pathname === '/api/secret') {
      const s = SECRETS.find((x) => x.name === u.searchParams.get('name') && x.engine === u.searchParams.get('engine'));
      if (!s) return { ok: false, status: 404, json: async () => ({ error: 'Secret not found for this host' }) };
      return { ok: true, status: 200, json: async () => ({ success: true, secret: { ...s, password: 'P@ss' } }) };
    }
    if (u.pathname.startsWith('/api/totp/')) return { ok: true, status: 200, json: async () => ({ success: true, code: '123456' }) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const ctx = {
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    URL, URLSearchParams, setTimeout, clearTimeout, setInterval, clearInterval,
    chrome: { storage: { session: { set: async (o) => { Object.assign(stored, o); }, get: async () => ({ ...stored }), remove: async () => {} } } },
    importScripts() {
      ctx.authManager = {
        start: async () => {},
        authenticatedFetch: async (url) => { requested.push(url); return respond(url); },
      };
    },
  };
  vm.createContext(ctx);
  vm.runInContext(bgSrc, ctx, { filename: BG_FILE });
  const fn = (name) => vm.runInContext(name, ctx);
  return { requested, stored, fn };
}

const sender = { tab: { url: 'https://localhost:8457/classic.html' }, frameId: 0 };

test('liste du site : noms d\'entrée intacts (espaces, > 200 caractères), entrée au nom invalide écartée, libellés nettoyés', async () => {
  const bg = loadBackground();
  const r = await bg.fn('handleGetCredentials')(sender);
  assert.equal(r.success, true);
  const names = r.credentials.map((c) => c.name);
  assert.deepEqual(names, ['espace-fin ', ' Banque', LONG, 'dossier/compte']);
  assert.equal(r.credentials[0].username, 'user-a', 'libellé affiché toujours nettoyé');
});

test('SELECT_CREDENTIAL : le nom exact est demandé au serveur et l\'identifiant est rempli', async () => {
  for (const name of ['espace-fin ', ' Banque', LONG]) {
    const bg = loadBackground();
    const r = await bg.fn('handleSelectCredential')({ engine: 'mes-secrets', name }, sender);
    const url = new URL(bg.requested[bg.requested.length - 1]);
    assert.equal(url.searchParams.get('name'), name, 'nom transmis sans altération');
    assert.equal(r.success, true, JSON.stringify(name) + ' : ' + JSON.stringify(r));
    assert.equal(r.credential.name, name);
    assert.equal(r.credential.password, 'P@ss');
  }
});

test('SELECT_CREDENTIAL : nom vide, trop long (> 512) ou avec caractère de contrôle refusé sans requête', async () => {
  for (const name of ['', 'a'.repeat(513), 'a\u0000b', 'a\nb', 42, null]) {
    const bg = loadBackground();
    const r = await bg.fn('handleSelectCredential')({ engine: 'mes-secrets', name }, sender);
    assert.equal(r.success, false, JSON.stringify(name));
    assert.equal(bg.requested.length, 0, 'aucune requête pour ' + JSON.stringify(name));
  }
});

test('TOTP : nom de clé exact (espace final) transmis et mémorisé sans altération', async () => {
  const bg = loadBackground();
  const r = await bg.fn('getTotpCodeFromDesktop')('MES-SECRETS-espace-fin ');
  assert.equal(r.success, true);
  assert.equal(bg.requested[0].endsWith('/api/totp/' + encodeURIComponent('MES-SECRETS-espace-fin ')), true, bg.requested[0]);
  const saved = await bg.fn('handleSaveLastCredential')({ name: 'espace-fin ', engine: 'mes-secrets', totpKey: 'MES-SECRETS-espace-fin ' }, 'localhost');
  assert.equal(saved.success, true);
  const last = Object.values(bg.stored)[0];
  assert.equal(last.name, 'espace-fin ');
  assert.equal(last.totpKey, 'MES-SECRETS-espace-fin ');
  // Nom de clé invalide : refusé sans requête
  const bad = loadBackground();
  assert.equal((await bad.fn('getTotpCodeFromDesktop')('a\u0001b')).success, false);
  assert.equal((await bad.fn('getTotpCodeFromDesktop')('k'.repeat(257))).success, false);
  assert.equal(bad.requested.length, 0);
});
