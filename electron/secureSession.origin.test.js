// ========================================
// TESTS UNITAIRES RBI (sans navigateur)
// ========================================
// RBI-11 : isInjectionTargetAllowed — un secret de l'entrée n'est saisi que dans un document dont
//          l'hôte correspond à celui de l'URL de l'entrée (même règle que l'extension : hostsMatch).
// RBI-12 : suppression du profil éphémère après la fin de Chromium, réessai après échec, nettoyage
//          des profils orphelins au démarrage (tous âges pour les profils RBI, sauf profil en usage).
// RBI-14 : detectKnownSelectors — correspondance par libellés, du domaine le plus spécifique au
//          plus général (AWS avant la boutique Amazon, jamais « notamazon.com »).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { spawn } = require('node:child_process');

// TEMP jetable AVANT le chargement du module (nettoyage au démarrage limité à ce dossier)
const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-rbi-unit-'));
process.env.TEMP = TMP_ROOT;
process.env.TMP = TMP_ROOT;
process.env.RDVAULT_LOG_LEVEL = process.env.RDVAULT_LOG_LEVEL || 'error';

const {
  isInjectionTargetAllowed,
  detectKnownSelectors,
  cleanupStaleProfiles,
  removeSessionProfile,
  KNOWN_SELECTORS,
} = require('./secureSession');

test.after(() => {
  try { fs.rmSync(TMP_ROOT, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); } catch { /* ignore */ }
});

// ---------------------------------------------------------------------------------------------
// RBI-11
// ---------------------------------------------------------------------------------------------

test('RBI-11 : hôtes acceptés (identique, sous-domaine, même domaine de base, équivalents, marque d\'un locataire)', () => {
  const allowed = [
    ['https://github.com/login', 'https://github.com/session'],
    ['https://example.com', 'https://login.example.com/auth'],             // domaine parent
    ['https://www.example.com/', 'https://auth.example.com/'],             // même domaine de base
    ['https://portal.office.com/', 'https://login.microsoftonline.com/'],  // domaines équivalents
    ['https://www.microsoft.com/', 'https://login.live.com/'],
    ['https://contoso.sharepoint.com/sites/rh', 'https://login.microsoftonline.com/common/oauth2'], // locataire → marque
    ['https://www.ovhcloud.com/', 'https://auth.ovh.com/'],
    ['http://127.0.0.1:8080/', 'http://127.0.0.1:9090/login'],            // IP identique (port ignoré, comme l'extension)
    ['https://intranet/', 'http://intranet/login'],                         // nom court identique
    ['https://github.com/', 'http://github.com/'],                          // schéma http(s) indifférent
    ['github.com', 'https://github.com/login'],                             // entrée sans schéma
  ];
  for (const [entry, target] of allowed) {
    assert.strictEqual(isInjectionTargetAllowed(entry, target), true, `${entry} → ${target} doit être accepté`);
  }
});

test('RBI-11 : hôtes refusés (autre IP, autre domaine, sosie, locataire voisin, sens marque → locataire)', () => {
  const refused = [
    ['http://127.0.0.1:18771/', 'http://127.0.0.2:18772/login'],          // autre IP (redirection du scénario)
    ['https://example.com/', 'https://evil-example.com/'],
    ['https://example.com/', 'https://example.com.evil.net/'],
    ['https://example.com/', 'https://notexample.com/'],
    ['https://contoso.sharepoint.com/', 'https://evil.sharepoint.com/'],  // locataire voisin
    ['https://team.github.io/', 'https://evil.github.io/'],               // PSL privée
    ['https://login.microsoftonline.com/', 'https://contoso.sharepoint.com/'], // jamais marque → locataire
    ['https://intranet/', 'https://intranet.corp.local/'],                 // nom court : identique uniquement
    ['https://app.corp.com/', 'https://corp.okta.com/'],                   // fournisseur d'identité tiers
  ];
  for (const [entry, target] of refused) {
    assert.strictEqual(isInjectionTargetAllowed(entry, target), false, `${entry} → ${target} doit être refusé`);
  }
});

test('RBI-11 : cibles sans hôte http(s) refusées, entrée invalide refusée', () => {
  for (const target of ['about:blank', 'about:srcdoc', 'data:text/html,<input>', 'blob:https://github.com/x',
    'chrome-error://chromewebdata/', 'javascript:void(0)', '', null, undefined, 'pas une url']) { // eslint-disable-line no-script-url
    assert.strictEqual(isInjectionTargetAllowed('https://github.com/', target), false, `${String(target)} refusé`);
  }
  for (const entry of ['', null, undefined, 42, {}]) {
    assert.strictEqual(isInjectionTargetAllowed(entry, 'https://github.com/'), false, `entrée ${String(entry)} refusée`);
  }
});

test('RBI-11 : plusieurs URL d\'entrée (url + website) : une correspondance suffit', () => {
  assert.strictEqual(isInjectionTargetAllowed(['https://app.example.com', 'https://id.example.org'], 'https://login.example.org/'), true);
  assert.strictEqual(isInjectionTargetAllowed(['https://app.example.com', 'https://id.example.org'], 'https://evil.example.net/'), false);
});

// ---------------------------------------------------------------------------------------------
// RBI-14
// ---------------------------------------------------------------------------------------------

test('RBI-14 : sélecteurs AWS atteignables, boutique Amazon pour amazon.*, défaut pour un sosie', () => {
  assert.deepStrictEqual(detectKnownSelectors('https://signin.aws.amazon.com/signin'), KNOWN_SELECTORS['signin.aws.amazon.com']);
  assert.deepStrictEqual(detectKnownSelectors('https://console.aws.amazon.com/console/home'), KNOWN_SELECTORS['console.aws.amazon.com']);
  assert.deepStrictEqual(detectKnownSelectors('https://www.amazon.fr/ap/signin'), KNOWN_SELECTORS['amazon.fr']);
  assert.deepStrictEqual(detectKnownSelectors('https://www.amazon.com/ap/signin'), KNOWN_SELECTORS['amazon.com']);
  assert.deepStrictEqual(detectKnownSelectors('https://www.amazon.com.au/ap/signin'), KNOWN_SELECTORS['amazon.com']);
  assert.deepStrictEqual(detectKnownSelectors('https://notamazon.com/login'), KNOWN_SELECTORS.default);
  assert.deepStrictEqual(detectKnownSelectors('https://mygithub.com/login'), KNOWN_SELECTORS.default);
  assert.deepStrictEqual(detectKnownSelectors('https://github.com/login'), KNOWN_SELECTORS['github.com']);
  assert.deepStrictEqual(detectKnownSelectors('https://login.salesforce.com/'), KNOWN_SELECTORS['salesforce.com']);
  assert.deepStrictEqual(detectKnownSelectors('https://monorg.lightning.force.com/'), KNOWN_SELECTORS['force.com']);
});

test('RBI-14 : copie renvoyée (KNOWN_SELECTORS jamais muté) et détections par port / motif inchangées', () => {
  const s = detectKnownSelectors('https://signin.aws.amazon.com/');
  s.username = 'muté';
  assert.strictEqual(KNOWN_SELECTORS['signin.aws.amazon.com'].username, '#account');
  assert.strictEqual(detectKnownSelectors('https://pve.lan:8006/').special, 'proxmox');
  assert.strictEqual(detectKnownSelectors('https://esxi01.lan/ui/').special, 'esxi');
  assert.deepStrictEqual(detectKnownSelectors('pas une url'), KNOWN_SELECTORS.default);
});

// ---------------------------------------------------------------------------------------------
// RBI-12
// ---------------------------------------------------------------------------------------------

function makeProfile(name) {
  const dir = path.join(TMP_ROOT, name);
  fs.mkdirSync(path.join(dir, 'Default', 'Network'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'Default', 'Network', 'Cookies'), 'auth_session=SESSION-TOKEN');
  return dir;
}

/** Faux browser Puppeteer dont le processus principal se termine sur commande */
function fakeBrowser() {
  const proc = new EventEmitter();
  proc.exitCode = null;
  proc.signalCode = null;
  return {
    proc,
    browser: { process: () => proc },
    exit() { proc.exitCode = 0; proc.emit('exit', 0, null); },
  };
}

test('RBI-12 : suppression du profil APRÈS la fin du processus Chromium, `cleaned` seulement si réussie', async () => {
  const dir = makeProfile('rbi-00000000000000a1');
  const fb = fakeBrowser();
  const session = { browser: fb.browser, profileDir: dir, ttlTimer: null, cleaned: false };
  const first = removeSessionProfile(session, 'unit-1');
  const second = removeSessionProfile(session, 'unit-1');
  assert.strictEqual(first, second, 'promesse mémorisée partagée par tous les chemins de fermeture');
  await new Promise((r) => setTimeout(r, 100));
  assert.strictEqual(fs.existsSync(dir), true, 'profil conservé tant que Chromium tourne');
  assert.strictEqual(session.cleaned, false);
  fb.exit();
  assert.strictEqual(await first, true);
  assert.strictEqual(fs.existsSync(dir), false);
  assert.strictEqual(session.cleaned, true);
  assert.strictEqual(await removeSessionProfile(session, 'unit-1'), true, 'appel ultérieur : déjà supprimé');
});

test('RBI-12 : profil verrouillé → échec borné, `cleaned` reste false, nouvel essai réussi une fois libéré', {
  skip: process.platform !== 'win32' ? 'verrou de dossier propre à Windows' : false, timeout: 60000,
}, async () => {
  const dir = makeProfile('rbi-00000000000000b2');
  const lockedSub = path.join(dir, 'Default');
  // Un processus dont le répertoire courant est dans le profil le verrouille (comme un enfant Chromium)
  const holder = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { cwd: lockedSub, stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 300));
  const session = { browser: null, profileDir: dir, ttlTimer: null, cleaned: false };
  try {
    const t0 = Date.now();
    assert.strictEqual(await removeSessionProfile(session, 'unit-2'), false);
    assert.ok(Date.now() - t0 < 20000, 'réessais bornés');
    assert.strictEqual(session.cleaned, false, 'pas marqué supprimé après un échec');
    assert.strictEqual(fs.existsSync(lockedSub), true);
  } finally {
    holder.kill();
    await new Promise((r) => holder.once('exit', r));
  }
  assert.strictEqual(await removeSessionProfile(session, 'unit-2'), true, 'nouvel essai après libération');
  assert.strictEqual(fs.existsSync(dir), false);
  assert.strictEqual(session.cleaned, true);
});

test('RBI-12 : démarrage — profils RBI orphelins supprimés quel que soit leur âge, autres « rbi-* » récents et liens conservés', () => {
  const recentOrphan = makeProfile('rbi-0123456789abcdef');
  fs.writeFileSync(path.join(recentOrphan, 'lockfile'), ''); // verrou resté d'un Chromium disparu
  const legacyRecent = makeProfile('rbi-autre-logiciel');
  const legacyOld = makeProfile('rbi-ancien-format');
  const old = new Date(Date.now() - 3 * 60 * 60 * 1000);
  fs.utimesSync(legacyOld, old, old);
  const target = makeProfile('cible-du-lien');
  const link = path.join(TMP_ROOT, 'rbi-fedcba9876543210');
  fs.symlinkSync(target, link, 'junction');

  const removed = cleanupStaleProfiles();

  assert.strictEqual(fs.existsSync(recentOrphan), false, 'profil RBI orphelin récent supprimé');
  assert.strictEqual(fs.existsSync(legacyOld), false, 'ancien « rbi-* » de plus de 2 h supprimé (règle historique)');
  assert.strictEqual(fs.existsSync(legacyRecent), true, '« rbi-* » d\'un autre format récent conservé');
  assert.strictEqual(fs.existsSync(path.join(target, 'Default', 'Network', 'Cookies')), true, 'lien / jonction jamais suivi');
  assert.ok(removed >= 2, `au moins les 2 orphelins supprimés (${removed})`);
  assert.strictEqual(fs.existsSync(link), true, 'le lien lui-même n\'est pas supprimé');
});
