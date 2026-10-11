// IPC rbi-launch-session (suite des notes RBI) — node --test electron/main.rbiLaunch.test.js
// main.js RÉEL sous Node (electron simulé) ; secureSession.launchSecureSession remplacé par un double qui
// enregistre les options reçues (aucun navigateur lancé).
// - Le champ « website » de l'entrée est transmis (validé) : seconde adresse de référence pour la saisie,
//   comme l'extension (url OU website) ; valeur invalide ignorée ; l'URL ouverte reste url.
// - Erreur inattendue : message dans la langue de l'interface (était toujours en français).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const calls = [];
let fail = false;
const ctx = loadMainWithMockElectron({
  beforeRequire: () => {
    const rbi = require('./secureSession');
    rbi.launchSecureSession = async (opts) => {
      calls.push(opts);
      if (fail) throw new Error('boum');
      return { success: true, sessionId: 'session_x' };
    };
  },
});
const mainI18n = require('./mainI18n');

test.after(() => { mainI18n.resetUiLanguage(); ctx.cleanup(); });

const launch = (extra) => ctx.invoke('rbi-launch-session', { url: 'https://login.a.example/', username: 'u', password: 'p', ...extra });

test('website valide (URL ou nom d\'hôte nu) transmis à secureSession ; URL ouverte inchangée', async () => {
  for (const website of ['https://sso.b.example/login', 'b.example', '  b.example  ']) {
    calls.length = 0;
    assert.equal((await launch({ website })).success, true);
    assert.equal(calls[0].url, 'https://login.a.example/');
    assert.equal(calls[0].website, website.trim(), JSON.stringify(website));
  }
});

test('website invalide ou absent : ignoré (aucune autre adresse de référence)', async () => {
  const scriptUrl = ['javascript', 'alert(1)'].join(':'); // URL de script (jamais ouverte, nom d'hôte invalide)
  for (const website of [undefined, '', 42, { href: 'x' }, scriptUrl, 'b.exa\u0001mple', 'https://' + 'a'.repeat(2050) + '.example', 'https://exa mple.com']) {
    calls.length = 0;
    await launch(website === undefined ? {} : { website });
    assert.equal(Object.prototype.hasOwnProperty.call(calls[0], 'website'), false, JSON.stringify(website));
  }
});

test('erreur inattendue : message dans la langue de l\'interface', async () => {
  fail = true;
  try {
    mainI18n.setUiLanguage('de');
    assert.deepEqual(await launch({}), { success: false, error: 'Fehler beim Starten der RBI-Sitzung' });
    mainI18n.setUiLanguage('fr');
    assert.deepEqual(await launch({}), { success: false, error: 'Erreur lancement session RBI' });
  } finally {
    fail = false;
  }
});
