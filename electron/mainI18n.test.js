// Tests du module de traduction du processus principal (electron/mainI18n.js, MAIN-26) —
// exécuter avec : node --test electron/mainI18n.test.js
// Couverture des 12 langues, mêmes variables {{…}} que l'anglais, français strictement identique aux textes
// d'origine (aucun changement pour les utilisateurs francophones), normalisation et repli anglais.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const i18n = require('./mainI18n');

const LANGS = ['ar', 'de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'pt', 'ru', 'tr', 'zh'];
const vars = (s) => (s.match(/\{\{\w+\}\}/g) || []).sort();

test.afterEach(() => { i18n.resetUiLanguage(); i18n.setDefaultLanguageProvider(null); });

test('12 langues prises en charge, identiques à celles de l\'interface', () => {
  assert.deepEqual([...i18n.SUPPORTED_LANGS].sort(), LANGS);
});

test('chaque texte existe dans les 12 langues, non vide, avec les mêmes variables que l\'anglais', () => {
  for (const [key, entry] of Object.entries(i18n.MESSAGES)) {
    assert.deepEqual(Object.keys(entry).sort(), LANGS, `${key} : langues manquantes ou en trop`);
    for (const lang of LANGS) {
      assert.equal(typeof entry[lang], 'string', `${key}.${lang}`);
      assert.ok(entry[lang].trim().length > 0, `${key}.${lang} vide`);
      assert.deepEqual(vars(entry[lang]), vars(entry.en), `${key}.${lang} : variables différentes de l'anglais`);
    }
  }
});

test('textes réellement traduits : aucune langue autre que fr ne reprend le texte français des boîtes de dialogue', () => {
  for (const key of ['pairing.title', 'pairing.message', 'pairing.detail', 'hostKey.title', 'hostKey.detail', 'cliAccess.title', 'cliAccess.message', 'cliHostKey.message', 'button.allow', 'button.deny', 'button.rememberContinue']) {
    for (const lang of LANGS.filter(l => l !== 'fr')) {
      assert.notEqual(i18n.MESSAGES[key][lang], i18n.MESSAGES[key].fr, `${key}.${lang} identique au français`);
    }
  }
});

test('français strictement identique aux textes d\'origine (avant traduction)', () => {
  const fr = (k, v) => i18n.tm(k, v, 'fr');
  const extId = 'abcdefghijklmnopabcdefghijklmnop';
  assert.equal(fr('button.allow'), 'Autoriser');
  assert.equal(fr('button.deny'), 'Refuser');
  assert.equal(fr('button.rememberContinue'), 'Mémoriser et continuer');
  assert.equal(fr('pairing.title'), 'Appairage extension Chrome');
  assert.equal(fr('pairing.message'), 'Une extension Chrome demande l\'accès à vos identifiants.');
  assert.equal(fr('pairing.detail', { extId }), 'Identifiant de l\'extension :\n' + extId +
    '\n\nVérifiez qu\'il correspond à l\'extension RDVAULT installée (chrome://extensions).' +
    '\nN\'autorisez que si vous venez d\'installer ou d\'ouvrir l\'extension.');
  assert.equal(fr('hostKey.title'), 'Clé d\'hôte SSH inconnue');
  assert.equal(fr('hostKey.message', { host: 'h', port: 22 }), 'Clé d\'hôte SSH inconnue pour h:22');
  assert.equal(fr('hostKey.detail', { fingerprint: 'SHA256:x' }), 'Empreinte de la clé d\'hôte :\nSHA256:x' +
    '\n\nComparez-la avec celle du serveur (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub).' +
    '\nSi vous la mémorisez, toute connexion ultérieure avec une clé différente sera refusée.');
  assert.equal(fr('cliAccess.title'), 'Accès secret — CLI mvault');
  assert.equal(fr('cliAccess.message'), 'Un processus CLI demande l\'accès à un secret Vault.');
  assert.equal(fr('cliAccess.detail', { path: 'kv/a' }), 'Chemin : kv/a\n\nAutoriser l\'accès ?');
  assert.equal(fr('cliAccess.burst', { path: 'kv/a', count: 16, seconds: 3 }), 'kv/a [burst: 16 accès en 3s]');
  assert.equal(fr('cliHostKey.title'), 'Clé d\'hôte SSH inconnue — CLI mvault');
  assert.equal(fr('cliHostKey.message'), 'Première connexion SSH à cet hôte : sa clé n\'est pas encore mémorisée.');
  assert.equal(fr('cliHostKey.detail', { host: 'h', port: 22, fingerprint: 'SHA256:x' }), 'Hôte : h:22\nEmpreinte : SHA256:x\n\nMémoriser cette clé et continuer ?');
  assert.equal(fr('load.failed'), 'Chargement échoué');
  assert.equal(fr('load.failedDev'), 'Chargement échoué (dev)');
  assert.equal(fr('error.invalidHost'), 'Nom d\'hôte invalide');
  assert.equal(fr('error.invalidUsername'), 'Nom d\'utilisateur invalide');
  assert.equal(fr('error.invalidPort'), 'Port invalide (1-65535)');
  assert.equal(fr('error.puttyNotFound'), 'PuTTY non trouvé. Veuillez installer PuTTY.');
  assert.equal(fr('error.sshOpen'), 'Erreur ouverture connexion SSH');
  assert.equal(fr('error.urlSchemeNotAllowed'), 'Protocole URL non autorisé');
  assert.equal(fr('error.linkOpen'), 'Erreur ouverture lien');
  assert.equal(fr('error.rdpDomainInvalid'), 'Domaine RDP invalide');
  assert.equal(fr('error.rdpOpen'), 'Erreur ouverture connexion RDP');
  assert.equal(fr('error.sftpClientMissing'), 'FileZilla ou WinSCP n\'est pas installé sur ce système');
  assert.equal(fr('error.sftpOpen'), 'Erreur ouverture connexion SFTP');
  assert.equal(fr('error.browserUnknown'), 'Navigateur non reconnu');
  assert.equal(fr('error.invalidUrl'), 'URL invalide');
  assert.equal(fr('error.urlOpen'), 'Erreur ouverture URL');
  assert.equal(fr('error.hostKeyPromptAborted'), 'Connexion SSH interrompue pendant la vérification de la clé d\'hôte (aucune clé mémorisée) : relancez la lecture.');
});

test('clé d\'hôte SSH (sshBroker), sessions RBI (secureSession), port de synchronisation : français identique aux textes d\'origine', () => {
  const fr = (k, v) => i18n.tm(k, v, 'fr');
  const w = 'h:22', e = 'SHA256:a', o = 'SHA256:b';
  assert.equal(fr('sshHostKey.changed', { where: w, expected: e, observed: o }), `La clé d'hôte SSH de ${w} A CHANGÉ : attendue ${e}, observée ${o} (possible attaque de l'homme du milieu)`);
  assert.equal(fr('sshHostKey.changedPinned', { where: w, expected: e, observed: o }), `La clé d'hôte SSH de ${w} A CHANGÉ : attendue ${e}, observée ${o} (possible attaque de l'homme du milieu)` +
    ' ; l\'empreinte épinglée ne remplace pas la clé mémorisée : supprimez l\'entrée de known_hosts si le changement est légitime');
  assert.equal(fr('sshHostKey.mismatch', { where: w, expected: e, observed: o }), `Empreinte de clé d'hôte SSH inattendue pour ${w} : attendue ${e}, observée ${o}`);
  assert.equal(fr('sshHostKey.rejected', { where: w, reason: 'boum' }), `Clé d'hôte SSH de ${w} refusée (boum)`);
  assert.equal(fr('sshHostKey.rejectedByUser', { where: w, observed: o }), `Clé d'hôte SSH de ${w} refusée par l'utilisateur (${o})`);
  assert.equal(fr('sshHostKey.unknown', { where: w, observed: o }), `Clé d'hôte SSH inconnue pour ${w} (${o}) : aucune empreinte épinglée ni mémorisée`);
  assert.equal(fr('sshHostKey.changedRekey', { where: w, expected: e, observed: o }), `La clé d'hôte SSH de ${w} A CHANGÉ EN COURS de session (renouvellement des clés) : attendue ${e}, ` +
    `observée ${o} ; connexion interrompue, known_hosts n'a pas été modifié`);
  assert.equal(fr('sshHostKey.readError', { where: w, reason: 'x' }), `Impossible de lire la mémoire des clés d'hôte SSH pour ${w} : x`);
  assert.equal(fr('sshHostKey.writeError', { where: w, reason: 'x' }), `Impossible de mémoriser la clé d'hôte SSH de ${w} : x`);
  assert.equal(fr('rbi.maxSessions', { max: 5 }), 'Nombre maximum de sessions RBI atteint (5)');
  assert.equal(fr('rbi.downloadPolicy'), 'Impossible d\'appliquer la politique de téléchargement (CDP indisponible)');
  assert.equal(fr('rbi.foreignOrigin'), 'Page de connexion hors du domaine de l\'entrée');
  assert.equal(fr('rbi.jsNotDisabled'), 'Saisie refusée : JavaScript de la frame de connexion non désactivable');
  assert.equal(fr('rbi.formNotFound'), 'Formulaire de connexion introuvable');
  assert.equal(fr('rbi.fieldsNotFound'), 'Champs de connexion introuvables sur la page');
  assert.equal(fr('rbi.loginNotConfirmed'), 'Connexion non confirmée (délai dépassé)');
  assert.equal(fr('rbi.loginFailed'), 'Connexion échouée sur la page');
  assert.equal(fr('rbi.globalTimeout', { seconds: 90 }), 'Délai dépassé (90s) - la page ne répond pas');
  assert.equal(fr('rbi.loginError'), 'Erreur pendant la connexion');
  assert.equal(fr('rbi.networkRestriction'), 'Impossible d\'activer la restriction réseau');
  assert.equal(fr('rbi.launchError'), 'Erreur lancement session RBI');
  assert.equal(fr('rbi.chromiumUnavailable'), 'Chromium non disponible');
  for (const key of Object.keys(i18n.MESSAGES).filter((k) => /^(sshHostKey|rbi|syncPort)\./.test(k))) {
    for (const lang of LANGS.filter(l => l !== 'fr')) {
      assert.notEqual(i18n.MESSAGES[key][lang], i18n.MESSAGES[key].fr, `${key}.${lang} identique au français`);
    }
  }
});

test('sshBroker : erreur de clé d\'hôte (HOST_KEY_*) dans la langue de l\'interface, code inchangé', async () => {
  const { createHostVerifier } = require('./sshBroker');
  const pinned = 'SHA256:' + 'A'.repeat(43);
  const run = async () => {
    const hv = createHostVerifier({ host: 'srv', port: 2222, hostFingerprint: pinned });
    assert.equal(await new Promise((r) => hv.verifier(Buffer.from('autre-cle'), r)), false);
    return hv.error;
  };
  i18n.setUiLanguage('en');
  let err = await run();
  assert.equal(err.code, 'HOST_KEY_MISMATCH');
  assert.match(err.message, /^Unexpected SSH host key fingerprint for srv:2222: expected SHA256:A{43}, observed SHA256:/);
  i18n.setUiLanguage('de');
  err = await run();
  assert.match(err.message, /^Unerwarteter Fingerabdruck des SSH-Host-Keys für srv:2222/);
  i18n.setUiLanguage('fr');
  err = await run();
  assert.match(err.message, /^Empreinte de clé d'hôte SSH inattendue pour srv:2222 : attendue SHA256:A{43}, observée SHA256:/);
});

test('priorité : langue de l\'interface > LANG de config.cfg > anglais', () => {
  i18n.setDefaultLanguageProvider(() => 'fr');
  assert.equal(i18n.getLanguage(), 'fr');
  assert.equal(i18n.tm('button.deny'), 'Refuser');
  assert.equal(i18n.setUiLanguage('ko'), true);
  assert.equal(i18n.tm('button.deny'), '거부');
  i18n.resetUiLanguage();
  i18n.setDefaultLanguageProvider(() => undefined);
  assert.equal(i18n.getLanguage(), 'en');
  i18n.setDefaultLanguageProvider(() => { throw new Error('config illisible'); });
  assert.equal(i18n.getLanguage(), 'en', 'configuration illisible : anglais');
});

test('normalisation et liste blanche', () => {
  assert.equal(i18n.normalizeLang('FR'), 'fr');
  assert.equal(i18n.normalizeLang(' pt-BR '), 'pt');
  assert.equal(i18n.normalizeLang('zh_CN'), 'zh');
  for (const bad of ['', 'xx', 'english', null, undefined, 42, {}, [], 'a'.repeat(17), '__proto__', 'constructor']) {
    assert.equal(i18n.normalizeLang(bad), null, JSON.stringify(bad));
    assert.equal(i18n.setUiLanguage(bad), false);
  }
});

test('tm : clé inconnue renvoyée telle quelle ; variable absente laissée visible ; pas de motif $ interprété', () => {
  assert.equal(i18n.tm('nope.missing', {}, 'en'), 'nope.missing');
  assert.equal(i18n.tm('hostKey.message', { host: 'h' }, 'en'), 'Unknown SSH host key for h:{{port}}');
  assert.equal(i18n.tm('cliAccess.detail', { path: "$& $' $1" }, 'en'), "Path: $& $' $1\n\nAllow access?");
  assert.equal(i18n.tm('cliAccess.detail', { path: 'x', toString: 'y' }, 'en'), 'Path: x\n\nAllow access?');
});
