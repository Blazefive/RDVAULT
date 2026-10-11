// Motifs d'échec des sessions RBI dans la langue de l'interface (suite MAIN-26) — node --test electron/secureSession.i18n.test.js
// Les erreurs renvoyées au renderer (result.error) sont affichées telles quelles dans un toast : elles restaient en
// français quelle que soit la langue. Aucun navigateur lancé : puppeteer.launch est remplacé par un double qui
// échoue (chemin « Erreur lancement session RBI », vérification de disponibilité). TEMP jetable (profil éphémère).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const TMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-rbi-i18n-'));
process.env.TEMP = TMP_ROOT;
process.env.TMP = TMP_ROOT;
process.env.RDVAULT_LOG_LEVEL = process.env.RDVAULT_LOG_LEVEL || 'silent';

const puppeteer = require('puppeteer-core');
let launches = 0;
puppeteer.launch = async () => { launches++; throw new Error('lancement simulé impossible'); };

const i18n = require('./mainI18n');
const secureSession = require('./secureSession');

test.after(() => {
  i18n.resetUiLanguage();
  try { fs.rmSync(TMP_ROOT, { recursive: true, force: true }); } catch { /* ignore */ }
});

const launch = () => secureSession.launchSecureSession({ url: 'https://login.example.com/', username: 'u', password: 'p', policies: {} });

test('échec de lancement : motif dans la langue de l\'interface (fr identique à l\'existant)', async () => {
  i18n.setUiLanguage('fr');
  assert.deepEqual(await launch(), { success: false, error: 'Erreur lancement session RBI' });
  i18n.setUiLanguage('de');
  assert.deepEqual(await launch(), { success: false, error: 'Fehler beim Starten der RBI-Sitzung' });
  i18n.setUiLanguage('ja');
  assert.deepEqual(await launch(), { success: false, error: 'RBI セッションの起動エラー' });
  assert.ok(launches >= 3);
  assert.deepEqual(fs.readdirSync(TMP_ROOT).filter((e) => e.startsWith('rbi-')), [], 'profils éphémères supprimés');
});

test('Chromium indisponible : motif traduit, y compris depuis le cache (changement de langue)', async () => {
  i18n.setUiLanguage('en');
  assert.deepEqual(await secureSession.checkAvailability(), { available: false, error: 'Chromium not available' });
  i18n.setUiLanguage('fr');
  assert.deepEqual(await secureSession.checkAvailability(), { available: false, error: 'Chromium non disponible' });
});

test('chargement du module : aucun nettoyage de profils (réservé à l\'instance qui détient le verrou, STARTUP-23)', () => {
  const orphan = path.join(TMP_ROOT, 'rbi-0123456789abcdef');
  fs.mkdirSync(orphan);
  // Nouveau chargement du module (cache vidé) : le profil n'est PAS supprimé
  delete require.cache[require.resolve('./secureSession')];
  const fresh = require('./secureSession');
  assert.equal(fs.existsSync(orphan), true, 'le simple chargement du module ne supprime rien');
  assert.ok(fresh.cleanupStaleProfiles() >= 1, 'nettoyage explicite au démarrage');
  assert.equal(fs.existsSync(orphan), false);
});
