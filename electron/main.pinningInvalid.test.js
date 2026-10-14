// Épinglage TLS inutilisable signalé au démarrage (PINNING_INVALID) — node --test electron/main.pinningInvalid.test.js
// main.js RÉEL sous Node (electron simulé, démarrage complet) avec une configuration simulée (configLoader remplacé
// AVANT le chargement de main.js ; config.cfg du projet jamais modifié). Aucun port ouvert (http.createServer
// remplacé), serveur CLI et coffre local remplacés par des doubles.
// Avant : TRUSTED_CERT_FINGERPRINTS renseigné sans aucune empreinte valide → épinglage maintenu (fail-closed),
// toutes les connexions Vault refusées, mais seulement une ligne de journal : aucune explication visible.
// Attendu : boîte d'avertissement INDÉPENDANTE (sans fenêtre parente), non attendue, traduite (LANG), une seule fois.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { EventEmitter } = require('events');
const { loadMainWithMockElectron } = require('../test/helpers/main-electron-mock');

const cfg = {
  APP_MODE: 'local',
  VAULT_URL: 'http://127.0.0.1:0',
  TRUSTED_DOMAINS: 'localhost,127.0.0.1',
  TRUSTED_CERT_FINGERPRINTS: '0000',
  RBI_PROXY_URL: '',
  LANG: 'fr',
  PINNING_INVALID: true,
};
const dialogs = [];
const origCreateServer = http.createServer;
let localVaultStarted = false;

const ctx = loadMainWithMockElectron({
  ready: true,
  activate: false,
  // Boîte jamais fermée : si le démarrage l'attendait, il resterait bloqué (fenêtre, serveurs)
  dialog: { showMessageBox: (...args) => { dialogs.push(args); return new Promise(() => {}); } },
  beforeRequire: () => {
    const cl = require('./configLoader');
    cl.getConfig = () => ({ ...cfg });
    cl.getAppMode = () => cfg.APP_MODE;
    cl.getTrustedDomains = () => cfg.TRUSTED_DOMAINS.split(',');
    cl.getTrustedCertFingerprints = () => ['0'.repeat(64)];
    cl.getRbiProxyUrl = () => cfg.RBI_PROXY_URL;
    // Langue des textes du processus principal : LANG de la configuration simulée
    require('./mainI18n').setDefaultLanguageProvider(() => cfg.LANG);
    http.createServer = () => {
      const s = new EventEmitter();
      s.listen = () => s; s.close = () => {};
      return s;
    };
    const cli = require('./cliServer');
    cli.startCLIServer = async () => ({ port: 1, token: 't' });
    const lv = require('./localVault/localVaultServer');
    lv.start = async () => { localVaultStarted = true; return 1; }; lv.stop = () => {}; lv.getPort = () => 1;
    const rbi = require('./secureSession');
    rbi.cleanupStaleProfiles = () => 0;
  },
});

const flush = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };

test.after(async () => {
  for (const fn of ctx.app.listeners('will-quit')) fn({ preventDefault() {} });
  await flush();
  http.createServer = origCreateServer;
  require('./mainI18n').setDefaultLanguageProvider(null);
  ctx.cleanup();
});

test('PINNING_INVALID : avertissement au démarrage, sans bloquer le mode local', async () => {
  await flush();
  assert.equal(localVaultStarted, true, 'coffre local démarré');
  assert.ok(ctx.win, 'fenêtre principale créée malgré la boîte jamais fermée');
  const shown = dialogs.filter(([opts]) => opts && opts.title === 'Épinglage TLS invalide');
  assert.equal(shown.length, 1, 'une seule boîte d\'avertissement');
  const [opts] = shown[0];
  assert.equal(shown[0].length, 1, 'boîte indépendante : aucune fenêtre parente (pas modale)');
  assert.equal(opts.type, 'warning');
  assert.equal(opts.message, 'Les connexions au serveur Vault seront refusées');
  assert.match(opts.detail, /TRUSTED_CERT_FINGERPRINTS/);
  assert.match(opts.detail, /config\.cfg/);
  assert.match(opts.detail, /SHA-256/);
  assert.match(opts.detail, /redémarrez RDVAULT/);
});
