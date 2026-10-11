// Outils communs des tests de bout en bout qui pilotent l'application RDVAULT réelle (run.js, features.js,
// passkey.js, app-ui.js, real-sites.js, diag-fields.js) : lanceur de l'application, garde du port de
// synchronisation de l'extension, connexion par l'interface, nettoyage du dossier temporaire.
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES

const path = require('path');
const fs = require('fs');
const net = require('net');
const { execFileSync } = require('child_process');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Script de lancement de l'application : test/e2e/app-wrapper.js, ou E2E_APP_WRAPPER (facultatif) pour un
 * autre script, par exemple un renderer construit ailleurs que dans build/.
 */
function appWrapperPath() {
  return process.env.E2E_APP_WRAPPER || path.join(__dirname, 'app-wrapper.js');
}

// ─── Port de synchronisation de l'extension (SITES-22) ───
// L'extension de test est chargée depuis le dossier du projet : même identifiant qu'une installation manuelle
// faite comme l'indique le README. Une instance RDVAULT déjà en écoute sur 127.0.0.1:45678 (instance réelle
// appairée, ou application d'un autre test) lui servirait donc SES identifiants, et un harnais sur de vrais
// sites les saisirait dans de vraies pages de connexion. L'application de test signale seulement le port pris
// (avertissement non bloquant) : le test doit donc refuser de démarrer, puis vérifier que le port est bien
// tenu par l'application qu'il a lancée.

const SYNC_PORT = 45678;

/**
 * Vrai si aucune connexion n'aboutit sur host:port (rien n'y écoute).
 * @param {number} port
 * @param {string} [host]
 * @returns {Promise<boolean>}
 */
function portFree(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const c = net.connect(port, host);
    c.once('connect', () => { c.destroy(); resolve(false); });
    c.once('error', () => { c.destroy(); resolve(true); });
  });
}

/**
 * Attend que le port de synchronisation soit libre AVANT de lancer l'application de test (3 nouvelles
 * tentatives espacées de 60 s par défaut), sinon lève une erreur : le test ne doit pas démarrer.
 * @param {{ port?: number, tries?: number, delayMs?: number, log?: (msg: string) => void }} [options]
 */
async function waitSyncPortFree({ port = SYNC_PORT, tries = 3, delayMs = 60000, log = console.log } = {}) {
  for (let i = 0; i < tries && !(await portFree(port)); i++) {
    log(`  [attente] port ${port} occupé (autre instance RDVAULT ?), nouvel essai dans ${Math.round(delayMs / 1000)} s`);
    await sleep(delayMs);
  }
  if (!(await portFree(port))) {
    throw new Error(`port ${port} occupé par une autre instance RDVAULT : test refusé (l'extension de test recevrait ses identifiants)`);
  }
}

/**
 * Processus en écoute TCP sur `port`, toutes adresses (IPv4 et IPv6).
 * Windows : netstat -ano (une socket en écoute a une adresse distante de port 0 ; l'état n'est pas lu car il
 * peut être traduit). Ailleurs : lsof. Lève une erreur si la liste ne peut pas être obtenue (le test s'arrête).
 * @param {number} port
 * @returns {number[]} PID distincts
 */
function listeningPids(port) {
  const pids = new Set();
  if (process.platform === 'win32') {
    const out = execFileSync('netstat', ['-ano'], { encoding: 'latin1', windowsHide: true, timeout: 20000 });
    for (const line of out.split(/\r?\n/)) {
      const cols = line.trim().split(/\s+/);
      if (cols[0] !== 'TCP' || cols.length < 5) continue;
      if (!cols[1].endsWith(':' + port) || !/:0$/.test(cols[2])) continue;
      const pid = Number(cols[cols.length - 1]);
      if (Number.isInteger(pid) && pid > 0) pids.add(pid);
    }
  } else {
    let out = '';
    try {
      out = execFileSync('lsof', ['-nP', '-iTCP:' + port, '-sTCP:LISTEN', '-t'], { encoding: 'utf8', timeout: 20000 });
    } catch (e) {
      // lsof sort avec le code 1 quand rien n'écoute ; toute autre erreur (lsof absent...) est remontée
      if (e && e.status === 1) return [];
      throw e;
    }
    for (const s of out.split(/\s+/)) if (/^\d+$/.test(s)) pids.add(Number(s));
  }
  return Array.from(pids);
}

/**
 * Vérifie, une fois l'application de test démarrée, que le port de synchronisation est tenu par CETTE
 * application (processus principal Electron lancé par le test) et par aucun autre processus.
 * @param {number} pid - PID du processus Electron lancé par le test
 * @param {{ port?: number }} [options]
 */
function assertSyncPortOwner(pid, { port = SYNC_PORT } = {}) {
  const pids = listeningPids(port);
  if (!pids.includes(pid)) {
    throw new Error(`port ${port} non tenu par l'application de test (PID ${pid}) mais par : ${pids.join(', ') || 'aucun processus'} — test interrompu`);
  }
  const others = pids.filter((p) => p !== pid);
  if (others.length) throw new Error(`port ${port} aussi tenu par le(s) processus ${others.join(', ')} — test interrompu`);
}

// ─── Connexion par l'interface ───
// AUTH-14 : au chargement, l'écran de connexion interroge GET /v1/sys/init. S'il a été affiché AVANT la
// création du compte par l'API du coffre local, il est resté en mode « création du compte administrateur »
// (champ de confirmation). La page est alors rechargée : le nouvel écran voit le compte et revient au
// formulaire de connexion habituel.

// Champs propres au mode création (mot de passe et confirmation en autocomplete="new-password")
const SETUP_FIELD = 'input.form-input-vertical[autocomplete="new-password"]';

/** Vrai si l'écran de connexion est en mode création du compte administrateur (AUTH-14) */
async function isSetupForm(appPage) {
  return (await appPage.$$(SETUP_FIELD)).length > 0;
}

/**
 * Affiche le formulaire de connexion habituel (recharge la page si l'écran de création est resté affiché).
 * @param {import('puppeteer-core').Page} appPage
 * @param {{ timeout?: number }} [options]
 */
async function ensureLoginForm(appPage, { timeout = 30000 } = {}) {
  await appPage.waitForSelector('.form-input-vertical', { timeout });
  // Laisse la détection du premier démarrage aboutir (serveur local : réponse immédiate)
  await sleep(500);
  if (!(await isSetupForm(appPage))) return;
  await appPage.reload({ waitUntil: 'load' });
  await appPage.waitForSelector('.form-input-vertical', { timeout });
  await sleep(1000);
  if (await isSetupForm(appPage)) throw new Error('écran de création du compte encore affiché alors que le compte existe (GET /v1/sys/init)');
}

/**
 * Connexion par le formulaire habituel avec un compte existant, puis attente de la vue principale (.toolbar).
 * @param {import('puppeteer-core').Page} appPage
 * @param {string} user
 * @param {string} pass
 * @param {{ timeout?: number }} [options]
 */
async function loginInApp(appPage, user, pass, { timeout = 30000 } = {}) {
  await ensureLoginForm(appPage, { timeout });
  const inputs = await appPage.$$('.form-input-vertical');
  await inputs[0].click({ clickCount: 3 }); await inputs[0].type(user);
  await inputs[1].click({ clickCount: 3 }); await inputs[1].type(pass);
  await appPage.click('.btn-login');
  await appPage.waitForSelector('.toolbar', { timeout });
}

// ─── Nettoyage ───

/**
 * Supprime le dossier temporaire d'un test (profil Chrome, userData de l'application, journaux) une fois
 * l'application arrêtée ; ré-essais le temps que Windows libère les fichiers des processus terminés.
 * @param {string} dir
 * @param {import('child_process').ChildProcess|null} [proc] - processus de l'application, attendu (10 s max)
 * @returns {Promise<boolean>} vrai si le dossier a été supprimé
 */
async function removeTempDir(dir, proc) {
  try {
    if (proc && proc.exitCode === null && proc.signalCode === null) {
      await Promise.race([new Promise((r) => proc.once('exit', r)), sleep(10000)]);
    }
  } catch { /* ignore */ }
  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 500 });
    return true;
  } catch (e) {
    console.log('  [nettoyage] ' + dir + ' non supprimé : ' + (e && e.message));
    return false;
  }
}

module.exports = {
  appWrapperPath, loginInApp, ensureLoginForm, isSetupForm, removeTempDir, SETUP_FIELD,
  SYNC_PORT, portFree, waitSyncPortFree, listeningPids, assertSyncPortOwner,
};
