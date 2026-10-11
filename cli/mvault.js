#!/usr/bin/env node
// ========================================
// MVAULT CLI — Client ligne de commande pour RDVault
// ========================================
// Récupère des secrets depuis Vault via l'application Electron RDVault.
// L'Electron doit être lancé et l'utilisateur connecté.
//
// Usage :
//   mvault get <engine>/<chemin>              → affiche les données du secret (JSON, valeurs sensibles masquées)
//   mvault get <engine>/<chemin> --reveal     → affiche les données du secret sans masquage
//   mvault get <engine>/<chemin> --key <clé>  → affiche uniquement la valeur d'une clé (texte brut)
//   mvault get <engine>/<chemin> -k password  → raccourci pour --key
//   mvault status                             → vérifie si l'Electron est actif
//   mvault rules                              → affiche les règles d'auto-approbation (lecture seule)
//
// Exemple avec sshpass (mot de passe passé par l'environnement, jamais en argument visible dans `ps`) :
//   SSHPASS="$(mvault get secrets/prod -k password)" sshpass -e ssh user@serveur
//
// Variables d'environnement :
//   MVAULT_SESSION_FILE — chemin personnalisé vers le fichier de session
//                         (par défaut : %APPDATA%\RDVAULT\cli\session.json sur Windows,
//                          ~/.config/RDVAULT/cli/session.json sur Linux,
//                          ~/Library/Application Support/RDVAULT/cli/session.json sur macOS)

'use strict';

const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

// ========================================
// LOCALISATION DU FICHIER DE SESSION
// ========================================

/** Nom du dossier userData Electron (productName) et ancien nom, conservé pour compatibilité */
const APP_DIR_NAME = 'RDVAULT';
const LEGACY_APP_DIR_NAME = 'rdvault';

/**
 * Dossier de configuration utilisateur selon la plateforme
 * (équivalent du parent de app.getPath('userData') côté Electron)
 */
function getUserConfigRoot() {
  const platform = process.platform;
  if (platform === 'win32') {
    // Electron app.getPath('userData') utilise Roaming sur Windows
    return process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  }
  if (platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support');
  }
  // Linux : XDG_CONFIG_HOME ou ~/.config
  return process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
}

/**
 * Chemins candidats du fichier de session, par ordre de priorité :
 * variable d'environnement, nouveau chemin (RDVAULT), ancien chemin (rdvault)
 */
function getSessionFileCandidates() {
  if (process.env.MVAULT_SESSION_FILE) {
    return [process.env.MVAULT_SESSION_FILE];
  }

  const root = getUserConfigRoot();
  const candidates = [path.join(root, APP_DIR_NAME, 'cli', 'session.json')];
  const legacy = path.join(root, LEGACY_APP_DIR_NAME, 'cli', 'session.json');
  if (legacy !== candidates[0]) {
    candidates.push(legacy);
  }
  return candidates;
}

/**
 * Lit le fichier de session écrit par l'Electron
 * (nouveau chemin en priorité, puis ancien chemin pour compatibilité)
 */
function readSession() {
  const candidates = getSessionFileCandidates();
  let lastError = null;

  for (const sessionFile of candidates) {
    try {
      const content = fs.readFileSync(sessionFile, 'utf-8');
      const session = JSON.parse(content);
      if (!session.port || !session.token) {
        throw new Error('Fichier de session incomplet');
      }
      return session;
    } catch (err) {
      if (err.code === 'ENOENT') {
        continue;
      }
      lastError = err;
      break;
    }
  }

  if (lastError) {
    console.error(`Erreur lecture session : ${lastError.message}`);
  } else {
    console.error('Erreur : RDVault ne semble pas lancé (fichier de session introuvable).');
    console.error(`Chemin attendu : ${candidates[0]}`);
  }
  process.exit(1);
}

// ========================================
// MASQUAGE DES VALEURS SENSIBLES
// ========================================

/** Clés dont la valeur est masquée dans la sortie JSON de `mvault get` (sans --reveal) */
const SENSITIVE_KEYS = new Set(['password', 'pass', 'secret', 'token', 'key', 'private_key']);
const MASK = '********';

/**
 * Retourne une copie des données avec les valeurs sensibles remplacées par ********
 * (comparaison de clé insensible à la casse, appliquée récursivement)
 */
function maskSensitiveData(data) {
  if (Array.isArray(data)) {
    return data.map(maskSensitiveData);
  }
  if (!data || typeof data !== 'object') {
    return data;
  }
  const masked = {};
  for (const [k, v] of Object.entries(data)) {
    if (SENSITIVE_KEYS.has(String(k).toLowerCase())) {
      masked[k] = MASK;
    } else {
      masked[k] = maskSensitiveData(v);
    }
  }
  return masked;
}

// ========================================
// CLIENT HTTP
// ========================================

/** Chemin du fichier known_hosts.json de RDVAULT (même dossier userData que la session CLI) */
function getKnownHostsFile() {
  if (process.env.MVAULT_SESSION_FILE) {
    return path.join(path.dirname(path.dirname(process.env.MVAULT_SESSION_FILE)), 'known_hosts.json');
  }
  return path.join(getUserConfigRoot(), APP_DIR_NAME, 'known_hosts.json');
}

/**
 * Effectue une requête HTTP vers le serveur CLI local de l'Electron
 * @param {number} [timeoutMs=60000] - délai global (0 = illimité) ; inclut le temps des popups
 */
function request(method, urlPath, session, body = null, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: '127.0.0.1',
      port: session.port,
      path: urlPath,
      method,
      headers: {
        'Authorization': `Bearer ${session.token}`,
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(options, (res) => {
      // Morceaux accumulés en Buffers et décodés UNE fois : un caractère UTF-8 coupé entre deux
      // segments TCP n'est jamais corrompu (U+FFFD) — même règle que parseBody côté serveur.
      const chunks = [];
      res.on('data', chunk => { chunks.push(chunk); });
      res.on('end', () => {
        const data = Buffer.concat(chunks).toString('utf8');
        try {
          const json = JSON.parse(data);
          resolve({ status: res.statusCode, body: json });
        } catch {
          resolve({ status: res.statusCode, body: { error: data } });
        }
      });
    });

    req.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        console.error('Erreur : impossible de joindre RDVault. L\'application est-elle lancée ?');
      } else {
        console.error(`Erreur réseau : ${err.message}`);
      }
      process.exit(1);
    });

    // Timeout (60 s par défaut, inclut le temps de la popup de confirmation)
    if (timeoutMs > 0) {
      req.setTimeout(timeoutMs, () => {
        req.destroy();
        console.error('Erreur : timeout — la demande de confirmation a peut-être expiré.');
        process.exit(1);
      });
    }

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * POST « silencieux » : n'interrompt jamais la session (contrairement à request()).
 * Renvoie une Promise JAMAIS rejetée, résolue à la réponse { status, body } (body : JSON ou null) ou, sur
 * erreur réseau ou délai `timeoutMs` dépassé (0 = aucun), à { status: 0, body: null } : à attendre avant
 * process.exit(), sinon la requête n'est jamais émise.
 */
function postQuiet(urlPath, session, body, timeoutMs = 0) {
  return new Promise((resolve) => {
    const failed = () => resolve({ status: 0, body: null });
    try {
      const data = JSON.stringify(body);
      const r = http.request({
        hostname: '127.0.0.1', port: session.port, path: urlPath, method: 'POST',
        headers: { 'Authorization': `Bearer ${session.token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => { chunks.push(c); });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* corps non JSON */ }
          resolve({ status: res.statusCode, body: json });
        });
        res.on('error', failed);
      });
      r.on('error', failed);
      if (timeoutMs > 0) r.setTimeout(timeoutMs, () => r.destroy());
      r.write(data); r.end();
    } catch { failed(); }
  });
}

/** Attend la fin d'un postQuiet au plus `ms` millisecondes (ex. /ssh/close avant de quitter) */
function awaitQuiet(promise, ms = 1500) {
  return Promise.race([promise, new Promise((resolve) => { const t = setTimeout(resolve, ms); if (t.unref) t.unref(); })]);
}

/**
 * Texte venu du serveur (message d'erreur pouvant provenir d'un pair SSH ou de PowerShell) rendu
 * sûr pour le terminal : caractères de contrôle (retours ligne, séquences ANSI…) neutralisés.
 */
function clean(value) {
  // eslint-disable-next-line no-control-regex -- volontaire : neutraliser les séquences de contrôle avant affichage terminal
  return String(value == null ? '' : value).replace(/[\x00-\x1F\x7F-\x9F]/g, '?');
}

/** Numéros des signaux de la RFC 4254 (convention POSIX) pour le code de sortie 128 + n */
const REMOTE_SIGNALS = { HUP: 1, INT: 2, QUIT: 3, ILL: 4, ABRT: 6, FPE: 8, KILL: 9, USR1: 10, SEGV: 11, USR2: 12, PIPE: 13, ALRM: 14, TERM: 15 };

/**
 * Code de sortie de mvault pour une commande exécutée à distance : son statut ; 128 + n° du signal
 * qui l'a tuée (convention des shells) ; 1 si indéterminé (flux fermé sans statut). Jamais 0 par défaut.
 */
function remoteExitCode(code, signal) {
  if (typeof code === 'number') return code;
  const name = String(signal || '').toUpperCase().replace(/^SIG/, '');
  return Object.prototype.hasOwnProperty.call(REMOTE_SIGNALS, name) ? 128 + REMOTE_SIGNALS[name] : 1;
}

/** Libellé lisible du statut de clé d'hôte renvoyé par le serveur */
function hostKeyStatusLabel(status) {
  if (status === 'new') return 'nouvelle, mémorisée';
  if (status === 'known') return 'connue';
  if (status === 'pinned') return 'épinglée';
  return 'statut inconnu';
}

/**
 * Avertissement proéminent (façon OpenSSH) quand la clé d'hôte ne correspond pas à l'attendu.
 * `pinned` : une empreinte a été passée avec --hostkey.
 */
function printHostKeyWarning(code, host, port, body, pinned) {
  const where = `${host}:${port}`;
  const bar = '@'.repeat(71);
  console.error(bar);
  console.error('@' + `    ATTENTION : LA CLÉ D'HÔTE A CHANGÉ (${where})`.padEnd(bar.length - 2) + '@');
  console.error(bar);
  console.error('QUELQU\'UN POURRAIT ÊTRE EN TRAIN D\'INTERCEPTER LA CONNEXION (attaque de l\'homme du milieu),');
  console.error('ou la clé SSH du serveur a simplement été régénérée.');
  console.error(`Empreinte attendue : ${clean(body.expected || '?')}`);
  console.error(`Empreinte observée : ${clean(body.observed || '?')}`);
  if (code === 'HOST_KEY_MISMATCH') {
    console.error('L\'empreinte observée ne correspond pas à celle passée avec --hostkey. Vérifiez-la auprès de');
    console.error('l\'administrateur du serveur avant de réessayer.');
  } else {
    if (pinned) {
      console.error('L\'empreinte passée avec --hostkey ne remplace pas la clé mémorisée dans RDVAULT pour cet hôte.');
    }
    console.error(`Si ce changement est légitime (serveur réinstallé, vérifié auprès de l'administrateur), supprimez`);
    console.error(`l'entrée « ${where} » du fichier :`);
    console.error(`  ${getKnownHostsFile()}`);
    console.error('puis relancez la commande.');
  }
  if (body.message) console.error(`Détail : ${clean(body.message)}`);
  console.error('Connexion refusée : le mot de passe n\'a PAS été envoyé.');
}

/**
 * Clé d'hôte changée lors d'un renouvellement des clés (re-KEX) EN COURS de session : la clé vérifiée
 * à la connexion reste celle mémorisée (known_hosts n'est pas modifié) — on ne suggère donc PAS de
 * supprimer l'entrée. La session était déjà authentifiée : la commande (mode 'exec') a pu s'exécuter en
 * partie ; un shell interactif (mode 'shell') est coupé après les commandes déjà saisies.
 */
function printRekeyHostKeyWarning(host, port, body, mode = 'exec') {
  console.error(`Erreur (${host}:${port}) : la clé d'hôte a changé EN COURS de session : connexion interrompue ; known_hosts n'a pas été modifié.`);
  console.error(`Empreinte vérifiée à la connexion        : ${clean(body.expected || '?')}`);
  console.error(`Empreinte présentée pendant la session   : ${clean(body.observed || '?')}`);
  console.error('Un serveur SSH ne change pas de clé d\'hôte au cours d\'une session : comportement anormal (serveur');
  console.error('défaillant ou compromis, interception). Signalez-le à l\'administrateur du serveur.');
  if (mode === 'shell') console.error('La session shell a été coupée : les commandes déjà saisies ont pu s\'exécuter.');
  else console.error('La commande a pu s\'exécuter partiellement : sa sortie n\'est pas affichée.');
  if (body.message) console.error(`Détail : ${clean(body.message)}`);
}

/** Durée lisible (« 4 h », « 30 min », « 1,5 s ») */
function formatDuration(ms) {
  const n = Number(ms) || 0;
  const [value, unit] = n >= 3600000 ? [n / 3600000, 'h'] : n >= 60000 ? [n / 60000, 'min'] : [n / 1000, 's'];
  return `${String(+value.toFixed(1)).replace('.', ',')} ${unit}`;
}

/**
 * Raison de la fin d'une session shell, demandée à RDVAULT (POST /ssh/status) après la fermeture de la
 * socket. Tant que RDVAULT n'a pas encore enregistré la fermeture (open: true), la question est reposée
 * `retries` fois (150 ms d'intervalle). Jamais rejetée : { status: 0 } si RDVAULT est injoignable.
 */
async function fetchShellStatus(session, sock, retries) {
  for (let i = 0; ; i++) {
    const st = await postQuiet('/ssh/status', session, { sock }, 3000);
    if (i >= retries || st.status !== 200 || !st.body || st.body.open !== true) return st;
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
}

/**
 * Fin d'une session shell : affiche la cause et renvoie le code de sortie de mvault. 0 sans message pour
 * une fin normale (shell quitté, fermeture propre par le serveur distant) ; message + 1 pour une coupure
 * côté RDVAULT (clé d'hôte changée en cours de session, garde-fou de durée, fermeture demandée, erreur), si
 * RDVAULT ne répond plus (application fermée, déconnexion) ou si la socket n'a pas pu être utilisée.
 * Un RDVAULT antérieur à /ssh/status (404) garde l'ancien comportement (0 sauf erreur de socket).
 */
function reportShellEnd(st, host, port, { connected, connError, tty }) {
  const where = `${host}:${port}`;
  const end = st.status === 200 && st.body && st.body.open === false ? st.body : null;
  const code = end && end.code ? String(end.code) : null;
  const say = (...lines) => { if (tty) process.stderr.write('\n'); for (const l of lines) console.error(l); }; // sous la dernière ligne distante
  if (code === 'HOST_KEY_CHANGED_REKEY') { if (tty) process.stderr.write('\n'); printRekeyHostKeyWarning(host, port, end, 'shell'); return 1; }
  if (code === 'SESSION_MAX_DURATION') {
    say(`Session SSH (${where}) interrompue par RDVAULT : durée maximale d'une session shell atteinte (${formatDuration(end.maxDurationMs)}).`,
      'Relancez « mvault ssh » pour ouvrir une nouvelle session.');
    return 1;
  }
  if (code === 'CLOSED_BY_REQUEST') { say(`Session SSH (${where}) fermée par RDVAULT à la demande d'un autre client CLI (/ssh/close).`); return 1; }
  if (code) { say(`Session SSH (${where}) interrompue par RDVAULT (${clean(code)})${end.message ? ' : ' + clean(end.message) : ''}.`); return 1; }
  if (end) { // fin normale confirmée par RDVAULT
    if (connected) return 0;
    say(`Session SSH (${where}) terminée avant que mvault ne s'y connecte.`);
    return 1;
  }
  if (st.status === 0) { say(`Session SSH (${where}) interrompue : RDVAULT ne répond plus (application fermée, déconnexion ou session CLI révoquée).`); return 1; }
  if (!connected || connError) { say('Session SSH : ' + clean(connError ? connError.message : 'socket fermée avant la connexion')); return 1; }
  if (st.status === 404 || (st.status === 200 && st.body && st.body.open === true)) return 0; // fin non qualifiée
  say(`Session SSH (${where}) terminée sans confirmation de RDVAULT (HTTP ${st.status}) : elle a pu être coupée.`);
  return 1;
}

// ========================================
// COMMANDES
// ========================================

async function cmdGet(args) {
  const session = readSession();

  // Parser les arguments
  let secretFullPath = args[0];
  let key = null;
  let reveal = false;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--key' || args[i] === '-k') {
      key = args[i + 1];
      i++;
    } else if (args[i] === '--reveal') {
      reveal = true;
    }
  }

  if (!secretFullPath) {
    console.error('Usage : mvault get <engine>/<chemin> [--key <clé>] [--reveal]');
    console.error('Exemple : mvault get secret/mon-serveur --key password');
    process.exit(1);
  }

  // Récupérer la liste des engines pour trouver la bonne coupure engine/path
  // Car les engines peuvent contenir des "/" (ex: "users/rdekien/LAB-TEST")
  const enginesResp = await request('GET', '/engines', session);
  let engine = null;
  let secretPath = null;

  if (enginesResp.status === 200 && enginesResp.body.success) {
    // Trier par longueur décroissante pour matcher le plus long engine d'abord
    const engineNames = enginesResp.body.engines
      .map(e => e.name.replace(/\/+$/, '')) // retirer le trailing slash
      .sort((a, b) => b.length - a.length);

    for (const name of engineNames) {
      if (secretFullPath === name || secretFullPath.startsWith(name + '/')) {
        engine = name;
        secretPath = secretFullPath.substring(name.length + 1);
        break;
      }
    }
  }

  if (!engine) {
    // Fallback : couper sur le premier slash
    const slashIndex = secretFullPath.indexOf('/');
    if (slashIndex === -1) {
      console.error('Erreur : le chemin doit inclure l\'engine. Ex: secret/mon-serveur');
      console.error('Utilisez "mvault engines" pour voir les engines disponibles.');
      process.exit(1);
    }
    engine = secretFullPath.substring(0, slashIndex);
    secretPath = secretFullPath.substring(slashIndex + 1);
  }

  if (!secretPath) {
    console.error('Erreur : chemin du secret manquant après l\'engine.');
    console.error('Utilisez "mvault engines" pour voir les engines disponibles.');
    process.exit(1);
  }

  const body = { engine, path: secretPath };
  if (key) body.key = key;

  const resp = await request('POST', '/secret', session, body);

  if (resp.status === 200 && resp.body.success) {
    if (key && resp.body.value !== undefined) {
      // Mode --key : afficher la valeur brute (pour usage en $(...))
      process.stdout.write(String(resp.body.value));
    } else if (resp.body.data) {
      // Mode complet : JSON formaté, valeurs sensibles masquées sauf --reveal
      const output = reveal ? resp.body.data : maskSensitiveData(resp.body.data);
      console.log(JSON.stringify(output, null, 2));
    }
  } else if (resp.status === 403) {
    console.error('Accès refusé : l\'utilisateur a refusé la demande dans RDVault.');
    process.exit(1);
  } else {
    console.error(`Erreur (${resp.status}) : ${resp.body.error || 'Erreur inconnue'}`);
    process.exit(1);
  }
}

async function cmdLs(args) {
  const session = readSession();

  let targetPath = args[0] || '';

  if (!targetPath) {
    console.error('Usage : mvault ls <engine>[/dossier]');
    console.error('Exemple : mvault ls users/rdekien/LAB-TEST');
    console.error('Utilisez "mvault engines" pour voir les engines disponibles.');
    process.exit(1);
  }

  // Résoudre engine/path comme pour cmdGet
  const enginesResp = await request('GET', '/engines', session);
  let engine = null;
  let folderPath = '';

  if (enginesResp.status === 200 && enginesResp.body.success) {
    const engineNames = enginesResp.body.engines
      .map(e => e.name.replace(/\/+$/, ''))
      .sort((a, b) => b.length - a.length);

    for (const name of engineNames) {
      if (targetPath === name || targetPath.startsWith(name + '/')) {
        engine = name;
        folderPath = targetPath.substring(name.length + 1);
        break;
      }
    }
  }

  if (!engine) {
    const slashIndex = targetPath.indexOf('/');
    if (slashIndex === -1) {
      engine = targetPath;
    } else {
      engine = targetPath.substring(0, slashIndex);
      folderPath = targetPath.substring(slashIndex + 1);
    }
  }

  const body = { engine };
  if (folderPath) body.path = folderPath;

  const resp = await request('POST', '/list', session, body);

  if (resp.status === 200 && resp.body.success) {
    if (resp.body.keys.length === 0) {
      console.log('Aucun secret trouvé.');
    } else {
      resp.body.keys.forEach(k => console.log(k));
    }
  } else if (resp.status === 403) {
    console.error(`Erreur : ${resp.body.error}`);
    process.exit(1);
  } else {
    console.error(`Erreur (${resp.status}) : ${resp.body.error || 'Erreur inconnue'}`);
    process.exit(1);
  }
}

async function cmdEngines() {
  const session = readSession();
  const resp = await request('GET', '/engines', session);

  if (resp.status === 200 && resp.body.success) {
    if (resp.body.engines.length === 0) {
      console.log('Aucun engine disponible. Êtes-vous connecté dans RDVault ?');
    } else {
      console.log('Engines disponibles :');
      resp.body.engines.forEach(e => {
        console.log(`  ${e.name}  (KV v${e.version})`);
      });
    }
  } else {
    console.error(`Erreur : ${resp.body.error || 'Erreur inconnue'}`);
    process.exit(1);
  }
}

async function cmdStatus() {
  const session = readSession();

  const resp = await request('GET', '/health', { ...session, token: 'dummy' });

  if (resp.status === 200 && resp.body.status === 'ok') {
    console.log(`RDVault actif (v${resp.body.version}) sur le port ${session.port}`);
  } else {
    console.error('RDVault ne répond pas correctement.');
    process.exit(1);
  }
}

async function cmdRules(args) {
  // Lecture seule : la sous-commande `rules set` a été supprimée (modification via l'UI RDVault)
  if (args.length > 0) {
    console.error('Erreur : `mvault rules` est en lecture seule. Modifiez les règles dans RDVault (Paramètres > CLI).');
    process.exit(1);
  }

  const session = readSession();
  const resp = await request('GET', '/rules', session);
  if (resp.status === 200) {
    if (resp.body.rules.length === 0) {
      console.log('No auto-approval rules. All access will require confirmation.');
    } else {
      console.log('Auto-approval rules (read-only, change in Settings > CLI):');
      resp.body.rules.forEach(r => console.log(`  - ${r}`));
    }
  } else {
    console.error(`Error: ${resp.body.error}`);
    process.exit(1);
  }
}

/**
 * Résout un chemin complet « engine/.../secret » en { engine, path } en interrogeant
 * la liste des engines (les engines peuvent contenir des « / »).
 */
async function resolveEnginePath(fullPath, session) {
  const enginesResp = await request('GET', '/engines', session);
  if (enginesResp.status === 200 && enginesResp.body.success) {
    const names = enginesResp.body.engines.map(e => e.name.replace(/\/+$/, '')).sort((a, b) => b.length - a.length);
    for (const name of names) {
      if (fullPath === name || fullPath.startsWith(name + '/')) {
        return { engine: name, path: fullPath.substring(name.length + 1) };
      }
    }
  }
  const slash = fullPath.indexOf('/');
  if (slash === -1) return { engine: null, path: null };
  return { engine: fullPath.substring(0, slash), path: fullPath.substring(slash + 1) };
}

/**
 * mvault ssh <user@hôte|hôte> --secret|-s <engine>/<chemin> [--key-field <f>] [--port|-p <n>]
 *            [--hostkey SHA256:…] [--exec-timeout <secondes>] [-- <args ssh | commande>]
 *
 * Clé privée dans le coffre : RDVAULT la charge dans un agent SSH éphémère et renvoie uniquement
 * le chemin SSH_AUTH_SOCK. mvault lance `ssh` avec cette socket : la clé est UTILISÉE pour
 * s'authentifier mais n'est JAMAIS exposée à l'appelant (ni argument, ni sortie, ni env).
 * Mot de passe dans le coffre : RDVAULT ouvre lui-même la connexion (broker) après vérification
 * de la clé d'hôte (--hostkey épinglée, ou known_hosts.json + popup à la première connexion).
 */
async function cmdSsh(args) {
  let target = null, secret = null, keyField = null, port = null, hostkey = null, execTimeoutSec = null;
  const extra = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--secret' || a === '-s') { secret = args[++i]; }
    else if (a === '--key-field') { keyField = args[++i]; }
    else if (a === '--port' || a === '-p') { port = args[++i]; }
    else if (a === '--hostkey') { hostkey = args[++i]; }
    else if (a === '--exec-timeout') { execTimeoutSec = args[++i]; }
    else if (a === '--') { for (let j = i + 1; j < args.length; j++) extra.push(args[j]); break; }
    else if (!target && !a.startsWith('-')) { target = a; }
    else { extra.push(a); }
  }

  if (!target || !secret) {
    console.error('Usage : mvault ssh <user@hôte> --secret|-s <engine>/<chemin> [--key-field <f>] [--port|-p <n>]');
    console.error('                   [--hostkey SHA256:…] [--exec-timeout <secondes>] [-- <args ssh | commande>]');
    console.error('Exemple : mvault ssh admin@serveur --secret users/moi/LAB/cle-prod');
    console.error('  --hostkey       empreinte SHA256 attendue de la clé d\'hôte (mode mot de passe) ; sinon known_hosts.json');
    console.error('                  + confirmation dans RDVAULT à la première connexion, refus si la clé change');
    console.error('  --exec-timeout  délai d\'exécution de la commande en secondes (défaut 600, 0 = illimité)');
    console.error('  (mode clé/agent : --hostkey et --exec-timeout ne s\'appliquent pas ; ssh vérifie ~/.ssh/known_hosts)');
    process.exit(1);
  }
  if (hostkey !== null && !/^(sha256:)?[A-Za-z0-9+/]{43}=?$/i.test(String(hostkey).trim())) {
    console.error('Erreur : --hostkey attend une empreinte « SHA256:<base64> » (ex. ssh-keygen -lf <clé publique>).');
    process.exit(1);
  }
  let execTimeoutMs = null;
  if (execTimeoutSec !== null) {
    const n = Number(execTimeoutSec);
    if (!/^\d+$/.test(String(execTimeoutSec).trim()) || !Number.isInteger(n) || n > 3600) {
      console.error('Erreur : --exec-timeout attend un entier en secondes (0 = illimité, max 3600).');
      process.exit(1);
    }
    execTimeoutMs = n * 1000;
  }

  const session = readSession(); // après la validation des arguments : l'usage s'affiche même sans RDVAULT
  const { engine, path: secretPath } = await resolveEnginePath(secret, session);
  if (!engine || !secretPath) {
    console.error('Erreur : --secret doit être <engine>/<chemin>. Voir « mvault engines ».');
    process.exit(1);
  }

  // Séparer user@host (le serveur choisit le mode selon le secret : clé → agent, mdp → broker)
  let user = null, host = target;
  const at = target.indexOf('@');
  if (at > 0) { user = target.slice(0, at); host = target.slice(at + 1); }
  const command = extra.length ? extra.join(' ') : undefined;

  const reqBody = { engine, path: secretPath, host };
  if (keyField) reqBody.keyField = keyField;
  if (user) reqBody.user = user;
  if (port) reqBody.port = String(port);
  if (command) reqBody.command = command;
  if (hostkey) reqBody.hostFingerprint = String(hostkey).trim();
  if (execTimeoutMs !== null) reqBody.execTimeoutMs = execTimeoutMs;

  // Délai HTTP : pire cas côté serveur AVANT l'exécution (popup d'accès 30 s + popup de clé d'hôte 30 s,
  // sérialisées, + connexion 20 s) + marge, plus le délai d'exécution (600 s par défaut, 0 = illimité).
  const setupMarginMs = 2 * 30000 + 20000 + 10000;
  const serverExecMs = execTimeoutMs === null ? 600000 : execTimeoutMs;
  const resp = await request('POST', '/ssh', session, reqBody, command ? (serverExecMs === 0 ? 0 : serverExecMs + setupMarginMs) : setupMarginMs);

  const portShown = port ? String(port) : '22';
  const where = `${host}:${portShown}`;
  const errCode = resp.body.error;
  if (resp.status === 403) {
    if (errCode === 'HOST_KEY_REJECTED') {
      console.error(`Clé d'hôte SSH de ${where} refusée${resp.body.observed ? ` (${clean(resp.body.observed)})` : ''} : ` +
        'elle n\'a pas été mémorisée dans RDVAULT (refus, délai dépassé ou fenêtre absente).');
      console.error('Le mot de passe n\'a PAS été envoyé. Confirmez la clé dans RDVAULT ou épinglez-la avec --hostkey SHA256:… .');
    } else {
      console.error('Accès refusé : l\'utilisateur a refusé la demande dans RDVAULT.');
    }
    process.exit(1);
  }
  if (errCode === 'HOST_KEY_CHANGED_REKEY') {
    printRekeyHostKeyWarning(host, portShown, resp.body);
    process.exit(1);
  }
  if (errCode === 'HOST_KEY_CHANGED' || errCode === 'HOST_KEY_MISMATCH') {
    printHostKeyWarning(errCode, host, portShown, resp.body, !!hostkey);
    process.exit(1);
  }
  if (errCode === 'KNOWN_HOSTS_READ' || errCode === 'KNOWN_HOSTS_WRITE') {
    console.error(errCode === 'KNOWN_HOSTS_READ'
      ? 'Erreur : la mémoire des clés d\'hôte SSH de RDVAULT est illisible ou corrompue :'
      : `Erreur : impossible de mémoriser la clé d'hôte de ${where} dans RDVAULT (droits, disque plein ?) :`);
    console.error(`  ${getKnownHostsFile()}`);
    if (errCode === 'KNOWN_HOSTS_READ') console.error('Corrigez ou supprimez ce fichier (les clés mémorisées seront redemandées), puis relancez la commande.');
    if (resp.body.message) console.error(`Détail : ${clean(resp.body.message)}`);
    console.error('Connexion refusée : le mot de passe n\'a PAS été envoyé.');
    process.exit(1);
  }
  if (errCode === 'CONNECT_TIMEOUT') {
    console.error(`Erreur : délai de connexion SSH dépassé pour ${where} (hôte injoignable, port filtré ou serveur muet).`);
    process.exit(1);
  }
  if (errCode === 'EXEC_TIMEOUT') {
    console.error(`Erreur : délai d'exécution SSH dépassé sur ${where} (${serverExecMs / 1000} s) : la commande a été interrompue ` +
      'et la connexion fermée. Augmentez --exec-timeout (secondes, 0 = illimité, max 3600).');
    process.exit(1);
  }
  if (resp.status !== 200 || !resp.body.success) {
    console.error(`Erreur (${resp.status}) : ${clean(resp.body.message || resp.body.error || 'Impossible de préparer la connexion SSH')}`);
    process.exit(1);
  }
  // Mode mot de passe : la clé d'hôte vérifiée est rappelée sur STDERR (jamais mélangée à la sortie)
  if (resp.body.hostFingerprint) {
    console.error(`Clé d'hôte ${host}:${portShown} : ${resp.body.hostFingerprint} (${hostKeyStatusLabel(resp.body.hostKeyStatus)})`);
  }

  // Mode MOT DE PASSE (broker) : RDVAULT a exécuté la commande, on affiche la sortie
  if (resp.body.mode === 'exec') {
    if (resp.body.stdout) process.stdout.write(resp.body.stdout);
    if (resp.body.stderr) process.stderr.write(resp.body.stderr);
    process.exit(remoteExitCode(resp.body.code, resp.body.signal));
    return;
  }

  // Mode SHELL interactif (mot de passe, sans commande) : brancher le terminal sur la socket.
  // Le mot de passe reste dans RDVAULT ; on ne fait que relayer stdin/stdout.
  if (resp.body.mode === 'shell' && resp.body.sock) {
    const sock = resp.body.sock;
    const stdin = process.stdin;
    const canRaw = stdin.isTTY && typeof stdin.setRawMode === 'function';
    const conn = net.connect(sock);
    // Taille du terminal : envoyée seulement si elle a changé, et les rafales d'événements 'resize'
    // (redimensionnement à la souris) sont regroupées (150 ms) en un seul POST /ssh/resize.
    let lastSize = '', resizeTimer = null;
    const sendSize = () => {
      resizeTimer = null;
      const rows = process.stdout.rows || 24, cols = process.stdout.columns || 80;
      if (`${rows}x${cols}` === lastSize) return;
      lastSize = `${rows}x${cols}`;
      postQuiet('/ssh/resize', session, { authSock: sock, rows, cols });
    };
    const onResize = () => { if (resizeTimer) clearTimeout(resizeTimer); resizeTimer = setTimeout(sendSize, 150); };
    const closeRemote = () => postQuiet('/ssh/close', session, { authSock: sock });
    const restore = () => {
      try { if (canRaw) stdin.setRawMode(false); } catch { /* ignore */ }
      try { stdin.unpipe(conn); } catch { /* ignore */ }
      try { stdin.pause(); } catch { /* ignore */ }
      try { process.stdout.removeListener('resize', onResize); } catch { /* ignore */ }
      if (resizeTimer) { clearTimeout(resizeTimer); resizeTimer = null; }
    };
    let connected = false, connError = null, finished = false;
    conn.on('connect', () => {
      connected = true;
      if (canRaw) { try { stdin.setRawMode(true); } catch { /* ignore */ } }
      stdin.resume();
      stdin.pipe(conn);
      conn.pipe(process.stdout);
      sendSize(); // taille initiale du terminal
      process.stdout.on('resize', onResize); // SIGWINCH : adapter le PTY distant
    });
    conn.on('error', (e) => { if (!connError) connError = e; }); // 'close' suit toujours 'error' : traité ci-dessous
    // Fin de session : la raison est demandée à RDVAULT (/ssh/status) AVANT /ssh/close, puis la fermeture est
    // attendue (1,5 s max) avant de quitter (process.exit() annulerait l'envoi). Code ≠ 0 si RDVAULT a coupé la session.
    conn.on('close', async () => {
      if (finished) return;
      finished = true;
      restore();
      const st = await fetchShellStatus(session, sock, connected ? 10 : 0);
      const exitCode = reportShellEnd(st, host, portShown, { connected, connError, tty: canRaw });
      await awaitQuiet(closeRemote());
      process.exit(exitCode);
    });
    return;
  }

  // Mode CLÉ (agent) : lancer ssh avec SSH_AUTH_SOCK ; la clé reste dans RDVAULT
  const authSock = resp.body.authSock;
  if (!authSock) {
    console.error('Erreur : réponse inattendue du serveur (ni exec, ni agent).');
    process.exit(1);
  }
  const sshBin = process.env.MVAULT_SSH_BIN
    || (process.platform === 'win32' ? 'C:\\Windows\\System32\\OpenSSH\\ssh.exe' : 'ssh');
  const sshArgs = [];
  if (port) sshArgs.push('-p', String(port));
  sshArgs.push(target, ...extra);

  // Destruction de l'agent (clé retirée de la mémoire) attendue AVANT de quitter, 1,5 s max
  const closeAgent = () => awaitQuiet(postQuiet('/ssh/close', session, { authSock }));
  const localSignalCode = (sig) => 128 + ((os.constants.signals && os.constants.signals[sig]) || 0);

  // En mode clé, ces options du broker (mot de passe) ne s'appliquent pas : le dire plutôt que les ignorer.
  if (hostkey) console.error(`Avertissement : --hostkey n'est pas appliqué en mode clé (agent) : la clé d'hôte de ${where} est vérifiée par ssh (~/.ssh/known_hosts), pas par RDVAULT.`);
  if (execTimeoutMs !== null) console.error('Avertissement : --exec-timeout n\'est pas appliqué en mode clé (agent) : la durée de la session ssh n\'est pas bornée par RDVAULT.');

  const child = spawn(sshBin, sshArgs, { stdio: 'inherit', env: { ...process.env, SSH_AUTH_SOCK: authSock } });
  // Ctrl+C / arrêt (commande sans PTY) : sans écouteur, Node quitterait aussitôt SANS /ssh/close (clé
  // gardée jusqu'au garde-fou). Le signal est relayé à ssh, dont la fin déclenche le nettoyage ci-dessous ;
  // un second signal force la sortie, après destruction de l'agent.
  let signalled = false;
  const onSignal = async (sig) => {
    if (signalled) { await closeAgent(); process.exit(localSignalCode(sig)); }
    signalled = true;
    try { child.kill(sig); } catch { try { child.kill(); } catch { /* déjà terminé */ } }
  };
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, onSignal);
  child.on('error', async (e) => {
    console.error(`Impossible de lancer ssh (${sshBin}) : ${e.message}`);
    await closeAgent();
    process.exit(1);
  });
  child.on('exit', async (code, signal) => { await closeAgent(); process.exit(code !== null ? code : (signal ? localSignalCode(signal) : 1)); });
}

/**
 * mvault winrm <user@hôte> --secret|-s <engine>/<chemin> [--ssl] [--port|-p <n>] [--auth <m>] -- <commande PowerShell>
 *
 * RDVAULT exécute la commande sur l'hôte Windows (WinRM/PowerShell Remoting) avec
 * l'identifiant du coffre et ne renvoie que la SORTIE : le mot de passe n'est jamais exposé.
 */
async function cmdWinrm(args) {
  let target = null, secret = null, port = null, authMethod = null, useSSL = false;
  const extra = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--secret' || a === '-s') { secret = args[++i]; }
    else if (a === '--port' || a === '-p') { port = args[++i]; }
    else if (a === '--auth') { authMethod = args[++i]; }
    else if (a === '--ssl') { useSSL = true; }
    else if (a === '--') { for (let j = i + 1; j < args.length; j++) extra.push(args[j]); break; }
    else if (!target && !a.startsWith('-')) { target = a; }
    else { extra.push(a); }
  }
  const command = extra.join(' ');
  if (!target || !secret || !command) {
    console.error('Usage : mvault winrm <user@hôte> --secret|-s <engine>/<chemin> [--ssl] [--port|-p <n>] [--auth <m>] -- <commande>');
    console.error('Exemple : mvault winrm administrateur@srv --secret users/moi/win/admin -- "hostname; whoami"');
    process.exit(1);
  }

  let user = null, host = target;
  const at = target.indexOf('@');
  if (at > 0) { user = target.slice(0, at); host = target.slice(at + 1); }

  const session = readSession(); // après la validation des arguments : l'usage s'affiche même sans RDVAULT
  const { engine, path: secretPath } = await resolveEnginePath(secret, session);
  if (!engine || !secretPath) {
    console.error('Erreur : --secret doit être <engine>/<chemin>. Voir « mvault engines ».');
    process.exit(1);
  }

  const reqBody = { engine, path: secretPath, host, command };
  if (user) reqBody.user = user;
  if (port) reqBody.port = String(port);
  if (authMethod) reqBody.authMethod = authMethod;
  if (useSSL) reqBody.useSSL = true;

  // Délai HTTP : popup d'accès (30 s) + délai PowerShell du broker (30 s) + marge
  const resp = await request('POST', '/winrm', session, reqBody, 30000 + 30000 + 10000);
  if (resp.status === 403) { console.error('Accès refusé : l\'utilisateur a refusé la demande dans RDVAULT.'); process.exit(1); }
  if (resp.status !== 200 || !resp.body.success) {
    console.error(`Erreur (${resp.status}) : ${clean(resp.body.error || 'WinRM échoué')}`);
    process.exit(1);
  }
  if (resp.body.stdout) process.stdout.write(resp.body.stdout);
  if (resp.body.stderr) process.stderr.write(resp.body.stderr);
  process.exit(remoteExitCode(resp.body.code, null)); // processus PowerShell tué (code null) → 1, jamais 0
}

function showHelp() {
  console.log(`mvault — CLI pour accéder aux secrets RDVault

Usage :
  mvault get <engine>/<chemin>              Récupère un secret (JSON, valeurs sensibles masquées)
  mvault get <engine>/<chemin> --reveal     Récupère un secret sans masquer les valeurs sensibles
  mvault get <engine>/<chemin> -k <clé>     Récupère une valeur spécifique (texte brut)
  mvault ls <engine>[/dossier]              Liste les secrets d'un engine
  mvault ssh <user@hôte> --secret <e>/<p>   Session SSH avec un secret du coffre, SANS l'exposer
                                            (clé → agent éphémère ; mot de passe → broker + commande)
      [-p <port>] [--hostkey SHA256:…]      Clé d'hôte : épinglée (--hostkey) ou mémorisée dans
      [--exec-timeout <s>]                  known_hosts.json après confirmation dans RDVAULT
  mvault winrm <user@hôte> --secret <e>/<p> -- <cmd>
                                            Exécute une commande Windows (WinRM) avec l'identifiant
                                            du coffre, SANS l'exposer (broker)
  (-s = --secret, -p = --port)
  mvault engines                            Liste les engines Vault disponibles
  mvault status                             Vérifie que RDVault est actif
  mvault rules                              Affiche les règles d'auto-approbation (lecture seule,
                                            modification dans RDVault : Paramètres > CLI)
  mvault help                               Affiche cette aide

Clés masquées sans --reveal : password, pass, secret, token, key, private_key

Exemples :
  mvault get secret/serveur-prod -k password
  mvault ssh admin@serveur --secret users/moi/LAB/cle-prod          # clé jamais exposée (agent)
  mvault ssh admin@serveur --secret users/moi/LAB/pw -- "uptime"    # mot de passe → broker
  mvault winrm administrateur@srv --secret users/moi/win/adm -- "hostname"  # WinRM
  SSHPASS="$(mvault get secret/prod -k password)" sshpass -e ssh admin@serveur
  mvault ls users/rdekien/LAB-TEST

L'application RDVault Desktop doit être lancée et l'utilisateur connecté.`);
}

// ========================================
// POINT D'ENTRÉE
// ========================================

const [,, command, ...args] = process.argv;

switch (command) {
  case 'get':
    cmdGet(args);
    break;
  case 'ls':
    cmdLs(args);
    break;
  case 'engines':
    cmdEngines();
    break;
  case 'status':
    cmdStatus();
    break;
  case 'rules':
    cmdRules(args);
    break;
  case 'ssh':
    cmdSsh(args);
    break;
  case 'winrm':
    cmdWinrm(args);
    break;
  case 'help':
  case '--help':
  case '-h':
  case undefined:
    showHelp();
    break;
  default:
    console.error(`Commande inconnue : ${command}`);
    showHelp();
    process.exit(1);
}
