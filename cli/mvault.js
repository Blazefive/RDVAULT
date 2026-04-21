#!/usr/bin/env node
// ========================================
// MVAULT CLI — Client ligne de commande pour RDVault
// ========================================
// Récupère des secrets depuis Vault via l'application Electron RDVault.
// L'Electron doit être lancé et l'utilisateur connecté.
//
// Usage :
//   mvault get <engine>/<chemin>              → affiche toutes les données du secret (JSON)
//   mvault get <engine>/<chemin> --key <clé>  → affiche uniquement la valeur d'une clé (texte brut)
//   mvault get <engine>/<chemin> -k password  → raccourci pour --key
//   mvault status                             → vérifie si l'Electron est actif
//   mvault rules                              → affiche les règles d'auto-approbation
//   mvault rules set "chemin/*" "autre/*"     → définit les règles d'auto-approbation
//
// Exemples avec sshpass :
//   sshpass -p "$(mvault get secrets/prod -k password)" ssh user@serveur
//
// Variables d'environnement :
//   MVAULT_SESSION_FILE — chemin personnalisé vers le fichier de session
//                         (par défaut : ~/AppData/Local/rdvault/cli/session.json)

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ========================================
// LOCALISATION DU FICHIER DE SESSION
// ========================================

function getSessionFilePath() {
  // Variable d'environnement en priorité
  if (process.env.MVAULT_SESSION_FILE) {
    return process.env.MVAULT_SESSION_FILE;
  }

  // Chemin par défaut selon la plateforme
  const platform = process.platform;
  let appData;
  if (platform === 'win32') {
    // Electron app.getPath('userData') utilise Roaming sur Windows
    appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(appData, 'rdvault', 'cli', 'session.json');
  } else if (platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'rdvault', 'cli', 'session.json');
  } else {
    // Linux : XDG_CONFIG_HOME ou ~/.config
    const configDir = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
    return path.join(configDir, 'rdvault', 'cli', 'session.json');
  }
}

/**
 * Lit le fichier de session écrit par l'Electron
 */
function readSession() {
  const sessionFile = getSessionFilePath();
  try {
    const content = fs.readFileSync(sessionFile, 'utf-8');
    const session = JSON.parse(content);
    if (!session.port || !session.token) {
      throw new Error('Fichier de session incomplet');
    }
    return session;
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.error('Erreur : RDVault ne semble pas lancé (fichier de session introuvable).');
      console.error(`Chemin attendu : ${sessionFile}`);
    } else {
      console.error(`Erreur lecture session : ${err.message}`);
    }
    process.exit(1);
  }
}

// ========================================
// CLIENT HTTP
// ========================================

/**
 * Effectue une requête HTTP vers le serveur CLI local de l'Electron
 */
function request(method, urlPath, session, body = null) {
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
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
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

    // Timeout de 60 secondes (inclut le temps de la popup de confirmation)
    req.setTimeout(60000, () => {
      req.destroy();
      console.error('Erreur : timeout — la demande de confirmation a peut-être expiré.');
      process.exit(1);
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

// ========================================
// COMMANDES
// ========================================

async function cmdGet(args) {
  const session = readSession();

  // Parser les arguments
  let secretFullPath = args[0];
  let key = null;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--key' || args[i] === '-k') {
      key = args[i + 1];
      i++;
    }
  }

  if (!secretFullPath) {
    console.error('Usage : mvault get <engine>/<chemin> [--key <clé>]');
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
      // Mode complet : afficher le JSON formaté
      console.log(JSON.stringify(resp.body.data, null, 2));
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

async function cmdRules() {
  const session = readSession();
  // Afficher les règles (lecture seule — modification uniquement via l'UI RDVault)
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

function showHelp() {
  console.log(`mvault — CLI pour accéder aux secrets RDVault

Usage :
  mvault get <engine>/<chemin>              Récupère un secret (JSON)
  mvault get <engine>/<chemin> -k <clé>     Récupère une valeur spécifique (texte brut)
  mvault ls <engine>[/dossier]                Liste les secrets d'un engine
  mvault engines                             Liste les engines Vault disponibles
  mvault status                             Vérifie que RDVault est actif
  mvault rules                              Affiche les règles d'auto-approbation
  mvault rules set <pattern> [<pattern>...] Définit les règles d'auto-approbation
  mvault help                               Affiche cette aide

Exemples :
  mvault get secret/serveur-prod -k password
  sshpass -p "$(mvault get secret/prod -k password)" ssh admin@serveur
  mvault ls users/rdekien/LAB-TEST
  mvault rules set "users/blaze/*" "secret/staging/*"

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
