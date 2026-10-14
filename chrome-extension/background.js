// background.js
// Service Worker pour gérer les requêtes Vault
//
// SÉCURITÉ :
// - Seules les URLs Vault en https sont acceptées
// - Le hostname utilisé pour le matching est TOUJOURS celui de l'onglet (sender.tab.url)
// - La liste envoyée au content script ne contient JAMAIS de mot de passe :
//   le mot de passe n'est renvoyé qu'à la sélection (SELECT_CREDENTIAL), depuis le cache

/* global chrome, importScripts, VaultClient */ // API d'extension et service worker « classique » ; VaultClient vient de vault-client.js
importScripts('vault-client.js');

let vaultClient = null;
let cachedSecrets = null;
let cacheTimestamp = null;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Suffixes publics courants : un secret dont le champ Website/URL se réduit à l'un d'eux
// ne doit JAMAIS matcher (sinon "com" matcherait tous les sites en .com)
const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'io', 'co', 'fr', 'de', 'uk', 'co.uk',
  'github.io', 'herokuapp.com', 'azurewebsites.net', 'cloudfront.net',
  'amazonaws.com', 'appspot.com', 'vercel.app', 'netlify.app',
  'pages.dev', 'web.app', 'firebaseapp.com'
]);

// Message traduit dans la langue du navigateur (chrome.i18n, _locales/<langue>/messages.json,
// repli « en »). `fallback` est le texte français d'origine, identique à _locales/fr : il ne sert
// que hors navigateur (tests) ; $1… y sont remplacés comme par Chrome.
function i18nMessage(key, fallback, subs) {
  const list = subs === undefined ? [] : [].concat(subs).map(String);
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
      const text = chrome.i18n.getMessage(key, list);
      if (text) return text;
    }
  } catch { /* API indisponible : repli */ }
  return fallback.replace(/\$([1-9])/g, (m, n) => (list[n - 1] !== undefined ? list[n - 1] : ''));
}

// Valider qu'une URL Vault est sûre (https obligatoire)
function isValidVaultUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

// Hostname (minuscules) de l'onglet expéditeur, uniquement si la page est en https
function getSenderHttpsHostname(sender) {
  try {
    const tabUrl = sender && sender.tab ? sender.tab.url : null;
    if (!tabUrl) return null;
    const parsed = new URL(tabUrl);
    if (parsed.protocol !== 'https:') return null;
    return parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

// Initialiser le client Vault depuis le storage
async function initVaultClient() {
  // SÉCURITÉ: Utiliser storage.session uniquement (disparaît quand le navigateur ferme)
  let data;
  try {
    data = await chrome.storage.session.get(['vaultUrl', 'vaultNamespace', 'vaultToken', 'username']);
  } catch {
    return false;
  }

  if (data.vaultUrl && data.vaultToken && isValidVaultUrl(data.vaultUrl)) {
    vaultClient = new VaultClient(data.vaultUrl, data.vaultNamespace || '');
    vaultClient.token = data.vaultToken;
    return true;
  }

  return false;
}

// Vérifier si le cache est valide
function isCacheValid() {
  if (!cachedSecrets || !cacheTimestamp) return false;
  return (Date.now() - cacheTimestamp) < CACHE_TTL;
}

// Récupérer tous les secrets et les mettre en cache
async function refreshSecretsCache() {
  if (!vaultClient) {
    const initialized = await initVaultClient();
    if (!initialized) {
      throw new Error('Vault client not initialized');
    }
  }

  try {
    cachedSecrets = await vaultClient.getAllSecrets();
    cacheTimestamp = Date.now();
    return cachedSecrets;
  } catch (err) {
    console.error('Error refreshing secrets cache');
    throw err;
  }
}

// Trouver les secrets (complets, en mémoire du background) pour un hostname.
// Un ÉCHEC renvoie { error } (message traduit), à distinguer d'une liste vide (« aucun identifiant
// pour ce site ») : le menu d'autoremplissage explique alors pourquoi rien n'est proposé.
async function getSecretsForHostname(hostname) {
  if (!vaultClient) {
    const initialized = await initVaultClient();
    if (!initialized) {
      return { error: i18nMessage('bgErrNotLoggedIn', 'Non connecté à Vault : ouvrez la fenêtre de l\'extension pour vous connecter.') };
    }
  }

  try {
    // Utiliser le cache si valide
    if (isCacheValid()) {
      return filterSecretsByHostname(cachedSecrets, hostname);
    }

    // Sinon, rafraîchir le cache
    await refreshSecretsCache();
    return filterSecretsByHostname(cachedSecrets, hostname);
  } catch (err) {
    console.error('Error getting credentials');
    return { error: i18nMessage('bgErrVaultUnreachable', 'Vault injoignable ou session expirée : reconnectez-vous depuis la fenêtre de l\'extension.') };
  }
}

// Extraire un hostname (minuscules) depuis un champ Website/URL, avec ou sans protocole
function extractHostname(value) {
  if (!value || typeof value !== 'string') return null;

  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;

  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//.test(trimmed);
    const parsed = new URL(hasScheme ? trimmed : `https://${trimmed}`);
    return parsed.hostname || null;
  } catch {
    return null;
  }
}

// Un hostname de secret est acceptable s'il a au moins 2 labels et n'est pas un suffixe public
function isAcceptableSecretHostname(secretHostname) {
  if (!secretHostname) return false;

  const labels = secretHostname.split('.').filter(Boolean);
  if (labels.length < 2) return false;

  if (PUBLIC_SUFFIXES.has(secretHostname)) return false;

  return true;
}

// Match exact ou sous-domaine (hostname de l'onglet se termine par ".secretHostname")
function hostnameMatches(hostname, secretHostname) {
  if (!isAcceptableSecretHostname(secretHostname)) return false;
  return secretHostname === hostname || hostname.endsWith(`.${secretHostname}`);
}

// Filtrer les secrets par hostname (champ Website prioritaire, URL en fallback)
function filterSecretsByHostname(secrets, hostname) {
  if (!Array.isArray(secrets) || !hostname) return [];

  return secrets.filter(secret => {
    if (!secret || typeof secret !== 'object') return false;

    if (hostnameMatches(hostname, extractHostname(secret.website))) {
      return true;
    }

    if (hostnameMatches(hostname, extractHostname(secret.url))) {
      return true;
    }

    return false;
  });
}

// Résumé transmis au content script : JAMAIS de mot de passe ni de notes
function toCredentialSummary(secret) {
  return {
    name: typeof secret.name === 'string' ? secret.name : '',
    engine: typeof secret.engine === 'string' ? secret.engine : '',
    username: typeof secret.username === 'string' ? secret.username : ''
  };
}

// Écouter les messages depuis content script et popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // SÉCURITÉ: Vérifier que le message vient de notre extension
  if (!sender || sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, error: i18nMessage('bgErrUnauthorizedSource', 'Source non autorisée') });
    return false;
  }

  // Utiliser une fonction async pour gérer les promesses
  (async () => {
    try {
      switch (request && request.type) {
        case 'GET_CREDENTIALS': {
          // SÉCURITÉ: hostname de l'onglet (source de vérité Chrome), page https obligatoire
          const hostname = getSenderHttpsHostname(sender);
          if (!hostname) {
            sendResponse({ success: false, credentials: [], error: i18nMessage('bgErrInsecurePage', 'Page non sécurisée') });
            break;
          }

          const matches = await getSecretsForHostname(hostname);
          if (!Array.isArray(matches)) {
            sendResponse({ success: false, credentials: [], error: matches.error });
            break;
          }
          sendResponse({ success: true, credentials: matches.map(toCredentialSummary) });
          break;
        }

        case 'SELECT_CREDENTIAL': {
          // Renvoie le mot de passe d'UNE entrée, depuis le cache, pour le hostname de l'onglet
          const hostname = getSenderHttpsHostname(sender);
          if (!hostname) {
            sendResponse({ success: false, error: i18nMessage('bgErrInsecurePage', 'Page non sécurisée') });
            break;
          }

          const engine = typeof request.engine === 'string' ? request.engine : '';
          const name = typeof request.name === 'string' ? request.name : '';
          if (!name) {
            sendResponse({ success: false, error: i18nMessage('bgErrNameRequired', 'Nom de secret requis') });
            break;
          }

          const matches = await getSecretsForHostname(hostname);
          if (!Array.isArray(matches)) {
            sendResponse({ success: false, error: matches.error });
            break;
          }
          const secret = matches.find(s => s.name === name && (s.engine || '') === engine);

          if (!secret) {
            sendResponse({ success: false, error: i18nMessage('bgErrNotFound', 'Identifiant introuvable pour ce site') });
            break;
          }

          sendResponse({
            success: true,
            credential: {
              name: secret.name,
              engine: secret.engine || '',
              username: typeof secret.username === 'string' ? secret.username : '',
              password: typeof secret.password === 'string' ? secret.password : ''
            }
          });
          break;
        }

        case 'LOGIN':
          try {
            if (!isValidVaultUrl(request.vaultUrl)) {
              sendResponse({ success: false, error: i18nMessage('bgErrInvalidVaultUrl', 'URL Vault invalide (https obligatoire)') });
              break;
            }
            vaultClient = new VaultClient(request.vaultUrl, request.vaultNamespace || '');
            const result = await vaultClient.login(request.username, request.password);

            // SÉCURITÉ: Sauvegarder dans storage.session uniquement (non persisté)
            const storageData = {
              vaultUrl: request.vaultUrl,
              vaultNamespace: request.vaultNamespace || '',
              vaultToken: result.token,
              username: result.username
            };
            await chrome.storage.session.set(storageData);

            // Pré-charger le cache
            await refreshSecretsCache();

            sendResponse({ success: true, username: result.username });
          } catch (err) {
            sendResponse({ success: false, error: i18nMessage('bgErrAuthFailed', 'Authentification échouée') });
          }
          break;

        case 'LOGOUT':
          vaultClient = null;
          cachedSecrets = null;
          cacheTimestamp = null;
          try { await chrome.storage.session.clear(); } catch {}
          // SÉCURITÉ: Ne supprimer que les clés liées à Vault (pas tout le storage)
          try { await chrome.storage.local.remove(['vaultToken', 'vaultUrl', 'username']); } catch {}
          sendResponse({ success: true });
          break;

        case 'CHECK_AUTH': {
          let data;
          try {
            data = await chrome.storage.session.get(['vaultToken', 'username']);
          } catch {
            data = {};
          }
          sendResponse({
            authenticated: !!data.vaultToken,
            username: data.username || null
          });
          break;
        }

        case 'REFRESH_CACHE':
          await refreshSecretsCache();
          sendResponse({ success: true, count: cachedSecrets?.length || 0 });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown request type' });
      }
    } catch (err) {
      console.error('Error handling message');
      sendResponse({ success: false, error: i18nMessage('bgErrInternal', 'Erreur interne') });
    }
  })();

  // Retourner true pour indiquer une réponse asynchrone
  return true;
});

// Initialiser au démarrage
chrome.runtime.onStartup.addListener(async () => {
  const initialized = await initVaultClient();
  if (initialized) {
    // Pré-charger le cache au démarrage
    try {
      await refreshSecretsCache();
      console.log('Vault client initialized and cache loaded');
    } catch (err) {
      console.error('Error loading cache on startup');
    }
  }
});

// Nettoyer le cache périodiquement
chrome.alarms.create('cleanCache', { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanCache') {
    if (!isCacheValid()) {
      cachedSecrets = null;
      cacheTimestamp = null;
    }
  }
});
