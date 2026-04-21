// background.js
// Service Worker pour gérer les requêtes Vault

importScripts('vault-client.js');

let vaultClient = null;
let cachedSecrets = null;
let cacheTimestamp = null;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Valider qu'une URL est sûre
function isValidVaultUrl(url) {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
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

// Trouver les credentials pour une URL
async function getCredentialsForUrl(url) {
  if (!vaultClient) {
    const initialized = await initVaultClient();
    if (!initialized) {
      return [];
    }
  }

  try {
    // Utiliser le cache si valide
    if (isCacheValid()) {
      return filterSecretsByUrl(cachedSecrets, url);
    }

    // Sinon, rafraîchir le cache
    await refreshSecretsCache();
    return filterSecretsByUrl(cachedSecrets, url);
  } catch (err) {
    console.error('Error getting credentials');
    return [];
  }
}

// Filtrer les secrets par URL (similaire à findSecretsByUrl mais en local)
function filterSecretsByUrl(secrets, targetUrl) {
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname.toLowerCase();

    return secrets.filter(secret => {
      // Vérifier le champ Website
      if (secret.website) {
        try {
          const secretUrl = new URL(secret.website.startsWith('http')
            ? secret.website
            : `https://${secret.website}`);
          const secretHostname = secretUrl.hostname.toLowerCase();

          if (secretHostname === hostname || hostname.endsWith(`.${secretHostname}`)) {
            return true;
          }
        } catch {
          // SÉCURITÉ: Comparaison stricte au lieu de .includes() pour éviter le matching partiel
          if (secret.website.toLowerCase() === hostname) {
            return true;
          }
        }
      }

      // Vérifier le champ URL (fallback)
      if (secret.url) {
        try {
          const secretUrl = new URL(secret.url.startsWith('http')
            ? secret.url
            : `https://${secret.url}`);
          const secretHostname = secretUrl.hostname.toLowerCase();

          if (secretHostname === hostname || hostname.endsWith(`.${secretHostname}`)) {
            return true;
          }
        } catch {
          // SÉCURITÉ: Comparaison stricte au lieu de .includes() pour éviter le matching partiel
          if (secret.url.toLowerCase() === hostname) {
            return true;
          }
        }
      }

      return false;
    });
  } catch (err) {
    console.error('Error filtering secrets by URL');
    return [];
  }
}

// Écouter les messages depuis content script et popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // SÉCURITÉ: Vérifier que le message vient de notre extension
  if (!sender || sender.id !== chrome.runtime.id) {
    sendResponse({ success: false, error: 'Source non autorisée' });
    return false;
  }

  // Utiliser une fonction async pour gérer les promesses
  (async () => {
    try {
      switch (request.type) {
        case 'GET_CREDENTIALS':
          const credentials = await getCredentialsForUrl(request.url);
          sendResponse({ success: true, credentials });
          break;

        case 'LOGIN':
          try {
            if (!isValidVaultUrl(request.vaultUrl)) {
              sendResponse({ success: false, error: 'URL Vault invalide' });
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
            sendResponse({ success: false, error: 'Authentification échouée' });
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

        case 'CHECK_AUTH':
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

        case 'REFRESH_CACHE':
          await refreshSecretsCache();
          sendResponse({ success: true, count: cachedSecrets?.length || 0 });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown request type' });
      }
    } catch (err) {
      console.error('Error handling message');
      sendResponse({ success: false, error: 'Erreur interne' });
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
