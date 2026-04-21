// sync-helper.js
// Helper pour synchroniser l'état de connexion entre Desktop et Extension
// SÉCURITÉ: Utilise chrome.storage.session (non persisté entre sessions navigateur)
// au lieu de localStorage (accessible par d'autres scripts de la page)

const SYNC_KEY = 'vault-client-sync';
const SYNC_CHECK_INTERVAL = 2000; // Vérifier toutes les 2 secondes

// Écrire l'état de connexion (utilisé par l'app Desktop)
async function writeSyncState(state) {
  try {
    await chrome.storage.session.set({
      [SYNC_KEY]: JSON.stringify({
        ...state,
        timestamp: Date.now()
      })
    });
  } catch (err) {
    // Ignorer silencieusement les erreurs
  }
}

// Lire l'état de connexion (utilisé par l'extension)
async function readSyncState() {
  try {
    const result = await chrome.storage.session.get(SYNC_KEY);
    const data = result[SYNC_KEY];
    if (!data) return null;

    const state = JSON.parse(data);

    // Vérifier que l'état n'est pas trop vieux (max 30 secondes)
    if (Date.now() - state.timestamp > 30000) {
      return null;
    }

    return state;
  } catch (err) {
    return null;
  }
}

// Nettoyer l'état de synchronisation (utilisé lors de la déconnexion)
async function clearSyncState() {
  try {
    await chrome.storage.session.remove(SYNC_KEY);
  } catch (err) {
    // Ignorer silencieusement les erreurs
  }
}

// Exporter pour utilisation
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { writeSyncState, readSyncState, clearSyncState, SYNC_CHECK_INTERVAL };
}
