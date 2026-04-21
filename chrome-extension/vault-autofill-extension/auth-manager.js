/**
 * auth-manager.js - Gestionnaire d'authentification pour Vault Autofill
 *
 * Ce module gère l'authentification avec le serveur sync local de l'application Desktop.
 * Il maintient un token d'authentification et le rafraîchit automatiquement.
 *
 * Architecture :
 * - Pattern Singleton pour l'instance AuthManager
 * - Stockage sécurisé du token dans chrome.storage.session (non persisté)
 * - Rafraîchissement automatique toutes les 60 secondes
 * - Retry automatique en cas d'échec de requête authentifiée
 *
 * @author Vault Autofill Team
 * @version 2.0.0
 */

'use strict';

// ============================================================================
// CONFIGURATION
// ============================================================================

/** URL de base du serveur sync local */
const SYNC_API_BASE = 'http://127.0.0.1:45678';

/** Clé de stockage pour le token d'authentification */
const TOKEN_STORAGE_KEY = 'vault_sync_auth_token';

/** Intervalle de rafraîchissement du token (ms) */
const TOKEN_REFRESH_INTERVAL_MS = 60000; // 60 secondes

/** Timeout pour les requêtes HTTP (ms) */
const REQUEST_TIMEOUT_MS = 10000; // 10 secondes

/** Nombre maximum de tentatives de récupération de token */
const MAX_TOKEN_FETCH_RETRIES = 3;

// ============================================================================
// CLASSE AUTHMANAGER
// ============================================================================

/**
 * Gestionnaire d'authentification pour le serveur sync
 *
 * Responsabilités :
 * - Stockage et récupération du token d'authentification
 * - Rafraîchissement automatique du token
 * - Encapsulation des requêtes authentifiées
 *
 * @class
 */
class AuthManager {
  /**
   * Crée une nouvelle instance AuthManager
   * Note : Utiliser l'instance singleton 'authManager' exportée
   */
  constructor() {
    /**
     * Token d'authentification actuel
     * @type {string|null}
     * @private
     */
    this._authToken = null;

    /**
     * Timer pour le rafraîchissement périodique
     * @type {number|null}
     * @private
     */
    this._refreshTimer = null;

    /**
     * Flag indiquant si le manager est démarré
     * @type {boolean}
     * @private
     */
    this._isStarted = false;

    /**
     * Promise partagée pour éviter les rafraîchissements concurrents
     * @type {Promise|null}
     * @private
     */
    this._refreshPromise = null;
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PUBLIQUES
  // --------------------------------------------------------------------------

  /**
   * Démarre le gestionnaire d'authentification
   *
   * Actions effectuées :
   * 1. Charge le token depuis le storage s'il existe
   * 2. Récupère un nouveau token si nécessaire
   * 3. Démarre le rafraîchissement périodique
   *
   * @returns {Promise<void>}
   * @throws {Error} Si impossible d'obtenir un token
   */
  async start() {
    if (this._isStarted) {
      console.log('[AuthManager] Déjà démarré');
      return;
    }

    console.log('[AuthManager] Démarrage...');

    // Charger le token existant
    const hasToken = await this._loadTokenFromStorage();

    // Récupérer un nouveau token si nécessaire
    if (!hasToken) {
      const success = await this._fetchNewToken();
      if (!success) {
        throw new Error('Impossible d\'obtenir un token d\'authentification');
      }
    }

    // Démarrer le rafraîchissement périodique
    this._startTokenRefresh();

    this._isStarted = true;
    console.log('[AuthManager] Démarré avec succès');
  }

  /**
   * Arrête le gestionnaire d'authentification
   *
   * Nettoie les timers et ressources
   */
  stop() {
    if (this._refreshTimer) {
      clearInterval(this._refreshTimer);
      this._refreshTimer = null;
    }

    this._isStarted = false;
    console.log('[AuthManager] Arrêté');
  }

  /**
   * Retourne le token d'authentification actuel
   *
   * @returns {string|null} Token ou null si non authentifié
   */
  getToken() {
    return this._authToken;
  }

  /**
   * Effectue une requête HTTP authentifiée
   *
   * Ajoute automatiquement l'en-tête Authorization avec le Bearer token.
   * En cas de réponse 401, tente de rafraîchir le token et réessaie.
   *
   * @param {string} url - URL de la requête
   * @param {Object} options - Options fetch (méthode, body, headers, etc.)
   * @returns {Promise<Response>} Réponse de la requête
   * @throws {Error} Si impossible d'authentifier la requête
   */
  async authenticatedFetch(url, options = {}) {
    // S'assurer qu'on a un token
    if (!this._authToken) {
      const success = await this._fetchNewToken();
      if (!success) {
        throw new Error('Impossible d\'obtenir un token d\'authentification');
      }
    }

    // Préparer les options avec le header Authorization
    const authenticatedOptions = this._prepareAuthenticatedOptions(options);

    // Effectuer la requête
    let response;
    try {
      response = await this._fetchWithTimeout(url, authenticatedOptions);
    } catch (err) {
      console.warn('[AuthManager] Erreur réseau');
      throw err;
    }

    // Si 401, le token est expiré/invalide
    if (response.status === 401) {
      console.warn('[AuthManager] Token invalide (401), rafraîchissement...');

      const refreshSuccess = await this._fetchNewToken();
      if (!refreshSuccess) {
        throw new Error('Impossible de rafraîchir le token');
      }

      // Réessayer avec le nouveau token
      const retryOptions = this._prepareAuthenticatedOptions(options);
      return await this._fetchWithTimeout(url, retryOptions);
    }

    return response;
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PRIVÉES - GESTION DU TOKEN
  // --------------------------------------------------------------------------

  /**
   * Charge le token depuis chrome.storage.local
   *
   * @returns {Promise<boolean>} True si un token valide a été chargé
   * @private
   */
  async _loadTokenFromStorage() {
    try {
      // SÉCURITÉ: Utiliser storage.session (non persisté entre sessions navigateur)
      const result = await chrome.storage.session.get(TOKEN_STORAGE_KEY);

      if (result[TOKEN_STORAGE_KEY]) {
        this._authToken = result[TOKEN_STORAGE_KEY];
        return true;
      }
    } catch (err) {
      console.error('[AuthManager] Erreur chargement token');
    }

    return false;
  }

  /**
   * Sauvegarde le token dans chrome.storage.local
   *
   * @returns {Promise<boolean>} True si la sauvegarde a réussi
   * @private
   */
  async _saveTokenToStorage() {
    if (!this._authToken) {
      return false;
    }

    try {
      // SÉCURITÉ: Utiliser storage.session (non persisté entre sessions navigateur)
      await chrome.storage.session.set({
        [TOKEN_STORAGE_KEY]: this._authToken
      });
      return true;
    } catch (err) {
      console.error('[AuthManager] Erreur sauvegarde token');
      return false;
    }
  }

  /**
   * Récupère un nouveau token depuis le serveur
   *
   * Effectue plusieurs tentatives en cas d'échec (MAX_TOKEN_FETCH_RETRIES)
   *
   * @returns {Promise<boolean>} True si un nouveau token a été obtenu
   * @private
   */
  async _fetchNewToken() {
    // SÉCURITÉ: Partager la promesse pour éviter les appels concurrents (pas de race condition)
    if (this._refreshPromise) {
      return this._refreshPromise;
    }

    this._refreshPromise = this._doFetchNewToken();
    try {
      return await this._refreshPromise;
    } finally {
      this._refreshPromise = null;
    }
  }

  async _doFetchNewToken() {
    try {
      console.log('[AuthManager] Récupération d\'un nouveau token...');

      for (let attempt = 1; attempt <= MAX_TOKEN_FETCH_RETRIES; attempt++) {
        try {
          const response = await this._fetchWithTimeout(
            `${SYNC_API_BASE}/auth/token`,
            { method: 'GET', headers: { 'X-Vault-Extension': 'rdvault' } }
          );

          if (response.status === 503) {
            console.warn(`[AuthManager] Tentative ${attempt}: serveur pas prêt (503)`);
          } else if (!response.ok) {
            console.warn(`[AuthManager] Tentative ${attempt}: HTTP ${response.status}`);
          } else {
            const data = await response.json();

            if (data && data.token && typeof data.token === 'string' && data.token.length > 0 && data.token.length <= 512) {
              this._authToken = data.token;
              await this._saveTokenToStorage();
              console.log('[AuthManager] Nouveau token obtenu');
              return true;
            }

            console.warn(`[AuthManager] Tentative ${attempt}: Token absent de la réponse`);
          }
        } catch (err) {
          console.warn(`[AuthManager] Tentative ${attempt}: erreur réseau (l'application Desktop est-elle lancée ?)`);
        }

        if (attempt < MAX_TOKEN_FETCH_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
      }

      console.error('[AuthManager] Échec récupération token après', MAX_TOKEN_FETCH_RETRIES, 'tentatives. Vérifiez que RDVAULT Desktop est lancé.');
      this._authToken = null;
      return false;
    } catch (err) {
      this._authToken = null;
      return false;
    }
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PRIVÉES - RAFRAÎCHISSEMENT PÉRIODIQUE
  // --------------------------------------------------------------------------

  /**
   * Démarre le rafraîchissement périodique du token
   *
   * Vérifie la validité du token à intervalles réguliers
   * et le renouvelle si nécessaire
   *
   * @private
   */
  _startTokenRefresh() {
    // Nettoyer un éventuel timer existant
    if (this._refreshTimer) {
      clearInterval(this._refreshTimer);
    }

    this._refreshTimer = setInterval(async () => {
      console.log('[AuthManager] Vérification périodique du token...');

      const isValid = await this._testToken();

      if (!isValid) {
        console.warn('[AuthManager] Token invalide, rafraîchissement...');
        await this._fetchNewToken();
      }
    }, TOKEN_REFRESH_INTERVAL_MS);
  }

  /**
   * Teste si le token actuel est toujours valide
   *
   * Effectue une requête de test vers /sync et vérifie la réponse
   *
   * @returns {Promise<boolean>} True si le token est valide
   * @private
   */
  async _testToken() {
    if (!this._authToken) {
      return false;
    }

    try {
      const response = await this._fetchWithTimeout(`${SYNC_API_BASE}/sync`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this._authToken}`
        }
      });

      // 401 = token invalide
      if (response.status === 401) {
        return false;
      }

      // Toute autre réponse (y compris erreurs) = considérer le token comme valide
      // (le serveur peut être temporairement indisponible)
      return true;
    } catch (err) {
      // Erreur réseau - considérer le token comme valide
      // pour éviter de le régénérer inutilement
      console.warn('[AuthManager] Erreur test token (réseau)');
      return true;
    }
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PRIVÉES - UTILITAIRES
  // --------------------------------------------------------------------------

  /**
   * Prépare les options fetch avec l'en-tête Authorization
   *
   * @param {Object} options - Options fetch originales
   * @returns {Object} Options avec Authorization header
   * @private
   */
  _prepareAuthenticatedOptions(options) {
    const headers = { ...(options.headers || {}) };
    headers['Authorization'] = `Bearer ${this._authToken}`;

    return {
      ...options,
      headers
    };
  }

  /**
   * Effectue une requête fetch avec timeout
   *
   * @param {string} url - URL de la requête
   * @param {Object} options - Options fetch
   * @returns {Promise<Response>} Réponse de la requête
   * @throws {Error} Si timeout ou erreur réseau
   * @private
   */
  async _fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      return response;
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new Error(`Timeout après ${REQUEST_TIMEOUT_MS}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

// ============================================================================
// EXPORT - INSTANCE SINGLETON
// ============================================================================

/**
 * Instance singleton du gestionnaire d'authentification
 *
 * Utiliser cette instance dans tout le code de l'extension :
 * @example
 * await authManager.start();
 * const response = await authManager.authenticatedFetch('/api/endpoint');
 *
 * @type {AuthManager}
 */
const authManager = new AuthManager();

// Export pour utilisation dans background.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { authManager, AuthManager };
}
