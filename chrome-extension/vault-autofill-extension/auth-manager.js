/**
 * auth-manager.js - Gestionnaire d'authentification pour Vault Autofill
 *
 * Ce module gère l'authentification avec le serveur sync local de l'application Desktop.
 * Il maintient un token d'authentification et le rafraîchit automatiquement.
 *
 * Architecture :
 * - Pattern Singleton pour l'instance AuthManager
 * - Stockage du token dans chrome.storage.session (non persisté)
 * - Vérification périodique via chrome.alarms (compatible service worker MV3)
 * - Appairage : à la première demande de token, l'application Desktop demande
 *   une confirmation à l'utilisateur (jusqu'à 60 s). Le fetch attend donc 65 s.
 * - Retry automatique en cas d'échec de requête authentifiée :
 *     401                          → token invalide (Desktop redémarré : nouveau token de session),
 *                                    nouvelle demande de token, sans boîte de dialogue si l'extension
 *                                    est toujours appairée (paired-extensions.json)
 *     403 {error:'pairing_required'} → extension plus appairée (fichier d'appairage supprimé), nouvel appairage
 * - Demande d'appairage EXPIRÉE (403 {error:'pairing_timeout'}, boîte restée sans réponse 60 s, EXT-25) :
 *   distincte d'un refus, sans délai de carence ; aucune nouvelle demande automatique (pas de boîte de
 *   dialogue relancée à chaque onglet) jusqu'à la réouverture de la popup (port 'rdvault-popup').
 *
 * @author Vault Autofill Team
 * @version 2.1.0
 */

/* global chrome */ // API d'extension (service worker, chargé par importScripts)
'use strict'; // eslint-disable-line strict -- script classique chargé par importScripts, pas un module ES

// ============================================================================
// CONFIGURATION
// ============================================================================

/** URL de base du serveur sync local */
const SYNC_API_BASE = 'http://127.0.0.1:45678';

/** Clé de stockage pour le token d'authentification */
const TOKEN_STORAGE_KEY = 'vault_sync_auth_token';

/** Nom de l'alarme de vérification périodique du token */
const TOKEN_REFRESH_ALARM = 'vault-token-refresh';

/** Période de vérification du token (minutes) — minimum autorisé par chrome.alarms */
const TOKEN_REFRESH_PERIOD_MINUTES = 1;

/** Timeout pour les requêtes HTTP courantes (ms) */
const REQUEST_TIMEOUT_MS = 10000; // 10 secondes

/**
 * Timeout pour la demande de token (ms)
 * L'application Desktop affiche une boîte de dialogue d'approbation (jusqu'à 60 s)
 * lors de la première demande d'un ID d'extension : on attend au moins 65 s.
 */
const TOKEN_REQUEST_TIMEOUT_MS = 65000;

/** Nombre maximum de tentatives de récupération de token (503 / erreur réseau) */
const MAX_TOKEN_FETCH_RETRIES = 3;

/** Délai avant une nouvelle demande de token après un refus ou un délai dépassé (ms) */
const PAIRING_COOLDOWN_MS = 60000;

/** Délai avant une nouvelle demande de token quand le Desktop est injoignable (ms) */
const UNAVAILABLE_COOLDOWN_MS = 10000;

/** Intervalle du keep-alive du service worker pendant l'attente d'appairage (ms) */
const KEEPALIVE_INTERVAL_MS = 20000;

/**
 * Délai après lequel une demande de token encore en cours est considérée comme « en attente
 * de confirmation dans RDVAULT » (ms). Une application fermée refuse la connexion en quelques
 * millisecondes ; la boîte d'appairage, elle, garde la requête ouverte (jusqu'à 60 s).
 */
const PAIRING_PENDING_DELAY_MS = 1000;

/**
 * Nom du port ouvert par la popup (chrome.runtime.connect) : sa connexion signale une réouverture de la
 * popup (nouvelle demande d'appairage permise après expiration) et transporte l'état « expiré » (EXT-25).
 */
const POPUP_PORT_NAME = 'rdvault-popup';

/** États possibles de l'appairage avec l'application Desktop */
const PAIRING_STATE = Object.freeze({
  IDLE: 'idle',
  // Demande de token envoyée, réponse pas encore reçue (moins de PAIRING_PENDING_DELAY_MS)
  CONNECTING: 'connecting',
  PENDING: 'pending',
  OK: 'ok',
  DENIED: 'denied',
  // Boîte d'appairage fermée par le délai, sans réponse de l'utilisateur (EXT-25) : pas un refus
  EXPIRED: 'expired',
  UNAVAILABLE: 'unavailable'
});

// ============================================================================
// CLASSE AUTHMANAGER
// ============================================================================

/**
 * Gestionnaire d'authentification pour le serveur sync
 *
 * Responsabilités :
 * - Stockage et récupération du token d'authentification
 * - Vérification périodique du token (chrome.alarms)
 * - Encapsulation des requêtes authentifiées
 * - Suivi de l'état d'appairage (en attente / refusé)
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

    /**
     * État courant de l'appairage
     * @type {string}
     * @private
     */
    this._pairingState = PAIRING_STATE.IDLE;

    /**
     * Horodatage avant lequel aucune nouvelle demande de token n'est tentée
     * @type {number}
     * @private
     */
    this._nextTokenAttemptAt = 0;

    /**
     * Ports des popups ouvertes (avertis d'une demande d'appairage expirée)
     * @type {Set<Object>}
     * @private
     */
    this._popupPorts = new Set();
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PUBLIQUES
  // --------------------------------------------------------------------------

  /**
   * Démarre le gestionnaire d'authentification
   *
   * Actions effectuées :
   * 1. Charge le token depuis le storage s'il existe
   * 2. Récupère un nouveau token si nécessaire (peut déclencher l'appairage)
   * 3. Programme la vérification périodique
   *
   * @returns {Promise<void>}
   * @throws {Error} Si impossible d'obtenir un token
   */
  async start() {
    if (this._isStarted) {
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

    // Programmer la vérification périodique
    this._startTokenRefresh();

    this._isStarted = true;
    console.log('[AuthManager] Démarré avec succès');
  }

  /**
   * Arrête le gestionnaire d'authentification
   *
   * Supprime l'alarme de vérification périodique
   */
  stop() {
    try {
      Promise.resolve(chrome.alarms.clear(TOKEN_REFRESH_ALARM)).catch(() => {});
    } catch (err) {
      // Ignorer : API alarms indisponible
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
   * Retourne l'état courant de l'appairage
   *
   * @returns {string} Une des valeurs de PAIRING_STATE
   */
  getPairingState() {
    return this._pairingState;
  }

  /**
   * Indique si une demande d'appairage est en attente de confirmation
   * dans l'application Desktop
   *
   * @returns {boolean}
   */
  isPairingPending() {
    return this._pairingState === PAIRING_STATE.PENDING;
  }

  /**
   * Indique si une demande de token vient d'être envoyée, sans réponse encore
   * (ni appairage en attente, ni échec connus à ce stade)
   *
   * @returns {boolean}
   */
  isConnecting() {
    return this._pairingState === PAIRING_STATE.CONNECTING;
  }

  /**
   * Indique si l'appairage a été refusé récemment dans l'application Desktop
   *
   * @returns {boolean}
   */
  isPairingDenied() {
    return this._pairingState === PAIRING_STATE.DENIED && Date.now() < this._nextTokenAttemptAt;
  }

  /**
   * Indique si la dernière demande d'appairage a expiré sans réponse dans RDVAULT (EXT-25)
   *
   * @returns {boolean}
   */
  isPairingExpired() {
    return this._pairingState === PAIRING_STATE.EXPIRED;
  }

  /**
   * Popup ouverte (port 'rdvault-popup') : une demande d'appairage expirée peut être renouvelée (la
   * prochaine demande de token rouvre la boîte dans RDVAULT) ; la popup est avertie si une demande expire
   * pendant qu'elle est ouverte.
   *
   * @param {Object} port - chrome.runtime.Port
   */
  onPopupConnected(port) {
    if (!port || port.name !== POPUP_PORT_NAME) return;
    if (this._pairingState === PAIRING_STATE.EXPIRED) {
      this._pairingState = PAIRING_STATE.IDLE;
      this._nextTokenAttemptAt = 0;
    }
    this._popupPorts.add(port);
    try {
      port.onDisconnect.addListener(() => { this._popupPorts.delete(port); });
    } catch (err) {
      // Ignorer : port déjà fermé
    }
  }

  /**
   * Avertit les popups ouvertes de l'état d'appairage courant
   *
   * @private
   */
  _notifyPopups() {
    for (const port of this._popupPorts) {
      try {
        port.postMessage({ type: 'PAIRING_STATE', state: this._pairingState });
      } catch (err) {
        this._popupPorts.delete(port);
      }
    }
  }

  /**
   * Effectue une requête HTTP authentifiée
   *
   * Ajoute automatiquement l'en-tête Authorization avec le Bearer token.
   * - 401 : token expiré/invalide → nouvelle demande de token puis nouvel essai
   * - 403 {error:'pairing_required'} : l'extension n'est plus appairée (appairage
   *   effacé côté Desktop, p. ex. désinstallation) → le token est oublié, un nouvel appairage est demandé
   *   (boîte de dialogue dans RDVAULT) puis la requête est rejouée une fois
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

    // Si 403 pairing_required, l'appairage a été perdu : redemander un token (nouvel appairage)
    if (response.status === 403 && await this._isPairingRequired(response)) {
      console.warn('[AuthManager] Appairage requis (403 pairing_required), nouvelle demande...');

      this._authToken = null;
      this._pairingState = PAIRING_STATE.IDLE;
      this._nextTokenAttemptAt = 0;
      await this._clearTokenFromStorage();

      const pairingSuccess = await this._fetchNewToken();
      if (!pairingSuccess) {
        throw new Error('Appairage avec RDVAULT requis');
      }

      const retryOptions = this._prepareAuthenticatedOptions(options);
      return await this._fetchWithTimeout(url, retryOptions);
    }

    return response;
  }

  /**
   * Indique si une réponse 403 correspond à {error:'pairing_required'}
   * (lecture sur un clone : le corps original reste lisible par l'appelant)
   *
   * @param {Response} response - Réponse HTTP
   * @returns {Promise<boolean>}
   * @private
   */
  async _isPairingRequired(response) {
    return (await this._errorCode(response)) === 'pairing_required';
  }

  /**
   * Indique si une réponse 403 correspond à {error:'pairing_timeout'} (demande d'appairage expirée, EXT-25)
   *
   * @param {Response} response - Réponse HTTP
   * @returns {Promise<boolean>}
   * @private
   */
  async _isPairingTimeout(response) {
    return (await this._errorCode(response)) === 'pairing_timeout';
  }

  /**
   * Code d'erreur {error} d'une réponse JSON, lu sur un clone (corps original intact) ; null si illisible
   *
   * @param {Response} response - Réponse HTTP
   * @returns {Promise<string|null>}
   * @private
   */
  async _errorCode(response) {
    try {
      const data = await response.clone().json();
      return data && typeof data.error === 'string' ? data.error : null;
    } catch (err) {
      return null;
    }
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PRIVÉES - GESTION DU TOKEN
  // --------------------------------------------------------------------------

  /**
   * Charge le token depuis chrome.storage.session
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
        this._pairingState = PAIRING_STATE.OK;
        return true;
      }
    } catch (err) {
      console.error('[AuthManager] Erreur chargement token');
    }

    return false;
  }

  /**
   * Sauvegarde le token dans chrome.storage.session
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
   * Supprime le token du storage
   *
   * @private
   */
  async _clearTokenFromStorage() {
    try {
      await chrome.storage.session.remove(TOKEN_STORAGE_KEY);
    } catch (err) {
      // Ignorer
    }
  }

  /**
   * Récupère un nouveau token depuis le serveur
   *
   * Partage la promesse en cours pour éviter les demandes concurrentes
   * (et donc plusieurs boîtes de dialogue d'appairage).
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

  /**
   * Implémentation de la demande de token
   *
   * Réponses du serveur :
   * - 200 {token}                  : token obtenu
   * - 403 {error:'pairing_denied'} : l'utilisateur a refusé l'accès dans RDVAULT
   * - 403 {error:'pairing_timeout'}: boîte d'appairage expirée sans réponse (EXT-25) → état EXPIRED
   * - 503 {error:'Token not ready'}: serveur pas prêt, nouvelle tentative
   *
   * @returns {Promise<boolean>}
   * @private
   */
  async _doFetchNewToken() {
    // Demande d'appairage expirée (EXT-25) : aucune nouvelle demande automatique (onglets, alarme) avant la
    // réouverture de la popup, sinon la boîte de dialogue réapparaîtrait sans action de l'utilisateur
    if (this._pairingState === PAIRING_STATE.EXPIRED) {
      return false;
    }

    // Respecter le délai de carence après un refus / délai dépassé / Desktop injoignable
    if (Date.now() < this._nextTokenAttemptAt) {
      return false;
    }

    // Maintenir le service worker en vie pendant l'attente d'approbation (jusqu'à 65 s)
    const keepAlive = setInterval(() => {
      try {
        chrome.runtime.getPlatformInfo(() => {});
      } catch (err) {
        // Ignorer
      }
    }, KEEPALIVE_INTERVAL_MS);

    try {
      console.log('[AuthManager] Demande de token (confirmez l\'accès dans RDVAULT si demandé)...');

      for (let attempt = 1; attempt <= MAX_TOKEN_FETCH_RETRIES; attempt++) {
        try {
          // « En attente de confirmation » seulement si la requête est encore ouverte après
          // PAIRING_PENDING_DELAY_MS (boîte d'appairage affichée) : une application fermée échoue
          // aussitôt et la popup ne doit pas annoncer une demande d'appairage jamais reçue (EXT-25)
          this._pairingState = PAIRING_STATE.CONNECTING;
          const pendingTimer = setTimeout(() => {
            if (this._pairingState === PAIRING_STATE.CONNECTING) this._pairingState = PAIRING_STATE.PENDING;
          }, PAIRING_PENDING_DELAY_MS);

          let response;
          try {
            response = await this._fetchWithTimeout(
              `${SYNC_API_BASE}/auth/token`,
              { method: 'GET', headers: { 'X-Vault-Extension': 'rdvault' } },
              TOKEN_REQUEST_TIMEOUT_MS
            );
          } finally {
            clearTimeout(pendingTimer);
          }

          if (response.status === 403 && await this._isPairingTimeout(response)) {
            // Boîte d'appairage fermée par le délai sans réponse (EXT-25) : pas un refus, pas de carence
            console.warn('[AuthManager] Demande d\'appairage expirée (pairing_timeout)');
            this._pairingState = PAIRING_STATE.EXPIRED;
            this._nextTokenAttemptAt = 0;
            this._authToken = null;
            await this._clearTokenFromStorage();
            this._notifyPopups();
            return false;
          }

          if (response.status === 403) {
            // L'utilisateur a refusé l'appairage dans l'application Desktop
            console.warn('[AuthManager] Accès refusé dans RDVAULT (pairing_denied)');
            this._pairingState = PAIRING_STATE.DENIED;
            this._nextTokenAttemptAt = Date.now() + PAIRING_COOLDOWN_MS;
            this._authToken = null;
            await this._clearTokenFromStorage();
            return false;
          }

          if (response.status === 503) {
            console.warn(`[AuthManager] Tentative ${attempt}: serveur pas prêt (503)`);
          } else if (!response.ok) {
            console.warn(`[AuthManager] Tentative ${attempt}: HTTP ${response.status}`);
          } else {
            const data = await response.json();

            if (data && typeof data.token === 'string' && data.token.length > 0 && data.token.length <= 512) {
              this._authToken = data.token;
              this._pairingState = PAIRING_STATE.OK;
              this._nextTokenAttemptAt = 0;
              await this._saveTokenToStorage();
              console.log('[AuthManager] Nouveau token obtenu');
              return true;
            }

            console.warn(`[AuthManager] Tentative ${attempt}: Token absent de la réponse`);
          }
        } catch (err) {
          if (err && err.name === 'TimeoutError') {
            // L'utilisateur n'a pas répondu à la demande d'appairage dans le délai :
            // ne pas relancer immédiatement une nouvelle boîte de dialogue
            console.warn('[AuthManager] Délai d\'appairage dépassé (aucune réponse dans RDVAULT)');
            this._pairingState = PAIRING_STATE.UNAVAILABLE;
            this._nextTokenAttemptAt = Date.now() + PAIRING_COOLDOWN_MS;
            this._authToken = null;
            return false;
          }
          console.warn(`[AuthManager] Tentative ${attempt}: erreur réseau (l'application Desktop est-elle lancée ?)`);
          // Application injoignable : « indisponible » dès l'attente avant la tentative suivante
          this._pairingState = PAIRING_STATE.UNAVAILABLE;
        }

        if (attempt < MAX_TOKEN_FETCH_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        }
      }

      console.error('[AuthManager] Échec récupération token après', MAX_TOKEN_FETCH_RETRIES, 'tentatives. Vérifiez que RDVAULT Desktop est lancé.');
      this._pairingState = PAIRING_STATE.UNAVAILABLE;
      this._nextTokenAttemptAt = Date.now() + UNAVAILABLE_COOLDOWN_MS;
      this._authToken = null;
      return false;
    } catch (err) {
      this._pairingState = PAIRING_STATE.UNAVAILABLE;
      this._nextTokenAttemptAt = Date.now() + UNAVAILABLE_COOLDOWN_MS;
      this._authToken = null;
      return false;
    } finally {
      clearInterval(keepAlive);
    }
  }

  // --------------------------------------------------------------------------
  // MÉTHODES PRIVÉES - VÉRIFICATION PÉRIODIQUE (chrome.alarms)
  // --------------------------------------------------------------------------

  /**
   * Programme la vérification périodique du token via chrome.alarms
   *
   * Contrairement à setInterval, une alarme survit à la mise en veille
   * du service worker MV3.
   *
   * @private
   */
  _startTokenRefresh() {
    try {
      Promise.resolve(chrome.alarms.create(TOKEN_REFRESH_ALARM, {
        delayInMinutes: TOKEN_REFRESH_PERIOD_MINUTES,
        periodInMinutes: TOKEN_REFRESH_PERIOD_MINUTES
      })).catch(() => {});
    } catch (err) {
      console.warn('[AuthManager] Impossible de créer l\'alarme de vérification');
    }
  }

  /**
   * Handler de l'alarme périodique : vérifie le token et le renouvelle si invalide
   *
   * Ne déclenche jamais une demande d'appairage non sollicitée : si aucun token
   * n'est connu, la demande sera faite lors de la prochaine requête utilisateur.
   *
   * @returns {Promise<void>}
   * @private
   */
  async _onRefreshAlarm() {
    if (!this._authToken) {
      await this._loadTokenFromStorage();
    }

    if (!this._authToken) {
      return;
    }

    const isValid = await this._testToken();

    if (!isValid) {
      console.warn('[AuthManager] Token invalide ou appairage perdu, rafraîchissement...');
      this._authToken = null;
      await this._clearTokenFromStorage();
      await this._fetchNewToken();
    }
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

      // 403 pairing_required = extension plus appairée (appairage effacé côté Desktop) : token à renouveler
      if (response.status === 403 && await this._isPairingRequired(response)) {
        return false;
      }

      // Toute autre réponse (y compris erreurs) = considérer le token comme valide
      // (le serveur peut être temporairement indisponible)
      return true;
    } catch (err) {
      // Erreur réseau - considérer le token comme valide
      // pour éviter de le régénérer inutilement
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
   * Effectue une requête fetch avec timeout (AbortController)
   *
   * @param {string} url - URL de la requête
   * @param {Object} options - Options fetch
   * @param {number} timeoutMs - Timeout en ms (défaut : REQUEST_TIMEOUT_MS)
   * @returns {Promise<Response>} Réponse de la requête
   * @throws {Error} Erreur nommée 'TimeoutError' si timeout, sinon erreur réseau
   * @private
   */
  async _fetchWithTimeout(url, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      // Identification explicite de l'extension auprès du serveur desktop : Chrome n'envoie pas
      // d'en-tête Origin sur les hôtes couverts par host_permissions (CORS court-circuité).
      const headers = { ...(options.headers || {}), 'X-Vault-Extension-Id': chrome.runtime.id };
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal
      });
      return response;
    } catch (err) {
      if (err && err.name === 'AbortError') {
        const timeoutError = new Error(`Timeout après ${timeoutMs}ms`);
        timeoutError.name = 'TimeoutError';
        throw timeoutError;
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

// Enregistrement du handler d'alarme au niveau racine du script
// (obligatoire pour qu'il soit rappelé après réveil du service worker)
if (typeof chrome !== 'undefined' && chrome.alarms && chrome.alarms.onAlarm) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm && alarm.name === TOKEN_REFRESH_ALARM) {
      authManager._onRefreshAlarm().catch(() => {});
    }
  });
}

// Popup ouverte : port 'rdvault-popup' (réouverture après une demande d'appairage expirée, EXT-25)
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onConnect) {
  chrome.runtime.onConnect.addListener((port) => {
    if (port && port.name === POPUP_PORT_NAME) authManager.onPopupConnected(port);
  });
}

// Export pour utilisation dans background.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { authManager, AuthManager, PAIRING_STATE, POPUP_PORT_NAME };
}
