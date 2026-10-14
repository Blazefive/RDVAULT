/**
 * popup.js - Interface popup de l'extension RDVAULT
 *
 * Affiche le statut de connexion avec l'application Desktop RDVAULT.
 * Les changements d'état sont annoncés aux lecteurs d'écran (#statusCard, région « status »).
 * Actualise automatiquement toutes les 10 secondes (2 s pendant l'appairage).
 *
 * @author Vault Autofill Team
 * @version 2.1.0
 */

/* global chrome */ // API d'extension (page de la popup)
'use strict'; // eslint-disable-line strict -- script classique de la popup, pas un module ES

/** Intervalle de vérification du statut (ms) */
const STATUS_POLL_INTERVAL_MS = 10000;

/** Intervalle pendant l'attente d'appairage (aucun appel réseau : le background répond en mémoire) */
const PAIRING_POLL_INTERVAL_MS = 2000;

/**
 * Texte traduit dans la langue du navigateur (chrome.i18n, _locales/<langue>/messages.json,
 * repli « en »). `fallback` est le texte français d'origine, identique à _locales/fr : il ne
 * sert que hors extension (tests) ; $1… y sont remplacés comme par Chrome.
 *
 * @param {string} key - Nom du message
 * @param {string} fallback - Texte français (repli)
 * @param {string|string[]} [subs] - Substitutions $1…$9
 * @returns {string}
 */
function msg(key, fallback, subs) {
  const list = subs === undefined ? [] : [].concat(subs).map(String);
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
      const text = chrome.i18n.getMessage(key, list);
      if (text) return text;
    }
  } catch (e) { /* API indisponible : repli */ }
  return fallback.replace(/\$([1-9])/g, (m, n) => (list[n - 1] !== undefined ? list[n - 1] : ''));
}

/**
 * Traduit les textes statiques de popup.html (attribut data-i18n : le texte français du HTML
 * sert de repli) et applique la langue / le sens d'écriture (arabe : de droite à gauche).
 */
function localizePage() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = msg(el.getAttribute('data-i18n'), el.textContent.replace(/\s+/g, ' ').trim());
  });
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && chrome.i18n.getUILanguage) {
      document.documentElement.lang = chrome.i18n.getUILanguage();
    }
  } catch (e) { /* lang="fr" conservé */ }
  document.documentElement.dir = msg('@@bidi_dir', 'ltr');
}

document.addEventListener('DOMContentLoaded', async () => {
  localizePage();

  // ============================================================================
  // ÉLÉMENTS DOM
  // ============================================================================

  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  const statusDetails = document.getElementById('statusDetails');

  let pollTimer = null;

  /** Dernier état affiché (voir stateChanged) : « Vérification... » au chargement */
  let lastStateKey = 'checking';

  /**
   * Demande d'appairage expirée sans réponse dans RDVAULT pendant que la popup est ouverte (EXT-25) :
   * signalée par le service worker sur le port 'rdvault-popup'. Reste affichée jusqu'à la fermeture de la
   * popup ; sa réouverture (nouveau port) autorise une nouvelle demande.
   */
  let pairingExpired = false;

  // ============================================================================
  // UTILITAIRES
  // ============================================================================

  /**
   * Crée un élément DOM de manière sécurisée
   *
   * @param {string} tag - Nom de la balise
   * @param {Object} attrs - Attributs à appliquer
   * @param {string|Node|Node[]} content - Contenu
   * @returns {HTMLElement}
   */
  function createElement(tag, attrs = {}, content = null) {
    const element = document.createElement(tag);

    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'className') {
        element.className = value;
      } else if (key === 'style' && typeof value === 'object') {
        Object.assign(element.style, value);
      } else {
        element.setAttribute(key, String(value));
      }
    }

    if (content !== null) {
      if (typeof content === 'string') {
        element.textContent = content;
      } else if (Array.isArray(content)) {
        content.forEach(child => {
          if (child instanceof Node) element.appendChild(child);
        });
      } else if (content instanceof Node) {
        element.appendChild(content);
      }
    }

    return element;
  }

  /**
   * Vide le contenu d'un élément de manière sécurisée
   *
   * @param {HTMLElement} element - Élément à vider
   */
  function clearElement(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  /**
   * Programme la prochaine vérification
   *
   * @param {number} delayMs - Délai en ms
   */
  function scheduleNextCheck(delayMs) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(checkDesktopStatus, delayMs);
  }

  // ============================================================================
  // GESTION DU STATUT
  // ============================================================================

  /**
   * Vérifie le statut de connexion avec l'application Desktop
   */
  async function checkDesktopStatus() {
    let nextDelay = STATUS_POLL_INTERVAL_MS;

    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_AUTH' });

      if (response && response.authenticated) {
        showConnected(response);
      } else if (pairingExpired || (response && response.pairing === 'expired')) {
        showPairingExpired();
      } else if (response && response.pairing === 'connecting') {
        // Demande de token en cours, sans réponse encore : ni « appairage envoyé » ni « indisponible »
        showChecking();
        nextDelay = PAIRING_POLL_INTERVAL_MS;
      } else if (response && response.pairing === 'pending') {
        showPairingPending();
        nextDelay = PAIRING_POLL_INTERVAL_MS;
      } else if (response && response.pairing === 'denied') {
        showPairingDenied();
      } else if (response && response.reachable === false) {
        showDisconnected(msg('popupDesktopUnavailable', 'Desktop non disponible'));
      } else {
        showDisconnected(msg('popupDesktopNotConnected', 'Desktop démarré mais non connecté'));
      }
    } catch (err) {
      showDisconnected(msg('popupDesktopUnavailable', 'Desktop non disponible'));
    }

    scheduleNextCheck(nextDelay);
  }

  /**
   * Annonce aux lecteurs d'écran (#statusCard : role="status", aria-live="polite") : le contenu
   * n'est réécrit que si l'état affiché change, sinon chaque rafraîchissement (10 s) serait relu.
   *
   * @param {string} key - Identifiant de l'état affiché (type + détails)
   * @returns {boolean} true si l'état a changé et doit être affiché
   */
  function stateChanged(key) {
    if (key === lastStateKey) return false;
    lastStateKey = key;
    return true;
  }

  /**
   * Affiche « Vérification... » (demande en cours auprès de RDVAULT)
   */
  function showChecking() {
    if (!stateChanged('checking')) return;
    statusIcon.className = 'status-icon pending';
    statusText.textContent = msg('popupStatusChecking', 'Vérification...');
    clearElement(statusDetails);
  }

  /**
   * Affiche l'état connecté
   *
   * @param {Object} data - Données de connexion (username, vaultUrl)
   */
  function showConnected(data) {
    if (!stateChanged(JSON.stringify(['connected', data.username || '', data.vaultUrl || '']))) return;
    statusIcon.className = 'status-icon connected';
    statusText.textContent = msg('popupDesktopConnected', 'Desktop connecté');

    clearElement(statusDetails);

    // Ligne utilisateur (libellé traduit suivi d'une espace, comme auparavant)
    const userLine = createElement('p');
    userLine.appendChild(createElement('strong', {}, msg('popupUserLabel', 'Utilisateur:') + ' '));
    userLine.appendChild(document.createTextNode(data.username || msg('popupUnknown', 'Inconnu')));
    statusDetails.appendChild(userLine);

    // Ligne serveur
    const serverLine = createElement('p');
    serverLine.appendChild(createElement('strong', {}, msg('popupServerLabel', 'Serveur:') + ' '));
    serverLine.appendChild(document.createTextNode(data.vaultUrl || msg('popupUnknown', 'Inconnu')));
    statusDetails.appendChild(serverLine);

    // Ligne statut actif
    statusDetails.appendChild(createElement('p', {
      style: { color: '#10b981', marginTop: '8px' }
    }, msg('popupAutofillActive', '✓ Auto-remplissage actif')));
  }

  /**
   * Affiche l'état "appairage en attente de confirmation dans RDVAULT"
   */
  function showPairingPending() {
    if (!stateChanged('pending')) return;
    statusIcon.className = 'status-icon pending';
    statusText.textContent = msg('popupPairingPendingTitle', 'Confirmez l\'accès dans l\'application RDVAULT');

    clearElement(statusDetails);

    statusDetails.appendChild(createElement('p', {
      style: { color: '#b45309' }
    }, msg('popupPairingPendingDetail', 'Une demande d\'appairage a été envoyée à RDVAULT. Acceptez-la dans l\'application (délai : 60 secondes) pour activer l\'auto-remplissage.')));
  }

  /**
   * Affiche l'état "accès refusé dans RDVAULT"
   */
  function showPairingDenied() {
    if (!stateChanged('denied')) return;
    statusIcon.className = 'status-icon disconnected';
    statusText.textContent = msg('popupPairingDeniedTitle', 'Accès refusé dans RDVAULT');

    clearElement(statusDetails);

    statusDetails.appendChild(createElement('p', {
      style: { color: '#ef4444' }
    }, msg('popupPairingDeniedDetail', 'L\'appairage de cette extension a été refusé dans l\'application. Une nouvelle demande sera possible dans une minute.')));
  }

  /**
   * Affiche l'état "demande d'appairage expirée" (boîte de RDVAULT fermée sans réponse, EXT-25)
   */
  function showPairingExpired() {
    if (!stateChanged('expired')) return;
    statusIcon.className = 'status-icon disconnected';
    statusText.textContent = msg('popupPairingExpiredTitle', 'Demande d\'appairage expirée : rouvrez l\'extension pour réessayer');

    clearElement(statusDetails);

    statusDetails.appendChild(createElement('p', {
      style: { color: '#b45309' }
    }, msg('popupPairingExpiredDetail', 'La demande n\'a pas reçu de réponse dans RDVAULT (délai : 60 secondes). Fermez puis rouvrez cette fenêtre pour envoyer une nouvelle demande.')));
  }

  /**
   * Ouvre le port 'rdvault-popup' vers le service worker : sa connexion signale la (ré)ouverture de la
   * popup (une demande d'appairage expirée peut être renouvelée) ; il transporte l'état « expiré » (EXT-25).
   * Sans service worker récent (port refusé), la popup fonctionne comme avant.
   */
  function connectPopupPort() {
    try {
      if (typeof chrome === 'undefined' || !chrome.runtime || typeof chrome.runtime.connect !== 'function') return;
      const port = chrome.runtime.connect({ name: 'rdvault-popup' });
      port.onMessage.addListener((message) => {
        if (message && message.type === 'PAIRING_STATE' && message.state === 'expired') {
          pairingExpired = true;
          showPairingExpired();
          scheduleNextCheck(STATUS_POLL_INTERVAL_MS);
        }
      });
    } catch (err) {
      // Port indisponible : affichage habituel
    }
  }

  /**
   * Affiche l'état déconnecté
   *
   * @param {string} message - Message de statut
   */
  function showDisconnected(message) {
    if (!stateChanged(JSON.stringify(['disconnected', message]))) return;
    statusIcon.className = 'status-icon disconnected';
    statusText.textContent = message;

    clearElement(statusDetails);

    statusDetails.appendChild(createElement('p', {
      style: { color: '#ef4444' }
    }, msg('popupDisconnectedDetail', 'Lancez l\'application Desktop et connectez-vous pour utiliser l\'auto-remplissage.')));
  }

  // ============================================================================
  // INITIALISATION
  // ============================================================================

  // Port vers le service worker AVANT la première vérification : une demande d'appairage expirée est
  // renouvelable dès cette ouverture (EXT-25)
  connectPopupPort();

  // Vérifier au démarrage (programme ensuite les vérifications suivantes)
  await checkDesktopStatus();
});
