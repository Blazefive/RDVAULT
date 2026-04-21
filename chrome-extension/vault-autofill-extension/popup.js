/**
 * popup.js - Interface popup pour Vault Autofill
 *
 * Affiche le statut de connexion avec l'application Desktop Vault.
 * Actualise automatiquement toutes les 2 secondes.
 *
 * @author Vault Autofill Team
 * @version 2.0.0
 */

'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  // ============================================================================
  // ÉLÉMENTS DOM
  // ============================================================================

  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  const statusDetails = document.getElementById('statusDetails');

  // ============================================================================
  // UTILITAIRES DE SÉCURITÉ
  // ============================================================================

  /**
   * Échappe les caractères HTML pour prévenir les attaques XSS
   *
   * @param {string} text - Texte à échapper
   * @returns {string} Texte échappé sécurisé
   */
  function escapeHtml(text) {
    if (!text || typeof text !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

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

  // ============================================================================
  // GESTION DU STATUT
  // ============================================================================

  /**
   * Vérifie le statut de connexion avec l'application Desktop
   */
  async function checkDesktopStatus() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_AUTH' });

      if (response && response.authenticated) {
        showConnected(response);
      } else {
        showDisconnected('Desktop démarré mais non connecté');
      }
    } catch (err) {
      showDisconnected('Desktop non disponible');
    }
  }

  /**
   * Affiche l'état connecté
   *
   * @param {Object} data - Données de connexion (username, vaultUrl)
   */
  function showConnected(data) {
    statusIcon.className = 'status-icon connected';
    statusText.textContent = 'Desktop connecté';

    // Vider et reconstruire le contenu de manière sécurisée
    clearElement(statusDetails);

    // Ligne utilisateur
    const userLine = createElement('p');
    const userLabel = createElement('strong', {}, 'Utilisateur: ');
    userLine.appendChild(userLabel);
    userLine.appendChild(document.createTextNode(data.username || 'Inconnu'));
    statusDetails.appendChild(userLine);

    // Ligne serveur
    const serverLine = createElement('p');
    const serverLabel = createElement('strong', {}, 'Serveur: ');
    serverLine.appendChild(serverLabel);
    serverLine.appendChild(document.createTextNode(data.vaultUrl || 'Inconnu'));
    statusDetails.appendChild(serverLine);

    // Ligne statut actif
    const activeLine = createElement('p', {
      style: { color: '#10b981', marginTop: '8px' }
    }, '✓ Auto-remplissage actif');
    statusDetails.appendChild(activeLine);
  }

  /**
   * Affiche l'état déconnecté
   *
   * @param {string} message - Message de statut
   */
  function showDisconnected(message) {
    statusIcon.className = 'status-icon disconnected';
    statusText.textContent = message;

    // Vider et reconstruire le contenu de manière sécurisée
    clearElement(statusDetails);

    const helpLine = createElement('p', {
      style: { color: '#ef4444' }
    }, 'Lancez l\'application Desktop et connectez-vous pour utiliser l\'auto-remplissage.');
    statusDetails.appendChild(helpLine);
  }

  // ============================================================================
  // INITIALISATION
  // ============================================================================

  // Vérifier au démarrage
  await checkDesktopStatus();

  // Vérifier périodiquement (toutes les 2 secondes)
  setInterval(checkDesktopStatus, 2000);
});
