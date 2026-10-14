// popup.js
/* global chrome */ // API d'extension (page de la popup)
// Logique de l'interface popup

// Texte traduit dans la langue du navigateur (chrome.i18n, _locales/<langue>/messages.json,
// repli « en »). `fallback` est le texte français d'origine, identique à _locales/fr : il ne sert
// que hors extension (tests) ; $1… y sont remplacés comme par Chrome.
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

// Traduit les textes statiques de popup.html (data-i18n : texte, data-i18n-placeholder :
// indication du champ ; le français du HTML sert de repli) et applique la langue / le sens
// d'écriture (arabe : de droite à gauche).
function localizePage() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = msg(el.getAttribute('data-i18n'), el.textContent.replace(/\s+/g, ' ').trim());
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.setAttribute('placeholder', msg(el.getAttribute('data-i18n-placeholder'), el.getAttribute('placeholder') || ''));
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

  const loading = document.getElementById('loading');
  const loginForm = document.getElementById('loginForm');
  const authenticatedView = document.getElementById('authenticatedView');
  const status = document.getElementById('status');
  const statusAuth = document.getElementById('statusAuth');

  const vaultUrlInput = document.getElementById('vaultUrl');
  const vaultNamespaceInput = document.getElementById('vaultNamespace');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const refreshBtn = document.getElementById('refreshBtn');
  const currentUser = document.getElementById('currentUser');

  // Afficher un message de statut, annoncé aux lecteurs d'écran : une erreur (role="alert") reste
  // affichée jusqu'à l'action suivante ; un succès (role="status") disparaît après 3 s
  const hideTimers = new Map();
  function showStatus(message, type = 'info', container = status) {
    clearTimeout(hideTimers.get(container));
    container.setAttribute('role', type === 'error' ? 'alert' : 'status');
    container.textContent = message;
    container.className = `status status-${type}`;
    container.classList.remove('hidden');

    if (type !== 'error') {
      hideTimers.set(container, setTimeout(() => {
        container.classList.add('hidden');
      }, 3000));
    }
  }

  // Vérifier l'état d'authentification
  async function checkAuth() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_AUTH' });

      loading.classList.add('hidden');

      if (response.authenticated) {
        loginForm.classList.add('hidden');
        authenticatedView.classList.remove('hidden');
        currentUser.textContent = response.username || msg('popupDefaultUser', 'Utilisateur');
      } else {
        loginForm.classList.remove('hidden');
        authenticatedView.classList.add('hidden');
      }
    } catch (err) {
      console.error('Error checking auth:', err);
      loading.classList.add('hidden');
      loginForm.classList.remove('hidden');
    }
  }

  // Gérer la connexion
  loginBtn.addEventListener('click', async () => {
    const vaultUrl = vaultUrlInput.value.trim();
    const vaultNamespace = vaultNamespaceInput.value.trim();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!vaultUrl || !username || !password) {
      showStatus(msg('popupFillRequired', 'Veuillez remplir tous les champs obligatoires'), 'error');
      return;
    }

    loginBtn.disabled = true;
    loginBtn.textContent = msg('popupLoggingIn', 'Connexion...');

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'LOGIN',
        vaultUrl,
        vaultNamespace,
        username,
        password
      });

      if (response.success) {
        showStatus(msg('popupLoginSuccess', 'Connexion réussie'), 'success');
        passwordInput.value = '';
        await checkAuth();
      } else {
        // SÉCURITÉ: Effacer le mot de passe en cas d'échec de connexion
        passwordInput.value = '';
        showStatus(msg('popupError', 'Erreur : $1', String(response.error)), 'error');
      }
    } catch (err) {
      // SÉCURITÉ: Effacer le mot de passe en cas d'erreur
      passwordInput.value = '';
      showStatus(msg('popupError', 'Erreur : $1', String(err.message)), 'error');
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = msg('popupLoginButton', 'Se connecter');
    }
  });

  // Gérer la déconnexion
  logoutBtn.addEventListener('click', async () => {
    try {
      await chrome.runtime.sendMessage({ type: 'LOGOUT' });
      showStatus(msg('popupLogoutSuccess', 'Déconnexion réussie'), 'success', statusAuth);
      await checkAuth();
    } catch (err) {
      showStatus(msg('popupError', 'Erreur : $1', String(err.message)), 'error', statusAuth);
    }
  });

  // Gérer l'actualisation du cache
  refreshBtn.addEventListener('click', async () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = msg('popupRefreshing', 'Actualisation...');

    try {
      const response = await chrome.runtime.sendMessage({ type: 'REFRESH_CACHE' });

      if (response.success) {
        showStatus(msg('popupCacheRefreshed', 'Cache actualisé ($1 secrets)', String(response.count)), 'success', statusAuth);
      } else {
        showStatus(msg('popupError', 'Erreur : $1', String(response.error)), 'error', statusAuth);
      }
    } catch (err) {
      showStatus(msg('popupError', 'Erreur : $1', String(err.message)), 'error', statusAuth);
    } finally {
      refreshBtn.disabled = false;
      refreshBtn.textContent = msg('popupRefreshButton', 'Actualiser le cache');
    }
  });

  // Permettre la soumission avec Enter
  passwordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      loginBtn.click();
    }
  });

  // Initialiser
  await checkAuth();
});
