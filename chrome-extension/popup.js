// popup.js
// Logique de l'interface popup

document.addEventListener('DOMContentLoaded', async () => {
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

  // Afficher un message de statut
  function showStatus(message, type = 'info', container = status) {
    container.textContent = message;
    container.className = `status status-${type}`;
    container.classList.remove('hidden');

    setTimeout(() => {
      container.classList.add('hidden');
    }, 3000);
  }

  // Vérifier l'état d'authentification
  async function checkAuth() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'CHECK_AUTH' });

      loading.classList.add('hidden');

      if (response.authenticated) {
        loginForm.classList.add('hidden');
        authenticatedView.classList.remove('hidden');
        currentUser.textContent = response.username || 'Utilisateur';
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
      showStatus('Veuillez remplir tous les champs obligatoires', 'error');
      return;
    }

    loginBtn.disabled = true;
    loginBtn.textContent = 'Connexion...';

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'LOGIN',
        vaultUrl,
        vaultNamespace,
        username,
        password
      });

      if (response.success) {
        showStatus('Connexion réussie', 'success');
        passwordInput.value = '';
        await checkAuth();
      } else {
        // SÉCURITÉ: Effacer le mot de passe en cas d'échec de connexion
        passwordInput.value = '';
        showStatus(`Erreur : ${response.error}`, 'error');
      }
    } catch (err) {
      // SÉCURITÉ: Effacer le mot de passe en cas d'erreur
      passwordInput.value = '';
      showStatus(`Erreur : ${err.message}`, 'error');
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = 'Se connecter';
    }
  });

  // Gérer la déconnexion
  logoutBtn.addEventListener('click', async () => {
    try {
      await chrome.runtime.sendMessage({ type: 'LOGOUT' });
      showStatus('Déconnexion réussie', 'success', statusAuth);
      await checkAuth();
    } catch (err) {
      showStatus(`Erreur : ${err.message}`, 'error', statusAuth);
    }
  });

  // Gérer l'actualisation du cache
  refreshBtn.addEventListener('click', async () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = 'Actualisation...';

    try {
      const response = await chrome.runtime.sendMessage({ type: 'REFRESH_CACHE' });

      if (response.success) {
        showStatus(`Cache actualisé (${response.count} secrets)`, 'success', statusAuth);
      } else {
        showStatus(`Erreur : ${response.error}`, 'error', statusAuth);
      }
    } catch (err) {
      showStatus(`Erreur : ${err.message}`, 'error', statusAuth);
    } finally {
      refreshBtn.disabled = false;
      refreshBtn.textContent = 'Actualiser le cache';
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
