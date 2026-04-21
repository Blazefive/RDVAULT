// content.js
// Content script pour détecter et auto-remplir les formulaires

(function() {
  'use strict';

  let credentialsList = [];
  let activeDropdown = null;

  // Styles CSS injectés
  const styles = `
    .vault-autofill-icon {
      position: absolute;
      right: 8px;
      top: 50%;
      transform: translateY(-50%);
      width: 20px;
      height: 20px;
      cursor: pointer;
      background: #3b82f6;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      color: white;
      font-weight: bold;
      z-index: 10000;
      user-select: none;
      box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }

    .vault-autofill-icon:hover {
      background: #2563eb;
    }

    .vault-autofill-dropdown {
      position: absolute;
      background: white;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 10001;
      min-width: 250px;
      max-width: 400px;
      max-height: 300px;
      overflow-y: auto;
    }

    .vault-autofill-item {
      padding: 10px 12px;
      cursor: pointer;
      border-bottom: 1px solid #e5e7eb;
      transition: background 0.1s;
    }

    .vault-autofill-item:last-child {
      border-bottom: none;
    }

    .vault-autofill-item:hover {
      background: #f3f4f6;
    }

    .vault-autofill-item-name {
      font-weight: 600;
      font-size: 14px;
      color: #111827;
      margin-bottom: 4px;
    }

    .vault-autofill-item-username {
      font-size: 12px;
      color: #6b7280;
    }

    .vault-autofill-no-results {
      padding: 12px;
      text-align: center;
      color: #9ca3af;
      font-size: 13px;
    }

    .vault-autofill-loading {
      padding: 12px;
      text-align: center;
      color: #3b82f6;
      font-size: 13px;
    }
  `;

  // Injecter les styles
  const styleSheet = document.createElement('style');
  styleSheet.textContent = styles;
  document.head.appendChild(styleSheet);

  // Détecter les champs de formulaire
  function detectFormFields() {
    // Champs username/email
    const usernameFields = document.querySelectorAll(
      'input[type="text"][name*="user" i], ' +
      'input[type="text"][name*="login" i], ' +
      'input[type="email"], ' +
      'input[type="text"][id*="user" i], ' +
      'input[type="text"][id*="login" i], ' +
      'input[type="text"][id*="email" i], ' +
      'input[type="text"][autocomplete*="username"], ' +
      'input[type="text"][autocomplete*="email"]'
    );

    // Champs password
    const passwordFields = document.querySelectorAll('input[type="password"]');

    return { usernameFields, passwordFields };
  }

  // Créer l'icône d'auto-remplissage
  function createAutofillIcon(field) {
    // Vérifier si une icône existe déjà
    const existingIcon = field.parentElement?.querySelector('.vault-autofill-icon');
    if (existingIcon) return existingIcon;

    // S'assurer que le parent a position relative
    const parent = field.parentElement;
    if (parent) {
      const position = window.getComputedStyle(parent).position;
      if (position === 'static') {
        parent.style.position = 'relative';
      }
    }

    const icon = document.createElement('div');
    icon.className = 'vault-autofill-icon';
    icon.textContent = 'V';
    icon.title = 'Auto-remplir avec Vault';

    // Insérer l'icône après le champ
    field.parentElement?.appendChild(icon);

    return icon;
  }

  // Créer le dropdown de sélection
  function createDropdown(field, credentials) {
    // Supprimer tout dropdown existant
    removeDropdown();

    const dropdown = document.createElement('div');
    dropdown.className = 'vault-autofill-dropdown';

    // Positionner le dropdown
    const rect = field.getBoundingClientRect();
    dropdown.style.position = 'fixed';
    dropdown.style.top = `${rect.bottom + 4}px`;
    dropdown.style.left = `${rect.left}px`;
    dropdown.style.width = `${rect.width}px`;

    if (credentials.length === 0) {
      const noResults = document.createElement('div');
      noResults.className = 'vault-autofill-no-results';
      noResults.textContent = 'Aucun identifiant trouvé pour ce site';
      dropdown.appendChild(noResults);
    } else {
      credentials.forEach(cred => {
        const item = document.createElement('div');
        item.className = 'vault-autofill-item';

        const name = document.createElement('div');
        name.className = 'vault-autofill-item-name';
        name.textContent = cred.name;

        const username = document.createElement('div');
        username.className = 'vault-autofill-item-username';
        username.textContent = cred.username || '(pas de username)';

        item.appendChild(name);
        item.appendChild(username);

        item.addEventListener('click', () => {
          autofillCredentials(cred);
          removeDropdown();
        });

        dropdown.appendChild(item);
      });
    }

    document.body.appendChild(dropdown);
    activeDropdown = dropdown;

    return dropdown;
  }

  // Supprimer le dropdown
  function removeDropdown() {
    if (activeDropdown) {
      activeDropdown.remove();
      activeDropdown = null;
    }
  }

  // Auto-remplir les credentials
  function autofillCredentials(credentials) {
    // SÉCURITÉ: Bloquer l'autofill sur les pages HTTP (credentials en clair sur le réseau)
    if (window.location.protocol !== 'https:') {
      console.warn('[Vault] Autofill bloqué : page non HTTPS');
      return;
    }

    const { usernameFields, passwordFields } = detectFormFields();

    // Remplir le premier champ username trouvé
    if (usernameFields.length > 0 && credentials.username) {
      const field = usernameFields[0];
      field.value = credentials.username;
      field.dispatchEvent(new Event('input', { bubbles: true }));
      field.dispatchEvent(new Event('change', { bubbles: true }));
    }

    // Remplir le premier champ password trouvé
    if (passwordFields.length > 0 && credentials.password) {
      const field = passwordFields[0];
      field.value = credentials.password;
      field.dispatchEvent(new Event('input', { bubbles: true }));
      field.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  // Charger les credentials pour l'URL actuelle
  async function loadCredentials() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'GET_CREDENTIALS',
        url: window.location.href
      });

      if (response.success) {
        credentialsList = response.credentials;
        return credentialsList;
      } else {
        console.error('Error loading credentials');
        return [];
      }
    } catch (err) {
      console.error('Error communicating with background script');
      return [];
    }
  }

  // Ajouter les icônes aux champs
  async function addAutofillIcons() {
    const { usernameFields, passwordFields } = detectFormFields();

    // Charger les credentials
    const credentials = await loadCredentials();

    // Ajouter des icônes uniquement si on a des credentials
    if (credentials.length > 0) {
      const allFields = [...usernameFields, ...passwordFields];

      allFields.forEach(field => {
        const icon = createAutofillIcon(field);

        // Click sur l'icône
        icon.addEventListener('click', (e) => {
          e.stopPropagation();
          createDropdown(field, credentials);
        });
      });
    }
  }

  // Fermer le dropdown au clic ailleurs
  document.addEventListener('click', (e) => {
    if (activeDropdown && !activeDropdown.contains(e.target)) {
      removeDropdown();
    }
  });

  // Fermer le dropdown à l'ESC
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && activeDropdown) {
      removeDropdown();
    }
  });

  // Observer les changements DOM pour détecter les formulaires ajoutés dynamiquement
  // SÉCURITÉ: Debounce pour éviter les boucles infinies et la surcharge CPU
  let mutationDebounceTimer = null;
  const observer = new MutationObserver(() => {
    if (mutationDebounceTimer) clearTimeout(mutationDebounceTimer);
    mutationDebounceTimer = setTimeout(() => {
      addAutofillIcons();
    }, 500);
  });

  // Initialiser
  function init() {
    // Attendre que le DOM soit prêt
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', addAutofillIcons);
    } else {
      addAutofillIcons();
    }

    // Observer les changements DOM
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  init();
})();
