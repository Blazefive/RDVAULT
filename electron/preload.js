// ========================================
// ELECTRON PRELOAD SCRIPT
// ========================================
// Ce script s'exécute AVANT le chargement de l'application React dans le renderer process.
// Il sert de pont sécurisé entre le code React (contexte web) et les API Node.js/Electron.
//
// Architecture de sécurité :
// - contextIsolation: true -> Le code React et le code Electron sont isolés
// - nodeIntegration: false -> React n'a PAS accès direct à Node.js
// - contextBridge -> Seules les API explicitement exposées ici sont accessibles à React
//
// Pourquoi ? Pour éviter que du code malveillant dans React (ex: une dépendance compromise)
// puisse accéder directement au système de fichiers, exécuter des commandes, etc.

const { contextBridge, ipcRenderer } = require('electron');

// ========================================
// API INFO - Vérification de disponibilité
// ========================================
// Expose un simple flag pour que React puisse vérifier que l'API Electron est disponible
contextBridge.exposeInMainWorld('electronInfo', { ok: true });

// ========================================
// API CLIPBOARD - Gestion sécurisée du presse-papier
// ========================================
// Permet à React de copier des mots de passe dans le presse-papier avec auto-effacement
// Toutes les opérations passent par IPC pour garder le contrôle dans le main process
contextBridge.exposeInMainWorld('electronClipboard', {
  // Efface le presse-papier (méthode legacy, garde pour compatibilité)
  clear: () => ipcRenderer.invoke('clipboard-clear'),

  // Copie un texte avec auto-effacement après un délai (défaut: 12s)
  // Utilisé pour les mots de passe et secrets sensibles
  copySecure: (text, timeoutMs) => {
    if (typeof text !== 'string') return Promise.reject(new Error('Texte invalide'));
    // Valider timeoutMs pour éviter les valeurs aberrantes
    const safeTimeout = (typeof timeoutMs === 'number' && timeoutMs > 0 && timeoutMs <= 300000)
      ? timeoutMs : undefined;
    return ipcRenderer.invoke('clipboard-copy-secure', text, safeTimeout);
  },

  // Efface immédiatement le presse-papier (annule le timer d'auto-effacement)
  clearNow: () => ipcRenderer.invoke('clipboard-clear-now'),

  // Copie un lien cliquable au format riche (HTML + texte)
  // Quand collé dans Outlook/Teams, le lien est cliquable avec le label affiché
  copyRichLink: (url, label) => {
    if (typeof url !== 'string' || typeof label !== 'string') return Promise.reject(new Error('Paramètres invalides'));
    return ipcRenderer.invoke('clipboard-copy-rich-link', url, label);
  }
});

// ========================================
// API SYNC - Synchronisation avec l'extension Chrome
// ========================================
// Permet à React d'écrire l'état de connexion Vault dans un fichier chiffré local
// L'extension Chrome lit ce fichier pour synchroniser l'auto-remplissage des formulaires
contextBridge.exposeInMainWorld('electronSync', {
  // Écrit l'état de synchronisation (token, secrets, etc.) dans le fichier chiffré
  writeState: (state) => {
    if (!state || typeof state !== 'object' || Array.isArray(state)) return Promise.reject(new Error('État invalide'));
    return ipcRenderer.invoke('sync-write-state', state);
  },

  // Lit l'état de synchronisation depuis le fichier chiffré
  readState: () => ipcRenderer.invoke('sync-read-state'),

  // Retourne le chemin du fichier de synchronisation (pour debug)
  getPath: () => ipcRenderer.invoke('sync-get-path'),

  // Retourne le token d'authentification déchiffré (pour l'extension Chrome)
  getAuthToken: () => ipcRenderer.invoke('sync-get-auth-token'),

  // Écoute les demandes de code TOTP depuis l'extension Chrome
  // L'extension envoie le nom d'une clé TOTP + requestId, React génère le code et le renvoie
  onTotpRequest: (callback) => {
    // SÉCURITÉ: Ne pas exposer l'objet event IPC à React
    // Retirer le listener précédent si existant pour éviter les doublons
    if (contextBridge._totpRequestCallback) {
      ipcRenderer.removeListener('get-totp-code', contextBridge._totpRequestCallback);
    }
    const wrappedCallback = (_event, keyName, requestId) => callback(keyName, requestId);
    contextBridge._totpRequestCallback = wrappedCallback;
    ipcRenderer.on('get-totp-code', wrappedCallback);
    // Retourne une fonction de cleanup pour éviter les fuites mémoire
    return () => {
      ipcRenderer.removeListener('get-totp-code', wrappedCallback);
      if (contextBridge._totpRequestCallback === wrappedCallback) {
        contextBridge._totpRequestCallback = null;
      }
    };
  },

  // Envoie la réponse TOTP à l'extension Chrome (code généré ou erreur)
  // Utilise le requestId pour la corrélation (évite les race conditions)
  sendTotpResponse: (result, requestId) => {
    // SÉCURITÉ: Valider le requestId et le result
    if (!requestId || typeof requestId !== 'string' || !/^[a-f0-9]{16}$/.test(requestId)) {
      console.warn('[Preload] sendTotpResponse: requestId invalide');
      return;
    }
    if (!result || typeof result !== 'object') {
      console.warn('[Preload] sendTotpResponse: result invalide');
      return;
    }
    // Whitelist des champs autorisés dans result
    const safeResult = {
      success: Boolean(result.success),
      code: (typeof result.code === 'string' && /^\d{4,10}$/.test(result.code)) ? result.code : undefined,
      error: typeof result.error === 'string' ? result.error.slice(0, 200) : undefined
    };
    ipcRenderer.send(`totp-code-response-${requestId}`, safeResult);
  }
});

// ========================================
// API BROWSER - Ouverture d'URLs et connexions externes
// ========================================
// Permet à React d'ouvrir des URLs dans des navigateurs spécifiques ou des connexions SSH/RDP
contextBridge.exposeInMainWorld('electronBrowser', {
  // Ouvre une URL dans un navigateur spécifique (chrome, firefox, edge, brave, default)
  openUrl: (url, browser) => {
    if (typeof url !== 'string' || url.length > 2048) return Promise.reject(new Error('URL invalide'));
    // SÉCURITÉ: Valider le schéma de l'URL
    try {
      const parsed = new URL(url);
      const allowedSchemes = ['http:', 'https:', 'ftp:', 'ftps:', 'ssh:', 'rdp:', 'sftp:', 'vnc:'];
      if (!allowedSchemes.includes(parsed.protocol)) return Promise.reject(new Error('Schéma URL non autorisé'));
    } catch { return Promise.reject(new Error('URL invalide')); }
    if (browser !== undefined && typeof browser !== 'string') return Promise.reject(new Error('Navigateur invalide'));
    return ipcRenderer.invoke('open-url-in-browser', url, browser);
  },

  // Retourne la liste des navigateurs installés sur le système
  getInstalledBrowsers: () => ipcRenderer.invoke('get-installed-browsers'),

  // Ouvre un lien externe avec l'application système par défaut (rdp://, ftp://, etc.)
  openExternalLink: (url) => {
    if (typeof url !== 'string' || url.length > 2048) return Promise.reject(new Error('URL invalide'));
    try {
      const parsed = new URL(url);
      const allowedSchemes = ['http:', 'https:', 'ftp:', 'ftps:', 'ssh:', 'rdp:', 'sftp:', 'vnc:'];
      if (!allowedSchemes.includes(parsed.protocol)) return Promise.reject(new Error('Schéma URL non autorisé'));
    } catch { return Promise.reject(new Error('URL invalide')); }
    return ipcRenderer.invoke('open-external-link', url);
  },

  // Ouvre une connexion SSH avec PuTTY (Windows uniquement)
  openSshConnection: (params) => {
    if (!params || typeof params !== 'object') return Promise.reject(new Error('Paramètres invalides'));
    // SÉCURITÉ: Ne transmettre que les champs utilisés par le main process (host, username, port)
    const { host, username, port } = params;
    return ipcRenderer.invoke('open-ssh-connection', { host, username, port });
  },

  // Ouvre une connexion RDP avec auto-remplissage des credentials
  openRdpConnection: (params) => {
    if (!params || typeof params !== 'object') return Promise.reject(new Error('Paramètres invalides'));
    const { host, username, password, port, domain } = params;
    // SÉCURITÉ: Validation type/longueur pour les champs transmis
    if (password !== undefined && (typeof password !== 'string' || password.length > 10000)) return Promise.reject(new Error('Password invalide'));
    if (domain !== undefined && (typeof domain !== 'string' || domain.length > 253)) return Promise.reject(new Error('Domaine invalide'));
    return ipcRenderer.invoke('open-rdp-connection', { host, username, password, port, domain });
  },

  // Ouvre une connexion SFTP avec FileZilla ou WinSCP
  openSftpConnection: (params) => {
    if (!params || typeof params !== 'object') return Promise.reject(new Error('Paramètres invalides'));
    const { host, username, password, port } = params;
    // SÉCURITÉ: Validation type/longueur
    if (password !== undefined && (typeof password !== 'string' || password.length > 10000)) return Promise.reject(new Error('Password invalide'));
    return ipcRenderer.invoke('open-sftp-connection', { host, username, password, port });
  }
});

// ========================================
// API ELECTRON - Configuration HTTPS
// ========================================
// API héritée pour la gestion des certificats auto-signés
// La gestion réelle est faite dans main.js via app.on('certificate-error')
contextBridge.exposeInMainWorld('electron', {
  createHttpsAgent: () => {
    // Note: Dans le renderer process (React), on ne peut pas créer un vrai agent Node.js https.Agent
    // car Node.js n'est pas disponible. On retourne null et on gère ça dans main.js
    // via app.on('certificate-error') pour accepter les certificats auto-signés de domaines de confiance
    return null;
  }
});

// ========================================
// API CONFIG - Configuration de l'application
// ========================================
// Expose la configuration de l'application à React
// Configuration chargée depuis config.json (créé par l'installateur)
// Paramètres : VAULT_URL, LDAP_AUTH_PATH, TRUSTED_DOMAINS
contextBridge.exposeInMainWorld('electronConfig', {
  // Récupère la configuration de l'application
  getConfig: () => ipcRenderer.invoke('get-app-config')
});

// ========================================
// API AUDIT - Lecture des logs Vault
// ========================================
// Permet à React de lire les fichiers de logs d'audit Vault (locaux ou via SSH)
contextBridge.exposeInMainWorld('electronAudit', {
  // Lit un fichier de logs complet (limité à maxLines lignes)
  readLogFile: (filePath, maxLines) => {
    // SÉCURITÉ: Valider les paramètres côté preload
    if (typeof filePath !== 'string' || filePath.length > 1024) return Promise.reject(new Error('Chemin invalide'));
    if (filePath.includes('..') || filePath.includes('\0')) return Promise.reject(new Error('Chemin non autorisé'));
    // SÉCURITÉ: Défense en profondeur — vérifier le préfixe autorisé aussi dans le preload
    const normalizedPath = filePath.replace(/\//g, '\\');
    if (!normalizedPath.toLowerCase().startsWith('c:\\programdata\\vault\\logs\\') && !filePath.startsWith('/var/log/vault/')) {
      return Promise.reject(new Error('Chemin non autorisé'));
    }
    const safeMaxLines = (typeof maxLines === 'number' && maxLines > 0 && maxLines <= 10000) ? maxLines : 1000;
    return ipcRenderer.invoke('audit-read-log-file', filePath, safeMaxLines);
  },

  // Lit les dernières lignes d'un fichier de logs (équivalent à tail -n)
  tailLogFile: (filePath, lines, sshConfig) => {
    if (typeof filePath !== 'string' || filePath.length > 1024) return Promise.reject(new Error('Chemin invalide'));
    if (filePath.includes('..') || filePath.includes('\0')) return Promise.reject(new Error('Chemin non autorisé'));
    const safeLines = (typeof lines === 'number' && lines > 0 && lines <= 10000) ? lines : 100;
    if (sshConfig !== null && sshConfig !== undefined && typeof sshConfig !== 'object') return Promise.reject(new Error('Config SSH invalide'));
    // SÉCURITÉ: Whitelist des champs SSH autorisés (empêche l'injection de propriétés arbitraires dans ssh2.connect())
    let safeSshConfig = sshConfig;
    if (sshConfig && typeof sshConfig === 'object') {
      // SÉCURITÉ: Whitelist avec validation de type pour chaque champ
      safeSshConfig = {};
      if (typeof sshConfig.host === 'string') safeSshConfig.host = sshConfig.host.slice(0, 253);
      if (typeof sshConfig.username === 'string') safeSshConfig.username = sshConfig.username.slice(0, 128);
      if (typeof sshConfig.password === 'string') safeSshConfig.password = sshConfig.password.slice(0, 1024);
      if (sshConfig.port !== undefined) safeSshConfig.port = Number(sshConfig.port);
    }
    return ipcRenderer.invoke('audit-tail-log-file', filePath, safeLines, safeSshConfig);
  }
});

// ========================================
// API POWER MONITOR - Détection verrouillage système
// ========================================
// Permet à React de détecter quand le PC est verrouillé/déverrouillé
// pour adapter le timeout de session (15 min actif, 3h verrouillé)

// Stockage des callbacks wrappés pour pouvoir les retirer proprement
const _powerMonitorCallbacks = { lock: null, unlock: null };

contextBridge.exposeInMainWorld('electronPowerMonitor', {
  // Enregistre un callback qui sera appelé quand le système est verrouillé
  onLockScreen: (callback) => {
    // Retirer le listener précédent pour éviter les fuites mémoire
    if (_powerMonitorCallbacks.lock) {
      ipcRenderer.removeListener('system-lock-screen', _powerMonitorCallbacks.lock);
    }
    // SÉCURITÉ: Ne pas exposer l'objet event IPC à React
    _powerMonitorCallbacks.lock = () => callback();
    ipcRenderer.on('system-lock-screen', _powerMonitorCallbacks.lock);
  },

  // Enregistre un callback qui sera appelé quand le système est déverrouillé
  onUnlockScreen: (callback) => {
    // Retirer le listener précédent pour éviter les fuites mémoire
    if (_powerMonitorCallbacks.unlock) {
      ipcRenderer.removeListener('system-unlock-screen', _powerMonitorCallbacks.unlock);
    }
    // SÉCURITÉ: Ne pas exposer l'objet event IPC à React
    _powerMonitorCallbacks.unlock = () => callback();
    ipcRenderer.on('system-unlock-screen', _powerMonitorCallbacks.unlock);
  },

  // Nettoie les listeners enregistrés (appelé au démontage du composant)
  removeAllListeners: () => {
    if (_powerMonitorCallbacks.lock) {
      ipcRenderer.removeListener('system-lock-screen', _powerMonitorCallbacks.lock);
      _powerMonitorCallbacks.lock = null;
    }
    if (_powerMonitorCallbacks.unlock) {
      ipcRenderer.removeListener('system-unlock-screen', _powerMonitorCallbacks.unlock);
      _powerMonitorCallbacks.unlock = null;
    }
  }
});

// ========================================
// API RBI - Sessions Navigateur Isolées
// ========================================
// Permet à React de lancer des sessions navigateur sécurisées
// où les credentials sont injectés automatiquement (l'utilisateur ne voit jamais le mdp)
contextBridge.exposeInMainWorld('electronRBI', {
  // Lance une session sécurisée
  // options: { url, username, password, selectors?, policies? }
  launchSession: (options) => {
    if (!options || typeof options !== 'object') return Promise.reject(new Error('Options invalides'));
    // SÉCURITÉ: Valider le schéma de l'URL
    if (typeof options.url === 'string') {
      try {
        const u = new URL(options.url);
        if (!['http:', 'https:'].includes(u.protocol)) return Promise.reject(new Error('URL non autorisée'));
      } catch { return Promise.reject(new Error('URL invalide')); }
    }
    return ipcRenderer.invoke('rbi-launch-session', options);
  },

  // Ferme une session active
  closeSession: (sessionId) => {
    if (typeof sessionId !== 'string' || !sessionId || sessionId.length > 128) {
      return Promise.reject(new Error('ID de session invalide'));
    }
    return ipcRenderer.invoke('rbi-close-session', sessionId);
  },

  // Liste les sessions actives
  listSessions: () => ipcRenderer.invoke('rbi-list-sessions'),

  // Vérifie si RBI est disponible (Chromium installé)
  checkAvailability: () => ipcRenderer.invoke('rbi-check-availability'),

  // Récupère les sélecteurs connus pour sites courants
  getKnownSelectors: () => ipcRenderer.invoke('rbi-get-known-selectors'),

  // Écoute la réception d'un lien de partage RBI (deep link rdvault://share/TOKEN)
  onShareReceived: (callback) => {
    // Retirer le listener précédent si existant pour éviter les doublons
    if (contextBridge._shareReceivedCallback) {
      ipcRenderer.removeListener('rdvault-share-received', contextBridge._shareReceivedCallback);
    }
    const wrappedCallback = (_event, shareToken) => {
      if (typeof shareToken === 'string' && shareToken.length > 0 && shareToken.length < 1024) callback(shareToken);
    };
    contextBridge._shareReceivedCallback = wrappedCallback;
    ipcRenderer.on('rdvault-share-received', wrappedCallback);
    return () => {
      ipcRenderer.removeListener('rdvault-share-received', wrappedCallback);
      if (contextBridge._shareReceivedCallback === wrappedCallback) {
        contextBridge._shareReceivedCallback = null;
      }
    };
  }
});

// ========================================
// API CLI - Accès secrets via ligne de commande (mvault)
// ========================================
// Permet au renderer de répondre aux demandes de secrets provenant de la CLI mvault.
// Le serveur CLI local (cliServer.js) envoie une requête IPC 'cli-read-secret',
// React fait l'appel Vault et renvoie le résultat via 'cli-secret-response-<requestId>'.
contextBridge.exposeInMainWorld('electronCLI', {
  // Écoute la notification de démarrage du serveur CLI (port + token)
  onServerReady: (callback) => {
    const wrappedCallback = (_event, data) => {
      const safeData = { port: Number(data?.port) || 0, token: String(data?.token || '') };
      callback(safeData);
    };
    ipcRenderer.on('cli-server-ready', wrappedCallback);
    return () => ipcRenderer.removeListener('cli-server-ready', wrappedCallback);
  },

  // Récupère les infos de session CLI (appel actif, pas d'écoute passive)
  getSession: () => ipcRenderer.invoke('cli-get-session'),

  // Écoute les demandes de secrets provenant de la CLI
  onSecretRequest: (callback) => {
    if (contextBridge._cliSecretCallback) {
      ipcRenderer.removeListener('cli-read-secret', contextBridge._cliSecretCallback);
    }
    const wrappedCallback = (_event, request) => callback(request);
    contextBridge._cliSecretCallback = wrappedCallback;
    ipcRenderer.on('cli-read-secret', wrappedCallback);
    return () => {
      ipcRenderer.removeListener('cli-read-secret', wrappedCallback);
      if (contextBridge._cliSecretCallback === wrappedCallback) {
        contextBridge._cliSecretCallback = null;
      }
    };
  },

  // Écoute les demandes de listage des engines provenant de la CLI
  onEnginesRequest: (callback) => {
    if (contextBridge._cliEnginesCallback) {
      ipcRenderer.removeListener('cli-list-engines', contextBridge._cliEnginesCallback);
    }
    const wrappedCallback = (_event, request) => callback(request);
    contextBridge._cliEnginesCallback = wrappedCallback;
    ipcRenderer.on('cli-list-engines', wrappedCallback);
    return () => {
      ipcRenderer.removeListener('cli-list-engines', wrappedCallback);
      if (contextBridge._cliEnginesCallback === wrappedCallback) {
        contextBridge._cliEnginesCallback = null;
      }
    };
  },

  // Envoie la liste des engines au serveur CLI
  sendEnginesResponse: (engines, requestId) => {
    if (!requestId || typeof requestId !== 'string' || !/^[a-f0-9]{16}$/.test(requestId)) return;
    ipcRenderer.send(`cli-engines-response-${requestId}`, engines);
  },

  // Écoute les demandes de listage des secrets d'un engine
  onListSecretsRequest: (callback) => {
    if (contextBridge._cliListSecretsCallback) {
      ipcRenderer.removeListener('cli-list-secrets', contextBridge._cliListSecretsCallback);
    }
    const wrappedCallback = (_event, request) => callback(request);
    contextBridge._cliListSecretsCallback = wrappedCallback;
    ipcRenderer.on('cli-list-secrets', wrappedCallback);
    return () => {
      ipcRenderer.removeListener('cli-list-secrets', wrappedCallback);
      if (contextBridge._cliListSecretsCallback === wrappedCallback) {
        contextBridge._cliListSecretsCallback = null;
      }
    };
  },

  // Envoie la liste des secrets au serveur CLI
  sendListSecretsResponse: (keys, requestId) => {
    if (!requestId || typeof requestId !== 'string' || !/^[a-f0-9]{16}$/.test(requestId)) return;
    ipcRenderer.send(`cli-list-secrets-response-${requestId}`, keys);
  },

  // Définit les engines autorisés pour le listing via CLI
  setListSecretsEngines: (engines) => {
    if (!Array.isArray(engines)) return Promise.reject(new Error('engines doit être un tableau'));
    return ipcRenderer.invoke('cli-set-list-secrets-engines', engines);
  },

  // Révoque la session CLI et régénère un nouveau token (appelé au logout)
  revokeSession: () => ipcRenderer.invoke('cli-revoke-session'),

  // Écoute les notifications d'accès auto-approuvé (pour afficher un toast)
  onAutoAccess: (callback) => {
    const wrapped = (_event, path) => callback(String(path || ''));
    ipcRenderer.on('cli-auto-access', wrapped);
    return () => ipcRenderer.removeListener('cli-auto-access', wrapped);
  },

  // Définit les règles d'auto-approbation via IPC (plus fiable que fetch HTTP)
  setAutoApproveRules: (rules) => {
    if (!Array.isArray(rules)) return Promise.reject(new Error('rules doit être un tableau'));
    return ipcRenderer.invoke('cli-set-auto-approve-rules', rules);
  },

  // Envoie la réponse (secret lu ou erreur) au serveur CLI
  sendSecretResponse: (result, requestId) => {
    if (!requestId || typeof requestId !== 'string' || !/^[a-f0-9]{16}$/.test(requestId)) {
      console.warn('[Preload] sendSecretResponse: requestId invalide');
      return;
    }
    if (!result || typeof result !== 'object') {
      console.warn('[Preload] sendSecretResponse: result invalide');
      return;
    }
    // Whitelist des champs autorisés
    const safeResult = {
      success: Boolean(result.success),
      data: result.data || undefined,
      error: typeof result.error === 'string' ? result.error.slice(0, 500) : undefined
    };
    ipcRenderer.send(`cli-secret-response-${requestId}`, safeResult);
  }
});

// ========================================
// API WINDOW - Contrôle fenêtre frameless
// ========================================
// API EXPORT — Sauvegarde de fichier d'export
// ========================================
contextBridge.exposeInMainWorld('electronExport', {
  saveFile: ({ defaultName, filters, content }) => {
    if (typeof content !== 'string') return Promise.reject(new Error('Content must be a string'));
    return ipcRenderer.invoke('export-save-file', { defaultName, filters, content });
  },
  openFile: ({ filters }) => {
    return ipcRenderer.invoke('import-open-file', { filters });
  }
});

// ========================================
// Permet au renderer de contrôle la fenêtre (minimiser, maximiser, fermer)
// et de basculer entre mode login (compact) et mode principal (1280x800)
contextBridge.exposeInMainWorld('electronWindow', {
  setMainMode: () => ipcRenderer.invoke('window-set-main-mode'),
  setLoginMode: () => ipcRenderer.invoke('window-set-login-mode'),
  close: () => ipcRenderer.invoke('window-close'),
  minimize: () => ipcRenderer.invoke('window-minimize'),
  maximize: () => ipcRenderer.invoke('window-maximize-toggle'),
  isMaximized: () => ipcRenderer.invoke('window-is-maximized'),
  onMaximizeChange: (callback) => {
    const wrapped = (_event, isMaximized) => callback(isMaximized);
    ipcRenderer.on('window-maximize-changed', wrapped);
    return wrapped;
  },
  removeMaximizeListener: (wrapped) => ipcRenderer.removeListener('window-maximize-changed', wrapped),
});
