// ========================================
// RDVAULT - APPLICATION PRINCIPALE
// ========================================
// Ce fichier contient toute la logique de l'application React :
// - Authentification LDAP avec Vault
// - Gestion des secrets engines (KV v1/v2)
// - CRUD des secrets (Create, Read, Update, Delete)
// - Génération de mots de passe
// - Gestion TOTP (codes 2FA)
// - Historique des versions
// - Synchronisation avec l'extension Chrome
// - Administration (panneau admin, audit logs, policies)
//
// Architecture :
// - Composant fonctionnel React avec hooks (useState, useEffect, useRef)
// - Appels API Vault via axios
// - Communication avec Electron via window.electronXXX (défini dans preload.js)
// - Styling CSS-in-JS (styles inline) + AppStyles.css

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import axios from 'axios';

// ========================================
// IMPORTS DES COMPOSANTS MODALS
// ========================================
import UserMenu from './UserMenu.jsx';                   // Menu utilisateur (déconnexion, settings)
import AdminPanel from './AdminPanel.jsx';               // Panneau d'administration (logs, policies)
import ClipboardTimer from './ClipboardTimer.jsx';       // Timer clipboard isolé (évite re-renders)
import WindowControls from './WindowControls.jsx';       // Boutons fenêtre frameless (minimiser/maximiser/fermer)
import { useTranslation } from './i18n';                 // Internationalisation

import './AppStyles.css';
import { sanitizeForDisplay, buildSafeUrl, encodeEnginePath, validateSecretName, sanitizeErrorMessage, safeWindowOpen } from './utils/security';
import { createVaultApi } from './services/vaultApi';
import { useToast, Toast } from './hooks/useToast';
import { useClipboard } from './hooks/useClipboard';
import { useSelection } from './hooks/useSelection';
import { useColumns } from './hooks/useColumns';
import { useTreeView } from './hooks/useTreeView';
import { useConfig } from './hooks/useConfig';
import { useContextMenus } from './hooks/useContextMenus';
import { useTotp } from './hooks/useTotp';
import { useTags } from './hooks/useTags';
import { useMigration } from './hooks/useMigration';
import { useDragDrop } from './hooks/useDragDrop';
import { useSync } from './hooks/useSync';
import { useAuth } from './hooks/useAuth';
import { useSecrets } from './hooks/useSecrets';
import { useEngines } from './hooks/useEngines';
import LoginForm from './components/auth/LoginForm';
import Toolbar from './components/layout/Toolbar';
import Sidebar from './components/layout/Sidebar';
import SecretContextMenu from './components/menus/SecretContextMenu';
import ContextMenus from './components/menus/ContextMenus';
import SecretsTable from './components/secrets/SecretsTable';
import ModalOrchestrator from './components/ModalOrchestrator';

// ========================================
// IMPORTS DES MODULES DE SÉCURITÉ
// ========================================
import { useSessionTimeout } from './useSessionTimeout';
import { useDebounce, useThrottle, useRateLimit } from './useRateLimit';
import secureLogger from './secureLogger';

// RateLimiter supprimé — remplacé par bruteForceProtection.js

export default function App() {
  const { t, lang, setLang } = useTranslation();
  const { vaultUrl, ldapAuthPath, rbiProxyUrl, configLoaded, appMode, vaultNs } = useConfig(setLang);
  const [currentView, setCurrentView] = useState('vault'); // 'vault' ou 'admin'
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('rdvault-theme');
    return saved === 'dark';
  });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [windowSize, setWindowSize] = useState({ width: window.innerWidth, height: window.innerHeight });

  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [visiblePasswords, setVisiblePasswords] = useState({});

  const [showDeleted, setShowDeleted] = useState(false);
  const [installedBrowsers, setInstalledBrowsers] = useState([]);

  const [multiVaultSearch, setMultiVaultSearch] = useState(false);
  const [allVaultSecrets, setAllVaultSecrets] = useState([]);
  const [showCreateFolderModal, setShowCreateFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');

  // ========================================
  // NOUVEAUX ÉTATS POUR VERSION 1.1
  // ========================================
  const { toast, showToast } = useToast();
  const { clipboardTimer, clearClipboardNow, handleClipboardExpire, startClipboardTimer } = useClipboard(showToast, t);
  const { visibleColumns, setVisibleColumns, columnWidths, resizingColumn, toggleColumn, saveColumnWidths, handleColumnResizeStart, handleColumnResizeMove, handleColumnResizeEnd, handleColumnAutoFit } = useColumns(showToast, t);
  const [notesPopup, setNotesPopup] = useState(null);           // Popup affichage notes
  const [showSettings, setShowSettings] = useState(false);      // Modal paramètres
  // discoveredTags moved to useTags hook
  const [shareRbiSecret, setShareRbiSecret] = useState(null);   // Secret à partager via RBI wrapping
  const [receiveShareOpen, setReceiveShareOpen] = useState(false); // Modal réception partage RBI

  // ========================================
  // ÉTATS POUR MULTI-SÉLECTION ET DRAG & DROP (v1.4)
  // ========================================
  const { selectedSecrets, setSelectedSecrets, lastClickedSecretRef, displayedSecretsRef, toggleSecretSelection, selectAllSecrets, clearSelection, isSecretSelected } = useSelection();

  const searchRef = useRef(null);
  const appRootRef = useRef(null);
  const syncExtensionRef = useRef(null);

  // Refs pour callbacks circulaires (définies plus bas)
  const vaultApiRef = useRef(null);
  const fetchEnginesLikeUiRef = useRef(null);
  const setDiscoveredTagsRef = useRef((tags) => {});
  const setSecretsRef = useRef((s) => {});
  const mergeDiscoveredAndSharedTagsRef = useRef(null);
  const getTotpKeyNameRef = useRef(null);
  const checkTotpExistsRef = useRef(null);
  const totpEngineNameRef = useRef('totp');
  const setSecretEnginesRef = useRef((e) => {});
  const setSelectedEngineRef = useRef((e) => {});
  const treeViewRef = useRef({ treeViewEnabled: false, currentPath: '', currentFolderContent: null });

  // ========================================
  // AUTHENTIFICATION (hook)
  // ========================================
  const {
    authUser, setAuthUser,
    password, setPassword,
    token, setToken,
    isAdmin, setIsAdmin,
    isModerator, setIsModerator,
    moderatorEngines,
    rememberMe, setRememberMe,
    isCurrentEngineRbiOnly: isCurrentEngineRbiOnlyFn,
    isSecretRbiOnly: isSecretRbiOnlyFn,
    handleLogin, handleLogout, handleSessionExpired,
    revokeToken, cleanupOnLogout,
  } = useAuth({
    vaultUrl, ldapAuthPath,
    showToast, t,
    vaultApiRef,
    fetchEnginesLikeUiRef,
    setSecretEngines: (e) => setSecretEnginesRef.current(e),
    setSelectedEngine: (e) => setSelectedEngineRef.current(e),
    setSecrets: (s) => setSecretsRef.current(s),
    setCurrentView, setVisiblePasswords,
    setAllVaultSecrets, setDiscoveredTags: (tags) => setDiscoveredTagsRef.current(tags),
    setMultiVaultSearch,
    setSelectedSecrets,
    setSearchState: { setSearch, setSearchInput },
  });

  // Service Vault API (recréé quand les credentials changent)
  const vaultApi = useMemo(() => createVaultApi(vaultUrl, token, vaultNs), [vaultUrl, token, vaultNs]);
  vaultApiRef.current = vaultApi;

  // ========================================
  // ENGINES (hook)
  // ========================================
  const fetchSecretsRef = useRef(null);
  const {
    secretEngines, setSecretEngines,
    selectedEngine, setSelectedEngine,
    engineToDelete, setEngineToDelete,
    deletingEngine,
    showEngineModal, setShowEngineModal,
    loadingMounts,
    lastError, lastUiError,
    fetchEnginesLikeUi,
    createEngine,
    confirmDeleteEngine,
    deleteEngine,
  } = useEngines({
    vaultApiRef,
    vaultUrl,
    token,
    setSecrets: (s) => setSecretsRef.current(s),
    fetchSecretsRef,
    restoreFocus: () => restoreFocus(),
    showToast, t,
  });
  fetchEnginesLikeUiRef.current = fetchEnginesLikeUi;
  setSecretEnginesRef.current = setSecretEngines;

  // Wrappers RBI-Only avec selectedEngine du scope (doit être après useEngines)
  const isCurrentEngineRbiOnly = isCurrentEngineRbiOnlyFn(selectedEngine);
  const isSecretRbiOnly = (secretName) => isSecretRbiOnlyFn(secretName, selectedEngine);
  setSelectedEngineRef.current = setSelectedEngine;

  // Wrapper pour handleColumnAutoFit avec le contexte de données
  const autoFitColumn = (e, columnKey) => {
    const dataSource = multiVaultSearch && search.trim() ? allVaultSecrets : secrets;
    handleColumnAutoFit(e, columnKey, { dataSource, treeViewEnabled, selectedEngine });
  };

  // Colonnes effectives : si coffre entièrement RBI-Only, seules name, url et tags sont visibles
  const effectiveVisibleColumns = isCurrentEngineRbiOnly
    ? { name: true, username: false, password: false, url: true, website: false, notes: false, tags: true, customFields: false, actions: false }
    : visibleColumns;

  // ========================================
  // SECRETS (hook)
  // ========================================
  const {
    secrets, setSecrets,
    editSecret, setEditSecret,
    secretToDelete, setSecretToDelete,
    deletingSecret,
    loadingSecrets,
    versionHistory, setVersionHistory,
    loadingAllSecrets, setLoadingAllSecrets,
    fetchSecrets,
    confirmDeleteSecret,
    deleteSecret,
    undeleteSecret,
    handleRestoreVersion,
    handleEditSecretSave,
    handleEditSecretClose,
    filteredSecrets,
  } = useSecrets({
    vaultApiRef,
    vaultUrl,
    selectedEngine,
    search,
    showDeleted,
    treeViewRef,
    multiVaultSearch, allVaultSecrets, setAllVaultSecrets,
    mergeDiscoveredAndSharedTagsRef,
    setDiscoveredTags: (tags) => setDiscoveredTagsRef.current(tags),
    syncExtensionRef,
    restoreFocus: () => restoreFocus(),
    getTotpKeyName: (...args) => getTotpKeyNameRef.current?.(...args),
    checkTotpExists: (...args) => checkTotpExistsRef.current?.(...args),
    totpEngineName: totpEngineNameRef.current,
    showToast, t,
  });
  setSecretsRef.current = setSecrets;

  // Vue arborescence (hook)
  const { treeViewEnabled, setTreeViewEnabled, currentPath, setCurrentPath, currentFolderContent } = useTreeView(secrets);

  // Mettre à jour les refs treeView pour useSecrets (casse la dépendance circulaire)
  treeViewRef.current = { treeViewEnabled, currentPath, currentFolderContent };

  // Gérer le redimensionnement de la fenêtre pour le mode responsive

  const handleDeleteFolder = async (folderPath) => {
    if (!selectedEngine) return;
    try {
      // Vérifier si le dossier contient d'autres secrets que .placeholder
      const folderPrefix = folderPath + '/';
      const nonPlaceholderSecrets = secrets.filter(s =>
        s.name.startsWith(folderPrefix) &&
        !s.name.endsWith('/.placeholder') &&
        s.name !== folderPrefix + '.placeholder'
      );

      if (nonPlaceholderSecrets.length > 0) {
        showToast(t('error.folderNotEmpty'), 'error');
        setFolderContextMenu(null);
        return;
      }

      // Supprimer tous les .placeholder dans ce dossier (récursivement)
      const placeholders = secrets.filter(s =>
        s.name.startsWith(folderPrefix) && s.name.endsWith('/.placeholder')
      );
      // Ajouter le .placeholder direct du dossier
      const directPlaceholder = folderPrefix + '.placeholder';
      const allPlaceholders = secrets.filter(s =>
        s.name === directPlaceholder || (s.name.startsWith(folderPrefix) && s.name.endsWith('/.placeholder'))
      );

      for (const ph of allPlaceholders) {
        if (selectedEngine.version === 2) await deleteSecretV2(selectedEngine, ph.name);
        else await deleteSecretV1(selectedEngine, ph.name);
      }

      setFolderContextMenu(null);
      await fetchSecrets(selectedEngine);
      syncExtensionRef.current?.();
      showToast(t('toast.folderDeleted'), 'success');
    } catch (err) {
      showToast(`${t('error.folderDelete')} ${sanitizeErrorMessage(err)}`, 'error');
    }
  };

  // Configuration chargée via useConfig hook

  useEffect(() => {
    const handleResize = () => {
      // Mettre à jour les dimensions de la fenêtre
      setWindowSize({ width: window.innerWidth, height: window.innerHeight });

      // Si on passe en mode desktop (>= 768px), fermer la sidebar mobile
      if (window.innerWidth >= 768) {
        setSidebarOpen(false);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // ========================================
  // DEEP LINK - Réception de liens rdvault://share/TOKEN
  // ========================================
  useEffect(() => {
    if (!window.electronRBI?.onShareReceived) return;

    const cleanup = window.electronRBI.onShareReceived(async (shareToken) => {
      secureLogger.debug('[DEEP-LINK] Token de partage reçu');

      if (!token) {
        showToast(t('error.notAuthenticatedShare'), 'error', 4000);
        return;
      }

      // SÉCURITÉ: Valider le format du shareToken avant utilisation comme header HTTP
      if (typeof shareToken !== 'string' || shareToken.length === 0 || shareToken.length > 512 || /[\r\n\x00-\x1F]/.test(shareToken)) {
        showToast(t('error.invalidShareToken'), 'error');
        return;
      }

      try {
        showToast(t('toast.fetchingShare'), 'info', 2000);

        // Appeler l'API Vault pour unwrap le token
        const res = await axios.post(
          `${vaultUrl}/v1/sys/wrapping/unwrap`,
          null,
          axiosConfig({
            headers: {
              'X-Vault-Token': shareToken,
              'Content-Type': 'application/json',
            },
          })
        );

        const data = res.data?.data;
        if (!data || !data.url) {
          showToast(t('error.shareDataMissing'), 'error');
          return;
        }

        // SÉCURITÉ: Valider le protocole de l'URL avant lancement RBI
        try {
          const parsedShareUrl = new URL(data.url);
          if (!['http:', 'https:'].includes(parsedShareUrl.protocol)) {
            showToast(t('error.shareUrlInvalid'), 'error');
            return;
          }
        } catch {
          showToast(t('error.invalidUrl'), 'error');
          return;
        }

        // Lancer la session RBI avec les credentials récupérés
        if (window.electronRBI?.launchSession) {
          showToast(t('toast.launchingRbi'), 'info', 2000);
          const result = await window.electronRBI.launchSession({
            url: data.url,
            username: data.username || '',
            password: data.password || '',
            skipOverlay: false, // SÉCURITÉ: Overlay toujours actif (empêche la capture de credentials)
            policies: {
              disableClipboard: true,
              disableNewTabs: true,
              disableDownloads: false,
            },
          });

          if (result.success) {
            showToast(t('toast.rbiOpened'), 'success', 3000);
          } else {
            showToast(result.error || t('error.rbiLaunch'), 'error');
          }
        } else {
          showToast(t('error.rbiUnavailable'), 'error');
        }
      } catch (err) {
        const status = err.response?.status;
        if (status === 400 || status === 404) {
          showToast(t('error.shareExpired'), 'error', 4000);
        } else {
          const msg = sanitizeErrorMessage(err);
          showToast(`${t('common.error')} : ${msg}`, 'error');
        }
      }
    });

    return cleanup;
  }, [token, vaultUrl]); // eslint-disable-line

  // SÉCURITÉ: Session Timeout avec détection de verrouillage PC (3h)
  useSessionTimeout(handleSessionExpired, 10800000, !!token);

  // Toggle login-mode sur body pour la transparence CSS
  useEffect(() => {
    if (!token) {
      document.body.classList.add('login-mode');
      document.documentElement.classList.add('login-mode');
    } else {
      document.body.classList.remove('login-mode');
      document.documentElement.classList.remove('login-mode');
    }
  }, [token]);

  // ========================================
  // SÉCURITÉ: Rate Limiting Hooks
  // ========================================
  const debouncedSearch = useDebounce((searchTerm) => {
    // Cette fonction sera appelée 300ms après la dernière frappe
    setSearch(searchTerm);
  }, 300);

  const throttledCopy = useThrottle((text, fieldName) => {
    // Limiter les copies à 1 par seconde
    startClipboardTimer(fieldName, text);
  }, 1000);

  // totpRateLimit moved to useTotp hook

  const toggleDarkMode = () => {
    setDarkMode(prev => !prev);
  };

  useEffect(() => {
    const theme = darkMode ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('rdvault-theme', theme);
  }, [darkMode]);

  // Raccourcis vers les méthodes du service Vault API
  const { baseHeaders, axiosConfig, writeSecretV2, deleteSecretV2, writeSecretV1, deleteSecretV1, listKeysV2, listKeysV1, readSecretV2, readSecretV1 } = vaultApi;
  const {
    discoveredTags, setDiscoveredTags,
    extractTagsFromSecrets,
    loadSharedTags,
    mergeDiscoveredAndSharedTags,
    handleAddTagToSecret,
    handleRemoveTagFromSecret,
    getTagColor
  } = useTags({
    vaultUrl, baseHeaders, axiosConfig,
    selectedEngine, secretEngines, multiVaultSearch,
    vaultApi, fetchSecretsRef,
    setAllVaultSecrets, setLoadingAllSecrets,
    showToast, t
  });
  setDiscoveredTagsRef.current = setDiscoveredTags;
  mergeDiscoveredAndSharedTagsRef.current = mergeDiscoveredAndSharedTags;

  // Migration / déplacement (hook)
  const {
    migrateSecrets, setMigrateSecrets,
    moveToFolder, setMoveToFolder,
    fetchSecretsForEngine,
    handleMigrateSecrets,
    handleMoveToFolder,
    migrateSecretsToEngine,
    moveSecretsToFolder
  } = useMigration({
    vaultApi, selectedEngine, secretEngines,
    fetchSecretsRef, showDeleted,
    clearSelection, syncExtensionRef,
    showToast, t
  });

  // Drag & Drop (hook)
  const {
    isDragging, dragOverTarget,
    handleDragStart, handleDragEnd, handleDragOver, handleDragLeave,
    handleDropOnEngine, handleDropOnFolder
  } = useDragDrop({
    selectedSecrets, setSelectedSecrets, isSecretSelected,
    migrateSecretsToEngine, moveSecretsToFolder,
    selectedEngine, secretEngines,
    showToast, t
  });

  fetchSecretsRef.current = fetchSecrets;

  const restoreFocus = () => {
    try { window.focus(); } catch {}
    requestAnimationFrame(() => {
      if (searchRef.current) {
        searchRef.current.focus();
        const v = searchRef.current.value; searchRef.current.value = ''; searchRef.current.value = v;
      } else if (appRootRef.current) {
        appRootRef.current.tabIndex = -1;
        appRootRef.current.focus();
      }
    });
  };

  // TOTP (hook)
  const {
    totpDisplay, setTotpDisplay,
    totpConfig, setTotpConfig,
    totpExistsCache, setTotpExistsCache,
    totpRateLimit,
    totpEngineName,
    getTotpKeyName,
    getTotpCode,
    configureTotpKey,
    checkTotpExists,
    handleShowTotp,
    handleCopyTotp,
    handleConfigureTotp,
    handleDeleteTotp,
    handleSaveTotpConfig
  } = useTotp({ vaultUrl, baseHeaders, axiosConfig, selectedEngine, startClipboardTimer, showToast, t, restoreFocus });
  getTotpKeyNameRef.current = getTotpKeyName;
  checkTotpExistsRef.current = checkTotpExists;
  totpEngineNameRef.current = totpEngineName;

  // Menus contextuels (hook)
  const {
    contextMenu, setContextMenu,
    columnContextMenu, setColumnContextMenu,
    tagContextMenu, setTagContextMenu,
    engineContextMenu, setEngineContextMenu,
    folderContextMenu, setFolderContextMenu,
    tagCreateMode, setTagCreateMode,
    tagCreateValue, setTagCreateValue,
    contextMenuRef,
    tagContextMenuRef,
    handleCellRightClick,
    handleEmptyAreaRightClick,
    handleFolderRightClick,
    handleColumnHeaderRightClick,
    handleTagCellRightClick,
    handleEngineRightClick
  } = useContextMenus({ getTotpKeyName, checkTotpExists, discoveredTags });

  // ========================================
  // GESTION DES TAGS
  // ========================================
  // Les tags sont maintenant découverts automatiquement depuis les secrets
  // Pas besoin de fonctions add/remove/refresh

  useEffect(() => {
    if (selectedEngine && token) fetchSecrets(selectedEngine, showDeleted);
  }, [selectedEngine, token, showDeleted]);

  // Sync extension Chrome + CLI IPC (hook)
  useSync({
    vaultApi, token, vaultUrl, authUser,
    secretEngines, selectedEngine,
    syncExtensionRef, totpRateLimit,
    showToast
  });

  useEffect(() => {
    const loadInstalledBrowsers = async () => {
      if (window.electronBrowser?.getInstalledBrowsers) {
        const result = await window.electronBrowser.getInstalledBrowsers();
        if (result.success) {
          setInstalledBrowsers(result.browsers);
        }
      }
    };
    loadInstalledBrowsers();
  }, []);

  useEffect(() => {
    const loadAllSecrets = async () => {
      if (!multiVaultSearch || !token) {
        setAllVaultSecrets([]);
        return;
      }

      setLoadingAllSecrets(true);

      try {
        // Paralléliser le chargement de tous les coffres
        const enginePromises = secretEngines.map(async (engine) => {
          try {
            const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);

            // Paralléliser le chargement des secrets de ce coffre
            const secretPromises = keys.map(async (key) => {
              try {
                const secret = engine.version === 2
                  ? await readSecretV2(engine, key)
                  : await readSecretV1(engine, key);
                return {
                  ...secret,
                  engineName: engine.name,
                  engineVersion: engine.version
                };
              } catch (err) {
                // Ignorer les 404 (secrets avec noms invalides/corrompus)
                if (err.response?.status === 404) {
                  secureLogger.debug('[Vault] Secret ignoré (404)');
                }
                return null;
              }
            });

            const secrets = await Promise.all(secretPromises);
            return secrets.filter(s => s !== null);
          } catch (err) {
            // Ignorer les erreurs de lecture des clés de ce coffre
            secureLogger.warn('[Vault] Coffre ignoré');
            return [];
          }
        });

        const allEngineSecrets = await Promise.all(enginePromises);
        const allSecrets = allEngineSecrets.flat();

        // Extraire les tags découverts depuis tous les coffres + tags partagés
        const tags = await mergeDiscoveredAndSharedTags(allSecrets);
        secureLogger.debug('[loadAllSecrets] tags:', tags.length);
        setDiscoveredTags(tags);

        setAllVaultSecrets(allSecrets);
        setLoadingAllSecrets(false);
      } catch (err) {
        secureLogger.error('[loadAllSecrets] Erreur chargement multi-coffre');
        setLoadingAllSecrets(false);
      }
    };

    loadAllSecrets();
  }, [multiVaultSearch, token, secretEngines]);


  return (
    <div ref={appRootRef} className={`app-container ${!token ? 'login-mode' : ''} ${windowSize.width <= 1366 ? 'small-screen' : ''}`}>
      {/* Bouton menu burger pour mobile */}
      {token && (
        <button
          className="mobile-menu-toggle"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          type="button"
          aria-label="Menu"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      )}

      {/* Indicateur de taille de fenêtre (désactivé) */}
      {/* <div className="window-size-indicator">
        {windowSize.width} × {windowSize.height}
      </div> */}

      {/* Overlay pour fermer la sidebar sur mobile */}
      {token && sidebarOpen && (
        <div
          className="sidebar-overlay visible"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar - visible seulement quand connecté */}
      {token && (
        <Sidebar
          secretEngines={secretEngines}
          selectedEngine={selectedEngine}
          onSelectEngine={(engine) => {
            setSelectedEngine(engine);
            setSearch('');
            setSearchInput('');
            setVisiblePasswords({}); // SÉCURITÉ: Clear visible passwords on engine switch
            setSidebarOpen(false);
            if (currentView === 'admin') setCurrentView('vault');
          }}
          isDragging={isDragging}
          dragOverTarget={dragOverTarget}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDropOnEngine={handleDropOnEngine}
          isAdmin={isAdmin}
          sidebarOpen={sidebarOpen}
          onEngineRightClick={handleEngineRightClick}
          onCreateEngine={() => setShowEngineModal(true)}
          t={t}
        />
      )}

      {/* Main Content */}
      <div className="main-content">
        {/* Bandeau header - masqué en mode admin */}
        {token && currentView !== 'admin' && (
          <div className="main-header">
            <div className="header-content">
              {/* Logo RDVAULT à gauche */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                <img src={process.env.PUBLIC_URL + '/logo.png'} alt="RDVAULT" style={{ height: '48px', width: 'auto' }} />
                <span style={{ fontSize: '24px', fontWeight: '700', letterSpacing: '-0.02em', color: 'var(--accent)' }}>
                  RDVAULT
                </span>
              </div>
              {/* User menu + window controls à droite */}
              <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
                <UserMenu
                  username={authUser || localStorage.getItem('vault-client.username') || t('user.connected')}
                  darkMode={darkMode}
                  onToggleDarkMode={toggleDarkMode}
                  isAdmin={isAdmin}
                  isModerator={isModerator}
                  currentView={currentView}
                  onToggleAdminView={() => setCurrentView(currentView === 'admin' ? 'vault' : 'admin')}
                  onOpenSettings={() => setShowSettings(true)}
                  onLogout={handleLogout}
                />
                <WindowControls />
              </div>
            </div>
          </div>
        )}

        {/* Connexion */}
        {!token && (
          <LoginForm
            authUser={authUser} setAuthUser={setAuthUser}
            password={password} setPassword={setPassword}
            rememberMe={rememberMe} setRememberMe={setRememberMe}
            onLogin={handleLogin}
            configLoaded={configLoaded}
            appMode={appMode}
            t={t}
          />
        )}

        {token && (
          currentView === 'admin' && (isAdmin || isModerator) ? (
            <AdminPanel
              vaultUrl={vaultUrl}
              vaultNs={vaultNs}
              ldapAuthPath={ldapAuthPath}
              token={token}
              baseHeaders={baseHeaders}
              axiosConfig={axiosConfig}
              showToast={showToast}
              username={authUser || localStorage.getItem('vault-client.username') || t('user.connected')}
              darkMode={darkMode}
              onToggleDarkMode={toggleDarkMode}
              currentView={currentView}
              onToggleAdminView={() => setCurrentView('vault')}
              isAdmin={isAdmin}
              isModerator={isModerator}
              moderatorEngines={moderatorEngines}
              onLogout={handleLogout}
            />
          ) : (
            <>
            {/* Toolbar - zone fixe en dehors du scroll */}
            {token && (
              <Toolbar
                selectedEngine={selectedEngine}
                isCurrentEngineRbiOnly={isCurrentEngineRbiOnly}
                treeViewEnabled={treeViewEnabled}
                currentPath={currentPath}
                setEditSecret={setEditSecret}
                searchRef={searchRef}
                searchInput={searchInput}
                setSearchInput={setSearchInput}
                debouncedSearch={debouncedSearch}
                multiVaultSearch={multiVaultSearch}
                setMultiVaultSearch={setMultiVaultSearch}
                search={search}
                setVisiblePasswords={setVisiblePasswords}
                loadingAllSecrets={loadingAllSecrets}
                showDeleted={showDeleted}
                setShowDeleted={setShowDeleted}
                appMode={appMode}
                setReceiveShareOpen={setReceiveShareOpen}
                setTreeViewEnabled={setTreeViewEnabled}
                setCurrentPath={setCurrentPath}
                t={t}
              />
          )}

          {/* Zone scrollable des secrets */}
          <div
            className="main-body"
            onContextMenu={(e) => {
              if (token && selectedEngine) {
                handleEmptyAreaRightClick(e);
              }
            }}
          >
          {/* Breadcrumb navigation */}
          {selectedEngine && !multiVaultSearch && treeViewEnabled && currentPath && (
            <div style={{ marginBottom: 'var(--sp-2)', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              <button
                onClick={() => setCurrentPath('')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--accent)',
                  cursor: 'pointer',
                  padding: 'var(--sp-1) var(--sp-2)',
                  borderRadius: 'var(--radius-sm)',
                  textDecoration: 'underline'
                }}
              >
                Racine
              </button>
              <span>/</span>
              {currentPath.split('/').map((part, index, arr) => {
                const isLast = index === arr.length - 1;
                const partialPath = arr.slice(0, index + 1).join('/');
                return (
                  <React.Fragment key={partialPath}>
                    {isLast ? (
                      <span style={{ fontWeight: 'var(--weight-semibold)', color: 'var(--text-primary)' }}>{part}</span>
                    ) : (
                      <>
                        <button
                          onClick={() => setCurrentPath(partialPath)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: 'var(--accent)',
                            cursor: 'pointer',
                            padding: 'var(--sp-1) var(--sp-2)',
                            borderRadius: 'var(--radius-sm)',
                            textDecoration: 'underline'
                          }}
                        >
                          {part}
                        </button>
                        <span>/</span>
                      </>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          )}

          <SecretsTable
            filteredSecrets={filteredSecrets}
            secrets={secrets}
            allVaultSecrets={allVaultSecrets}
            selectedEngine={selectedEngine}
            loadingSecrets={loadingSecrets}
            multiVaultSearch={multiVaultSearch}
            search={search}
            visiblePasswords={visiblePasswords}
            setVisiblePasswords={setVisiblePasswords}
            effectiveVisibleColumns={effectiveVisibleColumns}
            columnWidths={columnWidths}
            resizingColumn={resizingColumn}
            isCurrentEngineRbiOnly={isCurrentEngineRbiOnly}
            token={token}
            selectedSecrets={selectedSecrets}
            isSecretSelected={isSecretSelected}
            toggleSecretSelection={toggleSecretSelection}
            displayedSecretsRef={displayedSecretsRef}
            isDragging={isDragging}
            dragOverTarget={dragOverTarget}
            handleDragStart={handleDragStart}
            handleDragEnd={handleDragEnd}
            handleDragOver={handleDragOver}
            handleDragLeave={handleDragLeave}
            handleDropOnFolder={handleDropOnFolder}
            handleColumnResizeStart={handleColumnResizeStart}
            autoFitColumn={autoFitColumn}
            handleColumnHeaderRightClick={handleColumnHeaderRightClick}
            handleEmptyAreaRightClick={handleEmptyAreaRightClick}
            handleCellRightClick={handleCellRightClick}
            handleFolderRightClick={handleFolderRightClick}
            handleTagCellRightClick={handleTagCellRightClick}
            isSecretRbiOnly={isSecretRbiOnly}
            startClipboardTimer={startClipboardTimer}
            setNotesPopup={setNotesPopup}
            setCurrentPath={setCurrentPath}
            getTagColor={getTagColor}
            getTotpKeyName={getTotpKeyName}
            getTotpCode={getTotpCode}
            showToast={showToast}
            t={t}
          />

          </div>
          </>
        ))}
      </div>

      {/* Modales */}
      <ModalOrchestrator
        showEngineModal={showEngineModal} setShowEngineModal={setShowEngineModal}
        createEngine={createEngine} isAdmin={isAdmin}
        editSecret={editSecret} handleEditSecretClose={handleEditSecretClose}
        handleEditSecretSave={handleEditSecretSave}
        selectedEngine={selectedEngine} checkTotpExists={checkTotpExists}
        getTotpKeyName={getTotpKeyName} discoveredTags={discoveredTags}
        engineToDelete={engineToDelete} setEngineToDelete={setEngineToDelete}
        deletingEngine={deletingEngine} deleteEngine={deleteEngine}
        secretToDelete={secretToDelete} setSecretToDelete={setSecretToDelete}
        deletingSecret={deletingSecret} deleteSecret={deleteSecret}
        showCreateFolderModal={showCreateFolderModal} setShowCreateFolderModal={setShowCreateFolderModal}
        newFolderName={newFolderName} setNewFolderName={setNewFolderName}
        currentPath={currentPath} writeSecretV2={writeSecretV2} writeSecretV1={writeSecretV1}
        fetchSecrets={fetchSecrets} syncExtensionRef={syncExtensionRef}
        totpDisplay={totpDisplay} setTotpDisplay={setTotpDisplay}
        getTotpCode={getTotpCode} startClipboardTimer={startClipboardTimer}
        totpConfig={totpConfig} setTotpConfig={setTotpConfig}
        handleSaveTotpConfig={handleSaveTotpConfig}
        migrateSecrets={migrateSecrets} setMigrateSecrets={setMigrateSecrets}
        handleMigrateSecrets={handleMigrateSecrets} secretEngines={secretEngines}
        moveToFolder={moveToFolder} setMoveToFolder={setMoveToFolder}
        handleMoveToFolder={handleMoveToFolder} secrets={secrets}
        versionHistory={versionHistory} setVersionHistory={setVersionHistory}
        handleRestoreVersion={handleRestoreVersion}
        vaultUrl={vaultUrl} baseHeaders={baseHeaders} axiosConfig={axiosConfig}
        notesPopup={notesPopup} setNotesPopup={setNotesPopup}
        showSettings={showSettings} setShowSettings={setShowSettings}
        darkMode={darkMode} toggleDarkMode={toggleDarkMode}
        visibleColumns={visibleColumns} toggleColumn={toggleColumn}
        isModerator={isModerator} appMode={appMode} token={token}
        shareRbiSecret={shareRbiSecret} setShareRbiSecret={setShareRbiSecret}
        rbiProxyUrl={rbiProxyUrl}
        receiveShareOpen={receiveShareOpen} setReceiveShareOpen={setReceiveShareOpen}
        restoreFocus={restoreFocus} showToast={showToast} t={t}
      />

      <Toast toast={toast} />

      {/* Clipboard Timer - composant isolé pour éviter re-renders sur les modaux */}
      {clipboardTimer && (
        <ClipboardTimer
          key={clipboardTimer.startTime}
          fieldName={clipboardTimer.fieldName}
          duration={clipboardTimer.duration}
          startTime={clipboardTimer.startTime}
          onClear={clearClipboardNow}
          onExpire={handleClipboardExpire}
        />
      )}

      {/* Context Menu - Secrets */}
      <SecretContextMenu
        contextMenu={contextMenu}
        contextMenuRef={contextMenuRef}
        setContextMenu={setContextMenu}
        selectedEngine={selectedEngine}
        isCurrentEngineRbiOnly={isCurrentEngineRbiOnly}
        isSecretRbiOnly={isSecretRbiOnly}
        treeViewEnabled={treeViewEnabled}
        currentPath={currentPath}
        setEditSecret={setEditSecret}
        setShowCreateFolderModal={setShowCreateFolderModal}
        setNewFolderName={setNewFolderName}
        undeleteSecret={undeleteSecret}
        confirmDeleteSecret={confirmDeleteSecret}
        startClipboardTimer={startClipboardTimer}
        getTotpKeyName={getTotpKeyName}
        getTotpCode={getTotpCode}
        handleShowTotp={handleShowTotp}
        handleCopyTotp={handleCopyTotp}
        handleConfigureTotp={handleConfigureTotp}
        handleDeleteTotp={handleDeleteTotp}
        setShareRbiSecret={setShareRbiSecret}
        setVersionHistory={setVersionHistory}
        setMoveToFolder={setMoveToFolder}
        setMigrateSecrets={setMigrateSecrets}
        selectedSecrets={selectedSecrets}
        secrets={secrets}
        installedBrowsers={installedBrowsers}
        appMode={appMode}
        showToast={showToast}
        t={t}
      />

      {/* Context Menus - Folder, Column, Tag, Engine */}
      <ContextMenus
        folderContextMenu={folderContextMenu}
        handleDeleteFolder={handleDeleteFolder}
        columnContextMenu={columnContextMenu}
        visibleColumns={visibleColumns}
        setVisibleColumns={setVisibleColumns}
        tagContextMenu={tagContextMenu}
        setTagContextMenu={setTagContextMenu}
        tagContextMenuRef={tagContextMenuRef}
        tagCreateMode={tagCreateMode}
        setTagCreateMode={setTagCreateMode}
        tagCreateValue={tagCreateValue}
        setTagCreateValue={setTagCreateValue}
        handleAddTagToSecret={handleAddTagToSecret}
        handleRemoveTagFromSecret={handleRemoveTagFromSecret}
        getTagColor={getTagColor}
        engineContextMenu={engineContextMenu}
        setEngineContextMenu={setEngineContextMenu}
        setEngineToDelete={setEngineToDelete}
        t={t}
      />
    </div>
  );
}
