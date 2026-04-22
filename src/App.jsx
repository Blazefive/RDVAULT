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
import EditSecretModal from './EditSecretModal.jsx';     // Modal création/édition de secrets
import EditEngineModal from './EditEngineModal';         // Modal création de secret engines
import ConfirmModal from './ConfirmModal.jsx';           // Modal de confirmation (suppressions, etc.)
import TotpDisplayModal from './TotpDisplayModal.jsx';   // Modal affichage de codes TOTP
import TotpConfigModal from './TotpConfigModal.jsx';     // Modal configuration TOTP
import UserMenu from './UserMenu.jsx';                   // Menu utilisateur (déconnexion, settings)
import AdminPanel from './AdminPanel.jsx';               // Panneau d'administration (logs, policies)
import VersionHistoryModal from './VersionHistoryModal.jsx';  // Historique des versions de secrets
import MigrateSecretModal from './MigrateSecretModal.jsx';    // Modal de migration de secrets entre engines
import MoveToFolderModal from './MoveToFolderModal.jsx';      // Modal déplacement vers un dossier (intra-engine)
import NotesPopupModal from './NotesPopupModal.jsx';     // Modal affichage de notes (double-clic)
import SettingsModal from './SettingsModal.jsx';         // Modal paramètres (thème, colonnes, version)
import LoadingSpinner from './LoadingSpinner.jsx';       // Indicateur de chargement
import ClipboardTimer from './ClipboardTimer.jsx';       // Timer clipboard isolé (évite re-renders)
import EditSecretModalWrapper from './EditSecretModalWrapper.jsx'; // Wrapper modal édition (évite re-renders)
import WindowControls from './WindowControls.jsx';       // Boutons fenêtre frameless (minimiser/maximiser/fermer)
import ShareRbiModal from './ShareRbiModal.jsx';         // Modal partage RBI via Vault wrapping
import { useTranslation } from './i18n';                 // Internationalisation

import './AppStyles.css';
import { sanitizeForDisplay, buildSafeUrl, encodeEnginePath, validateSecretName, sanitizeError, sanitizeErrorMessage, safeWindowOpen } from './utils/security';
import { handleUrlAction } from './utils/urlHandler';
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
import LoginForm from './components/auth/LoginForm';
import Toolbar from './components/layout/Toolbar';
import Sidebar from './components/layout/Sidebar';
import SecretContextMenu from './components/menus/SecretContextMenu';

// ========================================
// IMPORTS DES MODULES DE SÉCURITÉ
// ========================================
import { useSessionTimeout } from './useSessionTimeout';
import { useDebounce, useThrottle, useRateLimit } from './useRateLimit';
import * as validation from './validation';
import secureLogger from './secureLogger';
import bruteForceProtection from './bruteForceProtection';

// RateLimiter supprimé — remplacé par bruteForceProtection.js

export default function App() {
  const { t, lang, setLang } = useTranslation();
  const { vaultUrl, ldapAuthPath, rbiProxyUrl, configLoaded, appMode, vaultNs } = useConfig(setLang);
  const [authUser, setAuthUser] = useState(() => {
    // Charger le nom d'utilisateur sauvegardé si disponible
    return localStorage.getItem('rdvault-saved-username') || '';
  });
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [currentView, setCurrentView] = useState('vault'); // 'vault' ou 'admin'
  const [rememberMe, setRememberMe] = useState(() => {
    // Si un nom d'utilisateur est sauvegardé, cocher la case par défaut
    return !!localStorage.getItem('rdvault-saved-username');
  });
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('rdvault-theme');
    return saved === 'dark';
  });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [windowSize, setWindowSize] = useState({ width: window.innerWidth, height: window.innerHeight });

  const [secretEngines, setSecretEngines] = useState([]);
  const [selectedEngine, setSelectedEngine] = useState(null);

  const [secrets, setSecrets] = useState([]);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [visiblePasswords, setVisiblePasswords] = useState({});
  const [editSecret, setEditSecret] = useState(null);
  const [showEngineModal, setShowEngineModal] = useState(false);

  const [engineToDelete, setEngineToDelete] = useState(null);
  const [deletingEngine, setDeletingEngine] = useState(false);
  const [secretToDelete, setSecretToDelete] = useState(null);
  const [deletingSecret, setDeletingSecret] = useState(false);

  const [lastError, setLastError] = useState('');
  const [lastUiError, setLastUiError] = useState('');
  const [loadingMounts, setLoadingMounts] = useState(false);

  const [showDeleted, setShowDeleted] = useState(false);
  const [installedBrowsers, setInstalledBrowsers] = useState([]);

  const [versionHistory, setVersionHistory] = useState(null);
  const [multiVaultSearch, setMultiVaultSearch] = useState(false);
  const [allVaultSecrets, setAllVaultSecrets] = useState([]);
  const [showCreateFolderModal, setShowCreateFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [loadingAllSecrets, setLoadingAllSecrets] = useState(false);

  // ========================================
  // NOUVEAUX ÉTATS POUR VERSION 1.1
  // ========================================
  const { toast, showToast } = useToast();
  const { clipboardTimer, clearClipboardNow, handleClipboardExpire, startClipboardTimer } = useClipboard(showToast, t);
  const { visibleColumns, setVisibleColumns, columnWidths, resizingColumn, toggleColumn, saveColumnWidths, handleColumnResizeStart, handleColumnResizeMove, handleColumnResizeEnd, handleColumnAutoFit } = useColumns(showToast, t);
  const [notesPopup, setNotesPopup] = useState(null);           // Popup affichage notes
  const [showSettings, setShowSettings] = useState(false);      // Modal paramètres
  // discoveredTags moved to useTags hook
  const [isModerator, setIsModerator] = useState(false);        // Rôle modérateur
  const [moderatorEngines, setModeratorEngines] = useState([]); // Coffres gérés par modérateur
  const [rbiOnlyEngines, setRbiOnlyEngines] = useState(new Set()); // Coffres entièrement RBI-only
  const [rbiOnlySecrets, setRbiOnlySecrets] = useState(new Set()); // Secrets spécifiques RBI-only (format: "engine/secret")
  const [shareRbiSecret, setShareRbiSecret] = useState(null);   // Secret à partager via RBI wrapping
  const [receiveShareOpen, setReceiveShareOpen] = useState(false); // Modal réception partage RBI
  const [loadingSecrets, setLoadingSecrets] = useState(false);  // Indicateur chargement secrets

  // ========================================
  // ÉTATS POUR MULTI-SÉLECTION ET DRAG & DROP (v1.4)
  // ========================================
  const { selectedSecrets, setSelectedSecrets, lastClickedSecretRef, displayedSecretsRef, toggleSecretSelection, selectAllSecrets, clearSelection, isSecretSelected } = useSelection();

  // Vue arborescence (hook)
  const { treeViewEnabled, setTreeViewEnabled, currentPath, setCurrentPath, currentFolderContent } = useTreeView(secrets);

  const searchRef = useRef(null);
  const appRootRef = useRef(null);
  const syncExtensionRef = useRef(null);

  // Vérifier si le coffre sélectionné est entièrement RBI-Only
  const isCurrentEngineRbiOnly = selectedEngine && rbiOnlyEngines.has(selectedEngine.name);
  // Vérifier si un secret spécifique est RBI-Only
  const isSecretRbiOnly = (secretName) => {
    if (!selectedEngine) return false;
    if (rbiOnlyEngines.has(selectedEngine.name)) return true;
    return rbiOnlySecrets.has(selectedEngine.name + '/' + secretName);
  };

  // Service Vault API (recréé quand les credentials changent)
  const vaultApi = useMemo(() => createVaultApi(vaultUrl, token, vaultNs), [vaultUrl, token, vaultNs]);

  // Wrapper pour handleColumnAutoFit avec le contexte de données
  const autoFitColumn = (e, columnKey) => {
    const dataSource = multiVaultSearch && search.trim() ? allVaultSecrets : secrets;
    handleColumnAutoFit(e, columnKey, { dataSource, treeViewEnabled, selectedEngine });
  };

  // Colonnes effectives : si coffre entièrement RBI-Only, seules name, url et tags sont visibles
  const effectiveVisibleColumns = isCurrentEngineRbiOnly
    ? { name: true, username: false, password: false, url: true, website: false, notes: false, tags: true, customFields: false, actions: false }
    : visibleColumns;

  // Gérer le redimensionnement de la fenêtre pour le mode responsive

  const handleRestoreVersion = async (version, versionData) => {
    try {
      if (!selectedEngine || selectedEngine.version !== 2 || !versionHistory) return;

      await writeSecretV2(selectedEngine, {
        name: versionHistory.secretName,
        username: versionData.Username || '',
        password: versionData.Password || '',
        url: versionData.URL || '',
        website: versionData.Website || '',
        notes: versionData.Notes || ''
      });

      await fetchSecrets(selectedEngine);
      // Resynchroniser l'extension Chrome
      syncExtensionRef.current?.();
      showToast(t('toast.versionRestored', { version }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.restoreVersion')} ${msg}`, 'error');
    }
  };

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

  // ========================================
  // SÉCURITÉ: Session Timeout avec détection de verrouillage PC
  // ========================================
  // Déconnexion automatique UNIQUEMENT si le PC est verrouillé pendant 3 heures
  // - Session active (PC déverrouillé): PAS de timeout, l'utilisateur reste connecté
  // - PC verrouillé: Timer de 3 heures démarre, déconnexion si pas déverrouillé
  useSessionTimeout(() => {
    if (token) {
      secureLogger.warn('Session expirée (PC verrouillé pendant 3 heures)');
      revokeToken();
      cleanupOnLogout();
      setToken('');
      setAuthUser('');
      setPassword('');
      setSecretEngines([]);
      setSelectedEngine(null);
      setSecrets([]);
      setRbiOnlyEngines(new Set());
      setRbiOnlySecrets(new Set());
      showToast(t('login.sessionExpired'), 'warning', 4000);
      if (window.electronWindow?.setLoginMode) window.electronWindow.setLoginMode();
    }
  }, 10800000, !!token); // 3h si verrouillé, pas de timeout sinon, actif seulement si connecté

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
  const { baseHeaders, axiosConfig } = vaultApi;

  // SÉCURITÉ: Nettoyage des données sensibles dans localStorage lors de la déconnexion
  const cleanupOnLogout = () => {
    localStorage.removeItem('vault-client.username');
    localStorage.removeItem('vault-client.isAdmin');
    // Révoquer la session CLI (régénérer le token pour invalider les sessions en cours)
    if (window.electronCLI?.revokeSession) {
      window.electronCLI.revokeSession().catch(() => {});
    }
    // Nettoyer les configs SSH d'audit
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('vault-audit-ssh-')) localStorage.removeItem(key);
    });
    // Nettoyer les états sensibles en mémoire
    setVisiblePasswords({});
    setAllVaultSecrets([]);
    setSelectedSecrets(new Set());
    setDiscoveredTags([]);
    setIsModerator(false);
    setModeratorEngines([]);
    setMultiVaultSearch(false);
    // SÉCURITÉ: Vider le fichier de sync extension Chrome (supprimer les secrets du disque)
    try {
      if (window.electronSync?.writeState) {
        window.electronSync.writeState({
          vaultUrl: '', username: '', connected: false, secrets: []
        });
      }
    } catch (err) { /* ignore */ }
  };

  // SÉCURITÉ: Révoquer le token Vault côté serveur avant déconnexion
  const revokeToken = async () => {
    if (!token) return;
    try {
      await axios.post(`${vaultUrl}/v1/auth/token/revoke-self`, null, axiosConfig({ headers: baseHeaders() }));
    } catch { /* best-effort */ }
  };

  const handleLogin = async () => {
    try {
      // ========================================
      // SÉCURITÉ: Validation des entrées
      // ========================================
      if (!authUser || !password) {
        showToast(t('login.fieldsRequired'), 'error');
        return;
      }

      // Valider le format du username
      const usernameValidation = validation.validateUsername(authUser);
      if (!usernameValidation.valid) {
        showToast(usernameValidation.error, 'error');
        return;
      }

      // Valider le format du password
      const passwordValidation = validation.validatePassword(password);
      if (!passwordValidation.valid) {
        showToast(passwordValidation.error, 'error');
        return;
      }

      // ========================================
      // SÉCURITÉ: Vérifier le brute force protection
      // ========================================
      if (bruteForceProtection.isBlocked(authUser)) {
        const stats = bruteForceProtection.getStats(authUser);
        const remainingSeconds = Math.ceil((stats.blockedUntil - Date.now()) / 1000);
        showToast(t('login.bruteForceLocked', { seconds: remainingSeconds }), 'error', 4000);
        return;
      }

      // SÉCURITÉ: Capturer et effacer le mot de passe du state AVANT la requête réseau
      const currentPassword = password;
      setPassword('');
      const res = await axios.post(`${vaultUrl}/v1/${ldapAuthPath}/login/${encodeURIComponent(authUser)}`, { password: currentPassword }, axiosConfig({ headers: baseHeaders() }));
      const userToken = res.data?.auth?.client_token;
      setToken(userToken);

      // ========================================
      // SÉCURITÉ: Connexion réussie - Reset brute force protection
      // ========================================
      bruteForceProtection.registerSuccessfulAttempt(authUser);

      // Sauvegarder ou supprimer le nom d'utilisateur selon la case à cocher
      if (rememberMe) {
        localStorage.setItem('rdvault-saved-username', authUser);
      } else {
        localStorage.removeItem('rdvault-saved-username');
      }

      try {
        const tokenInfo = await axios.get(`${vaultUrl}/v1/auth/token/lookup-self`, axiosConfig({ headers: baseHeaders(userToken) }));
        const entityName = tokenInfo.data?.data?.entity_name || authUser;
        const policies = tokenInfo.data?.data?.policies || [];

        // Détecter si l'utilisateur est admin (a la policy "admin" ou "root")
        const hasAdminPolicy = policies.some(p => p.toLowerCase() === 'admin' || p.toLowerCase() === 'root');
        setIsAdmin(hasAdminPolicy);

        // Détecter les coffres avec niveau "moderator" dans les policies
        const moderatorEnginesList = [];
        secureLogger.debug('[MODERATOR] Vérification des policies');

        for (const policyName of policies) {
          try {
            const policyRes = await axios.get(
              `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`,
              axiosConfig({ headers: baseHeaders(userToken) })
            );
            const policyHcl = policyRes.data?.data?.policy || policyRes.data?.policy || '';

            // Chercher les commentaires MODERATOR dans le HCL
            const moderatorMatches = [
              ...policyHcl.matchAll(/# KV v2 MODERATOR \(([^)]+)\)/g),
              ...policyHcl.matchAll(/# KV v1 MODERATOR \(([^)]+)\)/g)
            ];

            if (moderatorMatches.length > 0) {
              secureLogger.debug('[MODERATOR] Policy contient des droits moderateur');
            }

            for (const match of moderatorMatches) {
              const engineName = match[1];
              if (!moderatorEnginesList.includes(engineName)) {
                moderatorEnginesList.push(engineName);
              }
            }
          } catch (err) {
            // Ignorer les erreurs de lecture de policy
            secureLogger.warn('[Policy] Impossible de lire une policy');
          }
        }

        secureLogger.debug('[MODERATOR] Coffres modérateur détectés:', moderatorEnginesList.length);
        setIsModerator(moderatorEnginesList.length > 0);
        setModeratorEngines(moderatorEnginesList);

        // Détecter les coffres et secrets RBI-ONLY dans les policies
        const rbiEnginesSet = new Set();
        const rbiSecretsSet = new Set();
        for (const policyName of policies) {
          try {
            const policyRes = await axios.get(
              `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`,
              axiosConfig({ headers: baseHeaders(userToken) })
            );
            const policyHcl = policyRes.data?.data?.policy || policyRes.data?.policy || '';
            if (policyHcl.includes('# RBI-ONLY')) {
              // KV v2 coffre entier : # RBI-ONLY suivi de path "X/metadata/*"
              for (const m of policyHcl.matchAll(/# RBI-ONLY\npath "([^"]+)\/metadata\/\*"/g)) {
                rbiEnginesSet.add(m[1]);
              }
              // KV v1 coffre entier : # RBI-ONLY suivi de path "X/*"
              for (const m of policyHcl.matchAll(/# RBI-ONLY\npath "([^"]+)\/\*"/g)) {
                rbiEnginesSet.add(m[1]);
              }
              // KV v2 secret spécifique : # RBI-ONLY suivi de # Secret: puis path "X/metadata/Y"
              for (const m of policyHcl.matchAll(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/metadata\/([^"*\s]+)"/g)) {
                rbiSecretsSet.add(m[1] + '/' + m[2]);
              }
              // KV v1 secret spécifique : # RBI-ONLY suivi de # Secret: puis path "X/Y"
              for (const m of policyHcl.matchAll(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/([^"*\s]+)"/g)) {
                rbiSecretsSet.add(m[1] + '/' + m[2]);
              }
              secureLogger.debug('[RBI-ONLY] Policy contient des restrictions');
            }
          } catch (err) {
            secureLogger.warn('[RBI-ONLY] Impossible de lire une policy');
          }
        }
        setRbiOnlyEngines(rbiEnginesSet);
        setRbiOnlySecrets(rbiSecretsSet);
        secureLogger.debug('[RBI-ONLY] Engines:', rbiEnginesSet.size, 'Secrets:', rbiSecretsSet.size);

        // Afficher le panel admin par défaut pour les admins
        if (hasAdminPolicy) {
          setCurrentView('admin');
        }

        localStorage.setItem('vault-client.username', entityName);
        // isAdmin stocké en mémoire uniquement (pas dans localStorage)
      } catch {
        localStorage.setItem('vault-client.username', authUser);
        setIsAdmin(false);
        setIsModerator(false);
      }

      await fetchEnginesLikeUi(userToken);

      // Note: Les secrets seront synchronisés automatiquement par le useEffect
      // quand le premier coffre sera chargé

      showToast(t('login.success'), 'success');

      // Passer la fenêtre en mode principal (1280x800)
      if (window.electronWindow?.setMainMode) await window.electronWindow.setMainMode();
    } catch (err) {
      // ========================================
      // SÉCURITÉ: Différencier erreur réseau vs erreur d'authentification
      // ========================================
      const isNetworkError = !err.response && (
        err.code === 'ECONNREFUSED' || err.code === 'ECONNABORTED' ||
        err.code === 'ETIMEDOUT' || err.code === 'ERR_NETWORK' ||
        err.message?.includes('Network Error')
      );

      if (isNetworkError) {
        // Erreur réseau (Vault inaccessible, pas de VPN, etc.) — ne pas décompter d'essai
        showToast(t('login.networkError'), 'error', 5000);
        secureLogger.warn('Échec connexion : erreur réseau (non décompté)');
      } else if (authUser) {
        const bruteForceResult = bruteForceProtection.registerFailedAttempt(authUser);

        if (bruteForceResult.blocked) {
          // Compte bloqué après trop de tentatives
          showToast(bruteForceResult.message, 'error', 4000);
          secureLogger.warn('Tentative de connexion bloquée');
        } else {
          // Tentative échouée mais pas encore bloqué
          const safeMessage = sanitizeError(err);
          const detailedMessage = `${safeMessage}. ${bruteForceResult.message}`;
          showToast(`${t('login.failed')} : ${detailedMessage}`, 'error', 4000);
          secureLogger.warn(`Échec authentification (${bruteForceResult.remainingAttempts} tentatives restantes)`);
        }
      } else {
        // Pas de username fourni
        const safeMessage = sanitizeError(err);
        showToast(`${t('login.failed')} : ${safeMessage}`, 'error');
      }
    }
  };

  // ========================================
  // DÉCOUVERTE DES SECRET ENGINES (wrapper avec gestion d'état)
  // ========================================
  const fetchEnginesLikeUi = async (userToken = token) => {
    setLoadingMounts(true);
    setLastError(''); setLastUiError('');
    try {
      const { engines, errors } = await vaultApi.fetchEnginesRaw(userToken);
      if (errors.uiError) setLastUiError(errors.uiError);
      if (errors.sysError) setLastError(errors.sysError);
      setSecretEngines(engines);
      setSelectedEngine(engines[0] || null);
      if (!engines.length) setSecrets([]);
    } finally {
      setLoadingMounts(false);
    }
  };

  // Mémoiser le filtrage du tableau (hot path)
  const filteredSecrets = useMemo(() => {
    // Source des secrets selon le mode
    const rawSourceSecrets = multiVaultSearch && search.trim()
      ? allVaultSecrets
      : (treeViewEnabled && !multiVaultSearch
          ? (search.trim()
              ? secrets
                  .filter(s => !currentPath || s.name.startsWith(currentPath + '/'))
                  .map(s => ({ ...s, displayName: s.name.split('/').pop() }))
              : currentFolderContent)
          : secrets);
    // Masquer les .placeholder de l'affichage
    const sourceSecrets = rawSourceSecrets.filter(s => !s.name?.endsWith('/.placeholder') && s.name !== '.placeholder');
    const filtered = sourceSecrets.filter(s => {
      const searchRaw = search.trim();

      // Si pas de recherche, afficher tout
      if (!searchRaw) return true;

      // Extraire les tags (#tag) et le texte libre de la recherche
      const searchTags = [];
      const textParts = [];
      for (const part of searchRaw.split(/\s+/)) {
        if (part.startsWith('#') && part.length > 1) {
          searchTags.push(part.slice(1).toLowerCase());
        } else {
          textParts.push(part);
        }
      }
      const textQuery = textParts.join(' ').toLowerCase();

      // Vérifier les tags : TOUS les tags recherchés doivent être présents
      if (searchTags.length > 0) {
        const secretTags = s.tags ? s.tags.toLowerCase().split(/[\s,;]+/).filter(t => t) : [];
        const allTagsMatch = searchTags.every(tag => secretTags.some(st => st.includes(tag)));
        if (!allTagsMatch) return false;
        // Si que des tags sans texte, le match tags suffit
        if (!textQuery) return true;
      }

      // Si c'est un dossier, filtrer par le nom du dossier
      if (s.isFolder) {
        return s.displayName.toLowerCase().includes(textQuery) ||
               s.name.toLowerCase().includes(textQuery);
      }

      // En vue arborescence, chercher sur le nom de l'entrée (sans le chemin du dossier)
      const searchName = treeViewEnabled && s.name.includes('/')
        ? s.name.split('/').pop()
        : s.name;

      // Recherche dans les champs standards
      const matchesStandard =
        searchName.toLowerCase().includes(textQuery) ||
        (s.username && s.username.toLowerCase().includes(textQuery)) ||
        (s.notes && s.notes.toLowerCase().includes(textQuery)) ||
        (s.url && s.url.toLowerCase().includes(textQuery)) ||
        false; // SÉCURITÉ: Ne pas inclure le mot de passe dans la recherche

      // Recherche dans les champs personnalisés
      // SÉCURITÉ: Exclure les champs protégés (comme les mots de passe) de la recherche
      const matchesCustomFields = s.customFields && Array.isArray(s.customFields) && s.customFields.some(
        field => field.value && !field.protected && String(field.value).toLowerCase().includes(textQuery)
      );

      return matchesStandard || matchesCustomFields;
    });

    return filtered;
  }, [multiVaultSearch, search, allVaultSecrets, treeViewEnabled, secrets, currentPath, currentFolderContent, showDeleted]);

  // Raccourcis vers les méthodes CRUD du service Vault API
  const { readSecretV2, writeSecretV2, deleteSecretV2, listKeysV2, listKeysV1, readSecretV1, writeSecretV1, deleteSecretV1, readSecretForMigration, writeSecretToEngine, deleteSecretFromEngine } = vaultApi;

  // Tags (hook) - ref pour fetchSecrets (dépendance circulaire)
  const fetchSecretsRef = useRef(null);
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

  const fetchSecrets = async (engine, includeDeleted = false) => {
    setLoadingSecrets(true);
    try {
      const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
      secureLogger.debug('[fetchSecrets]', engine.name, keys.length);

      // Paralléliser le chargement de tous les secrets
      const secretsPromises = keys.map(async (key) => {
        if (engine.version === 2 && includeDeleted) {
          try {
            const metaRes = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
            const currentVersion = metaRes.data?.data?.current_version;
            const versionData = metaRes.data?.data?.versions?.[currentVersion];

            if (versionData?.deletion_time) {
              return { name: key, username: '', password: '', url: '', notes: '', deleted: true };
            } else {
              try {
                const item = await readSecretV2(engine, key);
                return { ...item, deleted: false };
              } catch {
                return null;
              }
            }
          } catch {
            return null;
          }
        } else {
          try {
            const item = engine.version === 2 ? await readSecretV2(engine, key) : await readSecretV1(engine, key);
            return { ...item, deleted: false };
          } catch {
            return null;
          }
        }
      });

      const results = await Promise.all(secretsPromises);
      const all = results.filter(s => s !== null);
      secureLogger.debug('[fetchSecrets]', results.length, 'valid:', all.length);

      // Extraire les tags découverts depuis les secrets + tags partagés
      const tags = await mergeDiscoveredAndSharedTags(all);
      secureLogger.debug('[fetchSecrets] tags:', tags.length);
      setDiscoveredTags(tags);

      setSecrets(all);
      setLoadingSecrets(false);
    } catch (err) {
      setLoadingSecrets(false);
      if (err.response?.status === 403) {
        setSecrets([]);
        showToast(t('error.noReadAccess'), 'error', 3500);
      } else if (err.response?.status === 404) {
        setSecrets([]);
      } else {
        setSecrets([]);
        showToast(`${t('error.engineList')} : ${sanitizeErrorMessage(err)}`, 'error', 3500);
      }
    }
  };
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

  const createEngine = async ({ name, version, description }) => {
    const mountPath = name.replace(/^\/+|\/+$/g, '');
    const body = { type: 'kv', description: description || undefined, options: { version: String(version) } };
    try {
      await axios.post(`${vaultUrl}/v1/sys/mounts/${encodeEnginePath(mountPath)}`, body, axiosConfig({ headers: baseHeaders() }));
      await fetchEnginesLikeUi(token);
      const created = { name: mountPath, version: Number(version) === 2 ? 2 : 1 };
      setSelectedEngine(created);
      await fetchSecrets(created);
      // Note: syncExtensionRef sera appelé automatiquement via le useEffect qui détecte le changement de secretEngines
      showToast(t('toast.engineCreated'), 'success');
      restoreFocus();
    } catch (err) {
      restoreFocus();
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.engineCreate')} : ${msg}`, 'error');
      throw err;
    }
  };

  const confirmDeleteEngine = (engine) => setEngineToDelete(engine);
  const deleteEngine = async () => {
    if (!engineToDelete) return;
    const mountPath = engineToDelete.name.replace(/^\/+|\/+$/g, '');
    try {
      setDeletingEngine(true);
      await axios.delete(`${vaultUrl}/v1/sys/mounts/${encodeEnginePath(mountPath)}`, axiosConfig({ headers: baseHeaders() }));
      setEngineToDelete(null);
      await fetchEnginesLikeUi(token);
      if (selectedEngine?.name === mountPath) {
        setSelectedEngine(null);
        setSecrets([]);
      }
      // Note: syncExtensionRef sera appelé automatiquement via le useEffect qui détecte le changement de secretEngines
      restoreFocus();
      showToast(t('toast.engineDeleted'), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.engineDelete')} : ${msg}`, 'error');
    } finally {
      setDeletingEngine(false);
    }
  };

  const confirmDeleteSecret = async (secret) => {
    const totpKeyName = getTotpKeyName(secret.name);
    const totpExists = await checkTotpExists(totpKeyName);
    setSecretToDelete({ ...secret, totpExists });
  };

  const deleteSecret = async () => {
    if (!secretToDelete || !selectedEngine) return;
    const key = secretToDelete.name;
    try {
      setDeletingSecret(true);

      if (selectedEngine.version === 2) await deleteSecretV2(selectedEngine, key);
      else await deleteSecretV1(selectedEngine, key);

      if (secretToDelete.totpExists) {
        try {
          const totpKeyName = getTotpKeyName(key);
          await axios.delete(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(totpKeyName)}`, axiosConfig({ headers: baseHeaders() }));
        } catch (totpErr) {}
      }

      // Retirer immédiatement le secret de l'état local (évite qu'il reste visible)
      setSecrets(prev => prev.filter(s => s.name !== key));
      setSecretToDelete(null);

      // Petit délai pour KV v1 (consistance éventuelle de Vault)
      if (selectedEngine.version === 1) await new Promise(r => setTimeout(r, 300));

      await fetchSecrets(selectedEngine, showDeleted);
      // Resynchroniser l'extension Chrome
      syncExtensionRef.current?.();
      restoreFocus();
      showToast(t('toast.secretDeleted'), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.deleteSecret')} ${msg}`, 'error');
    } finally {
      setDeletingSecret(false);
    }
  };

  const undeleteSecret = async (secret) => {
    if (!selectedEngine || selectedEngine.version !== 2) return;
    const key = secret.name;
    try {
      const metaRes = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
      const versions = Object.keys(metaRes.data?.data?.versions || {}).map(Number);

      if (versions.length > 0) {
        await axios.post(`${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/undelete/${encodeURIComponent(key)}`, { versions }, axiosConfig({ headers: baseHeaders() }));
      }
      await fetchSecrets(selectedEngine, showDeleted);
      // Resynchroniser l'extension Chrome
      syncExtensionRef.current?.();
      showToast(t('toast.secretRestored', { version: key }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.retrieveSecret')} ${msg}`, 'error');
    }
  };

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

  // Callbacks mémorisés pour EditSecretModalWrapper (évite re-renders)
  const handleEditSecretClose = useCallback(() => {
    setEditSecret(null);
    restoreFocus();
  }, []);

  const handleEditSecretSave = useCallback(async (updated) => {
    try {
      if (!selectedEngine) throw new Error('Aucun moteur sélectionné');
      if (!updated.name || !updated.name.trim()) { showToast(t('error.nameRequired'), 'error'); return; }

      // Création de dossier via .placeholder
      if (updated.entryType === 'folder') {
        const folderName = updated.name.trim().replace(/\/+$/, ''); // Retirer les trailing slashes
        const placeholderPath = (treeViewEnabled && currentPath ? `${currentPath}/` : '') + folderName + '/.placeholder';
        const placeholderEntry = {
          name: placeholderPath,
          username: '',
          password: '',
          url: '',
          website: '',
          notes: '',
          tags: '',
          entryType: 'placeholder'
        };
        if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, placeholderEntry);
        else await writeSecretV1(selectedEngine, placeholderEntry);
        setEditSecret(null);
        await fetchSecrets(selectedEngine);
        syncExtensionRef.current?.();
        restoreFocus();
        showToast(t('toast.folderCreated'), 'success');
        return;
      }

      if (!updated.website) updated.website = '';

      // Si on renomme, vérifier le TOTP et supprimer l'ancienne entrée
      if (editSecret?.name && editSecret.name !== updated.name) {
        const totpKeyName = getTotpKeyName(editSecret.name);
        const hasTot = await checkTotpExists(totpKeyName);
        if (hasTot) {
          showToast(t('error.totpLocksRename'), 'error');
          return;
        }

        // Supprimer l'ancienne entrée
        try {
          if (selectedEngine.version === 2) {
            await deleteSecretV2(selectedEngine, editSecret.name);
          } else {
            await deleteSecretV1(selectedEngine, editSecret.name);
          }
        } catch (err) {
          secureLogger.debug('[Vault] Erreur suppression ancienne entrée');
        }
      }

      if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, updated);
      else await writeSecretV1(selectedEngine, updated);
      setEditSecret(null);
      await fetchSecrets(selectedEngine);
      // Resynchroniser l'extension Chrome
      syncExtensionRef.current?.();
      restoreFocus();
      showToast(t('toast.secretSaved'), 'success');
    } catch (err) {
      restoreFocus();
      let msg = sanitizeErrorMessage(err);

      // Message spécifique pour erreur 500 (souvent lié à la taille du payload)
      if (err.response?.status === 500) {
        msg = 'Le secret est trop volumineux. Réduisez la taille des fichiers joints (max 2 MB par fichier recommandé) ou le nombre de champs personnalisés.';
      }

      showToast(`${t('error.saveSecret')} ${msg}`, 'error');
    }
  }, [selectedEngine, editSecret, currentPath, treeViewEnabled]);

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
                  onLogout={async () => {
                    await revokeToken();
                    try {
                      if (window.electronSync?.writeState) {
                        await window.electronSync.writeState({
                          vaultUrl: '',
                          username: '',
                          connected: false,
                          secrets: []
                        });
                      }
                    } catch (err) {}

                    cleanupOnLogout();
                    setToken('');
                    setSecretEngines([]);
                    setSelectedEngine(null);
                    setSecrets([]);
                    setSearch('');
                    setSearchInput('');
                    setPassword('');
                    setCurrentView('vault'); // Réinitialiser la vue à l'accueil
                    setIsAdmin(false); // Réinitialiser le statut admin
                    setRbiOnlyEngines(new Set()); // Réinitialiser les restrictions RBI-only
                    setRbiOnlySecrets(new Set());
                    showToast(t('login.logoutSuccess'), 'success');
                    if (window.electronWindow?.setLoginMode) await window.electronWindow.setLoginMode();
                  }}
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
              onLogout={async () => {
                await revokeToken();
                try {
                  if (window.electronSync?.writeState) {
                    await window.electronSync.writeState({
                      vaultUrl: '',
                      username: '',
                      connected: false,
                      secrets: []
                    });
                  }
                } catch (err) {}

                cleanupOnLogout();
                setToken('');
                setSecretEngines([]);
                setSelectedEngine(null);
                setSecrets([]);
                setSearch('');
                setSearchInput('');
                setPassword('');
                setCurrentView('vault');
                setIsAdmin(false);
                setRbiOnlyEngines(new Set());
                setRbiOnlySecrets(new Set());
                showToast(t('login.logoutSuccess'), 'success');
                if (window.electronWindow?.setLoginMode) await window.electronWindow.setLoginMode();
              }}
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

          {loadingSecrets ? (
            <LoadingSpinner />
          ) : (multiVaultSearch && search.trim() ? allVaultSecrets : secrets).length > 0 ? (
            <table
              className="secrets-table"
              onContextMenu={handleEmptyAreaRightClick}
              onDoubleClick={() => {
                // Annuler la sélection de texte après chaque double-clic sur la table
                setTimeout(() => window.getSelection().removeAllRanges(), 0);
              }}
            >
              <thead>
                <tr onContextMenu={isCurrentEngineRbiOnly ? undefined : handleColumnHeaderRightClick}>
                  {effectiveVisibleColumns.name && (
                    <th className="resizable-header" style={{ width: columnWidths.name || 'auto' }}>
                      {t('table.name')}
                      <div
                        className={`column-resizer ${resizingColumn === 'name' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'name', columnWidths.name)}
                        onDoubleClick={(e) => autoFitColumn(e, 'name')}
                      />
                    </th>
                  )}
                  {multiVaultSearch && search.trim() && (
                    <th className="resizable-header" style={{ width: columnWidths.engine || 'auto' }}>
                      {t('toolbar.vaultView')}
                      <div
                        className={`column-resizer ${resizingColumn === 'engine' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'engine', columnWidths.engine)}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.username && (
                    <th className="resizable-header" style={{ width: columnWidths.username || 'auto' }}>
                      {t('table.username')}
                      <div
                        className={`column-resizer ${resizingColumn === 'username' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'username', columnWidths.username)}
                        onDoubleClick={(e) => autoFitColumn(e, 'username')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.password && (
                    <th className="resizable-header" style={{ width: columnWidths.password || 'auto' }}>
                      {t('table.password')}
                      <div
                        className={`column-resizer ${resizingColumn === 'password' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'password', columnWidths.password)}
                        onDoubleClick={(e) => autoFitColumn(e, 'password')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.url && (
                    <th className="resizable-header" style={{ width: columnWidths.url || 'auto' }}>
                      {t('table.url')}
                      <div
                        className={`column-resizer ${resizingColumn === 'url' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'url', columnWidths.url)}
                        onDoubleClick={(e) => autoFitColumn(e, 'url')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.notes && (
                    <th className="resizable-header" style={{ width: columnWidths.notes || 'auto' }}>
                      {t('table.notes')}
                      <div
                        className={`column-resizer ${resizingColumn === 'notes' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'notes', columnWidths.notes)}
                        onDoubleClick={(e) => autoFitColumn(e, 'notes')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.tags && (
                    <th className="resizable-header" style={{ width: columnWidths.tags || 'auto' }}>
                      {t('table.tags')}
                      <div
                        className={`column-resizer ${resizingColumn === 'tags' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'tags', columnWidths.tags)}
                        onDoubleClick={(e) => autoFitColumn(e, 'tags')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.customFields && (
                    <th className="resizable-header" style={{ width: columnWidths.customFields || 'auto' }}>
                      {t('table.customFields')}
                      <div
                        className={`column-resizer ${resizingColumn === 'customFields' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'customFields', columnWidths.customFields)}
                        onDoubleClick={(e) => autoFitColumn(e, 'customFields')}
                      />
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {(() => { displayedSecretsRef.current = filteredSecrets; return filteredSecrets; })()
                  .map((s, idx) => {
                    // Si c'est un dossier, affichage spécial
                    if (s.isFolder) {
                      // Calculer le nombre de colonnes réellement affichées
                      const displayedColumnsCount = [
                        effectiveVisibleColumns.name,
                        effectiveVisibleColumns.username,
                        effectiveVisibleColumns.password,
                        effectiveVisibleColumns.url,
                        effectiveVisibleColumns.notes,
                        effectiveVisibleColumns.tags,
                        effectiveVisibleColumns.customFields
                      ].filter(Boolean).length + (multiVaultSearch && search.trim() ? 1 : 0);

                      // Déterminer si ce dossier est la cible de drop actuelle
                      const isFolderDropTarget = isDragging && dragOverTarget === `folder:${s.name}`;

                      return (
                        <tr
                          key={`folder-${s.name}-${idx}`}
                          onClick={() => setCurrentPath(s.name)}
                          onContextMenu={(e) => handleFolderRightClick(e, s.name)}
                          // Gestionnaires Drag & Drop pour les dossiers
                          onDragOver={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            handleDragOver(e, `folder:${s.name}`);
                          }}
                          onDragEnter={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            handleDragOver(e, `folder:${s.name}`);
                          }}
                          onDragLeave={(e) => {
                            e.stopPropagation();
                            handleDragLeave();
                          }}
                          onDrop={(e) => handleDropOnFolder(e, s.name)}
                          style={{
                            cursor: 'pointer',
                            background: isFolderDropTarget
                              ? 'var(--bg-selection, rgba(59, 130, 246, 0.25))'
                              : 'var(--bg-surface-hover)',
                            outline: isFolderDropTarget ? '2px dashed var(--accent, #3b82f6)' : undefined,
                            transition: 'all 0.15s ease'
                          }}
                        >
                          <td
                            colSpan={displayedColumnsCount}
                            style={{
                              padding: 'var(--sp-3)',
                              fontWeight: 'var(--weight-semibold)',
                              color: 'var(--accent)'
                            }}
                          >
                            📁 {s.displayName}
                            {/* Indicateur de drop zone pendant le drag */}
                            {isFolderDropTarget && (
                              <span style={{ marginLeft: 'var(--sp-2)', fontSize: 'var(--text-sm)' }}>
                                ⬇️ Déposer ici
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    }

                    // Sinon, affichage normal d'un secret
                    const isSelected = isSecretSelected(s.name);
                    return (
                      <tr
                        key={`${s.name}-${idx}`}
                        draggable={!s.deleted}
                        onClick={(e) => {
                          // Gérer Ctrl+Clic et Shift+Clic pour la multi-sélection
                          if (!s.deleted) {
                            toggleSecretSelection(s.name, e.ctrlKey || e.metaKey, e.shiftKey);
                          }
                        }}
                        onDragStart={(e) => !s.deleted && handleDragStart(e, s)}
                        onDragEnd={handleDragEnd}
                        className={isSelected ? 'row-selected' : ''}
                        style={{
                          cursor: s.deleted ? 'default' : 'pointer',
                          background: isSelected ? 'var(--bg-selection, rgba(59, 130, 246, 0.15))' : undefined,
                          outline: isSelected ? '2px solid var(--accent, #3b82f6)' : undefined,
                          outlineOffset: '-2px'
                        }}
                      >
                        {effectiveVisibleColumns.name && (
                          <td
                            className={`cell-name ${s.deleted ? 'cell-deleted' : ''}`}
                            onContextMenu={(e) => handleCellRightClick(e, s, 'name', s.name)}
                            style={{ width: columnWidths.name || 'auto' }}
                          >
                            {/* Indicateur de sélection (uniquement si multi-sélection) */}
                            {isSelected && selectedSecrets.size > 1 && (
                              <span style={{ marginRight: 'var(--sp-2)', color: 'var(--accent)' }}>✓</span>
                            )}
                            {s.entryType === 'ssh' && <span style={{ marginRight: 'var(--sp-1)' }}>🔑</span>}
                            {s.displayName || s.name.split('/').pop() || s.name}
                            {s.deleted && <span className="deleted-badge">({t('versionHistory.deleted')})</span>}
                          </td>
                        )}
                      {multiVaultSearch && search.trim() && (
                        <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', width: columnWidths.engine || 'auto' }}>
                          {s.engineName || selectedEngine?.name}
                        </td>
                      )}
                      {effectiveVisibleColumns.username && (
                        <td
                          className={s.deleted ? 'cell-deleted' : ''}
                          onContextMenu={s.deleted || isSecretRbiOnly(s.name) ? undefined : (e) => handleCellRightClick(e, s, 'username', s.username)}
                          onDoubleClick={async (e) => {
                            if (!s.deleted && s.username && !isSecretRbiOnly(s.name)) {
                              e.stopPropagation();
                              await startClipboardTimer('Username', s.username);
                              window.getSelection().removeAllRanges();
                            }
                          }}
                          style={{ cursor: !s.deleted && s.username && !isSecretRbiOnly(s.name) ? 'pointer' : 'default', width: columnWidths.username || 'auto' }}
                        >
                          {isSecretRbiOnly(s.name) ? '—' : s.username}
                        </td>
                      )}
                      {effectiveVisibleColumns.password && (
                        <td
                          className={s.deleted ? 'cell-deleted' : ''}
                          onContextMenu={s.deleted || isSecretRbiOnly(s.name) ? undefined : (e) => handleCellRightClick(e, s, 'password', s.password)}
                          onDoubleClick={async (e) => {
                            if (!s.deleted && s.password && !isSecretRbiOnly(s.name)) {
                              e.stopPropagation();
                              await startClipboardTimer('Password', s.password);
                              window.getSelection().removeAllRanges();
                            }
                          }}
                          style={{ cursor: !s.deleted && s.password && !isSecretRbiOnly(s.name) ? 'pointer' : 'default', width: columnWidths.password || 'auto' }}
                        >
  {s.deleted || isSecretRbiOnly(s.name) ? '—' : (
                            <>
                              <span style={{ marginRight: '8px' }}>{visiblePasswords[s.name] ? s.password : '••••••'}</span>
                              <button
                                onClick={() => setVisiblePasswords(prev => ({ ...prev, [s.name]: !prev[s.name] }))}
                                className="btn-action btn-action-view"
                                type="button"
                              >
                                {visiblePasswords[s.name] ? (
                                  <svg viewBox="0 0 24 24" fill="none">
                                    <path d="M17.94 17.94C16.2306 19.243 14.1491 19.9649 12 20C5 20 1 12 1 12C2.24389 9.68192 3.96914 7.65663 6.06 6.06M9.9 4.24C10.5883 4.0789 11.2931 3.99836 12 4C19 4 23 12 23 12C22.393 13.1356 21.6691 14.2048 20.84 15.19M14.12 14.12C13.8454 14.4148 13.5141 14.6512 13.1462 14.8151C12.7782 14.9791 12.3809 15.0673 11.9781 15.0744C11.5753 15.0815 11.1752 15.0074 10.8016 14.8565C10.4281 14.7056 10.0887 14.4811 9.80385 14.1962C9.51897 13.9113 9.29439 13.572 9.14351 13.1984C8.99262 12.8248 8.91853 12.4247 8.92563 12.0219C8.93274 11.6191 9.02091 11.2218 9.18488 10.8538C9.34884 10.4859 9.58525 10.1546 9.88 9.88" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                                    <path d="M1 1L23 23" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                                  </svg>
                                ) : (
                                  <svg viewBox="0 0 24 24" fill="none">
                                    <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                                    <path d="M12 15C13.6569 15 15 13.6569 15 12C15 10.3431 13.6569 9 12 9C10.3431 9 9 10.3431 9 12C9 13.6569 10.3431 15 12 15Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                                  </svg>
                                )}
                              </button>
                            </>
                          )}
                        </td>
                      )}
                      {effectiveVisibleColumns.url && (
                        <td
                        className={s.deleted ? 'cell-deleted' : ''}
                        onContextMenu={s.deleted ? undefined : (e) => handleCellRightClick(e, s, 'url', s.url)}
                        style={{ width: columnWidths.url || 'auto' }}
                      >
                        {s.url && !s.deleted ? (
                          <>
                            {/* Icône pour indiquer le type de lien */}
                            {(s.url.startsWith('\\\\') || s.url.startsWith('//') || /^[a-zA-Z]:\\/.test(s.url)) && (
                              <span style={{ marginRight: '6px', opacity: 0.7 }}>📁</span>
                            )}
                            {(s.url.toLowerCase().startsWith('ssh://') || s.url.includes(':22')) && (
                              <span style={{ marginRight: '6px', opacity: 0.7 }}>🔑</span>
                            )}
                            <span
                              className="url-link"
                              onClick={async (e) => {
                                e.stopPropagation();
                                await handleUrlAction(s.url, s, {
                                  isSecretRbiOnly, getTotpKeyName, getTotpCode,
                                  startClipboardTimer, showToast, t
                                });
                              }}
                          >
                            {s.url}
                          </span>
                          </>
                        ) : (
                          s.url
                        )}
                      </td>
                      )}
                      {effectiveVisibleColumns.notes && (
                        <td
                          className={s.deleted ? 'cell-deleted' : ''}
                          onContextMenu={s.deleted || isSecretRbiOnly(s.name) ? undefined : (e) => handleCellRightClick(e, s, 'notes', s.notes)}
                          onDoubleClick={isSecretRbiOnly(s.name) ? undefined : () => setNotesPopup({ notes: s.notes })}
                          style={{ cursor: isSecretRbiOnly(s.name) ? 'default' : 'pointer', width: columnWidths.notes || 'auto' }}
                        >
                          {isSecretRbiOnly(s.name) ? '—' : s.notes}
                        </td>
                      )}
                      {effectiveVisibleColumns.tags && (
                        <td
                          style={{
                            width: columnWidths.tags || 'auto',
                            cursor: 'context-menu',
                            minHeight: '32px',
                            whiteSpace: 'normal',
                            overflow: 'visible'
                          }}
                          onContextMenu={(e) => handleTagCellRightClick(e, s)}
                        >
                          {(() => {
                            const tagList = s.tags ? s.tags.split(/[\s,;]+/).filter(t => t) : [];
                            const hasOverflow = tagList.length > 2;
                            return (
                              <div style={{ position: 'relative' }}>
                                <div className="tags-scroll-container">
                                  {tagList.map((tag, tagIdx) => (
                                    <span key={tagIdx} className="tag-badge" style={{ background: getTagColor(tag) }}>
                                      {tag}
                                    </span>
                                  ))}
                                  {tagList.length === 0 && (
                                    <span style={{
                                      fontSize: 'var(--text-xs)',
                                      color: 'var(--text-tertiary)',
                                      fontStyle: 'italic',
                                      padding: '4px'
                                    }}>
                                      Clic droit pour ajouter
                                    </span>
                                  )}
                                </div>
                                {hasOverflow && (
                                  <div className="tags-overflow-indicator">▾</div>
                                )}
                              </div>
                            );
                          })()}
                        </td>
                      )}
                      {effectiveVisibleColumns.customFields && (
                        <td style={{ width: columnWidths.customFields || 'auto', whiteSpace: 'normal', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {s.customFields && s.customFields.length > 0 ? (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px' }}>
                              {s.customFields.map((cf, cfIdx) => (
                                <span key={cfIdx} style={{
                                  fontSize: 'var(--text-xs)',
                                  background: 'var(--bg-surface)',
                                  border: '1px solid var(--border)',
                                  borderRadius: 'var(--radius-sm)',
                                  padding: '1px 4px',
                                  color: 'var(--text-secondary)'
                                }}>
                                  {cf.key}: {cf.protected ? '••••' : cf.value}
                                </span>
                              ))}
                            </div>
                          ) : null}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (token && (selectedEngine || (multiVaultSearch && search.trim())) && (
            <div className="empty-state" onContextMenu={handleEmptyAreaRightClick}>
              {multiVaultSearch && search.trim() ? 'Aucun résultat dans tous les coffres.' : 'Aucun secret à afficher.'}
            </div>
          ))}

          </div>
          </>
        ))}
      </div>

      {/* Modales */}
      {showEngineModal && (
        <EditEngineModal
          onClose={() => { setShowEngineModal(false); restoreFocus(); }}
          onCreate={createEngine}
          isAdmin={isAdmin}
        />
      )}

      {editSecret && (
        <EditSecretModalWrapper
          editSecret={editSecret}
          selectedEngine={selectedEngine}
          onClose={handleEditSecretClose}
          onSave={handleEditSecretSave}
          checkTotpExists={checkTotpExists}
          getTotpKeyName={getTotpKeyName}
          existingTags={discoveredTags}
        />
      )}

      {engineToDelete && (
        <ConfirmModal
          title={t('confirm.deleteEngine')}
          message={
            <>
              {t('confirm.deleteEngineMsg', { name: engineToDelete.name })}
            </>
          }
          confirmLabel={deletingEngine ? t('common.loading') : t('common.delete')}
          cancelLabel={t('common.cancel')}
          danger
          onConfirm={() => !deletingEngine && deleteEngine()}
          onCancel={() => { setEngineToDelete(null); restoreFocus(); }}
        />
      )}

      {secretToDelete && (
        <ConfirmModal
          title={t('confirm.deleteSecret')}
          message={
            <>
              {t('confirm.deleteSecretMsg', { name: secretToDelete.name })}
            </>
          }
          confirmLabel={deletingSecret ? t('common.loading') : t('common.delete')}
          cancelLabel={t('common.cancel')}
          danger
          onConfirm={() => !deletingSecret && deleteSecret()}
          onCancel={() => { setSecretToDelete(null); restoreFocus(); }}
        />
      )}

      {showCreateFolderModal && (
        <div className="modal-overlay" onClick={() => setShowCreateFolderModal(false)}>
          <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>📁 {t('editSecret.typeFolder')}</h2>
              <button className="modal-close" onClick={() => setShowCreateFolderModal(false)} type="button">×</button>
            </div>
            <div className="modal-body">
              <div className="form-group-vertical">
                <label className="form-label-vertical">{t('editSecret.placeholderFolderName')}</label>
                <input
                  type="text"
                  className="form-input-vertical"
                  value={newFolderName}
                  onChange={(e) => setNewFolderName(e.target.value)}
                  placeholder={t('editSecret.placeholderFolderName')}
                  autoFocus
                  onKeyDown={async (e) => {
                    if (e.key === 'Enter' && newFolderName.trim() && selectedEngine) {
                      const sanitizedName = newFolderName.trim().replace(/\//g, '-');
                      const placeholderPath = (currentPath ? `${currentPath}/` : '') + sanitizedName + '/.placeholder';
                      const placeholderEntry = {
                        name: placeholderPath,
                        username: '', password: '', url: '', website: '', notes: '', tags: '',
                        entryType: 'placeholder'
                      };
                      try {
                        if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, placeholderEntry);
                        else await writeSecretV1(selectedEngine, placeholderEntry);
                        setShowCreateFolderModal(false);
                        await fetchSecrets(selectedEngine);
                        syncExtensionRef.current?.();
                        showToast(t('toast.folderCreated'), 'success');
                      } catch (err) {
                        showToast(`${t('error.folderDelete')} ${sanitizeErrorMessage(err)}`, 'error');
                      }
                    }
                  }}
                />
                {currentPath && (
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', marginTop: 'var(--sp-2)' }}>
                    Le dossier sera créé dans : <code>{currentPath}/</code>
                  </p>
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button
                onClick={() => setShowCreateFolderModal(false)}
                className="btn btn-secondary"
                type="button"
              >
                {t('common.cancel')}
              </button>
              <button
                onClick={async () => {
                  if (newFolderName.trim() && selectedEngine) {
                    const sanitizedName = newFolderName.trim().replace(/\//g, '-');
                    const placeholderPath = (currentPath ? `${currentPath}/` : '') + sanitizedName + '/.placeholder';
                    const placeholderEntry = {
                      name: placeholderPath,
                      username: '', password: '', url: '', website: '', notes: '', tags: '',
                      entryType: 'placeholder'
                    };
                    try {
                      if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, placeholderEntry);
                      else await writeSecretV1(selectedEngine, placeholderEntry);
                      setShowCreateFolderModal(false);
                      await fetchSecrets(selectedEngine);
                      syncExtensionRef.current?.();
                      showToast(t('toast.folderCreated'), 'success');
                    } catch (err) {
                      showToast(`${t('error.folderDelete')} ${sanitizeErrorMessage(err)}`, 'error');
                    }
                  }
                }}
                className="btn btn-primary"
                disabled={!newFolderName.trim()}
                type="button"
              >
                {t('engine.create')}
              </button>
            </div>
          </div>
        </div>
      )}

      {totpDisplay && (
        <TotpDisplayModal
          secretName={totpDisplay.secretName}
          totpCode={totpDisplay.code}
          onClose={() => { setTotpDisplay(null); restoreFocus(); }}
          onCopy={(code) => {
            startClipboardTimer('Code TOTP', code);
          }}
          onRefresh={async () => {
            try {
              return await getTotpCode(totpDisplay.totpKeyName);
            } catch (err) {
              return null;
            }
          }}
        />
      )}

      {totpConfig && (
        <TotpConfigModal
          secretName={totpConfig.name}
          totpKeyName={totpConfig.totpKeyName}
          engineName={totpConfig.engineName}
          onClose={() => { setTotpConfig(null); restoreFocus(); }}
          onSave={handleSaveTotpConfig}
        />
      )}

      {migrateSecrets && (
        <MigrateSecretModal
          secrets={migrateSecrets.secrets}
          engines={secretEngines}
          currentEngine={selectedEngine}
          mode={migrateSecrets.mode}
          onClose={() => { setMigrateSecrets(null); restoreFocus(); }}
          onConfirm={async (targetEngine) => {
            await handleMigrateSecrets(migrateSecrets.secrets, targetEngine, migrateSecrets.mode);
            setMigrateSecrets(null);
            restoreFocus();
          }}
        />
      )}

      {moveToFolder && (
        <MoveToFolderModal
          secretsToMove={moveToFolder.secrets}
          secrets={secrets}
          onClose={() => { setMoveToFolder(null); restoreFocus(); }}
          onConfirm={async (targetPath) => {
            await handleMoveToFolder(moveToFolder.secrets, targetPath);
            setMoveToFolder(null);
            restoreFocus();
          }}
        />
      )}

      {versionHistory && (
        <VersionHistoryModal
          secretName={versionHistory.secretName}
          engine={selectedEngine}
          vaultUrl={vaultUrl}
          baseHeaders={baseHeaders}
          axiosConfig={axiosConfig}
          onClose={() => { setVersionHistory(null); restoreFocus(); }}
          onRestore={handleRestoreVersion}
          showToast={showToast}
        />
      )}

      {notesPopup && (
        <NotesPopupModal
          notes={notesPopup.notes}
          onClose={() => setNotesPopup(null)}
        />
      )}

      {showSettings && (
        <SettingsModal
          darkMode={darkMode}
          onToggleDarkMode={toggleDarkMode}
          visibleColumns={visibleColumns}
          onToggleColumn={toggleColumn}
          discoveredTags={discoveredTags}
          isAdmin={isAdmin}
          isModerator={isModerator}
          appVersion="1.4.0"
          secretEngines={secretEngines}
          appMode={appMode}
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          baseHeaders={baseHeaders}
          showToast={showToast}
          onClose={() => setShowSettings(false)}
        />
      )}

      {shareRbiSecret && appMode !== 'local' && (
        <ShareRbiModal
          mode="send"
          secret={shareRbiSecret}
          totpKeyName={getTotpKeyName(shareRbiSecret.name)}
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          rbiProxyUrl={rbiProxyUrl}
          onClose={() => setShareRbiSecret(null)}
          showToast={showToast}
        />
      )}

      {receiveShareOpen && appMode !== 'local' && (
        <ShareRbiModal
          mode="receive"
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          rbiProxyUrl={rbiProxyUrl}
          onClose={() => setReceiveShareOpen(false)}
          showToast={showToast}
        />
      )}

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

      {/* Context Menu Dossier */}
      {folderContextMenu && (
        <div
          className="context-menu"
          style={{ top: folderContextMenu.y, left: folderContextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => handleDeleteFolder(folderContextMenu.folderPath)}
            className="context-menu-item"
            style={{ color: 'var(--error)' }}
            type="button"
          >
            🗑️ {t('contextMenu.deleteFolder')}
          </button>
        </div>
      )}

      {/* Context Menu */}
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

      {/* Column Context Menu */}
      {columnContextMenu && (
        <div
          className="context-menu"
          style={{ top: columnContextMenu.y, left: columnContextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="context-menu-label">{t('settings.columnsTitle')}</div>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.name}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, name: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.name')}</span>
          </label>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.username}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, username: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.username')}</span>
          </label>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.password}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, password: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.password')}</span>
          </label>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.url}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, url: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.url')}</span>
          </label>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.notes}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, notes: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.notes')}</span>
          </label>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.tags}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, tags: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.tags')}</span>
          </label>
          <label className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
            <input
              type="checkbox"
              checked={visibleColumns.customFields}
              onChange={(e) => {
                const newVisibleColumns = { ...visibleColumns, customFields: e.target.checked };
                setVisibleColumns(newVisibleColumns);
                localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
              }}
            />
            <span>{t('table.customFields')}</span>
          </label>
        </div>
      )}

      {/* Tag Context Menu */}
      {tagContextMenu && (
        <div
          ref={tagContextMenuRef}
          className="context-menu tag-context-menu"
          style={{
            top: tagContextMenu.y,
            left: tagContextMenu.x,
            maxHeight: '400px',
            overflowY: 'auto'
          }}
          onClick={(e) => e.stopPropagation()}
        >
          {!tagCreateMode ? (
            <button
              onClick={(e) => {
                e.stopPropagation();
                setTagCreateMode(true);
                setTagCreateValue('#');
              }}
              className="context-menu-item"
              type="button"
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}
            >
              <span style={{ fontSize: '16px' }}>+</span>
              <span>{t('contextMenu.createTag')}</span>
            </button>
          ) : (
            <div style={{ padding: 'var(--sp-2) var(--sp-3)', display: 'flex', gap: 'var(--sp-2)', alignItems: 'center' }}>
              <input
                type="text"
                value={tagCreateValue}
                autoFocus
                onChange={(e) => {
                  let val = e.target.value;
                  if (!val.startsWith('#')) val = '#' + val.replace(/^#+/, '');
                  setTagCreateValue(val);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    const tagName = tagCreateValue.trim();
                    if (tagName && tagName.length <= 64 && !/[\x00-\x1F\x7F]/.test(tagName)) {
                      handleAddTagToSecret(tagContextMenu.secret, tagName);
                      setTagCreateMode(false);
                      setTagCreateValue('#');
                      setTagContextMenu(null);
                    }
                  } else if (e.key === 'Escape') {
                    setTagCreateMode(false);
                    setTagCreateValue('#');
                  }
                }}
                onClick={(e) => e.stopPropagation()}
                placeholder="#nouveau-tag"
                style={{
                  flex: 1,
                  padding: 'var(--sp-2)',
                  fontSize: 'var(--text-sm)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  outline: 'none',
                  minWidth: 0
                }}
              />
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  const tagName = tagCreateValue.trim();
                  if (tagName && tagName.length <= 64 && !/[\x00-\x1F\x7F]/.test(tagName)) {
                    handleAddTagToSecret(tagContextMenu.secret, tagName);
                    setTagCreateMode(false);
                    setTagCreateValue('#');
                    setTagContextMenu(null);
                  }
                }}
                className="btn btn-primary"
                type="button"
                style={{ padding: 'var(--sp-2) var(--sp-3)', fontSize: 'var(--text-sm)', whiteSpace: 'nowrap' }}
              >
                OK
              </button>
            </div>
          )}
          <div className="context-menu-separator" />
          <div className="context-menu-label">
            {t('table.tags')} ({tagContextMenu.availableTags.length})
          </div>
          {tagContextMenu.availableTags.length === 0 ? (
            <div style={{
              padding: 'var(--sp-3)',
              fontSize: 'var(--text-sm)',
              color: 'var(--text-tertiary)',
              fontStyle: 'italic',
              textAlign: 'center'
            }}>
              {t('common.noData')}
            </div>
          ) : (
            tagContextMenu.availableTags.map((tag) => (
              <button
                key={tag}
                onClick={() => {
                  handleAddTagToSecret(tagContextMenu.secret, tag);
                  setTagContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--sp-2)'
                }}
              >
                <span
                  className="tag-badge"
                  style={{
                    background: getTagColor(tag),
                    fontSize: '11px',
                    padding: '2px 6px'
                  }}
                >
                  {tag}
                </span>
                <span style={{ flex: 1 }}>{t('contextMenu.addTag')} "{tag}"</span>
              </button>
            ))
          )}
          {tagContextMenu.currentTags.length > 0 && (
            <>
              <div className="context-menu-separator" />
              <div className="context-menu-label">
                {t('table.tags')} ({tagContextMenu.currentTags.length}) - {t('contextMenu.removeTag')}
              </div>
              {tagContextMenu.currentTags.map((tag) => (
                <button
                  key={tag}
                  onClick={() => {
                    handleRemoveTagFromSecret(tagContextMenu.secret, tag);
                    setTagContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--sp-2)'
                  }}
                >
                  <span
                    className="tag-badge"
                    style={{
                      background: getTagColor(tag),
                      fontSize: '11px',
                      padding: '2px 6px'
                    }}
                  >
                    {tag}
                  </span>
                  <span style={{ flex: 1 }}>{t('contextMenu.removeTag')} "{tag}"</span>
                  <span style={{ fontSize: '16px', opacity: 0.6 }}>✕</span>
                </button>
              ))}
            </>
          )}
          <div
            className="tag-menu-scroll-indicator"
            onClick={(e) => {
              e.stopPropagation();
              const menu = tagContextMenuRef.current;
              if (menu) {
                const itemHeight = menu.querySelector('.context-menu-item')?.offsetHeight || 36;
                menu.scrollBy({ top: itemHeight * 7, behavior: 'smooth' });
              }
            }}
            style={{ cursor: 'pointer' }}
          >▾</div>
        </div>
      )}

      {/* Menu contextuel pour les coffres (suppression uniquement) */}
      {engineContextMenu && (
        <div
          className="context-menu"
          style={{ top: engineContextMenu.y, left: engineContextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => {
              setEngineToDelete(engineContextMenu.engine);
              setEngineContextMenu(null);
            }}
            className="context-menu-item danger"
            type="button"
          >
            🗑️ {t('confirm.deleteEngine')}
          </button>
        </div>
      )}
    </div>
  );
}
