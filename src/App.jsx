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

import React, { useState, useEffect, useLayoutEffect, useRef, useCallback, useMemo, lazy, Suspense } from 'react';
import axios from 'axios';

// ========================================
// IMPORTS DES COMPOSANTS MODALS
// ========================================
import UserMenu from './UserMenu.jsx';                   // Menu utilisateur (déconnexion, settings)
import LoadingSpinner from './LoadingSpinner.jsx';        // Indicateur de chargement (fallback Suspense)
import ClipboardTimer from './ClipboardTimer.jsx';       // Timer clipboard isolé (évite re-renders)
import WindowControls from './WindowControls.jsx';       // Boutons fenêtre frameless (minimiser/maximiser/fermer)
import ConfirmModal from './ConfirmModal.jsx';           // Confirmation (deep link de partage RBI)
import { useTranslation } from './i18n';                 // Internationalisation

import './AppStyles.css';
import { sanitizeErrorMessage } from './utils/security';
import { rbiLaunchErrorMessage, rbiWebsiteOption } from './utils/urlHandler';
import { readAllSecrets } from './utils/readAllSecrets';
import { createVaultApi } from './services/vaultApi';
import { useToast, Toast } from './hooks/useToast';
import { useClipboard } from './hooks/useClipboard';
import { useSelection, entryKeyEngine } from './hooks/useSelection';
import { useColumns } from './hooks/useColumns';
import { useTreeView } from './hooks/useTreeView';
import { useConfig } from './hooks/useConfig';
import { useContextMenus } from './hooks/useContextMenus';
import { useTotp, buildTotpKeyName } from './hooks/useTotp';
import { useTags, incompleteReadMessage } from './hooks/useTags';
import { useMigration } from './hooks/useMigration';
import { useDragDrop } from './hooks/useDragDrop';
import { useSync } from './hooks/useSync';
import { usePasskeys } from './hooks/usePasskeys';
import { useAuth } from './hooks/useAuth';
import { useSecrets, reuseUnchangedSecrets } from './hooks/useSecrets';
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
import { useSessionTimeout, DEFAULT_LOCKED_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS } from './useSessionTimeout';
import { useDebounce } from './useRateLimit';
import secureLogger from './secureLogger';

// FLUIDITÉ : AdminPanel (volumineux, réservé aux admins/modérateurs) chargé à la demande
// via code-splitting (React.lazy) — allège le bundle initial et accélère le premier rendu.
const AdminPanel = lazy(() => import('./AdminPanel.jsx'));

// RateLimiter supprimé — remplacé par bruteForceProtection.js

// TREE-18 : mots de passe révélés, indexés par nom d'entrée dans un dictionnaire SANS prototype.
// Avec `{}`, une entrée nommée « constructor », « toString », « valueOf »… lisait la méthode
// héritée d'Object.prototype (valeur vraie) : son mot de passe s'affichait en clair sans clic sur
// l'œil. Toute valeur reçue (objet du tableau, `{}` des remises à zéro) est recopiée sans prototype.
const toVisibilityMap = (value) => Object.assign(Object.create(null), value && typeof value === 'object' ? value : null);

// Champ « website » d'un partage reçu par lien profond : chaîne bornée sans caractère de contrôle
// (le processus principal vérifie ensuite le nom d'hôte), sinon absent
// eslint-disable-next-line no-control-regex -- volontaire : valeur avec caractère de contrôle écartée
const sharedWebsite = (value) => (typeof value === 'string' && value.length <= 2048 && !/[\x00-\x1F\x7F]/.test(value) ? value : undefined);

export default function App() {
  const { t, setLang } = useTranslation();
  const { vaultUrl, ldapAuthPath, rbiProxyUrl, appMode, vaultNs } = useConfig(setLang);
  const [currentView, setCurrentView] = useState('vault'); // 'vault' ou 'admin'
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('rdvault-theme');
    return saved === 'dark';
  });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [windowSize, setWindowSize] = useState({ width: window.innerWidth, height: window.innerHeight });

  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  // Valeur affichée dans le champ de recherche, lue par l'anti-rebond (SEARCH-17)
  const searchInputRef = useRef(searchInput);
  searchInputRef.current = searchInput;
  const [visiblePasswords, setVisiblePasswordsState] = useState(() => Object.create(null));
  // Setter stable (dépendance de callbacks mémoïsés de useAuth) : valeur ou fonction de mise à jour
  const setVisiblePasswords = useCallback((next) => {
    setVisiblePasswordsState(prev => toVisibilityMap(typeof next === 'function' ? next(prev) : next));
  }, []);

  const [showDeleted, setShowDeleted] = useState(false);
  const [installedBrowsers, setInstalledBrowsers] = useState([]);

  const [multiVaultSearch, setMultiVaultSearch] = useState(false);
  const [allVaultSecrets, setAllVaultSecrets] = useState([]);
  const [showCreateFolderModal, setShowCreateFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');

  // Secrets du coffre sélectionné : état détenu ici pour pouvoir appeler
  // useTreeView(secrets) AVANT useSecrets (qui reçoit la vue arborescence en clair)
  const [secrets, setSecretsState] = useState([]);
  // Coffre dont `secrets` est la liste (coffre sélectionné au moment où elle a été posée) : une
  // action lancée depuis la recherche multi-coffres attend la liste du coffre de l'entrée (SEARCH-9)
  const [secretsEngineName, setSecretsEngineName] = useState(null);
  const shownEngineNameRef = useRef(null);
  const setSecrets = useCallback((value) => {
    setSecretsState(value);
    setSecretsEngineName(shownEngineNameRef.current);
  }, []);

  // ========================================
  // NOUVEAUX ÉTATS POUR VERSION 1.1
  // ========================================
  const { toast, showToast } = useToast();
  const { clipboardTimer, clearClipboardNow, handleClipboardExpire, startClipboardTimer } = useClipboard(showToast, t);
  const { visibleColumns, setVisibleColumns, columnWidths, resizingColumn, toggleColumn, handleColumnResizeStart, handleColumnAutoFit } = useColumns(showToast, t);
  const [notesPopup, setNotesPopup] = useState(null);           // Popup affichage notes
  const [showSettings, setShowSettings] = useState(false);      // Modal paramètres
  const [showPasswordHealth, setShowPasswordHealth] = useState(false); // Modal audit de santé des mots de passe
  const [showPasskeys, setShowPasskeys] = useState(false); // Modal gestion des passkeys
  // discoveredTags moved to useTags hook
  const [shareRbiSecret, setShareRbiSecret] = useState(null);   // Secret à partager via RBI wrapping
  const [receiveShareOpen, setReceiveShareOpen] = useState(false); // Modal réception partage RBI
  // Partage reçu via deep link rdvault://share/… en attente de confirmation ({ url, username, password })
  const [pendingShare, setPendingShare] = useState(null);

  // ========================================
  // ÉTATS POUR MULTI-SÉLECTION ET DRAG & DROP (v1.4)
  // ========================================
  // Sélection indexée par entryKey (useSelection) : nom pour une entrée du coffre sélectionné,
  // coffre + nom pour un résultat d'un autre coffre en recherche multi-coffres.
  const { selectedSecrets, setSelectedSecrets, displayedSecretsRef, toggleSecretSelection, clearSelection, isSecretSelected } = useSelection({ selectedEngineNameRef: shownEngineNameRef });

  const searchRef = useRef(null);
  const appRootRef = useRef(null);
  const syncExtensionRef = useRef(null);

  // Refs pour callbacks circulaires (définies plus bas)
  const vaultApiRef = useRef(null);
  const fetchEnginesLikeUiRef = useRef(null);
  const setDiscoveredTagsRef = useRef((tags) => {});
  const mergeDiscoveredAndSharedTagsRef = useRef(null);
  const getTotpKeyNameRef = useRef(null);
  const checkTotpExistsRef = useRef(null);
  const totpEngineNameRef = useRef('totp');
  const setSecretEnginesRef = useRef((e) => {});
  const setSelectedEngineRef = useRef((e) => {});

  // Wrappers stables (mémoïsés) vers les setters définis plus bas : ils sont
  // dans les dépendances de callbacks mémoïsés de useAuth (handleSessionExpired…)
  const setSecretEnginesViaRef = useCallback((e) => setSecretEnginesRef.current(e), []);
  const setSelectedEngineViaRef = useCallback((e) => setSelectedEngineRef.current(e), []);
  const setDiscoveredTagsViaRef = useCallback((tags) => setDiscoveredTagsRef.current(tags), []);

  // ========================================
  // AUTHENTIFICATION (hook)
  // ========================================
  const {
    authUser, setAuthUser,
    password, setPassword,
    token,
    isAdmin,
    isModerator,
    moderatorEngines,
    rememberMe, setRememberMe,
    firstRunRecheck,
    isCurrentEngineRbiOnly: isCurrentEngineRbiOnlyFn,
    isSecretRbiOnly: isSecretRbiOnlyFn,
    sessionTokenRef,
    handleLogin, handleLogout, handleSessionExpired,
  } = useAuth({
    vaultUrl, ldapAuthPath,
    showToast, t,
    vaultApiRef,
    fetchEnginesLikeUiRef,
    setSecretEngines: setSecretEnginesViaRef,
    setSelectedEngine: setSelectedEngineViaRef,
    setSecrets,
    setCurrentView, setVisiblePasswords,
    setAllVaultSecrets, setDiscoveredTags: setDiscoveredTagsViaRef,
    setMultiVaultSearch,
    setSelectedSecrets,
    setSearchState: { setSearch, setSearchInput },
  });

  // APP-3 : vrai si la session `start` (jeton relevé au lancement d'une action asynchrone) n'est plus la
  // session en cours (déconnexion, expiration, autre utilisateur) : le résultat tardif est abandonné.
  // sessionTokenRef est mis à jour de façon synchrone par useAuth.
  const sessionChanged = (start) => !start || sessionTokenRef.current !== start;

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
    fetchEnginesLikeUi,
    createEngine,
    deleteEngine,
  } = useEngines({
    vaultApiRef,
    vaultUrl,
    token,
    setSecrets,
    fetchSecretsRef,
    restoreFocus: () => restoreFocus(),
    showToast, t,
  });
  fetchEnginesLikeUiRef.current = fetchEnginesLikeUi;
  setSecretEnginesRef.current = setSecretEngines;
  shownEngineNameRef.current = selectedEngine?.name || null;

  // APP-4 / APP-8 : sélection et mots de passe révélés sont indexés par NOM d'entrée. Ils sont remis à zéro
  // à CHAQUE changement de coffre affiché (barre latérale, suppression ou création d'un coffre, action dans
  // le coffre d'une entrée, connexion), avant que le nouveau coffre ne soit peint (useLayoutEffect).
  // Avant : seul le clic sur un coffre vidait les mots de passe révélés et rien ne vidait la sélection ; les
  // homonymes du nouveau coffre apparaissaient sélectionnés (emportés par un glisser-déposer) ou révélés.
  const shownEngineName = selectedEngine?.name || null;
  useLayoutEffect(() => {
    setSelectedSecrets(prev => (prev.size ? new Set() : prev));
    setVisiblePasswordsState(prev => (Object.keys(prev).length ? Object.create(null) : prev));
  }, [shownEngineName, setSelectedSecrets]);

  // Wrappers RBI-Only avec selectedEngine du scope (doit être après useEngines)
  const isCurrentEngineRbiOnly = isCurrentEngineRbiOnlyFn(selectedEngine);
  // SÉCURITÉ (recherche multi-coffre) : le tableau affiche alors des secrets de TOUS
  // les coffres, mais ses appelants ne passent que le nom du secret. Chaque résultat
  // est donc évalué contre SON coffre (s.engineName) ; un nom présent dans plusieurs
  // coffres est masqué dès que l'un d'eux le rend « RBI uniquement » (sur-restriction
  // volontaire, jamais l'inverse).
  const multiVaultResultsShown = multiVaultSearch && !!search.trim();
  const rbiOnlyNamesInResults = useMemo(() => {
    const names = new Set();
    for (const s of allVaultSecrets) {
      if (s && s.engineName && isSecretRbiOnlyFn(s.name, { name: s.engineName })) names.add(s.name);
    }
    return names;
  }, [allVaultSecrets, isSecretRbiOnlyFn]);
  const isSecretRbiOnly = (secretName, engineName) => {
    if (engineName) return isSecretRbiOnlyFn(secretName, { name: engineName });
    if (isSecretRbiOnlyFn(secretName, selectedEngine)) return true;
    return multiVaultResultsShown && rbiOnlyNamesInResults.has(secretName);
  };
  setSelectedEngineRef.current = setSelectedEngine;

  // Wrapper pour handleColumnAutoFit avec le contexte de données
  const autoFitColumn = (e, columnKey) => {
    const dataSource = multiVaultSearch && search.trim() ? allVaultSecrets : secrets;
    handleColumnAutoFit(e, columnKey, { dataSource, treeViewEnabled, selectedEngine });
  };

  // Vue arborescence (hook) — AVANT useSecrets : filteredSecrets dépend
  // explicitement de treeViewEnabled / currentPath / currentFolderContent
  const { treeViewEnabled, setTreeViewEnabled, currentPath, setCurrentPath, currentFolderContent } = useTreeView(secrets);

  // ========================================
  // SECRETS (hook)
  // ========================================
  const {
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
    secrets, setSecrets,
    treeViewEnabled, currentPath, currentFolderContent,
    multiVaultSearch, allVaultSecrets,
    mergeDiscoveredAndSharedTagsRef,
    setDiscoveredTags: setDiscoveredTagsViaRef,
    syncExtensionRef,
    restoreFocus: () => restoreFocus(),
    getTotpKeyName: (...args) => getTotpKeyNameRef.current?.(...args),
    checkTotpExists: (...args) => checkTotpExistsRef.current?.(...args),
    totpEngineName: totpEngineNameRef.current,
    showToast, t,
  });

  // Colonnes effectives : si coffre entièrement RBI-Only, seules name, url et tags sont visibles.
  // Lignes affichées contenant un secret RBI-Only (secret désigné par la policy, ou résultat
  // d'un coffre RBI-Only en recherche multi-coffre) : identifiant, mot de passe et notes sont
  // masqués ligne par ligne (isSecretRbiOnly) ; les champs personnalisés, qui ne le sont pas,
  // sont retirés pour l'ensemble des lignes.
  const rbiOnlyResultShown = !isCurrentEngineRbiOnly
    && (filteredSecrets || []).some(s => s && typeof s.name === 'string' && isSecretRbiOnly(s.name));
  const effectiveVisibleColumns = isCurrentEngineRbiOnly
    ? { name: true, username: false, password: false, url: true, website: false, notes: false, tags: true, customFields: false, actions: false }
    : (rbiOnlyResultShown ? { ...visibleColumns, customFields: false } : visibleColumns);

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
      // + le .placeholder direct du dossier
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

  // APP-6 : entrées écrites par les Paramètres (import CSV/XML, écritures observées par ModalOrchestrator).
  // Coffre affiché : liste relue (tableau à jour, extension poussée) ; autres coffres : relus en entier pour
  // l'extension (une entrée écrasée par l'import y gardait sinon l'ancien mot de passe). Session terminée
  // entre-temps : rien.
  const handleSettingsWrites = (engineNames) => {
    if (!sessionTokenRef.current || !Array.isArray(engineNames) || engineNames.length === 0) return;
    const shown = selectedEngine;
    const others = engineNames.filter(name => name !== shown?.name);
    if (shown && others.length < engineNames.length) fetchSecretsRef.current?.(shown);
    if (others.length) syncExtensionRef.current?.({ invalidate: others });
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

  // SÉCURITÉ: Session Timeout — 15 min d'inactivité, 3 h si le PC est verrouillé
  // (handleSessionExpired est mémoïsé dans useAuth : pas de réinitialisation des timers à chaque rendu)
  const { isLocked } = useSessionTimeout(handleSessionExpired, DEFAULT_LOCKED_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, !!token);

  // ========================================
  // DEEP LINK - Réception de liens rdvault://share/TOKEN
  // ========================================
  // SÉCURITÉ : le lien est d'abord "unwrappé" puis une modale de confirmation
  // affiche l'URL cible et le nom d'utilisateur ; la session RBI n'est lancée
  // qu'après validation explicite. Refus si le poste est verrouillé.
  useEffect(() => {
    if (!window.electronRBI?.onShareReceived) return;

    const cleanup = window.electronRBI.onShareReceived(async (shareToken) => {
      secureLogger.debug('[DEEP-LINK] Token de partage reçu');

      if (!token) {
        showToast(t('error.notAuthenticatedShare'), 'error', 4000);
        return;
      }

      // SÉCURITÉ: Ne pas traiter un lien reçu pendant que le poste est verrouillé
      if (isLocked()) {
        showToast(t('error.shareWhileLocked'), 'error', 4000);
        return;
      }

      // SÉCURITÉ: Valider le format du shareToken avant utilisation comme header HTTP
      // eslint-disable-next-line no-control-regex -- volontaire : un jeton avec caractère de contrôle ne doit pas atteindre un en-tête HTTP
      if (typeof shareToken !== 'string' || shareToken.length === 0 || shareToken.length > 512 || /[\r\n\x00-\x1F]/.test(shareToken)) {
        showToast(t('error.invalidShareToken'), 'error');
        return;
      }

      // APP-3 : session au moment de la réception ; si elle a pris fin pendant l'unwrap (déconnexion,
      // expiration, autre utilisateur), le partage est abandonné : sa confirmation s'affichait sinon sur
      // l'écran de connexion et « Ouvrir » lançait la session RBI sans session RDVAULT
      const session = sessionTokenRef.current;
      if (!session) {
        showToast(t('error.notAuthenticatedShare'), 'error', 4000);
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

        if (sessionChanged(session)) return;
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

        // Demander confirmation à l'utilisateur AVANT de lancer la session (liée à CETTE session)
        setPendingShare({
          session,
          url: data.url,
          // Adresse « website » de l'entrée partagée (RBI-11), si l'émetteur l'a transmise
          website: sharedWebsite(data.website),
          username: data.username || '',
          password: data.password || '',
        });
      } catch (err) {
        if (sessionChanged(session)) return;
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

  // Lancement de la session RBI après confirmation de l'utilisateur
  const confirmPendingShare = async () => {
    const share = pendingShare;
    setPendingShare(null);
    if (!share) return;
    // APP-3 : partage reçu dans une autre session (ou session terminée) : rien n'est lancé
    if (sessionChanged(share.session)) return;

    if (isLocked()) {
      showToast(t('error.shareWhileLocked'), 'error', 4000);
      return;
    }

    if (!window.electronRBI?.launchSession) {
      showToast(t('error.rbiUnavailable'), 'error');
      return;
    }

    try {
      showToast(t('toast.launchingRbi'), 'info', 2000);
      const result = await window.electronRBI.launchSession({
        url: share.url,
        ...rbiWebsiteOption(share),
        username: share.username,
        password: share.password,
        skipOverlay: false, // SÉCURITÉ: Overlay toujours actif (empêche la capture de credentials)
        policies: {
          disableClipboard: true,
          disableNewTabs: true,
          disableDownloads: false,
        },
      });

      if (result?.success) {
        showToast(t('toast.rbiOpened'), 'success', 3000);
      } else {
        // Motif traduit (ex. RBI_FOREIGN_ORIGIN) plutôt que le texte brut du processus principal
        showToast(rbiLaunchErrorMessage(result, t), 'error');
      }
    } catch (err) {
      showToast(t('error.rbiLaunch'), 'error');
    }
  };

  // Toggle login-mode sur body pour la transparence CSS
  useEffect(() => {
    if (!token) {
      document.body.classList.add('login-mode');
      document.documentElement.classList.add('login-mode');
      // SÉCURITÉ: un partage en attente ne survit pas à la déconnexion
      setPendingShare(null);
    } else {
      document.body.classList.remove('login-mode');
      document.documentElement.classList.remove('login-mode');
    }
  }, [token]);

  // ========================================
  // SÉCURITÉ: Rate Limiting Hooks
  // ========================================
  const debouncedSearch = useDebounce((searchTerm) => {
    // Cette fonction sera appelée 300ms après la dernière frappe.
    // SEARCH-17 : le minuteur n'est pas annulé quand le champ est vidé entre-temps (changement de
    // coffre, déconnexion, expiration) : il rétablissait alors l'ancien filtre sur le nouveau
    // coffre avec un champ vide (tableau vide sans explication). Seul le texte encore affiché
    // dans le champ est appliqué.
    if (searchTerm !== searchInputRef.current) return;
    setSearch(searchTerm);
  }, 300);

  // Champ de recherche vidé (par l'utilisateur, au changement de coffre, à la déconnexion ou à
  // l'expiration) : filtre en attente annulé et recherche vidée aussitôt (SEARCH-17 reste la garde de
  // l'anti-rebond ; cancel est stable)
  const cancelPendingSearch = debouncedSearch.cancel;
  useEffect(() => {
    if (searchInput !== '') return;
    cancelPendingSearch();
    setSearch('');
  }, [searchInput, cancelPendingSearch]);

  // SEARCH-16 : recherche vidée → recherche multi-coffres désactivée (sinon la case restait
  // cochée, l'arborescence était perdue et tous les coffres restaient relus en mémoire)
  useEffect(() => {
    if (multiVaultSearch && !search.trim()) setMultiVaultSearch(false);
  }, [search, multiVaultSearch]);

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
  const { baseHeaders, axiosConfig, writeSecretV2, deleteSecretV2, writeSecretV1, deleteSecretV1 } = vaultApi;
  const {
    discoveredTags, setDiscoveredTags,
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
    handleMigrateSecrets,
    handleMoveToFolder,
    migrateSecretsToEngine,
    moveSecretsToFolder
  } = useMigration({
    vaultApi, selectedEngine, secretEngines,
    fetchSecretsRef,
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
    totpRateLimit,
    totpEngineName,
    getTotpKeyName,
    getTotpCode,
    checkTotpExists,
    handleShowTotp,
    handleCopyTotp,
    handleConfigureTotp,
    handleDeleteTotp,
    handleSaveTotpConfig
  } = useTotp({ vaultUrl, baseHeaders, axiosConfig, selectedEngine, startClipboardTimer, showToast, t, restoreFocus, vaultApi });
  getTotpKeyNameRef.current = getTotpKeyName;
  checkTotpExistsRef.current = checkTotpExists;
  totpEngineNameRef.current = totpEngineName;

  // ========================================
  // APP-3 : RÉPONSES TARDIVES APRÈS LA FIN DE LA SESSION
  // ========================================
  // Plusieurs actions des hooks attendent une requête puis posent un état d'interface (menu contextuel,
  // confirmation de suppression, code ou configuration TOTP) ou lancent une session RBI. Une réponse
  // arrivée après une déconnexion ou une expiration réapparaissait dans la session suivante (autre
  // utilisateur possible : menu copiant le mot de passe de la session précédente, « Supprimer » visant
  // l'entrée homonyme du NOUVEAU coffre) ou sur l'écran de connexion.

  // État posé APRÈS la requête par l'action d'un hook : effacé si la session a changé entre-temps
  const inSession = (action, clearLate) => async (...args) => {
    const session = sessionTokenRef.current;
    try {
      return await action(...args);
    } finally {
      if (sessionChanged(session)) clearLate();
    }
  };
  const confirmDeleteSecretInSession = inSession(confirmDeleteSecret, () => setSecretToDelete(null));
  const handleShowTotpInSession = inSession(handleShowTotp, () => setTotpDisplay(null));
  const handleConfigureTotpInSession = inSession(handleConfigureTotp, () => setTotpConfig(null));

  // Promesse jamais résolue : la suite d'une action abandonnée (menu à ouvrir, session RBI à lancer) ne
  // s'exécute pas. Sans référence, elle est libérée par le ramasse-miettes.
  const abandoned = () => new Promise(() => {});

  // Résultat d'une requête transmis seulement si la session n'a pas changé entre-temps ; sinon abandonné,
  // erreur comprise (l'appelant poursuivrait avec un repli, ex. session RBI lancée sans code TOTP)
  const sessionBound = (request) => async (...args) => {
    const session = sessionTokenRef.current;
    let value;
    let error = null;
    let failed = false;
    try { value = await request(...args); } catch (err) { failed = true; error = err; }
    if (sessionChanged(session)) return abandoned();
    if (failed) throw error;
    return value;
  };
  // Code TOTP lu avant le lancement d'une session RBI (menu contextuel, clic sur l'URL d'une ligne)
  const getTotpCodeInSession = sessionBound(getTotpCode);

  // Vérification TOTP d'un clic droit sur une ligne (useContextMenus l'attend avant d'ouvrir le menu) :
  // réponse d'une session terminée, ou d'un clic droit suivi d'un autre, abandonnée (seul le dernier clic
  // droit ouvre son menu ; avant, une réponse lente rouvrait le menu d'une ligne cliquée plus tôt).
  const rowMenuRequestRef = useRef(0);
  const checkTotpExistsForRowMenu = async (keyName) => {
    const request = ++rowMenuRequestRef.current;
    const session = sessionTokenRef.current;
    const exists = await checkTotpExists(keyName);
    if (request !== rowMenuRequestRef.current || sessionChanged(session)) return abandoned();
    return exists;
  };

  // « Supprimer le TOTP » en attente de confirmation (SECRETS-12) : { secret, engineName }. La boîte
  // (ModalOrchestrator) appelle handleDeleteTotp(secret, { confirmed: true }) ; elle est liée au
  // coffre sélectionné à l'ouverture (rien n'est fait s'il a changé entre-temps).
  const [totpToDelete, setTotpToDelete] = useState(null);
  const confirmDeleteTotp = (secret) => {
    if (!secret?.name || !selectedEngine) return;
    setTotpToDelete({ secret, engineName: selectedEngine.name });
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
  } = useContextMenus({ getTotpKeyName, checkTotpExists: checkTotpExistsForRowMenu, discoveredTags });

  // ========================================
  // RECHERCHE MULTI-COFFRES : ACTIONS DANS LE COFFRE DE L'ENTRÉE (SEARCH-9 / SEARCH-31)
  // ========================================
  // Les résultats d'une recherche dans tous les coffres portent le nom de LEUR coffre (engineName,
  // ajouté par readAllSecrets). Les actions des hooks (écriture, suppression, TOTP, historique,
  // déplacement, migration, partage) visent le coffre SÉLECTIONNÉ : appliquées telles quelles à un
  // résultat d'un autre coffre, elles écrivaient une copie dans le coffre sélectionné (parfois
  // partagé), supprimaient l'entrée homonyme de ce coffre et détruisaient sa graine TOTP.
  // Une action sur un tel résultat ouvre donc d'abord le coffre de l'entrée (sélection dans la
  // barre latérale, recherche conservée, recherche multi-coffres désactivée, mots de passe révélés
  // et sélection remis à zéro comme pour tout changement de coffre), puis s'exécute une fois la
  // liste de ce coffre affichée, sur la ligne relue de ce coffre : les chemins existants (écriture,
  // nom de clé TOTP, historique, source d'une migration, liste rafraîchie, reconnaissance d'une
  // modification par la fiche) visent alors le bon coffre et la bonne entrée.
  const isOtherVaultEntry = (secret) => !!(secret && typeof secret.engineName === 'string' && secret.engineName
    && secret.engineName !== selectedEngine?.name);
  const [entryVaultAction, setEntryVaultAction] = useState(null);

  const runInEntryVault = (secret, type, options = {}) => {
    const engine = secret ? secretEngines.find(e => e.name === secret.engineName) : null;
    if (!engine) {
      showToast(t('error.entryVaultUnavailable', { engine: secret?.engineName || '' }), 'error', 4000);
      return;
    }
    setVisiblePasswords({});
    clearSelection();
    setCurrentPath('');
    setMultiVaultSearch(false);
    setSelectedEngine(engine);
    setEntryVaultAction(type === 'open' ? null : { engineName: engine.name, type, secret, options });
  };

  // Exécution différée : coffre de l'entrée sélectionné ET sa liste affichée. Les gestionnaires (et
  // le nom de clé TOTP qu'ils calculent) sont alors ceux de ce coffre, et l'action reçoit la ligne
  // de CE coffre (données relues, reconnue par la fiche « Modifier » comme une entrée existante).
  useEffect(() => {
    const action = entryVaultAction;
    if (!action) return;
    // Coffre changé entre-temps (autre clic, déconnexion) : action abandonnée, rien n'est écrit
    if (!token || !selectedEngine || selectedEngine.name !== action.engineName) {
      setEntryVaultAction(null);
      return;
    }
    // Liste du coffre de l'entrée pas encore affichée (chargement en cours)
    if (loadingSecrets || secretsEngineName !== action.engineName) return;
    setEntryVaultAction(null);
    const row = secrets.find(s => s && !s.isFolder && !s.deleted && s.name === action.secret.name);
    if (!row) {
      // Entrée déplacée ou supprimée entre-temps : rien n'est fait
      showToast(t('error.entryNotInVault', { name: action.secret.name, engine: action.engineName }), 'error', 5000);
      return;
    }
    switch (action.type) {
      case 'edit': setEditSecret(row); break;
      case 'duplicate': setEditSecret({ ...row, name: `${row.name}_copie` }); break;
      case 'delete': confirmDeleteSecretInSession(row); break;
      case 'history': if (selectedEngine.version === 2) setVersionHistory({ secretName: row.name }); break;
      case 'moveToFolder': setMoveToFolder({ secrets: [row] }); break;
      case 'migrate': setMigrateSecrets({ secrets: [row], mode: action.options?.mode === 'move' ? 'move' : 'copy' }); break;
      case 'showTotp': handleShowTotpInSession(row); break;
      case 'copyTotp': handleCopyTotp(row); break;
      case 'configureTotp': handleConfigureTotpInSession(row); break;
      case 'deleteTotp': setTotpToDelete({ secret: row, engineName: selectedEngine.name }); break;
      case 'shareRbi': setShareRbiSecret(row); break;
      default: break;
    }
    // Gestionnaires lus dans CE rendu (coffre de l'entrée) ; relancé quand la liste attendue arrive
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entryVaultAction, selectedEngine, token, loadingSecrets, secretsEngineName, secrets]);

  // Clic droit sur une ligne : pour un résultat d'un autre coffre, l'existence du TOTP est vérifiée
  // sur la clé de SON coffre (useContextMenus la calcule sur le coffre sélectionné).
  const handleRowRightClick = async (e, secret, field, value) => {
    await handleCellRightClick(e, secret, field, value);
    if (!isOtherVaultEntry(secret)) return;
    let exists = false;
    try { exists = await checkTotpExists(buildTotpKeyName(secret.engineName, secret.name)); } catch { exists = false; }
    setContextMenu(m => (m && m.secret === secret ? { ...m, entryTotpExists: exists } : m));
  };

  // Glisser-déposer : la source d'un dépôt est le coffre sélectionné (useDragDrop) ; un résultat
  // d'un autre coffre n'est donc pas déplaçable depuis la recherche multi-coffres.
  const handleRowDragStart = (e, secret) => {
    if (isOtherVaultEntry(secret)) {
      e.preventDefault();
      showToast(t('error.dragOtherVault', { engine: secret.engineName }), 'warning', 4000);
      return;
    }
    // Ligne du coffre sélectionné faisant partie d'une sélection qui contient aussi des résultats
    // d'autres coffres (clés « coffre + nom ») : la sélection entière serait déplacée depuis le coffre
    // sélectionné. Refusé avec le même message (ces entrées ne sont pas déplaçables d'ici).
    if (secret && selectedSecrets.has(secret.name)) {
      const foreignEngine = Array.from(selectedSecrets).map(entryKeyEngine).find(Boolean);
      if (foreignEngine) {
        e.preventDefault();
        showToast(t('error.dragOtherVault', { engine: foreignEngine }), 'warning', 4000);
        return;
      }
    }
    handleDragStart(e, secret);
  };

  // Sortie de la recherche multi-coffres : les clés « coffre + nom » (résultats d'autres coffres) ne
  // désignent plus aucune ligne affichée. Retirées de la sélection (sinon comptées dans la
  // multi-sélection) et des mots de passe révélés (sinon révélés de nouveau au retour des résultats).
  useEffect(() => {
    if (multiVaultResultsShown) return;
    setSelectedSecrets(prev => {
      const kept = Array.from(prev).filter(k => !entryKeyEngine(k));
      return kept.length === prev.size ? prev : new Set(kept);
    });
    setVisiblePasswordsState(prev => {
      const keys = Object.keys(prev);
      const kept = keys.filter(k => !entryKeyEngine(k));
      if (kept.length === keys.length) return prev;
      const next = Object.create(null);
      for (const k of kept) next[k] = prev[k];
      return next;
    });
  }, [multiVaultResultsShown, setSelectedSecrets]);

  // APP-5 (annexe, suite n°5 de E1) : en recherche multi-coffres, les résultats du coffre SÉLECTIONNÉ
  // restaient ceux du chargement. Après « Modifier » + « Enregistrer » (ou toute action qui relit sa
  // liste), un second « Modifier » depuis les résultats rouvrait l'ancien contenu, pris pour une création
  // (SECRETS-11) et refusé (« existe déjà »). Quand sa liste est relue, ses résultats sont remplacés par
  // les lignes relues, à la même place (objets inchangés réutilisés) ; les autres coffres ne sont pas
  // touchés. Seul un changement de la liste déclenche la mise à jour : un chargement multi-coffres
  // (plus récent) n'est jamais remplacé par une liste plus ancienne. Liste vide (listage en échec,
  // remise à zéro) : résultats laissés tels quels.
  const resultsListRef = useRef(secrets);
  useEffect(() => {
    const listChanged = resultsListRef.current !== secrets;
    resultsListRef.current = secrets;
    const engine = selectedEngine;
    if (!listChanged || !multiVaultResultsShown || loadingAllSecrets || !engine || secretsEngineName !== engine.name) return;
    if (!Array.isArray(secrets) || secrets.length === 0) return;
    setAllVaultSecrets(prev => {
      if (!prev.length) return prev;
      const previousRows = prev.filter(s => s && s.engineName === engine.name);
      const freshRows = reuseUnchangedSecrets(previousRows, secrets
        .filter(s => s && !s.deleted && !s.isFolder && typeof s.name === 'string')
        .map(({ deleted, ...row }) => ({ ...row, engineName: engine.name, engineVersion: engine.version })));
      if (freshRows === previousRows || (freshRows.length === 0 && previousRows.length === 0)) return prev;
      const others = prev.filter(s => !s || s.engineName !== engine.name);
      const at = prev.findIndex(s => s && s.engineName === engine.name);
      return at === -1 ? [...others, ...freshRows] : [...others.slice(0, at), ...freshRows, ...others.slice(at)];
    });
  }, [secrets, multiVaultResultsShown, loadingAllSecrets, selectedEngine, secretsEngineName]);

  // Clic sur l'URL d'une ligne « RBI uniquement » (handleUrlAction ne transmet que le nom) : en
  // recherche multi-coffres, la clé TOTP est celle du coffre du résultat. Un nom présent dans
  // plusieurs coffres aux clés différentes est ambigu : aucune clé (session lancée sans TOTP,
  // l'utilisateur saisit le code) plutôt que le TOTP d'une autre entrée.
  const getRowTotpKeyName = (secretName) => {
    if (!multiVaultResultsShown) return getTotpKeyName(secretName);
    const keys = new Set();
    for (const s of allVaultSecrets) {
      if (s && s.name === secretName) keys.add(s.engineName ? buildTotpKeyName(s.engineName, secretName) : getTotpKeyName(secretName));
    }
    if (keys.size === 0) return getTotpKeyName(secretName);
    return keys.size === 1 ? keys.values().next().value : null;
  };
  const getRowTotpCode = (keyName) => (keyName ? getTotpCodeInSession(keyName) : Promise.resolve(null));

  // SÉCURITÉ : déconnexion / expiration de session → fermer toutes les modales et tous
  // les menus et vider leur état (mot de passe en clair de l'édition, notes, TOTP…).
  // Rien ne doit rester affiché sur l'écran de connexion ni réapparaître à la connexion
  // suivante, éventuellement d'un autre utilisateur (dont « Enregistrer » écrirait
  // dans SON coffre). Les setters sont stables (useState) : dépendance au seul jeton.
  // APP-3 : remise à zéro à CHAQUE changement de jeton, connexion comprise : un état posé par une
  // réponse tardive pendant l'écran de connexion ne s'affiche pas dans la session suivante.
  useEffect(() => {
    setPendingShare(null);
    setEditSecret(null);
    setSecretToDelete(null);
    setVersionHistory(null);
    setEngineToDelete(null);
    setShowEngineModal(false);
    setTotpDisplay(null);
    setTotpConfig(null);
    setMigrateSecrets(null);
    setMoveToFolder(null);
    setNotesPopup(null);
    setShowSettings(false);
    setShowPasswordHealth(false);
    setShowPasskeys(false);
    setShareRbiSecret(null);
    setReceiveShareOpen(false);
    setShowCreateFolderModal(false);
    setNewFolderName('');
    setContextMenu(null);
    setColumnContextMenu(null);
    setTagContextMenu(null);
    setEngineContextMenu(null);
    setFolderContextMenu(null);
    setTagCreateMode(false);
    setTagCreateValue('#');
    setSidebarOpen(false);
    setEntryVaultAction(null);
    setTotpToDelete(null);
  }, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  // ========================================
  // GESTION DES TAGS
  // ========================================
  // Les tags sont maintenant découverts automatiquement depuis les secrets
  // Pas besoin de fonctions add/remove/refresh

  useEffect(() => {
    if (selectedEngine && token) fetchSecrets(selectedEngine, showDeleted);
    // Rechargement uniquement au changement de coffre, de session ou de filtre « supprimés » :
    // fetchSecrets (useSecrets) est recréée à chaque rendu et relancerait la lecture en boucle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEngine, token, showDeleted]);

  // Sync extension Chrome + CLI IPC (hook)
  // SÉCURITÉ : sessionTokenRef (fin de session synchrone) et filtre « RBI uniquement »
  // (ces secrets ne sont ni envoyés à l'extension ni servis à la CLI)
  useSync({
    vaultApi, token, vaultUrl, authUser,
    secretEngines, selectedEngine,
    syncExtensionRef, totpRateLimit,
    showToast,
    sessionTokenRef,
    isSecretRbiOnly: isSecretRbiOnlyFn
  });

  // Stockage des passkeys WebAuthn de l'extension dans le coffre chiffré
  usePasskeys({ vaultApi, token, vaultUrl, secretEngines, authUser });

  // Mise à jour automatique : informer quand une nouvelle version est prête (installée au redémarrage)
  useEffect(() => {
    if (!window.electronUpdater?.onStatus) return;
    window.electronUpdater.onStatus((status) => {
      if (status?.state === 'downloaded') {
        showToast(t('update.downloaded', { version: status.version || '' }), 'success');
      } else if (status?.state === 'error') {
        showToast(t('update.error'), 'warning');
      }
    });
    return () => { try { window.electronUpdater.removeStatusListener(); } catch {} };
  }, [showToast, t]);

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

  // Recherche multi-coffre : chargement de tous les secrets, annulable.
  // Si le mode est désactivé, la liste des coffres change ou l'utilisateur se
  // déconnecte pendant le chargement, l'AbortController invalide le résultat
  // (pas de setState sur des données périmées ni après démontage).
  useEffect(() => {
    if (!multiVaultSearch || !token) {
      setAllVaultSecrets([]);
      return;
    }

    const controller = new AbortController();
    const { signal } = controller;

    const loadAllSecrets = async () => {
      setLoadingAllSecrets(true);

      try {
        const result = await readAllSecrets(vaultApi, secretEngines, { signal });
        const allSecrets = result.secrets;
        if (result.aborted || signal.aborted) return;
        // Lectures en échec (réseau, délai, 5xx) après relances : signalées, jamais ignorées en silence.
        // Coffre listé partiellement (borne de listage) : message précis, et non « erreur réseau »
        const incomplete = incompleteReadMessage(result, t);
        if (incomplete) showToast(incomplete, 'warning', 10000);

        // Extraire les tags découverts depuis tous les coffres + tags partagés
        const tags = await mergeDiscoveredAndSharedTags(allSecrets);
        if (signal.aborted) return;
        secureLogger.debug('[loadAllSecrets] tags:', tags.length);
        setDiscoveredTags(tags);

        setAllVaultSecrets(allSecrets);
      } catch (err) {
        if (!signal.aborted) secureLogger.error('[loadAllSecrets] Erreur chargement multi-coffre');
      } finally {
        if (!signal.aborted) setLoadingAllSecrets(false);
      }
    };

    loadAllSecrets();

    return () => controller.abort();
  }, [multiVaultSearch, token, secretEngines]); // eslint-disable-line


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
                  onOpenPasswordHealth={() => setShowPasswordHealth(true)}
                  onOpenPasskeys={() => setShowPasskeys(true)}
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
            setupRecheck={firstRunRecheck}
            t={t}
          />
        )}

        {token && (
          currentView === 'admin' && (isAdmin || isModerator) ? (
            <Suspense fallback={<LoadingSpinner />}>
            <AdminPanel
              vaultUrl={vaultUrl}
              vaultNs={vaultNs}
              ldapAuthPath={ldapAuthPath}
              token={token}
              baseHeaders={baseHeaders}
              axiosConfig={axiosConfig}
              vaultApi={vaultApi}
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
            </Suspense>
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
                {t('migrate.root')}
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
            handleDragStart={handleRowDragStart}
            handleDragEnd={handleDragEnd}
            handleDragOver={handleDragOver}
            handleDragLeave={handleDragLeave}
            handleDropOnFolder={handleDropOnFolder}
            handleColumnResizeStart={handleColumnResizeStart}
            autoFitColumn={autoFitColumn}
            handleColumnHeaderRightClick={handleColumnHeaderRightClick}
            handleEmptyAreaRightClick={handleEmptyAreaRightClick}
            handleCellRightClick={handleRowRightClick}
            handleFolderRightClick={handleFolderRightClick}
            handleTagCellRightClick={handleTagCellRightClick}
            isSecretRbiOnly={isSecretRbiOnly}
            startClipboardTimer={startClipboardTimer}
            setNotesPopup={setNotesPopup}
            setCurrentPath={setCurrentPath}
            getTagColor={getTagColor}
            getTotpKeyName={getRowTotpKeyName}
            getTotpCode={getRowTotpCode}
            showToast={showToast}
            t={t}
          />

          </div>
          </>
        ))}
      </div>

      {/* Modales — SÉCURITÉ : uniquement pendant une session (jamais sur l'écran de connexion) */}
      {token && (
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
        totpToDelete={totpToDelete} setTotpToDelete={setTotpToDelete} handleDeleteTotp={handleDeleteTotp}
        migrateSecrets={migrateSecrets} setMigrateSecrets={setMigrateSecrets}
        handleMigrateSecrets={handleMigrateSecrets} secretEngines={secretEngines}
        moveToFolder={moveToFolder} setMoveToFolder={setMoveToFolder}
        handleMoveToFolder={handleMoveToFolder} secrets={secrets}
        versionHistory={versionHistory} setVersionHistory={setVersionHistory}
        handleRestoreVersion={handleRestoreVersion}
        vaultUrl={vaultUrl} baseHeaders={baseHeaders} axiosConfig={axiosConfig}
        notesPopup={notesPopup} setNotesPopup={setNotesPopup}
        showSettings={showSettings} setShowSettings={setShowSettings} onSettingsWrites={handleSettingsWrites}
        darkMode={darkMode} toggleDarkMode={toggleDarkMode}
        visibleColumns={visibleColumns} toggleColumn={toggleColumn}
        isModerator={isModerator} appMode={appMode} token={token}
        shareRbiSecret={shareRbiSecret} setShareRbiSecret={setShareRbiSecret}
        rbiProxyUrl={rbiProxyUrl}
        receiveShareOpen={receiveShareOpen} setReceiveShareOpen={setReceiveShareOpen}
        showPasswordHealth={showPasswordHealth} setShowPasswordHealth={setShowPasswordHealth} vaultApi={vaultApi}
        showPasskeys={showPasskeys} setShowPasskeys={setShowPasskeys} authUser={authUser}
        restoreFocus={restoreFocus} showToast={showToast} t={t}
      />
      )}

      {/* Confirmation d'un partage reçu via deep link (URL cible + utilisateur) — session ouverte uniquement (APP-3) */}
      {token && pendingShare && (
        <ConfirmModal
          title={t('confirm.openShare')}
          message={t('confirm.openShareMsg', { url: pendingShare.url, username: pendingShare.username || '-' })}
          confirmLabel={t('confirm.open')}
          cancelLabel={t('common.cancel')}
          onConfirm={confirmPendingShare}
          onCancel={() => setPendingShare(null)}
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

      {/* Context Menu - Secrets (session ouverte uniquement) */}
      {token && (
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
        confirmDeleteSecret={confirmDeleteSecretInSession}
        startClipboardTimer={startClipboardTimer}
        getTotpKeyName={getTotpKeyName}
        getTotpCode={getTotpCodeInSession}
        handleShowTotp={handleShowTotpInSession}
        handleCopyTotp={handleCopyTotp}
        handleConfigureTotp={handleConfigureTotpInSession}
        handleDeleteTotp={handleDeleteTotp}
        confirmDeleteTotp={confirmDeleteTotp}
        setShareRbiSecret={setShareRbiSecret}
        setVersionHistory={setVersionHistory}
        setMoveToFolder={setMoveToFolder}
        setMigrateSecrets={setMigrateSecrets}
        runInEntryVault={runInEntryVault}
        selectedSecrets={selectedSecrets}
        secrets={secrets}
        installedBrowsers={installedBrowsers}
        appMode={appMode}
        showToast={showToast}
        t={t}
      />
      )}

      {/* Context Menus - Folder, Column, Tag, Engine (session ouverte uniquement) */}
      {token && (
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
      )}
    </div>
  );
}
