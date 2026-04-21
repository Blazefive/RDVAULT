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
import * as tagManager from './utils/tagManager';

// ========================================
// IMPORTS DES MODULES DE SÉCURITÉ
// ========================================
import { useSessionTimeout } from './useSessionTimeout';
import { useDebounce, useThrottle, useRateLimit } from './useRateLimit';
import * as validation from './validation';
import secureLogger from './secureLogger';
import bruteForceProtection from './bruteForceProtection';

// ========================================
// FONCTIONS DE SÉCURITÉ (LEGACY - À REMPLACER)
// ========================================

/**
 * Sanitize une chaîne pour affichage sécurisé
 * Protection contre XSS en encodant les caractères dangereux
 */
const sanitizeForDisplay = (str) => {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * SÉCURITÉ: Construit et valide une URL pour ouverture dans un navigateur/RBI
 * Rejette les protocoles dangereux (javascript:, data:, etc.)
 */
const buildSafeUrl = (rawUrl) => {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const url = rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return url;
  } catch { return null; }
};

/**
 * Encode un chemin d'engine Vault segment par segment
 * Les engine names peuvent contenir des / (ex: users/john) mais chaque segment doit être encodé
 */
const encodeEnginePath = (name) => {
  return name.replace(/^\/+|\/+$/g, '')
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/');
};

/**
 * Valide un nom de secret/engine
 * Autorise uniquement les caractères alphanumériques, tirets, underscores et slashes
 */
const validateSecretName = (name) => {
  if (!name || typeof name !== 'string') return false;
  // Autoriser a-z, A-Z, 0-9, -, _, /
  return /^[a-zA-Z0-9\-_\/]+$/.test(name);
};

/**
 * Masque les erreurs techniques sensibles
 */
const sanitizeError = (err) => {
  const status = err.response?.status;
  const genericMessages = {
    400: 'Requête invalide',
    401: 'Non authentifié',
    403: 'Accès refusé',
    404: 'Ressource introuvable',
    500: 'Erreur serveur',
    502: 'Service temporairement indisponible',
    503: 'Service temporairement indisponible'
  };

  // Retourner un message générique pour éviter l'exposition d'informations sensibles
  return genericMessages[status] || 'Une erreur est survenue';
};

// RateLimiter supprimé — remplacé par bruteForceProtection.js

function Toast({ toast }) {
  if (!toast?.visible) return null;
  return (
    <div
      className={`toast toast-${toast.type}`}
      style={{ pointerEvents: 'none' }}
      tabIndex={-1}
      aria-live="polite"
      aria-atomic="true"
    >
      {toast.message}
    </div>
  );
}

export default function App() {
  // Configuration chargée depuis config.json (via Electron)
  const [vaultUrl, setVaultUrl] = useState('');
  const [ldapAuthPath, setLdapAuthPath] = useState('auth/ldap');
  const [rbiProxyUrl, setRbiProxyUrl] = useState('');
  const [configLoaded, setConfigLoaded] = useState(false);
  const [appMode, setAppMode] = useState('enterprise'); // 'enterprise' ou 'local'
  const { t, lang, setLang } = useTranslation();
  const [vaultNs, setVaultNs] = useState('');
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

  const [contextMenu, setContextMenu] = useState(null);
  const [columnContextMenu, setColumnContextMenu] = useState(null);
  const [tagContextMenu, setTagContextMenu] = useState(null);
  const [tagCreateMode, setTagCreateMode] = useState(false);
  const [tagCreateValue, setTagCreateValue] = useState('#');
  const [engineContextMenu, setEngineContextMenu] = useState(null);
  const [totpExistsCache, setTotpExistsCache] = useState({});
  const [showDeleted, setShowDeleted] = useState(false);
  const [clipboardTimer, setClipboardTimer] = useState(null);
  const [installedBrowsers, setInstalledBrowsers] = useState([]);

  const [totpDisplay, setTotpDisplay] = useState(null);
  const [totpConfig, setTotpConfig] = useState(null);
  const [migrateSecrets, setMigrateSecrets] = useState(null);  // { secrets: [], mode: 'copy'|'move' }
  const [moveToFolder, setMoveToFolder] = useState(null);      // { secrets: [] } - déplacement intra-engine
  const [versionHistory, setVersionHistory] = useState(null);
  const [multiVaultSearch, setMultiVaultSearch] = useState(false);
  const [allVaultSecrets, setAllVaultSecrets] = useState([]);
  const [showCreateFolderModal, setShowCreateFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [folderContextMenu, setFolderContextMenu] = useState(null); // Menu contextuel dossier {x, y, folderPath}
  const [loadingAllSecrets, setLoadingAllSecrets] = useState(false);
  const totpEngineName = 'TOTP';

  // ========================================
  // NOUVEAUX ÉTATS POUR VERSION 1.1
  // ========================================
  const [toast, setToast] = useState({ visible: false, type: 'info', message: '' });
  const [notesPopup, setNotesPopup] = useState(null);           // Popup affichage notes
  const [showSettings, setShowSettings] = useState(false);      // Modal paramètres
  const [discoveredTags, setDiscoveredTags] = useState([]);     // Tags découverts automatiquement dans les secrets
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
  const [selectedSecrets, setSelectedSecrets] = useState(new Set()); // Secrets sélectionnés (noms)
  const [isDragging, setIsDragging] = useState(false);               // En cours de drag
  const [dragOverTarget, setDragOverTarget] = useState(null);        // Cible de drop survolée (engine name ou folder path)
  const [visibleColumns, setVisibleColumns] = useState(() => {
    // Charger les colonnes visibles depuis localStorage avec validation stricte
    const defaults = { name: true, username: true, password: true, url: true, website: true, notes: true, tags: true, customFields: false, actions: true };
    const allowedKeys = Object.keys(defaults);
    try {
      const saved = localStorage.getItem('rdvault-visible-columns');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          const clean = {};
          for (const k of allowedKeys) clean[k] = k in parsed ? parsed[k] !== false : defaults[k];
          return clean;
        }
      }
      return defaults;
    } catch { return defaults; }
  });
  const [columnWidths, setColumnWidths] = useState(() => {
    // Charger les largeurs de colonnes depuis localStorage avec validation stricte
    const allowedKeys = ['name', 'username', 'password', 'url', 'website', 'notes', 'tags', 'customFields', 'engine'];
    try {
      const saved = localStorage.getItem('rdvault-column-widths');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          const clean = {};
          for (const k of allowedKeys) {
            if (typeof parsed[k] === 'number' && parsed[k] > 0 && parsed[k] < 2000) clean[k] = parsed[k];
          }
          return clean;
        }
      }
      return {};
    } catch { return {}; }
  });
  const [resizingColumn, setResizingColumn] = useState(null);
  const resizeStartX = useRef(0);
  const resizeStartWidth = useRef(0);

  // États pour la vue arborescence
  const [treeViewEnabled, setTreeViewEnabled] = useState(() => {
    return localStorage.getItem('rdvault-tree-view-enabled') === 'true';
  });
  const [currentPath, setCurrentPath] = useState('');

  const toastTimer = useRef(null);
  const clipboardTimerRef = useRef(null);

  const searchRef = useRef(null);
  const appRootRef = useRef(null);
  const contextMenuRef = useRef(null);
  const tagContextMenuRef = useRef(null);
  const syncExtensionRef = useRef(null);
  const lastClickedSecretRef = useRef(null); // Pour Shift+Clic sélection par plage
  const displayedSecretsRef = useRef([]); // Liste affichée pour calcul de plage

  // Vérifier si le coffre sélectionné est entièrement RBI-Only
  const isCurrentEngineRbiOnly = selectedEngine && rbiOnlyEngines.has(selectedEngine.name);
  // Vérifier si un secret spécifique est RBI-Only
  const isSecretRbiOnly = (secretName) => {
    if (!selectedEngine) return false;
    if (rbiOnlyEngines.has(selectedEngine.name)) return true;
    return rbiOnlySecrets.has(selectedEngine.name + '/' + secretName);
  };

  // Colonnes effectives : si coffre entièrement RBI-Only, seules name, url et tags sont visibles
  const effectiveVisibleColumns = isCurrentEngineRbiOnly
    ? { name: true, username: false, password: false, url: true, website: false, notes: false, tags: true, customFields: false, actions: false }
    : visibleColumns;

  // Gérer le redimensionnement de la fenêtre pour le mode responsive
  // Récupérer la liste des noms de secrets d'un engine (léger, pour détection doublons)
  const fetchSecretsForEngine = async (engine) => {
    try {
      const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
      return keys.map(k => ({ name: k }));
    } catch { return []; }
  };

  // Migration/Copie d'entrées (supporte un tableau de secrets)
  const handleMigrateSecrets = async (secretsList, targetEngine, mode) => {
    const secrets = Array.isArray(secretsList) ? secretsList : [secretsList];
    if (secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
    const count = secrets.length;
    let successCount = 0;
    let failCount = 0;
    let renamedCount = 0;

    // Récupérer la liste des secrets existants dans le coffre cible pour détecter les doublons
    let targetSecretNames = new Set();
    try {
      const targetSecrets = await fetchSecretsForEngine(targetEngine);
      targetSecretNames = new Set((targetSecrets || []).map(s => s.name));
    } catch (e) { /* coffre vide ou erreur, on continue */ }

    for (const secret of secrets) {
      try {
        const sourceData = selectedEngine.version === 2
          ? await readSecretV2(selectedEngine, secret.name)
          : await readSecretV1(selectedEngine, secret.name);

        // Vérifier si un secret du même nom existe dans la cible
        let targetName = sourceData.name;
        if (targetSecretNames.has(targetName)) {
          // Générer un nom unique avec suffixe
          let suffix = 1;
          while (targetSecretNames.has(`${sourceData.name}_${suffix}`)) suffix++;
          targetName = `${sourceData.name}_${suffix}`;
          renamedCount++;
        }
        const dataToWrite = { ...sourceData, name: targetName };
        targetSecretNames.add(targetName);

        if (targetEngine.version === 2) {
          await writeSecretV2(targetEngine, dataToWrite);
        } else {
          await writeSecretV1(targetEngine, dataToWrite);
        }

        if (mode === 'move') {
          if (selectedEngine.version === 2) {
            await deleteSecretV2(selectedEngine, secret.name);
          } else {
            await deleteSecretV1(selectedEngine, secret.name);
          }
        }
        successCount++;
      } catch (err) {
        secureLogger.error(`[Migration] Erreur ${mode}`);
        failCount++;
      }
    }

    await fetchSecrets(selectedEngine, showDeleted);
    clearSelection();
    syncExtensionRef.current?.();

    const renamedMsg = renamedCount > 0 ? ` (${renamedCount} renommée(s) pour éviter les doublons)` : '';
    if (failCount === 0) {
      showToast(t('toast.migrationSuccess', { count: successCount }), 'success');
    } else {
      showToast(`${successCount} / ${failCount}`, 'warning');
    }
  };

  // Déplacement de secrets vers un autre dossier (intra-engine) - supporte un tableau
  const handleMoveToFolder = async (secretsList, targetFolderPath) => {
    const secrets = Array.isArray(secretsList) ? secretsList : [secretsList];
    if (secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
    const count = secrets.length;
    let successCount = 0;
    let failCount = 0;

    for (const secret of secrets) {
      try {
        // 1. Lire le secret source
        const sourceData = selectedEngine.version === 2
          ? await readSecretV2(selectedEngine, secret.name)
          : await readSecretV1(selectedEngine, secret.name);

        // 2. Calculer le nouveau nom
        const baseName = secret.name.split('/').pop();
        const newName = targetFolderPath ? `${targetFolderPath}/${baseName}` : baseName;

        // 3. Vérifier qu'on ne déplace pas au même endroit
        if (newName === secret.name) {
          continue; // Ignorer silencieusement
        }

        // 4. Écrire le secret avec le nouveau chemin
        const newEntry = { ...sourceData, name: newName };
        if (selectedEngine.version === 2) {
          await writeSecretV2(selectedEngine, newEntry);
          await deleteSecretV2(selectedEngine, secret.name);
        } else {
          await writeSecretV1(selectedEngine, newEntry);
          await deleteSecretV1(selectedEngine, secret.name);
        }
        successCount++;
      } catch (err) {
        secureLogger.error('[Déplacement] Erreur');
        failCount++;
      }
    }

    await fetchSecrets(selectedEngine, showDeleted);
    clearSelection();
    syncExtensionRef.current?.();

    if (failCount === 0) {
      showToast(t('toast.moveSuccess', { count: successCount }), 'success');
    } else {
      showToast(`${successCount} / ${failCount}`, 'warning');
    }
  };

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

  const handleCellRightClick = async (e, secret, field, value) => {
    e.preventDefault();

    const totpKeyName = getTotpKeyName(secret.name);
    const totpExists = await checkTotpExists(totpKeyName);

    setTagContextMenu(null);
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      secret,
      field,
      value,
      totpExists
    });
  };

  const handleEmptyAreaRightClick = (e) => {
    // Vérifier si le clic est sur une cellule de tableau (ou à l'intérieur)
    const isOnCell = e.target.closest('td');

    // Si le clic est sur une cellule, ne rien faire (le gestionnaire de cellule s'en occupera)
    if (isOnCell) {
      return;
    }

    // Ne pas ouvrir le menu si c'est sur un bouton, input, ou autre élément interactif
    const isInteractive = e.target.closest('button, input, a, select, textarea');
    if (isInteractive) {
      return;
    }

    e.preventDefault();
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      type: 'create' // Nouveau type pour distinguer du menu contextuel normal
    });
  };

  const handleFolderRightClick = (e, folderPath) => {
    e.preventDefault();
    e.stopPropagation();
    setFolderContextMenu({
      x: e.clientX,
      y: e.clientY,
      folderPath
    });
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

  const handleColumnHeaderRightClick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setColumnContextMenu({
      x: e.clientX,
      y: e.clientY
    });
  };

  const handleTagCellRightClick = (e, secret) => {
    e.preventDefault();
    e.stopPropagation();

    // Récupérer les tags actuels de l'entrée
    const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];

    // Filtrer pour ne garder que les tags non attribués
    // discoveredTags contient tous les tags détectés dans les coffres accessibles
    const availableTags = discoveredTags.filter(tag => !currentTags.includes(tag));

    setContextMenu(null);
    setTagContextMenu({
      x: e.clientX,
      y: e.clientY,
      secret,
      availableTags,
      currentTags
    });
  };

  const handleAddTagToSecret = async (secret, tagToAdd) => {
    try {
      // Ajouter le tag aux tags existants
      const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];
      const newTags = [...currentTags, tagToAdd].join(' ');

      // Mettre à jour l'entrée
      const updatedSecret = { ...secret, tags: newTags };

      // Déterminer quel engine utiliser (important pour la recherche multi-vault)
      let targetEngine = selectedEngine;
      if (secret.engineName && secret.engineVersion) {
        // En mode recherche multi-vault, trouver l'engine correspondant
        targetEngine = secretEngines.find(
          e => e.name === secret.engineName && e.version === secret.engineVersion
        );
      }

      if (!targetEngine) {
        showToast(t('error.engineNotFound'), 'error');
        return;
      }

      // Sauvegarder dans Vault
      if (targetEngine.version === 2) {
        await writeSecretV2(targetEngine, updatedSecret);
      } else {
        await writeSecretV1(targetEngine, updatedSecret);
      }

      // Rafraîchir la liste des secrets
      if (multiVaultSearch) {
        // En mode recherche multi-vault, recharger tous les secrets
        setLoadingAllSecrets(true);
        const allEngineSecrets = await Promise.all(
          secretEngines.map(async (engine) => {
            try {
              const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
              const secretPromises = keys.map(async (key) => {
                try {
                  const s = engine.version === 2 ? await readSecretV2(engine, key) : await readSecretV1(engine, key);
                  return { ...s, engineName: engine.name, engineVersion: engine.version };
                } catch { return null; }
              });
              return (await Promise.all(secretPromises)).filter(s => s !== null);
            } catch { return []; }
          })
        );
        const allSecrets = allEngineSecrets.flat();
        setAllVaultSecrets(allSecrets);
        setLoadingAllSecrets(false);
      } else {
        await fetchSecrets(targetEngine);
      }

      showToast(t('toast.tagAdded'), 'success', 1500);
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.tagAdd')} ${msg}`, 'error');
    }
  };

  const handleRemoveTagFromSecret = async (secret, tagToRemove) => {
    try {
      // Retirer le tag des tags existants
      const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];
      const newTags = currentTags.filter(tag => tag !== tagToRemove).join(' ');

      // Mettre à jour l'entrée
      const updatedSecret = { ...secret, tags: newTags };

      // Déterminer quel engine utiliser (important pour la recherche multi-vault)
      let targetEngine = selectedEngine;
      if (secret.engineName && secret.engineVersion) {
        // En mode recherche multi-vault, trouver l'engine correspondant
        targetEngine = secretEngines.find(
          e => e.name === secret.engineName && e.version === secret.engineVersion
        );
      }

      if (!targetEngine) {
        showToast(t('error.engineNotFound'), 'error');
        return;
      }

      // Sauvegarder dans Vault
      if (targetEngine.version === 2) {
        await writeSecretV2(targetEngine, updatedSecret);
      } else {
        await writeSecretV1(targetEngine, updatedSecret);
      }

      // Rafraîchir la liste des secrets
      if (multiVaultSearch) {
        // En mode recherche multi-vault, recharger tous les secrets
        setLoadingAllSecrets(true);
        const allEngineSecrets = await Promise.all(
          secretEngines.map(async (engine) => {
            try {
              const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
              const secretPromises = keys.map(async (key) => {
                try {
                  const s = engine.version === 2 ? await readSecretV2(engine, key) : await readSecretV1(engine, key);
                  return { ...s, engineName: engine.name, engineVersion: engine.version };
                } catch { return null; }
              });
              return (await Promise.all(secretPromises)).filter(s => s !== null);
            } catch { return []; }
          })
        );
        const allSecrets = allEngineSecrets.flat();
        setAllVaultSecrets(allSecrets);
        setLoadingAllSecrets(false);
      } else {
        await fetchSecrets(targetEngine);
      }

      showToast(t('toast.tagRemoved'), 'success', 1500);
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.tagRemove')} ${msg}`, 'error');
    }
  };

  const handleEngineRightClick = (e, engine) => {
    e.preventDefault();
    e.stopPropagation();

    // Vérifier si c'est un coffre personnel (peut être supprimé)
    const currentUser = localStorage.getItem('vault-client.username') || '';
    const userPrefix = currentUser ? `users/${currentUser}/` : '';
    const canDelete = userPrefix && (engine.name.startsWith(userPrefix) || engine.name.startsWith(`users/${currentUser}`));

    if (!canDelete) {
      // Ne rien afficher pour les coffres partagés
      return;
    }

    setEngineContextMenu({
      x: e.clientX,
      y: e.clientY,
      engine
    });
  };

  // ========================================
  // CHARGEMENT DE LA CONFIGURATION
  // ========================================
  // Charge la configuration depuis config.json via Electron au démarrage
  // Paramètres : VAULT_URL, LDAP_AUTH_PATH, TRUSTED_DOMAINS
  useEffect(() => {
    const loadConfig = async () => {
      try {
        // Vérifier si Electron est disponible
        if (window.electronConfig && window.electronConfig.getConfig) {
          const result = await window.electronConfig.getConfig();
          if (result.success && result.config) {
            secureLogger.debug('[CONFIG] Configuration chargée');
            setVaultUrl(result.config.VAULT_URL || 'https://vault.example.com:8200');
            // SÉCURITÉ: Valider ldapAuthPath pour éviter l'injection de chemin
            const rawAuthPath = (result.config.LDAP_AUTH_PATH || 'auth/ldap').trim();
            if (/^[a-zA-Z0-9/_-]+$/.test(rawAuthPath) && !rawAuthPath.includes('..')) {
              setLdapAuthPath(rawAuthPath);
            } else {
              secureLogger.warn('[CONFIG] LDAP_AUTH_PATH invalide, utilisation par défaut');
              setLdapAuthPath('auth/ldap');
            }
            if (result.config.RBI_PROXY_URL) setRbiProxyUrl(result.config.RBI_PROXY_URL);
            if (result.config.APP_MODE) setAppMode(result.config.APP_MODE);
            // Appliquer la langue depuis la config (si pas déjà changée manuellement)
            if (result.config.LANG && !localStorage.getItem('rdvault-lang')) {
              setLang(result.config.LANG);
            }
          } else {
            // Fallback sur les valeurs par défaut
            secureLogger.warn('[CONFIG] Échec du chargement, utilisation des valeurs par défaut');
            setVaultUrl('https://vault.example.com:8200');
          }
        } else {
          // Mode développement sans Electron
          secureLogger.debug('[CONFIG] Electron non disponible, utilisation des valeurs par défaut');
          setVaultUrl('https://vault.example.com:8200');
        }
      } catch (err) {
        secureLogger.error('[CONFIG] Erreur chargement configuration');
        setVaultUrl('https://vault.example.com:8200');
      } finally {
        setConfigLoaded(true);
      }
    };

    loadConfig();
  }, []);

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

  const totpRateLimit = useRateLimit(10, 60000); // Max 10 générations TOTP par minute

  // ========================================
  // FONCTIONS DE MULTI-SÉLECTION (v1.4)
  // ========================================

  /**
   * Toggle la sélection d'un secret (Ctrl+Clic, Shift+Clic)
   * @param {string} secretName - Nom du secret à sélectionner/désélectionner
   * @param {boolean} ctrlKey - Si Ctrl est pressé (ajoute à la sélection)
   * @param {boolean} shiftKey - Si Shift est pressé (sélection par plage)
   */
  const toggleSecretSelection = (secretName, ctrlKey = false, shiftKey = false) => {
    setSelectedSecrets(prev => {
      const newSet = new Set(prev);
      if (shiftKey && lastClickedSecretRef.current) {
        // Shift+Clic : sélectionner toute la plage entre le dernier clic et celui-ci
        const list = displayedSecretsRef.current;
        const startIdx = list.findIndex(s => s.name === lastClickedSecretRef.current);
        const endIdx = list.findIndex(s => s.name === secretName);
        if (startIdx !== -1 && endIdx !== -1) {
          const from = Math.min(startIdx, endIdx);
          const to = Math.max(startIdx, endIdx);
          for (let i = from; i <= to; i++) {
            if (!list[i].isFolder && !list[i].deleted) {
              newSet.add(list[i].name);
            }
          }
        }
      } else if (ctrlKey) {
        // Ctrl+Clic : toggle la sélection
        if (newSet.has(secretName)) {
          newSet.delete(secretName);
        } else {
          newSet.add(secretName);
        }
      } else {
        // Clic simple : sélection unique
        if (newSet.size === 1 && newSet.has(secretName)) {
          newSet.clear();
        } else {
          newSet.clear();
          newSet.add(secretName);
        }
      }
      lastClickedSecretRef.current = secretName;
      return newSet;
    });
  };

  /**
   * Sélectionne tous les secrets visibles
   * @param {Array} secretsList - Liste des secrets à sélectionner
   */
  const selectAllSecrets = (secretsList) => {
    const names = secretsList
      .filter(s => !s.isFolder && !s.deleted)
      .map(s => s.name);
    setSelectedSecrets(new Set(names));
  };

  /**
   * Efface la sélection
   */
  const clearSelection = () => {
    setSelectedSecrets(new Set());
  };

  /**
   * Vérifie si un secret est sélectionné
   * @param {string} secretName - Nom du secret
   * @returns {boolean}
   */
  const isSecretSelected = (secretName) => {
    return selectedSecrets.has(secretName);
  };

  // ========================================
  // FONCTIONS DE DRAG & DROP (v1.4)
  // ========================================

  /**
   * Gestionnaire de début de drag
   * @param {DragEvent} e - Événement de drag
   * @param {Object} secret - Secret en cours de drag
   */
  const handleDragStart = (e, secret) => {
    // Si le secret n'est pas dans la sélection, le sélectionner seul
    if (!selectedSecrets.has(secret.name)) {
      setSelectedSecrets(new Set([secret.name]));
    }

    // Stocker les données de drag
    const dragData = {
      type: 'secrets',
      secrets: selectedSecrets.has(secret.name)
        ? Array.from(selectedSecrets)
        : [secret.name],
      sourceEngine: selectedEngine?.name,
      sourceVersion: selectedEngine?.version
    };

    e.dataTransfer.setData('application/json', JSON.stringify(dragData));
    e.dataTransfer.effectAllowed = 'move';

    setIsDragging(true);

    // Créer un élément de drag visuel personnalisé
    const dragCount = dragData.secrets.length;
    const dragGhost = document.createElement('div');
    dragGhost.className = 'drag-ghost';
    dragGhost.textContent = `📦 ${dragCount} entrée${dragCount > 1 ? 's' : ''}`;
    dragGhost.style.cssText = `
      position: absolute;
      top: -1000px;
      left: -1000px;
      padding: 8px 16px;
      background: var(--accent, #3b82f6);
      color: white;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      pointer-events: none;
      z-index: 9999;
    `;
    document.body.appendChild(dragGhost);
    e.dataTransfer.setDragImage(dragGhost, 50, 20);

    // Nettoyer le ghost après un court délai
    setTimeout(() => {
      if (dragGhost.parentNode) {
        dragGhost.parentNode.removeChild(dragGhost);
      }
    }, 0);
  };

  /**
   * Gestionnaire de fin de drag
   */
  const handleDragEnd = () => {
    setIsDragging(false);
    setDragOverTarget(null);
  };

  /**
   * Gestionnaire de survol pour les drop zones
   * @param {DragEvent} e - Événement de drag
   * @param {string} targetId - Identifiant de la cible (engine name ou folder path)
   */
  const handleDragOver = (e, targetId) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOverTarget(targetId);
  };

  /**
   * Gestionnaire de sortie de zone de drop
   */
  const handleDragLeave = () => {
    setDragOverTarget(null);
  };

  /**
   * Gestionnaire de drop sur un engine (migration inter-coffre ou déplacement à la racine)
   * @param {DragEvent} e - Événement de drop
   * @param {Object} targetEngine - Engine cible
   */
  const handleDropOnEngine = async (e, targetEngine) => {
    e.preventDefault();
    setDragOverTarget(null);
    setIsDragging(false);

    try {
      const dragData = JSON.parse(e.dataTransfer.getData('application/json'));

      if (dragData.type !== 'secrets' || !Array.isArray(dragData.secrets) || !dragData.secrets.length) {
        return;
      }
      // SÉCURITÉ: Valider les données du drag-and-drop
      if (dragData.secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
      if (typeof dragData.sourceEngine !== 'string' || !secretEngines.some(eng => eng.name === dragData.sourceEngine)) return;
      if (dragData.secrets.some(n => typeof n !== 'string' || n.includes('..') || /[\x00-\x1F]/.test(n) || n.length > 512)) return;

      // Vérifier les droits d'écriture sur l'engine cible
      if (!targetEngine.canWrite) {
        showToast(t('error.noReadAccess'), 'error');
        return;
      }

      // Si drop sur le même engine → déplacer à la racine
      if (dragData.sourceEngine === targetEngine.name) {
        // Vérifier si les entrées sont déjà à la racine
        const secretsInFolders = dragData.secrets.filter(name => name.includes('/'));
        if (secretsInFolders.length === 0) {
          showToast(t('migrate.root'), 'info');
          return;
        }
        // Déplacer à la racine (chemin vide)
        await moveSecretsToFolder(dragData.secrets, '');
        return;
      }

      // Sinon → migration inter-coffre
      await migrateSecretsToEngine(dragData.secrets, dragData.sourceEngine, dragData.sourceVersion, targetEngine);

    } catch (err) {
      secureLogger.error('[Drop] Erreur');
      showToast(t('error.retrieveSecret'), 'error');
    }
  };

  /**
   * Gestionnaire de drop sur un dossier (déplacement intra-coffre)
   * @param {DragEvent} e - Événement de drop
   * @param {string} targetFolder - Chemin du dossier cible
   */
  const handleDropOnFolder = async (e, targetFolder) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverTarget(null);
    setIsDragging(false);

    try {
      const dragData = JSON.parse(e.dataTransfer.getData('application/json'));

      if (dragData.type !== 'secrets' || !Array.isArray(dragData.secrets) || !dragData.secrets.length) {
        return;
      }
      // SÉCURITÉ: Valider les données du drag-and-drop
      if (dragData.secrets.length > 500) return;
      if (dragData.secrets.some(n => typeof n !== 'string' || n.includes('..') || /[\x00-\x1F]/.test(n) || n.length > 512)) return;

      // Vérifier qu'on est dans le même engine
      if (dragData.sourceEngine !== selectedEngine?.name) {
        showToast(t('migrate.noWritableEngines'), 'warning');
        return;
      }

      // Lancer le déplacement vers le dossier
      await moveSecretsToFolder(dragData.secrets, targetFolder);

    } catch (err) {
      secureLogger.error('[Drop] Erreur dossier');
      showToast(t('error.retrieveSecret'), 'error');
    }
  };

  /**
   * Migre des secrets vers un autre engine
   */
  const migrateSecretsToEngine = async (secretNames, sourceEngineName, sourceVersion, targetEngine) => {
    const sourceEngine = secretEngines.find(e => e.name === sourceEngineName);
    if (!sourceEngine) {
      showToast(t('error.engineNotFound'), 'error');
      return;
    }

    const successCount = { moved: 0, failed: 0 };

    for (const secretName of secretNames) {
      try {
        // Lire le secret source
        const secretData = await readSecretForMigration(sourceEngine, secretName);
        if (!secretData) {
          successCount.failed++;
          continue;
        }

        // Écrire dans l'engine cible
        const writeSuccess = await writeSecretToEngine(targetEngine, secretName, secretData);
        if (!writeSuccess) {
          successCount.failed++;
          continue;
        }

        // Supprimer de l'engine source
        const deleteSuccess = await deleteSecretFromEngine(sourceEngine, secretName);
        if (deleteSuccess) {
          successCount.moved++;
        } else {
          successCount.failed++;
        }

      } catch (err) {
        secureLogger.error('[Migration] Erreur');
        successCount.failed++;
      }
    }

    // Rafraîchir les secrets
    await fetchSecrets(selectedEngine, showDeleted);
    clearSelection();

    // Afficher le résultat
    if (successCount.failed === 0) {
      showToast(t('toast.migrationSuccess', { count: successCount.moved }), 'success');
    } else {
      showToast(`${successCount.moved} / ${successCount.failed}`, 'warning');
    }
  };

  /**
   * Déplace des secrets vers un dossier (intra-engine)
   */
  const moveSecretsToFolder = async (secretNames, targetFolder) => {
    const successCount = { moved: 0, failed: 0 };

    for (const secretName of secretNames) {
      try {
        // Extraire le nom de base (sans le chemin)
        const baseName = secretName.split('/').pop();
        const newPath = targetFolder ? `${targetFolder}/${baseName}` : baseName;

        // Vérifier qu'on ne déplace pas vers le même endroit
        if (secretName === newPath) {
          continue;
        }

        // Lire le secret
        const secretData = await readSecretForMigration(selectedEngine, secretName);
        if (!secretData) {
          successCount.failed++;
          continue;
        }

        // Écrire au nouvel emplacement
        const writeSuccess = await writeSecretToEngine(selectedEngine, newPath, secretData);
        if (!writeSuccess) {
          successCount.failed++;
          continue;
        }

        // Supprimer l'ancien
        const deleteSuccess = await deleteSecretFromEngine(selectedEngine, secretName);
        if (deleteSuccess) {
          successCount.moved++;
        } else {
          successCount.failed++;
        }

      } catch (err) {
        secureLogger.error('[Déplacement] Erreur');
        successCount.failed++;
      }
    }

    // Rafraîchir les secrets
    await fetchSecrets(selectedEngine);
    clearSelection();

    // Afficher le résultat
    if (successCount.failed === 0) {
      showToast(t('toast.moveSuccess', { count: successCount.moved }), 'success');
    } else {
      showToast(`${successCount.moved} / ${successCount.failed}`, 'warning');
    }
  };

  /**
   * Lit un secret pour migration (retourne les données brutes)
   */
  const readSecretForMigration = async (engine, secretName) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      if (engine.version === 2) {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/data/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
        );
        return res.data?.data?.data || null;
      } else {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
        );
        return res.data?.data || null;
      }
    } catch (err) {
      secureLogger.error('[Lecture] Erreur');
      return null;
    }
  };

  /**
   * Écrit un secret dans un engine
   */
  const writeSecretToEngine = async (engine, secretName, data) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      if (engine.version === 2) {
        await axios.post(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/data/${encodeURIComponent(cleanKey)}`,
          { data },
          { headers: baseHeaders() }
        );
      } else {
        await axios.post(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          data,
          { headers: baseHeaders() }
        );
      }
      return true;
    } catch (err) {
      secureLogger.error('[Écriture] Erreur');
      return false;
    }
  };

  /**
   * Supprime un secret d'un engine
   */
  const deleteSecretFromEngine = async (engine, secretName) => {
    try {
      const cleanName = engine.name.replace(/^\/+|\/+$/g, '');
      const cleanKey = secretName.replace(/^\/+|\/+$/g, '');

      if (engine.version === 2) {
        await axios.delete(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/metadata/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
        );
      } else {
        await axios.delete(
          `${vaultUrl}/v1/${encodeEnginePath(cleanName)}/${encodeURIComponent(cleanKey)}`,
          { headers: baseHeaders() }
        );
      }
      return true;
    } catch (err) {
      secureLogger.error('[Suppression] Erreur');
      return false;
    }
  };

  const showToast = (message, type = 'info', duration = 2300) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ visible: true, type, message });
    toastTimer.current = setTimeout(() => setToast(t => ({ ...t, visible: false })), duration);
  };

  const toggleDarkMode = () => {
    setDarkMode(prev => !prev);
  };

  useEffect(() => {
    const theme = darkMode ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('rdvault-theme', theme);
  }, [darkMode]);

  // Fonctions pour le clipboard timer (logique simplifiée, le composant gère son propre countdown)
  const clearClipboardNow = async () => {
    if (clipboardTimerRef.current) {
      clearTimeout(clipboardTimerRef.current);
      clipboardTimerRef.current = null;
    }

    try {
      if (window.electronClipboard?.clearNow) {
        await window.electronClipboard.clearNow();
      }
    } catch (err) {}

    setClipboardTimer(null);
    showToast(t('toast.clipboardCleared'), 'info', 1500);
  };

  const handleClipboardExpire = () => {
    setClipboardTimer(null);
  };

  const startClipboardTimer = async (fieldName, text) => {
    if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);

    const duration = 12000;
    const startTime = Date.now();

    // Stocker startTime pour que le composant ClipboardTimer puisse calculer le temps restant de façon stable
    setClipboardTimer({ duration, fieldName, startTime });

    if (window.electronClipboard?.copySecure) {
      try {
        await window.electronClipboard.copySecure(text, duration);
      } catch (err) {
        await navigator.clipboard.writeText(text);
        // SÉCURITÉ: Auto-clear du fallback après la durée
        setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, duration);
      }
    } else {
      await navigator.clipboard.writeText(text);
      // SÉCURITÉ: Auto-clear du fallback après la durée
      setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, duration);
    }

    // Timer de secours pour fermer le composant si nécessaire
    clipboardTimerRef.current = setTimeout(() => {
      setClipboardTimer(null);
    }, duration + 500);
  };

  const baseHeaders = (overrideToken) => {
    const h = { 'X-Vault-Request': 'true' };
    const t = overrideToken || token;
    if (t) h['X-Vault-Token'] = t;
    if (vaultNs && vaultNs.trim()) h['X-Vault-Namespace'] = vaultNs.trim();
    return h;
  };

  // Configuration Axios pour toutes les requêtes
  // Note: Les certificats SSL auto-signés sont gérés par Electron via 'ignore-certificate-errors'
  const axiosConfig = (config = {}) => {
    return { ...config };
  };

  // SÉCURITÉ: Sanitise les messages d'erreur pour ne pas exposer les détails internes
  // SÉCURITÉ: Valider l'URL avant window.open (empêche javascript:, data:, vbscript:)
  const safeWindowOpen = (url) => {
    try {
      const parsed = new URL(url);
      if (['http:', 'https:', 'ftp:', 'ftps:'].includes(parsed.protocol)) {
        window.open(url, '_blank', 'noopener,noreferrer');
      }
    } catch { /* URL invalide, ignorer */ }
  };

  const sanitizeErrorMessage = (err, fallbackMsg = 'Une erreur est survenue') => {
    // Priorité 1 : status HTTP connu → message générique français
    const status = err?.response?.status;
    const genericMessages = {
      400: 'Requête invalide',
      401: 'Non authentifié',
      403: 'Accès refusé',
      404: 'Ressource introuvable',
      429: 'Trop de requêtes, réessayez plus tard',
      500: 'Erreur serveur',
      502: 'Service temporairement indisponible',
      503: 'Service temporairement indisponible'
    };
    if (status && genericMessages[status]) return genericMessages[status];
    if (err?.response?.status === 404) return 'Ressource introuvable';
    if (err?.response?.status >= 500) return 'Erreur serveur';
    // Priorité 3 : message réseau
    if (err?.code === 'ECONNREFUSED') return 'Connexion au serveur refusée';
    if (err?.code === 'ECONNABORTED' || err?.code === 'ETIMEDOUT') return 'Délai de connexion dépassé';
    // Fallback
    return fallbackMsg;
  };

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

  const parseFromSysMounts = (obj) =>
    Object.entries(obj || {})
      .filter(([mountPath, cfg]) => {
        const name = mountPath.replace(/\/$/, '').toLowerCase();
        return cfg && cfg.type === 'kv' && name !== 'totp' && name !== 'pki' && name !== 'tags-shared';
      })
      .map(([mountPath, cfg]) => ({
        name: mountPath.replace(/\/$/, ''),
        version: Number(cfg?.options?.version) === 2 ? 2 : 1,
        source: 'sys'
      }));

  const parseFromUiMounts = (payload) => {
    const data = payload?.data ?? payload ?? {};
    let items = [];

    if (Array.isArray(data.secrets)) items = data.secrets;
    else if (Array.isArray(data.secret)) items = data.secret;
    else if (data.mounts && typeof data.mounts === 'object') {
      items = Object.entries(data.mounts).map(([path, cfg]) => ({ path, ...(cfg || {}) }));
    } else if (typeof data === 'object' && Object.keys(data).every(k => typeof data[k] === 'object')) {
      items = Object.entries(data).map(([path, cfg]) => ({ path, ...(cfg || {}) }));
    }

    return (items || [])
      .filter(it => {
        if (!it) return false;
        const raw = (it.path || it.mount_path || it.name || '');
        const name = String(raw).replace(/\/$/, '').toLowerCase();
        if (name === 'totp' || name === 'pki' || name === 'tags-shared') return false;
        return it.type === 'kv' || it.options?.version || /\/$/.test(raw);
      })
      .map(it => {
        const raw = (it.path || it.mount_path || it.name || '');
        const name = String(raw).replace(/\/$/, '');
        const version = Number(it.options?.version) === 2 ? 2 : 1;
        return name ? { name, version, source: 'ui' } : null;
      })
      .filter(Boolean);
  };

  // ========================================
  // DÉTECTION VERSION KV (KEY-VALUE)
  // ========================================
  // HashiCorp Vault supporte deux versions du secret engine KV :
  // - KV v1 : Accès direct aux secrets via /{engine}/{key}
  // - KV v2 : Versioning, metadata, soft-delete via /{engine}/data/{key}
  //
  // Stratégie de détection :
  // 1. Essayer d'accéder à /metadata (KV v2 uniquement)
  // 2. Si 200 ou 403 → KV v2
  // 3. Sinon essayer /?list=true (KV v1)
  // 4. Par défaut, supposer KV v2 (plus récent)

  /**
   * Détecte la version du secret engine KV
   * @param {string} name - Nom du mount (ex: "secret", "users/john")
   * @param {string} tkn - Token Vault pour l'authentification
   * @returns {Promise<number>} 1 ou 2 selon la version détectée
   */
  const detectKvVersion = async (name, tkn) => {
    const clean = name.replace(/^\/+|\/+$/g, '');
    try {
      // Tentative KV v2 : l'endpoint /metadata n'existe qu'en v2
      const r2 = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}/metadata?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
      if ([200, 403].includes(r2.status)) return 2;
    } catch {}
    try {
      // Tentative KV v1 : liste directe à la racine
      const r1 = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
      if ([200, 403].includes(r1.status)) return 1;
    } catch {}
    // Par défaut, supposer KV v2 (version moderne)
    return 2;
  };

  /**
   * Vérifie les droits d'accès à un secret engine
   *
   * Détermine si l'utilisateur peut :
   * - accessible : Accéder au engine (au moins un droit)
   * - canList : Lister les secrets (LIST permission)
   * - canWrite : Créer/modifier des secrets (CREATE ou UPDATE)
   *
   * Utilise l'endpoint sys/capabilities-self pour vérifier les ACL Vault.
   *
   * @param {Object} engine - Objet {name, version} du engine
   * @param {string} tkn - Token Vault
   * @returns {Promise<{accessible: boolean, canList: boolean, canWrite: boolean}>}
   */
  const canAccessEngine = async ({ name, version }, tkn) => {
    const clean = name.replace(/^\/+|\/+$/g, '');
    let canList = false;
    let accessible = false;
    let canWrite = false;

    try {
      if (version === 2) {
        // KV v2 : vérifier via /metadata
        const r = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}/metadata?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
        accessible = true;
        canList = r.status === 200;
      } else {
        // KV v1 : vérifier via liste directe
        const r = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(clean)}?list=true`, axiosConfig({ headers: baseHeaders(tkn) }));
        accessible = true;
        canList = r.status === 200;
      }
    } catch (err) {
      if (err.response?.status === 403) {
        // 403 = pas de permission du tout
        return { accessible: false, canList: false, canWrite: false };
      }
      if (err.response?.status === 404) {
        // 404 = engine vide mais accessible
        accessible = true;
        canList = true;
      } else {
        return { accessible: false, canList: false, canWrite: false };
      }
    }

    // Tester les droits d'écriture avec sys/capabilities-self
    // Cette API retourne les capabilities effectives pour le token actuel
    try {
      const path = version === 2 ? `${clean}/data/*` : `${clean}/*`;
      const capRes = await axios.post(
        `${vaultUrl}/v1/sys/capabilities-self`,
        { paths: [path] },
        axiosConfig({ headers: baseHeaders(tkn) })
      );
      const caps = capRes.data?.data?.[path] || capRes.data?.[path] || [];
      canWrite = caps.includes('create') || caps.includes('update');
    } catch (err) {
      // En cas d'erreur, on suppose qu'on ne peut pas écrire (sécurité par défaut)
      canWrite = false;
    }

    return { accessible, canList, canWrite };
  };

  // ========================================
  // DÉCOUVERTE DES SECRET ENGINES
  // ========================================
  // Cette fonction utilise 3 endpoints Vault pour découvrir les engines :
  // 1. /sys/internal/ui/mounts?filter=secrets - UI-filtré (le plus précis)
  // 2. /sys/internal/ui/mounts - UI-compatible (tous les mounts visibles)
  // 3. /sys/mounts - System-level (tous les mounts, si l'utilisateur a les droits)
  //
  // Cette approche multi-source garantit qu'on découvre tous les engines
  // accessibles, même si certains endpoints échouent.

  /**
   * Récupère la liste des secret engines depuis Vault
   * Fusionne les résultats de plusieurs endpoints pour maximiser la découverte
   *
   * @param {string} userToken - Token Vault (défaut: token courant)
   * @returns {Promise<void>} Met à jour l'état secretEngines
   */
  const fetchEnginesLikeUi = async (userToken = token) => {
    setLoadingMounts(true);
    setLastError(''); setLastUiError('');
    try {
      // Appeler les 3 endpoints en parallèle (Promise.allSettled tolère les échecs)
      const [uiFilterRes, uiRes, sysRes] = await Promise.allSettled([
        axios.get(`${vaultUrl}/v1/sys/internal/ui/mounts?filter=secrets`, axiosConfig({ headers: baseHeaders(userToken) })),
        axios.get(`${vaultUrl}/v1/sys/internal/ui/mounts`, axiosConfig({ headers: baseHeaders(userToken) })),
        axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders(userToken) })),
      ]);

      if (uiRes.status === 'rejected') setLastUiError(uiRes.reason?.response?.data?.errors?.[0] || uiRes.reason?.message || 'ui/mounts échoué');
      if (sysRes.status === 'rejected') setLastError(sysRes.reason?.response?.data?.errors?.[0] || sysRes.reason?.message || 'sys/mounts échoué');

      const fromUiFilter = uiFilterRes.status === 'fulfilled' ? parseFromUiMounts(uiFilterRes.value.data) : [];
      const fromUi = uiRes.status === 'fulfilled' ? parseFromUiMounts(uiRes.value.data) : [];
      const fromSys = sysRes.status === 'fulfilled' ? parseFromSysMounts(sysRes.value.data) : [];

      const map = new Map();
      for (const e of [...fromUiFilter, ...fromUi, ...fromSys]) {
        if (!e?.name) continue;
        if (!map.has(e.name)) map.set(e.name, e);
      }
      const merged = Array.from(map.values());

      const prepared = [];
      for (const e of merged) {
        const version = e.version || await detectKvVersion(e.name, userToken);
        const access = await canAccessEngine({ name: e.name, version }, userToken);
        if (access.accessible) {
          prepared.push({
            name: e.name,
            version,
            source: e.source || 'auto',
            canList: access.canList,
            canWrite: access.canWrite
          });
        }
      }

      prepared.sort((a, b) => a.name.localeCompare(b.name));
      setSecretEngines(prepared);
      setSelectedEngine(prepared[0] || null);
      if (!prepared.length) setSecrets([]);
    } finally {
      setLoadingMounts(false);
    }
  };

  const MAX_LIST_DEPTH = 20;
  const MAX_LIST_KEYS = 5000;

  const listKeysV2 = async (engine, path = '', depth = 0) => {
    if (depth > MAX_LIST_DEPTH) return [];

    const url = path
      ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${path.split('/').map(s => encodeURIComponent(s)).join('/')}?list=true`
      : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata?list=true`;

    const list = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
    const keys = list.data?.data?.keys || [];

    const allKeys = [];

    for (const key of keys) {
      if (allKeys.length >= MAX_LIST_KEYS) break;
      if (key.endsWith('/')) {
        // C'est un dossier, lister récursivement
        const fullPath = path ? `${path}${key}` : key;
        try {
          const subKeys = await listKeysV2(engine, fullPath, depth + 1);
          allKeys.push(...subKeys);
        } catch (err) {
          secureLogger.warn('[Vault] Erreur listing dossier');
        }
      } else {
        // C'est un secret
        const fullKey = path ? `${path}${key}` : key;
        allKeys.push(fullKey);
      }
    }

    secureLogger.debug('[listKeysV2]', allKeys.length, 'keys');
    return allKeys;
  };

  // Fonction pour construire l'arborescence à partir de la liste plate de secrets
  const buildTree = (secretsList) => {
    const tree = { folders: {}, secrets: [] };

    secretsList.forEach(secret => {
      const parts = secret.name.split('/');

      if (parts.length === 1) {
        // Secret à la racine (masquer les .placeholder à la racine)
        if (secret.name !== '.placeholder') {
          tree.secrets.push(secret);
        }
      } else {
        // Secret dans un dossier
        let current = tree;
        for (let i = 0; i < parts.length - 1; i++) {
          const folderName = parts[i];
          if (!current.folders[folderName]) {
            current.folders[folderName] = { folders: {}, secrets: [] };
          }
          current = current.folders[folderName];
        }
        // Masquer les .placeholder de l'affichage
        const leafName = parts[parts.length - 1];
        if (leafName !== '.placeholder') {
          current.secrets.push({
            ...secret,
            displayName: leafName
          });
        }
      }
    });

    return tree;
  };

  // Calculer le contenu du dossier actuel (racine ou sous-dossier)
  const currentFolderContent = React.useMemo(() => {
    if (!treeViewEnabled) {
      // En vue liste, masquer les .placeholder
      return secrets.filter(s => !s.name.endsWith('/.placeholder') && s.name !== '.placeholder');
    }

    if (secrets.length === 0) {
      return [];
    }

    const tree = buildTree(secrets);

    // Si on est à la racine
    if (!currentPath) {
      const folders = Object.keys(tree.folders).map(name => ({
        name,
        displayName: name,
        isFolder: true
      }));
      return [...folders, ...tree.secrets];
    }

    // Naviguer dans le chemin
    const pathParts = currentPath.split('/');
    let current = tree;

    for (const part of pathParts) {
      if (current.folders[part]) {
        current = current.folders[part];
      } else {
        // Chemin invalide, retourner à la racine
        setCurrentPath('');
        const folders = Object.keys(tree.folders).map(name => ({
          name,
          displayName: name,
          isFolder: true
        }));
        return [...folders, ...tree.secrets];
      }
    }

    const folders = Object.keys(current.folders).map(name => ({
      name: currentPath ? `${currentPath}/${name}` : name,
      displayName: name,
      isFolder: true
    }));

    return [...folders, ...current.secrets];
  }, [secrets, treeViewEnabled, currentPath]);

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

  const readSecretV2 = async (engine, key) => {
    const res = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
    const data = res.data?.data?.data || {};

    // Extraire le Port depuis CustomFields si présent
    const customFields = data.CustomFields || [];
    const portField = customFields.find(f => f.key === 'Port' || f.key === 'port');

    return {
      name: key,
      username: data.Username || '',
      password: data.Password || '',
      url: data.URL || '',
      website: data.Website || '',
      notes: data.Notes || '',
      tags: data.Tags || '',
      Port: portField ? portField.value : '',  // Extraire depuis CustomFields
      customFields: customFields,
      attachments: data.Attachments || [],
      entryType: data.EntryType || 'secret'
    };
  };
  const writeSecretV2 = async (engine, entry) => {
    // ========================================
    // SÉCURITÉ: Validation de l'entrée avant écriture
    // ========================================
    const secretValidation = validation.validateSecret(entry);
    if (!secretValidation.valid) {
      const errorMessages = Object.values(secretValidation.errors).join(', ');
      throw new Error(`Validation échouée: ${errorMessages}`);
    }

    const data = {
      Username: entry.username,
      Password: entry.password,
      URL: entry.url,
      Website: entry.website,
      Notes: entry.notes,
      Tags: entry.tags || '',
      EntryType: entry.entryType || 'secret'
    };

    // Gérer les CustomFields avec le Port si présent
    let customFields = entry.customFields || [];

    // Si un Port est défini, l'ajouter/mettre à jour dans CustomFields
    if (entry.Port) {
      // Retirer l'ancien champ Port s'il existe
      customFields = customFields.filter(f => f.key !== 'Port' && f.key !== 'port');
      // Ajouter le nouveau
      customFields.push({ key: 'Port', value: entry.Port });
    }

    // N'ajouter CustomFields que s'ils ne sont pas vides
    if (customFields.length > 0) {
      data.CustomFields = customFields;
    }

    if (entry.attachments && entry.attachments.length > 0) {
      data.Attachments = entry.attachments;
    }

    await axios.post(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(entry.name)}`, { data }, axiosConfig({ headers: baseHeaders() }));
  };
  const deleteSecretV2 = async (engine, key) => {
    const metaRes = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
    const versions = Object.keys(metaRes.data?.data?.versions || {}).map(Number);

    if (versions.length > 0) {
      await axios.post(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/delete/${encodeURIComponent(key)}`, { versions }, axiosConfig({ headers: baseHeaders() }));
    }
  };

  const listKeysV1 = async (engine) => {
    const list = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}?list=true`, axiosConfig({ headers: baseHeaders() }));
    return (list.data?.data?.keys || []).filter(k => !k.endsWith('/'));
  };
  const readSecretV1 = async (engine, key) => {
    const res = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
    const data = res.data?.data || {};

    // Extraire le Port depuis CustomFields si présent
    const customFields = data.CustomFields || [];
    const portField = customFields.find(f => f.key === 'Port' || f.key === 'port');

    return {
      name: key,
      username: data.Username || '',
      password: data.Password || '',
      url: data.URL || '',
      website: data.Website || '',
      notes: data.Notes || '',
      tags: data.Tags || '',
      Port: portField ? portField.value : '',  // Extraire depuis CustomFields
      customFields: customFields,
      attachments: data.Attachments || [],
      entryType: data.EntryType || 'secret'
    };
  };
  const writeSecretV1 = async (engine, entry) => {
    // ========================================
    // SÉCURITÉ: Validation de l'entrée avant écriture
    // ========================================
    const secretValidation = validation.validateSecret(entry);
    if (!secretValidation.valid) {
      const errorMessages = Object.values(secretValidation.errors).join(', ');
      throw new Error(`Validation échouée: ${errorMessages}`);
    }

    const data = {
      Username: entry.username,
      Password: entry.password,
      URL: entry.url,
      Website: entry.website,
      Notes: entry.notes,
      Tags: entry.tags || '',
      EntryType: entry.entryType || 'secret'
    };

    // Gérer les CustomFields avec le Port si présent
    let customFields = entry.customFields || [];

    // Si un Port est défini, l'ajouter/mettre à jour dans CustomFields
    if (entry.Port) {
      // Retirer l'ancien champ Port s'il existe
      customFields = customFields.filter(f => f.key !== 'Port' && f.key !== 'port');
      // Ajouter le nouveau
      customFields.push({ key: 'Port', value: entry.Port });
    }

    // N'ajouter CustomFields que s'ils ne sont pas vides
    if (customFields.length > 0) {
      data.CustomFields = customFields;
    }

    if (entry.attachments && entry.attachments.length > 0) {
      data.Attachments = entry.attachments;
    }

    await axios.post(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(entry.name)}`, data, axiosConfig({ headers: baseHeaders() }));
  };
  const deleteSecretV1 = async (engine, key) => {
    await axios.delete(`${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
  };

  // Extraire tous les tags uniques depuis une liste de secrets
  const extractTagsFromSecrets = (secretsList) => {
    const allTags = new Set();
    secretsList.forEach(secret => {
      if (secret.tags && typeof secret.tags === 'string') {
        // Parser les tags (séparés par espaces, virgules ou points-virgules)
        const tags = secret.tags.split(/[\s,;]+/).filter(t => t.trim());
        tags.forEach(tag => allTags.add(tag.trim()));
      }
    });
    return Array.from(allTags).sort();
  };

  // Charger les tags partagés depuis le coffre tags-shared
  const loadSharedTags = async () => {
    try {
      const sharedTags = await tagManager.getSharedTags(vaultUrl, baseHeaders(), axiosConfig, axios);
      return sharedTags;
    } catch (err) {
      secureLogger.warn('[TAGS] Impossible de charger les tags partagés');
      return [];
    }
  };

  // Fusionner les tags découverts et les tags partagés
  const mergeDiscoveredAndSharedTags = async (secretsList) => {
    const discoveredFromSecrets = extractTagsFromSecrets(secretsList);
    const sharedFromVault = await loadSharedTags();

    // Fusionner et dédupliquer
    const allTags = new Set([...discoveredFromSecrets, ...sharedFromVault]);
    return Array.from(allTags).sort();
  };

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

  const getTotpKeyName = (secretName) => {
    if (!selectedEngine) return secretName;
    const engineName = selectedEngine.name
      .replace(/^users\/[^/]+\//i, '')
      .replace(/\/$/, '')
      .toUpperCase();
    return `${engineName}-${secretName}`;
  };

  // Fonction pour générer une couleur unique et cohérente pour chaque tag
  const getTagColor = (tag) => {
    const colors = [
      '#3b82f6', // blue
      '#10b981', // green
      '#f59e0b', // amber
      '#ef4444', // red
      '#8b5cf6', // violet
      '#ec4899', // pink
      '#06b6d4', // cyan
      '#f97316', // orange
      '#84cc16', // lime
      '#6366f1', // indigo
      '#14b8a6', // teal
      '#f43f5e', // rose
      '#a855f7', // purple
      '#22c55e', // green-500
      '#eab308', // yellow
      '#0ea5e9', // sky
      '#d946ef', // fuchsia
      '#fb923c', // orange-400
      '#4ade80', // green-400
      '#facc15'  // yellow-400
    ];

    // Hash simple basé sur tous les caractères du tag
    let hash = 0;
    for (let i = 0; i < tag.length; i++) {
      hash = ((hash << 5) - hash) + tag.charCodeAt(i);
      hash = hash & hash; // Convert to 32bit integer
    }

    return colors[Math.abs(hash) % colors.length];
  };

  const getTotpCode = async (keyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/${totpEngineName}/code/${encodeURIComponent(keyName)}`, axiosConfig({ headers: baseHeaders() }));
      return res.data?.data?.code || null;
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      throw new Error(msg);
    }
  };

  const configureTotpKey = async (keyName, config) => {
    try {
      await axios.post(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(keyName)}`, config, axiosConfig({ headers: baseHeaders() }));
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      throw new Error(msg);
    }
  };

  const checkTotpExists = async (keyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(keyName)}`, axiosConfig({ headers: baseHeaders() }));
      return res.status === 200;
    } catch (err) {
      if (err.response?.status === 404) return false;
      return false;
    }
  };

  const handleShowTotp = async (secret) => {
    if (!totpRateLimit.canCall()) { showToast(t('error.totpRateLimit'), 'error'); return; }
    totpRateLimit.registerCall();
    try {
      const totpKeyName = getTotpKeyName(secret.name);
      const code = await getTotpCode(totpKeyName);
      setTotpDisplay({ secretName: secret.name, totpKeyName, code });
    } catch (err) {
      showToast(`${t('error.totpConfig')} ${sanitizeErrorMessage(err)}`, 'error');
    }
  };

  const handleCopyTotp = async (secret) => {
    if (!totpRateLimit.canCall()) { showToast(t('error.totpRateLimit'), 'error'); return; }
    totpRateLimit.registerCall();
    try {
      const totpKeyName = getTotpKeyName(secret.name);
      const code = await getTotpCode(totpKeyName);
      await startClipboardTimer('Code TOTP', code);
    } catch (err) {
      showToast(`${t('error.totpConfig')} ${sanitizeErrorMessage(err)}`, 'error');
    }
  };

  const handleConfigureTotp = async (secret) => {
    const totpKeyName = getTotpKeyName(secret.name);
    const exists = await checkTotpExists(totpKeyName);

    if (exists) {
      showToast(t('error.totpAlreadyExists', { name: secret.name }), 'error', 2500);
      return;
    }

    const engineName = selectedEngine?.name
      ? selectedEngine.name
          .replace(/^users\/[^/]+\//i, '')
          .replace(/\/$/, '')
          .toUpperCase()
      : '';

    setTotpConfig({
      ...secret,
      totpKeyName,
      engineName
    });
  };

  const handleDeleteTotp = async (secret) => {
    const totpKeyName = getTotpKeyName(secret.name);
    try {
      await axios.delete(`${vaultUrl}/v1/${totpEngineName}/keys/${encodeURIComponent(totpKeyName)}`, axiosConfig({ headers: baseHeaders() }));
      showToast(t('toast.totpDeleted', { name: secret.name }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.totpDelete')} ${msg}`, 'error');
    }
  };

  const handleSaveTotpConfig = async (config) => {
    try {
      if (!totpConfig) return;
      await configureTotpKey(totpConfig.totpKeyName, config);
      setTotpConfig(null);
      restoreFocus();
      showToast(t('toast.totpConfigured', { name: totpConfig.totpKeyName }), 'success');
    } catch (err) {
      showToast(`${t('error.totpConfig')} ${sanitizeErrorMessage(err)}`, 'error');
      throw err;
    }
  };

  // ========================================
  // GESTION DES TAGS
  // ========================================
  // Les tags sont maintenant découverts automatiquement depuis les secrets
  // Pas besoin de fonctions add/remove/refresh

  // ========================================
  // GESTION DES COLONNES
  // ========================================

  const toggleColumn = (columnKey) => {
    const newVisibleColumns = {
      ...visibleColumns,
      [columnKey]: !visibleColumns[columnKey]
    };
    setVisibleColumns(newVisibleColumns);
    localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
  };

  const saveColumnWidths = (newWidths) => {
    setColumnWidths(newWidths);
    localStorage.setItem('rdvault-column-widths', JSON.stringify(newWidths));
  };

  // Redimensionnement des colonnes
  const handleColumnResizeStart = (e, columnKey, currentWidth) => {
    e.preventDefault();
    e.stopPropagation();
    setResizingColumn(columnKey);
    resizeStartX.current = e.clientX;
    resizeStartWidth.current = currentWidth || 150; // Largeur par défaut si non définie
  };

  const handleColumnResizeMove = (e) => {
    if (!resizingColumn) return;
    const diff = e.clientX - resizeStartX.current;

    // Calculer la nouvelle largeur avec contraintes
    const minWidth = 80; // Minimum 80px pour lisibilité
    const maxWidth = 600; // Maximum 600px pour éviter d'écraser les autres colonnes

    const newWidth = Math.max(minWidth, Math.min(maxWidth, resizeStartWidth.current + diff));

    saveColumnWidths({
      ...columnWidths,
      [resizingColumn]: newWidth
    });
  };

  const handleColumnResizeEnd = () => {
    setResizingColumn(null);
  };

  // Auto-ajustement de la colonne (fit to content)
  const handleColumnAutoFit = (e, columnKey) => {
    e.preventDefault();
    e.stopPropagation();

    // Créer un élément temporaire pour mesurer le texte
    const measureElement = document.createElement('span');
    measureElement.style.visibility = 'hidden';
    measureElement.style.position = 'absolute';
    measureElement.style.whiteSpace = 'nowrap';
    measureElement.style.font = 'var(--text-base) var(--font-body)';
    measureElement.style.fontWeight = 'var(--weight-normal)';
    document.body.appendChild(measureElement);

    let maxWidth = 100; // Largeur minimale

    // Mesurer le header
    const headerText = columnKey.charAt(0).toUpperCase() + columnKey.slice(1);
    measureElement.textContent = headerText.toUpperCase();
    measureElement.style.fontSize = 'var(--text-xs)';
    measureElement.style.fontWeight = 'var(--weight-bold)';
    measureElement.style.letterSpacing = '0.08em';
    maxWidth = Math.max(maxWidth, measureElement.offsetWidth);

    // Mesurer un échantillon des cellules (max 100 entrées pour performance)
    measureElement.style.fontSize = 'var(--text-base)';
    measureElement.style.fontWeight = 'var(--weight-normal)';
    measureElement.style.letterSpacing = 'normal';

    const dataSource = multiVaultSearch && search.trim() ? allVaultSecrets : secrets;
    const sampleSize = Math.min(100, dataSource.length);
    const step = Math.max(1, Math.floor(dataSource.length / sampleSize));

    for (let i = 0; i < dataSource.length; i += step) {
      const secret = dataSource[i];
      let content = '';

      if (columnKey === 'name') {
        content = treeViewEnabled && secret.displayName ? secret.displayName : secret.name;
      } else if (columnKey === 'username') {
        content = secret.username || '';
      } else if (columnKey === 'password') {
        content = secret.password || '';
      } else if (columnKey === 'url') {
        content = secret.url || '';
      } else if (columnKey === 'notes') {
        content = secret.notes ? secret.notes.substring(0, 50) : '';
      } else if (columnKey === 'tags') {
        content = secret.tags || '';
      } else if (columnKey === 'customFields') {
        content = secret.customFields ? secret.customFields.map(f => `${f.key}: ${f.protected ? '••••' : f.value}`).join(', ') : '';
      } else if (columnKey === 'engine') {
        content = secret.engineName || selectedEngine?.name || '';
      }

      measureElement.textContent = content;
      maxWidth = Math.max(maxWidth, measureElement.offsetWidth);
    }

    document.body.removeChild(measureElement);

    // Ajouter du padding (environ 40px de chaque côté + icônes)
    const newWidth = Math.min(600, Math.max(100, maxWidth + 80));

    saveColumnWidths({
      ...columnWidths,
      [columnKey]: newWidth
    });

    showToast(t('toast.copied'), 'success', 1500);
  };

  useEffect(() => {
    if (resizingColumn) {
      document.addEventListener('mousemove', handleColumnResizeMove);
      document.addEventListener('mouseup', handleColumnResizeEnd);
      return () => {
        document.removeEventListener('mousemove', handleColumnResizeMove);
        document.removeEventListener('mouseup', handleColumnResizeEnd);
      };
    }
  }, [resizingColumn, columnWidths]);

  useEffect(() => {
    if (selectedEngine && token) fetchSecrets(selectedEngine, showDeleted);
  }, [selectedEngine, token, showDeleted]);

  // Fonction de synchronisation des secrets avec l'extension Chrome
  const syncAllSecretsToExtension = async () => {
    if (!token || secretEngines.length === 0) return;

    try {
      // Charger tous les secrets de tous les coffres
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
                name: secret.name,
                username: secret.username,
                password: secret.password,
                url: secret.url,
                website: secret.website,
                notes: secret.notes,
                engine: engine.name  // Utilisé par l'extension pour construire le nom de clé TOTP
              };
            } catch (err) {
              return null;
            }
          });

          const secrets = await Promise.all(secretPromises);
          return secrets.filter(s => s !== null);
        } catch (err) {
          secureLogger.warn('[Vault] Erreur chargement coffre');
          return [];
        }
      });

      const allEngineSecrets = await Promise.all(enginePromises);
      const allSecrets = allEngineSecrets.flat();

      // Synchroniser avec l'extension (SÉCURITÉ: ne PAS inclure le token Vault)
      if (window.electronSync?.writeState) {
        const username = localStorage.getItem('vault-client.username') || authUser;
        await window.electronSync.writeState({
          vaultUrl,
          username,
          connected: true,
          secrets: allSecrets
        });
        secureLogger.debug('[Sync] Extension synchronisée');
      }
    } catch (err) {
      secureLogger.error('[Sync] Erreur extension');
    }
  };

  // Stocker la fonction de sync dans une ref pour pouvoir l'appeler manuellement
  useEffect(() => {
    syncExtensionRef.current = syncAllSecretsToExtension;
  });

  // Synchroniser automatiquement au démarrage et quand les coffres changent
  useEffect(() => {
    syncAllSecretsToExtension();
  }, [secretEngines, token, vaultUrl, authUser]);

  useEffect(() => {
    const closeMenu = () => {
      setContextMenu(null);
      setColumnContextMenu(null);
      setTagContextMenu(null);
      setTagCreateMode(false);
      setTagCreateValue('#');
      setEngineContextMenu(null);
      setFolderContextMenu(null);
    };
    document.addEventListener('click', closeMenu);
    return () => document.removeEventListener('click', closeMenu);
  }, []);

  // Gestionnaire IPC pour les demandes de code TOTP de l'extension Chrome
  useEffect(() => {
    if (!window.electronSync?.onTotpRequest || !token) return;

    const handleTotpRequest = async (totpKeyName, requestId) => {
      secureLogger.debug('[TOTP IPC] Demande de code TOTP');

      if (!totpRateLimit.canCall()) {
        window.electronSync.sendTotpResponse({ success: false, error: 'Rate limit exceeded' }, requestId);
        return;
      }
      totpRateLimit.registerCall();

      try {
        // Récupérer le code TOTP depuis Vault
        const response = await axios.get(
          `${vaultUrl}/v1/TOTP/code/${encodeURIComponent(totpKeyName)}`,
          axiosConfig({ headers: baseHeaders() })
        );

        const code = response.data?.data?.code;

        if (code) {
          secureLogger.debug('[TOTP IPC] Code TOTP généré');
          window.electronSync.sendTotpResponse({ success: true, code }, requestId);
        } else {
          secureLogger.debug('[TOTP IPC] Pas de code dans la réponse');
          window.electronSync.sendTotpResponse({ success: false, error: 'No code in response' }, requestId);
        }
      } catch (err) {
        secureLogger.error('[TOTP IPC] Erreur génération code TOTP');
        window.electronSync.sendTotpResponse({
          success: false,
          error: sanitizeErrorMessage(err, 'TOTP generation failed')
        }, requestId);
      }
    };

    // Enregistrer le listener et récupérer la fonction de cleanup
    const removeListener = window.electronSync.onTotpRequest(handleTotpRequest);

    // Cleanup : supprimer le listener quand le composant se démonte ou que le token change
    return removeListener;
  }, [token]); // Seulement token, car vaultUrl ne change jamais

  // Restaurer les règles CLI au montage (appel actif, pas d'écoute passive)
  useEffect(() => {
    if (!window.electronCLI?.getSession) return;

    const restoreCLISettings = async () => {
      try {
        const session = await window.electronCLI.getSession();
        if (session) {
          localStorage.setItem('rdvault-cli-session', JSON.stringify(session));
        }
      } catch { /* ignore */ }

      // Restaurer les règles d'auto-approbation via IPC
      try {
        const saved = JSON.parse(localStorage.getItem('rdvault-cli-auto-approve') || '{}');
        const rules = Object.entries(saved)
          .filter(([, enabled]) => enabled)
          .map(([engine]) => `${engine.replace(/\/+$/, '')}/*`);
        if (rules.length > 0 && window.electronCLI?.setAutoApproveRules) {
          window.electronCLI.setAutoApproveRules(rules);
        }
      } catch { /* ignore */ }

      // Restaurer les engines autorisés pour le listing via IPC
      try {
        const savedList = JSON.parse(localStorage.getItem('rdvault-cli-list-approve') || '{}');
        const allowedEngines = Object.entries(savedList)
          .filter(([, enabled]) => enabled)
          .map(([engine]) => engine.replace(/\/+$/, ''));
        if (allowedEngines.length > 0 && window.electronCLI?.setListSecretsEngines) {
          window.electronCLI.setListSecretsEngines(allowedEngines);
        }
      } catch { /* ignore */ }
    };

    restoreCLISettings();
  }, []);

  // Gestionnaire IPC pour les demandes de secrets provenant de la CLI mvault
  useEffect(() => {
    if (!window.electronCLI?.onSecretRequest || !token) return;

    const handleCLISecretRequest = async ({ engine: engineName, path: secretPath, requestId }) => {
      try {
        // Chercher l'engine par nom dans la liste des engines connus
        const engine = secretEngines.find(e =>
          e.name === engineName || e.name === engineName + '/' || e.name === '/' + engineName
        );

        if (!engine) {
          window.electronCLI.sendSecretResponse(
            { success: false, error: `Engine "${engineName}" introuvable` },
            requestId
          );
          return;
        }

        // Lire le secret via les fonctions Vault existantes
        const data = engine.version === 2
          ? await readSecretV2(engine, secretPath)
          : await readSecretV1(engine, secretPath);

        window.electronCLI.sendSecretResponse(
          { success: true, data },
          requestId
        );
      } catch (err) {
        window.electronCLI.sendSecretResponse(
          { success: false, error: err.response?.status === 404 ? 'Secret introuvable' : (err.message || 'Erreur lecture secret') },
          requestId
        );
      }
    };

    const removeListener = window.electronCLI.onSecretRequest(handleCLISecretRequest);

    // Écouter aussi les demandes de listage d'engines
    let removeEnginesListener;
    if (window.electronCLI.onEnginesRequest) {
      removeEnginesListener = window.electronCLI.onEnginesRequest(({ requestId }) => {
        const engines = secretEngines.map(e => ({
          name: e.name,
          version: e.version,
          type: e.type || 'kv'
        }));
        window.electronCLI.sendEnginesResponse(engines, requestId);
      });
    }

    return () => {
      removeListener();
      if (removeEnginesListener) removeEnginesListener();
    };
  }, [token, secretEngines]);

  // Gestionnaire IPC pour les demandes de listage de secrets provenant de la CLI mvault
  useEffect(() => {
    if (!window.electronCLI?.onListSecretsRequest || !token) return;

    const handleListSecretsRequest = async ({ engine: engineName, path: folderPath, requestId }) => {
      try {
        const engine = secretEngines.find(e =>
          e.name === engineName || e.name === engineName + '/' || e.name === '/' + engineName
        );

        if (!engine) {
          window.electronCLI.sendListSecretsResponse([], requestId);
          return;
        }

        const keys = engine.version === 2
          ? await listKeysV2(engine, folderPath)
          : await listKeysV1(engine);

        window.electronCLI.sendListSecretsResponse(keys, requestId);
      } catch {
        window.electronCLI.sendListSecretsResponse([], requestId);
      }
    };

    const removeListener = window.electronCLI.onListSecretsRequest(handleListSecretsRequest);
    return removeListener;
  }, [token, secretEngines]);

  // Ajuster la position du menu contextuel pour qu'il reste dans la fenêtre
  useEffect(() => {
    if (contextMenu && contextMenuRef.current) {
      const menu = contextMenuRef.current;
      const menuRect = menu.getBoundingClientRect();
      const windowWidth = window.innerWidth;
      const windowHeight = window.innerHeight;

      let newX = contextMenu.x;
      let newY = contextMenu.y;

      // Si le menu dépasse à droite, le repositionner à gauche du curseur
      if (menuRect.right > windowWidth) {
        newX = contextMenu.x - menuRect.width;
      }

      // Si le menu dépasse en bas, le repositionner au-dessus du curseur
      if (menuRect.bottom > windowHeight) {
        newY = contextMenu.y - menuRect.height;
      }

      // S'assurer que le menu ne dépasse pas à gauche ou en haut
      if (newX < 0) newX = 10;
      if (newY < 0) newY = 10;

      // Appliquer les nouvelles positions si différentes
      if (newX !== contextMenu.x || newY !== contextMenu.y) {
        menu.style.left = `${newX}px`;
        menu.style.top = `${newY}px`;
      }
    }
  }, [contextMenu]);

  // Ajuster la position du menu contextuel des tags pour qu'il reste dans la fenêtre
  useEffect(() => {
    if (tagContextMenu && tagContextMenuRef.current) {
      const menu = tagContextMenuRef.current;
      const menuRect = menu.getBoundingClientRect();
      const windowWidth = window.innerWidth;
      const windowHeight = window.innerHeight;

      let newX = tagContextMenu.x;
      let newY = tagContextMenu.y;

      // Si le menu dépasse à droite, le repositionner à gauche du curseur
      if (menuRect.right > windowWidth) {
        newX = tagContextMenu.x - menuRect.width;
      }

      // Si le menu dépasse en bas, le repositionner au-dessus du curseur
      if (menuRect.bottom > windowHeight) {
        newY = tagContextMenu.y - menuRect.height;
      }

      // S'assurer que le menu ne dépasse pas à gauche ou en haut
      if (newX < 0) newX = 10;
      if (newY < 0) newY = 10;

      // Appliquer les nouvelles positions si différentes
      if (newX !== tagContextMenu.x || newY !== tagContextMenu.y) {
        menu.style.left = `${newX}px`;
        menu.style.top = `${newY}px`;
      }
    }
  }, [tagContextMenu]);

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
        <div className={`sidebar ${sidebarOpen ? "open" : ""}`}>
          <div className="sidebar-header">
            <h2>{t('toolbar.vaultView')}</h2>
            <button
                onClick={() => setShowEngineModal(true)}
                className="btn btn-success btn-sm"
                title={t('toolbar.newEngine')}
                type="button"
                style={{ flexShrink: 0, whiteSpace: 'nowrap' }}
              >
                + {t('toolbar.newEngine')}
              </button>
          </div>

          <div className="sidebar-content">
            {secretEngines.map(engine => {
              const active = selectedEngine?.name === engine.name && selectedEngine?.version === engine.version;
              const currentUser = localStorage.getItem('vault-client.username') || '';
              const userPrefix = currentUser ? `users/${currentUser}/` : '';
              const canDelete = !userPrefix || engine.name.startsWith(userPrefix) || engine.name.startsWith(`users/${currentUser}`);

              // Extraire uniquement le nom du coffre pour les coffres personnels
              const isPersonalVault = engine.name.startsWith(userPrefix);
              const displayName = isPersonalVault
                ? engine.name.substring(userPrefix.length)
                : engine.name;

              // Déterminer si ce engine est la cible de drop actuelle
              const isDropTarget = isDragging && dragOverTarget === engine.name;
              // Permettre le drop sur tous les engines avec droits d'écriture
              // (même engine = déplacer à la racine, autre engine = migration)
              const canReceiveDrop = engine.canWrite;

              return (
                <div
                  key={`${engine.name}-${engine.version}-${engine.source || 'auto'}`}
                  className={`engine-card ${active ? 'active' : ''} ${isDropTarget ? 'drop-target' : ''}`}
                  onClick={() => {
                    setSelectedEngine(engine);
                    setSearch('');
                    setSearchInput('');
                    setVisiblePasswords({}); // SÉCURITÉ: Clear visible passwords on engine switch
                    setSidebarOpen(false);
                    // Fermer le panel admin si ouvert
                    if (currentView === 'admin') {
                      setCurrentView('vault');
                    }
                  }}
                  onContextMenu={(e) => handleEngineRightClick(e, engine)}
                  // Gestionnaires Drag & Drop
                  onDragOver={(e) => canReceiveDrop && handleDragOver(e, engine.name)}
                  onDragEnter={(e) => canReceiveDrop && handleDragOver(e, engine.name)}
                  onDragLeave={handleDragLeave}
                  onDrop={(e) => canReceiveDrop && handleDropOnEngine(e, engine)}
                  style={{
                    // Style visuel pour indiquer qu'on peut dropper
                    outline: isDropTarget ? '2px dashed var(--accent, #3b82f6)' : undefined,
                    background: isDropTarget ? 'var(--bg-selection, rgba(59, 130, 246, 0.15))' : undefined,
                    transform: isDropTarget ? 'scale(1.02)' : undefined,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <span className="engine-name">{displayName}</span>
                  <div className="engine-card-actions">
                    {isAdmin && <span className="badge badge-version">kv{engine.version}</span>}
                    {isAdmin && engine.source && <span className="badge badge-source">{engine.source}</span>}
                    {!canDelete && isAdmin && (
                      <span className="badge badge-shared">
                        Partagé
                      </span>
                    )}
                    {/* Indicateur de drop zone pendant le drag */}
                    {isDragging && canReceiveDrop && (
                      <span
                        className="badge"
                        style={{ background: 'var(--accent)', color: 'white' }}
                      >
                        {active ? '🏠' : '⬇️'}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
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
          <div className="main-header">
            <div className="login-container">
              <div className="login-card">
                <div className="login-header" style={{ WebkitAppRegion: 'drag' }}>
                  <button
                    className="login-close-btn"
                    onClick={() => window.electronWindow?.close()}
                    title={t('common.close')}
                    type="button"
                    style={{ WebkitAppRegion: 'no-drag' }}
                  >
                    <svg width="10" height="10" viewBox="0 0 10 10"><path stroke="currentColor" strokeWidth="1.2" d="M1,1 L9,9 M9,1 L1,9" /></svg>
                  </button>
                  <img src={process.env.PUBLIC_URL + '/logo.png'} alt="RDVAULT" style={{ height: '176px', width: 'auto', marginBottom: '-4px' }} />
                  <h2>{t('login.title')}</h2>
                  <p>{t('login.fieldsRequired')}</p>
                </div>

                <div className="login-form">
                  <div className="form-group-vertical">
                    <label className="form-label-vertical">{t('login.username')}</label>
                    <input
                      value={authUser}
                      onChange={e => setAuthUser(e.target.value)}
                      placeholder={t('login.placeholderUser')}
                      className="form-input-vertical"
                      onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                    />
                  </div>

                  <div className="form-group-vertical">
                    <label className="form-label-vertical">{t('login.password')}</label>
                    <input
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      placeholder={t('login.placeholderPass')}
                      type="password"
                      className="form-input-vertical"
                      onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                    />
                  </div>

                  <div className="form-group-vertical" style={{ marginBottom: 'var(--sp-4)' }}>
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={rememberMe}
                        onChange={(e) => setRememberMe(e.target.checked)}
                      />
                      <span>{t('login.rememberUser')}</span>
                    </label>
                  </div>

                  <button onClick={handleLogin} className="btn btn-primary btn-login" type="button">
                    <svg viewBox="0 0 24 24" fill="none" width="20" height="20">
                      <path d="M15 3H19C19.5304 3 20.0391 3.21071 20.4142 3.58579C20.7893 3.96086 21 4.46957 21 5V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M10 17L15 12L10 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M15 12H3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    {t('login.submit')}
                  </button>
                </div>
              </div>
            </div>
          </div>
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
            <div className="toolbar">
              {selectedEngine && !isCurrentEngineRbiOnly && (
                <button
                  onClick={() => {
                    // Si on est en mode arborescence et dans un dossier, pré-remplir le chemin
                    const initialName = treeViewEnabled && currentPath ? `${currentPath}/` : '';
                    setEditSecret({ name: initialName, username: '', password: '', url: '', notes: '' });
                  }}
                  className="btn btn-primary"
                  title={selectedEngine?.canWrite === false ? t('error.noReadAccess') : t('toolbar.newEntry')}
                  type="button"
                  disabled={selectedEngine?.canWrite === false}
                  style={{
                    cursor: selectedEngine?.canWrite === false ? 'not-allowed' : 'pointer',
                    opacity: selectedEngine?.canWrite === false ? 0.5 : 1,
                    flexShrink: 0
                  }}
                >
                  + {t('toolbar.newEntry')}
                </button>
              )}

              <input
                ref={searchRef}
                value={searchInput}
                onChange={(e) => { setSearchInput(e.target.value); debouncedSearch(e.target.value); }}
                placeholder={multiVaultSearch ? t('toolbar.searchAll') : t('toolbar.search')}
                className="search-input"
                style={{
                  flex: 1,
                  marginBottom: 0,
                  minWidth: '200px'
                }}
              />
              {loadingAllSecrets && (
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', flexShrink: 0 }}>
                  {t('common.loading')}
                </span>
              )}
              <label className="checkbox-label" style={{ marginBottom: 0, whiteSpace: 'nowrap', flexShrink: 0, opacity: !search.trim() ? 0.5 : 1 }}>
                <input
                  type="checkbox"
                  checked={multiVaultSearch}
                  disabled={loadingAllSecrets || !search.trim()}
                  onChange={(e) => { setMultiVaultSearch(e.target.checked); setVisiblePasswords({}); }}
                />
                <span>{t('toolbar.searchAll').split('...')[0]}</span>
              </label>
              {selectedEngine && selectedEngine.version === 2 && (
                <label className="checkbox-label" style={{ marginBottom: 0, flexShrink: 0 }}>
                  <input
                    type="checkbox"
                    checked={showDeleted}
                    onChange={(e) => setShowDeleted(e.target.checked)}
                  />
                  <span>{t('toolbar.showDeleted')}</span>
                </label>
              )}
              {appMode !== 'local' && (
              <button
                onClick={() => setReceiveShareOpen(true)}
                className="btn btn-secondary"
                type="button"
                title={t('toolbar.receiveShare')}
                style={{ flexShrink: 0, whiteSpace: 'nowrap' }}
              >
                {t('toolbar.receiveShare')}
              </button>
              )}
              {selectedEngine && (
                <>
                  {!multiVaultSearch && (
                    <button
                      onClick={() => {
                        const newValue = !treeViewEnabled;
                        setTreeViewEnabled(newValue);
                        localStorage.setItem('rdvault-tree-view-enabled', JSON.stringify(newValue));
                        if (!newValue) setCurrentPath('');
                      }}
                      style={{
                        padding: 'var(--sp-2) var(--sp-4)',
                        background: treeViewEnabled ? 'var(--accent)' : 'var(--bg-surface)',
                        color: treeViewEnabled ? 'white' : 'var(--text-primary)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-md)',
                        cursor: 'pointer',
                        fontSize: 'var(--text-sm)',
                        fontWeight: 'var(--weight-medium)',
                        transition: 'all 0.2s ease',
                        flexShrink: 0
                      }}
                    >
                      {treeViewEnabled ? `📄 ${t('toolbar.listView')}` : `📂 ${t('toolbar.treeView')}`}
                    </button>
                  )}
                </>
              )}
            </div>
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
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'name')}
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
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'username')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.password && (
                    <th className="resizable-header" style={{ width: columnWidths.password || 'auto' }}>
                      {t('table.password')}
                      <div
                        className={`column-resizer ${resizingColumn === 'password' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'password', columnWidths.password)}
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'password')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.url && (
                    <th className="resizable-header" style={{ width: columnWidths.url || 'auto' }}>
                      {t('table.url')}
                      <div
                        className={`column-resizer ${resizingColumn === 'url' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'url', columnWidths.url)}
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'url')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.notes && (
                    <th className="resizable-header" style={{ width: columnWidths.notes || 'auto' }}>
                      {t('table.notes')}
                      <div
                        className={`column-resizer ${resizingColumn === 'notes' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'notes', columnWidths.notes)}
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'notes')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.tags && (
                    <th className="resizable-header" style={{ width: columnWidths.tags || 'auto' }}>
                      {t('table.tags')}
                      <div
                        className={`column-resizer ${resizingColumn === 'tags' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'tags', columnWidths.tags)}
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'tags')}
                      />
                    </th>
                  )}
                  {effectiveVisibleColumns.customFields && (
                    <th className="resizable-header" style={{ width: columnWidths.customFields || 'auto' }}>
                      {t('table.customFields')}
                      <div
                        className={`column-resizer ${resizingColumn === 'customFields' ? 'resizing' : ''}`}
                        onMouseDown={(e) => handleColumnResizeStart(e, 'customFields', columnWidths.customFields)}
                        onDoubleClick={(e) => handleColumnAutoFit(e, 'customFields')}
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

                                // Détecter les différents types de liens
                                const urlLower = s.url.toLowerCase();
                                const isSsh = urlLower.startsWith('ssh://') || urlLower.includes(':22');
                                const isUncPath = s.url.startsWith('\\\\') || s.url.startsWith('//');
                                const isLocalPath = /^[a-zA-Z]:\\/.test(s.url); // C:\, D:\, L:\, etc.
                                const isWindowsPath = isUncPath || isLocalPath;

                                if (isWindowsPath) {
                                // Chemin Windows (réseau UNC ou disque local)
                                // SÉCURITÉ: Valider le format du chemin Windows
                                if (!/^(\\\\[^\\]+\\|\/\/[^/]+\/|[a-zA-Z]:\\)/.test(s.url)) {
                                  showToast(t('error.invalidPath'), 'error');
                                  return;
                                }
                                try {
                                  if (window.electronBrowser?.openExternalLink) {
                                    const result = await window.electronBrowser.openExternalLink(s.url);
                                    if (result.success) {
                                      showToast(t('toast.explorerOpened'), 'success', 1500);
                                    } else {
                                      showToast(result.error || t('error.explorerOpen'), 'error');
                                    }
                                  } else {
                                    showToast(t('error.explorerUnavailable'), 'error');
                                  }
                                } catch (err) {
                                  showToast(`${t('error.explorerOpen')} ${sanitizeErrorMessage(err)}`, 'error');
                                }
                              } else if (isSsh) {
                                // Connexion SSH avec PuTTY
                                try {
                                  // Parser l'URL SSH
                                  let host = s.url.replace(/^ssh:\/\//i, '');
                                  let port = '22';

                                  // Priorité 1 : Utiliser le champ personnalisé "Port" du secret
                                  if (s.Port || s.port) {
                                    port = String(s.Port || s.port);
                                    secureLogger.debug('[SSH] Port depuis champ personnalisé');
                                  } else {
                                    // Priorité 2 : Extraire le port de l'URL si présent (host:port)
                                    const portMatch = host.match(/:(\d+)$/);
                                    if (portMatch) {
                                      port = portMatch[1];
                                      host = host.replace(`:${port}`, '');
                                      secureLogger.debug('[SSH] Port depuis URL');
                                    } else {
                                      secureLogger.debug('[SSH] Port par défaut: 22');
                                    }
                                  }

                                  // Retirer le username de l'URL s'il est présent
                                  host = host.replace(/^[^@]+@/, '');

                                  // SÉCURITÉ: Valider le host SSH avant passage IPC
                                  if (!host || host.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(host)) {
                                    showToast(t('error.invalidSshHost'), 'error');
                                    return;
                                  }
                                  const portNum = parseInt(port, 10);
                                  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                                    showToast(t('error.invalidSshPort'), 'error');
                                    return;
                                  }

                                  secureLogger.debug('[SSH] Connexion lancée');

                                  if (window.electronBrowser?.openSshConnection) {
                                    const result = await window.electronBrowser.openSshConnection({
                                      host,
                                      username: s.username,
                                      port
                                    });

                                    if (result.success) {
                                      // Copier le mot de passe dans le presse-papiers avec timer
                                      if (s.password) {
                                        await startClipboardTimer('Password (SSH)', s.password);
                                      }
                                    } else {
                                      showToast(result.error || t('error.sshOpen'), 'error');
                                    }
                                  } else {
                                    showToast(t('error.sshUnavailable'), 'error');
                                  }
                                } catch (err) {
                                  showToast(`${t('error.sshOpen')} ${sanitizeErrorMessage(err)}`, 'error');
                                }
                              } else if (urlLower.startsWith('rdp:')) {
                                // Connexion RDP avec auto-remplissage
                                if (window.electronBrowser?.openRdpConnection) {
                                  try {
                                    // Parser l'URL RDP : rdp://host:port
                                    const rdpUrl = s.url.replace(/^rdp:\/\//i, '');
                                    const [hostPort] = rdpUrl.split('/');
                                    const [host, port] = hostPort.split(':');

                                    // SÉCURITÉ: Valider host et port parsés
                                    if (!host || host.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(host)) {
                                      showToast(t('error.invalidRdpHost'), 'error'); return;
                                    }
                                    const rdpPort = port || '3389';
                                    const rdpPortNum = parseInt(rdpPort, 10);
                                    if (isNaN(rdpPortNum) || rdpPortNum < 1 || rdpPortNum > 65535) {
                                      showToast(t('error.invalidRdpPort'), 'error'); return;
                                    }

                                    const result = await window.electronBrowser.openRdpConnection({
                                      host,
                                      username: s.username,
                                      password: s.password,
                                      port: rdpPort
                                    });

                                    if (result.success) {
                                      if (s.password) {
                                        await startClipboardTimer('Password (RDP)', s.password);
                                      }
                                    } else {
                                      showToast(result.error || t('error.rdpOpen'), 'error');
                                    }
                                  } catch (err) {
                                    showToast(`${t('error.rdpOpen')} ${sanitizeErrorMessage(err)}`, 'error');
                                  }
                                } else {
                                  showToast(t('error.rdpUnavailable'), 'error');
                                }
                              } else if (urlLower.startsWith('sftp:')) {
                                // Connexion SFTP avec FileZilla ou WinSCP
                                if (window.electronBrowser?.openSftpConnection) {
                                  try {
                                    // Parser l'URL SFTP : sftp://host:port
                                    const sftpUrl = s.url.replace(/^sftp:\/\//i, '');
                                    const [hostPort] = sftpUrl.split('/');
                                    const [host, port] = hostPort.split(':');

                                    // SÉCURITÉ: Valider host et port parsés
                                    if (!host || host.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(host)) {
                                      showToast(t('error.invalidSftpHost'), 'error'); return;
                                    }
                                    const sftpPort = port || '22';
                                    const sftpPortNum = parseInt(sftpPort, 10);
                                    if (isNaN(sftpPortNum) || sftpPortNum < 1 || sftpPortNum > 65535) {
                                      showToast(t('error.invalidSftpPort'), 'error'); return;
                                    }

                                    const result = await window.electronBrowser.openSftpConnection({
                                      host,
                                      username: s.username,
                                      password: s.password,
                                      port: sftpPort
                                    });

                                    if (result.success) {
                                      showToast(result.client === 'filezilla' ? t('toast.sftpFilezilla') : t('toast.sftpWinscp'), 'success', 3000);
                                    } else {
                                      showToast(result.error || t('error.sftpOpen'), 'error');
                                    }
                                  } catch (err) {
                                    showToast(`${t('error.sftpOpen')} ${sanitizeErrorMessage(err)}`, 'error');
                                  }
                                } else {
                                  showToast(t('error.sftpOpen'), 'error');
                                }
                              } else {
                                // Autres protocoles spéciaux (ftp://, telnet://, vnc:, etc.)
                                const otherProtocols = ['ftp:', 'telnet:', 'vnc:'];
                                const isOtherProtocol = otherProtocols.some(proto => urlLower.startsWith(proto));

                                if (isOtherProtocol) {
                                  // SÉCURITÉ: Valider l'URL avant ouverture
                                  try {
                                    const parsedProto = new URL(s.url);
                                    if (!['ftp:', 'telnet:', 'vnc:'].includes(parsedProto.protocol)) {
                                      showToast(t('error.protocolBlocked'), 'error'); return;
                                    }
                                  } catch { showToast(t('error.invalidUrl'), 'error'); return; }
                                  // Ouvrir avec l'application système par défaut
                                  if (window.electronBrowser?.openExternalLink) {
                                    await window.electronBrowser.openExternalLink(s.url);
                                  } else {
                                    safeWindowOpen(s.url);
                                  }
                                } else {
                                  // URLs HTTP/HTTPS classiques
                                  const url = buildSafeUrl(s.url);
                                  if (!url) { showToast(t('error.invalidUrl'), 'error'); return; }
                                  if (isSecretRbiOnly(s.name) && window.electronRBI?.launchSession) {
                                    // Mode RBI-Only : toujours ouvrir en session sécurisée
                                    // Récupérer le code TOTP si configuré
                                    let totpCode = null;
                                    try {
                                      const totpKey = getTotpKeyName(s.name);
                                      totpCode = await getTotpCode(totpKey);
                                      if (totpCode) {
                                        showToast(t('toast.totpRetrieved'), 'info', 2000);
                                      } else {
                                        showToast(t('toast.launchingRbiNoTotp'), 'info', 2000);
                                      }
                                    } catch (e) {
                                      showToast(t('toast.launchingRbi'), 'info', 3000);
                                    }
                                    const result = await window.electronRBI.launchSession({
                                      url,
                                      username: s.username,
                                      password: s.password,
                                      totp: totpCode,
                                      skipOverlay: false, // SÉCURITÉ: Overlay toujours actif (empêche la capture de credentials)
                                      policies: {
                                        disableClipboard: true,
                                        disableNewTabs: true,
                                        disableDownloads: false
                                      }
                                    });
                                    if (result.success) {
                                      showToast(t('toast.rbiOpened'), 'success', 3000);
                                    } else {
                                      showToast(result.error || t('error.rbiLaunch'), 'error');
                                    }
                                  } else if (window.electronBrowser?.openUrl) {
                                    await window.electronBrowser.openUrl(url, 'default');
                                  } else {
                                    safeWindowOpen(url);
                                  }
                                }
                              }
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
      {contextMenu && !(contextMenu.type === 'create' && (selectedEngine?.canWrite === false || isCurrentEngineRbiOnly)) && (
        <div
          ref={contextMenuRef}
          className="context-menu"
          style={{ top: contextMenu.y, left: contextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          {contextMenu.type === 'create' ? (
            <>
              <button
                onClick={() => {
                  // Si on est en mode arborescence et dans un dossier, pré-remplir le chemin
                  const initialName = treeViewEnabled && currentPath ? `${currentPath}/` : '';
                  setEditSecret({ name: initialName, username: '', password: '', url: '', notes: '' });
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
              >
                + {t('toolbar.newEntry')}
              </button>
              {treeViewEnabled && (
                <button
                  onClick={() => {
                    setShowCreateFolderModal(true);
                    setNewFolderName('');
                    setContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                >
                  📁 {t('editSecret.typeFolder')}
                </button>
              )}
            </>
          ) : (contextMenu.secret?.deleted) ? (
            /* Secret supprimé : seule l'option Récupérer est disponible */
            <button
              onClick={async () => {
                await undeleteSecret(contextMenu.secret);
                setContextMenu(null);
              }}
              className="context-menu-item"
              type="button"
              style={{ color: 'var(--success)' }}
            >
              ♻️ {t('contextMenu.restore')}
            </button>
          ) : (contextMenu.secret && isSecretRbiOnly(contextMenu.secret.name)) ? (
            /* Mode RBI-Only : seule l'option Session Sécurisée est disponible */
            <>
              {contextMenu.secret?.url && (contextMenu.secret.url.startsWith('http') || !contextMenu.secret.url.includes('://')) && !contextMenu.secret.url.toLowerCase().startsWith('ssh:') && !contextMenu.secret.url.toLowerCase().startsWith('rdp:') && !contextMenu.secret.url.toLowerCase().startsWith('sftp:') && (
                <button
                  onClick={async () => {
                    const url = buildSafeUrl(contextMenu.secret.url);
                    if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                    if (window.electronRBI?.launchSession) {
                      // Récupérer le code TOTP si configuré
                      let totpCode = null;
                      try {
                        const totpKey = getTotpKeyName(contextMenu.secret.name);
                        totpCode = await getTotpCode(totpKey);
                        if (totpCode) {
                          showToast(t('toast.totpRetrieved'), 'info', 2000);
                        } else {
                          showToast(t('toast.launchingRbiNoTotp'), 'info', 2000);
                        }
                      } catch (e) {
                        showToast(t('toast.launchingRbi'), 'info', 3000);
                      }
                      const result = await window.electronRBI.launchSession({
                        url,
                        username: contextMenu.secret.username,
                        password: contextMenu.secret.password,
                        totp: totpCode,
                        skipOverlay: false, // SÉCURITÉ: Overlay toujours actif (empêche la capture de credentials)
                        policies: {
                          disableClipboard: true,
                          disableNewTabs: true,
                          disableDownloads: false
                        }
                      });
                      if (result.success) {
                        showToast(t('toast.rbiOpened'), 'success', 3000);
                      } else {
                        showToast(result.error || t('error.rbiLaunch'), 'error');
                      }
                    } else {
                      showToast(t('error.rbiUnavailable'), 'error');
                    }
                    setContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                  style={{ fontWeight: 'bold', color: 'var(--success)' }}
                >
                  🔒 {t('contextMenu.openSecureBrowser')}
                </button>
              )}
            </>
          ) : (
            <>
              <button
                onClick={async () => {
                  // Pour le mot de passe, utiliser la valeur du secret directement
                  const copyValue = contextMenu.field === 'password'
                    ? contextMenu.secret?.password
                    : contextMenu.value;
                  if (copyValue) {
                    const fieldName =
                      contextMenu.field === 'name' ? t('table.name') :
                      contextMenu.field === 'username' ? t('table.username') :
                      contextMenu.field === 'password' ? t('table.password') :
                      contextMenu.field === 'url' ? t('table.url') :
                      contextMenu.field === 'notes' ? t('table.notes') : t('table.customFields');

                    // Utiliser le clipboard timer pour tous les champs (affiche le compte à rebours)
                    await startClipboardTimer(fieldName, copyValue);
                  }
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
                style={{
                  opacity: (contextMenu.field === 'password' ? contextMenu.secret?.password : contextMenu.value) ? 1 : 0.4,
                  cursor: (contextMenu.field === 'password' ? contextMenu.secret?.password : contextMenu.value) ? 'pointer' : 'default'
                }}
              >
                {t('toast.copied')}
              </button>

              <div className="context-menu-separator" />

              <button
                onClick={() => {
                  setEditSecret(contextMenu.secret);
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
              >
                ✏️ {t('contextMenu.edit')}
              </button>

              <button
                onClick={() => {
                  // Dupliquer : ouvrir la modale de création avec les données pré-remplies et un nom différent
                  const duplicated = {
                    ...contextMenu.secret,
                    name: `${contextMenu.secret.name}_copie`
                  };
                  setEditSecret(duplicated);
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
              >
                📋 {t('contextMenu.copyTo')}
              </button>

              <button
                onClick={() => {
                  confirmDeleteSecret(contextMenu.secret);
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
              >
                🗑️ {t('contextMenu.delete')}
              </button>

          {/* Session Sécurisée - disponible si le secret a une URL web */}
          {contextMenu.secret?.url && (contextMenu.secret.url.startsWith('http') || !contextMenu.secret.url.includes('://')) && !contextMenu.secret.url.toLowerCase().startsWith('ssh:') && !contextMenu.secret.url.toLowerCase().startsWith('rdp:') && !contextMenu.secret.url.toLowerCase().startsWith('sftp:') && (
            <>
              <div className="context-menu-separator" />
              <button
                onClick={async () => {
                  const url = buildSafeUrl(contextMenu.secret.url);
                  if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                  if (window.electronRBI?.launchSession) {
                    // Récupérer le code TOTP si configuré
                    let totpCode = null;
                    try {
                      const totpKey = getTotpKeyName(contextMenu.secret.name);
                      totpCode = await getTotpCode(totpKey);
                      if (totpCode) {
                        showToast(t('toast.totpRetrieved'), 'info', 2000);
                      } else {
                        showToast(t('toast.launchingRbiNoTotp'), 'info', 2000);
                      }
                    } catch (e) {
                      showToast(t('toast.launchingRbi'), 'info', 3000);
                    }
                    const result = await window.electronRBI.launchSession({
                      url,
                      username: contextMenu.secret.username,
                      password: contextMenu.secret.password,
                      totp: totpCode,
                      skipOverlay: false, // SÉCURITÉ: Overlay toujours actif (empêche la capture de credentials)
                      policies: {
                        disableClipboard: false,
                        disableNewTabs: true,
                        disableDownloads: false
                      }
                    });
                    if (result.success) {
                      showToast(t('toast.rbiAutoInject'), 'success', 3000);
                    } else {
                      showToast(result.error || t('error.rbiLaunch'), 'error');
                    }
                  } else {
                    showToast(t('error.rbiUnavailable'), 'error');
                  }
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
                style={{ fontWeight: 'bold', color: 'var(--success)' }}
              >
                🔒 {t('contextMenu.openSecureBrowser')}
              </button>
            </>
          )}

          {/* Partager en RBI - masqué en mode local */}
          {appMode !== 'local' && contextMenu.secret?.url && (contextMenu.secret.url.startsWith('http') || !contextMenu.secret.url.includes('://')) && !contextMenu.secret.url.toLowerCase().startsWith('ssh:') && !contextMenu.secret.url.toLowerCase().startsWith('rdp:') && !contextMenu.secret.url.toLowerCase().startsWith('sftp:') && (
            <>
              <button
                onClick={() => {
                  setShareRbiSecret(contextMenu.secret);
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
              >
                🔗 {t('contextMenu.shareRbi')}
              </button>
            </>
          )}

          {contextMenu.field === 'url' && contextMenu.value && (
            <>
              <div className="context-menu-separator" />
              <div className="context-menu-label">{t('contextMenu.openUrl')}</div>
              <button
                onClick={async () => {
                  const url = buildSafeUrl(contextMenu.value); if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                  if (window.electronBrowser?.openUrl) {
                    await window.electronBrowser.openUrl(url, 'default');
                  } else {
                    safeWindowOpen(url);
                  }
                  setContextMenu(null);
                }}
                className="context-menu-item"
                type="button"
              >
                🌐 Navigateur par défaut
              </button>
              {installedBrowsers.includes('chrome') && (
                <button
                  onClick={async () => {
                    const url = buildSafeUrl(contextMenu.value); if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                    if (window.electronBrowser?.openUrl) {
                      await window.electronBrowser.openUrl(url, 'chrome');
                    } else {
                      safeWindowOpen(url);
                    }
                    setContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                >
                  <span style={{ fontSize: '16px' }}>🔵</span> Google Chrome
                </button>
              )}
              {installedBrowsers.includes('firefox') && (
                <button
                  onClick={async () => {
                    const url = buildSafeUrl(contextMenu.value); if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                    if (window.electronBrowser?.openUrl) {
                      await window.electronBrowser.openUrl(url, 'firefox');
                    } else {
                      safeWindowOpen(url);
                    }
                    setContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                >
                  🦊 Mozilla Firefox
                </button>
              )}
              {installedBrowsers.includes('edge') && (
                <button
                  onClick={async () => {
                    const url = buildSafeUrl(contextMenu.value); if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                    if (window.electronBrowser?.openUrl) {
                      await window.electronBrowser.openUrl(url, 'edge');
                    } else {
                      safeWindowOpen(url);
                    }
                    setContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                >
                  <span style={{ fontSize: '16px' }}>🌊</span> Microsoft Edge
                </button>
              )}
              {installedBrowsers.includes('brave') && (
                <button
                  onClick={async () => {
                    const url = buildSafeUrl(contextMenu.value); if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
                    if (window.electronBrowser?.openUrl) {
                      await window.electronBrowser.openUrl(url, 'brave');
                    } else {
                      safeWindowOpen(url);
                    }
                    setContextMenu(null);
                  }}
                  className="context-menu-item"
                  type="button"
                >
                  🦁 Brave
                </button>
              )}
            </>
          )}

          <div className="context-menu-separator" />

          <div className="context-menu-label">{t('migrate.migrateTitle')}</div>
          <button
            onClick={() => {
              // Si le secret cliqué fait partie de la sélection, déplacer tous les sélectionnés
              const secretsToMove = selectedSecrets.has(contextMenu.secret.name)
                ? secrets.filter(s => selectedSecrets.has(s.name))
                : [contextMenu.secret];
              setMoveToFolder({ secrets: secretsToMove });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            📁 {t('contextMenu.moveToFolder')}...{selectedSecrets.has(contextMenu.secret.name) && selectedSecrets.size > 1 ? ` (${selectedSecrets.size})` : ''}
          </button>

          <div className="context-menu-label" style={{ fontSize: 'var(--text-xs)', opacity: 0.7 }}>{t('migrate.migrateTitle')}</div>
          <button
            onClick={() => {
              // Si le secret cliqué fait partie de la sélection, copier tous les sélectionnés
              const secretsToCopy = selectedSecrets.has(contextMenu.secret.name)
                ? secrets.filter(s => selectedSecrets.has(s.name))
                : [contextMenu.secret];
              setMigrateSecrets({ secrets: secretsToCopy, mode: 'copy' });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.copyTo')}...{selectedSecrets.has(contextMenu.secret.name) && selectedSecrets.size > 1 ? ` (${selectedSecrets.size})` : ''}
          </button>
          <button
            onClick={() => {
              // Si le secret cliqué fait partie de la sélection, migrer tous les sélectionnés
              const secretsToMigrate = selectedSecrets.has(contextMenu.secret.name)
                ? secrets.filter(s => selectedSecrets.has(s.name))
                : [contextMenu.secret];
              setMigrateSecrets({ secrets: secretsToMigrate, mode: 'move' });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.migrate')}...{selectedSecrets.has(contextMenu.secret.name) && selectedSecrets.size > 1 ? ` (${selectedSecrets.size})` : ''}
          </button>

          {selectedEngine?.version === 2 && (
            <button
              onClick={() => {
                setVersionHistory({ secretName: contextMenu.secret.name });
                setContextMenu(null);
              }}
              className="context-menu-item"
              type="button"
            >
              {t('contextMenu.history')}
            </button>
          )}

          <div className="context-menu-separator" />

          <div className="context-menu-label">{t('totp.title')}</div>
          <button
            onClick={async () => {
              await handleShowTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.showTotp')}
          </button>
          <button
            onClick={async () => {
              await handleCopyTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.copyField', { field: 'TOTP' })}
          </button>
          <button
            onClick={() => {
              if (!contextMenu.totpExists) {
                handleConfigureTotp(contextMenu.secret);
                setContextMenu(null);
              }
            }}
            disabled={contextMenu.totpExists}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.configurTotp')} {contextMenu.totpExists && `(${t('contextMenu.showTotp')})`}
          </button>
          {contextMenu.totpExists && (
            <button
              onClick={async () => {
                await handleDeleteTotp(contextMenu.secret);
                setContextMenu(null);
              }}
              className="context-menu-item danger"
              type="button"
            >
              {t('contextMenu.deleteTotp')}
            </button>
          )}
            </>
          )}
        </div>
      )}

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
