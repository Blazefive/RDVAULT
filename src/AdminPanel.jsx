// src/AdminPanel.jsx
import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import ConfirmModal from './ConfirmModal';
import EditEngineModal from './EditEngineModal';
import UserMenu from './UserMenu.jsx';
import WindowControls from './WindowControls.jsx';
import * as tagManager from './utils/tagManager';
import secureLogger from './secureLogger';
import { escapeCsvField } from './utils/csv';
import { encodeEnginePath, encodeSecretPath } from './utils/security';
import { readAllSecrets } from './utils/readAllSecrets';
import CreatePolicyModal from './components/admin/CreatePolicyModal';
import PolicyBuilderModal from './components/admin/PolicyBuilderModal';
import EnableAuditModal from './components/admin/EnableAuditModal';
import SshPasswordModal from './components/admin/SshPasswordModal';
import { policyGrantsMount } from './components/admin/policyHcl';
import { useTranslation } from './i18n';
import { richText, tPlural, formatDateTime, Ltr, richLtr } from './components/admin/i18nHelpers';
import useTabs from './components/admin/useTabs';

// Coffres système exclus des listings admin
const SYSTEM_MOUNTS = ['cubbyhole', 'identity', 'sys', 'tags-shared', 'totp', 'pki'];

export default function AdminPanel({ vaultUrl, vaultNs, ldapAuthPath = 'auth/ldap', token, baseHeaders, axiosConfig, vaultApi, showToast, username, darkMode, onToggleDarkMode, currentView, onToggleAdminView, onLogout, hiddenEngines = [], isAdmin, isModerator, moderatorEngines = [] }) {
  const { t, lang } = useTranslation();
  // Singulier / pluriel selon les règles de la langue courante (clés « …One » / « …Many »)
  const tp = (baseKey, count, vars) => tPlural(t, lang, baseKey, count, vars);
  // Modérateur non admin : consultation seule des objets système (coffres, policies,
  // liaisons de groupes AD). Sa policy Vault (générée par le builder, cf. DEPLOYMENT.md)
  // est en lecture seule sur ces chemins : y donner l'écriture équivaudrait à root
  // (réécrire sa propre policy ou s'ajouter au groupe admin). Les actions d'écriture
  // ne sont donc pas proposées, au lieu d'échouer systématiquement (403).
  const moderatorReadOnly = Boolean(isModerator && !isAdmin);
  const [activeTab, setActiveTab] = useState('mounts');
  const [policies, setPolicies] = useState([]);
  const [allMounts, setAllMounts] = useState([]);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [policyContent, setPolicyContent] = useState('');
  const [selectedMount, setSelectedMount] = useState(null);
  const [appliedPolicies, setAppliedPolicies] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingPolicies, setLoadingPolicies] = useState(false);

  // États pour les groupes AD
  const [adGroups, setAdGroups] = useState([]);
  const [policyGroups, setPolicyGroups] = useState({});
  const [loadingGroups, setLoadingGroups] = useState(false);

  // États pour la config LDAP
  const [ldapConfig, setLdapConfig] = useState(null);
  const [loadingLdap, setLoadingLdap] = useState(false);
  const [ldapGroupsCount, setLdapGroupsCount] = useState(0);

  // États pour l'audit
  const [auditDevices, setAuditDevices] = useState([]);
  const [selectedAuditDevice, setSelectedAuditDevice] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [loadingLogs, setLoadingLogs] = useState(false);
  // Demande de mot de passe SSH pour la lecture des logs distants ({ device, host, username })
  const [sshPasswordPrompt, setSshPasswordPrompt] = useState(null);

  // États pour les tags
  const [discoveredTags, setDiscoveredTags] = useState([]);
  const [sharedTags, setSharedTags] = useState([]);
  const [loadingTags, setLoadingTags] = useState(false);

  // États pour les modals
  const [confirmModal, setConfirmModal] = useState(null);
  const [showCreateMountModal, setShowCreateMountModal] = useState(false);
  const [showCreatePolicyModal, setShowCreatePolicyModal] = useState(false);
  const [showPolicyBuilderModal, setShowPolicyBuilderModal] = useState(false);
  const [showEnableAuditModal, setShowEnableAuditModal] = useState(false);
  const [editPolicyName, setEditPolicyName] = useState(null);

  // Menu contextuel pour les policies
  const [policyContextMenu, setPolicyContextMenu] = useState(null);
  const policyMenuRef = useRef(null);
  // Élément focalisé à l'ouverture du menu (focus rendu à la fermeture par Échap / Tab)
  const policyMenuOpenerRef = useRef(null);

  // Charger les policies
  const loadPolicies = async () => {
    try {
      setLoading(true);
      const res = await axios({
        method: 'LIST',
        url: `${vaultUrl}/v1/sys/policies/acl`,
        ...axiosConfig({ headers: baseHeaders() })
      });
      const policyNames = res.data?.data?.keys || res.data?.keys || [];
      // 🔒 Filtrer les policies système (default, root)
      let filteredPolicies = policyNames.filter(name => !['default', 'root'].includes(name));

      // 🔒 Filtrage pour les modérateurs : ne montrer que les policies qui référencent leurs engines autorisés
      // ET masquer les policies contenant des droits modérateur (leur propre policy)
      if (isModerator && moderatorEngines.length > 0) {
        const moderatorPolicies = [];

        for (const policyName of filteredPolicies) {
          try {
            const policyRes = await axios.get(
              `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`,
              axiosConfig({ headers: baseHeaders() })
            );
            const policyHcl = policyRes.data?.data?.policy || policyRes.data?.policy || '';

            // Masquer les policies contenant des droits MODERATOR
            if (policyHcl.includes('# KV v2 MODERATOR') || policyHcl.includes('# KV v1 MODERATOR')) {
              continue;
            }

            // Vérifier si la policy contient des références aux engines du modérateur
            const containsModeratorEngine = moderatorEngines.some(engineName => {
              return policyHcl.includes(`"${engineName}/`) || policyHcl.includes(`"${engineName}/*`);
            });

            if (containsModeratorEngine) {
              moderatorPolicies.push(policyName);
            }
          } catch (err) {
            secureLogger.debug('[Admin] Impossible de lire une policy');
          }
        }

        filteredPolicies = moderatorPolicies;
      }

      setPolicies(filteredPolicies);
    } catch (err) {
      showToast(t('admin.toast.loadPoliciesError'), 'error');
    } finally {
      setLoading(false);
    }
  };

  // Charger le contenu d'une policy
  const loadPolicyContent = async (policyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
      setPolicyContent(res.data?.data?.policy || res.data?.policy || '');
      setSelectedPolicy(policyName);
    } catch (err) {
      showToast(t('admin.toast.readPolicyError'), 'error');
    }
  };

  // Sauvegarder une policy
  // @returns {Promise<boolean>} true si la policy a été écrite dans Vault
  //
  // NOTE SÉCURITÉ : la validation ci-dessous côté client est de l'UX only
  // (message d'erreur immédiat, pas d'aller-retour serveur). La vraie barrière
  // est la policy Vault du modérateur elle-même (lecture seule sur
  // sys/policies/acl/*, sys/mounts/*, <ldap>/groups/*) : un client modifié ne
  // peut pas contourner Vault.
  const savePolicy = async (policyName, content) => {
    // 🔒 Restrictions modérateur (ne repose PAS sur les commentaires HCL) — validation client = UX only
    if (isModerator && content) {
      // 0) Vault accepte aussi les policies au format JSON, que les contrôles ci-dessous
      //    (syntaxe HCL) ne savent pas analyser : refusées pour un modérateur
      if (/^\s*[{[]/.test(content)) {
        showToast(t('admin.toast.policyForbiddenPaths'), 'error');
        return false;
      }
      // 1) Bloquer les capabilities dangereuses (sudo, deny)
      const capsRegex = /capabilities\s*=\s*\[([^\]]*)\]/gi;
      let capsMatch;
      while ((capsMatch = capsRegex.exec(content)) !== null) {
        const caps = capsMatch[1].toLowerCase();
        if (caps.includes('sudo') || caps.includes('deny')) {
          showToast(t('admin.toast.moderatorSudoDeny'), 'error');
          return false;
        }
      }
      // SÉCURITÉ: Bloquer aussi le keyword deprecated "policy" (alias de capabilities)
      const policyKeywordRegex = /policy\s*=\s*"([^"]+)"/gi;
      let policyKwMatch;
      while ((policyKwMatch = policyKeywordRegex.exec(content)) !== null) {
        const pol = policyKwMatch[1].toLowerCase();
        if (pol === 'sudo' || pol === 'write') {
          showToast(t('admin.toast.moderatorPolicyKeyword'), 'error');
          return false;
        }
      }

      // 2) Valider les chemins autorisés
      // SÉCURITÉ: Matcher les paths avec simple ET double quotes (HCL supporte les deux)
      const pathRegex = /path\s+["']([^"']+)["']/g;
      let match;
      while ((match = pathRegex.exec(content)) !== null) {
        const policyPath = match[1];
        // SÉCURITÉ: Rejeter les path traversal
        if (policyPath.includes('..') || policyPath.includes('//') || policyPath.startsWith('/')) {
          showToast(t('admin.toast.policyTraversal'), 'error');
          return false;
        }
        // Autoriser sys/mounts en lecture seule (listing), TOTP paths
        // SÉCURITÉ: Match exact pour éviter que sys/mounts/* permette mount/unmount
        if (policyPath === 'sys/mounts' || policyPath === 'sys/mounts/' || policyPath.startsWith('TOTP/')) continue;
        // Vérifier que le path est dans un engine autorisé
        const isAllowed = moderatorEngines.some(eng => policyPath.startsWith(eng + '/') || policyPath === eng + '/*');
        if (!isAllowed) {
          showToast(t('admin.toast.policyForbiddenPaths'), 'error');
          return false;
        }
      }
    }

    try {
      await axios.put(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, {
        policy: content
      }, axiosConfig({ headers: baseHeaders() }));
      showToast(t('admin.toast.policySaved', { name: policyName }), 'success');
      await loadPolicies();
      // Rafraîchir l'éditeur si la policy modifiée est celle affichée (ex. via le builder)
      if (selectedPolicy === policyName) {
        setPolicyContent(content);
      }
      return true;
    } catch (err) {
      showToast(t('admin.toast.savePolicyError'), 'error');
      return false;
    }
  };

  // Supprimer une policy
  const deletePolicy = async (policyName) => {
    // 🔒 Empêcher les modérateurs de supprimer leur propre policy modérateur
    if (isModerator) {
      try {
        const res = await axios.get(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
        const policyHcl = res.data?.data?.policy || res.data?.policy || '';

        if (policyHcl.includes('# KV v2 MODERATOR') || policyHcl.includes('# KV v1 MODERATOR')) {
          showToast(t('admin.toast.cannotDeleteModeratorPolicy'), 'error');
          return;
        }
      } catch (err) {
        showToast(t('admin.toast.checkPolicyError'), 'error');
        return;
      }
    }

    setConfirmModal({
      title: t('admin.confirm.deletePolicyTitle'),
      message: t('admin.confirm.deletePolicyMessage', { name: policyName }),
      danger: true,
      onConfirm: async () => {
        setConfirmModal(null);
        try {
          await axios.delete(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
          showToast(t('admin.toast.policyDeleted', { name: policyName }), 'success');
          setPolicyContent('');
          setSelectedPolicy(null);
          await loadPolicies();
        } catch (err) {
          showToast(t('admin.toast.deletePolicyError'), 'error');
        }
      },
      onCancel: () => setConfirmModal(null)
    });
  };

  // Charger les groupes AD disponibles
  // @returns {Promise<string[]>} la liste chargée (l'état React n'est pas encore
  // à jour au retour : les appelants doivent utiliser cette valeur)
  const loadAdGroups = async () => {
    try {
      setLoadingGroups(true);
      // Lister les groupes LDAP depuis Vault
      const res = await axios({
        method: 'LIST',
        url: `${vaultUrl}/v1/${ldapAuthPath}/groups`,
        ...axiosConfig({ headers: baseHeaders() })
      });
      const groups = res.data?.data?.keys || res.data?.keys || [];
      setAdGroups(groups);
      return groups;
    } catch (err) {
      showToast(t('admin.toast.loadAdGroupsError'), 'error');
      setAdGroups([]);
      return [];
    } finally {
      setLoadingGroups(false);
    }
  };

  // Charger tous les groupes liés aux policies
  // @param {string[]} [groups] - liste de groupes à utiliser (défaut : état adGroups)
  const loadAllPolicyGroups = async (groups = adGroups) => {
    try {
      const groupsMap = {};
      for (const group of groups) {
        const res = await axios.get(`${vaultUrl}/v1/${ldapAuthPath}/groups/${encodeURIComponent(group)}`, axiosConfig({ headers: baseHeaders() }));
        const groupPolicies = res.data?.data?.policies || [];
        groupPolicies.forEach(policy => {
          if (!groupsMap[policy]) {
            groupsMap[policy] = [];
          }
          groupsMap[policy].push(group);
        });
      }
      setPolicyGroups(groupsMap);
    } catch (err) {
      secureLogger.error('[Admin] Erreur chargement liens policies-groupes');
    }
  };

  // Lier/délier un groupe AD à une policy
  const toggleGroupForPolicy = async (groupName, policyName, add) => {
    try {
      // Récupérer les policies actuelles du groupe
      const res = await axios.get(`${vaultUrl}/v1/${ldapAuthPath}/groups/${encodeURIComponent(groupName)}`, axiosConfig({ headers: baseHeaders() }));
      let currentPolicies = res.data?.data?.policies || [];

      if (add) {
        // Ajouter la policy si elle n'est pas déjà présente
        if (!currentPolicies.includes(policyName)) {
          currentPolicies.push(policyName);
        }
      } else {
        // Retirer la policy
        currentPolicies = currentPolicies.filter(p => p !== policyName);
      }

      // Mettre à jour le groupe
      await axios.post(`${vaultUrl}/v1/${ldapAuthPath}/groups/${encodeURIComponent(groupName)}`, {
        policies: currentPolicies
      }, axiosConfig({ headers: baseHeaders() }));

      showToast(t(add ? 'admin.toast.groupLinked' : 'admin.toast.groupUnlinked', { group: groupName, policy: policyName }), 'success');
      await loadAllPolicyGroups();
    } catch (err) {
      showToast(t('admin.toast.groupLinkError'), 'error');
    }
  };

  // Charger la configuration LDAP depuis Vault
  const loadLdapConfig = async () => {
    try {
      setLoadingLdap(true);
      const res = await axios.get(`${vaultUrl}/v1/${ldapAuthPath}/config`, axiosConfig({ headers: baseHeaders() }));
      const config = res.data?.data || {};
      setLdapConfig(config);

      // Charger le nombre de groupes configurés
      const groupsRes = await axios({
        method: 'LIST',
        url: `${vaultUrl}/v1/${ldapAuthPath}/groups`,
        ...axiosConfig({ headers: baseHeaders() })
      });
      const groups = groupsRes.data?.data?.keys || groupsRes.data?.keys || [];
      setLdapGroupsCount(groups.length);
    } catch (err) {
      if (err.response?.status === 403) {
        showToast(t('admin.toast.ldapForbidden'), 'error');
      } else {
        showToast(t('admin.toast.ldapLoadError'), 'error');
      }
      setLdapConfig(null);
    } finally {
      setLoadingLdap(false);
    }
  };

  // Synchroniser les groupes LDAP (recharger depuis Vault)
  const syncLdapGroups = async () => {
    try {
      setLoadingGroups(true);
      // Utiliser la valeur retournée : l'état adGroups n'est pas encore mis à jour ici
      const groups = await loadAdGroups();
      await loadAllPolicyGroups(groups);

      // Mettre à jour le compteur
      setLdapGroupsCount(groups.length);

      showToast(t('admin.toast.groupsSynced', { count: groups.length }), 'success');
    } catch (err) {
      showToast(t('admin.toast.syncGroupsError'), 'error');
    } finally {
      setLoadingGroups(false);
    }
  };

  // Charger tous les mounts
  const loadAllMounts = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders() }));
      const mountsData = res.data?.data || res.data || {};
      let mountsList = Object.entries(mountsData)
        .map(([path, config]) => ({
          path: path.replace(/\/$/, ''),
          type: config.type,
          description: config.description,
          version: Number(config.options?.version) || 1
        }))
        // 🔒 Filtrer les coffres système (cubbyhole, identity, sys, tags-shared, totp, pki)
        .filter(mount => !SYSTEM_MOUNTS.includes(mount.path.toLowerCase()));

      // 🔒 Filtrage pour les modérateurs : ne montrer que leurs engines autorisés
      if (isModerator && moderatorEngines.length > 0) {
        mountsList = mountsList.filter(mount => moderatorEngines.includes(mount.path));
      }

      setAllMounts(mountsList);
    } catch (err) {
      secureLogger.error('[Admin] Erreur chargement mounts');
      showToast(t('admin.toast.loadMountsError'), 'error');
    } finally {
      setLoading(false);
    }
  };

  // Créer un nouveau mount/coffre
  const createMount = async ({ name, version, description }) => {
    const mountPath = name.replace(/^\/+|\/+$/g, '');
    // SÉCURITÉ: Vérifier que le modérateur crée dans son périmètre
    if (isModerator && !moderatorEngines.some(eng => mountPath === eng || mountPath.startsWith(eng + '/'))) {
      showToast(t('admin.toast.mountCreateOutOfScope'), 'error');
      return;
    }
    const body = {
      type: 'kv',
      description: description || undefined,
      options: { version: String(version) }
    };
    try {
      // Encodage segment par segment (les chemins de coffre peuvent contenir des /)
      await axios.post(`${vaultUrl}/v1/sys/mounts/${encodeEnginePath(mountPath)}`, body, axiosConfig({ headers: baseHeaders() }));
      showToast(t('admin.toast.mountCreated', { path: mountPath, version }), 'success');
      await loadAllMounts();

      // Sélectionner le nouveau mount
      const newMount = {
        path: mountPath,
        type: 'kv',
        description: description || '',
        version: Number(version)
      };
      setSelectedMount(newMount);
    } catch (err) {
      secureLogger.error('[Admin] Erreur création coffre');
      showToast(t('admin.toast.createMountError'), 'error');
      throw err;
    }
  };

  // Supprimer un mount
  const deleteMount = async (mountPath) => {
    // SÉCURITÉ: Vérifier que le modérateur supprime dans son périmètre
    if (isModerator && !moderatorEngines.some(eng => mountPath === eng || mountPath.startsWith(eng + '/'))) {
      showToast(t('admin.toast.mountDeleteOutOfScope'), 'error');
      return;
    }
    setConfirmModal({
      title: t('admin.confirm.deleteMountTitle'),
      message: t('admin.confirm.deleteMountMessage', { path: mountPath }),
      danger: true,
      onConfirm: async () => {
        setConfirmModal(null);
        try {
          // Désélectionner le mount avant suppression
          if (selectedMount?.path === mountPath) {
            setSelectedMount(null);
            setAppliedPolicies([]);
          }

          await axios.delete(`${vaultUrl}/v1/sys/mounts/${encodeEnginePath(mountPath)}`, axiosConfig({ headers: baseHeaders() }));
          showToast(t('admin.toast.mountDeleted', { path: mountPath }), 'success');
          await loadAllMounts();
        } catch (err) {
          showToast(t('admin.toast.deleteMountError'), 'error');
        }
      },
      onCancel: () => setConfirmModal(null)
    });
  };

  // Charger les policies disponibles pour associer à un mount
  const loadAllPoliciesForMount = async () => {
    try {
      const res = await axios({
        method: 'LIST',
        url: `${vaultUrl}/v1/sys/policies/acl`,
        ...axiosConfig({ headers: baseHeaders() })
      });
      return res.data?.data?.keys || res.data?.keys || [];
    } catch (err) {
      showToast(t('admin.toast.loadPoliciesError'), 'error');
      return [];
    }
  };

  // Vérifier si une policy est appliquée à un mount (en lisant son contenu)
  const checkPolicyForMount = async (policyName, mountPath) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
      const content = res.data?.data?.policy || res.data?.policy || '';

      // Toute règle (hors « deny ») touchant un chemin du coffre : coffre entier, secret
      // spécifique (X/data/<secret>), listing (X/metadata) ou glob englobant (« * »…)
      return policyGrantsMount(content, mountPath);
    } catch (err) {
      return false;
    }
  };

  // Charger les policies appliquées à un mount
  // (applyPolicyToMount, jamais appelée, a été supprimée : code mort)
  const loadAppliedPolicies = async (mountPath) => {
    const allPolicies = await loadAllPoliciesForMount();
    const appliedPolicies = [];

    for (const policy of allPolicies) {
      const isApplied = await checkPolicyForMount(policy, mountPath);
      if (isApplied) {
        appliedPolicies.push(policy);
      }
    }

    return { allPolicies, appliedPolicies };
  };

  // Helper CSV : escapeCsvField (utils/csv) avec le séparateur ';' de l'export admin,
  // sauts de ligne remplacés par des espaces (1 ligne = 1 secret) et
  // SÉCURITÉ : neutralisation des formules tableur (=, +, -, @, |, tab, CR).
  const csvField = (field) => escapeCsvField(field, { separator: ';', flattenNewlines: true });

  // Lister récursivement les clés d'un mount
  // SÉCURITÉ : chemin de coffre et préfixe encodés segment par segment avant interpolation URL
  const listKeysRecursive = async (mountPath, version, prefix = '') => {
    try {
      const url = version === 2
        ? `${vaultUrl}/v1/${encodeEnginePath(mountPath)}/metadata/${encodeSecretPath(prefix)}?list=true`
        : `${vaultUrl}/v1/${encodeEnginePath(mountPath)}/${encodeSecretPath(prefix)}?list=true`;
      const res = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
      const keys = res.data?.data?.keys || [];
      let allKeys = [];
      for (const key of keys) {
        if (key.endsWith('/')) {
          const subKeys = await listKeysRecursive(mountPath, version, prefix + key);
          allKeys = allKeys.concat(subKeys);
        } else {
          allKeys.push(prefix + key);
        }
      }
      return allKeys;
    } catch {
      return [];
    }
  };

  // Exporter tous les secrets d'un mount en CSV
  const exportMountToCsv = async (mount) => {
    try {
      showToast(t('admin.toast.exportInProgress'), 'info');
      const version = mount.version || 1;
      const keys = await listKeysRecursive(mount.path, version);

      if (keys.length === 0) {
        showToast(t('admin.toast.exportEmpty'), 'warning');
        return;
      }

      const rows = [];
      let failedReads = 0;
      for (const key of keys) {
        try {
          // SÉCURITÉ : chemin de coffre et clé encodés avant interpolation URL
          const secretRes = version === 2
            ? await axios.get(`${vaultUrl}/v1/${encodeEnginePath(mount.path)}/data/${encodeSecretPath(key)}`, axiosConfig({ headers: baseHeaders() }))
            : await axios.get(`${vaultUrl}/v1/${encodeEnginePath(mount.path)}/${encodeSecretPath(key)}`, axiosConfig({ headers: baseHeaders() }));
          const data = version === 2 ? (secretRes.data?.data?.data || {}) : (secretRes.data?.data || {});
          // Ignorer les dossiers et entrées non-secret
          if (data.EntryType === 'folder') continue;
          const customFields = data.CustomFields || [];
          const portField = customFields.find(f => f.key === 'Port' || f.key === 'port');
          const name = key.split('/').pop();
          const username = data.Username || '';
          const password = data.Password || '';
          const urlVal = data.URL || '';
          const website = data.Website || '';
          const notes = data.Notes || '';
          const tags = data.Tags || '';
          const port = portField ? portField.value : '';
          // Ignorer les entrées vides (aucun champ rempli)
          if (!username && !password && !urlVal && !website && !notes && !tags && !port) continue;
          rows.push([
            csvField(name),
            csvField(username),
            csvField(password),
            csvField(urlVal),
            csvField(website),
            csvField(notes),
            csvField(tags),
            csvField(port)
          ].join(';'));
        } catch {
          // Erreur de lecture individuelle : comptée et signalée (export partiel)
          failedReads++;
        }
      }

      const header = 'name;username;password;url;website;notes;tags;Port';
      const csv = header + '\n' + rows.join('\n');
      const bom = '\uFEFF';
      const blob = new Blob([bom + csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${mount.path}_export.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      if (failedReads > 0) {
        showToast(t('admin.toast.exportPartial', {
          exported: tp('admin.toast.secretsExported', rows.length),
          unreadable: tp('admin.toast.unreadable', failedReads)
        }), 'warning', 5000);
      } else {
        showToast(t('admin.toast.exportDone', { exported: tp('admin.toast.secretsExported', rows.length) }), 'success');
      }
    } catch (err) {
      showToast(t('admin.toast.exportError'), 'error');
    }
  };

  // Charger les audit devices
  const loadAuditDevices = async () => {
    try {
      setLoadingAudit(true);
      const res = await axios.get(`${vaultUrl}/v1/sys/audit`, axiosConfig({ headers: baseHeaders() }));
      const devicesData = res.data?.data || res.data || {};
      const devicesList = Object.entries(devicesData).map(([path, config]) => ({
        path: path.replace(/\/$/, ''),
        type: config.type,
        description: config.description,
        options: config.options
      }));
      setAuditDevices(devicesList);
    } catch (err) {
      if (err.response?.status === 403) {
        showToast(t('admin.toast.auditForbidden'), 'error');
      } else {
        showToast(t('admin.toast.auditLoadError'), 'error');
      }
    } finally {
      setLoadingAudit(false);
    }
  };

  // Activer un audit device
  const enableAuditDevice = async (path, type, description, options) => {
    try {
      // Construire le payload en n'incluant que les champs non vides
      const payload = { type };

      // N'ajouter description que si elle n'est pas vide
      if (description && description.trim()) {
        payload.description = description.trim();
      }

      // N'ajouter options que s'il contient des données
      if (options && Object.keys(options).length > 0) {
        payload.options = options;
      }

      await axios.put(`${vaultUrl}/v1/sys/audit/${encodeURIComponent(path)}`, payload, axiosConfig({ headers: baseHeaders() }));
      showToast(t('admin.toast.auditEnabled', { path }), 'success');
      await loadAuditDevices();
    } catch (err) {
      secureLogger.error('[Admin] Erreur activation audit device');
      showToast(t('admin.toast.auditEnableError'), 'error');
    }
  };

  // Désactiver un audit device
  const disableAuditDevice = async (path) => {
    setConfirmModal({
      title: t('admin.confirm.disableAuditTitle'),
      message: t('admin.confirm.disableAuditMessage', { path }),
      danger: true,
      onConfirm: async () => {
        setConfirmModal(null);
        try {
          await axios.delete(`${vaultUrl}/v1/sys/audit/${encodeURIComponent(path)}`, axiosConfig({ headers: baseHeaders() }));
          showToast(t('admin.toast.auditDisabled', { path }), 'success');

          // Désélectionner si c'est le device sélectionné
          if (selectedAuditDevice?.path === path) {
            setSelectedAuditDevice(null);
            setAuditLogs([]);
          }

          // Supprimer la configuration SSH associée
          try {
            localStorage.removeItem(`vault-audit-ssh-${path.replace(/[^a-zA-Z0-9._-]/g, '_')}`);
          } catch (err) {
            secureLogger.debug('[Admin] Erreur suppression config SSH locale');
          }

          await loadAuditDevices();
        } catch (err) {
          showToast(t('admin.toast.auditDisableError'), 'error');
        }
      },
      onCancel: () => setConfirmModal(null)
    });
  };

  // Charger les logs d'un audit device
  // Si une configuration SSH est associée au device, le mot de passe est demandé
  // via une modale (SshPasswordModal) — plus de window.prompt(), non supporté par
  // Electron — puis readAuditLogs() est appelée avec la config complète.
  const loadAuditLogs = async (device) => {
    secureLogger.debug('[Audit] loadAuditLogs');

    if (!device?.options?.file_path) {
      showToast(t('admin.toast.noFilePath'), 'error');
      return;
    }

    if (!window.electronAudit?.tailLogFile) {
      showToast(t('admin.toast.logReaderUnavailable'), 'error');
      return;
    }

    // Récupérer la configuration SSH si elle existe (sans mot de passe)
    // SÉCURITÉ: Appliquer la même sanitisation qu'à l'écriture (cohérence des clés)
    const safeDevicePath = device.path.replace(/[^a-zA-Z0-9._-]/g, '_');
    const sshConfigKey = `vault-audit-ssh-${safeDevicePath}`;
    let sshConfig = null;
    try {
      const storedConfig = localStorage.getItem(sshConfigKey);
      if (storedConfig) sshConfig = JSON.parse(storedConfig);
    } catch (err) {
      secureLogger.error('[Audit] Erreur lecture config SSH');
    }

    // 🔒 SÉCURITÉ : Demander le mot de passe SSH à chaque lecture (jamais stocké)
    if (sshConfig && sshConfig.host) {
      setSshPasswordPrompt({ device, sshConfig });
      return;
    }

    await readAuditLogs(device, null);
  };

  // Lecture effective des logs (fichier local ou distant via SSH)
  // @param {Object|null} sshConfig - { host, port, username, password } ou null
  const readAuditLogs = async (device, sshConfig) => {
    try {
      setLoadingLogs(true);

      const result = await window.electronAudit.tailLogFile(device.options.file_path, 100, sshConfig);

      if (result.success) {
        setAuditLogs(result.logs || []);
        if (result.totalLines > result.loadedLines) {
          showToast(t('admin.toast.logsPartial', { loaded: result.loadedLines, total: result.totalLines }), 'info');
        } else {
          showToast(t('admin.toast.logsLoaded', { count: result.loadedLines }), 'success');
        }
      } else {
        secureLogger.error('[Audit] Erreur lecture logs');
        // Erreur de clé d'hôte SSH (clé changée/refusée/inconnue, known_hosts non inscriptible) :
        // afficher le message explicite du main (empreinte attendue/observée) plutôt que le message générique
        const code = typeof result.code === 'string' ? result.code : '';
        const isHostKeyError = code.startsWith('HOST_KEY_') || code === 'KNOWN_HOSTS_WRITE';
        if (isHostKeyError && typeof result.error === 'string' && result.error) {
          showToast(result.error, 'error');
        } else {
          showToast(t('admin.toast.readLogsError'), 'error');
        }
        setAuditLogs([]);
      }
    } catch (err) {
      secureLogger.error('[Audit] Exception lecture logs');
      showToast(t('admin.toast.readLogsError'), 'error');
      setAuditLogs([]);
    } finally {
      setLoadingLogs(false);
    }
  };

  // Ouvrir le builder en mode édition
  const openBuilderForEdit = async (policyName) => {
    setEditPolicyName(policyName);
    setShowPolicyBuilderModal(true);
  };

  // Charger les données selon l'onglet actif
  useEffect(() => {
    if (activeTab === 'policies') {
      loadPolicies();
      loadAdGroups();
    } else if (activeTab === 'mounts') {
      loadAllMounts();
    } else if (activeTab === 'auth') {
      loadLdapConfig();
      loadAdGroups();
    } else if (activeTab === 'audit') {
      loadAuditDevices();
    } else if (activeTab === 'tags') {
      loadSharedTags();
    }
    // Chargement déclenché uniquement au changement d'onglet : les fonctions load* sont recréées
    // à chaque rendu, les ajouter relancerait les requêtes Vault en boucle.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  // Fonction pour extraire les tags des secrets
  const extractTagsFromSecrets = (secretsList) => {
    const allTags = new Set();
    secretsList.forEach(secret => {
      if (secret.tags && typeof secret.tags === 'string') {
        const tags = secret.tags.split(/[\s,;]+/).filter(t => t && typeof t === 'string' && t.trim());
        tags.forEach(tag => {
          const trimmed = String(tag).trim();
          if (trimmed) {
            allTags.add(trimmed);
          }
        });
      }
    });
    return Array.from(allTags).sort();
  };

  // Fonction pour supprimer un tag de toutes les entrées dans tous les coffres
  const removeTagFromAllSecrets = async (tagToRemove) => {
    try {
      setLoadingTags(true);
      secureLogger.debug('[TAGS] Suppression tag de toutes les entrées');

      // Charger tous les coffres accessibles
      const allAccessibleMounts = await listAccessibleKvMounts();

      let modifiedCount = 0;

      // Appartenance EXACTE au tag (même découpage que la découverte des tags) :
      // « obsolete » ne doit pas toucher un secret tagué « obsolete-v2 ».
      // @returns {string|null} nouveaux tags, ou null si le secret ne porte pas le tag
      const tagsWithout = (rawTags) => {
        if (!rawTags || typeof rawTags !== 'string') return null;
        const tags = rawTags.split(/[\s,;]+/).map(tag => tag.trim()).filter(Boolean);
        if (!tags.includes(tagToRemove)) return null;
        return tags.filter(tag => tag !== tagToRemove).join(' ');
      };

      for (const mount of allAccessibleMounts) {
        try {
          // SÉCURITÉ : chemin de coffre et clé encodés avant interpolation URL
          const mountUrl = `${vaultUrl}/v1/${encodeEnginePath(mount.path)}`;
          // Listing RÉCURSIF (dossiers compris), comme la découverte des tags
          const keys = await listKeysRecursive(mount.path, mount.version);
          if (mount.version === 2) {
            // KV v2
            for (const key of keys) {
              try {
                const secretRes = await axios.get(
                  `${mountUrl}/data/${encodeSecretPath(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const data = secretRes.data?.data?.data || {};

                const newTags = tagsWithout(data.Tags);
                if (newTags !== null) {
                  // Mettre à jour le secret
                  await axios.post(
                    `${mountUrl}/data/${encodeSecretPath(key)}`,
                    { data: { ...data, Tags: newTags } },
                    axiosConfig({ headers: baseHeaders() })
                  );
                  modifiedCount++;
                  secureLogger.debug('[TAGS] Tag retiré d\'une entrée');
                }
              } catch (err) {
                // Ignorer les erreurs individuelles
              }
            }
          } else {
            // KV v1
            for (const key of keys) {
              try {
                const secretRes = await axios.get(
                  `${mountUrl}/${encodeSecretPath(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const data = secretRes.data?.data || {};

                const newTags = tagsWithout(data.Tags);
                if (newTags !== null) {
                  // Mettre à jour le secret
                  await axios.post(
                    `${mountUrl}/${encodeSecretPath(key)}`,
                    { ...data, Tags: newTags },
                    axiosConfig({ headers: baseHeaders() })
                  );
                  modifiedCount++;
                  secureLogger.debug('[TAGS] Tag retiré d\'une entrée');
                }
              } catch (err) {
                // Ignorer les erreurs individuelles
              }
            }
          }
        } catch (err) {
          secureLogger.debug('[TAGS] Impossible de traiter un coffre');
        }
      }

      secureLogger.debug('[TAGS] Tag supprimé de', modifiedCount, 'entrée(s)');
      showToast(t('admin.toast.tagRemovedFromEntries', { tag: tagToRemove, count: modifiedCount }), 'success');
    } catch (err) {
      secureLogger.error('[TAGS] Erreur suppression tag');
      throw err;
    } finally {
      setLoadingTags(false);
    }
  };

  // Lister TOUS les coffres KV accessibles (pas seulement ceux du panel admin),
  // hors coffres système. Retourne [{ path, name, type, version }].
  const listAccessibleKvMounts = async () => {
    const mountsRes = await axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders() }));
    const mountsData = mountsRes.data?.data || mountsRes.data || {};
    return Object.entries(mountsData)
      .map(([path, config]) => ({
        path: path.replace(/\/$/, ''),
        name: path.replace(/\/$/, ''),
        type: config.type,
        version: Number(config.options?.version) || 1
      }))
      .filter(mount => mount.type === 'kv' && !SYSTEM_MOUNTS.includes(mount.path.toLowerCase()));
  };

  // Lire tous les secrets de tous les coffres KV accessibles via l'utilitaire
  // partagé readAllSecrets (vaultApi : listing récursif + lecture normalisée).
  const readAllAccessibleSecrets = async () => {
    if (!vaultApi) {
      secureLogger.error('[TAGS] vaultApi non fourni au panneau admin');
      return [];
    }
    const mounts = await listAccessibleKvMounts();
    const { secrets } = await readAllSecrets(vaultApi, mounts);
    return secrets;
  };

  // Fonction pour vérifier et créer le coffre tags-shared si nécessaire
  const ensureTagsSharedMount = async () => {
    try {
      // Vérifier si le coffre existe déjà
      const mountsRes = await axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders() }));
      const mountsData = mountsRes.data?.data || mountsRes.data || {};

      if (mountsData['tags-shared/'] || mountsData['tags-shared']) {
        secureLogger.debug('[TAGS] Le coffre tags-shared existe déjà');
        return true;
      }

      secureLogger.debug('[TAGS] Création du coffre tags-shared');

      // Créer le coffre tags-shared (KV v2)
      await axios.post(
        `${vaultUrl}/v1/sys/mounts/tags-shared`,
        {
          type: 'kv',
          options: {
            version: '2'
          },
          description: t('admin.tags.sharedMountDescription')
        },
        axiosConfig({ headers: baseHeaders() })
      );

      showToast(t('admin.toast.tagsSharedCreated'), 'success');
      return true;
    } catch (err) {
      secureLogger.error('[TAGS] Erreur création coffre tags-shared');
      if (err.response?.status === 403) {
        showToast(t('admin.toast.tagsSharedForbidden'), 'error');
      } else {
        showToast(t('admin.toast.tagsSharedCreateError'), 'error');
      }
      return false;
    }
  };

  const loadSharedTags = async () => {
    try {
      setLoadingTags(true);
      secureLogger.debug('[TAGS] Chargement des tags depuis tous les coffres');

      // Charger TOUS les coffres accessibles (pas seulement ceux du panel admin)
      // Seul le champ tags est conservé en mémoire (pas de secrets inutiles)
      const allSecrets = (await readAllAccessibleSecrets())
        .filter(s => s.tags)
        .map(s => ({ tags: s.tags }));

      const discovered = extractTagsFromSecrets(allSecrets);
      secureLogger.debug('[TAGS] Tags découverts:', discovered.length);
      setDiscoveredTags(discovered);

      // Charger aussi les tags partagés du vault
      try {
        const vaultTags = await tagManager.getSharedTags(vaultUrl, baseHeaders(), axiosConfig, axios);
        setSharedTags(vaultTags);
      } catch (err) {
        setSharedTags([]);
      }
    } catch (err) {
      secureLogger.error('[TAGS] Erreur chargement tags');
      showToast(t('admin.toast.loadTagsError'), 'error');
    } finally {
      setLoadingTags(false);
    }
  };

  // Charger les liens policies-groupes quand les groupes sont chargés
  useEffect(() => {
    if (adGroups.length > 0) {
      loadAllPolicyGroups();
    }
    // Rechargement uniquement quand la liste des groupes change (loadAllPolicyGroups est recréée à chaque rendu)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [adGroups]);

  // Fermer le menu contextuel lors du clic
  useEffect(() => {
    const closeMenu = () => setPolicyContextMenu(null);
    document.addEventListener('click', closeMenu);
    return () => document.removeEventListener('click', closeMenu);
  }, []);

  // UI-31 : menu des policies utilisable au clavier (motif APG « Menu », comme les menus de la
  // vue principale) : focus sur le premier élément à l'ouverture, flèches haut/bas, Début/Fin,
  // Échap ou Tab ferme le menu et rend le focus à la policy d'origine.
  useEffect(() => {
    if (!policyContextMenu) return undefined;
    const items = () => Array.from(policyMenuRef.current?.querySelectorAll('[role="menuitem"]') || []);
    items()[0]?.focus();
    const close = () => {
      setPolicyContextMenu(null);
      const opener = policyMenuOpenerRef.current;
      if (opener && opener.isConnected) opener.focus();
    };
    const onKeyDown = (e) => {
      const menu = policyMenuRef.current;
      if (e.key === 'Escape' || e.key === 'Tab') {
        e.preventDefault();
        close();
        return;
      }
      if (!menu || !menu.contains(document.activeElement)) return;
      const list = items();
      if (!list.length || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
      e.preventDefault();
      const index = list.indexOf(document.activeElement);
      let next;
      if (e.key === 'Home') next = list[0];
      else if (e.key === 'End') next = list[list.length - 1];
      else next = list[(index + (e.key === 'ArrowDown' ? 1 : -1) + list.length) % list.length];
      next.focus();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [policyContextMenu]);

  // Ouverture du menu d'une policy : clic droit (coordonnées du pointeur) ou touche Menu /
  // Maj+F10 sur la policy focalisée (événement sans coordonnées : menu ancré sous l'élément)
  const openPolicyMenu = (e, policy) => {
    e.preventDefault();
    e.stopPropagation();
    // Menu « Modifier / Supprimer » : actions d'écriture, absentes en consultation seule
    if (moderatorReadOnly) return;
    policyMenuOpenerRef.current = document.activeElement;
    let x = e.clientX;
    let y = e.clientY;
    if (!x && !y) {
      const rect = e.currentTarget.getBoundingClientRect();
      x = Math.round(rect.left + Math.min(24, rect.width / 2));
      y = Math.round(rect.bottom);
    }
    setPolicyContextMenu({ x, y, policy });
  };

  // Onglets (motif APG « Tabs ») : uniquement ceux autorisés pour le rôle
  const tabKeys = ['mounts', 'policies'];
  if (isAdmin) tabKeys.push('auth', 'audit');
  if (isAdmin || isModerator) tabKeys.push('tags');
  if (isAdmin) tabKeys.push('export');
  const { tabProps, panelProps } = useTabs(tabKeys, activeTab, setActiveTab);

  return (
    <div className="admin-panel">
      <div className="admin-header" style={{ WebkitAppRegion: 'drag' }}>
        <div style={{
          position: 'absolute',
          inset: 0,
          overflow: 'hidden',
          pointerEvents: 'none',
          zIndex: 0
        }}>
          {/* Reflet décoratif en rotation (arrêté en mouvement réduit : .admin-header-glow) */}
          <div className="admin-header-glow" style={{
            position: 'absolute',
            top: '-50%',
            right: '-50%',
            width: '200%',
            height: '200%',
            background: 'radial-gradient(circle, rgba(255,255,255,0.2), transparent 60%)',
            animation: 'rotate 30s linear infinite'
          }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px', position: 'relative', zIndex: 1, WebkitAppRegion: 'no-drag' }}>
          <div>
            <h1>🛡️ {t('admin.header.title')}</h1>
            <p className="admin-subtitle">{t('admin.header.subtitle')}</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div className="user-menu-wrapper-admin">
              <UserMenu
                username={username}
                darkMode={darkMode}
                onToggleDarkMode={onToggleDarkMode}
                isAdmin={true}
                currentView={currentView}
                onToggleAdminView={onToggleAdminView}
                onLogout={onLogout}
              />
            </div>
            <WindowControls />
          </div>
        </div>
      </div>

      {/* Onglets */}
      {/* Onglets : sémantique d'onglets (tablist / tab / aria-selected), flèches, Début / Fin */}
      <div className="admin-tabs" role="tablist" aria-label={t('admin.header.title')}>
        <button
          {...tabProps('mounts')}
          className={`admin-tab ${activeTab === 'mounts' ? 'active' : ''}`}
        >
          <span aria-hidden="true">📦</span> {t('admin.tab.mounts')}
        </button>
        <button
          {...tabProps('policies')}
          className={`admin-tab ${activeTab === 'policies' ? 'active' : ''}`}
        >
          <span aria-hidden="true">📜</span> {t('admin.tab.policies')}
        </button>
        {isAdmin && (
          <button
            {...tabProps('auth')}
            className={`admin-tab ${activeTab === 'auth' ? 'active' : ''}`}
          >
            <span aria-hidden="true">👥</span> {t('admin.tab.auth')}
          </button>
        )}
        {isAdmin && (
          <button
            {...tabProps('audit')}
            className={`admin-tab ${activeTab === 'audit' ? 'active' : ''}`}
          >
            <span aria-hidden="true">📊</span> {t('admin.tab.audit')}
          </button>
        )}
        {(isAdmin || isModerator) && (
          <button
            {...tabProps('tags')}
            className={`admin-tab ${activeTab === 'tags' ? 'active' : ''}`}
          >
            <span aria-hidden="true">🏷️</span> {t('admin.tab.tags')}
          </button>
        )}
        {isAdmin && (
          <button
            {...tabProps('export')}
            className={`admin-tab ${activeTab === 'export' ? 'active' : ''}`}
          >
            <span aria-hidden="true">📥</span> {t('admin.tab.export')}
          </button>
        )}
      </div>

      {/* Contenu selon l'onglet (panneau relié à l'onglet actif) */}
      <div className="admin-content" {...panelProps(activeTab)}>
        {moderatorReadOnly && (
          <div className="admin-help" role="note" style={{ marginBottom: '16px' }}>
            <p style={{ margin: 0 }}>👮 {t('admin.header.moderatorReadOnly')}</p>
          </div>
        )}
        {activeTab === 'mounts' && (
          <div className="admin-section">
            <div className="admin-split">
              {/* Liste des mounts */}
              <div className="admin-list">
                <div className="admin-list-header">
                  <h3>{t('admin.mount.available')}</h3>
                  {(isAdmin || isModerator) && !moderatorReadOnly && (
                    <button
                      type="button"
                      className="btn btn-success btn-sm"
                      onClick={() => setShowCreateMountModal(true)}
                    >
                      + {t('admin.mount.new')}
                    </button>
                  )}
                </div>
                {loading ? (
                  <p>{t('common.loading')}</p>
                ) : (
                  <ul className="admin-items-list">
                    {allMounts.map(mount => {
                      const isHidden = hiddenEngines.includes(mount.path);
                      return (
                      <li
                        key={mount.path}
                        className={`admin-item ${selectedMount?.path === mount.path ? 'active' : ''}`}
                        onClick={async () => {
                          setSelectedMount(mount);
                          setLoadingPolicies(true);
                          setAppliedPolicies([]);

                          const { appliedPolicies: applied } = await loadAppliedPolicies(mount.path);
                          setAppliedPolicies(applied);
                          setLoadingPolicies(false);
                        }}
                      >
                        {/* ADMIN-11 : chemin isolé en ltr avec sa barre oblique (en arabe, « Comptabilite/ »
                            s'affichait « /Comptabilite ») ; ADMIN-16 : marge logique du badge.
                            UI-31 : vrai bouton (focalisable, Entrée / Espace) ; son « click » remonte
                            au <li>, qui porte la sélection (clic n'importe où sur la ligne conservé).
                            UI-38 : coffre sélectionné exposé par aria-current. */}
                        <button
                          type="button"
                          className="admin-item-select"
                          aria-current={selectedMount?.path === mount.path ? 'true' : undefined}
                        >
                          <span aria-hidden="true">📦</span> <Ltr>{mount.path}/</Ltr>
                          {isHidden && <span style={{ marginInlineStart: '8px', fontSize: '11px', color: 'var(--warning)', fontWeight: '600' }}>{t('admin.mount.hidden')}</span>}
                        </button>
                        {(isAdmin || isModerator) && !moderatorReadOnly && (
                          <button
                            type="button"
                            className="btn-mini btn-danger"
                            aria-label={t('admin.mount.deleteNamed', { path: mount.path })}
                            title={t('admin.mount.deleteNamed', { path: mount.path })}
                            onClick={(e) => { e.stopPropagation(); deleteMount(mount.path); }}
                          >
                            <span aria-hidden="true">✕</span>
                          </button>
                        )}
                      </li>
                    );
                    })}
                  </ul>
                )}
              </div>

              {/* Gestion des policies pour le mount sélectionné */}
              <div className="admin-editor">
                {selectedMount ? (
                  <>
                    <div className="admin-editor-header">
                      <h3>{richLtr(t('admin.mount.title'), 'path', selectedMount.path)}</h3>
                    </div>
                    <div className="mount-details">
                      <p><strong>{t('admin.common.typeLabel')}</strong> {selectedMount.type}</p>
                      <p><strong>{t('admin.common.versionLabel')}</strong> {selectedMount.type === 'kv' ? `v${selectedMount.version}` : '-'}</p>
                      <p><strong>{t('admin.common.descriptionLabel')}</strong> {selectedMount.description || t('admin.common.none')}</p>
                    </div>

                    <h4 style={{ marginTop: '24px', marginBottom: '12px' }}>
                      {t('admin.mount.linkedPolicies')}
                      {appliedPolicies.length > 0 && (
                        <span style={{ marginInlineStart: '12px', fontSize: '13px', color: 'var(--success)', fontWeight: 'normal' }}>
                          {tp('admin.mount.policyCount', appliedPolicies.length)}
                        </span>
                      )}
                    </h4>
                    {loadingPolicies ? (
                      <p style={{ color: 'var(--text-tertiary)', fontSize: '14px' }}>🔄 {t('admin.mount.loadingPolicies')}</p>
                    ) : appliedPolicies.length > 0 ? (
                      <div className="policy-selector">
                        {appliedPolicies.map(policy => {
                          return (
                            <div
                              key={policy}
                              className="policy-badge"
                              style={{
                                marginInlineEnd: '8px',
                                marginBottom: '8px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '6px',
                                padding: '8px 12px',
                                background: 'var(--success-bg)',
                                color: 'var(--success)',
                                border: '1px solid var(--success)',
                                borderRadius: 'var(--radius-sm)',
                                fontSize: '13px',
                                fontWeight: '500'
                              }}
                            >
                              ✓ <Ltr>{policy}</Ltr>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <p style={{ color: 'var(--text-tertiary)', fontSize: '14px' }}>{t('admin.mount.noLinkedPolicy')}</p>
                    )}

                    <div className="admin-help" style={{ marginTop: '24px' }}>
                      <p><strong>💡 {t('admin.mount.infoTitle')}</strong></p>
                      <p>{richText(t('admin.mount.infoText'), { path: <code>{`${selectedMount.path}/`}</code> })}</p>
                    </div>
                  </>
                ) : (
                  <div className="admin-empty">
                    <p>{t('admin.mount.selectPrompt')}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'policies' && (
          <div className="admin-section">
            <div className="admin-split">
              {/* Liste des policies */}
              <div className="admin-list">
                <div className="admin-list-header">
                  <h3>{t('admin.policy.available')}</h3>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    {!moderatorReadOnly && (
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        onClick={() => setShowPolicyBuilderModal(true)}
                        title={t('admin.policy.builderTooltip')}
                      >
                        🛠️ {t('admin.policy.builder')}
                      </button>
                    )}
                    {(isAdmin || isModerator) && !moderatorReadOnly && (
                      <button
                        type="button"
                        className="btn btn-success btn-sm"
                        onClick={() => setShowCreatePolicyModal(true)}
                      >
                        + {t('admin.policy.new')}
                      </button>
                    )}
                  </div>
                </div>
                {loading ? (
                  <p>{t('common.loading')}</p>
                ) : (
                  <ul className="admin-items-list">
                    {policies.map(policy => (
                      <li
                        key={policy}
                        className={`admin-item ${selectedPolicy === policy ? 'active' : ''}`}
                        onClick={() => loadPolicyContent(policy)}
                        onContextMenu={(e) => openPolicyMenu(e, policy)}
                      >
                        {/* UI-31 : bouton focalisable (Entrée / Espace = ouverture de l'éditeur, touche
                            Menu / Maj+F10 = menu « Modifier / Supprimer ») ; UI-38 : aria-current */}
                        <button
                          type="button"
                          className="admin-item-select"
                          aria-current={selectedPolicy === policy ? 'true' : undefined}
                        >
                          <span aria-hidden="true">📜</span> <Ltr>{policy}</Ltr>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Éditeur de policy */}
              <div className="admin-editor">
                {selectedPolicy ? (
                  <>
                    <div className="admin-editor-header">
                      <h3>{richLtr(t('admin.policy.editorTitle'), 'name', selectedPolicy)}</h3>
                      {!moderatorReadOnly && (
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => openBuilderForEdit(selectedPolicy)}
                            title={t('admin.policy.editWithBuilder')}
                          >
                            ✏️ {t('admin.common.edit')}
                          </button>
                          <button
                            className="btn btn-primary btn-sm"
                            onClick={() => savePolicy(selectedPolicy, policyContent)}
                          >
                            💾 {t('admin.common.save')}
                          </button>
                          {/* UI-31 : « Supprimer » proposé aussi hors du menu contextuel (même
                              confirmation ; policies système default / root exclues comme au menu) */}
                          {(isAdmin || isModerator) && selectedPolicy !== 'default' && selectedPolicy !== 'root' && (
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => deletePolicy(selectedPolicy)}
                            >
                              🗑️ {t('common.delete')}
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                    {/* HCL : du code, toujours de gauche à droite (y compris en arabe) */}
                    <textarea
                      className="admin-textarea"
                      dir="ltr"
                      value={policyContent}
                      readOnly={moderatorReadOnly}
                      onChange={(e) => setPolicyContent(e.target.value)}
                      placeholder={t('admin.policy.hclPlaceholder')}
                      spellCheck={false}
                      style={{ marginBottom: '16px' }}
                    />

                    {/* Section groupes AD */}
                    <div style={{ marginBottom: '16px', padding: '16px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                      <div style={{ marginTop: '0', marginBottom: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <h4 style={{ margin: '0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span>👥 {t('admin.policy.linkedGroups')}</span>
                          {policyGroups[selectedPolicy] && policyGroups[selectedPolicy].length > 0 && (
                            <span style={{ fontSize: '13px', color: 'var(--success)', fontWeight: 'normal' }}>
                              {tp('admin.policy.groupCount', policyGroups[selectedPolicy].length)}
                            </span>
                          )}
                        </h4>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={async () => {
                            await loadAdGroups();
                            await loadAllPolicyGroups();
                            showToast(t('admin.toast.groupsReloaded'), 'success');
                          }}
                          disabled={loadingGroups}
                          style={{ fontSize: '12px', padding: '4px 10px' }}
                          title={t('admin.policy.reloadGroupsTooltip')}
                        >
                          🔄 {t('admin.common.refresh')}
                        </button>
                      </div>

                      {loadingGroups ? (
                        <p style={{ color: 'var(--text-tertiary)', fontSize: '14px' }}>🔄 {t('admin.policy.loadingGroups')}</p>
                      ) : (
                        <>
                          {/* Groupes liés */}
                          {policyGroups[selectedPolicy] && policyGroups[selectedPolicy].length > 0 && (
                            <div style={{ marginBottom: '12px' }}>
                              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px' }}>{t('admin.policy.groupsWithAccess')}</p>
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                {policyGroups[selectedPolicy].map(group => (
                                  <div
                                    key={group}
                                    style={{
                                      display: 'inline-flex',
                                      alignItems: 'center',
                                      gap: '6px',
                                      padding: '6px 10px',
                                      background: 'var(--success-bg)',
                                      color: 'var(--success)',
                                      border: '1px solid var(--success)',
                                      borderRadius: 'var(--radius-sm)',
                                      fontSize: '13px',
                                      fontWeight: '500'
                                    }}
                                  >
                                    ✓ <Ltr>{group}</Ltr>
                                    {!moderatorReadOnly && (
                                      <button
                                        className="btn-mini btn-danger"
                                        style={{ marginInlineStart: '4px' }}
                                        onClick={() => toggleGroupForPolicy(group, selectedPolicy, false)}
                                        title={t('admin.policy.removeGroup')}
                                      >
                                        ✕
                                      </button>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Groupes disponibles (liaison = écriture sur les groupes : admin seulement) */}
                          {adGroups.length > 0 && !moderatorReadOnly && (
                            <div>
                              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px' }}>{t('admin.policy.addGroup')}</p>
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                                {adGroups
                                  .filter(group => !policyGroups[selectedPolicy]?.includes(group))
                                  .map(group => (
                                    <button
                                      key={group}
                                      className="btn btn-secondary btn-sm"
                                      style={{ fontSize: '13px' }}
                                      onClick={() => toggleGroupForPolicy(group, selectedPolicy, true)}
                                    >
                                      + <Ltr>{group}</Ltr>
                                    </button>
                                  ))}
                              </div>
                              {adGroups.filter(group => !policyGroups[selectedPolicy]?.includes(group)).length === 0 && (
                                <p style={{ color: 'var(--text-tertiary)', fontSize: '13px', fontStyle: 'italic' }}>{t('admin.policy.allGroupsLinked')}</p>
                              )}
                            </div>
                          )}

                          {adGroups.length === 0 && (
                            <p style={{ color: 'var(--text-tertiary)', fontSize: '14px' }}>{t('admin.policy.noAdGroups')}</p>
                          )}
                        </>
                      )}
                    </div>

                    <div className="admin-help">
                      <p><strong>{t('admin.policy.capabilitiesExamples')}</strong></p>
                      <code>read, create, update, delete, list, sudo, deny</code>
                      <p><strong>{t('admin.policy.example')}</strong></p>
                      <pre>{`path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}`}</pre>
                    </div>
                  </>
                ) : (
                  <div className="admin-empty">
                    <p>{t('admin.policy.selectPrompt')}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'auth' && (
          <div className="admin-section">
            <div style={{ maxWidth: '900px' }}>
              <h3 style={{ marginBottom: '24px', fontSize: '20px', fontWeight: '700' }}>
                🔐 {t('admin.ldap.title')}
              </h3>

              {loadingLdap ? (
                <p style={{ color: 'var(--text-tertiary)', fontSize: '14px' }}>🔄 {t('admin.ldap.loading')}</p>
              ) : ldapConfig ? (
                <>
                  {/* Configuration LDAP */}
                  <div style={{ marginBottom: '24px', padding: '20px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600' }}>
                        📋 {t('admin.ldap.serverConfig')}
                      </h4>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={loadLdapConfig}
                        style={{ fontSize: '12px', padding: '4px 10px' }}
                      >
                        🔄 {t('admin.common.refresh')}
                      </button>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '12px', fontSize: '14px' }}>
                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{t('admin.ldap.server')}</div>
                      {/* Valeurs de configuration (URL, DN, filtre) : isolées en ltr ; les libellés de
                          repli traduits gardent le sens de la langue */}
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.url ? <Ltr>{ldapConfig.url}</Ltr> : t('admin.ldap.notConfigured')}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{t('admin.ldap.userDn')}</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {(ldapConfig.userdn || ldapConfig.binddn) ? <Ltr>{ldapConfig.userdn || ldapConfig.binddn}</Ltr> : t('admin.ldap.notConfigured')}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{t('admin.ldap.groupDn')}</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.groupdn ? <Ltr>{ldapConfig.groupdn}</Ltr> : t('admin.ldap.notConfigured')}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{t('admin.ldap.groupFilter')}</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                        {ldapConfig.groupfilter ? <Ltr>{ldapConfig.groupfilter}</Ltr> : t('admin.ldap.default')}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{t('admin.ldap.groupAttr')}</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.groupattr ? <Ltr>{ldapConfig.groupattr}</Ltr> : t('admin.ldap.cnDefault')}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>{t('admin.ldap.caseSensitive')}</div>
                      <div style={{ color: 'var(--text-primary)' }}>
                        {ldapConfig.case_sensitive_names === false ? `❌ ${t('common.no')}` : `✓ ${t('common.yes')}`}
                      </div>
                    </div>
                  </div>

                  {/* Synchronisation des groupes */}
                  <div style={{ marginBottom: '24px', padding: '20px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600' }}>
                        👥 {t('admin.ldap.adGroups')}
                      </h4>
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        onClick={syncLdapGroups}
                        disabled={loadingGroups}
                        style={{ fontSize: '12px', padding: '6px 14px' }}
                      >
                        {loadingGroups ? `🔄 ${t('admin.ldap.syncing')}` : `🔄 ${t('admin.ldap.syncGroups')}`}
                      </button>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                      <div style={{ fontSize: '32px', fontWeight: '700', color: 'var(--primary)' }}>
                        {ldapGroupsCount}
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
                        {tp('admin.ldap.groupsConfigured', ldapGroupsCount)}
                      </div>
                    </div>

                    {adGroups.length > 0 && (
                      <div>
                        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px', fontWeight: '600' }}>
                          {t('admin.ldap.groupList')}
                        </p>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', maxHeight: '200px', overflow: 'auto', padding: '8px', background: 'var(--bg-app)', borderRadius: '6px' }}>
                          {adGroups.map(group => (
                            <div
                              key={group}
                              style={{
                                padding: '4px 10px',
                                background: 'var(--bg-surface)',
                                border: '1px solid var(--border)',
                                borderRadius: 'var(--radius-sm)',
                                fontSize: '12px',
                                color: 'var(--text-secondary)',
                                fontFamily: 'monospace'
                              }}
                            >
                              <Ltr>{group}</Ltr>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Informations et explications */}
                  <div className="admin-help">
                    <p><strong>💡 {t('admin.ldap.aboutTitle')}</strong></p>
                    <ul style={{ fontSize: '13px', lineHeight: '1.6', marginTop: '8px' }}>
                      <li><strong>{t('admin.ldap.autoSyncLabel')}</strong> {richText(t('admin.ldap.autoSyncText'), { ou: <code>OU=VAULT,OU=Groupes,DC=lab,DC=proxmox</code> })}</li>
                      <li><strong>{t('admin.ldap.configuredLabel')}</strong> {richText(t('admin.ldap.configuredText'), { policy: <code>policy=default</code> })}</li>
                      <li><strong>{t('admin.ldap.addLabel')}</strong> {t('admin.ldap.addText')}
                        <ol style={{ marginTop: '4px', marginInlineStart: '20px' }}>
                          <li>{richText(t('admin.ldap.addStep1'), { ou: <code>{'VAULT\\Groupes'}</code> })}</li>
                          <li>{t('admin.ldap.addStep2')}</li>
                          <li>{richText(t('admin.ldap.addStep3'), { policy: <code>policy=default</code> })}</li>
                          <li>{t('admin.ldap.addStep4')}</li>
                        </ol>
                      </li>
                      <li><strong>{t('admin.ldap.scriptLabel')}</strong> {richText(t('admin.ldap.scriptText'), { script: <code>/usr/local/bin/vault_sync_ad_groups.sh</code>, log: <code>/var/log/vault_sync_ad_groups.log</code> })}</li>
                    </ul>
                  </div>
                </>
              ) : (
                <div style={{ padding: '40px', textAlign: 'center', background: 'var(--warning-bg)', border: '1px solid var(--warning-border)', borderRadius: '8px' }}>
                  <div style={{ fontSize: '48px', marginBottom: '12px' }}>⚠️</div>
                  <p style={{ fontSize: '16px', fontWeight: '600', color: 'var(--warning-text)', marginBottom: '8px' }}>
                    {t('admin.ldap.unavailableTitle')}
                  </p>
                  <p style={{ fontSize: '13px', color: 'var(--warning-text)' }}>
                    {t('admin.ldap.unavailableText')}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="admin-section">
            <div className="admin-split">
              {/* Audit Devices */}
              <div className="admin-list">
                <div className="admin-list-header">
                  <h3>{t('admin.audit.devices')}</h3>
                  <button
                    type="button"
                    className="btn btn-success btn-sm"
                    onClick={() => setShowEnableAuditModal(true)}
                  >
                    + {t('admin.common.enable')}
                  </button>
                </div>
                {loadingAudit ? (
                  <p>{t('common.loading')}</p>
                ) : auditDevices.length > 0 ? (
                  <ul className="admin-items-list">
                    {auditDevices.map(device => (
                      <li
                        key={device.path}
                        className={`admin-item ${selectedAuditDevice?.path === device.path ? 'active' : ''}`}
                        onClick={() => {
                          setSelectedAuditDevice(device);
                          loadAuditLogs(device);
                        }}
                        style={{ cursor: 'pointer' }}
                      >
                        {/* ADMIN-11 : chemin du device et du journal isolés en ltr.
                            UI-31 : bouton focalisable (Entrée / Espace = lecture du journal) ; UI-38 : aria-current */}
                        <button
                          type="button"
                          className="admin-item-select"
                          aria-current={selectedAuditDevice?.path === device.path ? 'true' : undefined}
                        >
                          <span style={{ display: 'block' }}><span aria-hidden="true">📊</span> <Ltr>{device.path}/</Ltr></span>
                          <span style={{ display: 'block', fontSize: 11, color: 'var(--text-tertiary)', marginTop: 4 }}>
                            {t('admin.common.typeLabel')} {device.type}
                            {device.options?.file_path && <>{` | ${t('admin.common.fileLabel')} `}<Ltr>{device.options.file_path}</Ltr></>}
                          </span>
                        </button>
                        <button
                          type="button"
                          className="btn-mini btn-danger"
                          aria-label={t('admin.audit.disableNamed', { path: device.path })}
                          title={t('admin.audit.disableNamed', { path: device.path })}
                          onClick={(e) => { e.stopPropagation(); disableAuditDevice(device.path); }}
                        >
                          <span aria-hidden="true">✕</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div style={{ padding: 16, color: 'var(--text-tertiary)', fontSize: 14 }}>
                    {t('admin.audit.noDevice')}
                  </div>
                )}
              </div>

              {/* Affichage des logs */}
              <div className="admin-editor">
                <div className="admin-editor-header">
                  <h3>📋 {t('admin.audit.logsTitle')}</h3>
                  {selectedAuditDevice && (
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => loadAuditLogs(selectedAuditDevice)}
                      disabled={loadingLogs}
                    >
                      🔄 {t('admin.common.refresh')}
                    </button>
                  )}
                </div>

                {selectedAuditDevice ? (
                  <div>
                    {/* Info sur le device sélectionné */}
                    <div style={{ background: 'var(--info-bg)', border: '1px solid var(--info-border)', borderRadius: 8, padding: 12, marginBottom: 16 }}>
                      <div style={{ fontWeight: 600, marginBottom: 8, color: 'var(--info-text)' }}>
                        📊 <Ltr>{selectedAuditDevice.path}/</Ltr>
                      </div>
                      <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: 0 }}>
                        <strong>{t('admin.common.typeLabel')}</strong> {selectedAuditDevice.type}
                        {selectedAuditDevice.options?.file_path && (
                          <>
                            <br /><strong>{t('admin.common.fileLabel')}</strong> <code style={{ fontSize: 11, background: 'var(--bg-surface)', color: 'var(--text-primary)', padding: '2px 6px', borderRadius: 4 }}>
                              {selectedAuditDevice.options.file_path}
                            </code>
                          </>
                        )}
                      </p>
                    </div>

                    {/* Logs */}
                    {loadingLogs ? (
                      <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-tertiary)' }}>
                        🔄 {t('admin.audit.loadingLogs')}
                      </div>
                    ) : auditLogs.length > 0 ? (
                      <div>
                        <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
                          {t('admin.audit.lastEntries', { count: auditLogs.length })}
                        </h4>
                        {/* Console de logs volontairement sombre dans les DEUX thèmes : couleurs fixes
                            choisies pour ce fond #1f2937 (texte ≥ 4.5:1 ; « ERROR » en rouge clair
                            #f87171, le #ef4444 précédent n'atteignait que 3.9:1).
                            Journal technique (user=… path=…) : toujours de gauche à droite. */}
                        <div data-testid="audit-log-console" dir="ltr" style={{ background: '#1f2937', color: '#e5e7eb', padding: 12, borderRadius: 8, fontSize: 11, fontFamily: 'monospace', maxHeight: 500, overflow: 'auto' }}>
                          {auditLogs.map((log, idx) => {
                            // Date au format de la langue de l'application (et non 'fr-FR' en dur)
                            const time = log.time ? formatDateTime(log.time, lang) : 'N/A';
                            const username = log.auth?.display_name || log.auth?.metadata?.username || 'unknown';
                            const operation = log.request?.operation || 'unknown';
                            const path = log.request?.path || 'unknown';
                            const statusCode = log.response?.status_code;
                            const isError = statusCode && statusCode >= 400;

                            return (
                              <div key={idx} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid #374151' }}>
                                <div>
                                  <span style={{ color: '#9ca3af' }}>[{time}]</span>{' '}
                                  <span style={{ color: isError ? '#f87171' : '#10b981' }}>
                                    {isError ? 'ERROR' : 'INFO'}
                                  </span>{' '}
                                  <span style={{ color: '#fbbf24' }}>user={username}</span>{' '}
                                  operation={operation} path={path}
                                  {statusCode && ` status=${statusCode}`}
                                </div>
                                {log.error && (
                                  <div style={{ color: '#f87171', marginTop: 4, fontSize: 10 }}>
                                    ⚠️ {log.error}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ) : (
                      <div style={{ textAlign: 'center', padding: 40, color: 'var(--text-tertiary)' }}>
                        {t('admin.audit.noLogs')}
                      </div>
                    )}

                    <div className="admin-help" style={{ marginTop: 20 }}>
                      <p><strong>💡 {t('admin.audit.aboutTitle')}</strong></p>
                      <p style={{ fontSize: 13 }}>
                        • {t('admin.audit.aboutLast100')}<br />
                        • {t('admin.audit.aboutRefresh')}<br />
                        • {t('admin.audit.aboutFormat')}
                      </p>
                    </div>
                  </div>
                ) : auditDevices.length > 0 ? (
                  <div className="admin-empty">
                    <p>{t('admin.audit.selectPrompt')}</p>
                    <p style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 12 }}>
                      {t('admin.audit.selectHint')}
                    </p>
                  </div>
                ) : (
                  <div className="admin-empty">
                    <p>{t('admin.audit.enablePrompt')}</p>
                    <p style={{ fontSize: 13, color: 'var(--text-tertiary)', marginTop: 12 }}>
                      {t('admin.audit.enableHint')}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'tags' && (
          <div className="admin-section">
            <div style={{ maxWidth: 800, margin: '0 auto' }}>
              <h2 style={{ marginBottom: 20 }}>🏷️ {t('admin.tags.title')}</h2>

              {/* Couleurs du thème (variables CSS) : les anciens fonds clairs codés en dur (#fff,
                  #f3f4f6, #dbeafe…) restaient blancs en thème sombre, sous un texte clair illisible */}
              <div style={{ background: 'var(--info-bg)', border: '1px solid var(--info-border)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <p style={{ margin: 0, fontSize: 14, color: 'var(--info-text)' }}>
                  {t('admin.tags.intro')}
                </p>
              </div>

              {/* Créer un nouveau tag partagé */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 20 }}>
                <h3 style={{ fontSize: 16, marginBottom: 12 }}>➕ {t('admin.tags.createTitle')}</h3>
                <form onSubmit={async (e) => {
                  e.preventDefault();
                  const tagInput = e.target.elements.newTag;
                  const newTag = tagInput.value.trim();
                  if (!newTag) {
                    showToast(t('admin.toast.tagNameEmpty'), 'error');
                    return;
                  }
                  // SÉCURITÉ: Valider le format du tag
                  // eslint-disable-next-line no-control-regex -- volontaire : tag avec caractère de contrôle refusé
                  if (newTag.length > 64 || /[\x00-\x1F\x7F\r\n\\/".]/.test(newTag)) {
                    showToast(t('admin.toast.tagNameInvalid'), 'error');
                    return;
                  }
                  if (sharedTags.includes(newTag)) {
                    showToast(t('admin.toast.tagExists'), 'error');
                    return;
                  }
                  // SÉCURITÉ: Limiter le nombre total de tags partagés
                  if (sharedTags.length >= 500) {
                    showToast(t('admin.toast.tagLimit'), 'error');
                    return;
                  }
                  try {
                    setLoadingTags(true);

                    // Vérifier et créer le coffre tags-shared si nécessaire
                    const mountExists = await ensureTagsSharedMount();
                    if (!mountExists) {
                      return; // Le coffre n'a pas pu être créé
                    }

                    await tagManager.addSharedTag(vaultUrl, newTag, baseHeaders(), axiosConfig, axios);
                    showToast(t('admin.toast.tagCreated', { tag: newTag }), 'success');
                    tagInput.value = '';
                    await loadSharedTags();
                  } catch (err) {
                    showToast(t('admin.toast.tagCreateError'), 'error');
                  } finally {
                    setLoadingTags(false);
                  }
                }}>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <input
                      type="text"
                      name="newTag"
                      placeholder={t('admin.tags.newTagPlaceholder')}
                      aria-label={t('admin.tags.newTagPlaceholder')}
                      style={{
                        flex: 1,
                        padding: '8px 12px',
                        border: '1px solid var(--border-control, var(--border))',
                        borderRadius: 6,
                        fontSize: 14,
                        background: 'var(--bg-app)',
                        color: 'var(--text-primary)'
                      }}
                      disabled={loadingTags}
                    />
                    <button
                      type="submit"
                      className="btn btn-success"
                      disabled={loadingTags}
                    >
                      {loadingTags ? '🔄' : '➕'} {t('admin.common.create')}
                    </button>
                  </div>
                </form>
              </div>

              {/* Tags partagés existants */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 20 }}>
                <h3 style={{ fontSize: 16, marginBottom: 12 }}>🏷️ {t('admin.tags.sharedTitle', { count: sharedTags.length })}</h3>
                {loadingTags ? (
                  <p style={{ textAlign: 'center', padding: 20, color: 'var(--text-tertiary)' }}>
                    🔄 {t('common.loading')}
                  </p>
                ) : sharedTags.length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                    {sharedTags.map(tag => (
                      <div
                        key={tag}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          background: 'var(--bg-surface-active)',
                          padding: '6px 12px',
                          borderRadius: 6,
                          border: '1px solid var(--border)'
                        }}
                      >
                        <span style={{ fontSize: 14 }}>🏷️ {tag}</span>
                        <button
                          onClick={async () => {
                            setConfirmModal({
                              title: t('admin.confirm.deleteTagTitle'),
                              message: t('admin.confirm.deleteSharedTagMessage', { tag }),
                              danger: true,
                              onConfirm: async () => {
                                try {
                                  setLoadingTags(true);
                                  await tagManager.removeSharedTag(vaultUrl, tag, baseHeaders(), axiosConfig, axios);
                                  showToast(t('admin.toast.tagDeleted', { tag }), 'success');
                                  await loadSharedTags();
                                } catch (err) {
                                  showToast(t('admin.toast.tagDeleteError'), 'error');
                                } finally {
                                  setLoadingTags(false);
                                  setConfirmModal(null);
                                }
                              },
                              onCancel: () => setConfirmModal(null)
                            });
                          }}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            cursor: 'pointer',
                            color: 'var(--error)',
                            fontSize: 16,
                            padding: 0,
                            lineHeight: 1
                          }}
                          title={t('admin.tags.deleteTooltip')}
                          disabled={loadingTags}
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ textAlign: 'center', padding: 20, color: 'var(--text-tertiary)' }}>
                    {t('admin.tags.noShared')}
                  </p>
                )}
              </div>

              {/* Tags découverts dans les coffres */}
              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <h3 style={{ fontSize: 16, margin: 0 }}>📋 {t('admin.tags.discoveredTitle', { count: discoveredTags.filter(tag => !sharedTags.includes(tag)).length })}</h3>

                  {/* Bouton de migration globale */}
                  {!loadingTags && discoveredTags.filter(tag => !sharedTags.includes(tag)).length > 0 && (
                    <button
                      onClick={async () => {
                        setConfirmModal({
                          title: t('admin.tags.migrateAll'),
                          message: t('admin.confirm.migrateAllMessage', { count: discoveredTags.filter(tag => !sharedTags.includes(tag)).length }),
                          danger: false,
                          onConfirm: async () => {
                            try {
                              setLoadingTags(true);
                              setConfirmModal(null);

                              // Vérifier et créer le coffre tags-shared si nécessaire
                              const mountExists = await ensureTagsSharedMount();
                              if (!mountExists) {
                                return;
                              }

                              // Récupérer tous les secrets de tous les coffres pour la migration
                              // (readAllSecrets normalise le champ `tags` attendu par tagManager)
                              const allSecrets = (await readAllAccessibleSecrets())
                                .filter(s => s.tags)
                                .map(s => ({ tags: s.tags }));

                              // Appeler la fonction de migration
                              const stats = await tagManager.migrateTagsToShared(
                                vaultUrl,
                                allSecrets,
                                baseHeaders(),
                                axiosConfig,
                                axios
                              );

                              showToast(
                                t('admin.toast.migrationDone', { added: tp('admin.toast.tagsAdded', stats.added), total: stats.total }),
                                'success'
                              );

                              // Recharger les tags
                              await loadSharedTags();
                            } catch (err) {
                              secureLogger.error('[TAGS] Erreur migration');
                              showToast(t('admin.toast.migrationError'), 'error');
                            } finally {
                              setLoadingTags(false);
                            }
                          },
                          onCancel: () => setConfirmModal(null)
                        });
                      }}
                      className="btn btn-primary"
                      style={{ fontSize: 14, padding: '6px 12px' }}
                      disabled={loadingTags}
                    >
                      🔄 {t('admin.tags.migrateAll')}
                    </button>
                  )}
                </div>

                {/* Info sur la migration */}
                {!loadingTags && discoveredTags.filter(tag => !sharedTags.includes(tag)).length > 0 && (
                  <div style={{ background: 'var(--warning-bg)', border: '1px solid var(--warning-border)', borderRadius: 6, padding: 12, marginBottom: 12, fontSize: 13, color: 'var(--text-primary)' }}>
                    💡 {t('admin.tags.migrateInfo')}
                  </div>
                )}

                {loadingTags ? (
                  <p style={{ textAlign: 'center', padding: 20, color: 'var(--text-tertiary)' }}>
                    🔄 {t('common.loading')}
                  </p>
                ) : discoveredTags.filter(tag => !sharedTags.includes(tag)).length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                    {discoveredTags.filter(tag => !sharedTags.includes(tag)).map(tag => (
                      <div
                        key={tag}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          background: 'var(--info-bg)',
                          padding: '6px 12px',
                          borderRadius: 6,
                          border: '1px solid var(--info-border)'
                        }}
                      >
                        <span style={{ fontSize: 14 }}>🏷️ {tag}</span>

                        {/* Bouton pour ajouter aux tags partagés */}
                        <button
                          onClick={async () => {
                            try {
                              setLoadingTags(true);

                              // Vérifier et créer le coffre tags-shared si nécessaire
                              const mountExists = await ensureTagsSharedMount();
                              if (!mountExists) {
                                return;
                              }

                              await tagManager.addSharedTag(vaultUrl, tag, baseHeaders(), axiosConfig, axios);
                              showToast(t('admin.toast.tagAddedToShared', { tag }), 'success');
                              await loadSharedTags();
                            } catch (err) {
                              showToast(t('admin.toast.tagAddError'), 'error');
                            } finally {
                              setLoadingTags(false);
                            }
                          }}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            cursor: 'pointer',
                            color: 'var(--success)',
                            fontSize: 16,
                            padding: 0,
                            lineHeight: 1
                          }}
                          title={t('admin.tags.addToSharedTooltip')}
                          disabled={loadingTags}
                        >
                          ➕
                        </button>

                        <button
                          onClick={async () => {
                            setConfirmModal({
                              title: t('admin.confirm.deleteTagTitle'),
                              message: t('admin.confirm.deleteTagEverywhereMessage', { tag }),
                              danger: true,
                              onConfirm: async () => {
                                try {
                                  await removeTagFromAllSecrets(tag);
                                  await loadSharedTags();
                                } catch (err) {
                                  showToast(t('admin.toast.tagDeleteError'), 'error');
                                } finally {
                                  setConfirmModal(null);
                                }
                              },
                              onCancel: () => setConfirmModal(null)
                            });
                          }}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            cursor: 'pointer',
                            color: 'var(--error)',
                            fontSize: 16,
                            padding: 0,
                            lineHeight: 1
                          }}
                          title={t('admin.tags.deleteEverywhereTooltip')}
                          disabled={loadingTags}
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ textAlign: 'center', padding: 20, color: 'var(--text-tertiary)' }}>
                    {discoveredTags.length > 0
                      ? `✅ ${t('admin.tags.allMigrated')}`
                      : t('admin.tags.noneFound')}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'export' && isAdmin && (
          <div className="admin-section">
            <div style={{ maxWidth: 800, margin: '0 auto' }}>
              <h2 style={{ marginBottom: 20 }}>📥 {t('admin.export.title')}</h2>

              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <p style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)' }}>
                  {t('admin.export.intro', { columns: 'name, username, password, url, website, notes, tags, Port' })}
                </p>
              </div>

              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                {allMounts.filter(m => m.type === 'kv').length === 0 ? (
                  <p style={{ color: 'var(--text-secondary)', fontSize: 14, padding: 20 }}>{t('admin.export.noKv')}</p>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', color: 'var(--text-primary)' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
                        {/* ADMIN-15 : alignement logique (à droite en arabe, comme les cellules) */}
                        <th style={{ textAlign: 'start', padding: '10px 16px', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>{t('admin.common.vault')}</th>
                        <th style={{ textAlign: 'start', padding: '10px 16px', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>{t('admin.common.version')}</th>
                        <th style={{ textAlign: 'start', padding: '10px 16px', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>{t('admin.common.description')}</th>
                        <th style={{ textAlign: 'end', padding: '10px 16px' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {allMounts.filter(m => m.type === 'kv').map(mount => (
                        <tr key={mount.path} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td style={{ padding: '10px 16px', fontWeight: 500 }}><Ltr>{mount.path}</Ltr></td>
                          <td style={{ padding: '10px 16px', fontSize: 13, color: 'var(--text-secondary)' }}>KV v{mount.version}</td>
                          <td style={{ padding: '10px 16px', fontSize: 13, color: 'var(--text-secondary)' }}>{mount.description || '—'}</td>
                          <td style={{ padding: '10px 16px', textAlign: 'end' }}>
                            <button
                              className="btn btn-sm"
                              onClick={() => exportMountToCsv(mount)}
                              style={{ whiteSpace: 'nowrap' }}
                            >
                              {t('admin.export.exportCsv')}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modal de confirmation */}
      {confirmModal && (
        <ConfirmModal
          title={confirmModal.title}
          message={confirmModal.message}
          danger={confirmModal.danger}
          onConfirm={confirmModal.onConfirm}
          onCancel={confirmModal.onCancel}
        />
      )}

      {/* Modal de création de coffre */}
      {showCreateMountModal && (
        <EditEngineModal
          onClose={() => setShowCreateMountModal(false)}
          onCreate={createMount}
          isAdmin={true}
        />
      )}

      {/* Modal de création de policy (passe par savePolicy : validations modérateur) */}
      {showCreatePolicyModal && (
        <CreatePolicyModal
          savePolicy={savePolicy}
          showToast={showToast}
          onCreated={(name, hcl) => {
            setSelectedPolicy(name);
            setPolicyContent(hcl);
          }}
          onClose={() => setShowCreatePolicyModal(false)}
        />
      )}

      {/* Modal de saisie du mot de passe SSH (lecture des logs d'audit distants) */}
      {sshPasswordPrompt && (
        <SshPasswordModal
          host={sshPasswordPrompt.sshConfig.host}
          username={sshPasswordPrompt.sshConfig.username}
          onSubmit={(sshPassword) => {
            const { device, sshConfig } = sshPasswordPrompt;
            setSshPasswordPrompt(null);
            // Le mot de passe n'est utilisé que pour cette lecture, jamais stocké
            readAuditLogs(device, { ...sshConfig, password: sshPassword });
          }}
          onClose={() => {
            setSshPasswordPrompt(null);
            showToast(t('admin.toast.sshPasswordRequired'), 'error');
          }}
        />
      )}

      {/* Menu contextuel pour les policies */}
      {policyContextMenu && (
        // UI-31 : role="menu" / menuitem, focus et flèches gérés par l'effet du menu (plus haut)
        <div
          ref={policyMenuRef}
          className="admin-policy-menu"
          role="menu"
          aria-label={policyContextMenu.policy}
          style={{ left: policyContextMenu.x, top: policyContextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            type="button"
            role="menuitem"
            tabIndex={-1}
            className="admin-policy-menu-item"
            onClick={() => {
              openBuilderForEdit(policyContextMenu.policy);
              setPolicyContextMenu(null);
            }}
          >
            ✏️ {t('admin.common.edit')}
          </button>
          {(isAdmin || isModerator) && (
            <>
              <div role="separator" className="admin-policy-menu-separator" />
              {policyContextMenu.policy !== 'default' && policyContextMenu.policy !== 'root' && (
                <button
                  type="button"
                  role="menuitem"
                  tabIndex={-1}
                  className="admin-policy-menu-item danger"
                  onClick={() => {
                    deletePolicy(policyContextMenu.policy);
                    setPolicyContextMenu(null);
                  }}
                >
                  🗑️ {t('common.delete')}
                </button>
              )}
            </>
          )}
        </div>
      )}

      {/* Modal de builder de policy */}
      {showPolicyBuilderModal && (
        <PolicyBuilderModal
          allMounts={allMounts}
          loadAllMounts={loadAllMounts}
          editPolicyName={editPolicyName}
          vaultUrl={vaultUrl}
          axiosConfig={axiosConfig}
          baseHeaders={baseHeaders}
          ldapAuthPath={ldapAuthPath}
          savePolicy={savePolicy}
          showToast={showToast}
          onClose={() => {
            setShowPolicyBuilderModal(false);
            setEditPolicyName(null);
          }}
        />
      )}

      {/* Modal d'activation d'audit device (mot de passe SSH saisi dans la modale, jamais stocké) */}
      {showEnableAuditModal && (
        <EnableAuditModal
          onEnable={enableAuditDevice}
          showToast={showToast}
          onClose={() => setShowEnableAuditModal(false)}
        />
      )}
    </div>
  );
}
