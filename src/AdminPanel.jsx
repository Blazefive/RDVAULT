// src/AdminPanel.jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ConfirmModal from './ConfirmModal';
import EditEngineModal from './EditEngineModal';
import UserMenu from './UserMenu.jsx';
import WindowControls from './WindowControls.jsx';
import * as tagManager from './utils/tagManager';
import secureLogger from './secureLogger';

// SÉCURITÉ: Échappement des métacaractères regex pour éviter le ReDoS
const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export default function AdminPanel({ vaultUrl, vaultNs, ldapAuthPath = 'auth/ldap', token, baseHeaders, axiosConfig, showToast, username, darkMode, onToggleDarkMode, currentView, onToggleAdminView, onLogout, hiddenEngines = [], isAdmin, isModerator, moderatorEngines = [] }) {
  const [activeTab, setActiveTab] = useState('mounts');
  const [policies, setPolicies] = useState([]);
  const [allMounts, setAllMounts] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedPolicy, setSelectedPolicy] = useState(null);
  const [policyContent, setPolicyContent] = useState('');
  const [selectedMount, setSelectedMount] = useState(null);
  const [mountPolicies, setMountPolicies] = useState([]);
  const [appliedPolicies, setAppliedPolicies] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingPolicies, setLoadingPolicies] = useState(false);

  // États pour les groupes AD
  const [adGroups, setAdGroups] = useState([]);
  const [policyGroups, setPolicyGroups] = useState({});
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [showGroupSelector, setShowGroupSelector] = useState(false);
  const [selectedGroupsForPolicy, setSelectedGroupsForPolicy] = useState([]);

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
      showToast('Erreur lors du chargement des policies', 'error');
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
      showToast('Erreur lors de la lecture de la policy', 'error');
    }
  };

  // Sauvegarder une policy
  const savePolicy = async (policyName, content) => {
    // 🔒 SÉCURITÉ: Restrictions modérateur (ne repose PAS sur les commentaires HCL)
    if (isModerator && content) {
      // 1) Bloquer les capabilities dangereuses (sudo, deny)
      const capsRegex = /capabilities\s*=\s*\[([^\]]*)\]/gi;
      let capsMatch;
      while ((capsMatch = capsRegex.exec(content)) !== null) {
        const caps = capsMatch[1].toLowerCase();
        if (caps.includes('sudo') || caps.includes('deny')) {
          showToast('Les modérateurs ne peuvent pas utiliser les capabilities "sudo" ou "deny"', 'error');
          return;
        }
      }
      // SÉCURITÉ: Bloquer aussi le keyword deprecated "policy" (alias de capabilities)
      const policyKeywordRegex = /policy\s*=\s*"([^"]+)"/gi;
      let policyKwMatch;
      while ((policyKwMatch = policyKeywordRegex.exec(content)) !== null) {
        const pol = policyKwMatch[1].toLowerCase();
        if (pol === 'sudo' || pol === 'write') {
          showToast('Les modérateurs ne peuvent pas utiliser "sudo" via le keyword "policy"', 'error');
          return;
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
          showToast('La policy contient des chemins invalides (traversal détecté)', 'error');
          return;
        }
        // Autoriser sys/mounts en lecture seule (listing), TOTP paths
        // SÉCURITÉ: Match exact pour éviter que sys/mounts/* permette mount/unmount
        if (policyPath === 'sys/mounts' || policyPath === 'sys/mounts/' || policyPath.startsWith('TOTP/')) continue;
        // Vérifier que le path est dans un engine autorisé
        const isAllowed = moderatorEngines.some(eng => policyPath.startsWith(eng + '/') || policyPath === eng + '/*');
        if (!isAllowed) {
          showToast('La policy contient des chemins non autorisés pour un modérateur', 'error');
          return;
        }
      }
    }

    try {
      await axios.put(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, {
        policy: content
      }, axiosConfig({ headers: baseHeaders() }));
      showToast(`Policy "${policyName}" sauvegardée`, 'success');
      await loadPolicies();
    } catch (err) {
      showToast('Erreur lors de la sauvegarde de la policy', 'error');
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
          showToast('Vous ne pouvez pas supprimer une policy contenant des droits modérateur', 'error');
          return;
        }
      } catch (err) {
        showToast('Erreur lors de la vérification de la policy', 'error');
        return;
      }
    }

    setConfirmModal({
      title: 'Supprimer la policy',
      message: `Voulez-vous vraiment supprimer la policy "${policyName}" ?`,
      danger: true,
      onConfirm: async () => {
        setConfirmModal(null);
        try {
          await axios.delete(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
          showToast(`Policy "${policyName}" supprimée`, 'success');
          setPolicyContent('');
          setSelectedPolicy(null);
          await loadPolicies();
        } catch (err) {
          showToast('Erreur lors de la suppression de la policy', 'error');
        }
      },
      onCancel: () => setConfirmModal(null)
    });
  };

  // Charger les groupes AD disponibles
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
    } catch (err) {
      showToast('Erreur lors du chargement des groupes AD', 'error');
      setAdGroups([]);
    } finally {
      setLoadingGroups(false);
    }
  };

  // Charger les groupes liés à une policy
  const loadPolicyGroups = async (policyName) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/${ldapAuthPath}/groups/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
      return res.data?.data?.policies || [];
    } catch (err) {
      return [];
    }
  };

  // Charger tous les groupes liés aux policies
  const loadAllPolicyGroups = async () => {
    try {
      const groupsMap = {};
      for (const group of adGroups) {
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

      showToast(`Groupe "${groupName}" ${add ? 'lié à' : 'délié de'} la policy "${policyName}"`, 'success');
      await loadAllPolicyGroups();
    } catch (err) {
      showToast('Erreur lors de la modification de la liaison groupe/policy', 'error');
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
        showToast('Permissions insuffisantes pour lire la config LDAP', 'error');
      } else {
        showToast('Erreur lors du chargement de la configuration LDAP', 'error');
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
      await loadAdGroups();
      await loadAllPolicyGroups();

      // Mettre à jour le compteur
      setLdapGroupsCount(adGroups.length);

      showToast(`${adGroups.length} groupe(s) AD synchronisé(s)`, 'success');
    } catch (err) {
      showToast('Erreur lors de la synchronisation des groupes', 'error');
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
        .filter(mount => !['cubbyhole', 'identity', 'sys', 'tags-shared', 'totp', 'pki'].includes(mount.path.toLowerCase()));

      // 🔒 Filtrage pour les modérateurs : ne montrer que leurs engines autorisés
      if (isModerator && moderatorEngines.length > 0) {
        mountsList = mountsList.filter(mount => moderatorEngines.includes(mount.path));
      }

      setAllMounts(mountsList);
    } catch (err) {
      secureLogger.error('[Admin] Erreur chargement mounts');
      showToast('Erreur lors du chargement des coffres', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Créer un nouveau mount/coffre
  const createMount = async ({ name, version, description }) => {
    const mountPath = name.replace(/^\/+|\/+$/g, '');
    // SÉCURITÉ: Vérifier que le modérateur crée dans son périmètre
    if (isModerator && !moderatorEngines.some(eng => mountPath === eng || mountPath.startsWith(eng + '/'))) {
      showToast('Vous ne pouvez créer des coffres que dans votre périmètre', 'error');
      return;
    }
    const body = {
      type: 'kv',
      description: description || undefined,
      options: { version: String(version) }
    };
    try {
      await axios.post(`${vaultUrl}/v1/sys/mounts/${encodeURIComponent(mountPath)}`, body, axiosConfig({ headers: baseHeaders() }));
      showToast(`Coffre "${mountPath}" (kv${version}) créé.`, 'success');
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
      showToast('Erreur lors de la création du coffre', 'error');
      throw err;
    }
  };

  // Supprimer un mount
  const deleteMount = async (mountPath) => {
    // SÉCURITÉ: Vérifier que le modérateur supprime dans son périmètre
    if (isModerator && !moderatorEngines.some(eng => mountPath === eng || mountPath.startsWith(eng + '/'))) {
      showToast('Vous ne pouvez supprimer que les coffres de votre périmètre', 'error');
      return;
    }
    setConfirmModal({
      title: 'Supprimer le coffre',
      message: `Supprimer le coffre "${mountPath}" ? Tous les secrets seront perdus !`,
      danger: true,
      onConfirm: async () => {
        setConfirmModal(null);
        try {
          // Désélectionner le mount avant suppression
          if (selectedMount?.path === mountPath) {
            setSelectedMount(null);
            setMountPolicies([]);
            setAppliedPolicies([]);
          }

          await axios.delete(`${vaultUrl}/v1/sys/mounts/${encodeURIComponent(mountPath)}`, axiosConfig({ headers: baseHeaders() }));
          showToast(`Coffre "${mountPath}" supprimé`, 'success');
          await loadAllMounts();
        } catch (err) {
          showToast('Erreur lors de la suppression du coffre', 'error');
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
      showToast('Erreur lors du chargement des policies', 'error');
      return [];
    }
  };

  // Vérifier si une policy est appliquée à un mount (en lisant son contenu)
  const checkPolicyForMount = async (policyName, mountPath) => {
    try {
      const res = await axios.get(`${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`, axiosConfig({ headers: baseHeaders() }));
      const content = res.data?.data?.policy || res.data?.policy || '';

      // Vérifier si le contenu contient le path du mount
      // Patterns possibles: "mountPath/*", "mountPath/data/*", "mountPath/metadata/*"
      const patterns = [
        `"${mountPath}/*"`,
        `"${mountPath}/data/*"`,
        `"${mountPath}/metadata/*"`,
        `'${mountPath}/*'`,
        `'${mountPath}/data/*'`,
        `'${mountPath}/metadata/*'`
      ];

      return patterns.some(pattern => content.includes(pattern));
    } catch (err) {
      return false;
    }
  };

  // Charger les policies appliquées à un mount
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

  // Associer une policy à un mount (via une policy path)
  const applyPolicyToMount = async (mountPath, policyName) => {
    try {
      // SÉCURITÉ: Vérifier périmètre modérateur
      if (isModerator && !moderatorEngines.some(eng => mountPath === eng || mountPath.startsWith(eng + '/'))) {
        showToast('Vous ne pouvez appliquer des policies que dans votre périmètre', 'error');
        return;
      }
      // Créer ou mettre à jour une policy spécifique pour ce mount
      const safeMountPath = mountPath.replace(/[\r\n"\\*+]/g, '');
      const policyContent = `path "${safeMountPath}/*" {\n  capabilities = ["create", "read", "update", "delete", "list"]\n}`;

      // SÉCURITÉ: Passer par savePolicy pour appliquer les validations modérateur
      await savePolicy(policyName, policyContent);

      showToast(`Policy "${policyName}" appliquée à "${mountPath}"`, 'success');

      // Recharger les policies appliquées pour mettre à jour l'affichage
      if (selectedMount) {
        setLoadingPolicies(true);
        const { allPolicies, appliedPolicies: applied } = await loadAppliedPolicies(mountPath);
        setMountPolicies(allPolicies);
        setAppliedPolicies(applied);
        setLoadingPolicies(false);
      }
    } catch (err) {
      showToast('Erreur lors de l\'application de la policy', 'error');
    }
  };

  // Helper CSV : échapper les champs (remplace les sauts de ligne par des espaces pour garder 1 ligne = 1 secret)
  const escapeCsvField = (field) => {
    const str = String(field ?? '').replace(/\r?\n/g, ' ').replace(/\r/g, ' ');
    return (str.includes(';') || str.includes('"')) ? `"${str.replace(/"/g, '""')}"` : str;
  };

  // Lister récursivement les clés d'un mount
  const listKeysRecursive = async (mountPath, version, prefix = '') => {
    try {
      const url = version === 2
        ? `${vaultUrl}/v1/${mountPath}/metadata/${prefix}?list=true`
        : `${vaultUrl}/v1/${mountPath}/${prefix}?list=true`;
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
      showToast('Export en cours...', 'info');
      const version = mount.version || 1;
      const keys = await listKeysRecursive(mount.path, version);

      if (keys.length === 0) {
        showToast('Aucun secret trouvé dans ce coffre', 'warning');
        return;
      }

      const rows = [];
      for (const key of keys) {
        try {
          const secretRes = version === 2
            ? await axios.get(`${vaultUrl}/v1/${mount.path}/data/${key}`, axiosConfig({ headers: baseHeaders() }))
            : await axios.get(`${vaultUrl}/v1/${mount.path}/${key}`, axiosConfig({ headers: baseHeaders() }));
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
            escapeCsvField(name),
            escapeCsvField(username),
            escapeCsvField(password),
            escapeCsvField(urlVal),
            escapeCsvField(website),
            escapeCsvField(notes),
            escapeCsvField(tags),
            escapeCsvField(port)
          ].join(';'));
        } catch {
          // Ignorer les erreurs de lecture individuelle
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

      showToast(`Export terminé : ${rows.length} secret${rows.length > 1 ? 's' : ''} exporté${rows.length > 1 ? 's' : ''}`, 'success');
    } catch (err) {
      showToast('Erreur lors de l\'export CSV', 'error');
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
        showToast('Permissions insuffisantes pour lire les audit devices', 'error');
      } else {
        showToast('Erreur lors du chargement des audit devices', 'error');
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
      showToast(`Audit device "${path}" activé`, 'success');
      await loadAuditDevices();
    } catch (err) {
      secureLogger.error('[Admin] Erreur activation audit device');
      showToast('Erreur lors de l\'activation de l\'audit device', 'error');
    }
  };

  // Désactiver un audit device
  const disableAuditDevice = async (path) => {
    setConfirmModal({
      title: 'Désactiver l\'audit device',
      message: `Voulez-vous vraiment désactiver l'audit device "${path}" ?`,
      danger: true,
      onConfirm: async () => {
        setConfirmModal(null);
        try {
          await axios.delete(`${vaultUrl}/v1/sys/audit/${encodeURIComponent(path)}`, axiosConfig({ headers: baseHeaders() }));
          showToast(`Audit device "${path}" désactivé`, 'success');

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
          showToast('Erreur lors de la désactivation de l\'audit device', 'error');
        }
      },
      onCancel: () => setConfirmModal(null)
    });
  };

  // Charger les logs d'un audit device
  const loadAuditLogs = async (device) => {
    secureLogger.debug('[Audit] loadAuditLogs');

    if (!device?.options?.file_path) {
      showToast('Aucun chemin de fichier configuré pour cet audit device', 'error');
      return;
    }

    if (!window.electronAudit?.tailLogFile) {
      showToast('Fonctionnalité de lecture de logs non disponible (redémarrez l\'application)', 'error');
      return;
    }

    try {
      setLoadingLogs(true);

      // Récupérer la configuration SSH si elle existe
      // SÉCURITÉ: Appliquer la même sanitisation qu'à l'écriture (cohérence des clés)
      const safeDevicePath = device.path.replace(/[^a-zA-Z0-9._-]/g, '_');
      const sshConfigKey = `vault-audit-ssh-${safeDevicePath}`;
      let sshConfig = null;
      try {
        const storedConfig = localStorage.getItem(sshConfigKey);
        if (storedConfig) {
          sshConfig = JSON.parse(storedConfig);

          // 🔒 SÉCURITÉ : Demander le mot de passe SSH à chaque fois
          if (sshConfig && sshConfig.host) {
            const sshPassword = prompt(`Mot de passe SSH pour ${sshConfig.username}@${sshConfig.host}:`);
            if (!sshPassword) {
              showToast('Mot de passe SSH requis pour lire les logs distants', 'error');
              setLoadingLogs(false);
              return;
            }
            sshConfig.password = sshPassword; // Ajouter temporairement pour cette lecture uniquement
          }
        }
      } catch (err) {
        secureLogger.error('[Audit] Erreur lecture config SSH');
      }

      const result = await window.electronAudit.tailLogFile(device.options.file_path, 100, sshConfig);

      if (result.success) {
        setAuditLogs(result.logs || []);
        if (result.totalLines > result.loadedLines) {
          showToast(`${result.loadedLines} dernières entrées chargées (${result.totalLines} au total)`, 'info');
        } else {
          showToast(`${result.loadedLines} entrées chargées`, 'success');
        }
      } else {
        secureLogger.error('[Audit] Erreur lecture logs');
        showToast('Erreur lors de la lecture des logs d\'audit', 'error');
        setAuditLogs([]);
      }
    } catch (err) {
      secureLogger.error('[Audit] Exception lecture logs');
      showToast('Erreur lors de la lecture des logs d\'audit', 'error');
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
      const mountsRes = await axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders() }));
      const mountsData = mountsRes.data?.data || mountsRes.data || {};

      const allAccessibleMounts = Object.entries(mountsData)
        .map(([path, config]) => ({
          path: path.replace(/\/$/, ''),
          type: config.type,
          version: Number(config.options?.version) || 1
        }))
        .filter(mount => mount.type === 'kv' && !['cubbyhole', 'identity', 'sys', 'tags-shared', 'totp', 'pki'].includes(mount.path.toLowerCase()));

      let modifiedCount = 0;

      for (const mount of allAccessibleMounts) {
        try {
          if (mount.version === 2) {
            // KV v2
            const listRes = await axios.get(
              `${vaultUrl}/v1/${mount.path}/metadata?list=true`,
              axiosConfig({ headers: baseHeaders() })
            );
            const keys = (listRes.data?.data?.keys || []).filter(k => !k.endsWith('/'));

            for (const key of keys) {
              try {
                const secretRes = await axios.get(
                  `${vaultUrl}/v1/${mount.path}/data/${encodeURIComponent(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const data = secretRes.data?.data?.data || {};

                if (data.Tags && data.Tags.includes(tagToRemove)) {
                  // Retirer le tag
                  const currentTags = data.Tags.split(/[\s,;]+/).filter(t => t && t.trim() !== tagToRemove);
                  const newTags = currentTags.join(' ');

                  // Mettre à jour le secret
                  await axios.post(
                    `${vaultUrl}/v1/${mount.path}/data/${encodeURIComponent(key)}`,
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
            const listRes = await axios.get(
              `${vaultUrl}/v1/${mount.path}?list=true`,
              axiosConfig({ headers: baseHeaders() })
            );
            const keys = (listRes.data?.data?.keys || []).filter(k => !k.endsWith('/'));

            for (const key of keys) {
              try {
                const secretRes = await axios.get(
                  `${vaultUrl}/v1/${mount.path}/${encodeURIComponent(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const data = secretRes.data?.data || {};

                if (data.Tags && data.Tags.includes(tagToRemove)) {
                  // Retirer le tag
                  const currentTags = data.Tags.split(/[\s,;]+/).filter(t => t && t.trim() !== tagToRemove);
                  const newTags = currentTags.join(' ');

                  // Mettre à jour le secret
                  await axios.post(
                    `${vaultUrl}/v1/${mount.path}/${encodeURIComponent(key)}`,
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
      showToast(`Tag "${tagToRemove}" supprimé de ${modifiedCount} entrée(s)`, 'success');
    } catch (err) {
      secureLogger.error('[TAGS] Erreur suppression tag');
      throw err;
    } finally {
      setLoadingTags(false);
    }
  };

  // Fonction pour charger les tags découverts dans les coffres accessibles
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
          description: 'Coffre pour les tags partagés'
        },
        axiosConfig({ headers: baseHeaders() })
      );

      showToast('Coffre tags-shared créé automatiquement', 'success');
      return true;
    } catch (err) {
      secureLogger.error('[TAGS] Erreur création coffre tags-shared');
      if (err.response?.status === 403) {
        showToast('Permissions insuffisantes pour créer le coffre tags-shared. Contactez un administrateur.', 'error');
      } else {
        showToast('Erreur lors de la création du coffre de tags partagés', 'error');
      }
      return false;
    }
  };

  const loadSharedTags = async () => {
    try {
      setLoadingTags(true);
      secureLogger.debug('[TAGS] Chargement des tags depuis tous les coffres');

      // Charger TOUS les coffres accessibles (pas seulement ceux du panel admin)
      const mountsRes = await axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders() }));
      const mountsData = mountsRes.data?.data || mountsRes.data || {};

      const allAccessibleMounts = Object.entries(mountsData)
        .map(([path, config]) => ({
          path: path.replace(/\/$/, ''),
          type: config.type,
          version: Number(config.options?.version) || 1
        }))
        .filter(mount => mount.type === 'kv' && !['cubbyhole', 'identity', 'sys', 'tags-shared', 'totp', 'pki'].includes(mount.path.toLowerCase()));

      const allSecrets = [];
      for (const mount of allAccessibleMounts) {
        try {
          if (mount.version === 2) {
            // KV v2 - Lire depuis /data/
            const listRes = await axios.get(
              `${vaultUrl}/v1/${mount.path}/metadata?list=true`,
              axiosConfig({ headers: baseHeaders() })
            );
            const keys = (listRes.data?.data?.keys || []).filter(k => !k.endsWith('/'));

            for (const key of keys) {
              try {
                const secretRes = await axios.get(
                  `${vaultUrl}/v1/${mount.path}/data/${encodeURIComponent(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const data = secretRes.data?.data?.data || {};

                if (data.Tags) {
                  allSecrets.push({ tags: data.Tags });
                }
              } catch (err) {
                // Ignorer les erreurs de lecture individuelle
              }
            }
          } else {
            // KV v1
            const listRes = await axios.get(
              `${vaultUrl}/v1/${mount.path}?list=true`,
              axiosConfig({ headers: baseHeaders() })
            );
            const keys = (listRes.data?.data?.keys || []).filter(k => !k.endsWith('/'));

            for (const key of keys) {
              try {
                const secretRes = await axios.get(
                  `${vaultUrl}/v1/${mount.path}/${encodeURIComponent(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const data = secretRes.data?.data || {};
                if (data.Tags) {
                  allSecrets.push({ tags: data.Tags });
                }
              } catch (err) {
                // Ignorer les erreurs de lecture individuelle
              }
            }
          }
        } catch (err) {
          secureLogger.debug('[TAGS] Impossible de lire un coffre');
        }
      }

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
      showToast('Erreur lors du chargement des tags', 'error');
    } finally {
      setLoadingTags(false);
    }
  };

  // Charger les liens policies-groupes quand les groupes sont chargés
  useEffect(() => {
    if (adGroups.length > 0) {
      loadAllPolicyGroups();
    }
  }, [adGroups]);

  // Fermer le menu contextuel lors du clic
  useEffect(() => {
    const closeMenu = () => setPolicyContextMenu(null);
    document.addEventListener('click', closeMenu);
    return () => document.removeEventListener('click', closeMenu);
  }, []);

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
          <div style={{
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
            <h1>🛡️ Panel Administration</h1>
            <p className="admin-subtitle">Gestion complète de Vault</p>
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
      <div className="admin-tabs">
        <button
          className={`admin-tab ${activeTab === 'mounts' ? 'active' : ''}`}
          onClick={() => setActiveTab('mounts')}
        >
          📦 Coffres
        </button>
        <button
          className={`admin-tab ${activeTab === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveTab('policies')}
        >
          📜 Policies
        </button>
        {isAdmin && (
          <button
            className={`admin-tab ${activeTab === 'auth' ? 'active' : ''}`}
            onClick={() => setActiveTab('auth')}
          >
            👥 Auth Methods
          </button>
        )}
        {isAdmin && (
          <button
            className={`admin-tab ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            📊 Audit
          </button>
        )}
        {(isAdmin || isModerator) && (
          <button
            className={`admin-tab ${activeTab === 'tags' ? 'active' : ''}`}
            onClick={() => setActiveTab('tags')}
          >
            🏷️ Tags
          </button>
        )}
        {isAdmin && (
          <button
            className={`admin-tab ${activeTab === 'export' ? 'active' : ''}`}
            onClick={() => setActiveTab('export')}
          >
            📥 Export
          </button>
        )}
      </div>

      {/* Contenu selon l'onglet */}
      <div className="admin-content">
        {activeTab === 'mounts' && (
          <div className="admin-section">
            <div className="admin-split">
              {/* Liste des mounts */}
              <div className="admin-list">
                <div className="admin-list-header">
                  <h3>Coffres disponibles</h3>
                  {(isAdmin || isModerator) && (
                    <button
                      type="button"
                      className="btn btn-success btn-sm"
                      onClick={() => setShowCreateMountModal(true)}
                    >
                      + Nouveau
                    </button>
                  )}
                </div>
                {loading ? (
                  <p>Chargement...</p>
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
                          setMountPolicies([]);
                          setAppliedPolicies([]);

                          const { allPolicies, appliedPolicies: applied } = await loadAppliedPolicies(mount.path);
                          setMountPolicies(allPolicies);
                          setAppliedPolicies(applied);
                          setLoadingPolicies(false);
                        }}
                      >
                        <span>
                          📦 {mount.path}/
                          {isHidden && <span style={{ marginLeft: '8px', fontSize: '11px', color: '#f59e0b', fontWeight: '600' }}>(masqué)</span>}
                        </span>
                        {(isAdmin || isModerator) && (
                          <button
                            className="btn-mini btn-danger"
                            onClick={(e) => { e.stopPropagation(); deleteMount(mount.path); }}
                          >
                            ✕
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
                      <h3>Coffre: {selectedMount.path}/</h3>
                    </div>
                    <div className="mount-details">
                      <p><strong>Type:</strong> {selectedMount.type}</p>
                      <p><strong>Version:</strong> {selectedMount.type === 'kv' ? `v${selectedMount.version}` : '-'}</p>
                      <p><strong>Description:</strong> {selectedMount.description || 'Aucune'}</p>
                    </div>

                    <h4 style={{ marginTop: '24px', marginBottom: '12px' }}>
                      Policies liées
                      {appliedPolicies.length > 0 && (
                        <span style={{ marginLeft: '12px', fontSize: '13px', color: '#10b981', fontWeight: 'normal' }}>
                          ({appliedPolicies.length} policy{appliedPolicies.length > 1 ? 's' : ''})
                        </span>
                      )}
                    </h4>
                    {loadingPolicies ? (
                      <p style={{ color: '#6b7280', fontSize: '14px' }}>🔄 Chargement et vérification des policies...</p>
                    ) : appliedPolicies.length > 0 ? (
                      <div className="policy-selector">
                        {appliedPolicies.map(policy => {
                          return (
                            <div
                              key={policy}
                              className="policy-badge"
                              style={{
                                marginRight: '8px',
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
                              ✓ {policy}
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <p style={{ color: '#6b7280', fontSize: '14px' }}>Aucune policy liée à ce coffre</p>
                    )}

                    <div className="admin-help" style={{ marginTop: '24px' }}>
                      <p><strong>💡 Information :</strong></p>
                      <p>Les policies listées ci-dessus donnent accès à <code>{selectedMount.path}/*</code>. Gérez les policies et leurs groupes AD dans l'onglet "Policies".</p>
                    </div>
                  </>
                ) : (
                  <div className="admin-empty">
                    <p>Sélectionnez un coffre pour gérer ses policies</p>
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
                  <h3>Policies disponibles</h3>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={() => setShowPolicyBuilderModal(true)}
                      title="Construire une policy visuellement"
                    >
                      🛠️ Builder
                    </button>
                    {(isAdmin || isModerator) && (
                      <button
                        type="button"
                        className="btn btn-success btn-sm"
                        onClick={() => setShowCreatePolicyModal(true)}
                      >
                        + Nouvelle
                      </button>
                    )}
                  </div>
                </div>
                {loading ? (
                  <p>Chargement...</p>
                ) : (
                  <ul className="admin-items-list">
                    {policies.map(policy => (
                      <li
                        key={policy}
                        className={`admin-item ${selectedPolicy === policy ? 'active' : ''}`}
                        onClick={() => loadPolicyContent(policy)}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          setPolicyContextMenu({
                            x: e.clientX,
                            y: e.clientY,
                            policy
                          });
                        }}
                      >
                        <span>📜 {policy}</span>
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
                      <h3>Policy: {selectedPolicy}</h3>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => openBuilderForEdit(selectedPolicy)}
                          title="Modifier avec le builder"
                        >
                          ✏️ Modifier
                        </button>
                        <button
                          className="btn btn-primary btn-sm"
                          onClick={() => savePolicy(selectedPolicy, policyContent)}
                        >
                          💾 Sauvegarder
                        </button>
                      </div>
                    </div>
                    <textarea
                      className="admin-textarea"
                      value={policyContent}
                      onChange={(e) => setPolicyContent(e.target.value)}
                      placeholder="Contenu de la policy en HCL..."
                      spellCheck={false}
                      style={{ marginBottom: '16px' }}
                    />

                    {/* Section groupes AD */}
                    <div style={{ marginBottom: '16px', padding: '16px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                      <div style={{ marginTop: '0', marginBottom: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <h4 style={{ margin: '0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span>👥 Groupes AD liés</span>
                          {policyGroups[selectedPolicy] && policyGroups[selectedPolicy].length > 0 && (
                            <span style={{ fontSize: '13px', color: '#10b981', fontWeight: 'normal' }}>
                              ({policyGroups[selectedPolicy].length} groupe{policyGroups[selectedPolicy].length > 1 ? 's' : ''})
                            </span>
                          )}
                        </h4>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={async () => {
                            await loadAdGroups();
                            await loadAllPolicyGroups();
                            showToast('Groupes AD rechargés', 'success');
                          }}
                          disabled={loadingGroups}
                          style={{ fontSize: '12px', padding: '4px 10px' }}
                          title="Recharger la liste des groupes AD"
                        >
                          🔄 Actualiser
                        </button>
                      </div>

                      {loadingGroups ? (
                        <p style={{ color: '#6b7280', fontSize: '14px' }}>🔄 Chargement des groupes AD...</p>
                      ) : (
                        <>
                          {/* Groupes liés */}
                          {policyGroups[selectedPolicy] && policyGroups[selectedPolicy].length > 0 && (
                            <div style={{ marginBottom: '12px' }}>
                              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px' }}>Groupes ayant accès via cette policy :</p>
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
                                    ✓ {group}
                                    <button
                                      className="btn-mini btn-danger"
                                      style={{ marginLeft: '4px' }}
                                      onClick={() => toggleGroupForPolicy(group, selectedPolicy, false)}
                                      title="Retirer ce groupe"
                                    >
                                      ✕
                                    </button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Groupes disponibles */}
                          {adGroups.length > 0 && (
                            <div>
                              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px' }}>Ajouter un groupe AD :</p>
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
                                      + {group}
                                    </button>
                                  ))}
                              </div>
                              {adGroups.filter(group => !policyGroups[selectedPolicy]?.includes(group)).length === 0 && (
                                <p style={{ color: '#6b7280', fontSize: '13px', fontStyle: 'italic' }}>Tous les groupes sont déjà liés</p>
                              )}
                            </div>
                          )}

                          {adGroups.length === 0 && (
                            <p style={{ color: '#6b7280', fontSize: '14px' }}>Aucun groupe AD configuré dans Vault</p>
                          )}
                        </>
                      )}
                    </div>

                    <div className="admin-help">
                      <p><strong>Exemples de capabilities:</strong></p>
                      <code>read, create, update, delete, list, sudo, deny</code>
                      <p><strong>Exemple:</strong></p>
                      <pre>{`path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}`}</pre>
                    </div>
                  </>
                ) : (
                  <div className="admin-empty">
                    <p>Sélectionnez une policy pour l'éditer</p>
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
                🔐 Authentification LDAP
              </h3>

              {loadingLdap ? (
                <p style={{ color: '#6b7280', fontSize: '14px' }}>🔄 Chargement de la configuration LDAP...</p>
              ) : ldapConfig ? (
                <>
                  {/* Configuration LDAP */}
                  <div style={{ marginBottom: '24px', padding: '20px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600' }}>
                        📋 Configuration du serveur LDAP
                      </h4>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={loadLdapConfig}
                        style={{ fontSize: '12px', padding: '4px 10px' }}
                      >
                        🔄 Actualiser
                      </button>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '12px', fontSize: '14px' }}>
                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>Serveur :</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.url || 'Non configuré'}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>Base DN utilisateurs :</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.userdn || ldapConfig.binddn || 'Non configuré'}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>Base DN groupes :</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.groupdn || 'Non configuré'}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>Filtre groupes :</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                        {ldapConfig.groupfilter || 'Par défaut'}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>Attribut groupes :</div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                        {ldapConfig.groupattr || 'cn (par défaut)'}
                      </div>

                      <div style={{ fontWeight: '600', color: 'var(--text-secondary)' }}>Case sensitive :</div>
                      <div style={{ color: 'var(--text-primary)' }}>
                        {ldapConfig.case_sensitive_names === false ? '❌ Non' : '✓ Oui'}
                      </div>
                    </div>
                  </div>

                  {/* Synchronisation des groupes */}
                  <div style={{ marginBottom: '24px', padding: '20px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <h4 style={{ margin: 0, fontSize: '16px', fontWeight: '600' }}>
                        👥 Groupes Active Directory
                      </h4>
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        onClick={syncLdapGroups}
                        disabled={loadingGroups}
                        style={{ fontSize: '12px', padding: '6px 14px' }}
                      >
                        {loadingGroups ? '🔄 Synchronisation...' : '🔄 Synchroniser les groupes'}
                      </button>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
                      <div style={{ fontSize: '32px', fontWeight: '700', color: 'var(--primary)' }}>
                        {ldapGroupsCount}
                      </div>
                      <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
                        groupe{ldapGroupsCount > 1 ? 's' : ''} configuré{ldapGroupsCount > 1 ? 's' : ''} dans Vault
                      </div>
                    </div>

                    {adGroups.length > 0 && (
                      <div>
                        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px', fontWeight: '600' }}>
                          Liste des groupes :
                        </p>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', maxHeight: '200px', overflow: 'auto', padding: '8px', background: '#f9fafb', borderRadius: '6px' }}>
                          {adGroups.map(group => (
                            <div
                              key={group}
                              style={{
                                padding: '4px 10px',
                                background: '#fff',
                                border: '1px solid #e5e7eb',
                                borderRadius: 'var(--radius-sm)',
                                fontSize: '12px',
                                color: '#374151',
                                fontFamily: 'monospace'
                              }}
                            >
                              {group}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Informations et explications */}
                  <div className="admin-help">
                    <p><strong>💡 À propos de la synchronisation LDAP :</strong></p>
                    <ul style={{ fontSize: '13px', lineHeight: '1.6', marginTop: '8px' }}>
                      <li><strong>Synchronisation automatique :</strong> Un script cron s'exécute toutes les 3 minutes sur le serveur Vault pour synchroniser automatiquement les groupes depuis <code>OU=VAULT,OU=Groupes,DC=lab,DC=proxmox</code>. Les nouveaux groupes AD sont automatiquement ajoutés à Vault avec la policy par défaut, et les groupes supprimés de l'AD sont retirés de Vault.</li>
                      <li><strong>Groupes configurés :</strong> Les groupes listés ci-dessus sont automatiquement synchronisés depuis votre Active Directory. Chaque groupe est créé dans Vault avec <code>policy=default</code> lors de la première synchronisation.</li>
                      <li><strong>Ajout de groupes :</strong> Pour ajouter un nouveau groupe AD à Vault :
                        <ol style={{ marginTop: '4px', marginLeft: '20px' }}>
                          <li>Créez le groupe dans l'OU <code>VAULT\Groupes</code> de votre Active Directory</li>
                          <li>Attendez 3 minutes maximum (synchronisation automatique via cron)</li>
                          <li>Le nouveau groupe apparaîtra automatiquement dans Vault avec <code>policy=default</code></li>
                          <li>Assignez ensuite les policies souhaitées au groupe via l'onglet "Policies"</li>
                        </ol>
                      </li>
                      <li><strong>Script de synchronisation :</strong> Le script <code>/usr/local/bin/vault_sync_ad_groups.sh</code> gère automatiquement l'ajout et la suppression des groupes. Les logs sont disponibles dans <code>/var/log/vault_sync_ad_groups.log</code>.</li>
                    </ul>
                  </div>
                </>
              ) : (
                <div style={{ padding: '40px', textAlign: 'center', background: '#fef3c7', border: '1px solid #fbbf24', borderRadius: '8px' }}>
                  <div style={{ fontSize: '48px', marginBottom: '12px' }}>⚠️</div>
                  <p style={{ fontSize: '16px', fontWeight: '600', color: '#92400e', marginBottom: '8px' }}>
                    Configuration LDAP non disponible
                  </p>
                  <p style={{ fontSize: '13px', color: '#78350f' }}>
                    Vous n'avez pas les permissions pour lire la configuration LDAP ou celle-ci n'est pas configurée.
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
                  <h3>Audit Devices</h3>
                  <button
                    type="button"
                    className="btn btn-success btn-sm"
                    onClick={() => setShowEnableAuditModal(true)}
                  >
                    + Activer
                  </button>
                </div>
                {loadingAudit ? (
                  <p>Chargement...</p>
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
                        <div>
                          <span>📊 {device.path}/</span>
                          <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4 }}>
                            Type: {device.type}
                            {device.options?.file_path && ` | Fichier: ${device.options.file_path}`}
                          </div>
                        </div>
                        <button
                          className="btn-mini btn-danger"
                          onClick={(e) => { e.stopPropagation(); disableAuditDevice(device.path); }}
                        >
                          ✕
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div style={{ padding: 16, color: '#6b7280', fontSize: 14 }}>
                    Aucun audit device activé
                  </div>
                )}
              </div>

              {/* Affichage des logs */}
              <div className="admin-editor">
                <div className="admin-editor-header">
                  <h3>📋 Logs d'Audit</h3>
                  {selectedAuditDevice && (
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => loadAuditLogs(selectedAuditDevice)}
                      disabled={loadingLogs}
                    >
                      🔄 Actualiser
                    </button>
                  )}
                </div>

                {selectedAuditDevice ? (
                  <div>
                    {/* Info sur le device sélectionné */}
                    <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 8, padding: 12, marginBottom: 16 }}>
                      <div style={{ fontWeight: 600, marginBottom: 8, color: '#1e40af' }}>
                        📊 {selectedAuditDevice.path}/
                      </div>
                      <p style={{ fontSize: 13, color: '#374151', margin: 0 }}>
                        <strong>Type:</strong> {selectedAuditDevice.type}
                        {selectedAuditDevice.options?.file_path && (
                          <>
                            <br /><strong>Fichier:</strong> <code style={{ fontSize: 11, background: '#fff', padding: '2px 6px', borderRadius: 4 }}>
                              {selectedAuditDevice.options.file_path}
                            </code>
                          </>
                        )}
                      </p>
                    </div>

                    {/* Logs */}
                    {loadingLogs ? (
                      <div style={{ textAlign: 'center', padding: 40, color: '#6b7280' }}>
                        🔄 Chargement des logs...
                      </div>
                    ) : auditLogs.length > 0 ? (
                      <div>
                        <h4 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>
                          Dernières entrées ({auditLogs.length})
                        </h4>
                        <div style={{ background: '#1f2937', color: '#e5e7eb', padding: 12, borderRadius: 8, fontSize: 11, fontFamily: 'monospace', maxHeight: 500, overflow: 'auto' }}>
                          {auditLogs.map((log, idx) => {
                            const time = log.time ? new Date(log.time).toLocaleString('fr-FR') : 'N/A';
                            const type = log.type || 'unknown';
                            const username = log.auth?.display_name || log.auth?.metadata?.username || 'unknown';
                            const operation = log.request?.operation || 'unknown';
                            const path = log.request?.path || 'unknown';
                            const statusCode = log.response?.status_code;
                            const isError = statusCode && statusCode >= 400;

                            return (
                              <div key={idx} style={{ marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid #374151' }}>
                                <div>
                                  <span style={{ color: '#9ca3af' }}>[{time}]</span>{' '}
                                  <span style={{ color: isError ? '#ef4444' : '#10b981' }}>
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
                      <div style={{ textAlign: 'center', padding: 40, color: '#6b7280' }}>
                        Aucun log disponible
                      </div>
                    )}

                    <div className="admin-help" style={{ marginTop: 20 }}>
                      <p><strong>💡 À propos des logs :</strong></p>
                      <p style={{ fontSize: 13 }}>
                        • Les 100 dernières entrées sont affichées<br />
                        • Cliquez sur "Actualiser" pour recharger<br />
                        • Format JSON natif de Vault
                      </p>
                    </div>
                  </div>
                ) : auditDevices.length > 0 ? (
                  <div className="admin-empty">
                    <p>Sélectionnez un audit device pour voir ses logs</p>
                    <p style={{ fontSize: 13, color: '#6b7280', marginTop: 12 }}>
                      Cliquez sur un device dans la liste de gauche pour afficher ses logs d'audit.
                    </p>
                  </div>
                ) : (
                  <div className="admin-empty">
                    <p>Activez un audit device pour commencer à enregistrer les logs</p>
                    <p style={{ fontSize: 13, color: '#6b7280', marginTop: 12 }}>
                      Les logs d'audit enregistrent toutes les opérations effectuées dans Vault : qui, quand, quelle action, sur quelle ressource.
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
              <h2 style={{ marginBottom: 20 }}>🏷️ Gestion des Tags</h2>

              <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <p style={{ margin: 0, fontSize: 14, color: '#1e40af' }}>
                  Créez des tags partagés et consultez les tags utilisés dans vos coffres.
                </p>
              </div>

              {/* Créer un nouveau tag partagé */}
              <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8, padding: 20, marginBottom: 20 }}>
                <h3 style={{ fontSize: 16, marginBottom: 12 }}>➕ Créer un tag partagé</h3>
                <form onSubmit={async (e) => {
                  e.preventDefault();
                  const tagInput = e.target.elements.newTag;
                  const newTag = tagInput.value.trim();
                  if (!newTag) {
                    showToast('Le nom du tag ne peut pas être vide', 'error');
                    return;
                  }
                  // SÉCURITÉ: Valider le format du tag
                  if (newTag.length > 64 || /[\x00-\x1F\x7F\r\n\\/".]/.test(newTag)) {
                    showToast('Nom de tag invalide (max 64 caractères, pas de caractères spéciaux)', 'error');
                    return;
                  }
                  if (sharedTags.includes(newTag)) {
                    showToast('Ce tag existe déjà', 'error');
                    return;
                  }
                  // SÉCURITÉ: Limiter le nombre total de tags partagés
                  if (sharedTags.length >= 500) {
                    showToast('Nombre maximum de tags partagés atteint (500)', 'error');
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
                    showToast(`Tag "${newTag}" créé avec succès`, 'success');
                    tagInput.value = '';
                    await loadSharedTags();
                  } catch (err) {
                    showToast('Erreur lors de la création du tag', 'error');
                  } finally {
                    setLoadingTags(false);
                  }
                }}>
                  <div style={{ display: 'flex', gap: 10 }}>
                    <input
                      type="text"
                      name="newTag"
                      placeholder="Nom du nouveau tag..."
                      style={{
                        flex: 1,
                        padding: '8px 12px',
                        border: '1px solid #e5e7eb',
                        borderRadius: 6,
                        fontSize: 14
                      }}
                      disabled={loadingTags}
                    />
                    <button
                      type="submit"
                      className="btn btn-success"
                      disabled={loadingTags}
                    >
                      {loadingTags ? '🔄' : '➕'} Créer
                    </button>
                  </div>
                </form>
              </div>

              {/* Tags partagés existants */}
              <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8, padding: 20, marginBottom: 20 }}>
                <h3 style={{ fontSize: 16, marginBottom: 12 }}>🏷️ Tags partagés ({sharedTags.length})</h3>
                {loadingTags ? (
                  <p style={{ textAlign: 'center', padding: 20, color: '#6b7280' }}>
                    🔄 Chargement...
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
                          background: '#f3f4f6',
                          padding: '6px 12px',
                          borderRadius: 6,
                          border: '1px solid #e5e7eb'
                        }}
                      >
                        <span style={{ fontSize: 14 }}>🏷️ {tag}</span>
                        <button
                          onClick={async () => {
                            setConfirmModal({
                              title: 'Supprimer le tag',
                              message: `Voulez-vous vraiment supprimer le tag partagé "${tag}" ?`,
                              danger: true,
                              onConfirm: async () => {
                                try {
                                  setLoadingTags(true);
                                  await tagManager.removeSharedTag(vaultUrl, tag, baseHeaders(), axiosConfig, axios);
                                  showToast(`Tag "${tag}" supprimé avec succès`, 'success');
                                  await loadSharedTags();
                                } catch (err) {
                                  showToast('Erreur lors de la suppression du tag', 'error');
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
                            color: '#ef4444',
                            fontSize: 16,
                            padding: 0,
                            lineHeight: 1
                          }}
                          title="Supprimer ce tag"
                          disabled={loadingTags}
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ textAlign: 'center', padding: 20, color: '#6b7280' }}>
                    Aucun tag partagé. Créez-en un ci-dessus !
                  </p>
                )}
              </div>

              {/* Tags découverts dans les coffres */}
              <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: 8, padding: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                  <h3 style={{ fontSize: 16, margin: 0 }}>📋 Tags utilisés dans les coffres (non migrés) ({discoveredTags.filter(tag => !sharedTags.includes(tag)).length})</h3>

                  {/* Bouton de migration globale */}
                  {!loadingTags && discoveredTags.filter(tag => !sharedTags.includes(tag)).length > 0 && (
                    <button
                      onClick={async () => {
                        setConfirmModal({
                          title: 'Migrer tous les tags',
                          message: `Migrer tous les tags découverts (${discoveredTags.filter(t => !sharedTags.includes(t)).length} nouveaux) vers les tags partagés ? Les tags sur les entrées ne seront pas supprimés.`,
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
                              const mountsRes = await axios.get(`${vaultUrl}/v1/sys/mounts`, axiosConfig({ headers: baseHeaders() }));
                              const mountsData = mountsRes.data?.data || mountsRes.data || {};

                              const allAccessibleMounts = Object.entries(mountsData)
                                .map(([path, config]) => ({
                                  name: path.replace(/\/$/, ''),
                                  version: Number(config.options?.version) || 1
                                }))
                                .filter(mount => !['cubbyhole', 'identity', 'sys', 'tags-shared', 'totp', 'pki'].includes(mount.name.toLowerCase()));

                              // Charger tous les secrets
                              const allSecrets = [];
                              for (const mount of allAccessibleMounts) {
                                try {
                                  const keys = mount.version === 2
                                    ? (await axios.get(`${vaultUrl}/v1/${mount.name}/metadata?list=true`, axiosConfig({ headers: baseHeaders() }))).data?.data?.keys || []
                                    : (await axios.get(`${vaultUrl}/v1/${mount.name}?list=true`, axiosConfig({ headers: baseHeaders() }))).data?.data?.keys || [];

                                  for (const key of keys) {
                                    try {
                                      const secretData = mount.version === 2
                                        ? (await axios.get(`${vaultUrl}/v1/${mount.name}/data/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }))).data?.data?.data
                                        : (await axios.get(`${vaultUrl}/v1/${mount.name}/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }))).data?.data;

                                      if (secretData) {
                                        allSecrets.push(secretData);
                                      }
                                    } catch (err) {
                                      // Ignorer les erreurs de lecture individuelle
                                    }
                                  }
                                } catch (err) {
                                  // Ignorer les erreurs de lecture de coffre
                                }
                              }

                              // Appeler la fonction de migration
                              const stats = await tagManager.migrateTagsToShared(
                                vaultUrl,
                                allSecrets,
                                baseHeaders(),
                                axiosConfig,
                                axios
                              );

                              showToast(
                                `Migration terminée : ${stats.added} tag${stats.added > 1 ? 's' : ''} ajouté${stats.added > 1 ? 's' : ''} aux tags partagés (${stats.total} tags trouvés dans les coffres)`,
                                'success'
                              );

                              // Recharger les tags
                              await loadSharedTags();
                            } catch (err) {
                              secureLogger.error('[TAGS] Erreur migration');
                              showToast('Erreur lors de la migration des tags', 'error');
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
                      🔄 Migrer tous les tags
                    </button>
                  )}
                </div>

                {/* Info sur la migration */}
                {!loadingTags && discoveredTags.filter(tag => !sharedTags.includes(tag)).length > 0 && (
                  <div style={{ background: '#fef3c7', border: '1px solid #fcd34d', borderRadius: 6, padding: 12, marginBottom: 12, fontSize: 13 }}>
                    💡 La migration copie tous les tags découverts vers les tags partagés sans modifier les entrées existantes.
                  </div>
                )}

                {loadingTags ? (
                  <p style={{ textAlign: 'center', padding: 20, color: '#6b7280' }}>
                    🔄 Chargement...
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
                          background: '#dbeafe',
                          padding: '6px 12px',
                          borderRadius: 6,
                          border: '1px solid #93c5fd'
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
                              showToast(`Tag "${tag}" ajouté aux tags partagés`, 'success');
                              await loadSharedTags();
                            } catch (err) {
                              showToast('Erreur lors de l\'ajout du tag', 'error');
                            } finally {
                              setLoadingTags(false);
                            }
                          }}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            cursor: 'pointer',
                            color: '#10b981',
                            fontSize: 16,
                            padding: 0,
                            lineHeight: 1
                          }}
                          title="Ajouter aux tags partagés"
                          disabled={loadingTags}
                        >
                          ➕
                        </button>

                        <button
                          onClick={async () => {
                            setConfirmModal({
                              title: 'Supprimer le tag',
                              message: `Voulez-vous vraiment supprimer le tag "${tag}" de toutes les entrées qui l'utilisent ?`,
                              danger: true,
                              onConfirm: async () => {
                                try {
                                  await removeTagFromAllSecrets(tag);
                                  await loadSharedTags();
                                } catch (err) {
                                  showToast('Erreur lors de la suppression du tag', 'error');
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
                            color: '#ef4444',
                            fontSize: 16,
                            padding: 0,
                            lineHeight: 1
                          }}
                          title="Supprimer ce tag de toutes les entrées"
                          disabled={loadingTags}
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ textAlign: 'center', padding: 20, color: '#6b7280' }}>
                    {discoveredTags.length > 0
                      ? '✅ Tous les tags ont été migrés vers les tags partagés !'
                      : 'Aucun tag trouvé dans vos coffres accessibles'}
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'export' && isAdmin && (
          <div className="admin-section">
            <div style={{ maxWidth: 800, margin: '0 auto' }}>
              <h2 style={{ marginBottom: 20 }}>📥 Export CSV</h2>

              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <p style={{ margin: 0, fontSize: 14, color: 'var(--text-secondary)' }}>
                  Exportez tous les secrets d'un coffre au format CSV (compatible Excel).
                  Les colonnes exportées sont : name, username, password, url, website, notes, tags, Port.
                </p>
              </div>

              <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                {allMounts.filter(m => m.type === 'kv').length === 0 ? (
                  <p style={{ color: 'var(--text-secondary)', fontSize: 14, padding: 20 }}>Aucun coffre KV disponible.</p>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', color: 'var(--text-primary)' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
                        <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>Coffre</th>
                        <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>Version</th>
                        <th style={{ textAlign: 'left', padding: '10px 16px', fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>Description</th>
                        <th style={{ textAlign: 'right', padding: '10px 16px' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {allMounts.filter(m => m.type === 'kv').map(mount => (
                        <tr key={mount.path} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td style={{ padding: '10px 16px', fontWeight: 500 }}>{mount.path}</td>
                          <td style={{ padding: '10px 16px', fontSize: 13, color: 'var(--text-secondary)' }}>KV v{mount.version}</td>
                          <td style={{ padding: '10px 16px', fontSize: 13, color: 'var(--text-secondary)' }}>{mount.description || '—'}</td>
                          <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                            <button
                              className="btn btn-sm"
                              onClick={() => exportMountToCsv(mount)}
                              style={{ whiteSpace: 'nowrap' }}
                            >
                              Exporter CSV
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

      {/* Modal de création de policy */}
      {showCreatePolicyModal && <CreatePolicyModal />}

      {/* Menu contextuel pour les policies */}
      {policyContextMenu && (
        <div
          style={{
            position: 'fixed',
            left: policyContextMenu.x,
            top: policyContextMenu.y,
            background: '#fff',
            border: '1px solid #e5e7eb',
            borderRadius: 8,
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            zIndex: 30000,
            minWidth: 160,
            overflow: 'hidden'
          }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              width: '100%',
              padding: '10px 14px',
              border: 'none',
              background: 'transparent',
              cursor: 'pointer',
              fontSize: 13,
              textAlign: 'left',
              color: '#374151'
            }}
            onMouseEnter={(e) => e.target.style.background = '#f3f4f6'}
            onMouseLeave={(e) => e.target.style.background = 'transparent'}
            onClick={() => {
              openBuilderForEdit(policyContextMenu.policy);
              setPolicyContextMenu(null);
            }}
          >
            ✏️ Modifier
          </button>
          {(isAdmin || isModerator) && (
            <>
              <div style={{ height: 1, background: '#e5e7eb' }} />
              {policyContextMenu.policy !== 'default' && policyContextMenu.policy !== 'root' && (
                <button
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    width: '100%',
                    padding: '10px 14px',
                    border: 'none',
                    background: 'transparent',
                    cursor: 'pointer',
                    fontSize: 13,
                    textAlign: 'left',
                    color: '#ef4444'
                  }}
                  onMouseEnter={(e) => e.target.style.background = '#fef2f2'}
                  onMouseLeave={(e) => e.target.style.background = 'transparent'}
                  onClick={() => {
                    deletePolicy(policyContextMenu.policy);
                    setPolicyContextMenu(null);
                  }}
                >
                  🗑️ Supprimer
                </button>
              )}
            </>
          )}
        </div>
      )}

      {/* Modal de builder de policy */}
      {showPolicyBuilderModal && <PolicyBuilderModal />}

      {/* Modal d'activation d'audit device */}
      {showEnableAuditModal && <EnableAuditModal />}
    </div>
  );

  // Composant modal pour créer une nouvelle policy
  function CreatePolicyModal() {
    const [policyName, setPolicyName] = React.useState('');
    const inputRef = React.useRef(null);

    React.useEffect(() => {
      inputRef.current?.focus();
    }, []);

    React.useEffect(() => {
      const onKey = (e) => {
        if (e.key === 'Escape') {
          setShowCreatePolicyModal(false);
        } else if (e.key === 'Enter' && policyName.trim()) {
          handleCreate();
        }
      };
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, [policyName]);

    const handleCreate = async () => {
      if (!policyName.trim()) return;

      // SÉCURITÉ: Sanitiser le nom de policy pour éviter l'injection HCL
      const name = policyName.trim().replace(/[\r\n"\\*+]/g, '');
      if (!name || name.length > 256) {
        showToast('Nom de policy invalide (max 256 caractères)', 'error');
        return;
      }

      // Créer une policy de base avec configuration minimale
      const basePolicy = `# Policy créée automatiquement - ${name}
# Modifiez cette policy selon vos besoins

# Lecture de la liste des secrets engines
path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/internal/ui/mounts" {
  capabilities = ["read"]
}

# Accès en lecture au coffre personnel
path "secret/data/users/{{identity.entity.name}}/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/users/{{identity.entity.name}}/*" {
  capabilities = ["read", "list"]
}

# Lookup token (pour entity_name)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}`;

      try {
        // Sauvegarder dans Vault
        await axios.put(
          `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(name)}`,
          { policy: basePolicy },
          axiosConfig({ headers: baseHeaders() })
        );

        // Mettre à jour l'interface
        setSelectedPolicy(name);
        setPolicyContent(basePolicy);

        // Ajouter à la liste si pas déjà présent
        if (!policies.includes(name)) {
          setPolicies([...policies, name]);
        }

        setShowCreatePolicyModal(false);
        showToast(`Policy "${name}" créée et sauvegardée dans Vault`, 'success');
      } catch (err) {
        secureLogger.error('[Admin] Erreur création policy');
        showToast('Erreur lors de la création de la policy', 'error');
      }
    };

    const overlayStyle = {
      position: 'fixed',
      inset: 0,
      background: 'rgba(0,0,0,0.45)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 20000,
    };

    const panelStyle = {
      width: 460,
      maxWidth: '90vw',
      background: '#fff',
      borderRadius: 12,
      boxShadow: '0 20px 60px rgba(0,0,0,0.35)',
      padding: 16,
    };

    const titleStyle = {
      fontSize: 18,
      fontWeight: 700,
      marginBottom: 12
    };

    const labelStyle = {
      fontSize: 13,
      fontWeight: 600,
      color: '#374151',
      marginBottom: 6,
      display: 'block'
    };

    const inputStyle = {
      width: '100%',
      padding: 8,
      border: '1px solid #d1d5db',
      borderRadius: 6,
      fontSize: 14,
      marginBottom: 16
    };

    const buttonRowStyle = {
      display: 'flex',
      justifyContent: 'flex-end',
      gap: 8
    };

    const btnStyle = {
      padding: '8px 12px',
      borderRadius: 8,
      cursor: 'pointer',
      border: '1px solid #d1d5db',
      background: '#fff',
      color: '#111827'
    };

    const btnPrimaryStyle = {
      ...btnStyle,
      background: '#10b981',
      borderColor: '#10b981',
      color: '#fff'
    };

    return (
      <div style={overlayStyle} onClick={() => setShowCreatePolicyModal(false)}>
        <div style={panelStyle} onClick={(e) => e.stopPropagation()}>
          <div style={titleStyle}>Nouvelle Policy</div>
          <label style={labelStyle}>Nom de la policy*</label>
          <input
            ref={inputRef}
            type="text"
            style={inputStyle}
            placeholder="ex: app-read-only"
            value={policyName}
            onChange={(e) => setPolicyName(e.target.value)}
          />
          <div style={buttonRowStyle}>
            <button
              type="button"
              style={btnStyle}
              onClick={() => setShowCreatePolicyModal(false)}
            >
              Annuler
            </button>
            <button
              type="button"
              style={btnPrimaryStyle}
              onClick={handleCreate}
              disabled={!policyName.trim()}
            >
              Créer
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Composant modal pour le builder de policy
  function PolicyBuilderModal() {
    const [policyName, setPolicyName] = React.useState('');
    const [allowListMounts, setAllowListMounts] = React.useState(true);
    const [paths, setPaths] = React.useState([
      {
        type: 'coffre', // 'coffre' ou 'secret'
        coffre: '',
        secret: '',
        accessLevel: 'read-only', // 'read-only', 'read-write', 'full-admin'
        includeTotp: true,
        totpLevel: 'read-only' // 'read-only' ou 'read-write'
      }
    ]);
    const [availableSecrets, setAvailableSecrets] = React.useState({});
    const [isEditMode, setIsEditMode] = React.useState(false);
    const inputRef = React.useRef(null);

    React.useEffect(() => {
      inputRef.current?.focus();
      // Charger les mounts si pas déjà chargés
      if (allMounts.length === 0) {
        loadAllMounts();
      }

      // Si mode édition, charger la policy
      if (editPolicyName) {
        loadPolicyForEdit(editPolicyName);
      }
    }, []);

    // Charger la policy pour l'éditer
    const loadPolicyForEdit = async (name) => {
      try {
        const res = await axios.get(
          `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(name)}`,
          axiosConfig({ headers: baseHeaders() })
        );
        const hcl = res.data?.data?.policy || res.data?.policy || '';

        setPolicyName(name);
        setIsEditMode(true);

        // Parser le HCL pour extraire les configs
        parseHclToState(hcl);
      } catch (err) {
        // Si c'est une 404, c'est une nouvelle policy - initialiser vide
        if (err.response?.status === 404) {
          secureLogger.debug('[AdminPanel] Nouvelle policy - initialisation vide');
          setPolicyName(name);
          setIsEditMode(true);
          setAllowListMounts(true);
          setPaths([
            {
              type: 'coffre',
              coffre: '',
              secret: '',
              accessLevel: 'read-only',
              includeTotp: true,
              totpLevel: 'read-only'
            }
          ]);
        } else {
          showToast('Erreur lors du chargement de la policy', 'error');
          secureLogger.error('[AdminPanel] Erreur chargement policy');
        }
      }
    };

    // Parser le HCL et mettre à jour l'état
    const parseHclToState = (hcl) => {
      // Vérifier si sys/mounts est présent
      const hasMountsList = hcl.includes('path "sys/mounts"');
      setAllowListMounts(hasMountsList);

      const parsedPaths = [];
      const lines = hcl.split('\n');

      // Extraire les coffres KV
      const kvDataMatches = hcl.match(/path "([^"]+)\/(?:data|metadata)\/\*"/g) || [];
      const kvV1Matches = hcl.match(/path "([^"]+)\/\*"/g) || [];

      const processedCoffres = new Set();

      // Détecter si la policy contient le marqueur RBI-ONLY
      const hasRbiOnly = hcl.includes('# RBI-ONLY');

      // Parser KV v2
      for (const match of kvDataMatches) {
        const pathMatch = match.match(/path "([^"]+)\/(data|metadata)\/\*"/);
        if (pathMatch) {
          const coffreName = pathMatch[1];

          if (processedCoffres.has(coffreName) || coffreName === 'sys/mounts') continue;
          processedCoffres.add(coffreName);

          // Détecter le niveau d'accès
          let accessLevel = 'read-only';

          // Vérifier d'abord si c'est un moderator (commentaire spécial)
          const moderatorCommentRegex = new RegExp(`# KV v2 MODERATOR \\(${escapeRegex(coffreName)}\\)`);
          if (moderatorCommentRegex.test(hcl)) {
            accessLevel = 'moderator';
          } else {
            const dataPathRegex = new RegExp(`path "${escapeRegex(coffreName)}/data/\\*"[^}]+capabilities = \\[([^\\]]+)\\]`);
            const dataMatch = hcl.match(dataPathRegex);

            if (dataMatch) {
              const caps = dataMatch[1];
              if (caps.includes('sudo')) {
                accessLevel = 'full-admin';
              } else if (caps.includes('create') || caps.includes('update') || caps.includes('delete')) {
                accessLevel = 'read-write';
              } else if (hasRbiOnly) {
                accessLevel = 'rbi-only';
              }
            } else if (hasRbiOnly) {
              accessLevel = 'rbi-only';
            }
          }

          // Vérifier TOTP (le nom TOTP est strippé du préfixe users/xxx/)
          const coffreNameStripped = coffreName
            .replace(/^users\/[^/]+\//i, '')
            .replace(/\/$/, '')
            .toUpperCase();
          const hasTotpKeys = hcl.includes(`path "TOTP/keys/${coffreNameStripped}-`);
          const hasTotpCode = hcl.includes(`path "TOTP/code/${coffreNameStripped}-`);
          const hasTotpValidate = hcl.includes(`path "TOTP/validate/${coffreNameStripped}-`);

          // Synchroniser le niveau TOTP avec le niveau d'accès
          let totpLevel = 'read-only';
          if (accessLevel === 'read-write' || accessLevel === 'moderator' || accessLevel === 'full-admin') {
            totpLevel = 'read-write';
          }

          parsedPaths.push({
            type: 'coffre',
            coffre: coffreName,
            secret: '',
            accessLevel,
            includeTotp: hasTotpCode || hasTotpKeys || hasTotpValidate,
            totpLevel: hasTotpKeys ? 'read-write' : totpLevel
          });
        }
      }

      // Parser KV v1 (seulement si pas déjà traité en v2)
      for (const match of kvV1Matches) {
        const pathMatch = match.match(/path "([^"]+)\/\*"/);
        if (pathMatch) {
          const coffreName = pathMatch[1];

          if (processedCoffres.has(coffreName) || coffreName === 'sys/mounts' || coffreName.includes('/')) continue;
          processedCoffres.add(coffreName);

          // Détecter le niveau d'accès
          let accessLevel = 'read-only';

          // Vérifier d'abord si c'est un moderator (commentaire spécial)
          const moderatorCommentRegex = new RegExp(`# KV v1 MODERATOR \\(${escapeRegex(coffreName)}\\)`);
          if (moderatorCommentRegex.test(hcl)) {
            accessLevel = 'moderator';
          } else {
            const pathRegex = new RegExp(`path "${escapeRegex(coffreName)}/\\*"[^}]+capabilities = \\[([^\\]]+)\\]`);
            const pathMatchCaps = hcl.match(pathRegex);

            if (pathMatchCaps) {
              const caps = pathMatchCaps[1];
              if (caps.includes('sudo')) {
                accessLevel = 'full-admin';
              } else if (caps.includes('create') || caps.includes('update') || caps.includes('delete')) {
                accessLevel = 'read-write';
              } else if (hasRbiOnly) {
                accessLevel = 'rbi-only';
              }
            } else if (hasRbiOnly) {
              accessLevel = 'rbi-only';
            }
          }

          // Vérifier TOTP (le nom TOTP est strippé du préfixe users/xxx/)
          const coffreNameStripped = coffreName
            .replace(/^users\/[^/]+\//i, '')
            .replace(/\/$/, '')
            .toUpperCase();
          const hasTotpKeys = hcl.includes(`path "TOTP/keys/${coffreNameStripped}-`);
          const hasTotpCode = hcl.includes(`path "TOTP/code/${coffreNameStripped}-`);
          const hasTotpValidate = hcl.includes(`path "TOTP/validate/${coffreNameStripped}-`);

          // Synchroniser le niveau TOTP avec le niveau d'accès
          let totpLevel = 'read-only';
          if (accessLevel === 'read-write' || accessLevel === 'moderator' || accessLevel === 'full-admin') {
            totpLevel = 'read-write';
          }

          parsedPaths.push({
            type: 'coffre',
            coffre: coffreName,
            secret: '',
            accessLevel,
            includeTotp: hasTotpCode || hasTotpKeys || hasTotpValidate,
            totpLevel: hasTotpKeys ? 'read-write' : totpLevel
          });
        }
      }

      if (parsedPaths.length > 0) {
        setPaths(parsedPaths);
      }
    };

    React.useEffect(() => {
      const onKey = (e) => {
        if (e.key === 'Escape') {
          closeModal();
        }
      };
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, []);

    const closeModal = () => {
      setShowPolicyBuilderModal(false);
      setEditPolicyName(null);
    };

    // Charger les secrets d'un coffre
    const loadSecretsForMount = async (mountPath, index) => {
      try {
        const mount = allMounts.find(m => m.path === mountPath);
        if (!mount) {
          secureLogger.error('[AdminPanel] Mount non trouvé');
          return;
        }

        let secretsList = [];
        if (mount.version === 2) {
          const res = await axios.get(
            `${vaultUrl}/v1/${mount.path}/metadata?list=true`,
            axiosConfig({ headers: baseHeaders() })
          );
          const allKeys = res.data?.data?.keys || [];

          // Filtrer les dossiers
          const keys = allKeys.filter(k => !k.endsWith('/'));

          // Pour KV v2, vérifier si les secrets sont supprimés
          const secretsWithStatus = await Promise.all(
            keys.map(async (key) => {
              try {
                const metaRes = await axios.get(
                  `${vaultUrl}/v1/${mount.path}/metadata/${encodeURIComponent(key)}`,
                  axiosConfig({ headers: baseHeaders() })
                );
                const currentVersion = metaRes.data?.data?.current_version;
                const versionData = metaRes.data?.data?.versions?.[currentVersion];

                // Retourner null si supprimé
                if (versionData?.deletion_time) {
                  return null;
                }
                return key;
              } catch {
                return null; // En cas d'erreur, on ignore ce secret
              }
            })
          );

          // Filtrer les secrets non supprimés
          secretsList = secretsWithStatus.filter(k => k !== null);
        } else {
          const res = await axios.get(
            `${vaultUrl}/v1/${mount.path}?list=true`,
            axiosConfig({ headers: baseHeaders() })
          );
          secretsList = res.data?.data?.keys || [];
          // Filtrer les dossiers
          secretsList = secretsList.filter(k => !k.endsWith('/'));
        }

        setAvailableSecrets(prev => ({ ...prev, [mountPath]: secretsList }));
      } catch (err) {
        secureLogger.error('[AdminPanel] Erreur chargement secrets');
        setAvailableSecrets(prev => ({ ...prev, [mountPath]: [] }));
      }
    };

    const addPath = () => {
      setPaths([...paths, {
        type: 'coffre',
        coffre: '',
        secret: '',
        accessLevel: 'read-only',
        includeTotp: true,
        totpLevel: 'read-only'
      }]);
    };

    const removePath = (index) => {
      setPaths(paths.filter((_, i) => i !== index));
    };

    const updatePath = (index, field, value) => {
      const newPaths = [...paths];
      newPaths[index][field] = value;

      // Si on change de coffre, réinitialiser le secret et charger les secrets
      if (field === 'coffre' && value) {
        newPaths[index].secret = '';
        loadSecretsForMount(value, index);
      }

      // Si on change le type vers "secret" et qu'un coffre est déjà sélectionné, charger les secrets
      if (field === 'type' && value === 'secret' && newPaths[index].coffre) {
        loadSecretsForMount(newPaths[index].coffre, index);
      }

      // Si on change le niveau d'accès, synchroniser le niveau TOTP
      if (field === 'accessLevel') {
        if (value === 'read-only' || value === 'rbi-only') {
          newPaths[index].totpLevel = 'read-only';
        } else if (value === 'read-write' || value === 'moderator' || value === 'full-admin') {
          newPaths[index].totpLevel = 'read-write';
        }
      }

      setPaths(newPaths);
    };

    const generateHCL = () => {
      let hcl = '# Policy générée par le builder\n\n';
      const addedMetadataList = new Set();

      // Ajouter le listing des coffres si demandé
      if (allowListMounts) {
        hcl += '# Lister tous les coffres\n';
        hcl += 'path "sys/mounts"   { capabilities = ["read","list"] }\n';
        hcl += 'path "sys/mounts/*" { capabilities = ["read","list"] }\n\n';
      }

      paths.forEach(p => {
        if (!p.coffre) return; // Skip si pas de coffre sélectionné

        // SÉCURITÉ: Sanitiser le nom du coffre pour éviter l'injection HCL
        // Rejeter les caractères dangereux (newlines, quotes, backslashes)
        const safeCoffre = p.coffre.replace(/[\r\n"\\*+]/g, '');
        if (safeCoffre !== p.coffre || !safeCoffre) return;
        p.coffre = safeCoffre;

        const mount = allMounts.find(m => m.path === p.coffre);
        if (!mount) return;

        const coffreName = p.coffre
          .replace(/^users\/[^/]+\//i, '')
          .replace(/\/$/, '')
          .toUpperCase();

        if (p.type === 'coffre') {
          // Accès au coffre entier
          if (mount.version === 2) {
            // KV v2
            if (p.accessLevel === 'rbi-only') {
              hcl += `# RBI-ONLY\n`;
              hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read"] }\n`;
              hcl += `path "${p.coffre}/data/*"     { capabilities = ["read"] }\n\n`;
            } else if (p.accessLevel === 'read-only') {
              hcl += `# KV v2 RO\n`;
              hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read"] }\n`;
              hcl += `path "${p.coffre}/data/*"     { capabilities = ["read"] }\n\n`;
            } else if (p.accessLevel === 'read-write') {
              hcl += `# KV v2 RW complet\n`;
              hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read","delete"] }\n`;
              hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","update","read","delete","list"] }\n`;
              hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update"] }\n`;
              hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update"] }\n`;
              hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update"] }\n\n`;
            } else if (p.accessLevel === 'moderator') {
              hcl += `# KV v2 MODERATOR (${p.coffre})\n`;
              hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read","delete"] }\n`;
              hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","update","read","delete","list"] }\n`;
              hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update"] }\n`;
              hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update"] }\n`;
              hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update"] }\n\n`;
            } else if (p.accessLevel === 'full-admin') {
              hcl += `# KV v2 Full Admin\n`;
              hcl += `path "${p.coffre}/metadata/*" { capabilities = ["create","read","update","delete","list","sudo"] }\n`;
              hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","read","update","delete","list","sudo"] }\n`;
              hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update","sudo"] }\n`;
              hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update","sudo"] }\n`;
              hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update","sudo"] }\n\n`;
            }
          } else {
            // KV v1
            if (p.accessLevel === 'rbi-only') {
              hcl += `# RBI-ONLY\n`;
              hcl += `path "${p.coffre}/*" { capabilities = ["read","list"] }\n\n`;
            } else if (p.accessLevel === 'read-only') {
              hcl += `# KV v1 RO\n`;
              hcl += `path "${p.coffre}/*" { capabilities = ["read","list"] }\n\n`;
            } else if (p.accessLevel === 'read-write') {
              hcl += `# KV v1 RW\n`;
              hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list"] }\n\n`;
            } else if (p.accessLevel === 'moderator') {
              hcl += `# KV v1 MODERATOR (${p.coffre})\n`;
              hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list"] }\n\n`;
            } else if (p.accessLevel === 'full-admin') {
              hcl += `# KV v1 Full Admin\n`;
              hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list","sudo"] }\n\n`;
            }
          }

          // Ajouter TOTP si demandé OU si RBI-only (nécessaire pour l'injection automatique en session sécurisée)
          if (p.includeTotp || p.accessLevel === 'rbi-only') {
            hcl += `# TOTP (${coffreName}-*)\n`;
            if (p.totpLevel === 'read-only' || p.accessLevel === 'rbi-only') {
              hcl += `path "TOTP/code/${coffreName}-*"     { capabilities = ["read"] }\n`;
              hcl += `path "TOTP/validate/${coffreName}-*" { capabilities = ["update"] }\n\n`;
            } else {
              hcl += `path "TOTP/keys/${coffreName}-*"     { capabilities = ["create","update","read","delete"] }\n`;
              hcl += `path "TOTP/code/${coffreName}-*"     { capabilities = ["read"] }\n`;
              hcl += `path "TOTP/validate/${coffreName}-*" { capabilities = ["update"] }\n\n`;
            }
          }
        } else if (p.type === 'secret' && p.secret) {
          // Accès à un secret spécifique
          let secretName = p.secret.replace(/\/$/, '');
          // SÉCURITÉ: Sanitiser le nom du secret pour éviter l'injection HCL
          secretName = secretName.replace(/[\r\n"\\*+]/g, '');
          if (!secretName) return;
          if (mount.version === 2) {
            // Listing du coffre nécessaire pour que l'app puisse énumérer les secrets
            if (!addedMetadataList.has(p.coffre)) {
              hcl += `# Listing secrets du coffre ${p.coffre}\n`;
              hcl += `path "${p.coffre}/metadata" { capabilities = ["list"] }\n\n`;
              addedMetadataList.add(p.coffre);
            }
            if (p.accessLevel === 'rbi-only') {
              hcl += `# RBI-ONLY\n`;
              hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RBI-ONLY)\n`;
              hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read"] }\n`;
              hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["read"] }\n\n`;
            } else if (p.accessLevel === 'read-only') {
              hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RO)\n`;
              hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read"] }\n`;
              hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["read"] }\n\n`;
            } else {
              hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RW)\n`;
              hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read","delete"] }\n`;
              hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["create","update","read","delete"] }\n\n`;
            }
          } else {
            // KV v1 : listing du coffre
            if (!addedMetadataList.has(p.coffre)) {
              hcl += `# Listing secrets du coffre ${p.coffre}\n`;
              hcl += `path "${p.coffre}" { capabilities = ["list"] }\n\n`;
              addedMetadataList.add(p.coffre);
            }
            if (p.accessLevel === 'rbi-only') {
              hcl += `# RBI-ONLY\n`;
              hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RBI-ONLY)\n`;
              hcl += `path "${p.coffre}/${secretName}" { capabilities = ["read"] }\n\n`;
            } else if (p.accessLevel === 'read-only') {
              hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RO)\n`;
              hcl += `path "${p.coffre}/${secretName}" { capabilities = ["read"] }\n\n`;
            } else {
              hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RW)\n`;
              hcl += `path "${p.coffre}/${secretName}" { capabilities = ["create","read","update","delete"] }\n\n`;
            }
          }

          // Ajouter TOTP pour secret spécifique
          if (p.includeTotp || p.accessLevel === 'rbi-only') {
            const sName = p.secret.replace(/\/$/, '').replace(/[\r\n"\\*+]/g, '');
            if (!sName) return;
            hcl += `# TOTP (${coffreName}-${sName})\n`;
            if (p.totpLevel === 'read-only' || p.accessLevel === 'rbi-only') {
              hcl += `path "TOTP/code/${coffreName}-${sName}"     { capabilities = ["read"] }\n`;
              hcl += `path "TOTP/validate/${coffreName}-${sName}" { capabilities = ["update"] }\n\n`;
            } else {
              hcl += `path "TOTP/keys/${coffreName}-${sName}"     { capabilities = ["create","update","read","delete"] }\n`;
              hcl += `path "TOTP/code/${coffreName}-${sName}"     { capabilities = ["read"] }\n`;
              hcl += `path "TOTP/validate/${coffreName}-${sName}" { capabilities = ["update"] }\n\n`;
            }
          }
        }
      });

      // Si au moins un path a le niveau "moderator", ajouter les permissions de lecture des policies et mounts
      const hasModerator = paths.some(p => p.accessLevel === 'moderator');
      if (hasModerator) {
        hcl += '# Permissions modérateur : gestion policies, mounts, groupes AD et tags\n';
        hcl += 'path "sys/policies/acl"     { capabilities = ["list"] }\n';
        hcl += 'path "sys/policies/acl/*"   { capabilities = ["read","create","update"] }\n';
        hcl += 'path "sys/mounts"           { capabilities = ["read","list"] }\n';
        hcl += 'path "sys/mounts/*"         { capabilities = ["read","create","update","delete"] }\n';
        const safeLdapPath = ldapAuthPath.replace(/[\r\n"\\*+]/g, '');
        hcl += `path "${safeLdapPath}/groups"     { capabilities = ["list"] }\n`;
        hcl += `path "${safeLdapPath}/groups/*"   { capabilities = ["read","create","update"] }\n`;
        hcl += '# Accès au coffre des tags partagés\n';
        hcl += 'path "tags-shared/metadata/*" { capabilities = ["list","read"] }\n';
        hcl += 'path "tags-shared/data/*"     { capabilities = ["create","update","read","list"] }\n\n';
      }

      // Si la policy contient des restrictions RBI-ONLY, ajouter la permission
      // de lecture de sa propre policy (nécessaire pour la détection RBI côté client)
      const hasRbiOnly = paths.some(p => p.accessLevel === 'rbi-only');
      if (hasRbiOnly && policyName.trim()) {
        const safePolicyName = policyName.trim().replace(/[\r\n"\\*+]/g, '');
        if (safePolicyName) {
          hcl += '# Lecture de la policy (détection RBI côté client)\n';
          hcl += `path "sys/policies/acl/${safePolicyName}" { capabilities = ["read"] }\n\n`;
        }
      }

      return hcl || '# Aucun path configuré';
    };

    const handleSave = async () => {
      if (!policyName.trim()) {
        showToast('Veuillez entrer un nom de policy', 'error');
        return;
      }

      const validPaths = paths.filter(p => p.coffre && (p.type === 'coffre' || (p.type === 'secret' && p.secret)));
      if (validPaths.length === 0) {
        showToast('Veuillez configurer au moins un coffre ou secret', 'error');
        return;
      }

      const hclContent = generateHCL();
      await savePolicy(policyName.trim(), hclContent);
      closeModal();
    };

    const overlayStyle = {
      position: 'fixed',
      inset: 0,
      background: 'rgba(0,0,0,0.45)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 20000,
    };

    const panelStyle = {
      width: 700,
      maxWidth: '90vw',
      maxHeight: '90vh',
      background: '#fff',
      borderRadius: 12,
      boxShadow: '0 20px 60px rgba(0,0,0,0.35)',
      padding: 20,
      overflow: 'auto'
    };

    const titleStyle = {
      fontSize: 20,
      fontWeight: 700,
      marginBottom: 16
    };

    const labelStyle = {
      fontSize: 13,
      fontWeight: 600,
      color: '#374151',
      marginBottom: 6,
      display: 'block'
    };

    const inputStyle = {
      width: '100%',
      padding: 8,
      border: '1px solid #d1d5db',
      borderRadius: 6,
      fontSize: 14,
      marginBottom: 16
    };

    const pathItemStyle = {
      border: '1px solid #e5e7eb',
      borderRadius: 8,
      padding: 12,
      marginBottom: 12,
      background: '#f9fafb'
    };

    const buttonRowStyle = {
      display: 'flex',
      justifyContent: 'space-between',
      gap: 8,
      marginTop: 16
    };

    const btnStyle = {
      padding: '8px 12px',
      borderRadius: 8,
      cursor: 'pointer',
      border: '1px solid #d1d5db',
      background: '#fff',
      color: '#111827'
    };

    const btnPrimaryStyle = {
      ...btnStyle,
      background: '#10b981',
      borderColor: '#10b981',
      color: '#fff'
    };

    const btnSecondaryStyle = {
      ...btnStyle,
      background: '#3b82f6',
      borderColor: '#3b82f6',
      color: '#fff'
    };

    return (
      <div style={overlayStyle} onClick={() => closeModal()}>
        <div style={panelStyle} onClick={(e) => e.stopPropagation()}>
          <div style={titleStyle}>
            {isEditMode ? '✏️ Modifier la Policy' : '🛠️ Builder de Policy'}
          </div>

          <label style={labelStyle}>Nom de la policy*</label>
          <input
            ref={inputRef}
            type="text"
            style={{ ...inputStyle, ...(isEditMode ? { background: '#f3f4f6', cursor: 'not-allowed' } : {}) }}
            placeholder="ex: app-read-write"
            value={policyName}
            onChange={(e) => setPolicyName(e.target.value)}
            disabled={isEditMode}
          />

          {/* Option globale pour lister les coffres */}
          <div style={{ marginBottom: 16, padding: 12, background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8 }}>
            <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={allowListMounts}
                onChange={(e) => setAllowListMounts(e.target.checked)}
                style={{ marginRight: 8, width: 16, height: 16 }}
              />
              <span style={{ fontSize: 13, fontWeight: 600 }}>📋 Permettre le listing de tous les coffres (sys/mounts)</span>
            </label>
            <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4, marginLeft: 24 }}>
              Nécessaire pour que l'utilisateur puisse voir tous les coffres disponibles
            </div>
          </div>

          <label style={labelStyle}>Règles d'accès</label>
          {paths.map((p, idx) => (
            <div key={idx} style={pathItemStyle}>
              {/* En-tête avec type et suppression */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>Type d'accès</label>
                  <select
                    style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                    value={p.type}
                    onChange={(e) => updatePath(idx, 'type', e.target.value)}
                  >
                    <option value="coffre">Coffre entier</option>
                    <option value="secret">Secret spécifique</option>
                  </select>
                </div>
                {paths.length > 1 && (
                  <button
                    style={{ padding: '8px 12px', border: '1px solid #ef4444', borderRadius: 6, background: '#fff', color: '#ef4444', cursor: 'pointer', marginTop: 18 }}
                    onClick={() => removePath(idx)}
                  >
                    ✕ Retirer
                  </button>
                )}
              </div>

              {/* Sélection du coffre */}
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>
                  {p.type === 'coffre' ? 'Coffre' : 'Coffre contenant le secret'}
                </label>
                <select
                  style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                  value={p.coffre}
                  onChange={(e) => updatePath(idx, 'coffre', e.target.value)}
                >
                  <option value="">-- Sélectionnez un coffre --</option>
                  {allMounts.filter(m => m.type === 'kv').map(mount => (
                    <option key={mount.path} value={mount.path}>
                      {mount.path}/ (KV v{mount.version})
                    </option>
                  ))}
                </select>
              </div>

              {/* Sélection du secret (seulement si type = secret) */}
              {p.type === 'secret' && p.coffre && (
                <div style={{ marginBottom: 12 }}>
                  <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>Secret</label>
                  <select
                    style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                    value={p.secret}
                    onChange={(e) => updatePath(idx, 'secret', e.target.value)}
                  >
                    <option value="">-- Sélectionnez un secret --</option>
                    {(availableSecrets[p.coffre] || []).map(secretName => (
                      <option key={secretName} value={secretName}>
                        {secretName}
                      </option>
                    ))}
                  </select>
                  {(!availableSecrets[p.coffre] || availableSecrets[p.coffre].length === 0) && (
                    <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 4 }}>
                      Aucun secret disponible ou chargement...
                    </div>
                  )}
                </div>
              )}

              {/* Niveau d'accès */}
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>Niveau d'accès</label>
                <select
                  style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                  value={p.accessLevel}
                  onChange={(e) => updatePath(idx, 'accessLevel', e.target.value)}
                >
                  <option value="read-only">🔒 Lecture seule (RO)</option>
                  <option value="rbi-only">🖥️ RBI uniquement (session securisee)</option>
                  <option value="read-write">✏️ Lecture/Écriture (RW)</option>
                  <option value="moderator">👮 Modérateur (RW + gestion du coffre)</option>
                  <option value="full-admin">👑 Full Admin (avec delete/undelete/destroy)</option>
                </select>
              </div>

              {/* TOTP */}
              {p.coffre && (p.type === 'coffre' || (p.type === 'secret' && p.secret)) && (
                <div style={{ marginTop: 12, padding: 10, background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 6 }}>
                  <label style={{ display: 'flex', alignItems: 'center', cursor: p.accessLevel === 'rbi-only' ? 'default' : 'pointer', marginBottom: 8 }}>
                    <input
                      type="checkbox"
                      checked={p.includeTotp || p.accessLevel === 'rbi-only'}
                      onChange={(e) => updatePath(idx, 'includeTotp', e.target.checked)}
                      disabled={p.accessLevel === 'rbi-only'}
                      style={{ marginRight: 8, width: 16, height: 16 }}
                    />
                    <span style={{ fontSize: 12, fontWeight: 600 }}>Inclure acces TOTP</span>
                    {p.accessLevel === 'rbi-only' && (
                      <span style={{ fontSize: 10, color: '#3b82f6', marginLeft: 8, fontStyle: 'italic' }}>(inclus automatiquement en RBI)</span>
                    )}
                  </label>
                  {(p.includeTotp || p.accessLevel === 'rbi-only') && (
                    <div style={{ marginLeft: 24 }}>
                      <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 6 }}>
                        {p.type === 'secret'
                          ? <>Cle TOTP : <code style={{ background: '#fff', padding: '2px 6px', borderRadius: 4, fontWeight: 600 }}>{p.coffre.replace(/^users\/[^/]+\//i, '').replace(/\/$/, '').toUpperCase()}-{p.secret}</code></>
                          : <>Prefixe TOTP : <code style={{ background: '#fff', padding: '2px 6px', borderRadius: 4, fontWeight: 600 }}>{p.coffre.replace(/^users\/[^/]+\//i, '').replace(/\/$/, '').toUpperCase()}-*</code></>
                        }
                      </div>
                      {p.accessLevel === 'rbi-only' ? (
                        <div style={{ fontSize: 11, color: '#3b82f6', marginBottom: 6, fontStyle: 'italic' }}>
                          Lecture seule (injection automatique en session securisee)
                        </div>
                      ) : (
                        <>
                          <div style={{ fontSize: 11, color: '#3b82f6', marginBottom: 6, fontStyle: 'italic' }}>
                            Le niveau TOTP suit automatiquement le niveau d'acces du coffre
                          </div>
                          <select
                            style={{ width: '100%', padding: 6, border: '1px solid #bfdbfe', borderRadius: 6, fontSize: 12 }}
                            value={p.totpLevel}
                            onChange={(e) => updatePath(idx, 'totpLevel', e.target.value)}
                          >
                            <option value="read-only">Lecture seule (code/validate)</option>
                            <option value="read-write">Gestion complete (keys/code/validate)</option>
                          </select>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}

          <button
            type="button"
            style={{ ...btnSecondaryStyle, width: '100%', marginBottom: 16 }}
            onClick={addPath}
          >
            + Ajouter une règle
          </button>

          <div style={{ background: '#f3f4f6', padding: 12, borderRadius: 8, marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 6 }}>Aperçu HCL :</div>
            <pre style={{ fontSize: 11, margin: 0, whiteSpace: 'pre-wrap', color: '#1f2937' }}>{generateHCL()}</pre>
          </div>

          <div style={buttonRowStyle}>
            <button
              type="button"
              style={btnStyle}
              onClick={() => setShowPolicyBuilderModal(false)}
            >
              Annuler
            </button>
            <button
              type="button"
              style={btnPrimaryStyle}
              onClick={handleSave}
            >
              💾 Sauvegarder la policy
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Composant modal pour activer un audit device
  function EnableAuditModal() {
    const [deviceName, setDeviceName] = React.useState('file');
    const [deviceType, setDeviceType] = React.useState('file');
    const [description, setDescription] = React.useState('');
    const [filePath, setFilePath] = React.useState('/var/log/vault/vault_audit.log');
    const [useSSH, setUseSSH] = React.useState(false);
    const [sshHost, setSshHost] = React.useState('');
    const [sshPort, setSshPort] = React.useState('22');
    const [sshUsername, setSshUsername] = React.useState('root');
    const [sshPassword, setSshPassword] = React.useState('');
    const inputRef = React.useRef(null);

    React.useEffect(() => {
      inputRef.current?.focus();
    }, []);

    React.useEffect(() => {
      const onKey = (e) => {
        if (e.key === 'Escape') {
          setShowEnableAuditModal(false);
        }
      };
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, []);

    const handleEnable = async () => {
      if (!deviceName.trim()) {
        showToast('Veuillez entrer un nom de device', 'error');
        return;
      }

      let options = {};
      if (deviceType === 'file') {
        if (!filePath.trim()) {
          showToast('Veuillez spécifier un chemin de fichier', 'error');
          return;
        }
        // SÉCURITÉ: Valider le chemin de fichier
        const trimmedPath = filePath.trim();
        if (trimmedPath.includes('..') || /[\x00-\x1F]/.test(trimmedPath)) {
          showToast('Chemin de fichier invalide', 'error');
          return;
        }
        options = { file_path: trimmedPath };
      }

      // Valider les informations SSH si activé
      if (useSSH) {
        const trimmedHost = sshHost.trim();
        const trimmedUsername = sshUsername.trim();
        if (!trimmedHost) {
          showToast('Veuillez spécifier un hôte SSH', 'error');
          return;
        }
        // SÉCURITÉ: Valider le format du host SSH
        if (trimmedHost.length > 253 || /[\x00-\x1F\s;|&`$(){}@#\[\]\\]/.test(trimmedHost)) {
          showToast('Hôte SSH invalide', 'error');
          return;
        }
        if (!trimmedUsername) {
          showToast('Veuillez spécifier un nom d\'utilisateur SSH', 'error');
          return;
        }
        // SÉCURITÉ: Valider le format du username SSH
        if (!/^[a-zA-Z0-9._-]{1,64}$/.test(trimmedUsername)) {
          showToast('Nom d\'utilisateur SSH invalide (lettres, chiffres, ._- uniquement)', 'error');
          return;
        }
        if (!sshPassword.trim()) {
          showToast('Veuillez spécifier un mot de passe SSH', 'error');
          return;
        }
        const parsedPort = parseInt(sshPort) || 22;
        if (parsedPort < 1 || parsedPort > 65535) {
          showToast('Port SSH invalide (1-65535)', 'error');
          return;
        }

        // SÉCURITÉ: Sanitiser le nom du device pour la clé localStorage
        const safeDeviceName = deviceName.trim().replace(/[^a-zA-Z0-9._-]/g, '_');

        // Stocker uniquement les infos non-sensibles (PAS le mot de passe)
        const sshConfig = {
          host: trimmedHost,
          port: parsedPort,
          username: trimmedUsername
        };
        localStorage.setItem(`vault-audit-ssh-${safeDeviceName}`, JSON.stringify(sshConfig));
      }

      await enableAuditDevice(deviceName.trim(), deviceType, description.trim(), options);
      setShowEnableAuditModal(false);
    };

    const overlayStyle = {
      position: 'fixed',
      inset: 0,
      background: 'rgba(0,0,0,0.45)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 20000,
    };

    const panelStyle = {
      width: 500,
      maxWidth: '90vw',
      background: '#fff',
      borderRadius: 12,
      boxShadow: '0 20px 60px rgba(0,0,0,0.35)',
      padding: 20,
    };

    const titleStyle = {
      fontSize: 18,
      fontWeight: 700,
      marginBottom: 16
    };

    const labelStyle = {
      fontSize: 13,
      fontWeight: 600,
      color: '#374151',
      marginBottom: 6,
      display: 'block'
    };

    const inputStyle = {
      width: '100%',
      padding: 8,
      border: '1px solid #d1d5db',
      borderRadius: 6,
      fontSize: 14,
      marginBottom: 16
    };

    const selectStyle = {
      ...inputStyle,
      padding: 6
    };

    const buttonRowStyle = {
      display: 'flex',
      justifyContent: 'flex-end',
      gap: 8,
      marginTop: 16
    };

    const btnStyle = {
      padding: '8px 12px',
      borderRadius: 8,
      cursor: 'pointer',
      border: '1px solid #d1d5db',
      background: '#fff',
      color: '#111827'
    };

    const btnPrimaryStyle = {
      ...btnStyle,
      background: '#10b981',
      borderColor: '#10b981',
      color: '#fff'
    };

    return (
      <div style={overlayStyle} onClick={() => setShowEnableAuditModal(false)}>
        <div style={panelStyle} onClick={(e) => e.stopPropagation()}>
          <div style={titleStyle}>📊 Activer un Audit Device</div>

          <label style={labelStyle}>Nom du device*</label>
          <input
            ref={inputRef}
            type="text"
            style={inputStyle}
            placeholder="ex: file"
            value={deviceName}
            onChange={(e) => setDeviceName(e.target.value)}
          />

          <label style={labelStyle}>Type*</label>
          <select
            style={selectStyle}
            value={deviceType}
            onChange={(e) => setDeviceType(e.target.value)}
          >
            <option value="file">File (fichier de logs)</option>
            <option value="syslog">Syslog (système de logs)</option>
            <option value="socket">Socket (connexion réseau)</option>
          </select>

          <label style={labelStyle}>Description</label>
          <input
            type="text"
            style={inputStyle}
            placeholder="Optionnel"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />

          {deviceType === 'file' && (
            <>
              <label style={labelStyle}>Chemin du fichier*</label>
              <input
                type="text"
                style={inputStyle}
                placeholder="/var/log/vault/vault_audit.log"
                value={filePath}
                onChange={(e) => setFilePath(e.target.value)}
              />
              <div style={{ fontSize: 11, color: '#6b7280', marginTop: -12, marginBottom: 12 }}>
                💡 Le fichier sera créé automatiquement par Vault sur le serveur
              </div>

              {/* Option SSH */}
              <div style={{ marginTop: 16, marginBottom: 16 }}>
                <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={useSSH}
                    onChange={(e) => setUseSSH(e.target.checked)}
                    style={{ marginRight: 8 }}
                  />
                  <span style={{ fontSize: 13, fontWeight: 600 }}>📡 Activer la lecture SSH (fichier distant)</span>
                </label>
                <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4, marginLeft: 24 }}>
                  Cochez cette option si le fichier de logs est sur un serveur distant
                </div>
              </div>

              {/* Champs SSH */}
              {useSSH && (
                <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8, padding: 12, marginBottom: 12 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: '#374151' }}>
                    Configuration SSH
                  </div>

                  <label style={labelStyle}>Hôte SSH*</label>
                  <input
                    type="text"
                    style={inputStyle}
                    placeholder="hachi ou 192.168.1.x"
                    value={sshHost}
                    onChange={(e) => setSshHost(e.target.value)}
                  />

                  <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: 12 }}>
                    <div>
                      <label style={labelStyle}>Nom d'utilisateur*</label>
                      <input
                        type="text"
                        style={inputStyle}
                        placeholder="root"
                        value={sshUsername}
                        onChange={(e) => setSshUsername(e.target.value)}
                      />
                    </div>
                    <div>
                      <label style={labelStyle}>Port</label>
                      <input
                        type="text"
                        style={inputStyle}
                        placeholder="22"
                        value={sshPort}
                        onChange={(e) => setSshPort(e.target.value)}
                      />
                    </div>
                  </div>

                  <label style={labelStyle}>Mot de passe SSH*</label>
                  <input
                    type="password"
                    style={inputStyle}
                    placeholder="Mot de passe SSH"
                    value={sshPassword}
                    onChange={(e) => setSshPassword(e.target.value)}
                  />

                  <div style={{ fontSize: 11, color: '#6b7280', marginTop: -8 }}>
                    🔒 Les informations SSH seront stockées localement de manière sécurisée
                  </div>
                </div>
              )}
            </>
          )}

          <div style={{ background: '#fef3c7', border: '1px solid #fbbf24', borderRadius: 6, padding: 10, marginBottom: 12 }}>
            <div style={{ fontSize: 12, color: '#92400e' }}>
              ⚠️ <strong>Important :</strong> L'activation d'un audit device nécessite des permissions root/admin dans Vault.
            </div>
          </div>

          <div style={buttonRowStyle}>
            <button
              type="button"
              style={btnStyle}
              onClick={() => setShowEnableAuditModal(false)}
            >
              Annuler
            </button>
            <button
              type="button"
              style={btnPrimaryStyle}
              onClick={handleEnable}
            >
              ✓ Activer
            </button>
          </div>
        </div>
      </div>
    );
  }
}
