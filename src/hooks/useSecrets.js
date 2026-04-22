// ========================================
// HOOK: useSecrets — CRUD des secrets Vault
// ========================================
import { useState, useCallback, useMemo } from 'react';
import axios from 'axios';
import secureLogger from '../secureLogger';
import { encodeEnginePath, sanitizeErrorMessage } from '../utils/security';

export function useSecrets(options) {
  const {
    vaultApiRef,
    vaultUrl,
    selectedEngine,
    search,
    showDeleted,
    treeViewRef,
    multiVaultSearch, allVaultSecrets, setAllVaultSecrets,
    mergeDiscoveredAndSharedTagsRef,
    setDiscoveredTags,
    syncExtensionRef,
    restoreFocus,
    // TOTP
    getTotpKeyName, checkTotpExists, totpEngineName,
    showToast, t,
  } = options;

  // Lire les valeurs treeView depuis la ref (casse la dépendance circulaire)
  const getTreeView = () => treeViewRef?.current || { treeViewEnabled: false, currentPath: '', currentFolderContent: null };

  const [secrets, setSecrets] = useState([]);
  const [editSecret, setEditSecret] = useState(null);
  const [secretToDelete, setSecretToDelete] = useState(null);
  const [deletingSecret, setDeletingSecret] = useState(false);
  const [loadingSecrets, setLoadingSecrets] = useState(false);
  const [versionHistory, setVersionHistory] = useState(null);
  const [loadingAllSecrets, setLoadingAllSecrets] = useState(false);

  const fetchSecrets = async (engine, includeDeleted = false) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { listKeysV2, listKeysV1, readSecretV2, readSecretV1, baseHeaders, axiosConfig } = vaultApi;

    setLoadingSecrets(true);
    try {
      const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
      secureLogger.debug('[fetchSecrets]', engine.name, keys.length);

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
      const mergeFn = mergeDiscoveredAndSharedTagsRef.current;
      if (mergeFn) {
        const tags = await mergeFn(all);
        secureLogger.debug('[fetchSecrets] tags:', tags.length);
        setDiscoveredTags(tags);
      }

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

  const confirmDeleteSecret = async (secret) => {
    const totpKeyName = getTotpKeyName(secret.name);
    const totpExists = await checkTotpExists(totpKeyName);
    setSecretToDelete({ ...secret, totpExists });
  };

  const deleteSecret = async () => {
    if (!secretToDelete || !selectedEngine) return;
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { deleteSecretV2, deleteSecretV1, baseHeaders, axiosConfig } = vaultApi;

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

      setSecrets(prev => prev.filter(s => s.name !== key));
      setSecretToDelete(null);

      if (selectedEngine.version === 1) await new Promise(r => setTimeout(r, 300));

      await fetchSecrets(selectedEngine, showDeleted);
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
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { baseHeaders, axiosConfig } = vaultApi;

    const key = secret.name;
    try {
      const metaRes = await axios.get(`${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/metadata/${encodeURIComponent(key)}`, axiosConfig({ headers: baseHeaders() }));
      const versions = Object.keys(metaRes.data?.data?.versions || {}).map(Number);

      if (versions.length > 0) {
        await axios.post(`${vaultUrl}/v1/${encodeEnginePath(selectedEngine.name)}/undelete/${encodeURIComponent(key)}`, { versions }, axiosConfig({ headers: baseHeaders() }));
      }
      await fetchSecrets(selectedEngine, showDeleted);
      syncExtensionRef.current?.();
      showToast(t('toast.secretRestored', { version: key }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.retrieveSecret')} ${msg}`, 'error');
    }
  };

  const handleRestoreVersion = async (version, versionData) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { writeSecretV2 } = vaultApi;

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
      syncExtensionRef.current?.();
      showToast(t('toast.versionRestored', { version }), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.restoreVersion')} ${msg}`, 'error');
    }
  };

  const handleEditSecretSave = useCallback(async (updated) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { writeSecretV2, writeSecretV1, deleteSecretV2, deleteSecretV1 } = vaultApi;

    try {
      if (!selectedEngine) throw new Error('Aucun moteur sélectionné');
      if (!updated.name || !updated.name.trim()) { showToast(t('error.nameRequired'), 'error'); return; }

      // Création de dossier via .placeholder
      if (updated.entryType === 'folder') {
        const folderName = updated.name.trim().replace(/\/+$/, '');
        const { treeViewEnabled, currentPath } = getTreeView();
        const placeholderPath = (treeViewEnabled && currentPath ? `${currentPath}/` : '') + folderName + '/.placeholder';
        const placeholderEntry = {
          name: placeholderPath,
          username: '', password: '', url: '', website: '', notes: '', tags: '',
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
      syncExtensionRef.current?.();
      restoreFocus();
      showToast(t('toast.secretSaved'), 'success');
    } catch (err) {
      restoreFocus();
      let msg = sanitizeErrorMessage(err);

      if (err.response?.status === 500) {
        msg = 'Le secret est trop volumineux. Réduisez la taille des fichiers joints (max 2 MB par fichier recommandé) ou le nombre de champs personnalisés.';
      }

      showToast(`${t('error.saveSecret')} ${msg}`, 'error');
    }
  }, [selectedEngine, editSecret]); // eslint-disable-line

  const handleEditSecretClose = useCallback(() => {
    setEditSecret(null);
    restoreFocus();
  }, []); // eslint-disable-line

  // Mémoiser le filtrage du tableau (hot path)
  const filteredSecrets = useMemo(() => {
    const { treeViewEnabled, currentPath, currentFolderContent } = getTreeView();
    const rawSourceSecrets = multiVaultSearch && search.trim()
      ? allVaultSecrets
      : (treeViewEnabled && !multiVaultSearch
          ? (search.trim()
              ? secrets
                  .filter(s => !currentPath || s.name.startsWith(currentPath + '/'))
                  .map(s => ({ ...s, displayName: s.name.split('/').pop() }))
              : currentFolderContent)
          : secrets);
    const sourceSecrets = rawSourceSecrets.filter(s => !s.name?.endsWith('/.placeholder') && s.name !== '.placeholder');
    const filtered = sourceSecrets.filter(s => {
      const searchRaw = search.trim();
      if (!searchRaw) return true;

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

      if (searchTags.length > 0) {
        const secretTags = s.tags ? s.tags.toLowerCase().split(/[\s,;]+/).filter(t => t) : [];
        const allTagsMatch = searchTags.every(tag => secretTags.some(st => st.includes(tag)));
        if (!allTagsMatch) return false;
        if (!textQuery) return true;
      }

      if (s.isFolder) {
        return s.displayName.toLowerCase().includes(textQuery) ||
               s.name.toLowerCase().includes(textQuery);
      }

      const searchName = treeViewEnabled && s.name.includes('/')
        ? s.name.split('/').pop()
        : s.name;

      const matchesStandard =
        searchName.toLowerCase().includes(textQuery) ||
        (s.username && s.username.toLowerCase().includes(textQuery)) ||
        (s.notes && s.notes.toLowerCase().includes(textQuery)) ||
        (s.url && s.url.toLowerCase().includes(textQuery)) ||
        false;

      const matchesCustomFields = s.customFields && Array.isArray(s.customFields) && s.customFields.some(
        field => field.value && !field.protected && String(field.value).toLowerCase().includes(textQuery)
      );

      return matchesStandard || matchesCustomFields;
    });

    return filtered;
  }, [multiVaultSearch, search, allVaultSecrets, secrets, showDeleted]); // eslint-disable-line

  return {
    secrets, setSecrets,
    editSecret, setEditSecret,
    secretToDelete, setSecretToDelete,
    deletingSecret,
    loadingSecrets, setLoadingSecrets,
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
  };
}
