// ========================================
// HOOK: useEngines — Gestion des secret engines Vault
// ========================================
import { useState } from 'react';
import axios from 'axios';
import { encodeEnginePath, sanitizeErrorMessage } from '../utils/security';

export function useEngines(options) {
  const {
    vaultApiRef,
    vaultUrl,
    token,
    setSecrets,
    fetchSecretsRef,
    restoreFocus,
    showToast, t,
  } = options;

  const [secretEngines, setSecretEngines] = useState([]);
  const [selectedEngine, setSelectedEngine] = useState(null);
  const [engineToDelete, setEngineToDelete] = useState(null);
  const [deletingEngine, setDeletingEngine] = useState(false);
  const [showEngineModal, setShowEngineModal] = useState(false);
  const [loadingMounts, setLoadingMounts] = useState(false);
  const [lastError, setLastError] = useState('');
  const [lastUiError, setLastUiError] = useState('');

  const fetchEnginesLikeUi = async (userToken = token) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;

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

  const createEngine = async ({ name, version, description }) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { baseHeaders, axiosConfig } = vaultApi;

    const mountPath = name.replace(/^\/+|\/+$/g, '');
    const body = { type: 'kv', description: description || undefined, options: { version: String(version) } };
    try {
      await axios.post(`${vaultUrl}/v1/sys/mounts/${encodeEnginePath(mountPath)}`, body, axiosConfig({ headers: baseHeaders() }));
      await fetchEnginesLikeUi(token);
      const created = { name: mountPath, version: Number(version) === 2 ? 2 : 1 };
      setSelectedEngine(created);
      await fetchSecretsRef.current(created);
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
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { baseHeaders, axiosConfig } = vaultApi;

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
      restoreFocus();
      showToast(t('toast.engineDeleted'), 'success');
    } catch (err) {
      const msg = sanitizeErrorMessage(err);
      showToast(`${t('error.engineDelete')} : ${msg}`, 'error');
    } finally {
      setDeletingEngine(false);
    }
  };

  return {
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
  };
}
