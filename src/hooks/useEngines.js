// ========================================
// HOOK: useEngines — Gestion des secret engines Vault
// ========================================
import { useState } from 'react';
import axios from 'axios';
import { encodeEnginePath, sanitizeErrorMessage } from '../utils/security';
import secureLogger from '../secureLogger';

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

  /**
   * Liste des coffres relue. Sélection : premier coffre (connexion), ou, avec `keepSelection`, le coffre
   * affiché s'il existe encore (APP-8 : supprimer ou créer un AUTRE coffre renvoyait sur le premier coffre
   * sans la remise à zéro d'un changement de coffre).
   * @param {string} [userToken]
   * @param {{ keepSelection?: boolean }} [options]
   */
  const fetchEnginesLikeUi = async (userToken = token, { keepSelection = false } = {}) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;

    const { engines, errors } = await vaultApi.fetchEnginesRaw(userToken);
    // Les erreurs partielles (UI mounts / sys/mounts) ne sont plus stockées dans
    // un état inutilisé (lastError/lastUiError) : simple trace de debug.
    if (errors?.uiError) secureLogger.debug('[Engines] Erreur listing UI mounts');
    if (errors?.sysError) secureLogger.debug('[Engines] Erreur listing sys/mounts');
    setSecretEngines(engines);
    // Coffre affiché conservé tel quel (même objet : sa liste n'est pas relue inutilement)
    setSelectedEngine(prev => ((keepSelection && prev && engines.some(e => e.name === prev.name)) ? prev : (engines[0] || null)));
    if (!engines.length) setSecrets([]);
  };

  const createEngine = async ({ name, version, description }) => {
    const vaultApi = vaultApiRef.current;
    if (!vaultApi) return;
    const { baseHeaders, axiosConfig } = vaultApi;

    const mountPath = name.replace(/^\/+|\/+$/g, '');
    const body = { type: 'kv', description: description || undefined, options: { version: String(version) } };
    try {
      await axios.post(`${vaultUrl}/v1/sys/mounts/${encodeEnginePath(mountPath)}`, body, axiosConfig({ headers: baseHeaders() }));
      await fetchEnginesLikeUi(token, { keepSelection: true });
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
      // APP-8 : un AUTRE coffre supprimé → le coffre affiché reste affiché (avant : premier coffre de la
      // liste, sans remise à zéro, mot de passe homonyme révélé en clair)
      await fetchEnginesLikeUi(token, { keepSelection: true });
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
    fetchEnginesLikeUi,
    createEngine,
    confirmDeleteEngine,
    deleteEngine,
  };
}
