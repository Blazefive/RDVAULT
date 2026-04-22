import { useState } from 'react';
import axios from 'axios';
import { useRateLimit } from '../useRateLimit';
import { sanitizeErrorMessage } from '../utils/security';

/**
 * Hook de gestion TOTP (Time-based One-Time Password).
 * Gere la configuration, l'affichage, la copie et la suppression des cles TOTP.
 *
 * @param {Object} options
 * @param {string} options.vaultUrl - URL du serveur Vault
 * @param {Function} options.baseHeaders - Fonction retournant les headers de base
 * @param {Function} options.axiosConfig - Fonction retournant la config axios
 * @param {Object|null} options.selectedEngine - Engine actuellement selectionne
 * @param {Function} options.startClipboardTimer - Fonction pour copier avec timer
 * @param {Function} options.showToast - Fonction pour afficher un toast
 * @param {Function} options.t - Fonction de traduction
 * @param {Function} options.restoreFocus - Fonction pour restaurer le focus
 * @returns {Object} Etats et handlers TOTP
 */
export function useTotp({ vaultUrl, baseHeaders, axiosConfig, selectedEngine, startClipboardTimer, showToast, t, restoreFocus }) {
  const totpEngineName = 'TOTP';

  const [totpDisplay, setTotpDisplay] = useState(null);
  const [totpConfig, setTotpConfig] = useState(null);
  const [totpExistsCache, setTotpExistsCache] = useState({});

  const totpRateLimit = useRateLimit(10, 60000); // Max 10 generations TOTP par minute

  const getTotpKeyName = (secretName) => {
    if (!selectedEngine) return secretName;
    const engineName = selectedEngine.name
      .replace(/^users\/[^/]+\//i, '')
      .replace(/\/$/, '')
      .toUpperCase();
    return `${engineName}-${secretName}`;
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

  return {
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
  };
}
