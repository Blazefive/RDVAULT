// ========================================
// HOOK: useAuth — Authentification LDAP Vault
// ========================================
import { useState, useRef, useCallback } from 'react';
import axios from 'axios';
import * as validation from '../validation';
import bruteForceProtection from '../bruteForceProtection';
import secureLogger from '../secureLogger';
import { sanitizeError, sanitizeErrorMessage } from '../utils/security';

/**
 * Hook d'authentification LDAP Vault.
 *
 * @param {object} options - dépendances stables ou recréées chaque rendu
 *   vaultUrl, ldapAuthPath, showToast, t,
 *   vaultApiRef  — { current: vaultApi } (ref pour éviter la dépendance circulaire)
 *   setters pour l'état global que le hook doit vider au logout
 */
export function useAuth(options) {
  const {
    vaultUrl, ldapAuthPath,
    showToast, t,
    vaultApiRef,
    // Refs vers des callbacks définies après le hook
    fetchEnginesLikeUiRef,
    // Setters passés depuis App pour le cleanup au logout
    setSecretEngines, setSelectedEngine, setSecrets,
    setCurrentView, setVisiblePasswords,
    setAllVaultSecrets, setDiscoveredTags, setMultiVaultSearch,
    setSelectedSecrets,
    setSearchState, // { setSearch, setSearchInput }
  } = options;

  const [authUser, setAuthUser] = useState(() => {
    return localStorage.getItem('rdvault-saved-username') || '';
  });
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [isModerator, setIsModerator] = useState(false);
  const [moderatorEngines, setModeratorEngines] = useState([]);
  const [rememberMe, setRememberMe] = useState(() => {
    return !!localStorage.getItem('rdvault-saved-username');
  });
  const [rbiOnlyEngines, setRbiOnlyEngines] = useState(new Set());
  const [rbiOnlySecrets, setRbiOnlySecrets] = useState(new Set());

  // Vérifier si le coffre sélectionné est entièrement RBI-Only
  const isCurrentEngineRbiOnly = (selectedEngine) => {
    return selectedEngine && rbiOnlyEngines.has(selectedEngine.name);
  };

  // Vérifier si un secret spécifique est RBI-Only
  const isSecretRbiOnly = (secretName, selectedEngine) => {
    if (!selectedEngine) return false;
    if (rbiOnlyEngines.has(selectedEngine.name)) return true;
    return rbiOnlySecrets.has(selectedEngine.name + '/' + secretName);
  };

  // SÉCURITÉ: Nettoyage des données sensibles dans localStorage lors de la déconnexion
  const cleanupOnLogout = useCallback(() => {
    localStorage.removeItem('vault-client.username');
    localStorage.removeItem('vault-client.isAdmin');
    if (window.electronCLI?.revokeSession) {
      window.electronCLI.revokeSession().catch(() => {});
    }
    // SÉCURITÉ: Nettoyer toutes les données sensibles du localStorage
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('vault-audit-ssh-')) localStorage.removeItem(key);
    });
    localStorage.removeItem('rdvault-cli-session');
    localStorage.removeItem('rdvault-cli-auto-approve');
    localStorage.removeItem('rdvault-cli-list-approve');
    localStorage.removeItem('rdvault-user-tags');
    // Nettoyer le sessionStorage (brute force state)
    try { sessionStorage.removeItem('rdvault-bf-state'); } catch { /* ignore */ }
    setVisiblePasswords({});
    setAllVaultSecrets([]);
    setSelectedSecrets(new Set());
    setDiscoveredTags([]);
    setIsModerator(false);
    setModeratorEngines([]);
    setMultiVaultSearch(false);
    // SÉCURITÉ: Vider le fichier de sync extension Chrome
    try {
      if (window.electronSync?.writeState) {
        window.electronSync.writeState({
          vaultUrl: '', username: '', connected: false, secrets: []
        });
      }
    } catch (err) { /* ignore */ }
  }, [setVisiblePasswords, setAllVaultSecrets, setSelectedSecrets, setDiscoveredTags, setMultiVaultSearch]);

  // SÉCURITÉ: Révoquer le token Vault côté serveur avant déconnexion
  const revokeToken = useCallback(async () => {
    if (!token) return;
    const api = vaultApiRef.current;
    if (!api) return;
    try {
      await axios.post(`${vaultUrl}/v1/auth/token/revoke-self`, null, api.axiosConfig({ headers: api.baseHeaders() }));
    } catch { /* best-effort */ }
  }, [token, vaultUrl, vaultApiRef]);

  const handleLogin = async () => {
    const api = vaultApiRef.current;
    if (!api) return;
    const { baseHeaders, axiosConfig } = api;
    try {
      // SÉCURITÉ: Validation des entrées
      if (!authUser || !password) {
        showToast(t('login.fieldsRequired'), 'error');
        return;
      }

      const usernameValidation = validation.validateUsername(authUser);
      if (!usernameValidation.valid) {
        showToast(usernameValidation.error, 'error');
        return;
      }

      const passwordValidation = validation.validatePassword(password);
      if (!passwordValidation.valid) {
        showToast(passwordValidation.error, 'error');
        return;
      }

      // SÉCURITÉ: Vérifier le brute force protection
      if (bruteForceProtection.isBlocked(authUser)) {
        const stats = bruteForceProtection.getStats(authUser);
        const remainingSeconds = Math.ceil((stats.blockedUntil - Date.now()) / 1000);
        showToast(t('login.bruteForceLocked', { seconds: remainingSeconds }), 'error', 4000);
        return;
      }

      // SÉCURITÉ: Capturer et effacer le mot de passe du state AVANT la requête réseau
      let currentPassword = password;
      setPassword('');
      try {
      const res = await axios.post(`${vaultUrl}/v1/${ldapAuthPath}/login/${encodeURIComponent(authUser)}`, { password: currentPassword }, axiosConfig({ headers: baseHeaders() }));
      const userToken = res.data?.auth?.client_token;
      setToken(userToken);

      // SÉCURITÉ: Connexion réussie - Reset brute force protection
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

        // Détecter si l'utilisateur est admin
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
              for (const m of policyHcl.matchAll(/# RBI-ONLY\npath "([^"]+)\/metadata\/\*"/g)) {
                rbiEnginesSet.add(m[1]);
              }
              for (const m of policyHcl.matchAll(/# RBI-ONLY\npath "([^"]+)\/\*"/g)) {
                rbiEnginesSet.add(m[1]);
              }
              for (const m of policyHcl.matchAll(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/metadata\/([^"*\s]+)"/g)) {
                rbiSecretsSet.add(m[1] + '/' + m[2]);
              }
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
      } catch {
        localStorage.setItem('vault-client.username', authUser);
        setIsAdmin(false);
        setIsModerator(false);
      }

      await fetchEnginesLikeUiRef.current(userToken);

      showToast(t('login.success'), 'success');

      // Passer la fenêtre en mode principal (1280x800)
      if (window.electronWindow?.setMainMode) await window.electronWindow.setMainMode();
      } finally {
        // SÉCURITÉ: Effacer la copie locale du mot de passe
        currentPassword = undefined;
      }
    } catch (err) {
      // SÉCURITÉ: Différencier erreur réseau vs erreur d'authentification
      const isNetworkError = !err.response && (
        err.code === 'ECONNREFUSED' || err.code === 'ECONNABORTED' ||
        err.code === 'ETIMEDOUT' || err.code === 'ERR_NETWORK' ||
        err.message?.includes('Network Error')
      );

      if (isNetworkError) {
        showToast(t('login.networkError'), 'error', 5000);
        secureLogger.warn('Échec connexion : erreur réseau (non décompté)');
      } else if (authUser) {
        const bruteForceResult = bruteForceProtection.registerFailedAttempt(authUser);

        if (bruteForceResult.blocked) {
          showToast(bruteForceResult.message, 'error', 4000);
          secureLogger.warn('Tentative de connexion bloquée');
        } else {
          const safeMessage = sanitizeError(err);
          const detailedMessage = `${safeMessage}. ${bruteForceResult.message}`;
          showToast(`${t('login.failed')} : ${detailedMessage}`, 'error', 4000);
          secureLogger.warn(`Échec authentification (${bruteForceResult.remainingAttempts} tentatives restantes)`);
        }
      } else {
        const safeMessage = sanitizeError(err);
        showToast(`${t('login.failed')} : ${safeMessage}`, 'error');
      }
    }
  };

  const handleLogout = async () => {
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
    if (setSearchState) {
      setSearchState.setSearch('');
      setSearchState.setSearchInput('');
    }
    setPassword('');
    setCurrentView('vault');
    setIsAdmin(false);
    setRbiOnlyEngines(new Set());
    setRbiOnlySecrets(new Set());
    showToast(t('login.logoutSuccess'), 'success');
    if (window.electronWindow?.setLoginMode) await window.electronWindow.setLoginMode();
  };

  const handleSessionExpired = () => {
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
  };

  return {
    authUser, setAuthUser,
    password, setPassword,
    token, setToken,
    isAdmin, setIsAdmin,
    isModerator, setIsModerator,
    moderatorEngines, setModeratorEngines,
    rememberMe, setRememberMe,
    rbiOnlyEngines, setRbiOnlyEngines,
    rbiOnlySecrets, setRbiOnlySecrets,
    isCurrentEngineRbiOnly,
    isSecretRbiOnly,
    handleLogin,
    handleLogout,
    handleSessionExpired,
    revokeToken,
    cleanupOnLogout,
  };
}
