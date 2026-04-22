import { useState, useEffect } from 'react';
import secureLogger from '../secureLogger';

/**
 * Hook de chargement de la configuration de l'application.
 * Charge les paramètres depuis config.json via Electron au démarrage.
 * @param {Function} setLang - Setter de langue depuis useTranslation
 * @returns {Object} Configuration chargée
 */
export function useConfig(setLang) {
  const [vaultUrl, setVaultUrl] = useState('');
  const [ldapAuthPath, setLdapAuthPath] = useState('auth/ldap');
  const [rbiProxyUrl, setRbiProxyUrl] = useState('');
  const [configLoaded, setConfigLoaded] = useState(false);
  const [appMode, setAppMode] = useState('enterprise'); // 'enterprise' ou 'local'
  const [vaultNs, setVaultNs] = useState('');

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
  }, []); // eslint-disable-line

  return { vaultUrl, ldapAuthPath, rbiProxyUrl, configLoaded, appMode, vaultNs };
}
