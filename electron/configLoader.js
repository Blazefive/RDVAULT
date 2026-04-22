// ========================================
// CONFIG LOADER - Chargement de la configuration
// ========================================
// Ce module gère le chargement de la configuration de l'application.
// La configuration peut provenir de :
// 1. config.cfg dans le dossier d'installation (prioritaire, format clé=valeur)
// 2. config.json dans le dossier d'installation (format JSON)
// 3. config.cfg dans le dossier userData
// 4. config.json dans le dossier userData
// 5. config.default.json embarqué dans l'application (fallback)
//
// Formats supportés :
// - .cfg : Format clé=valeur avec commentaires # (voir config.example.cfg)
// - .json : Format JSON standard
//
// Paramètres configurables :
// - VAULT_URL : URL du serveur HashiCorp Vault
// - LDAP_AUTH_PATH : Chemin d'authentification LDAP (ex: auth/ldap)
// - TRUSTED_DOMAINS : Liste des domaines SSL de confiance (séparés par virgules)
// - RBI_PROXY_URL : URL du proxy RBI pour le partage de sessions sécurisées

const fs = require('fs');
const path = require('path');
const { app } = require('electron');

// Configuration par défaut (utilisée si aucun fichier trouvé)
// SÉCURITÉ: Les valeurs par défaut ne contiennent pas d'IPs/hostnames internes
// Configurer via config.cfg ou config.json dans le dossier d'installation
const DEFAULT_CONFIG = {
  VAULT_URL: 'https://vault.example.com:8200',
  LDAP_AUTH_PATH: 'auth/ldap',
  TRUSTED_DOMAINS: 'localhost,127.0.0.1',
  RBI_PROXY_URL: '',
  APP_MODE: 'enterprise',  // 'enterprise' (Vault distant) ou 'local' (base locale)
  LANG: 'en'               // Langue par défaut (en, fr, es, de, ru, zh, pt, it, ja, ko, ar, tr)
};

// Cache de la configuration chargée
let loadedConfig = null;

/**
 * Parse un fichier de configuration au format .cfg
 * Format: clé=valeur, lignes commençant par # sont des commentaires
 *
 * @param {string} content - Contenu du fichier .cfg
 * @returns {Object} Configuration parsée
 */
function parseCfgFile(content) {
  const config = {};
  const lines = content.split('\n');

  for (const line of lines) {
    // Ignorer les lignes vides et les commentaires
    const trimmedLine = line.trim();
    if (!trimmedLine || trimmedLine.startsWith('#')) {
      continue;
    }

    // Parser les lignes clé=valeur
    const equalIndex = trimmedLine.indexOf('=');
    if (equalIndex > 0) {
      const key = trimmedLine.substring(0, equalIndex).trim();
      const value = trimmedLine.substring(equalIndex + 1).trim();

      // Ne stocker que les clés reconnues
      if (key === 'VAULT_URL' || key === 'LDAP_AUTH_PATH' || key === 'TRUSTED_DOMAINS' || key === 'RBI_PROXY_URL' || key === 'APP_MODE' || key === 'LANG') {
        config[key] = value;
      }
    }
  }

  return config;
}

/**
 * Charge la configuration depuis les fichiers disponibles
 *
 * Ordre de priorité :
 * 1. config.cfg dans le dossier d'installation (format clé=valeur)
 * 2. config.json dans le dossier d'installation (format JSON)
 * 3. config.cfg dans le dossier userData
 * 4. config.json dans le dossier userData
 * 5. config.default.json dans les ressources de l'application
 * 6. Configuration par défaut en dur
 *
 * @returns {Object} Configuration chargée
 */
function loadConfig() {
  // Retourner le cache si déjà chargé
  if (loadedConfig !== null) {
    return loadedConfig;
  }

  const configPaths = [];

  // En mode packagé (production)
  if (app.isPackaged) {
    // 1. config.cfg dans le dossier d'installation (prioritaire)
    configPaths.push({ path: path.join(path.dirname(process.execPath), 'config.cfg'), type: 'cfg' });
    // 2. config.json dans le dossier d'installation
    configPaths.push({ path: path.join(path.dirname(process.execPath), 'config.json'), type: 'json' });
    // 3. config.cfg dans userData
    configPaths.push({ path: path.join(app.getPath('userData'), 'config.cfg'), type: 'cfg' });
    // 4. config.json dans userData
    configPaths.push({ path: path.join(app.getPath('userData'), 'config.json'), type: 'json' });
    // 5. config.default.json dans resources
    configPaths.push({ path: path.join(process.resourcesPath, 'config.default.json'), type: 'json' });
  } else {
    // Mode développement
    // 1. config.cfg à la racine du projet (prioritaire)
    configPaths.push({ path: path.join(__dirname, '..', 'config.cfg'), type: 'cfg' });
    // 2. config.json à la racine du projet
    configPaths.push({ path: path.join(__dirname, '..', 'config.json'), type: 'json' });
    // 3. config.default.json à la racine du projet
    configPaths.push({ path: path.join(__dirname, '..', 'config.default.json'), type: 'json' });
  }

  // Essayer de charger depuis chaque chemin
  for (const configEntry of configPaths) {
    try {
      if (fs.existsSync(configEntry.path)) {
        const content = fs.readFileSync(configEntry.path, 'utf8');
        let config;

        // Parser selon le type de fichier
        if (configEntry.type === 'cfg') {
          config = parseCfgFile(content);
        } else {
          config = JSON.parse(content);
        }

        // Valider et compléter avec les valeurs par défaut
        const candidateUrl = config.VAULT_URL || DEFAULT_CONFIG.VAULT_URL;

        // SÉCURITÉ: Valider que VAULT_URL est bien une URL https:// valide
        // Empêche un fichier config malveillant de rediriger vers un faux Vault
        let validVaultUrl = DEFAULT_CONFIG.VAULT_URL;
        try {
          const parsed = new URL(candidateUrl);
          if (parsed.protocol === 'https:' && parsed.hostname && !parsed.username && !parsed.password) {
            validVaultUrl = candidateUrl;
          } else {
            console.warn(`[CONFIG] VAULT_URL rejetée (protocole non-HTTPS ou credentials dans l'URL): ${parsed.protocol}`);
          }
        } catch (e) {
          console.warn(`[CONFIG] VAULT_URL invalide, utilisation du défaut`);
        }

        // APP_MODE : 'local' ou 'enterprise' (défaut)
        const appMode = (config.APP_MODE === 'local') ? 'local' : 'enterprise';

        // SÉCURITÉ: Valider LDAP_AUTH_PATH (prévention path traversal)
        let safeLdapPath = (config.LDAP_AUTH_PATH || DEFAULT_CONFIG.LDAP_AUTH_PATH).replace(/^\/+|\/+$/g, '');
        if (!/^[a-zA-Z0-9\-_\/]+$/.test(safeLdapPath) || safeLdapPath.includes('..')) {
          console.warn('[CONFIG] LDAP_AUTH_PATH invalide, utilisation du défaut');
          safeLdapPath = DEFAULT_CONFIG.LDAP_AUTH_PATH;
        }

        // SÉCURITÉ: Valider RBI_PROXY_URL
        let safeRbiUrl = config.RBI_PROXY_URL || DEFAULT_CONFIG.RBI_PROXY_URL;
        if (safeRbiUrl) {
          try {
            const parsed = new URL(safeRbiUrl);
            if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
              console.warn('[CONFIG] RBI_PROXY_URL invalide, ignorée');
              safeRbiUrl = '';
            }
          } catch {
            console.warn('[CONFIG] RBI_PROXY_URL invalide, ignorée');
            safeRbiUrl = '';
          }
        }

        loadedConfig = {
          VAULT_URL: appMode === 'local' ? 'http://127.0.0.1:0' : validVaultUrl,
          LDAP_AUTH_PATH: safeLdapPath,
          TRUSTED_DOMAINS: config.TRUSTED_DOMAINS || DEFAULT_CONFIG.TRUSTED_DOMAINS,
          RBI_PROXY_URL: safeRbiUrl,
          APP_MODE: appMode,
          LANG: config.LANG || DEFAULT_CONFIG.LANG
        };

        // SÉCURITÉ: Ne pas logger les valeurs de configuration (IPs/domaines internes)
        console.log(`[CONFIG] Configuration chargée depuis: ${configEntry.path} (format: ${configEntry.type})`);

        return loadedConfig;
      }
    } catch (err) {
      console.warn(`[CONFIG] Erreur lecture ${configEntry.path}:`, err.message);
    }
  }

  // Aucun fichier trouvé, utiliser la config par défaut
  console.log('[CONFIG] Aucun fichier de configuration trouvé, utilisation des valeurs par défaut');
  loadedConfig = { ...DEFAULT_CONFIG };
  return loadedConfig;
}

/**
 * Retourne la liste des domaines de confiance sous forme de tableau
 *
 * @returns {string[]} Liste des domaines
 */
function getTrustedDomains() {
  const config = loadConfig();
  return config.TRUSTED_DOMAINS.split(',').map(d => d.trim()).filter(d => d.length > 0);
}

/**
 * Retourne l'URL du serveur Vault
 *
 * @returns {string} URL du serveur Vault
 */
function getVaultUrl() {
  const config = loadConfig();
  return config.VAULT_URL;
}

/**
 * Retourne le chemin d'authentification LDAP
 *
 * @returns {string} Chemin LDAP (ex: auth/ldap)
 */
function getLdapAuthPath() {
  const config = loadConfig();
  return config.LDAP_AUTH_PATH;
}

/**
 * Retourne l'URL du proxy RBI
 *
 * @returns {string} URL du proxy RBI
 */
function getRbiProxyUrl() {
  const config = loadConfig();
  return config.RBI_PROXY_URL;
}

/**
 * Retourne le mode de l'application ('enterprise' ou 'local')
 * @returns {string}
 */
function getAppMode() {
  const config = loadConfig();
  return config.APP_MODE || 'enterprise';
}

/**
 * Retourne toute la configuration
 *
 * @returns {Object} Configuration complète
 */
function getConfig() {
  return loadConfig();
}

/**
 * Recharge la configuration depuis le disque (utile pour les tests)
 *
 * @returns {Object} Configuration rechargée
 */
function reloadConfig() {
  loadedConfig = null;
  return loadConfig();
}

module.exports = {
  loadConfig,
  getConfig,
  getTrustedDomains,
  getVaultUrl,
  getLdapAuthPath,
  getRbiProxyUrl,
  getAppMode,
  reloadConfig,
  parseCfgFile,
  DEFAULT_CONFIG
};
