import { useEffect } from 'react';
import axios from 'axios';
import secureLogger from '../secureLogger';
import { sanitizeErrorMessage } from '../utils/security';

/**
 * Hook useSync — gère la synchronisation avec l'extension Chrome,
 * les listeners IPC CLI (secrets, engines, list) et les requêtes TOTP IPC.
 */
export function useSync({
  vaultApi,
  token,
  vaultUrl,
  authUser,
  secretEngines,
  selectedEngine,
  syncExtensionRef,
  totpRateLimit,
  showToast
}) {
  const { baseHeaders, axiosConfig, readSecretV2, readSecretV1, listKeysV2, listKeysV1 } = vaultApi;

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
  }, [secretEngines, token, vaultUrl, authUser]); // eslint-disable-line

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
  }, [token]); // eslint-disable-line

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
          { success: false, error: err.response?.status === 404 ? 'Secret introuvable' : (err.response?.status === 403 ? 'Access denied' : 'Error reading secret') },
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
  }, [token, secretEngines]); // eslint-disable-line

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
  }, [token, secretEngines]); // eslint-disable-line
}
