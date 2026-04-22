import { useState } from 'react';
import secureLogger from '../secureLogger';

/**
 * Hook useMigration — gère la migration/copie de secrets entre engines
 * et le déplacement de secrets vers des dossiers (intra-engine).
 */
export function useMigration({
  vaultApi,
  selectedEngine,
  secretEngines,
  fetchSecretsRef,
  showDeleted,
  clearSelection,
  syncExtensionRef,
  showToast,
  t
}) {
  const [migrateSecrets, setMigrateSecrets] = useState(null);   // { secrets: [], mode: 'copy'|'move' }
  const [moveToFolder, setMoveToFolder] = useState(null);        // { secrets: [] } - déplacement intra-engine

  const { readSecretV2, readSecretV1, writeSecretV2, writeSecretV1, deleteSecretV2, deleteSecretV1,
          listKeysV2, listKeysV1, readSecretForMigration, writeSecretToEngine, deleteSecretFromEngine } = vaultApi;

  // Récupérer la liste des noms de secrets d'un engine (léger, pour détection doublons)
  const fetchSecretsForEngine = async (engine) => {
    try {
      const keys = engine.version === 2 ? await listKeysV2(engine) : await listKeysV1(engine);
      return keys.map(k => ({ name: k }));
    } catch { return []; }
  };

  // Migration/Copie d'entrées (supporte un tableau de secrets)
  const handleMigrateSecrets = async (secretsList, targetEngine, mode) => {
    const secrets = Array.isArray(secretsList) ? secretsList : [secretsList];
    if (secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
    let successCount = 0;
    let failCount = 0;
    let renamedCount = 0;

    // Récupérer la liste des secrets existants dans le coffre cible pour détecter les doublons
    let targetSecretNames = new Set();
    try {
      const targetSecrets = await fetchSecretsForEngine(targetEngine);
      targetSecretNames = new Set((targetSecrets || []).map(s => s.name));
    } catch (e) { /* coffre vide ou erreur, on continue */ }

    for (const secret of secrets) {
      try {
        const sourceData = selectedEngine.version === 2
          ? await readSecretV2(selectedEngine, secret.name)
          : await readSecretV1(selectedEngine, secret.name);

        // Vérifier si un secret du même nom existe dans la cible
        let targetName = sourceData.name;
        if (targetSecretNames.has(targetName)) {
          // Générer un nom unique avec suffixe
          let suffix = 1;
          while (targetSecretNames.has(`${sourceData.name}_${suffix}`)) suffix++;
          targetName = `${sourceData.name}_${suffix}`;
          renamedCount++;
        }
        const dataToWrite = { ...sourceData, name: targetName };
        targetSecretNames.add(targetName);

        if (targetEngine.version === 2) {
          await writeSecretV2(targetEngine, dataToWrite);
        } else {
          await writeSecretV1(targetEngine, dataToWrite);
        }

        if (mode === 'move') {
          if (selectedEngine.version === 2) {
            await deleteSecretV2(selectedEngine, secret.name);
          } else {
            await deleteSecretV1(selectedEngine, secret.name);
          }
        }
        successCount++;
      } catch (err) {
        secureLogger.error(`[Migration] Erreur ${mode}`);
        failCount++;
      }
    }

    await fetchSecretsRef.current(selectedEngine, showDeleted);
    clearSelection();
    syncExtensionRef.current?.();

    const renamedMsg = renamedCount > 0 ? ` (${renamedCount} renommée(s) pour éviter les doublons)` : '';
    if (failCount === 0) {
      showToast(t('toast.migrationSuccess', { count: successCount }), 'success');
    } else {
      showToast(`${successCount} / ${failCount}`, 'warning');
    }
  };

  // Déplacement de secrets vers un autre dossier (intra-engine) - supporte un tableau
  const handleMoveToFolder = async (secretsList, targetFolderPath) => {
    const secrets = Array.isArray(secretsList) ? secretsList : [secretsList];
    if (secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
    let successCount = 0;
    let failCount = 0;

    for (const secret of secrets) {
      try {
        // 1. Lire le secret source
        const sourceData = selectedEngine.version === 2
          ? await readSecretV2(selectedEngine, secret.name)
          : await readSecretV1(selectedEngine, secret.name);

        // 2. Calculer le nouveau nom
        const baseName = secret.name.split('/').pop();
        const newName = targetFolderPath ? `${targetFolderPath}/${baseName}` : baseName;

        // 3. Vérifier qu'on ne déplace pas au même endroit
        if (newName === secret.name) {
          continue; // Ignorer silencieusement
        }

        // 4. Écrire le secret avec le nouveau chemin
        const newEntry = { ...sourceData, name: newName };
        if (selectedEngine.version === 2) {
          await writeSecretV2(selectedEngine, newEntry);
          await deleteSecretV2(selectedEngine, secret.name);
        } else {
          await writeSecretV1(selectedEngine, newEntry);
          await deleteSecretV1(selectedEngine, secret.name);
        }
        successCount++;
      } catch (err) {
        secureLogger.error('[Déplacement] Erreur');
        failCount++;
      }
    }

    await fetchSecretsRef.current(selectedEngine, showDeleted);
    clearSelection();
    syncExtensionRef.current?.();

    if (failCount === 0) {
      showToast(t('toast.moveSuccess', { count: successCount }), 'success');
    } else {
      showToast(`${successCount} / ${failCount}`, 'warning');
    }
  };

  /**
   * Migre des secrets vers un autre engine (used by drag & drop)
   */
  const migrateSecretsToEngine = async (secretNames, sourceEngineName, sourceVersion, targetEngine) => {
    const sourceEngine = secretEngines.find(e => e.name === sourceEngineName);
    if (!sourceEngine) {
      showToast(t('error.engineNotFound'), 'error');
      return;
    }

    const successCount = { moved: 0, failed: 0 };

    for (const secretName of secretNames) {
      try {
        // Lire le secret source
        const secretData = await readSecretForMigration(sourceEngine, secretName);
        if (!secretData) {
          successCount.failed++;
          continue;
        }

        // Écrire dans l'engine cible
        const writeSuccess = await writeSecretToEngine(targetEngine, secretName, secretData);
        if (!writeSuccess) {
          successCount.failed++;
          continue;
        }

        // Supprimer de l'engine source
        const deleteSuccess = await deleteSecretFromEngine(sourceEngine, secretName);
        if (deleteSuccess) {
          successCount.moved++;
        } else {
          successCount.failed++;
        }

      } catch (err) {
        secureLogger.error('[Migration] Erreur');
        successCount.failed++;
      }
    }

    // Rafraîchir les secrets
    await fetchSecretsRef.current(selectedEngine, showDeleted);
    clearSelection();

    // Afficher le résultat
    if (successCount.failed === 0) {
      showToast(t('toast.migrationSuccess', { count: successCount.moved }), 'success');
    } else {
      showToast(`${successCount.moved} / ${successCount.failed}`, 'warning');
    }
  };

  /**
   * Déplace des secrets vers un dossier (intra-engine) (used by drag & drop)
   */
  const moveSecretsToFolder = async (secretNames, targetFolder) => {
    const successCount = { moved: 0, failed: 0 };

    for (const secretName of secretNames) {
      try {
        // Extraire le nom de base (sans le chemin)
        const baseName = secretName.split('/').pop();
        const newPath = targetFolder ? `${targetFolder}/${baseName}` : baseName;

        // Vérifier qu'on ne déplace pas vers le même endroit
        if (secretName === newPath) {
          continue;
        }

        // Lire le secret
        const secretData = await readSecretForMigration(selectedEngine, secretName);
        if (!secretData) {
          successCount.failed++;
          continue;
        }

        // Écrire au nouvel emplacement
        const writeSuccess = await writeSecretToEngine(selectedEngine, newPath, secretData);
        if (!writeSuccess) {
          successCount.failed++;
          continue;
        }

        // Supprimer l'ancien
        const deleteSuccess = await deleteSecretFromEngine(selectedEngine, secretName);
        if (deleteSuccess) {
          successCount.moved++;
        } else {
          successCount.failed++;
        }

      } catch (err) {
        secureLogger.error('[Déplacement] Erreur');
        successCount.failed++;
      }
    }

    // Rafraîchir les secrets
    await fetchSecretsRef.current(selectedEngine);
    clearSelection();

    // Afficher le résultat
    if (successCount.failed === 0) {
      showToast(t('toast.moveSuccess', { count: successCount.moved }), 'success');
    } else {
      showToast(`${successCount.moved} / ${successCount.failed}`, 'warning');
    }
  };

  return {
    migrateSecrets, setMigrateSecrets,
    moveToFolder, setMoveToFolder,
    fetchSecretsForEngine,
    handleMigrateSecrets,
    handleMoveToFolder,
    migrateSecretsToEngine,
    moveSecretsToFolder
  };
}
