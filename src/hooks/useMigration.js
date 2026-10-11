import { useState, useRef } from 'react';
import secureLogger from '../secureLogger';
import { withRetry } from '../utils/mapLimit';
import { sanitizeErrorMessage } from '../utils/security';
import { buildTotpKeyName } from './useTotp';

/**
 * Nom libre dans `taken` : le nom lui-même, sinon `${nom}_${n}` (même règle que la modale
 * « Migrer »). Ne modifie pas `taken` : l'appelant y ajoute le nom une fois l'écriture faite.
 */
function uniqueName(name, taken) {
  if (!taken.has(name)) return { name, renamed: false };
  let suffix = 1;
  while (taken.has(`${name}_${suffix}`)) suffix++;
  return { name: `${name}_${suffix}`, renamed: true };
}

/** JSON à clés triées (comparaison d'une copie relue : l'ordre des clés peut changer au stockage) */
function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// Délai maximal d'une lecture / écriture brute : readSecretForMigration et writeSecretToEngine (vaultApi)
// n'appliquent pas le délai de 30 s d'axiosConfig ; sans borne, une requête bloquée immobiliserait
// toute la file ci-dessous. Passé ce délai, l'entrée est comptée en échec (source conservée).
const MIGRATION_REQUEST_TIMEOUT_MS = 60000;
function withTimeout(promise, fallback) {
  let timer;
  const expired = new Promise((resolve) => { timer = setTimeout(() => resolve(fallback), MIGRATION_REQUEST_TIMEOUT_MS); });
  return Promise.race([promise, expired]).finally(() => clearTimeout(timer));
}

// SECRETS-36 : file UNIQUE (niveau module) des opérations de migration / déplacement. Deux opérations
// qui se chevauchaient (second glisser-déposer lancé pendant le premier) lisaient chacune les noms pris
// de la destination AU DÉBUT, choisissaient le même nom libre et la seconde recouvrait la première.
// Chaque opération s'exécute désormais seule et relit les noms pris en commençant ; un échec ne bloque
// pas la suivante.
let migrationQueue = Promise.resolve();
function enqueueMigration(task) {
  const run = migrationQueue.then(task, task);
  migrationQueue = run.catch(() => {});
  return run;
}

/**
 * Hook useMigration — gère la migration/copie de secrets entre engines
 * et le déplacement de secrets vers des dossiers (intra-engine).
 *
 * Règles communes aux quatre chemins (modales et glisser-déposer) :
 * - les données BRUTES de l'entrée sont copiées (tous les champs, y compris ceux écrits par un
 *   autre outil hors du schéma RDVAULT : `username`/`password` en minuscules, `api_key`…) ;
 * - une entrée existante de la destination n'est jamais écrasée : renommage `_n` ; si les entrées de
 *   la destination ne peuvent pas être listées (réseau, 403, 5xx, liste trop grande), l'opération est
 *   annulée avant toute écriture (message traduit) au lieu de sauter la détection des doublons ;
 * - la source d'un déplacement est supprimée en douceur (KV v2 : historique restaurable) ; une source
 *   KV v1 (suppression définitive, sans historique) seulement après relecture conforme de la copie ;
 * - une entrée avec TOTP n'est pas déplacée si le nom de sa clé TOTP changerait : la graine n'est
 *   pas relisible par l'API, la clé deviendrait orpheline (et se rattacherait à une future entrée
 *   du même nom). La copie reste permise (la source garde son TOTP) ;
 * - les opérations sont sérialisées (file unique) ; en fin d'opération, c'est le coffre AFFICHÉ
 *   (et non celui capturé au lancement) qui est rafraîchi, et l'extension est resynchronisée (APP-7 :
 *   aussi pour le glisser-déposer) ;
 * - création seule à destination (check-and-set 0) : jamais d'écrasement d'une entrée créée entre-temps.
 */
export function useMigration({
  vaultApi,
  selectedEngine,
  secretEngines,
  fetchSecretsRef,
  // showDeleted (encore transmis par App) n'est plus utilisé : fetchSecrets suit lui-même la case
  // « Afficher les supprimés » COURANTE, même si elle change pendant l'opération (SECRETS-19).
  clearSelection,
  syncExtensionRef,
  showToast,
  t
}) {
  const [migrateSecrets, setMigrateSecrets] = useState(null);   // { secrets: [], mode: 'copy'|'move' }
  const [moveToFolder, setMoveToFolder] = useState(null);        // { secrets: [] } - déplacement intra-engine

  // Coffre AFFICHÉ au moment où l'opération se termine (SECRETS-32) : l'utilisateur a pu en ouvrir un
  // autre pendant un glisser-déposer (aucune interface bloquante).
  const selectedEngineRef = useRef(selectedEngine);
  selectedEngineRef.current = selectedEngine;

  const { deleteSecretV2, deleteSecretV1,
          listKeysV2, listKeysV1, readSecretForMigration, writeSecretToEngine, totpKeyExists } = vaultApi;

  /**
   * Liste des noms d'entrées d'un coffre (léger, pour la détection des doublons).
   * Coffre vide (404 au listage) : aucun nom. Toute autre erreur — réseau ou délai après relances, 403,
   * 5xx, borne LIST_TOO_LARGE / LIST_TOO_DEEP (liste partielle) — est PROPAGÉE : renvoyer une liste vide
   * ou partielle ferait sauter la détection des doublons, et une entrée existante serait écrasée.
   * @throws {Error} listage impossible ou incomplet
   */
  const fetchSecretsForEngine = async (engine) => {
    let keys;
    try {
      keys = await withRetry(() => (engine.version === 2 ? listKeysV2(engine) : listKeysV1(engine)));
    } catch (err) {
      if (err?.response?.status === 404) return [];
      throw err;
    }
    return (Array.isArray(keys) ? keys : []).map(k => ({ name: k }));
  };

  // Noms déjà pris dans un coffre (entrées supprimées comprises : elles restent restaurables)
  const loadTakenNames = async (engine) => new Set((await fetchSecretsForEngine(engine)).map(s => s.name));

  // Vrai si déplacer `oldName` (coffre source) vers `newName` (coffre cible) ferait perdre son TOTP
  const totpBlocksMove = async (sourceEngine, oldName, targetEngine, newName) => {
    const oldKey = buildTotpKeyName(sourceEngine.name, oldName);
    if (oldKey === buildTotpKeyName(targetEngine.name, newName)) return false; // même clé : le TOTP suit
    return typeof totpKeyExists === 'function' ? totpKeyExists(oldKey) : false;
  };

  // Suppression douce de la source d'un déplacement (comme le bouton « Supprimer »)
  const softDelete = (engine, name) => (engine.version === 2 ? deleteSecretV2(engine, name) : deleteSecretV1(engine, name));

  /**
   * Copie BRUTE d'une entrée (SECRETS-34), puis, pour un déplacement, suppression de la source.
   * Les données lues sont réécrites telles quelles (aucun re-mappage par writeSecretV2, qui ne garde
   * que les champs du schéma RDVAULT), comme « Restaurer une version ».
   * Source KV v1 : sa suppression est DÉFINITIVE (pas d'historique) ; elle n'a lieu qu'après relecture
   * de la copie identique aux données écrites. Sinon la source est conservée (échec signalé).
   * @returns {Promise<boolean>} true si l'entrée a été copiée (et, en déplacement, la source supprimée)
   */
  const transferEntry = async (sourceEngine, name, targetEngine, targetName, move) => {
    const raw = await withTimeout(readSecretForMigration(sourceEngine, name), null);
    if (!raw || typeof raw !== 'object') return false;
    const payload = JSON.parse(JSON.stringify(raw)); // writeSecretToEngine assainit l'objet sur place
    // SECRETS-36 : création seule à destination (check-and-set 0, KV v2 ; ignoré en KV v1). Le nom visé
    // est libre d'après le listage (entrées supprimées en douceur comprises : elles restent listées, leur
    // nom n'est jamais choisi) ; une entrée créée entre-temps par un autre client n'est donc pas écrasée :
    // l'écriture est refusée et comptée en échec (source conservée).
    if (!await withTimeout(writeSecretToEngine(targetEngine, targetName, payload, { cas: 0 }), false)) return false;
    if (!move) return true;
    if (sourceEngine.version !== 2) {
      const copy = await withTimeout(readSecretForMigration(targetEngine, targetName), null);
      if (!copy || stableJson(copy) !== stableJson(payload)) {
        secureLogger.warn('[Migration] Copie non vérifiée : source KV v1 conservée');
        return false;
      }
    }
    try {
      await softDelete(sourceEngine, name);
      return true;
    } catch {
      return false;
    }
  };

  // Fin d'opération : rafraîchir le coffre AFFICHÉ (SECRETS-32), selon la case « Afficher les supprimés »
  const refreshShownEngine = async () => {
    const shown = selectedEngineRef.current;
    if (shown) await fetchSecretsRef.current?.(shown);
  };

  // Toast de fin d'opération (renommages et entrées refusées pour TOTP précisés entre parenthèses)
  const reportResult = (successKey, { done, failed, renamed, locked }) => {
    const details = [];
    if (renamed > 0) details.push(t('migrate.renamedDuplicates', { count: renamed }));
    if (locked > 0) details.push(t('error.totpLocksMove', { count: locked }));
    const suffix = details.length ? ` (${details.join(' ; ')})` : '';
    if (failed > 0) showToast(t('migrate.partialResult', { done, failed }) + suffix, 'warning');
    else showToast(t(successKey, { count: done }) + suffix, locked > 0 ? 'warning' : 'success');
  };

  /**
   * Fin d'opération commune aux quatre chemins. Listage de la destination impossible (`listError`) :
   * rien n'a été écrit, l'opération est signalée comme annulée (message traduit, cause assainie) ; ni
   * rafraîchissement ni désélection, l'utilisateur peut la relancer telle quelle.
   */
  const finishOperation = async (successKey, result, targetEngine, { syncExtension }) => {
    if (result.listError) {
      const reason = sanitizeErrorMessage(result.listError, undefined, t);
      showToast(t('migrate.destinationUnlisted', { engine: targetEngine?.name || '', reason }), 'error', 10000);
      return;
    }
    await refreshShownEngine();
    clearSelection();
    if (syncExtension) syncExtensionRef.current?.();
    reportResult(successKey, result);
  };

  /**
   * Boucle commune : pour chaque entrée, nom cible libre (`_n`), refus TOTP, copie brute.
   * @param {Object} sourceEngine
   * @param {Object} targetEngine
   * @param {string[]} names - Entrées de la source
   * @param {(name: string) => string|null} targetPathOf - Nom visé à destination (null = ignorer)
   * @param {boolean} move - Déplacement (source supprimée) ou copie
   */
  const transferAll = async (sourceEngine, targetEngine, names, targetPathOf, move) => {
    const result = { done: 0, failed: 0, renamed: 0, locked: 0 };
    // Noms pris relus au début de l'opération, DANS la file (une opération précédente a pu en ajouter).
    // Listage impossible : opération INTERROMPUE avant toute écriture (aucun doublon détectable).
    let takenNames;
    try {
      takenNames = await loadTakenNames(targetEngine);
    } catch (err) {
      secureLogger.warn('[Migration] Listage de la destination impossible : opération interrompue');
      return { ...result, listError: err };
    }
    for (const name of names) {
      try {
        const wanted = targetPathOf(name);
        if (wanted === null) continue; // déjà à cet endroit : ignoré silencieusement
        const target = uniqueName(wanted, takenNames);
        if (move && await totpBlocksMove(sourceEngine, name, targetEngine, target.name)) {
          result.locked++;
          continue;
        }
        if (await transferEntry(sourceEngine, name, targetEngine, target.name, move)) {
          takenNames.add(target.name);
          if (target.renamed) result.renamed++;
          result.done++;
        } else {
          result.failed++;
          // Une copie a pu être écrite (relecture non conforme) : son nom n'est plus libre
          takenNames.add(target.name);
        }
      } catch (err) {
        secureLogger.error(`[Migration] Erreur ${move ? 'move' : 'copy'}`);
        result.failed++;
      }
    }
    return result;
  };

  // Migration/Copie d'entrées (supporte un tableau de secrets)
  const handleMigrateSecrets = async (secretsList, targetEngine, mode) => {
    const secrets = Array.isArray(secretsList) ? secretsList : [secretsList];
    if (secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
    const sourceEngine = selectedEngine;
    await enqueueMigration(async () => {
      const result = await transferAll(sourceEngine, targetEngine, secrets.map(s => s.name), (name) => name, mode === 'move');
      await finishOperation('toast.migrationSuccess', result, targetEngine, { syncExtension: true });
    });
  };

  // Déplacement de secrets vers un autre dossier (intra-engine) - supporte un tableau
  const handleMoveToFolder = async (secretsList, targetFolderPath) => {
    const secrets = Array.isArray(secretsList) ? secretsList : [secretsList];
    if (secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
    const engine = selectedEngine;
    await enqueueMigration(async () => {
      const result = await transferAll(engine, engine, secrets.map(s => s.name), (name) => {
        const baseName = name.split('/').pop();
        const newName = targetFolderPath ? `${targetFolderPath}/${baseName}` : baseName;
        return newName === name ? null : newName;
      }, true);
      await finishOperation('toast.moveSuccess', result, engine, { syncExtension: true });
    });
  };

  /**
   * Migre des secrets vers un autre engine (used by drag & drop)
   * APP-7 : comme le chemin « Migrer vers… », l'extension est resynchronisée (coffre de destination
   * vérifié) ; seul le coffre affiché était relu, l'entrée déplacée disparaissait de l'extension.
   */
  const migrateSecretsToEngine = async (secretNames, sourceEngineName, sourceVersion, targetEngine) => {
    const sourceEngine = secretEngines.find(e => e.name === sourceEngineName);
    if (!sourceEngine) {
      showToast(t('error.engineNotFound'), 'error');
      return;
    }
    await enqueueMigration(async () => {
      const result = await transferAll(sourceEngine, targetEngine, secretNames, (name) => name, true);
      await finishOperation('toast.migrationSuccess', result, targetEngine, { syncExtension: true });
    });
  };

  /**
   * Déplace des secrets vers un dossier (intra-engine) (used by drag & drop)
   * APP-7 : extension resynchronisée comme pour « Déplacer vers… » (coffre affiché changé entre-temps).
   */
  const moveSecretsToFolder = async (secretNames, targetFolder) => {
    const engine = selectedEngine;
    await enqueueMigration(async () => {
      const result = await transferAll(engine, engine, secretNames, (name) => {
        const baseName = name.split('/').pop();
        const newPath = targetFolder ? `${targetFolder}/${baseName}` : baseName;
        return newPath === name ? null : newPath;
      }, true);
      await finishOperation('toast.moveSuccess', result, engine, { syncExtension: true });
    });
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
