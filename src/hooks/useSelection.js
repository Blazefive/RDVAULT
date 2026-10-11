import { useState, useRef } from 'react';

// ========================================
// CLÉ D'UNE LIGNE DU TABLEAU (sélection, mots de passe révélés)
// ========================================
// Recherche multi-coffres : le tableau mêle les entrées de plusieurs coffres, et deux coffres peuvent
// contenir une entrée du même nom. Indexées par nom seul, deux homonymes s'allumaient (sélection) ou
// se révélaient (mot de passe) ensemble. La clé d'une entrée d'un AUTRE coffre que le coffre
// sélectionné est donc « coffre + séparateur + nom ».
// Une entrée du coffre sélectionné garde son nom pour clé (en recherche multi-coffres comme en vue
// normale) : les opérations par lot (menu contextuel, glisser-déposer, useDragDrop) travaillent sur
// les noms du coffre sélectionné et restent inchangées.
// Séparateur : caractère NUL, refusé dans les noms d'entrée (validation.js : caractères de contrôle
// interdits) : une clé composée ne peut jamais coïncider avec le nom d'une entrée.
export const ENTRY_KEY_SEPARATOR = '\u0000';

/**
 * Clé de sélection / de visibilité d'une ligne du tableau.
 * @param {Object} secret - Ligne affichée (name, engineName éventuel en recherche multi-coffres)
 * @param {string|null|undefined} selectedEngineName - Nom du coffre sélectionné
 * @returns {string}
 */
export function entryKey(secret, selectedEngineName) {
  const name = secret && typeof secret.name === 'string' ? secret.name : '';
  const engine = secret && typeof secret.engineName === 'string' ? secret.engineName : '';
  if (engine && engine !== selectedEngineName) return `${engine}${ENTRY_KEY_SEPARATOR}${name}`;
  return name;
}

/**
 * Coffre d'une clé composée (entrée d'un autre coffre), ou null pour une entrée du coffre sélectionné.
 * @param {string} key
 * @returns {string|null}
 */
export function entryKeyEngine(key) {
  if (typeof key !== 'string') return null;
  const index = key.indexOf(ENTRY_KEY_SEPARATOR);
  return index === -1 ? null : key.slice(0, index);
}

/**
 * Hook useSelection — gère la multi-sélection de secrets (Ctrl+Clic, Shift+Clic)
 * @param {Object} [options]
 * @param {{ current: string|null }} [options.selectedEngineNameRef] - Nom du coffre sélectionné (lu au
 *   moment du clic) : clés des lignes pour la sélection par plage (Maj+Clic). Absent : aucune ligne
 *   n'est considérée comme appartenant au coffre sélectionné (toute ligne avec engineName est composée).
 * @returns {{ selectedSecrets, lastClickedSecretRef, displayedSecretsRef, toggleSecretSelection, selectAllSecrets, clearSelection, isSecretSelected }}
 */
export function useSelection({ selectedEngineNameRef } = {}) {
  const [selectedSecrets, setSelectedSecrets] = useState(new Set());
  const lastClickedSecretRef = useRef(null);
  const displayedSecretsRef = useRef([]);

  // Clé d'une ligne affichée (même règle que le tableau : entryKey)
  const keyOf = (secret) => entryKey(secret, selectedEngineNameRef ? selectedEngineNameRef.current : undefined);

  /**
   * Toggle la sélection d'un secret (Ctrl+Clic, Shift+Clic)
   * @param {string} secretKey - Clé de la ligne (entryKey : nom de l'entrée, ou coffre + nom pour un
   *   résultat d'un autre coffre en recherche multi-coffres)
   * @param {boolean} ctrlKey - Si Ctrl est pressé (ajoute à la sélection)
   * @param {boolean} shiftKey - Si Shift est pressé (sélection par plage)
   */
  const toggleSecretSelection = (secretKey, ctrlKey = false, shiftKey = false) => {
    setSelectedSecrets(prev => {
      const newSet = new Set(prev);
      if (shiftKey && lastClickedSecretRef.current) {
        // Shift+Clic : sélectionner toute la plage entre le dernier clic et celui-ci
        const list = displayedSecretsRef.current || [];
        const startIdx = list.findIndex(s => keyOf(s) === lastClickedSecretRef.current);
        const endIdx = list.findIndex(s => keyOf(s) === secretKey);
        if (startIdx !== -1 && endIdx !== -1) {
          const from = Math.min(startIdx, endIdx);
          const to = Math.max(startIdx, endIdx);
          for (let i = from; i <= to; i++) {
            if (!list[i].isFolder && !list[i].deleted) {
              newSet.add(keyOf(list[i]));
            }
          }
        }
      } else if (ctrlKey) {
        // Ctrl+Clic : toggle la sélection
        if (newSet.has(secretKey)) {
          newSet.delete(secretKey);
        } else {
          newSet.add(secretKey);
        }
      } else {
        // Clic simple : sélection unique
        if (newSet.size === 1 && newSet.has(secretKey)) {
          newSet.clear();
        } else {
          newSet.clear();
          newSet.add(secretKey);
        }
      }
      lastClickedSecretRef.current = secretKey;
      return newSet;
    });
  };

  /**
   * Sélectionne tous les secrets visibles
   * @param {Array} secretsList - Liste des secrets à sélectionner
   */
  const selectAllSecrets = (secretsList) => {
    const keys = secretsList
      .filter(s => !s.isFolder && !s.deleted)
      .map(keyOf);
    setSelectedSecrets(new Set(keys));
  };

  /**
   * Efface la sélection
   */
  const clearSelection = () => {
    setSelectedSecrets(new Set());
  };

  /**
   * Vérifie si un secret est sélectionné
   * @param {string} secretKey - Clé de la ligne (entryKey)
   * @returns {boolean}
   */
  const isSecretSelected = (secretKey) => {
    return selectedSecrets.has(secretKey);
  };

  return {
    selectedSecrets,
    setSelectedSecrets,
    lastClickedSecretRef,
    displayedSecretsRef,
    toggleSecretSelection,
    selectAllSecrets,
    clearSelection,
    isSecretSelected
  };
}
