import { useState, useRef } from 'react';

/**
 * Hook useSelection — gère la multi-sélection de secrets (Ctrl+Clic, Shift+Clic)
 * @returns {{ selectedSecrets, lastClickedSecretRef, displayedSecretsRef, toggleSecretSelection, selectAllSecrets, clearSelection, isSecretSelected }}
 */
export function useSelection() {
  const [selectedSecrets, setSelectedSecrets] = useState(new Set());
  const lastClickedSecretRef = useRef(null);
  const displayedSecretsRef = useRef([]);

  /**
   * Toggle la sélection d'un secret (Ctrl+Clic, Shift+Clic)
   * @param {string} secretName - Nom du secret à sélectionner/désélectionner
   * @param {boolean} ctrlKey - Si Ctrl est pressé (ajoute à la sélection)
   * @param {boolean} shiftKey - Si Shift est pressé (sélection par plage)
   */
  const toggleSecretSelection = (secretName, ctrlKey = false, shiftKey = false) => {
    setSelectedSecrets(prev => {
      const newSet = new Set(prev);
      if (shiftKey && lastClickedSecretRef.current) {
        // Shift+Clic : sélectionner toute la plage entre le dernier clic et celui-ci
        const list = displayedSecretsRef.current;
        const startIdx = list.findIndex(s => s.name === lastClickedSecretRef.current);
        const endIdx = list.findIndex(s => s.name === secretName);
        if (startIdx !== -1 && endIdx !== -1) {
          const from = Math.min(startIdx, endIdx);
          const to = Math.max(startIdx, endIdx);
          for (let i = from; i <= to; i++) {
            if (!list[i].isFolder && !list[i].deleted) {
              newSet.add(list[i].name);
            }
          }
        }
      } else if (ctrlKey) {
        // Ctrl+Clic : toggle la sélection
        if (newSet.has(secretName)) {
          newSet.delete(secretName);
        } else {
          newSet.add(secretName);
        }
      } else {
        // Clic simple : sélection unique
        if (newSet.size === 1 && newSet.has(secretName)) {
          newSet.clear();
        } else {
          newSet.clear();
          newSet.add(secretName);
        }
      }
      lastClickedSecretRef.current = secretName;
      return newSet;
    });
  };

  /**
   * Sélectionne tous les secrets visibles
   * @param {Array} secretsList - Liste des secrets à sélectionner
   */
  const selectAllSecrets = (secretsList) => {
    const names = secretsList
      .filter(s => !s.isFolder && !s.deleted)
      .map(s => s.name);
    setSelectedSecrets(new Set(names));
  };

  /**
   * Efface la sélection
   */
  const clearSelection = () => {
    setSelectedSecrets(new Set());
  };

  /**
   * Vérifie si un secret est sélectionné
   * @param {string} secretName - Nom du secret
   * @returns {boolean}
   */
  const isSecretSelected = (secretName) => {
    return selectedSecrets.has(secretName);
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
