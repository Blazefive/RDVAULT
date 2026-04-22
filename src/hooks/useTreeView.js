import { useState, useMemo } from 'react';

/**
 * Construit l'arborescence à partir de la liste plate de secrets
 * @param {Array} secretsList - Liste plate des secrets
 * @returns {Object} - Arbre { folders: {}, secrets: [] }
 */
export function buildTree(secretsList) {
  const tree = { folders: {}, secrets: [] };

  secretsList.forEach(secret => {
    const parts = secret.name.split('/');

    if (parts.length === 1) {
      // Secret à la racine (masquer les .placeholder à la racine)
      if (secret.name !== '.placeholder') {
        tree.secrets.push(secret);
      }
    } else {
      // Secret dans un dossier
      let current = tree;
      for (let i = 0; i < parts.length - 1; i++) {
        const folderName = parts[i];
        if (!current.folders[folderName]) {
          current.folders[folderName] = { folders: {}, secrets: [] };
        }
        current = current.folders[folderName];
      }
      // Masquer les .placeholder de l'affichage
      const leafName = parts[parts.length - 1];
      if (leafName !== '.placeholder') {
        current.secrets.push({
          ...secret,
          displayName: leafName
        });
      }
    }
  });

  return tree;
}

/**
 * Hook useTreeView — gère la vue arborescence des secrets
 * @param {Array} secrets - Liste des secrets
 * @returns {{ treeViewEnabled, setTreeViewEnabled, currentPath, setCurrentPath, buildTree, currentFolderContent }}
 */
export function useTreeView(secrets) {
  const [treeViewEnabled, setTreeViewEnabled] = useState(() => {
    return localStorage.getItem('rdvault-tree-view-enabled') === 'true';
  });
  const [currentPath, setCurrentPath] = useState('');

  // Calculer le contenu du dossier actuel (racine ou sous-dossier)
  const currentFolderContent = useMemo(() => {
    if (!treeViewEnabled) {
      // En vue liste, masquer les .placeholder
      return secrets.filter(s => !s.name.endsWith('/.placeholder') && s.name !== '.placeholder');
    }

    if (secrets.length === 0) {
      return [];
    }

    const tree = buildTree(secrets);

    // Si on est à la racine
    if (!currentPath) {
      const folders = Object.keys(tree.folders).map(name => ({
        name,
        displayName: name,
        isFolder: true
      }));
      return [...folders, ...tree.secrets];
    }

    // Naviguer dans le chemin
    const pathParts = currentPath.split('/');
    let current = tree;

    for (const part of pathParts) {
      if (current.folders[part]) {
        current = current.folders[part];
      } else {
        // Chemin invalide, retourner à la racine
        setCurrentPath('');
        const folders = Object.keys(tree.folders).map(name => ({
          name,
          displayName: name,
          isFolder: true
        }));
        return [...folders, ...tree.secrets];
      }
    }

    const folders = Object.keys(current.folders).map(name => ({
      name: currentPath ? `${currentPath}/${name}` : name,
      displayName: name,
      isFolder: true
    }));

    return [...folders, ...current.secrets];
  }, [secrets, treeViewEnabled, currentPath]);

  return {
    treeViewEnabled,
    setTreeViewEnabled,
    currentPath,
    setCurrentPath,
    currentFolderContent
  };
}
