import { useState, useRef, useEffect } from 'react';

/**
 * Hook de gestion de tous les menus contextuels de l'application.
 * @param {Object} options
 * @param {Function} options.getTotpKeyName - Fonction pour obtenir le nom de clé TOTP
 * @param {Function} options.checkTotpExists - Fonction pour vérifier si un TOTP existe
 * @param {Array} options.discoveredTags - Liste des tags découverts
 * @returns {Object} États et handlers des menus contextuels
 */
export function useContextMenus({ getTotpKeyName, checkTotpExists, discoveredTags }) {
  const [contextMenu, setContextMenu] = useState(null);
  const [columnContextMenu, setColumnContextMenu] = useState(null);
  const [tagContextMenu, setTagContextMenu] = useState(null);
  const [engineContextMenu, setEngineContextMenu] = useState(null);
  const [folderContextMenu, setFolderContextMenu] = useState(null);
  const [tagCreateMode, setTagCreateMode] = useState(false);
  const [tagCreateValue, setTagCreateValue] = useState('#');

  const contextMenuRef = useRef(null);
  const tagContextMenuRef = useRef(null);

  const handleCellRightClick = async (e, secret, field, value) => {
    e.preventDefault();

    const totpKeyName = getTotpKeyName(secret.name);
    const totpExists = await checkTotpExists(totpKeyName);

    setTagContextMenu(null);
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      secret,
      field,
      value,
      totpExists
    });
  };

  const handleEmptyAreaRightClick = (e) => {
    // Vérifier si le clic est sur une cellule de tableau (ou à l'intérieur)
    const isOnCell = e.target.closest('td');

    // Si le clic est sur une cellule, ne rien faire (le gestionnaire de cellule s'en occupera)
    if (isOnCell) {
      return;
    }

    // Ne pas ouvrir le menu si c'est sur un bouton, input, ou autre élément interactif
    const isInteractive = e.target.closest('button, input, a, select, textarea');
    if (isInteractive) {
      return;
    }

    e.preventDefault();
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      type: 'create' // Nouveau type pour distinguer du menu contextuel normal
    });
  };

  const handleFolderRightClick = (e, folderPath) => {
    e.preventDefault();
    e.stopPropagation();
    setFolderContextMenu({
      x: e.clientX,
      y: e.clientY,
      folderPath
    });
  };

  const handleColumnHeaderRightClick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setColumnContextMenu({
      x: e.clientX,
      y: e.clientY
    });
  };

  const handleTagCellRightClick = (e, secret) => {
    e.preventDefault();
    e.stopPropagation();

    // Récupérer les tags actuels de l'entrée
    const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];

    // Filtrer pour ne garder que les tags non attribués
    // discoveredTags contient tous les tags détectés dans les coffres accessibles
    const availableTags = discoveredTags.filter(tag => !currentTags.includes(tag));

    setContextMenu(null);
    setTagContextMenu({
      x: e.clientX,
      y: e.clientY,
      secret,
      availableTags,
      currentTags
    });
  };

  const handleEngineRightClick = (e, engine) => {
    e.preventDefault();
    e.stopPropagation();

    // Vérifier si c'est un coffre personnel (peut être supprimé)
    const currentUser = localStorage.getItem('vault-client.username') || '';
    const userPrefix = currentUser ? `users/${currentUser}/` : '';
    const canDelete = userPrefix && (engine.name.startsWith(userPrefix) || engine.name.startsWith(`users/${currentUser}`));

    if (!canDelete) {
      // Ne rien afficher pour les coffres partagés
      return;
    }

    setEngineContextMenu({
      x: e.clientX,
      y: e.clientY,
      engine
    });
  };

  // Fermer tous les menus au clic/scroll extérieur
  useEffect(() => {
    const closeMenu = () => {
      setContextMenu(null);
      setColumnContextMenu(null);
      setTagContextMenu(null);
      setTagCreateMode(false);
      setTagCreateValue('#');
      setEngineContextMenu(null);
      setFolderContextMenu(null);
    };
    document.addEventListener('click', closeMenu);
    return () => document.removeEventListener('click', closeMenu);
  }, []);

  // Ajuster la position du menu contextuel pour qu'il reste dans la fenêtre
  useEffect(() => {
    if (contextMenu && contextMenuRef.current) {
      const menu = contextMenuRef.current;
      const menuRect = menu.getBoundingClientRect();
      const windowWidth = window.innerWidth;
      const windowHeight = window.innerHeight;

      let newX = contextMenu.x;
      let newY = contextMenu.y;

      // Si le menu dépasse à droite, le repositionner à gauche du curseur
      if (menuRect.right > windowWidth) {
        newX = contextMenu.x - menuRect.width;
      }

      // Si le menu dépasse en bas, le repositionner au-dessus du curseur
      if (menuRect.bottom > windowHeight) {
        newY = contextMenu.y - menuRect.height;
      }

      // S'assurer que le menu ne dépasse pas à gauche ou en haut
      if (newX < 0) newX = 10;
      if (newY < 0) newY = 10;

      // Appliquer les nouvelles positions si différentes
      if (newX !== contextMenu.x || newY !== contextMenu.y) {
        menu.style.left = `${newX}px`;
        menu.style.top = `${newY}px`;
      }
    }
  }, [contextMenu]);

  // Ajuster la position du menu contextuel des tags pour qu'il reste dans la fenêtre
  useEffect(() => {
    if (tagContextMenu && tagContextMenuRef.current) {
      const menu = tagContextMenuRef.current;
      const menuRect = menu.getBoundingClientRect();
      const windowWidth = window.innerWidth;
      const windowHeight = window.innerHeight;

      let newX = tagContextMenu.x;
      let newY = tagContextMenu.y;

      // Si le menu dépasse à droite, le repositionner à gauche du curseur
      if (menuRect.right > windowWidth) {
        newX = tagContextMenu.x - menuRect.width;
      }

      // Si le menu dépasse en bas, le repositionner au-dessus du curseur
      if (menuRect.bottom > windowHeight) {
        newY = tagContextMenu.y - menuRect.height;
      }

      // S'assurer que le menu ne dépasse pas à gauche ou en haut
      if (newX < 0) newX = 10;
      if (newY < 0) newY = 10;

      // Appliquer les nouvelles positions si différentes
      if (newX !== tagContextMenu.x || newY !== tagContextMenu.y) {
        menu.style.left = `${newX}px`;
        menu.style.top = `${newY}px`;
      }
    }
  }, [tagContextMenu]);

  return {
    contextMenu, setContextMenu,
    columnContextMenu, setColumnContextMenu,
    tagContextMenu, setTagContextMenu,
    engineContextMenu, setEngineContextMenu,
    folderContextMenu, setFolderContextMenu,
    tagCreateMode, setTagCreateMode,
    tagCreateValue, setTagCreateValue,
    contextMenuRef,
    tagContextMenuRef,
    handleCellRightClick,
    handleEmptyAreaRightClick,
    handleFolderRightClick,
    handleColumnHeaderRightClick,
    handleTagCellRightClick,
    handleEngineRightClick
  };
}
