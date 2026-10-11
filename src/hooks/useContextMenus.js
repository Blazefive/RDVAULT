import { useState, useRef, useEffect, useCallback } from 'react';
import { getFocusableElements } from '../components/common/Modal';

// Menu contextuel actuellement affiché (un seul à la fois, voir closeAllMenus)
const getOpenMenuElement = () => (typeof document !== 'undefined' ? document.querySelector('.context-menu') : null);

/**
 * Hook de gestion de tous les menus contextuels de l'application.
 *
 * Accessibilité clavier (WAI-ARIA APG « Menu ») :
 * - un seul menu ouvert à la fois (chaque ouverture ferme les autres) ;
 * - à l'ouverture, le focus va sur le premier élément du menu ; flèches haut/bas, Début/Fin ;
 * - Échap (ou Tab) ferme le menu et rend le focus à l'élément qui l'avait (ligne, carte de coffre…).
 *
 * Réponses tardives (APP-3) : le menu d'une ligne n'est ouvert qu'après la vérification TOTP (requête).
 * Une numérotation COMMUNE à tous les menus garantit que cette réponse n'ouvre le menu que si rien ne
 * s'est passé entre-temps : toute ouverture (autre ligne, zone vide, dossier, en-tête, tag, coffre),
 * toute fermeture (clic extérieur, Échap, Tab) et tout changement posé par l'appelant via les setters
 * exposés (fermeture après une action, remise à zéro à la déconnexion) rendent la réponse caduque.
 *
 * @param {Object} options
 * @param {Function} options.getTotpKeyName - Fonction pour obtenir le nom de clé TOTP
 * @param {Function} options.checkTotpExists - Fonction pour vérifier si un TOTP existe
 * @param {Array} options.discoveredTags - Liste des tags découverts
 * @param {{ current: string }} [options.sessionTokenRef] - Jeton de la session en cours (useAuth),
 *   facultatif : une réponse arrivée après un changement de session n'ouvre aucun menu
 * @returns {Object} États et handlers des menus contextuels
 */
export function useContextMenus({ getTotpKeyName, checkTotpExists, discoveredTags, sessionTokenRef }) {
  const [contextMenu, setContextMenuState] = useState(null);
  const [columnContextMenu, setColumnContextMenuState] = useState(null);
  const [tagContextMenu, setTagContextMenuState] = useState(null);
  const [engineContextMenu, setEngineContextMenuState] = useState(null);
  const [folderContextMenu, setFolderContextMenuState] = useState(null);
  const [tagCreateMode, setTagCreateMode] = useState(false);
  const [tagCreateValue, setTagCreateValue] = useState('#');

  const contextMenuRef = useRef(null);
  const tagContextMenuRef = useRef(null);
  // Élément focalisé à l'ouverture du menu (focus rendu à la fermeture)
  const openerRef = useRef(null);

  // Numéro de la dernière ouverture / fermeture d'un menu, tous menus confondus (voir en-tête)
  const menuSeqRef = useRef(0);
  // Setters exposés : stables (useCallback) et numérotés comme les ouvertures internes
  const setContextMenu = useCallback((value) => { menuSeqRef.current += 1; setContextMenuState(value); }, []);
  const setColumnContextMenu = useCallback((value) => { menuSeqRef.current += 1; setColumnContextMenuState(value); }, []);
  const setTagContextMenu = useCallback((value) => { menuSeqRef.current += 1; setTagContextMenuState(value); }, []);
  const setEngineContextMenu = useCallback((value) => { menuSeqRef.current += 1; setEngineContextMenuState(value); }, []);
  const setFolderContextMenu = useCallback((value) => { menuSeqRef.current += 1; setFolderContextMenuState(value); }, []);

  const rememberOpener = () => {
    const el = typeof document !== 'undefined' ? document.activeElement : null;
    if (!el || el === document.body) { openerRef.current = null; return; }
    // Clic droit pendant qu'un menu a le focus : on garde l'élément d'origine
    if (el.closest && el.closest('.context-menu')) return;
    openerRef.current = el;
  };

  const focusOpener = () => {
    const opener = openerRef.current;
    if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
  };

  // BUG CORRIGÉ : les menus n'étaient pas exclusifs (clic droit sur un coffre puis sur une
  // cellule = deux menus superposés). Toute ouverture ferme d'abord tous les menus.
  // Numérotée : une réponse tardive d'un clic droit sur une ligne n'ouvre plus son menu.
  const closeAllMenus = () => {
    menuSeqRef.current += 1;
    setContextMenuState(null);
    setColumnContextMenuState(null);
    setTagContextMenuState(null);
    setTagCreateMode(false);
    setTagCreateValue('#');
    setEngineContextMenuState(null);
    setFolderContextMenuState(null);
  };

  const handleCellRightClick = async (e, secret, field, value) => {
    e.preventDefault();
    rememberOpener();
    closeAllMenus();
    // Ouverture en attente : numéro et session relevés AVANT la requête
    const seq = menuSeqRef.current;
    const session = sessionTokenRef ? sessionTokenRef.current : undefined;
    const x = e.clientX;
    const y = e.clientY;
    const opener = openerRef.current;

    const totpKeyName = getTotpKeyName(secret.name);
    let totpExists = false;
    try {
      totpExists = await checkTotpExists(totpKeyName);
    } catch {
      totpExists = false; // vérification impossible : menu ouvert sans les actions TOTP réservées
    }
    // Un autre menu a été ouvert ou fermé entre-temps, ou la session a changé : réponse ignorée
    if (seq !== menuSeqRef.current) return;
    if (sessionTokenRef && sessionTokenRef.current !== session) return;

    setContextMenuState({
      x,
      y,
      secret,
      field,
      value,
      totpExists,
      opener
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
    rememberOpener();
    closeAllMenus();
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      type: 'create', // Nouveau type pour distinguer du menu contextuel normal
      opener: openerRef.current
    });
  };

  const handleFolderRightClick = (e, folderPath) => {
    e.preventDefault();
    e.stopPropagation();
    rememberOpener();
    closeAllMenus();
    setFolderContextMenu({
      x: e.clientX,
      y: e.clientY,
      folderPath
    });
  };

  const handleColumnHeaderRightClick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    rememberOpener();
    closeAllMenus();
    setColumnContextMenu({
      x: e.clientX,
      y: e.clientY
    });
  };

  const handleTagCellRightClick = (e, secret) => {
    e.preventDefault();
    e.stopPropagation();
    rememberOpener();
    closeAllMenus();

    // Récupérer les tags actuels de l'entrée
    const currentTags = secret.tags ? secret.tags.split(/[\s,;]+/).filter(t => t) : [];

    // Filtrer pour ne garder que les tags non attribués
    // discoveredTags contient tous les tags détectés dans les coffres accessibles
    const availableTags = discoveredTags.filter(tag => !currentTags.includes(tag));

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
    rememberOpener();
    closeAllMenus();

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

  // Fermer tous les menus au clic/scroll extérieur (numérotée comme closeAllMenus : un clic ailleurs
  // pendant la vérification TOTP d'un clic droit annule aussi l'ouverture de ce menu)
  useEffect(() => {
    const closeMenu = () => {
      menuSeqRef.current += 1;
      setContextMenuState(null);
      setColumnContextMenuState(null);
      setTagContextMenuState(null);
      setTagCreateMode(false);
      setTagCreateValue('#');
      setEngineContextMenuState(null);
      setFolderContextMenuState(null);
    };
    document.addEventListener('click', closeMenu);
    return () => document.removeEventListener('click', closeMenu);
  }, []);

  const openMenu = contextMenu || columnContextMenu || tagContextMenu || engineContextMenu || folderContextMenu;
  const anyMenuOpen = !!openMenu;

  // Focus : dans le menu à son ouverture ; rendu à l'élément d'origine s'il est perdu à la fermeture
  // (une modale ouverte depuis le menu a déjà pris le focus : on ne le lui vole pas).
  const prevOpenMenuRef = useRef(null);
  useEffect(() => {
    const prev = prevOpenMenuRef.current;
    prevOpenMenuRef.current = openMenu;
    if (openMenu && openMenu !== prev) {
      const menu = getOpenMenuElement();
      if (menu && !menu.contains(document.activeElement)) {
        const [first] = getFocusableElements(menu);
        if (first) {
          try { first.focus({ preventScroll: true }); } catch { first.focus(); }
        }
      }
    } else if (!openMenu && prev) {
      const current = document.activeElement;
      if (!current || current === document.body || !current.isConnected) focusOpener();
    }
  }, [openMenu]);

  // Clavier pendant qu'un menu est ouvert : Échap / Tab ferment, flèches naviguent
  useEffect(() => {
    if (!anyMenuOpen) return undefined;
    const onKeyDown = (e) => {
      const menu = getOpenMenuElement();
      const focusInMenu = !!(menu && menu.contains(document.activeElement));
      const isTextField = !!(e.target && e.target.matches && e.target.matches('input:not([type="checkbox"]):not([type="radio"]), textarea'));
      // Champ de saisie du menu (création de tag) : il gère lui-même Échap (sortie du mode création)
      if (e.key === 'Escape' && focusInMenu && isTextField) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        closeAllMenus();
        if (focusInMenu || document.activeElement === document.body) focusOpener();
        return;
      }
      if (e.key === 'Tab') {
        closeAllMenus();
        if (focusInMenu) {
          e.preventDefault();
          focusOpener();
        }
        return;
      }
      if (!focusInMenu) return;
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key) || (isTextField && (e.key === 'Home' || e.key === 'End'))) return;
      const items = getFocusableElements(menu);
      if (!items.length) return;
      e.preventDefault();
      const index = items.indexOf(document.activeElement);
      let next;
      if (e.key === 'Home') next = items[0];
      else if (e.key === 'End') next = items[items.length - 1];
      else {
        const delta = e.key === 'ArrowDown' ? 1 : -1;
        next = items[index < 0 ? 0 : (index + delta + items.length) % items.length];
      }
      next.focus();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
    // closeAllMenus / focusOpener ne lisent que des setters et des refs stables
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anyMenuOpen]);

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
