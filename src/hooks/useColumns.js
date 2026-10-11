import { useState, useRef, useCallback, useEffect } from 'react';

const MIN_COLUMN_WIDTH = 80;  // Minimum 80px pour lisibilité
const MAX_COLUMN_WIDTH = 600; // Maximum 600px pour éviter d'écraser les autres colonnes

// Une image d'animation au plus par recalcul (repli setTimeout hors navigateur)
const scheduleFrame = (cb) => (typeof requestAnimationFrame === 'function'
  ? requestAnimationFrame(cb)
  : setTimeout(cb, 16));
const cancelFrame = (id) => {
  if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(id);
  else clearTimeout(id);
};

// Enregistrement des largeurs (stockage indisponible : la largeur reste appliquée pour la session)
const persistWidths = (widths) => {
  try { localStorage.setItem('rdvault-column-widths', JSON.stringify(widths)); } catch { /* ignoré */ }
};

/**
 * Sens du geste de redimensionnement (I18N-31 : écriture de droite à gauche).
 * La colonne s'agrandit vers la FIN de ligne : à droite en LTR, à gauche en RTL. Tirer la poignée
 * vers la fin de ligne doit élargir la colonne : delta = clientX - départ en LTR, inversé en RTL.
 * La poignée réellement affichée fait foi : si elle est sur la moitié gauche de l'en-tête (feuille
 * de style en miroir), le geste est inversé ; sur la moitié droite, il ne l'est pas (une poignée
 * restée au bord droit en RTL ne doit pas inverser le geste). Sans géométrie (rendu hors mise en
 * page), le sens du document décide.
 * @param {Element|null} handle - Poignée saisie
 * @returns {1|-1}
 */
export function resizeDirection(handle) {
  const header = handle && typeof handle.closest === 'function' ? handle.closest('th') : null;
  if (header && typeof handle.getBoundingClientRect === 'function') {
    const h = handle.getBoundingClientRect();
    const c = header.getBoundingClientRect();
    if (c && h && c.width > 0) {
      return (h.left + h.right) / 2 < (c.left + c.right) / 2 ? -1 : 1;
    }
  }
  const scoped = handle && typeof handle.closest === 'function' ? handle.closest('[dir]') : null;
  const dir = String((scoped && scoped.getAttribute('dir')) || (typeof document !== 'undefined' && document.documentElement.dir) || '').toLowerCase();
  return dir === 'rtl' ? -1 : 1;
}

// Largeur affichée de l'en-tête de la poignée (colonne encore en largeur automatique), 0 si inconnue
function headerWidth(handle) {
  const header = handle && typeof handle.closest === 'function' ? handle.closest('th') : null;
  const width = header && typeof header.getBoundingClientRect === 'function' ? header.getBoundingClientRect().width : 0;
  return Number.isFinite(width) && width > 0 ? Math.round(width) : 0;
}

/**
 * Hook useColumns — gère la visibilité et le redimensionnement des colonnes du tableau
 * @param {Function} showToast - Fonction d'affichage des toasts (conservée pour compatibilité)
 * @param {Function} t - Fonction de traduction i18n (conservée pour compatibilité)
 * @returns {Object}
 */
export function useColumns(showToast, t) {
  const [visibleColumns, setVisibleColumns] = useState(() => {
    // Charger les colonnes visibles depuis localStorage avec validation stricte
    const defaults = { name: true, username: true, password: true, url: true, website: true, notes: true, tags: true, customFields: false, actions: true };
    const allowedKeys = Object.keys(defaults);
    try {
      const saved = localStorage.getItem('rdvault-visible-columns');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          const clean = {};
          for (const k of allowedKeys) clean[k] = k in parsed ? parsed[k] !== false : defaults[k];
          return clean;
        }
      }
      return defaults;
    } catch { return defaults; }
  });

  const [columnWidths, setColumnWidths] = useState(() => {
    // Charger les largeurs de colonnes depuis localStorage avec validation stricte
    const allowedKeys = ['name', 'username', 'password', 'url', 'website', 'notes', 'tags', 'customFields', 'engine'];
    try {
      const saved = localStorage.getItem('rdvault-column-widths');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          const clean = {};
          for (const k of allowedKeys) {
            if (typeof parsed[k] === 'number' && parsed[k] > 0 && parsed[k] < 2000) clean[k] = parsed[k];
          }
          return clean;
        }
      }
      return {};
    } catch { return {}; }
  });

  const [resizingColumn, setResizingColumn] = useState(null);
  // Geste en cours (refs : lues par les gestionnaires document sans dépendre d'un rendu)
  const activeColumn = useRef(null);
  const resizeStartX = useRef(0);
  const resizeStartWidth = useRef(0);
  // Sens du geste : +1 si tirer vers la droite élargit la colonne, -1 si c'est vers la gauche (RTL)
  const resizeSign = useRef(1);
  // PERFORMANCE : un seul recalcul de largeur par image (requestAnimationFrame). Les mousemove
  // arrivent bien plus souvent que les images ; chacun provoquait un setState, donc une mise en
  // page du tableau (~250 ms à 5 000 lignes), et une écriture localStorage.
  const pendingClientX = useRef(null);
  const frameRef = useRef(null);
  // Largeurs courantes, tenues à jour entre deux rendus (enregistrées une fois en fin de geste)
  const widthsRef = useRef(columnWidths);
  widthsRef.current = columnWidths;

  const toggleColumn = (columnKey) => {
    const newVisibleColumns = {
      ...visibleColumns,
      [columnKey]: !visibleColumns[columnKey]
    };
    setVisibleColumns(newVisibleColumns);
    localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
  };

  // Applique la dernière position de souris reçue (au plus une fois par image)
  const applyPendingResize = useCallback(() => {
    frameRef.current = null;
    const clientX = pendingClientX.current;
    pendingClientX.current = null;
    const column = activeColumn.current;
    if (clientX === null || !column) return;
    // RTL : la colonne s'étend vers la gauche, le delta est inversé (resizeDirection)
    const diff = (clientX - resizeStartX.current) * resizeSign.current;
    const newWidth = Math.max(MIN_COLUMN_WIDTH, Math.min(MAX_COLUMN_WIDTH, resizeStartWidth.current + diff));
    if (widthsRef.current[column] === newWidth) return;
    const newWidths = { ...widthsRef.current, [column]: newWidth };
    widthsRef.current = newWidths;
    setColumnWidths(newWidths);
  }, []);

  // Redimensionnement des colonnes
  const handleColumnResizeStart = (e, columnKey, currentWidth) => {
    e.preventDefault();
    e.stopPropagation();
    if (frameRef.current !== null) { cancelFrame(frameRef.current); frameRef.current = null; }
    pendingClientX.current = null;
    const handle = e.currentTarget || e.target;
    activeColumn.current = columnKey;
    resizeStartX.current = e.clientX;
    // Colonne encore en largeur automatique : départ de sa largeur AFFICHÉE (avant : 150 px fixes,
    // la colonne sautait à 150 + déplacement au premier mouvement) ; 150 px si elle est inconnue
    resizeStartWidth.current = currentWidth || headerWidth(handle) || 150;
    resizeSign.current = resizeDirection(handle);
    setResizingColumn(columnKey);
  };

  const handleColumnResizeMove = useCallback((e) => {
    if (!activeColumn.current) return;
    pendingClientX.current = e.clientX;
    if (frameRef.current === null) frameRef.current = scheduleFrame(applyPendingResize);
  }, [applyPendingResize]);

  const handleColumnResizeEnd = useCallback(() => {
    if (!activeColumn.current) return;
    // Dernière position pas encore appliquée : appliquée maintenant (largeur finale = celle du
    // relâchement), puis un seul enregistrement de la largeur choisie
    if (frameRef.current !== null) {
      cancelFrame(frameRef.current);
      applyPendingResize();
    }
    activeColumn.current = null;
    persistWidths(widthsRef.current);
    setResizingColumn(null);
  }, [applyPendingResize]);

  // Démontage pendant un geste : image en attente annulée
  useEffect(() => {
    const frame = frameRef;
    return () => {
      if (frame.current !== null) cancelFrame(frame.current);
      frame.current = null;
    };
  }, []);

  /**
   * Auto-ajustement de la colonne (fit to content)
   * @param {MouseEvent} e
   * @param {string} columnKey
   * @param {Object} dataContext - { dataSource, treeViewEnabled, selectedEngine }
   */
  const handleColumnAutoFit = (e, columnKey, dataContext = {}) => {
    e.preventDefault();
    e.stopPropagation();

    const { dataSource = [], treeViewEnabled: treeView = false, selectedEngine = null } = dataContext;

    // Créer un élément temporaire pour mesurer le texte
    const measureElement = document.createElement('span');
    measureElement.style.visibility = 'hidden';
    measureElement.style.position = 'absolute';
    measureElement.style.whiteSpace = 'nowrap';
    measureElement.style.font = 'var(--text-base) var(--font-body)';
    measureElement.style.fontWeight = 'var(--weight-normal)';
    document.body.appendChild(measureElement);

    let maxWidth = 100; // Largeur minimale

    // Mesurer le header
    const headerText = columnKey.charAt(0).toUpperCase() + columnKey.slice(1);
    measureElement.textContent = headerText.toUpperCase();
    measureElement.style.fontSize = 'var(--text-xs)';
    measureElement.style.fontWeight = 'var(--weight-bold)';
    measureElement.style.letterSpacing = '0.08em';
    maxWidth = Math.max(maxWidth, measureElement.offsetWidth);

    // Mesurer un échantillon des cellules (max 100 entrées pour performance)
    measureElement.style.fontSize = 'var(--text-base)';
    measureElement.style.fontWeight = 'var(--weight-normal)';
    measureElement.style.letterSpacing = 'normal';

    const sampleSize = Math.min(100, dataSource.length);
    const step = Math.max(1, Math.floor(dataSource.length / sampleSize));

    for (let i = 0; i < dataSource.length; i += step) {
      const secret = dataSource[i];
      let content = '';

      if (columnKey === 'name') {
        content = treeView && secret.displayName ? secret.displayName : secret.name;
      } else if (columnKey === 'username') {
        content = secret.username || '';
      } else if (columnKey === 'password') {
        // TREE-20 : la colonne affiche des puces, pas le mot de passe. Mesurer le mot de passe en
        // clair donnait une largeur révélant la longueur du plus long mot de passe du coffre.
        content = secret.password ? '••••••' : '';
      } else if (columnKey === 'url') {
        content = secret.url || '';
      } else if (columnKey === 'notes') {
        content = secret.notes ? secret.notes.substring(0, 50) : '';
      } else if (columnKey === 'tags') {
        content = secret.tags || '';
      } else if (columnKey === 'customFields') {
        content = secret.customFields ? secret.customFields.map(f => `${f.key}: ${f.protected ? '••••' : f.value}`).join(', ') : '';
      } else if (columnKey === 'engine') {
        content = secret.engineName || selectedEngine?.name || '';
      }

      measureElement.textContent = content;
      maxWidth = Math.max(maxWidth, measureElement.offsetWidth);
    }

    document.body.removeChild(measureElement);

    // Ajouter du padding (environ 40px de chaque côté + icônes)
    const newWidth = Math.min(MAX_COLUMN_WIDTH, Math.max(100, maxWidth + 80));

    const newWidths = {
      ...widthsRef.current,
      [columnKey]: newWidth
    };
    widthsRef.current = newWidths;
    setColumnWidths(newWidths);
    persistWidths(newWidths);
    // TREE-20 : plus de toast « Copié » (aucune copie n'a lieu ; l'utilisateur pouvait croire
    // qu'un contenu, éventuellement un mot de passe, était passé dans le presse-papiers).
    // La nouvelle largeur de la colonne est le retour visuel.
  };

  useEffect(() => {
    if (resizingColumn) {
      document.addEventListener('mousemove', handleColumnResizeMove);
      document.addEventListener('mouseup', handleColumnResizeEnd);
      return () => {
        document.removeEventListener('mousemove', handleColumnResizeMove);
        document.removeEventListener('mouseup', handleColumnResizeEnd);
      };
    }
  }, [resizingColumn, handleColumnResizeMove, handleColumnResizeEnd]);

  return {
    visibleColumns,
    setVisibleColumns,
    columnWidths,
    resizingColumn,
    toggleColumn,
    handleColumnResizeStart,
    handleColumnResizeMove,
    handleColumnResizeEnd,
    handleColumnAutoFit
  };
}
