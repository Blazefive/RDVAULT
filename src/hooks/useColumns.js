import { useState, useRef, useCallback, useEffect } from 'react';

/**
 * Hook useColumns — gère la visibilité et le redimensionnement des colonnes du tableau
 * @param {Function} showToast - Fonction d'affichage des toasts
 * @param {Function} t - Fonction de traduction i18n
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
  const resizeStartX = useRef(0);
  const resizeStartWidth = useRef(0);

  const toggleColumn = (columnKey) => {
    const newVisibleColumns = {
      ...visibleColumns,
      [columnKey]: !visibleColumns[columnKey]
    };
    setVisibleColumns(newVisibleColumns);
    localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
  };

  const saveColumnWidths = (newWidths) => {
    setColumnWidths(newWidths);
    localStorage.setItem('rdvault-column-widths', JSON.stringify(newWidths));
  };

  // Redimensionnement des colonnes
  const handleColumnResizeStart = (e, columnKey, currentWidth) => {
    e.preventDefault();
    e.stopPropagation();
    setResizingColumn(columnKey);
    resizeStartX.current = e.clientX;
    resizeStartWidth.current = currentWidth || 150; // Largeur par défaut si non définie
  };

  const handleColumnResizeMove = useCallback((e) => {
    if (!resizingColumn) return;
    const diff = e.clientX - resizeStartX.current;

    // Calculer la nouvelle largeur avec contraintes
    const minWidth = 80; // Minimum 80px pour lisibilité
    const maxWidth = 600; // Maximum 600px pour éviter d'écraser les autres colonnes

    const newWidth = Math.max(minWidth, Math.min(maxWidth, resizeStartWidth.current + diff));

    const newWidths = {
      ...columnWidths,
      [resizingColumn]: newWidth
    };
    setColumnWidths(newWidths);
    localStorage.setItem('rdvault-column-widths', JSON.stringify(newWidths));
  }, [resizingColumn, columnWidths]);

  const handleColumnResizeEnd = useCallback(() => {
    setResizingColumn(null);
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
        content = secret.password || '';
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
    const newWidth = Math.min(600, Math.max(100, maxWidth + 80));

    const newWidths = {
      ...columnWidths,
      [columnKey]: newWidth
    };
    setColumnWidths(newWidths);
    localStorage.setItem('rdvault-column-widths', JSON.stringify(newWidths));

    showToast(t('toast.copied'), 'success', 1500);
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
  }, [resizingColumn, columnWidths, handleColumnResizeMove, handleColumnResizeEnd]);

  return {
    visibleColumns,
    setVisibleColumns,
    columnWidths,
    resizingColumn,
    toggleColumn,
    saveColumnWidths,
    handleColumnResizeStart,
    handleColumnResizeMove,
    handleColumnResizeEnd,
    handleColumnAutoFit
  };
}
