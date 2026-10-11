// ========================================
// COMPOSANT: SecretsTable — Tableau des secrets
// ========================================
// PERFORMANCE (coffres de plusieurs milliers d'entrées) : chaque ligne est un composant
// mémoïsé (React.memo) qui ne reçoit que des valeurs propres à SA ligne (sélectionnée,
// mot de passe visible, « RBI uniquement », cible de dépôt) et des actions STABLES
// (relais vers les derniers callbacks reçus). Une frappe dans la recherche, un clic de
// sélection, le survol d'une cible de glisser-déposer ou un toast ne re-rendent plus
// que les lignes concernées (avant : les 5 000 lignes, plus d'une seconde de gel).
// Largeurs de colonne : portées par les seuls en-têtes (th). Le tableau est en
// « table-layout: fixed » (AppStyles.css) : la première rangée (thead) fixe la largeur des
// colonnes, la largeur répétée sur chaque cellule était ignorée. Redimensionner une colonne
// ne re-rend donc plus aucune ligne (avant : 5 000 lignes re-rendues à chaque mouvement).
// (Une variable CSS posée sur le tableau a été écartée : la modifier recalcule le style de
// toutes les cellules, plus d'une seconde par mouvement de souris à 5 000 lignes.)
import React, { memo, useMemo, useRef } from 'react';
import LoadingSpinner from '../../LoadingSpinner.jsx';
import { handleUrlAction } from '../../utils/urlHandler';
import { entryKey } from '../../hooks/useSelection';

const COLUMN_KEYS = ['name', 'username', 'password', 'url', 'notes', 'tags', 'customFields'];

// TABLE-19 : infobulle (title) avec le texte complet d'une cellule tronquée par une ellipse
// (white-space: nowrap, AppStyles.css). JAMAIS pour le mot de passe ni pour un champ protégé.
// Bornée : une note de plusieurs centaines de Ko ne doit pas être recopiée dans un attribut.
const TOOLTIP_MAX_LENGTH = 1000;
function cellTooltip(text) {
  if (typeof text !== 'string' || !text) return undefined;
  if (text.length <= TOOLTIP_MAX_LENGTH) return text;
  // Coupe sans laisser une moitié de paire UTF-16 (emoji) isolée
  return `${text.slice(0, TOOLTIP_MAX_LENGTH).replace(/[\uD800-\uDBFF]$/, '')}…`;
}

// Événement « clic droit » synthétique ancré sur un élément (ouverture du menu contextuel au clavier)
function keyboardContextEvent(el) {
  const rect = el.getBoundingClientRect();
  return {
    preventDefault() {},
    stopPropagation() {},
    clientX: Math.round(rect.left + Math.min(24, rect.width / 2)),
    clientY: Math.round(rect.bottom),
    target: el,
    currentTarget: el,
  };
}

// Déplace le focus vers la ligne focalisable voisine (flèches haut/bas, Début/Fin)
function focusSiblingRow(row, key) {
  const rows = Array.from(row.closest('tbody')?.querySelectorAll('tr[tabindex="0"]') || []);
  const index = rows.indexOf(row);
  let next = null;
  if (key === 'ArrowDown') next = rows[index + 1];
  else if (key === 'ArrowUp') next = rows[index - 1];
  else if (key === 'Home') next = rows[0];
  else if (key === 'End') next = rows[rows.length - 1];
  if (next) next.focus();
  return !!next;
}

// Ligne « dossier » (vue arborescence), mémoïsée
const FolderRow = memo(function FolderRow({ s, colSpan, isDropTarget, actions, t }) {
  // Clavier : la ligne dossier est focalisable ; Entrée / Espace ouvre le dossier,
  // touche Menu / Maj+F10 ouvre son menu contextuel (événement natif contextmenu).
  return (
    <tr
      className="folder-row"
      tabIndex={0}
      aria-label={`${t('editSecret.typeFolder')} ${s.displayName}`}
      onClick={() => actions.setCurrentPath(s.name)}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          actions.setCurrentPath(s.name);
        } else if (focusSiblingRow(e.currentTarget, e.key)) {
          e.preventDefault();
        }
      }}
      onContextMenu={(e) => actions.handleFolderRightClick(e, s.name)}
      onDragOver={(e) => {
        e.preventDefault();
        e.stopPropagation();
        actions.handleDragOver(e, `folder:${s.name}`);
      }}
      onDragEnter={(e) => {
        e.preventDefault();
        e.stopPropagation();
        actions.handleDragOver(e, `folder:${s.name}`);
      }}
      onDragLeave={(e) => {
        e.stopPropagation();
        actions.handleDragLeave();
      }}
      onDrop={(e) => actions.handleDropOnFolder(e, s.name)}
      style={{
        cursor: 'pointer',
        background: isDropTarget
          ? 'var(--bg-selection, rgba(59, 130, 246, 0.25))'
          : 'var(--bg-surface-hover)',
        outline: isDropTarget ? '2px dashed var(--accent, #3b82f6)' : undefined,
        transition: 'all 0.15s ease'
      }}
    >
      <td
        colSpan={colSpan}
        style={{
          padding: 'var(--sp-3)',
          fontWeight: 'var(--weight-semibold)',
          color: 'var(--accent)'
        }}
      >
        {'📁'} {s.displayName}
        {isDropTarget && (
          <span style={{ marginInlineStart: 'var(--sp-2)', fontSize: 'var(--text-sm)' }}>
            {'⬇️'} {t('table.dropHere')}
          </span>
        )}
      </td>
    </tr>
  );
});

// Ligne d'entrée, mémoïsée : ne se re-rend que si SES valeurs changent
// rowKey : clé de sélection / de visibilité de la ligne (entryKey : nom, ou coffre + nom pour un
// résultat d'un autre coffre en recherche multi-coffres — deux homonymes ne s'allument plus ensemble)
const SecretRow = memo(function SecretRow({
  s, rowKey, isSelected, showCheck, passwordVisible, rbiOnly, cols, showEngine, engineLabel, actions, t,
}) {
  // Menu contextuel de la ligne (actions : copier, modifier, restaurer, session sécurisée…)
  const openRowMenu = (e) => actions.handleCellRightClick(e, s, 'name', s.name);
  return (
    <tr
      draggable={!s.deleted}
      // Clavier : ligne focalisable ; Espace = sélection (Ctrl/Maj comme à la souris),
      // Entrée / touche Menu / Maj+F10 = menu contextuel de l'entrée, flèches = ligne voisine.
      tabIndex={0}
      onClick={(e) => {
        if (!s.deleted) {
          actions.toggleSecretSelection(rowKey, e.ctrlKey || e.metaKey, e.shiftKey);
        }
      }}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return; // touches destinées au bouton œil / lien URL
        if (e.key === ' ') {
          e.preventDefault();
          if (!s.deleted) actions.toggleSecretSelection(rowKey, e.ctrlKey || e.metaKey, e.shiftKey);
        } else if (e.key === 'Enter') {
          e.preventDefault();
          openRowMenu(keyboardContextEvent(e.currentTarget));
        } else if (focusSiblingRow(e.currentTarget, e.key)) {
          e.preventDefault();
        }
      }}
      onContextMenu={(e) => {
        // Touche Menu / Maj+F10 sur la ligne focalisée (cible = la ligne elle-même) :
        // sans cela, l'événement remontait au tableau et ouvrait le menu « Nouvelle entrée ».
        if (e.target !== e.currentTarget) return;
        e.stopPropagation();
        openRowMenu(e);
      }}
      onDragStart={(e) => !s.deleted && actions.handleDragStart(e, s)}
      onDragEnd={actions.handleDragEnd}
      className={isSelected ? 'row-selected' : ''}
      style={{
        cursor: s.deleted ? 'default' : 'pointer',
        background: isSelected ? 'var(--bg-selection, rgba(59, 130, 246, 0.15))' : undefined,
        outline: isSelected ? '2px solid var(--accent, #3b82f6)' : undefined,
        outlineOffset: '-2px'
      }}
    >
      {cols.name && (
        <td
          className={`cell-name ${s.deleted ? 'cell-deleted' : ''}`}
          title={cellTooltip(s.name)}
          onContextMenu={(e) => actions.handleCellRightClick(e, s, 'name', s.name)}
        >
          {/* Marges logiques (margin-inline-*) : l'espace reste côté texte en arabe (dir="rtl") */}
          {showCheck && (
            <span style={{ marginInlineEnd: 'var(--sp-2)', color: 'var(--accent)' }}>{'✓'}</span>
          )}
          {s.entryType === 'ssh' && <span style={{ marginInlineEnd: 'var(--sp-1)' }}>{'🔑'}</span>}
          {/* Vue liste (sans arborescence) : afficher le chemin complet, dossier en retrait,
              pour distinguer deux secrets de même nom dans des dossiers différents */}
          {s.displayName || (s.name.includes('/')
            ? (<><span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>{s.name.slice(0, s.name.lastIndexOf('/') + 1)}</span>{s.name.split('/').pop()}</>)
            : s.name)}
          {s.deleted && <span className="deleted-badge">({t('versionHistory.deleted')})</span>}
        </td>
      )}
      {showEngine && (
        <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }} title={cellTooltip(engineLabel)}>
          {engineLabel}
        </td>
      )}
      {cols.username && (
        <td
          className={s.deleted ? 'cell-deleted' : ''}
          onContextMenu={s.deleted || rbiOnly ? undefined : (e) => actions.handleCellRightClick(e, s, 'username', s.username)}
          onDoubleClick={async (e) => {
            if (!s.deleted && s.username && !rbiOnly) {
              e.stopPropagation();
              await actions.startClipboardTimer(t('table.username'), s.username);
              window.getSelection().removeAllRanges();
            }
          }}
          style={{ cursor: !s.deleted && s.username && !rbiOnly ? 'pointer' : 'default' }}
          title={rbiOnly ? undefined : cellTooltip(s.username)}
        >
          {rbiOnly ? '—' : s.username}
        </td>
      )}
      {cols.password && (
        <td
          className={s.deleted ? 'cell-deleted' : ''}
          onContextMenu={s.deleted || rbiOnly ? undefined : (e) => actions.handleCellRightClick(e, s, 'password', s.password)}
          onDoubleClick={async (e) => {
            if (!s.deleted && s.password && !rbiOnly) {
              e.stopPropagation();
              await actions.startClipboardTimer(t('table.password'), s.password);
              window.getSelection().removeAllRanges();
            }
          }}
          style={{ cursor: !s.deleted && s.password && !rbiOnly ? 'pointer' : 'default' }}
        >
          {s.deleted || rbiOnly ? '—' : (
            <>
              <span style={{ marginInlineEnd: '8px' }}>{passwordVisible ? s.password : '••••••'}</span>
              <button
                onClick={(e) => {
                  // BUG CORRIGÉ : le clic remontait à la ligne et remplaçait la sélection en cours
                  e.stopPropagation();
                  actions.setVisiblePasswords(prev => ({ ...prev, [rowKey]: !prev[rowKey] }));
                }}
                className="btn-action btn-action-view"
                type="button"
                // Bouton bascule : nom constant + état aria-pressed (APG « Button ») ; infobulle selon l'état
                aria-label={t('table.showPassword')}
                aria-pressed={passwordVisible}
                title={passwordVisible ? t('table.hidePassword') : t('table.showPassword')}
              >
                {passwordVisible ? (
                  <svg viewBox="0 0 24 24" fill="none">
                    <path d="M17.94 17.94C16.2306 19.243 14.1491 19.9649 12 20C5 20 1 12 1 12C2.24389 9.68192 3.96914 7.65663 6.06 6.06M9.9 4.24C10.5883 4.0789 11.2931 3.99836 12 4C19 4 23 12 23 12C22.393 13.1356 21.6691 14.2048 20.84 15.19M14.12 14.12C13.8454 14.4148 13.5141 14.6512 13.1462 14.8151C12.7782 14.9791 12.3809 15.0673 11.9781 15.0744C11.5753 15.0815 11.1752 15.0074 10.8016 14.8565C10.4281 14.7056 10.0887 14.4811 9.80385 14.1962C9.51897 13.9113 9.29439 13.572 9.14351 13.1984C8.99262 12.8248 8.91853 12.4247 8.92563 12.0219C8.93274 11.6191 9.02091 11.2218 9.18488 10.8538C9.34884 10.4859 9.58525 10.1546 9.88 9.88" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M1 1L23 23" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" fill="none">
                    <path d="M1 12C1 12 5 4 12 4C19 4 23 12 23 12C23 12 19 20 12 20C5 20 1 12 1 12Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M12 15C13.6569 15 15 13.6569 15 12C15 10.3431 13.6569 9 12 9C10.3431 9 9 10.3431 9 12C9 13.6569 10.3431 15 12 15Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                )}
              </button>
            </>
          )}
        </td>
      )}
      {cols.url && (
        <td
          className={s.deleted ? 'cell-deleted' : ''}
          onContextMenu={s.deleted ? undefined : (e) => actions.handleCellRightClick(e, s, 'url', s.url)}
        >
          {s.url && !s.deleted ? (
            <>
              {(s.url.startsWith('\\\\') || s.url.startsWith('//') || /^[a-zA-Z]:\\/.test(s.url)) && (
                <span style={{ marginInlineEnd: '6px', opacity: 0.7 }}>{'📁'}</span>
              )}
              {(s.url.toLowerCase().startsWith('ssh://') || s.url.includes(':22')) && (
                <span style={{ marginInlineEnd: '6px', opacity: 0.7 }}>{'🔑'}</span>
              )}
              {/* Bouton (et non <span>) : focalisable et activable au clavier (Entrée / Espace) */}
              <button
                type="button"
                className="url-link"
                title={cellTooltip(s.url)}
                onClick={async (e) => {
                  e.stopPropagation();
                  await handleUrlAction(s.url, s, {
                    isSecretRbiOnly: actions.isSecretRbiOnly,
                    getTotpKeyName: actions.getTotpKeyName,
                    getTotpCode: actions.getTotpCode,
                    startClipboardTimer: actions.startClipboardTimer,
                    showToast: actions.showToast,
                    t
                  });
                }}
              >
                {s.url}
              </button>
            </>
          ) : (
            s.url
          )}
        </td>
      )}
      {cols.notes && (
        <td
          className={s.deleted ? 'cell-deleted' : ''}
          onContextMenu={s.deleted || rbiOnly ? undefined : (e) => actions.handleCellRightClick(e, s, 'notes', s.notes)}
          onDoubleClick={rbiOnly ? undefined : () => actions.setNotesPopup({ notes: s.notes })}
          style={{ cursor: rbiOnly ? 'default' : 'pointer' }}
          title={rbiOnly ? undefined : cellTooltip(s.notes)}
        >
          {rbiOnly ? '—' : s.notes}
        </td>
      )}
      {cols.tags && (
        <td
          style={{
            cursor: 'context-menu',
            minHeight: '32px',
            whiteSpace: 'normal',
            overflow: 'visible'
          }}
          onContextMenu={(e) => actions.handleTagCellRightClick(e, s)}
        >
          {(() => {
            const tagList = s.tags ? s.tags.split(/[\s,;]+/).filter(tag => tag) : [];
            const hasOverflow = tagList.length > 2;
            return (
              <div style={{ position: 'relative' }}>
                <div className="tags-scroll-container">
                  {tagList.map((tag, tagIdx) => (
                    <span key={tagIdx} className="tag-badge" style={{ background: actions.getTagColor(tag) }}>
                      {tag}
                    </span>
                  ))}
                  {tagList.length === 0 && (
                    <span style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-tertiary)',
                      fontStyle: 'italic',
                      padding: '4px'
                    }}>
                      {t('table.rightClickToAddTag')}
                    </span>
                  )}
                </div>
                {hasOverflow && (
                  <div className="tags-overflow-indicator">{'▾'}</div>
                )}
              </div>
            );
          })()}
        </td>
      )}
      {cols.customFields && (
        <td style={{ whiteSpace: 'normal', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {s.customFields && s.customFields.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px' }}>
              {s.customFields.map((cf, cfIdx) => (
                <span key={cfIdx} style={{
                  fontSize: 'var(--text-xs)',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '1px 4px',
                  color: 'var(--text-secondary)'
                }}>
                  {cf.key}: {cf.protected ? '••••' : cf.value}
                </span>
              ))}
            </div>
          ) : null}
        </td>
      )}
    </tr>
  );
});

// Callbacks relayés par les actions stables des lignes
const ACTION_NAMES = [
  'toggleSecretSelection', 'setVisiblePasswords', 'setCurrentPath', 'setNotesPopup',
  'handleCellRightClick', 'handleFolderRightClick', 'handleTagCellRightClick',
  'handleDragStart', 'handleDragEnd', 'handleDragOver', 'handleDragLeave', 'handleDropOnFolder',
  'isSecretRbiOnly', 'startClipboardTimer', 'getTagColor', 'getTotpKeyName', 'getTotpCode', 'showToast',
];

export default function SecretsTable({
  // Data
  filteredSecrets,
  secrets,
  allVaultSecrets,
  selectedEngine,
  // State
  loadingSecrets,
  multiVaultSearch,
  search,
  visiblePasswords, setVisiblePasswords,
  effectiveVisibleColumns,
  columnWidths,
  resizingColumn,
  isCurrentEngineRbiOnly,
  token,
  // Selection
  selectedSecrets,
  isSecretSelected,
  toggleSecretSelection,
  displayedSecretsRef,
  // Drag & Drop
  isDragging, dragOverTarget,
  handleDragStart, handleDragEnd, handleDragOver, handleDragLeave, handleDropOnFolder,
  // Columns
  handleColumnResizeStart,
  autoFitColumn,
  handleColumnHeaderRightClick,
  // Context menus
  handleEmptyAreaRightClick,
  handleCellRightClick,
  handleFolderRightClick,
  handleTagCellRightClick,
  // Actions
  isSecretRbiOnly,
  startClipboardTimer,
  setNotesPopup,
  setCurrentPath,
  getTagColor,
  getTotpKeyName, getTotpCode,
  showToast,
  t,
}) {
  // Derniers callbacks reçus (souvent recréés à chaque rendu d'App) : les lignes mémoïsées
  // reçoivent des relais STABLES qui appellent toujours la version la plus récente.
  const latestRef = useRef(null);
  latestRef.current = {
    toggleSecretSelection, setVisiblePasswords, setCurrentPath, setNotesPopup,
    handleCellRightClick, handleFolderRightClick, handleTagCellRightClick,
    handleDragStart, handleDragEnd, handleDragOver, handleDragLeave, handleDropOnFolder,
    isSecretRbiOnly, startClipboardTimer, getTagColor, getTotpKeyName, getTotpCode, showToast,
  };
  const actions = useMemo(() => {
    const relays = {};
    for (const name of ACTION_NAMES) relays[name] = (...args) => latestRef.current[name]?.(...args);
    return relays;
  }, []);

  // Colonnes affichées : objet stable tant que les booléens ne changent pas
  const visible = effectiveVisibleColumns || {};
  const { name: cName, username: cUser, password: cPass, url: cUrl, notes: cNotes, tags: cTags, customFields: cFields } = visible;
  const cols = useMemo(() => ({
    name: !!cName, username: !!cUser, password: !!cPass, url: !!cUrl, notes: !!cNotes, tags: !!cTags, customFields: !!cFields,
  }), [cName, cUser, cPass, cUrl, cNotes, cTags, cFields]);

  if (loadingSecrets) {
    return <LoadingSpinner />;
  }

  const hasSecrets = (multiVaultSearch && search.trim() ? allVaultSecrets : secrets).length > 0;

  if (!hasSecrets) {
    if (token && (selectedEngine || (multiVaultSearch && search.trim()))) {
      return (
        <div className="empty-state" onContextMenu={handleEmptyAreaRightClick}>
          {multiVaultSearch && search.trim() ? t('table.noResultsAllVaults') : t('table.noSecrets')}
        </div>
      );
    }
    return null;
  }

  const showEngine = !!(multiVaultSearch && search.trim());
  const folderColSpan = COLUMN_KEYS.filter(key => cols[key]).length + (showEngine ? 1 : 0);
  const multiSelection = (selectedSecrets?.size || 0) > 1;
  displayedSecretsRef.current = filteredSecrets;

  // Clés stables (coffre + nom) : une ligne garde son élément DOM quand la liste est filtrée ou
  // rafraîchie (avant : index dans la clé → démontage/remontage de toutes les lignes suivantes).
  const usedKeys = new Set();
  const rows = filteredSecrets.map((s, idx) => {
    let key = s.isFolder ? `folder:${s.name}` : `${s.engineName || ''}␟${s.name}`;
    if (usedKeys.has(key)) key = `${key}␟${idx}`;
    usedKeys.add(key);
    if (s.isFolder) {
      return (
        <FolderRow
          key={key}
          s={s}
          colSpan={folderColSpan}
          isDropTarget={!!isDragging && dragOverTarget === `folder:${s.name}`}
          actions={actions}
          t={t}
        />
      );
    }
    // Sélection et mot de passe révélé indexés par coffre + nom pour un résultat d'un autre coffre
    const rowKey = entryKey(s, selectedEngine?.name);
    const isSelected = !!isSecretSelected(rowKey);
    return (
      <SecretRow
        key={key}
        s={s}
        rowKey={rowKey}
        isSelected={isSelected}
        showCheck={isSelected && multiSelection}
        passwordVisible={!!visiblePasswords?.[rowKey]}
        rbiOnly={!!isSecretRbiOnly(s.name)}
        cols={cols}
        showEngine={showEngine}
        engineLabel={showEngine ? (s.engineName || selectedEngine?.name) : undefined}
        actions={actions}
        t={t}
      />
    );
  });

  return (
    <table
      className="secrets-table"
      onContextMenu={handleEmptyAreaRightClick}
      onDoubleClick={() => {
        setTimeout(() => window.getSelection().removeAllRanges(), 0);
      }}
    >
      <thead>
        <tr onContextMenu={isCurrentEngineRbiOnly ? undefined : handleColumnHeaderRightClick}>
          {cols.name && (
            <th className="resizable-header" style={{ width: columnWidths.name || 'auto' }}>
              {t('table.name')}
              <div
                className={`column-resizer ${resizingColumn === 'name' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'name', columnWidths.name)}
                onDoubleClick={(e) => autoFitColumn(e, 'name')}
              />
            </th>
          )}
          {showEngine && (
            <th className="resizable-header" style={{ width: columnWidths.engine || 'auto' }}>
              {t('toolbar.vaultView')}
              <div
                className={`column-resizer ${resizingColumn === 'engine' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'engine', columnWidths.engine)}
              />
            </th>
          )}
          {cols.username && (
            <th className="resizable-header" style={{ width: columnWidths.username || 'auto' }}>
              {t('table.username')}
              <div
                className={`column-resizer ${resizingColumn === 'username' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'username', columnWidths.username)}
                onDoubleClick={(e) => autoFitColumn(e, 'username')}
              />
            </th>
          )}
          {cols.password && (
            <th className="resizable-header" style={{ width: columnWidths.password || 'auto' }}>
              {t('table.password')}
              <div
                className={`column-resizer ${resizingColumn === 'password' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'password', columnWidths.password)}
                onDoubleClick={(e) => autoFitColumn(e, 'password')}
              />
            </th>
          )}
          {cols.url && (
            <th className="resizable-header" style={{ width: columnWidths.url || 'auto' }}>
              {t('table.url')}
              <div
                className={`column-resizer ${resizingColumn === 'url' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'url', columnWidths.url)}
                onDoubleClick={(e) => autoFitColumn(e, 'url')}
              />
            </th>
          )}
          {cols.notes && (
            <th className="resizable-header" style={{ width: columnWidths.notes || 'auto' }}>
              {t('table.notes')}
              <div
                className={`column-resizer ${resizingColumn === 'notes' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'notes', columnWidths.notes)}
                onDoubleClick={(e) => autoFitColumn(e, 'notes')}
              />
            </th>
          )}
          {cols.tags && (
            <th className="resizable-header" style={{ width: columnWidths.tags || 'auto' }}>
              {t('table.tags')}
              <div
                className={`column-resizer ${resizingColumn === 'tags' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'tags', columnWidths.tags)}
                onDoubleClick={(e) => autoFitColumn(e, 'tags')}
              />
            </th>
          )}
          {cols.customFields && (
            <th className="resizable-header" style={{ width: columnWidths.customFields || 'auto' }}>
              {t('table.customFields')}
              <div
                className={`column-resizer ${resizingColumn === 'customFields' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'customFields', columnWidths.customFields)}
                onDoubleClick={(e) => autoFitColumn(e, 'customFields')}
              />
            </th>
          )}
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  );
}
