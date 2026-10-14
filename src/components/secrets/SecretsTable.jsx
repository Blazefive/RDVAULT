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
// VIRTUALISATION (au-delà de VIRTUALIZE_THRESHOLD lignes, virtualRows.js) : seules les lignes visibles
// et une marge sont dans le DOM ; deux lignes « espaceurs » conservent la hauteur totale (barre de
// défilement inchangée). Avant : 1 200 lignes = 5 à 9 ms de fil principal par image d'animation,
// mise en page d'un tableau de 5 000 lignes ≈ 65 ms (le confinement CSS ne s'applique pas aux lignes
// d'un <table>). Sous le seuil, rendu complet strictement inchangé. Restent dans le DOM même hors de
// la zone visible : la ligne qui a (ou a eu en dernier) le focus — le focus clavier et le retour de
// focus des menus / modales ne sont jamais perdus — et la ligne en cours de glisser (dragend).
// Sélection (Maj / Ctrl), glisser-déposer et menus travaillent sur la liste complète
// (displayedSecretsRef), pas sur le DOM : les lignes non rendues sont sélectionnables par plage.
import React, { memo, useLayoutEffect, useMemo, useRef, useState } from 'react';
import LoadingSpinner from '../../LoadingSpinner.jsx';
import { handleUrlAction } from '../../utils/urlHandler';
import { entryKey } from '../../hooks/useSelection';
import {
  VIRTUALIZE_THRESHOLD, INITIAL_ROWS, DEFAULT_ROW_HEIGHT, FALLBACK_VIEWPORT,
  computeOffsets, computeRange, renderedIndices, averageHeight, findScrollContainer,
} from './virtualRows';

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

// Nombre de lignes d'une « page » (Page préc. / Page suiv.) : lignes entièrement visibles sous
// l'en-tête collant, moins une (la ligne de départ reste visible) ; 10 sans géométrie (élément masqué).
function rowsPerPage(viewHeight, headerHeight, rowHeight) {
  if (!(viewHeight > 0) || !(rowHeight > 0)) return 10;
  return Math.max(1, Math.floor((viewHeight - headerHeight) / rowHeight) - 1);
}

// Déplace le focus vers la ligne focalisable voisine (flèches haut/bas, Début/Fin, Page préc./suiv.)
// — tableau NON virtualisé : toutes les lignes sont dans le DOM.
function focusSiblingRow(row, key) {
  const rows = Array.from(row.closest('tbody')?.querySelectorAll('tr[tabindex="0"]') || []);
  const index = rows.indexOf(row);
  let next = null;
  if (key === 'ArrowDown') next = rows[index + 1];
  else if (key === 'ArrowUp') next = rows[index - 1];
  else if (key === 'Home') next = rows[0];
  else if (key === 'End') next = rows[rows.length - 1];
  else if (key === 'PageDown' || key === 'PageUp') {
    const sc = findScrollContainer(row);
    const viewHeight = sc === window ? window.innerHeight : sc.clientHeight;
    const head = row.closest('table')?.tHead;
    const page = rowsPerPage(viewHeight, head ? head.getBoundingClientRect().height : 0, row.getBoundingClientRect().height);
    next = rows[key === 'PageDown' ? Math.min(rows.length - 1, index + page) : Math.max(0, index - page)];
  }
  if (next) next.focus();
  return !!next;
}

// Ligne « dossier » (vue arborescence), mémoïsée
// ariaRowIndex : position dans le tableau complet (tableau virtualisé seulement, sinon absent)
const FolderRow = memo(function FolderRow({ s, colSpan, isDropTarget, ariaRowIndex, actions, t }) {
  // Clavier : la ligne dossier est focalisable ; Entrée / Espace ouvre le dossier,
  // touche Menu / Maj+F10 ouvre son menu contextuel (événement natif contextmenu).
  return (
    <tr
      className="folder-row"
      aria-rowindex={ariaRowIndex}
      tabIndex={0}
      aria-label={`${t('editSecret.typeFolder')} ${s.displayName}`}
      onClick={() => actions.setCurrentPath(s.name)}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          actions.setCurrentPath(s.name);
        } else if (actions.navigateRow(e.currentTarget, e.key)) {
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
        transition: 'background-color 0.15s ease'
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
  s, rowKey, isSelected, showCheck, passwordVisible, rbiOnly, cols, showEngine, engineLabel, ariaRowIndex, actions, t,
}) {
  // Menu contextuel de la ligne (actions : copier, modifier, restaurer, session sécurisée…)
  const openRowMenu = (e) => actions.handleCellRightClick(e, s, 'name', s.name);
  return (
    <tr
      aria-rowindex={ariaRowIndex}
      draggable={!s.deleted}
      // Clavier : ligne focalisable ; Espace = sélection (Ctrl/Maj comme à la souris),
      // Entrée / touche Menu / Maj+F10 = menu contextuel de l'entrée, flèches / Début / Fin /
      // Page préc. / Page suiv. = autre ligne (rendue au besoin si le tableau est virtualisé).
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
        } else if (actions.navigateRow(e.currentTarget, e.key)) {
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
          {/* UI-38 : sélection (lot des actions « Déplacer / Copier vers / Migrer ») annoncée aux
              lecteurs d'écran ; aria-selected n'est pas valide sur la ligne d'un <table> statique */}
          {isSelected && <span className="sr-only">{`, ${t('table.rowSelected')}`}</span>}
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
  'navigateRow',
];

// Clés React stables (coffre + nom) : une ligne garde son élément DOM quand la liste est filtrée ou
// rafraîchie (avant : index dans la clé → démontage/remontage de toutes les lignes suivantes).
// Servent aussi de clés au cache des hauteurs mesurées (tableau virtualisé).
function computeRowKeys(list) {
  const usedKeys = new Set();
  return list.map((s, idx) => {
    let key = s.isFolder ? `folder:${s.name}` : `${s.engineName || ''}␟${s.name}`;
    if (usedKeys.has(key)) key = `${key}␟${idx}`;
    usedKeys.add(key);
    return key;
  });
}

// Index de ligne (0 = première ligne de données) porté par aria-rowindex (1 = ligne d'en-tête)
const rowIndexOf = (tr) => {
  const v = tr && tr.getAttribute ? tr.getAttribute('aria-rowindex') : null;
  return v === null ? -1 : Number(v) - 2;
};

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
  // ─── Virtualisation : état et références (hooks appelés avant tout retour anticipé) ───
  const list = useMemo(() => (Array.isArray(filteredSecrets) ? filteredSecrets : []), [filteredSecrets]);
  const showEngine = !!(multiVaultSearch && typeof search === 'string' && search.trim());
  const hasSecrets = !loadingSecrets && ((showEngine ? allVaultSecrets : secrets) || []).length > 0;
  const virtual = hasSecrets && list.length > VIRTUALIZE_THRESHOLD;

  const rowKeys = useMemo(() => computeRowKeys(list), [list]);
  const keyIndex = useMemo(() => new Map(rowKeys.map((k, i) => [k, i])), [rowKeys]);
  const tableRef = useRef(null);
  const tbodyRef = useRef(null);
  const scrollerRef = useRef(null);
  const heightsRef = useRef(new Map()); // clé de ligne → hauteur mesurée (px, fractionnaire)
  const estimateRef = useRef(null); // hauteur retenue pour une ligne jamais rendue
  const pendingFocusRef = useRef(null); // clé de la ligne à focaliser dès qu'elle est rendue
  const measureLoopRef = useRef(0);
  const [measureVersion, setMeasureVersion] = useState(0);
  const [range, setRange] = useState({ start: 0, end: INITIAL_ROWS });
  const [focusKey, setFocusKey] = useState(null); // ligne focalisée en dernier (épinglée)
  const [dragKey, setDragKey] = useState(null); // ligne source d'un glisser en cours (épinglée)

  // Colonnes affichées : objet stable tant que les booléens ne changent pas
  const visible = effectiveVisibleColumns || {};
  const { name: cName, username: cUser, password: cPass, url: cUrl, notes: cNotes, tags: cTags, customFields: cFields } = visible;
  const cols = useMemo(() => ({
    name: !!cName, username: !!cUser, password: !!cPass, url: !!cUrl, notes: !!cNotes, tags: !!cTags, customFields: !!cFields,
  }), [cName, cUser, cPass, cUrl, cNotes, cTags, cFields]);

  // Colonnes affichées changées : les hauteurs mesurées ne valent plus (une cellule Tags peut
  // passer sur deux lignes) ; elles seront remesurées au rendu
  const layoutSig = `${Object.values(cols).join()}|${showEngine}`;
  const layoutSigRef = useRef(layoutSig);
  if (layoutSigRef.current !== layoutSig) {
    layoutSigRef.current = layoutSig;
    heightsRef.current = new Map();
    estimateRef.current = null;
  }
  // Cache borné (changements de coffre successifs)
  if (heightsRef.current.size > 4 * list.length + 5000) heightsRef.current = new Map();

  const offsets = useMemo(
    () => (virtual ? computeOffsets(rowKeys, heightsRef.current, estimateRef.current || DEFAULT_ROW_HEIGHT) : null),
    // measureVersion / layoutSig : nouvelles mesures (cache muté) → positions recalculées
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [virtual, rowKeys, measureVersion, layoutSig],
  );

  // Valeurs lues par les fonctions stables ci-dessous (écouteurs de défilement, navigation clavier)
  const vRef = useRef(null);
  vRef.current = { virtual, rowKeys, keyIndex, offsets };

  const virt = useMemo(() => {
    // Zone visible en coordonnées du tbody (0 = haut de la première ligne de données).
    // visTop : haut de la zone où une ligne est réellement visible, sous l'en-tête s'il recouvre le
    // haut du conteneur (en-tête collant), sinon le haut du conteneur. Position RÉELLE de l'en-tête :
    // dans l'application, le tableau (overflow: hidden) empêche l'en-tête de rester collé.
    const geometry = () => {
      const tbody = tbodyRef.current;
      if (!tbody) return null;
      let sc = scrollerRef.current;
      if (!sc || (sc !== window && !sc.contains(tbody))) sc = scrollerRef.current = findScrollContainer(tableRef.current);
      const tRect = tbody.getBoundingClientRect();
      let top = 0;
      let height = window.innerHeight;
      if (sc !== window) {
        top = sc.getBoundingClientRect().top + (sc.clientTop || 0);
        height = sc.clientHeight;
      }
      if (!(height > 0)) height = FALLBACK_VIEWPORT;
      const head = tableRef.current ? tableRef.current.tHead : null;
      const viewTop = top - tRect.top;
      const visTop = Math.max(viewTop, head ? head.getBoundingClientRect().bottom - tRect.top : 0);
      return { sc, viewTop, viewHeight: height, visTop };
    };
    const updateRange = () => {
      const { virtual: on, offsets: offs } = vRef.current;
      if (!on || !offs) return;
      const g = geometry();
      if (!g) return;
      const next = computeRange(offs, g.viewTop, g.viewHeight);
      setRange(prev => (prev.start === next.start && prev.end === next.end ? prev : next));
    };
    const rowElement = (index) => {
      const tbody = tbodyRef.current;
      return tbody ? tbody.querySelector(`tr[aria-rowindex="${index + 2}"]`) : null;
    };
    // Fait défiler le conteneur au plus juste pour que la ligne soit entièrement visible
    const scrollRowIntoView = (index) => {
      const { offsets: offs } = vRef.current;
      const g = geometry();
      if (!g || !offs || index < 0 || index >= offs.length - 1) return;
      const top = offs[index];
      const bottom = offs[index + 1];
      const { visTop } = g;
      const visBottom = g.viewTop + g.viewHeight;
      let delta = 0;
      if (top < visTop) delta = top - visTop;
      else if (bottom > visBottom) delta = Math.min(bottom - visBottom, top - visTop);
      if (!delta) return;
      if (g.sc === window) window.scrollBy(0, delta);
      else g.sc.scrollTop += delta;
    };
    const focusElement = (el) => {
      try { el.focus({ preventScroll: true }); } catch { el.focus(); }
    };
    // Focus vers la ligne d'index donné, rendue au besoin (épinglée puis focalisée après le rendu)
    const focusRowIndex = (index) => {
      const { rowKeys: keys } = vRef.current;
      scrollRowIntoView(index);
      const el = rowElement(index);
      if (el) {
        focusElement(el);
      } else {
        pendingFocusRef.current = keys[index];
        setFocusKey(keys[index]);
      }
      updateRange();
    };
    // Navigation clavier entre lignes (flèches, Début / Fin, Page préc. / suiv.)
    const navigateRow = (rowEl, key) => {
      const { virtual: on, rowKeys: keys } = vRef.current;
      if (!on) return focusSiblingRow(rowEl, key);
      const index = rowIndexOf(rowEl);
      const last = keys.length - 1;
      if (index < 0) return false;
      let target;
      if (key === 'ArrowDown') target = index + 1;
      else if (key === 'ArrowUp') target = index - 1;
      else if (key === 'Home') target = 0;
      else if (key === 'End') target = last;
      else if (key === 'PageDown' || key === 'PageUp') {
        const g = geometry();
        const page = rowsPerPage(g ? g.viewHeight : 0, g ? g.visTop - g.viewTop : 0, rowEl.getBoundingClientRect().height || estimateRef.current || DEFAULT_ROW_HEIGHT);
        target = key === 'PageDown' ? Math.min(last, index + page) : Math.max(0, index - page);
      } else return false;
      if (target < 0 || target > last) return false;
      focusRowIndex(target);
      return true;
    };
    // Tabulation : l'ordre natif saute les lignes non rendues (ligne focalisée isolée loin de la
    // fenêtre, ou bord de la marge). Quittant le dernier élément focalisable d'une ligne (Tab) ou la
    // ligne elle-même (Maj+Tab) vers une voisine absente du DOM : la voisine est rendue et focalisée.
    const handleTab = (e) => {
      const { virtual: on, rowKeys: keys } = vRef.current;
      if (!on || e.key !== 'Tab' || e.altKey || e.ctrlKey || e.metaKey) return;
      const tr = e.target && e.target.closest ? e.target.closest('tr[aria-rowindex]') : null;
      const index = rowIndexOf(tr);
      if (index < 0) return;
      const target = e.shiftKey ? index - 1 : index + 1;
      if (target < 0 || target >= keys.length || rowElement(target)) return; // ordre natif correct
      const stops = [tr, ...Array.from(tr.querySelectorAll('button, a[href], input, select, textarea, [tabindex]'))
        .filter(el => el.tabIndex >= 0 && !el.disabled)];
      const pos = stops.indexOf(e.target);
      if (e.shiftKey ? pos !== 0 : pos !== stops.length - 1) return;
      e.preventDefault();
      focusRowIndex(target);
    };
    return { updateRange, rowElement, scrollRowIntoView, focusElement, navigateRow, handleTab };
  }, []);

  // Défilement / redimensionnement du conteneur → fenêtre recalculée (une fois par image)
  useLayoutEffect(() => {
    if (!virtual || !tableRef.current) return undefined;
    const sc = findScrollContainer(tableRef.current);
    scrollerRef.current = sc;
    let raf = 0;
    const schedule = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => { raf = 0; virt.updateRange(); });
    };
    sc.addEventListener('scroll', schedule, { passive: true });
    window.addEventListener('resize', schedule);
    let ro = null;
    if (sc !== window && typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(schedule);
      ro.observe(sc);
    }
    return () => {
      if (raf) cancelAnimationFrame(raf);
      sc.removeEventListener('scroll', schedule);
      window.removeEventListener('resize', schedule);
      if (ro) ro.disconnect();
    };
  }, [virtual, hasSecrets, virt]);

  // Après chaque rendu utile : mesure des lignes rendues, fenêtre recalculée, focus en attente.
  // (Pas à chaque rendu d'App : une modale qui s'ouvre ne déclenche aucune mesure.)
  useLayoutEffect(() => {
    if (!virtual || !tbodyRef.current) return;
    const heights = heightsRef.current;
    const batch = [];
    const fresh = [];
    let changed = false;
    for (const tr of tbodyRef.current.rows) {
      const index = rowIndexOf(tr);
      const key = index >= 0 ? rowKeys[index] : undefined;
      if (key === undefined) continue;
      const h = tr.getBoundingClientRect().height;
      if (!(h > 0)) continue; // non mis en page (élément masqué, jsdom) : estimation conservée
      // Première ligne exclue de l'estimation : sans bordure haute (tr:first-child), 1 px plus basse
      if (index > 0) batch.push(h);
      const prev = heights.get(key);
      if (prev === undefined) fresh.push([key, h]);
      else if (Math.abs(prev - h) > 0.5) { heights.set(key, h); changed = true; }
    }
    if (estimateRef.current === null && batch.length) {
      estimateRef.current = averageHeight(batch);
      changed = true;
    }
    const estimate = estimateRef.current || DEFAULT_ROW_HEIGHT;
    for (const [key, h] of fresh) {
      heights.set(key, h);
      if (Math.abs(h - estimate) > 0.5) changed = true; // égale à l'estimation : positions inchangées
    }
    // Garde-fou : jamais de boucle de rendus si une hauteur oscillait
    if (changed && measureLoopRef.current < 4) {
      measureLoopRef.current += 1;
      setMeasureVersion(v => v + 1);
      return;
    }
    measureLoopRef.current = 0;
    virt.updateRange();
    const pending = pendingFocusRef.current;
    if (pending !== null) {
      const index = keyIndex.get(pending);
      const el = index === undefined ? null : virt.rowElement(index);
      if (index === undefined) pendingFocusRef.current = null;
      else if (el) {
        pendingFocusRef.current = null;
        virt.scrollRowIntoView(index);
        virt.focusElement(el);
      }
    }
  }, [virtual, hasSecrets, rowKeys, keyIndex, range.start, range.end, measureVersion, focusKey, dragKey, cols, showEngine, columnWidths, virt]);

  // Derniers callbacks reçus (souvent recréés à chaque rendu d'App) : les lignes mémoïsées
  // reçoivent des relais STABLES qui appellent toujours la version la plus récente.
  const latestRef = useRef(null);
  latestRef.current = {
    toggleSecretSelection, setVisiblePasswords, setCurrentPath, setNotesPopup,
    handleCellRightClick, handleFolderRightClick, handleTagCellRightClick,
    handleDragStart, handleDragEnd, handleDragOver, handleDragLeave, handleDropOnFolder,
    isSecretRbiOnly, startClipboardTimer, getTagColor, getTotpKeyName, getTotpCode, showToast,
    navigateRow: virt.navigateRow,
  };
  const actions = useMemo(() => {
    const relays = {};
    for (const name of ACTION_NAMES) relays[name] = (...args) => latestRef.current[name]?.(...args);
    return relays;
  }, []);

  if (loadingSecrets) {
    return <LoadingSpinner />;
  }

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

  const folderColSpan = COLUMN_KEYS.filter(key => cols[key]).length + (showEngine ? 1 : 0);
  const multiSelection = (selectedSecrets?.size || 0) > 1;
  displayedSecretsRef.current = filteredSecrets;

  const renderRow = (s, idx) => {
    const key = rowKeys[idx];
    const ariaRowIndex = virtual ? idx + 2 : undefined;
    if (s.isFolder) {
      return (
        <FolderRow
          key={key}
          s={s}
          colSpan={folderColSpan}
          isDropTarget={!!isDragging && dragOverTarget === `folder:${s.name}`}
          ariaRowIndex={ariaRowIndex}
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
        ariaRowIndex={ariaRowIndex}
        actions={actions}
        t={t}
      />
    );
  };

  // Ligne « espaceur » : tient la place des lignes non rendues (hauteur totale et barre de
  // défilement conservées). Masquée aux technologies d'assistance (aria-rowcount donne le total).
  const spacer = (key, height) => (
    <tr key={key} className="virtual-spacer" aria-hidden="true">
      <td colSpan={folderColSpan} style={{ height: `${height}px` }} />
    </tr>
  );

  let rows;
  if (!virtual) {
    rows = list.map((s, idx) => renderRow(s, idx));
  } else {
    const n = list.length;
    const pinned = [focusKey, dragKey].map(k => (k === null ? -1 : (keyIndex.get(k) ?? -1)));
    rows = [];
    let cursor = 0;
    for (const idx of renderedIndices(range.start, range.end, pinned, n)) {
      if (idx > cursor) rows.push(spacer(cursor === 0 ? 'spacer-top' : `spacer-${cursor}`, offsets[idx] - offsets[cursor]));
      rows.push(renderRow(list[idx], idx));
      cursor = idx + 1;
    }
    if (cursor < n) rows.push(spacer('spacer-bottom', offsets[n] - offsets[cursor]));
  }

  // Ligne focalisée / glissée épinglée (rendue même hors de la zone visible) : voir en-tête du fichier
  const pinFromEvent = (setter) => (e) => {
    const index = rowIndexOf(e.target && e.target.closest ? e.target.closest('tr[aria-rowindex]') : null);
    if (index >= 0 && rowKeys[index] !== undefined) setter(rowKeys[index]);
  };

  return (
    <table
      ref={tableRef}
      className="secrets-table"
      aria-rowcount={virtual ? list.length + 1 : undefined}
      onContextMenu={handleEmptyAreaRightClick}
      onDoubleClick={() => {
        setTimeout(() => window.getSelection().removeAllRanges(), 0);
      }}
    >
      <thead>
        <tr
          aria-rowindex={virtual ? 1 : undefined}
          onContextMenu={isCurrentEngineRbiOnly ? undefined : handleColumnHeaderRightClick}
        >
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
      <tbody
        ref={tbodyRef}
        onFocus={virtual ? pinFromEvent(setFocusKey) : undefined}
        onKeyDown={virtual ? virt.handleTab : undefined}
        onDragStart={virtual ? pinFromEvent(setDragKey) : undefined}
        onDragEnd={virtual ? () => setDragKey(null) : undefined}
      >
        {rows}
      </tbody>
    </table>
  );
}
