// ========================================
// COMPOSANT: SecretsTable — Tableau des secrets
// ========================================
import React from 'react';
import LoadingSpinner from '../../LoadingSpinner.jsx';
import { handleUrlAction } from '../../utils/urlHandler';

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
  if (loadingSecrets) {
    return <LoadingSpinner />;
  }

  const hasSecrets = (multiVaultSearch && search.trim() ? allVaultSecrets : secrets).length > 0;

  if (!hasSecrets) {
    if (token && (selectedEngine || (multiVaultSearch && search.trim()))) {
      return (
        <div className="empty-state" onContextMenu={handleEmptyAreaRightClick}>
          {multiVaultSearch && search.trim() ? 'Aucun résultat dans tous les coffres.' : 'Aucun secret à afficher.'}
        </div>
      );
    }
    return null;
  }

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
          {effectiveVisibleColumns.name && (
            <th className="resizable-header" style={{ width: columnWidths.name || 'auto' }}>
              {t('table.name')}
              <div
                className={`column-resizer ${resizingColumn === 'name' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'name', columnWidths.name)}
                onDoubleClick={(e) => autoFitColumn(e, 'name')}
              />
            </th>
          )}
          {multiVaultSearch && search.trim() && (
            <th className="resizable-header" style={{ width: columnWidths.engine || 'auto' }}>
              {t('toolbar.vaultView')}
              <div
                className={`column-resizer ${resizingColumn === 'engine' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'engine', columnWidths.engine)}
              />
            </th>
          )}
          {effectiveVisibleColumns.username && (
            <th className="resizable-header" style={{ width: columnWidths.username || 'auto' }}>
              {t('table.username')}
              <div
                className={`column-resizer ${resizingColumn === 'username' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'username', columnWidths.username)}
                onDoubleClick={(e) => autoFitColumn(e, 'username')}
              />
            </th>
          )}
          {effectiveVisibleColumns.password && (
            <th className="resizable-header" style={{ width: columnWidths.password || 'auto' }}>
              {t('table.password')}
              <div
                className={`column-resizer ${resizingColumn === 'password' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'password', columnWidths.password)}
                onDoubleClick={(e) => autoFitColumn(e, 'password')}
              />
            </th>
          )}
          {effectiveVisibleColumns.url && (
            <th className="resizable-header" style={{ width: columnWidths.url || 'auto' }}>
              {t('table.url')}
              <div
                className={`column-resizer ${resizingColumn === 'url' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'url', columnWidths.url)}
                onDoubleClick={(e) => autoFitColumn(e, 'url')}
              />
            </th>
          )}
          {effectiveVisibleColumns.notes && (
            <th className="resizable-header" style={{ width: columnWidths.notes || 'auto' }}>
              {t('table.notes')}
              <div
                className={`column-resizer ${resizingColumn === 'notes' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'notes', columnWidths.notes)}
                onDoubleClick={(e) => autoFitColumn(e, 'notes')}
              />
            </th>
          )}
          {effectiveVisibleColumns.tags && (
            <th className="resizable-header" style={{ width: columnWidths.tags || 'auto' }}>
              {t('table.tags')}
              <div
                className={`column-resizer ${resizingColumn === 'tags' ? 'resizing' : ''}`}
                onMouseDown={(e) => handleColumnResizeStart(e, 'tags', columnWidths.tags)}
                onDoubleClick={(e) => autoFitColumn(e, 'tags')}
              />
            </th>
          )}
          {effectiveVisibleColumns.customFields && (
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
        {(() => { displayedSecretsRef.current = filteredSecrets; return filteredSecrets; })()
          .map((s, idx) => {
            if (s.isFolder) {
              const displayedColumnsCount = [
                effectiveVisibleColumns.name,
                effectiveVisibleColumns.username,
                effectiveVisibleColumns.password,
                effectiveVisibleColumns.url,
                effectiveVisibleColumns.notes,
                effectiveVisibleColumns.tags,
                effectiveVisibleColumns.customFields
              ].filter(Boolean).length + (multiVaultSearch && search.trim() ? 1 : 0);

              const isFolderDropTarget = isDragging && dragOverTarget === `folder:${s.name}`;

              return (
                <tr
                  key={`folder-${s.name}-${idx}`}
                  onClick={() => setCurrentPath(s.name)}
                  onContextMenu={(e) => handleFolderRightClick(e, s.name)}
                  onDragOver={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    handleDragOver(e, `folder:${s.name}`);
                  }}
                  onDragEnter={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    handleDragOver(e, `folder:${s.name}`);
                  }}
                  onDragLeave={(e) => {
                    e.stopPropagation();
                    handleDragLeave();
                  }}
                  onDrop={(e) => handleDropOnFolder(e, s.name)}
                  style={{
                    cursor: 'pointer',
                    background: isFolderDropTarget
                      ? 'var(--bg-selection, rgba(59, 130, 246, 0.25))'
                      : 'var(--bg-surface-hover)',
                    outline: isFolderDropTarget ? '2px dashed var(--accent, #3b82f6)' : undefined,
                    transition: 'all 0.15s ease'
                  }}
                >
                  <td
                    colSpan={displayedColumnsCount}
                    style={{
                      padding: 'var(--sp-3)',
                      fontWeight: 'var(--weight-semibold)',
                      color: 'var(--accent)'
                    }}
                  >
                    {'\uD83D\uDCC1'} {s.displayName}
                    {isFolderDropTarget && (
                      <span style={{ marginLeft: 'var(--sp-2)', fontSize: 'var(--text-sm)' }}>
                        {'\u2B07\uFE0F'} Déposer ici
                      </span>
                    )}
                  </td>
                </tr>
              );
            }

            const isSelected = isSecretSelected(s.name);
            return (
              <tr
                key={`${s.name}-${idx}`}
                draggable={!s.deleted}
                onClick={(e) => {
                  if (!s.deleted) {
                    toggleSecretSelection(s.name, e.ctrlKey || e.metaKey, e.shiftKey);
                  }
                }}
                onDragStart={(e) => !s.deleted && handleDragStart(e, s)}
                onDragEnd={handleDragEnd}
                className={isSelected ? 'row-selected' : ''}
                style={{
                  cursor: s.deleted ? 'default' : 'pointer',
                  background: isSelected ? 'var(--bg-selection, rgba(59, 130, 246, 0.15))' : undefined,
                  outline: isSelected ? '2px solid var(--accent, #3b82f6)' : undefined,
                  outlineOffset: '-2px'
                }}
              >
                {effectiveVisibleColumns.name && (
                  <td
                    className={`cell-name ${s.deleted ? 'cell-deleted' : ''}`}
                    onContextMenu={(e) => handleCellRightClick(e, s, 'name', s.name)}
                    style={{ width: columnWidths.name || 'auto' }}
                  >
                    {isSelected && selectedSecrets.size > 1 && (
                      <span style={{ marginRight: 'var(--sp-2)', color: 'var(--accent)' }}>{'\u2713'}</span>
                    )}
                    {s.entryType === 'ssh' && <span style={{ marginRight: 'var(--sp-1)' }}>{'\uD83D\uDD11'}</span>}
                    {s.displayName || s.name.split('/').pop() || s.name}
                    {s.deleted && <span className="deleted-badge">({t('versionHistory.deleted')})</span>}
                  </td>
                )}
                {multiVaultSearch && search.trim() && (
                  <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', width: columnWidths.engine || 'auto' }}>
                    {s.engineName || selectedEngine?.name}
                  </td>
                )}
                {effectiveVisibleColumns.username && (
                  <td
                    className={s.deleted ? 'cell-deleted' : ''}
                    onContextMenu={s.deleted || isSecretRbiOnly(s.name) ? undefined : (e) => handleCellRightClick(e, s, 'username', s.username)}
                    onDoubleClick={async (e) => {
                      if (!s.deleted && s.username && !isSecretRbiOnly(s.name)) {
                        e.stopPropagation();
                        await startClipboardTimer('Username', s.username);
                        window.getSelection().removeAllRanges();
                      }
                    }}
                    style={{ cursor: !s.deleted && s.username && !isSecretRbiOnly(s.name) ? 'pointer' : 'default', width: columnWidths.username || 'auto' }}
                  >
                    {isSecretRbiOnly(s.name) ? '\u2014' : s.username}
                  </td>
                )}
                {effectiveVisibleColumns.password && (
                  <td
                    className={s.deleted ? 'cell-deleted' : ''}
                    onContextMenu={s.deleted || isSecretRbiOnly(s.name) ? undefined : (e) => handleCellRightClick(e, s, 'password', s.password)}
                    onDoubleClick={async (e) => {
                      if (!s.deleted && s.password && !isSecretRbiOnly(s.name)) {
                        e.stopPropagation();
                        await startClipboardTimer('Password', s.password);
                        window.getSelection().removeAllRanges();
                      }
                    }}
                    style={{ cursor: !s.deleted && s.password && !isSecretRbiOnly(s.name) ? 'pointer' : 'default', width: columnWidths.password || 'auto' }}
                  >
                    {s.deleted || isSecretRbiOnly(s.name) ? '\u2014' : (
                      <>
                        <span style={{ marginRight: '8px' }}>{visiblePasswords[s.name] ? s.password : '\u2022\u2022\u2022\u2022\u2022\u2022'}</span>
                        <button
                          onClick={() => setVisiblePasswords(prev => ({ ...prev, [s.name]: !prev[s.name] }))}
                          className="btn-action btn-action-view"
                          type="button"
                        >
                          {visiblePasswords[s.name] ? (
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
                {effectiveVisibleColumns.url && (
                  <td
                    className={s.deleted ? 'cell-deleted' : ''}
                    onContextMenu={s.deleted ? undefined : (e) => handleCellRightClick(e, s, 'url', s.url)}
                    style={{ width: columnWidths.url || 'auto' }}
                  >
                    {s.url && !s.deleted ? (
                      <>
                        {(s.url.startsWith('\\\\') || s.url.startsWith('//') || /^[a-zA-Z]:\\/.test(s.url)) && (
                          <span style={{ marginRight: '6px', opacity: 0.7 }}>{'\uD83D\uDCC1'}</span>
                        )}
                        {(s.url.toLowerCase().startsWith('ssh://') || s.url.includes(':22')) && (
                          <span style={{ marginRight: '6px', opacity: 0.7 }}>{'\uD83D\uDD11'}</span>
                        )}
                        <span
                          className="url-link"
                          onClick={async (e) => {
                            e.stopPropagation();
                            await handleUrlAction(s.url, s, {
                              isSecretRbiOnly, getTotpKeyName, getTotpCode,
                              startClipboardTimer, showToast, t
                            });
                          }}
                        >
                          {s.url}
                        </span>
                      </>
                    ) : (
                      s.url
                    )}
                  </td>
                )}
                {effectiveVisibleColumns.notes && (
                  <td
                    className={s.deleted ? 'cell-deleted' : ''}
                    onContextMenu={s.deleted || isSecretRbiOnly(s.name) ? undefined : (e) => handleCellRightClick(e, s, 'notes', s.notes)}
                    onDoubleClick={isSecretRbiOnly(s.name) ? undefined : () => setNotesPopup({ notes: s.notes })}
                    style={{ cursor: isSecretRbiOnly(s.name) ? 'default' : 'pointer', width: columnWidths.notes || 'auto' }}
                  >
                    {isSecretRbiOnly(s.name) ? '\u2014' : s.notes}
                  </td>
                )}
                {effectiveVisibleColumns.tags && (
                  <td
                    style={{
                      width: columnWidths.tags || 'auto',
                      cursor: 'context-menu',
                      minHeight: '32px',
                      whiteSpace: 'normal',
                      overflow: 'visible'
                    }}
                    onContextMenu={(e) => handleTagCellRightClick(e, s)}
                  >
                    {(() => {
                      const tagList = s.tags ? s.tags.split(/[\s,;]+/).filter(t => t) : [];
                      const hasOverflow = tagList.length > 2;
                      return (
                        <div style={{ position: 'relative' }}>
                          <div className="tags-scroll-container">
                            {tagList.map((tag, tagIdx) => (
                              <span key={tagIdx} className="tag-badge" style={{ background: getTagColor(tag) }}>
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
                                Clic droit pour ajouter
                              </span>
                            )}
                          </div>
                          {hasOverflow && (
                            <div className="tags-overflow-indicator">{'\u25BE'}</div>
                          )}
                        </div>
                      );
                    })()}
                  </td>
                )}
                {effectiveVisibleColumns.customFields && (
                  <td style={{ width: columnWidths.customFields || 'auto', whiteSpace: 'normal', overflow: 'hidden', textOverflow: 'ellipsis' }}>
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
                            {cf.key}: {cf.protected ? '\u2022\u2022\u2022\u2022' : cf.value}
                          </span>
                        ))}
                      </div>
                    ) : null}
                  </td>
                )}
              </tr>
            );
          })}
      </tbody>
    </table>
  );
}
