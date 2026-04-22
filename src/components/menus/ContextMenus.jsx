// ========================================
// COMPOSANT: ContextMenus — Column, Tag, Folder, Engine context menus
// ========================================
import React from 'react';

export default function ContextMenus({
  // Folder context menu
  folderContextMenu, handleDeleteFolder,
  // Column context menu
  columnContextMenu,
  visibleColumns, setVisibleColumns,
  // Tag context menu
  tagContextMenu, setTagContextMenu,
  tagContextMenuRef,
  tagCreateMode, setTagCreateMode,
  tagCreateValue, setTagCreateValue,
  handleAddTagToSecret, handleRemoveTagFromSecret, getTagColor,
  // Engine context menu
  engineContextMenu, setEngineContextMenu,
  setEngineToDelete,
  t,
}) {
  return (
    <>
      {/* Context Menu Dossier */}
      {folderContextMenu && (
        <div
          className="context-menu"
          style={{ top: folderContextMenu.y, left: folderContextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => handleDeleteFolder(folderContextMenu.folderPath)}
            className="context-menu-item"
            style={{ color: 'var(--error)' }}
            type="button"
          >
            {'\uD83D\uDDD1\uFE0F'} {t('contextMenu.deleteFolder')}
          </button>
        </div>
      )}

      {/* Column Context Menu */}
      {columnContextMenu && (
        <ColumnContextMenuContent
          columnContextMenu={columnContextMenu}
          visibleColumns={visibleColumns}
          setVisibleColumns={setVisibleColumns}
          t={t}
        />
      )}

      {/* Tag Context Menu */}
      {tagContextMenu && (
        <TagContextMenuContent
          tagContextMenu={tagContextMenu}
          setTagContextMenu={setTagContextMenu}
          tagContextMenuRef={tagContextMenuRef}
          tagCreateMode={tagCreateMode}
          setTagCreateMode={setTagCreateMode}
          tagCreateValue={tagCreateValue}
          setTagCreateValue={setTagCreateValue}
          handleAddTagToSecret={handleAddTagToSecret}
          handleRemoveTagFromSecret={handleRemoveTagFromSecret}
          getTagColor={getTagColor}
          t={t}
        />
      )}

      {/* Menu contextuel pour les coffres */}
      {engineContextMenu && (
        <div
          className="context-menu"
          style={{ top: engineContextMenu.y, left: engineContextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => {
              setEngineToDelete(engineContextMenu.engine);
              setEngineContextMenu(null);
            }}
            className="context-menu-item danger"
            type="button"
          >
            {'\uD83D\uDDD1\uFE0F'} {t('confirm.deleteEngine')}
          </button>
        </div>
      )}
    </>
  );
}

function ColumnContextMenuContent({ columnContextMenu, visibleColumns, setVisibleColumns, t }) {
  const columnKeys = ['name', 'username', 'password', 'url', 'notes', 'tags', 'customFields'];
  const columnLabels = {
    name: 'table.name',
    username: 'table.username',
    password: 'table.password',
    url: 'table.url',
    notes: 'table.notes',
    tags: 'table.tags',
    customFields: 'table.customFields',
  };

  return (
    <div
      className="context-menu"
      style={{ top: columnContextMenu.y, left: columnContextMenu.x }}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="context-menu-label">{t('settings.columnsTitle')}</div>
      {columnKeys.map((key) => (
        <label key={key} className="context-menu-item" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}>
          <input
            type="checkbox"
            checked={visibleColumns[key]}
            onChange={(e) => {
              const newVisibleColumns = { ...visibleColumns, [key]: e.target.checked };
              setVisibleColumns(newVisibleColumns);
              localStorage.setItem('rdvault-visible-columns', JSON.stringify(newVisibleColumns));
            }}
          />
          <span>{t(columnLabels[key])}</span>
        </label>
      ))}
    </div>
  );
}

function TagContextMenuContent({
  tagContextMenu, setTagContextMenu, tagContextMenuRef,
  tagCreateMode, setTagCreateMode, tagCreateValue, setTagCreateValue,
  handleAddTagToSecret, handleRemoveTagFromSecret, getTagColor, t,
}) {
  const handleCreateTag = (tagName) => {
    if (tagName && tagName.length <= 64 && !/[\x00-\x1F\x7F]/.test(tagName)) {
      handleAddTagToSecret(tagContextMenu.secret, tagName);
      setTagCreateMode(false);
      setTagCreateValue('#');
      setTagContextMenu(null);
    }
  };

  return (
    <div
      ref={tagContextMenuRef}
      className="context-menu tag-context-menu"
      style={{
        top: tagContextMenu.y,
        left: tagContextMenu.x,
        maxHeight: '400px',
        overflowY: 'auto'
      }}
      onClick={(e) => e.stopPropagation()}
    >
      {!tagCreateMode ? (
        <button
          onClick={(e) => {
            e.stopPropagation();
            setTagCreateMode(true);
            setTagCreateValue('#');
          }}
          className="context-menu-item"
          type="button"
          style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}
        >
          <span style={{ fontSize: '16px' }}>+</span>
          <span>{t('contextMenu.createTag')}</span>
        </button>
      ) : (
        <div style={{ padding: 'var(--sp-2) var(--sp-3)', display: 'flex', gap: 'var(--sp-2)', alignItems: 'center' }}>
          <input
            type="text"
            value={tagCreateValue}
            autoFocus
            onChange={(e) => {
              let val = e.target.value;
              if (!val.startsWith('#')) val = '#' + val.replace(/^#+/, '');
              setTagCreateValue(val);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleCreateTag(tagCreateValue.trim());
              } else if (e.key === 'Escape') {
                setTagCreateMode(false);
                setTagCreateValue('#');
              }
            }}
            onClick={(e) => e.stopPropagation()}
            placeholder="#nouveau-tag"
            style={{
              flex: 1,
              padding: 'var(--sp-2)',
              fontSize: 'var(--text-sm)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--bg-primary)',
              color: 'var(--text-primary)',
              outline: 'none',
              minWidth: 0
            }}
          />
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleCreateTag(tagCreateValue.trim());
            }}
            className="btn btn-primary"
            type="button"
            style={{ padding: 'var(--sp-2) var(--sp-3)', fontSize: 'var(--text-sm)', whiteSpace: 'nowrap' }}
          >
            OK
          </button>
        </div>
      )}
      <div className="context-menu-separator" />
      <div className="context-menu-label">
        {t('table.tags')} ({tagContextMenu.availableTags.length})
      </div>
      {tagContextMenu.availableTags.length === 0 ? (
        <div style={{
          padding: 'var(--sp-3)',
          fontSize: 'var(--text-sm)',
          color: 'var(--text-tertiary)',
          fontStyle: 'italic',
          textAlign: 'center'
        }}>
          {t('common.noData')}
        </div>
      ) : (
        tagContextMenu.availableTags.map((tag) => (
          <button
            key={tag}
            onClick={() => {
              handleAddTagToSecret(tagContextMenu.secret, tag);
              setTagContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
            style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}
          >
            <span className="tag-badge" style={{ background: getTagColor(tag), fontSize: '11px', padding: '2px 6px' }}>
              {tag}
            </span>
            <span style={{ flex: 1 }}>{t('contextMenu.addTag')} "{tag}"</span>
          </button>
        ))
      )}
      {tagContextMenu.currentTags.length > 0 && (
        <>
          <div className="context-menu-separator" />
          <div className="context-menu-label">
            {t('table.tags')} ({tagContextMenu.currentTags.length}) - {t('contextMenu.removeTag')}
          </div>
          {tagContextMenu.currentTags.map((tag) => (
            <button
              key={tag}
              onClick={() => {
                handleRemoveTagFromSecret(tagContextMenu.secret, tag);
                setTagContextMenu(null);
              }}
              className="context-menu-item"
              type="button"
              style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)' }}
            >
              <span className="tag-badge" style={{ background: getTagColor(tag), fontSize: '11px', padding: '2px 6px' }}>
                {tag}
              </span>
              <span style={{ flex: 1 }}>{t('contextMenu.removeTag')} "{tag}"</span>
              <span style={{ fontSize: '16px', opacity: 0.6 }}>{'\u2715'}</span>
            </button>
          ))}
        </>
      )}
      <div
        className="tag-menu-scroll-indicator"
        onClick={(e) => {
          e.stopPropagation();
          const menu = tagContextMenuRef.current;
          if (menu) {
            const itemHeight = menu.querySelector('.context-menu-item')?.offsetHeight || 36;
            menu.scrollBy({ top: itemHeight * 7, behavior: 'smooth' });
          }
        }}
        style={{ cursor: 'pointer' }}
      >{'\u25BE'}</div>
    </div>
  );
}
