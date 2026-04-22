import React from 'react';

/**
 * Barre d'outils principale : recherche, boutons d'action, toggles.
 */
export default function Toolbar({
  selectedEngine,
  isCurrentEngineRbiOnly,
  treeViewEnabled,
  currentPath,
  setEditSecret,
  searchRef,
  searchInput,
  setSearchInput,
  debouncedSearch,
  multiVaultSearch,
  setMultiVaultSearch,
  search,
  setVisiblePasswords,
  loadingAllSecrets,
  showDeleted,
  setShowDeleted,
  appMode,
  setReceiveShareOpen,
  setTreeViewEnabled,
  setCurrentPath,
  t
}) {
  return (
    <div className="toolbar">
      {selectedEngine && !isCurrentEngineRbiOnly && (
        <button
          onClick={() => {
            // Si on est en mode arborescence et dans un dossier, pre-remplir le chemin
            const initialName = treeViewEnabled && currentPath ? `${currentPath}/` : '';
            setEditSecret({ name: initialName, username: '', password: '', url: '', notes: '' });
          }}
          className="btn btn-primary"
          title={selectedEngine?.canWrite === false ? t('error.noReadAccess') : t('toolbar.newEntry')}
          type="button"
          disabled={selectedEngine?.canWrite === false}
          style={{
            cursor: selectedEngine?.canWrite === false ? 'not-allowed' : 'pointer',
            opacity: selectedEngine?.canWrite === false ? 0.5 : 1,
            flexShrink: 0
          }}
        >
          + {t('toolbar.newEntry')}
        </button>
      )}

      <input
        ref={searchRef}
        value={searchInput}
        onChange={(e) => { setSearchInput(e.target.value); debouncedSearch(e.target.value); }}
        placeholder={multiVaultSearch ? t('toolbar.searchAll') : t('toolbar.search')}
        className="search-input"
        style={{
          flex: 1,
          marginBottom: 0,
          minWidth: '200px'
        }}
      />
      {loadingAllSecrets && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', flexShrink: 0 }}>
          {t('common.loading')}
        </span>
      )}
      <label className="checkbox-label" style={{ marginBottom: 0, whiteSpace: 'nowrap', flexShrink: 0, opacity: !search.trim() ? 0.5 : 1 }}>
        <input
          type="checkbox"
          checked={multiVaultSearch}
          disabled={loadingAllSecrets || !search.trim()}
          onChange={(e) => { setMultiVaultSearch(e.target.checked); setVisiblePasswords({}); }}
        />
        <span>{t('toolbar.searchAll').split('...')[0]}</span>
      </label>
      {selectedEngine && selectedEngine.version === 2 && (
        <label className="checkbox-label" style={{ marginBottom: 0, flexShrink: 0 }}>
          <input
            type="checkbox"
            checked={showDeleted}
            onChange={(e) => setShowDeleted(e.target.checked)}
          />
          <span>{t('toolbar.showDeleted')}</span>
        </label>
      )}
      {appMode !== 'local' && (
      <button
        onClick={() => setReceiveShareOpen(true)}
        className="btn btn-secondary"
        type="button"
        title={t('toolbar.receiveShare')}
        style={{ flexShrink: 0, whiteSpace: 'nowrap' }}
      >
        {t('toolbar.receiveShare')}
      </button>
      )}
      {selectedEngine && (
        <>
          {!multiVaultSearch && (
            <button
              onClick={() => {
                const newValue = !treeViewEnabled;
                setTreeViewEnabled(newValue);
                localStorage.setItem('rdvault-tree-view-enabled', JSON.stringify(newValue));
                if (!newValue) setCurrentPath('');
              }}
              style={{
                padding: 'var(--sp-2) var(--sp-4)',
                background: treeViewEnabled ? 'var(--accent)' : 'var(--bg-surface)',
                color: treeViewEnabled ? 'white' : 'var(--text-primary)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
                cursor: 'pointer',
                fontSize: 'var(--text-sm)',
                fontWeight: 'var(--weight-medium)',
                transition: 'all 0.2s ease',
                flexShrink: 0
              }}
            >
              {treeViewEnabled ? `\uD83D\uDCC4 ${t('toolbar.listView')}` : `\uD83D\uDCC2 ${t('toolbar.treeView')}`}
            </button>
          )}
        </>
      )}
    </div>
  );
}
