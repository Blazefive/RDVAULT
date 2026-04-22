import React from 'react';

/**
 * Sidebar — liste des engines avec support drag & drop
 */
export default function Sidebar({
  secretEngines,
  selectedEngine,
  onSelectEngine,
  isDragging,
  dragOverTarget,
  onDragOver,
  onDragLeave,
  onDropOnEngine,
  isAdmin,
  sidebarOpen,
  onEngineRightClick,
  onCreateEngine,
  t
}) {
  return (
    <div className={`sidebar ${sidebarOpen ? "open" : ""}`}>
      <div className="sidebar-header">
        <h2>{t('toolbar.vaultView')}</h2>
        <button
          onClick={onCreateEngine}
          className="btn btn-success btn-sm"
          title={t('toolbar.newEngine')}
          type="button"
          style={{ flexShrink: 0, whiteSpace: 'nowrap' }}
        >
          + {t('toolbar.newEngine')}
        </button>
      </div>

      <div className="sidebar-content">
        {secretEngines.map(engine => {
          const active = selectedEngine?.name === engine.name && selectedEngine?.version === engine.version;
          const currentUser = localStorage.getItem('vault-client.username') || '';
          const userPrefix = currentUser ? `users/${currentUser}/` : '';
          const canDelete = !userPrefix || engine.name.startsWith(userPrefix) || engine.name.startsWith(`users/${currentUser}`);

          // Extraire uniquement le nom du coffre pour les coffres personnels
          const isPersonalVault = engine.name.startsWith(userPrefix);
          const displayName = isPersonalVault
            ? engine.name.substring(userPrefix.length)
            : engine.name;

          // Déterminer si ce engine est la cible de drop actuelle
          const isDropTarget = isDragging && dragOverTarget === engine.name;
          // Permettre le drop sur tous les engines avec droits d'écriture
          const canReceiveDrop = engine.canWrite;

          return (
            <div
              key={`${engine.name}-${engine.version}-${engine.source || 'auto'}`}
              className={`engine-card ${active ? 'active' : ''} ${isDropTarget ? 'drop-target' : ''}`}
              onClick={() => onSelectEngine(engine)}
              onContextMenu={(e) => onEngineRightClick(e, engine)}
              // Gestionnaires Drag & Drop
              onDragOver={(e) => canReceiveDrop && onDragOver(e, engine.name)}
              onDragEnter={(e) => canReceiveDrop && onDragOver(e, engine.name)}
              onDragLeave={onDragLeave}
              onDrop={(e) => canReceiveDrop && onDropOnEngine(e, engine)}
              style={{
                outline: isDropTarget ? '2px dashed var(--accent, #3b82f6)' : undefined,
                background: isDropTarget ? 'var(--bg-selection, rgba(59, 130, 246, 0.15))' : undefined,
                transform: isDropTarget ? 'scale(1.02)' : undefined,
                transition: 'all 0.15s ease'
              }}
            >
              <span className="engine-name">{displayName}</span>
              <div className="engine-card-actions">
                {isAdmin && <span className="badge badge-version">kv{engine.version}</span>}
                {isAdmin && engine.source && <span className="badge badge-source">{engine.source}</span>}
                {!canDelete && isAdmin && (
                  <span className="badge badge-shared">
                    Partagé
                  </span>
                )}
                {/* Indicateur de drop zone pendant le drag */}
                {isDragging && canReceiveDrop && (
                  <span
                    className="badge"
                    style={{ background: 'var(--accent)', color: 'white' }}
                  >
                    {active ? '\u{1F3E0}' : '\u2B07\uFE0F'}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
