// src/MoveToFolderModal.jsx
import React, { useState, useEffect } from 'react';
import { useTranslation } from './i18n';

/**
 * Modal pour déplacer un ou plusieurs secrets vers un dossier du coffre actuel.
 * Affiche l'arborescence des dossiers et permet la navigation.
 */
export default function MoveToFolderModal({ secretsToMove, secrets, onClose, onConfirm }) {
  const { t } = useTranslation();
  const [browsingPath, setBrowsingPath] = useState('');
  const [mouseDownPos, setMouseDownPos] = useState(null);

  // Normaliser en tableau
  const secretsList = Array.isArray(secretsToMove) ? secretsToMove : [secretsToMove];
  const count = secretsList.length;

  // Pour l'affichage, utiliser le premier secret comme référence
  const firstSecret = secretsList[0];
  const secretParts = firstSecret.name.split('/');
  const secretBaseName = secretParts.pop();
  const currentSecretFolder = secretParts.join('/');

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  // Construire l'arbre des dossiers à partir des secrets
  const buildTree = (secretsList) => {
    const tree = { folders: {}, secrets: [] };
    secretsList.forEach(s => {
      const parts = s.name.split('/');
      if (parts.length === 1) {
        if (s.name !== '.placeholder') {
          tree.secrets.push(s);
        }
      } else {
        let current = tree;
        for (let i = 0; i < parts.length - 1; i++) {
          const folderName = parts[i];
          if (!current.folders[folderName]) {
            current.folders[folderName] = { folders: {}, secrets: [] };
          }
          current = current.folders[folderName];
        }
        const leafName = parts[parts.length - 1];
        if (leafName !== '.placeholder') {
          current.secrets.push({ ...s, displayName: leafName });
        }
      }
    });
    return tree;
  };

  // Obtenir les sous-dossiers du chemin courant
  const getSubfolders = () => {
    const tree = buildTree(secrets);
    if (!browsingPath) {
      return Object.keys(tree.folders).sort();
    }
    const pathParts = browsingPath.split('/');
    let current = tree;
    for (const part of pathParts) {
      if (current.folders[part]) {
        current = current.folders[part];
      } else {
        return [];
      }
    }
    return Object.keys(current.folders).sort();
  };

  const subfolders = getSubfolders();
  const breadcrumbParts = browsingPath ? browsingPath.split('/') : [];

  // Chemin de destination complet
  const destinationPath = browsingPath ? `${browsingPath}/${secretBaseName}` : secretBaseName;
  const isSameFolder = browsingPath === currentSecretFolder;

  const handleOverlayMouseDown = (e) => {
    if (e.target.className === 'modal-overlay') {
      setMouseDownPos({ x: e.clientX, y: e.clientY });
    }
  };

  const handleOverlayMouseUp = (e) => {
    if (e.target.className === 'modal-overlay' && mouseDownPos) {
      const deltaX = Math.abs(e.clientX - mouseDownPos.x);
      const deltaY = Math.abs(e.clientY - mouseDownPos.y);
      if (deltaX < 5 && deltaY < 5) {
        onClose();
      }
    }
    setMouseDownPos(null);
  };

  return (
    <div
      className="modal-overlay"
      onMouseDown={handleOverlayMouseDown}
      onMouseUp={handleOverlayMouseUp}
    >
      <div
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '500px' }}
      >
        <div className="modal-header">
          <h2>{count === 1 ? t('migrate.moveTitle', { name: secretBaseName }) : t('migrate.moveTitlePlural', { count })}</h2>
        </div>

        <div className="modal-body">
          {/* Breadcrumb */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--sp-1)',
            flexWrap: 'wrap',
            marginBottom: 'var(--sp-3)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)'
          }}>
            <span style={{ marginRight: 'var(--sp-1)' }}>📍</span>
            <button
              onClick={() => setBrowsingPath('')}
              className="btn-link"
              type="button"
              style={{
                background: 'none',
                border: 'none',
                padding: '2px 4px',
                cursor: 'pointer',
                color: browsingPath ? 'var(--accent)' : 'var(--text-primary)',
                fontWeight: browsingPath ? 'normal' : 'bold',
                textDecoration: browsingPath ? 'underline' : 'none',
                borderRadius: 'var(--radius-sm)',
                fontSize: 'var(--text-sm)'
              }}
            >
              {t('migrate.root')}
            </button>
            {breadcrumbParts.map((part, idx) => {
              const pathUpTo = breadcrumbParts.slice(0, idx + 1).join('/');
              const isLast = idx === breadcrumbParts.length - 1;
              return (
                <React.Fragment key={pathUpTo}>
                  <span style={{ color: 'var(--text-tertiary)' }}>/</span>
                  <button
                    onClick={() => setBrowsingPath(pathUpTo)}
                    className="btn-link"
                    type="button"
                    style={{
                      background: 'none',
                      border: 'none',
                      padding: '2px 4px',
                      cursor: isLast ? 'default' : 'pointer',
                      color: isLast ? 'var(--text-primary)' : 'var(--accent)',
                      fontWeight: isLast ? 'bold' : 'normal',
                      textDecoration: isLast ? 'none' : 'underline',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: 'var(--text-sm)'
                    }}
                  >
                    {part}
                  </button>
                </React.Fragment>
              );
            })}
          </div>

          {/* Liste des sous-dossiers */}
          <div style={{
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius)',
            maxHeight: '250px',
            overflowY: 'auto',
            background: 'var(--bg-surface)'
          }}>
            {subfolders.length === 0 ? (
              <div style={{
                padding: 'var(--sp-4)',
                textAlign: 'center',
                color: 'var(--text-tertiary)',
                fontSize: 'var(--text-sm)'
              }}>
                Aucun sous-dossier
              </div>
            ) : (
              subfolders.map(folder => {
                const fullFolderPath = browsingPath ? `${browsingPath}/${folder}` : folder;
                const isCurrentFolder = fullFolderPath === currentSecretFolder;
                return (
                  <button
                    key={folder}
                    onClick={() => setBrowsingPath(fullFolderPath)}
                    type="button"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--sp-2)',
                      width: '100%',
                      padding: 'var(--sp-2) var(--sp-3)',
                      background: 'none',
                      border: 'none',
                      borderBottom: '1px solid var(--border)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      fontSize: 'var(--text-sm)',
                      color: isCurrentFolder ? 'var(--text-tertiary)' : 'var(--text-primary)',
                      fontStyle: isCurrentFolder ? 'italic' : 'normal'
                    }}
                    onMouseEnter={(e) => {
                      if (!isCurrentFolder) e.currentTarget.style.background = 'var(--bg-surface-hover)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'none';
                    }}
                  >
                    <span>📁</span>
                    <span style={{ flex: 1 }}>{folder}</span>
                    {isCurrentFolder && (
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                        (dossier actuel)
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>

          {/* Aperçu de la destination */}
          <div style={{
            marginTop: 'var(--sp-3)',
            padding: 'var(--sp-2) var(--sp-3)',
            background: 'var(--bg-surface)',
            borderRadius: 'var(--radius)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)'
          }}>
            {count === 1 ? (
              <>
                Destination : <code style={{
                  background: 'var(--bg-surface-active)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 'var(--text-xs)'
                }}>{destinationPath}</code>
              </>
            ) : (
              <>
                Déplacer <strong>{count} entrées</strong> vers : <code style={{
                  background: 'var(--bg-surface-active)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 'var(--text-xs)'
                }}>{browsingPath || t('migrate.root')}/</code>
              </>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('migrate.cancel')}
          </button>
          <button
            onClick={() => onConfirm(browsingPath)}
            className="btn btn-primary"
            type="button"
            disabled={isSameFolder}
            title={isSameFolder ? 'L\'entrée est déjà dans ce dossier' : ''}
          >
            {t('migrate.move')}
          </button>
        </div>
      </div>
    </div>
  );
}
