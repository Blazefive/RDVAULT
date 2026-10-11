// src/MoveToFolderModal.jsx
import React, { useState, useMemo } from 'react';
import { useTranslation } from './i18n';
import Modal from './components/common/Modal';
import { buildTree } from './hooks/useTreeView';

/**
 * Modal pour déplacer un ou plusieurs secrets vers un dossier du coffre actuel.
 * Affiche l'arborescence des dossiers et permet la navigation.
 * (squelette commun Modal : Escape, clic hors zone avec tolérance de déplacement ;
 *  arbre construit par buildTree de useTreeView, plus de doublon local)
 */
export default function MoveToFolderModal({ secretsToMove, secrets, onClose, onConfirm }) {
  const { t } = useTranslation();
  const [browsingPath, setBrowsingPath] = useState('');

  // Normaliser en tableau
  const secretsList = Array.isArray(secretsToMove) ? secretsToMove : [secretsToMove];
  const count = secretsList.length;

  // Pour l'affichage, utiliser le premier secret comme référence
  const firstSecret = secretsList[0];
  const secretParts = firstSecret.name.split('/');
  const secretBaseName = secretParts.pop();
  const currentSecretFolder = secretParts.join('/');

  // Arbre des dossiers (recalculé uniquement quand la liste des secrets change)
  const tree = useMemo(() => buildTree(secrets || []), [secrets]);

  // Obtenir les sous-dossiers du chemin courant
  const getSubfolders = () => {
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

  return (
    <Modal
      title={count === 1 ? t('migrate.moveTitle', { name: secretBaseName }) : t('migrate.moveTitlePlural', { count })}
      onClose={onClose}
      maxWidth="500px"
      footer={(
        <>
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('migrate.cancel')}
          </button>
          <button
            onClick={() => onConfirm(browsingPath)}
            className="btn btn-primary"
            type="button"
            disabled={isSameFolder}
            title={isSameFolder ? t('migrate.alreadyInFolder') : ''}
          >
            {t('migrate.move')}
          </button>
        </>
      )}
    >
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
            <span style={{ marginRight: 'var(--sp-1)' }} aria-hidden="true">📍</span>
            <button
              onClick={() => setBrowsingPath('')}
              className="btn-link"
              type="button"
              aria-current={browsingPath ? undefined : 'location'}
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
                    aria-current={isLast ? 'location' : undefined}
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
                {t('migrate.noSubfolders')}
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
                    <span aria-hidden="true">📁</span>
                    <span style={{ flex: 1 }}>{folder}</span>
                    {isCurrentFolder && (
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                        {t('migrate.currentFolder')}
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
                {t('migrate.destination')} <code style={{
                  background: 'var(--bg-surface-active)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 'var(--text-xs)'
                }}>{destinationPath}</code>
              </>
            ) : (
              <>
                {t('migrate.moveCountTo', { count })} <code style={{
                  background: 'var(--bg-surface-active)',
                  padding: '2px 6px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: 'var(--text-xs)'
                }}>{browsingPath || t('migrate.root')}/</code>
              </>
            )}
          </div>
    </Modal>
  );
}
