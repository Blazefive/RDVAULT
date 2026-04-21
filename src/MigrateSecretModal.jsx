// src/MigrateSecretModal.jsx
import React, { useEffect, useState } from 'react';
import { useTranslation } from './i18n';

export default function MigrateSecretModal({
  secrets, // Tableau de secrets à migrer/copier
  engines,
  currentEngine,
  mode, // 'move' ou 'copy'
  onClose,
  onConfirm
}) {
  const { t } = useTranslation();
  const [selectedEngine, setSelectedEngine] = useState(null);
  const [processing, setProcessing] = useState(false);

  // Normaliser secrets en tableau
  const secretsList = Array.isArray(secrets) ? secrets : [secrets];
  const count = secretsList.length;

  // Filtrer les engines pour ne montrer que ceux avec accès RW
  const writableEngines = engines.filter(
    e => e.canWrite && e.name !== currentEngine?.name
  );

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  const handleConfirm = async () => {
    if (!selectedEngine || processing) return;
    setProcessing(true);
    try {
      await onConfirm(selectedEngine);
      onClose();
    } catch (err) {
      setProcessing(false);
    }
  };

  const title = mode === 'move' ? t('migrate.migrateTitle') : t('migrate.copyTitle');
  const actionLabel = mode === 'move' ? t('migrate.migrate') : t('migrate.copy');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '500px' }}
      >
        <div className="modal-header">
          <h2>{title}</h2>
        </div>

        <div className="modal-body">
          <div style={{ marginBottom: 'var(--sp-4)', color: 'var(--text-secondary)' }}>
            {count === 1 ? (
              mode === 'move' ? (
                <>
                  Déplacer l'entrée <strong>{secretsList[0].name}</strong> depuis <strong>{currentEngine?.name}</strong> vers :
                </>
              ) : (
                <>
                  Copier l'entrée <strong>{secretsList[0].name}</strong> depuis <strong>{currentEngine?.name}</strong> vers :
                </>
              )
            ) : (
              mode === 'move' ? (
                <>
                  Déplacer <strong>{count} entrées</strong> depuis <strong>{currentEngine?.name}</strong> vers :
                </>
              ) : (
                <>
                  Copier <strong>{count} entrées</strong> depuis <strong>{currentEngine?.name}</strong> vers :
                </>
              )
            )}
          </div>

          {writableEngines.length === 0 ? (
            <div style={{ padding: 'var(--sp-4)', background: 'var(--bg-app)', borderRadius: 'var(--radius-lg)', color: 'var(--text-tertiary)' }}>
              {t('migrate.noWritableEngines')}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)', maxHeight: '400px', overflowY: 'auto' }}>
              {writableEngines.map((engine) => (
                <button
                  key={engine.name}
                  onClick={() => setSelectedEngine(engine)}
                  className={`engine-select-btn ${selectedEngine?.name === engine.name ? 'selected' : ''}`}
                  type="button"
                  style={{
                    padding: 'var(--sp-3) var(--sp-4)',
                    border: selectedEngine?.name === engine.name ? '2px solid var(--accent)' : '2px solid var(--border)',
                    background: selectedEngine?.name === engine.name ? 'var(--bg-surface-active)' : 'var(--bg-surface)',
                    borderRadius: 'var(--radius-md)',
                    textAlign: 'left',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 'var(--weight-bold)', color: 'var(--text-primary)' }}>
                      {engine.name}
                    </div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                      KV{engine.version}
                    </div>
                  </div>
                  {selectedEngine?.name === engine.name && (
                    <svg viewBox="0 0 24 24" fill="none" width="20" height="20" style={{ color: 'var(--accent)' }}>
                      <path d="M20 6L9 17L4 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-secondary" type="button" disabled={processing}>
            {t('migrate.cancel')}
          </button>
          <button
            onClick={handleConfirm}
            className="btn btn-primary"
            type="button"
            disabled={!selectedEngine || processing}
          >
            {processing ? t('common.loading') : actionLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
