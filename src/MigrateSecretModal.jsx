// src/MigrateSecretModal.jsx
// Migration / copie d'entrées vers un autre coffre (squelette commun Modal : role="dialog",
// aria-modal, nom accessible, focus initial et piège de focus, Échap réservé à la modale du
// dessus, fermeture sur le fond seulement si mousedown ET mouseup y tombent).
import React, { useState } from 'react';
import { useTranslation } from './i18n';
import Modal from './components/common/Modal';

/**
 * Rend une phrase traduite dont les variables {{x}} sont affichées en gras.
 * t(key) est appelé sans variables : les marqueurs {{x}} restent dans le texte et servent de
 * points de découpe (l'ordre des mots reste celui de la traduction).
 */
function renderWithStrong(template, vars) {
  return template.split(/\{\{(\w+)\}\}/).map((part, i) => (
    i % 2 === 1 ? <strong key={i}>{vars[part] ?? ''}</strong> : <React.Fragment key={i}>{part}</React.Fragment>
  ));
}

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
    <Modal
      title={title}
      onClose={onClose}
      maxWidth="500px"
      footer={(
        <>
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
        </>
      )}
    >
      {/* Phrase traduite (était codée en dur en français) ; nom, nombre et coffre en gras */}
      <div style={{ marginBottom: 'var(--sp-4)', color: 'var(--text-secondary)' }}>
        {count === 1
          ? renderWithStrong(t(mode === 'move' ? 'migrate.moveOneFrom' : 'migrate.copyOneFrom'), {
            name: secretsList[0].name,
            engine: currentEngine?.name,
          })
          : renderWithStrong(t(mode === 'move' ? 'migrate.moveManyFrom' : 'migrate.copyManyFrom'), {
            entries: t('migrate.entriesCount', { count }),
            engine: currentEngine?.name,
          })}
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
                transition: 'background-color 0.2s, border-color 0.2s',
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
    </Modal>
  );
}
