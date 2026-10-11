// src/NotesPopupModal.jsx
// Popup d'affichage des notes d'un secret (squelette commun Modal :
// Escape, clic hors zone avec tolérance de déplacement pour la sélection de texte)
import React from 'react';
import { useTranslation } from './i18n';
import Modal from './components/common/Modal';

export default function NotesPopupModal({ notes, onClose }) {
  const { t } = useTranslation();

  return (
    <Modal
      title={t('notes.title')}
      onClose={onClose}
      panelStyle={{ maxWidth: '600px', maxHeight: '70vh' }}
      bodyStyle={{ maxHeight: 'calc(70vh - 120px)', overflowY: 'auto' }}
      footer={(
        <button onClick={onClose} className="btn btn-primary" type="button">
          {t('notes.close')}
        </button>
      )}
    >
      <div style={{
        whiteSpace: 'pre-wrap',
        fontFamily: 'inherit',
        fontSize: 'var(--text-base)',
        lineHeight: '1.6',
        color: 'var(--text-primary)'
      }}>
        {notes || <em style={{ color: 'var(--text-tertiary)' }}>{t('notes.empty')}</em>}
      </div>
    </Modal>
  );
}
