// src/NotesPopupModal.jsx
import React, { useEffect, useState } from 'react';
import { useTranslation } from './i18n';

export default function NotesPopupModal({ notes, onClose }) {
  const { t } = useTranslation();
  const [mouseDownPos, setMouseDownPos] = useState(null);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  const handleOverlayMouseDown = (e) => {
    if (e.target.className === 'modal-overlay') {
      setMouseDownPos({ x: e.clientX, y: e.clientY });
    }
  };

  const handleOverlayMouseUp = (e) => {
    if (e.target.className === 'modal-overlay' && mouseDownPos) {
      const deltaX = Math.abs(e.clientX - mouseDownPos.x);
      const deltaY = Math.abs(e.clientY - mouseDownPos.y);

      // Fermer seulement si déplacement < 5px (clic réel, pas drag)
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
        style={{ maxWidth: '600px', maxHeight: '70vh' }}
      >
        <div className="modal-header">
          <h2>{t('notes.title')}</h2>
        </div>

        <div className="modal-body" style={{ maxHeight: 'calc(70vh - 120px)', overflowY: 'auto' }}>
          <div style={{
            whiteSpace: 'pre-wrap',
            fontFamily: 'inherit',
            fontSize: 'var(--text-base)',
            lineHeight: '1.6',
            color: 'var(--text-primary)'
          }}>
            {notes || <em style={{ color: 'var(--text-tertiary)' }}>{t('notes.empty')}</em>}
          </div>
        </div>

        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-primary" type="button">
            {t('notes.close')}
          </button>
        </div>
      </div>
    </div>
  );
}
