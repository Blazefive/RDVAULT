// ========================================
// MODAL DE CONFIRMATION
// ========================================
// Composant réutilisable pour les confirmations d'actions (suppressions, etc.)
//
// Props :
// - title : Titre de la modal (défaut: "Confirmer")
// - message : Message de confirmation à afficher
// - confirmLabel : Texte du bouton de confirmation (défaut: "Confirmer")
// - cancelLabel : Texte du bouton d'annulation (défaut: "Annuler")
// - danger : Si true, le bouton de confirmation est rouge (actions destructives)
// - onConfirm : Callback appelée quand l'utilisateur confirme
// - onCancel : Callback appelée quand l'utilisateur annule (Escape, clic hors modal, bouton Annuler)
//
// Comportement :
// - Escape pour fermer
// - Clic en dehors de la modal pour fermer
// - Overlay sombre avec z-index élevé

import React, { useEffect } from 'react';
import { useTranslation } from './i18n';

/**
 * Modal de confirmation générique
 * Utilisée pour confirmer des actions importantes (suppressions, etc.)
 */
export default function ConfirmModal({
  title,
  message = '',
  confirmLabel,
  cancelLabel,
  danger = false,
  onConfirm,
  onCancel,
}) {
  const { t } = useTranslation();
  const resolvedTitle = title || t('confirm.title');
  const resolvedConfirmLabel = confirmLabel || t('confirm.confirm');
  const resolvedCancelLabel = cancelLabel || t('common.cancel');
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancel && onCancel();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onCancel]);

  return (
    <div className="modal-overlay" onClick={() => onCancel && onCancel()} style={{ zIndex: 'var(--z-modal)' }}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '460px' }}>
        <div className="modal-header">
          <h2>{resolvedTitle}</h2>
        </div>
        <div className="modal-body">
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            {message}
          </div>
        </div>
        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={() => onCancel && onCancel()}>
            {resolvedCancelLabel}
          </button>
          <button
            type="button"
            className={danger ? 'btn btn-danger' : 'btn btn-primary'}
            onClick={() => onConfirm && onConfirm()}
          >
            {resolvedConfirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
