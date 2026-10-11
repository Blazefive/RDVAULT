// ========================================
// MODAL DE CONFIRMATION
// ========================================
// Composant réutilisable pour les confirmations d'actions (suppressions, etc.)
//
// Props :
// - title : Titre de la modal (défaut: "Confirmer")
// - message : Message de confirmation à afficher (texte déjà traduit, ou nœud React)
// - messageKey / values / ltrValues : alternative à `message` — le message est construit ici depuis
//   t(messageKey) ; chaque {{variable}} est remplacée par values[variable], ISOLÉE (<bdi>). Les variables
//   nommées dans ltrValues (identifiants techniques : chemin, nom de coffre, de policy) sont lues de
//   gauche à droite ; les autres (texte libre : nom d'entrée, tag) gardent leur propre sens. Le texte
//   rendu est identique à t(messageKey, values).
// - confirmLabel : Texte du bouton de confirmation (défaut: "Confirmer")
// - cancelLabel : Texte du bouton d'annulation (défaut: "Annuler")
// - danger : Si true, le bouton de confirmation est rouge (actions destructives)
// - onConfirm : Callback appelée quand l'utilisateur confirme
// - onCancel : Callback appelée quand l'utilisateur annule (Escape, clic hors modal, bouton Annuler)
//
// BIDI (arabe) : une valeur technique insérée dans la phrase (« users/alice/Compta/ », « admin-policy »)
// se mêlait au texte de droite à gauche (barre oblique ou guillemet déplacés). Avec messageKey, chaque
// valeur est isolée. Avec un `message` texte (ou un fragment contenant du texte), les passages entre
// guillemets — où les traductions placent ces valeurs — sont isolés automatiquement ; le texte rendu
// ne change pas.
//
// Comportement (fourni par le squelette commun Modal) :
// - Escape pour fermer
// - Clic en dehors de la modal pour fermer
// - Overlay sombre avec z-index élevé

import React from 'react';
import { useTranslation } from './i18n';
import Modal from './components/common/Modal';
import { isolateQuoted, richIsolated } from './components/admin/i18nHelpers';

/**
 * Message d'une confirmation, valeurs entre guillemets isolées : texte brut, ou fragment dont les
 * enfants directs de type texte sont traités (les autres nœuds sont rendus tels quels).
 */
function isolateMessage(message) {
  if (typeof message === 'string') return isolateQuoted(message);
  if (React.isValidElement(message) && message.type === React.Fragment) {
    const children = React.Children.map(message.props.children, child => (typeof child === 'string' ? isolateQuoted(child) : child));
    return React.createElement(React.Fragment, null, children);
  }
  return message;
}

/**
 * Modal de confirmation générique
 * Utilisée pour confirmer des actions importantes (suppressions, etc.)
 */
export default function ConfirmModal({
  title,
  message = '',
  messageKey,
  values,
  ltrValues,
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
  // t(clé) sans variables : les marqueurs {{…}} sont conservés et remplacés par les valeurs isolées
  const body = messageKey ? richIsolated(t(messageKey), values || {}, ltrValues || []) : isolateMessage(message);

  return (
    <Modal
      title={resolvedTitle}
      onClose={onCancel}
      maxWidth="460px"
      overlayStyle={{ zIndex: 'var(--z-modal)' }}
      footer={(
        <>
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
        </>
      )}
    >
      <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
        {body}
      </div>
    </Modal>
  );
}
