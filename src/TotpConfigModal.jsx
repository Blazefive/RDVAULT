// src/TotpConfigModal.jsx
// Modale de configuration d'une clé TOTP pour un secret.
//
// Props :
// - secretName, totpKeyName, engineName
// - onClose, onSave(config)
// - showToast : affichage des erreurs de validation (remplace alert(), non supporté par Electron)
//
// Accessibilité (hook useDialogA11y du squelette commun Modal) : role="dialog" + aria-modal +
// aria-labelledby (titre), focus initial (champ de la clé), piège de focus, retour du focus,
// Échap réservé à la modale du dessus. Fermeture sur le fond seulement si mousedown ET mouseup
// y tombent (une sélection de texte qui déborde du panneau ne ferme plus la modale).
// Mise en page (UI-34) : le <form> (classe .modal-form) prolonge la colonne flex du panneau :
// corps défilant, pied « Annuler / Configurer » toujours visible.
import React, { useState, useEffect, useId, useRef } from 'react';
import { useTranslation } from './i18n';
import { useDialogA11y } from './components/common/Modal';

// Tolérance de déplacement (px) d'un clic sur le fond (même valeur que components/common/Modal)
const CLICK_TOLERANCE_PX = 5;

export default function TotpConfigModal({ secretName, totpKeyName, engineName, onClose, onSave, showToast }) {
  const { t } = useTranslation();
  const [accountName] = useState(secretName || '');
  const [totpKey, setTotpKey] = useState('');
  const [algorithm] = useState('SHA1');
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);
  const [generating, setGenerating] = useState(false);

  const totpKeyRef = useRef(null);
  const panelRef = useRef(null);
  const overlayDownRef = useRef(null);
  const titleId = useId();
  // Libellés associés aux champs (nom accessible des champs au lecteur d'écran)
  const keyFieldId = useId();
  const digitsFieldId = useId();
  const periodFieldId = useId();

  const notifyError = (message) => {
    if (typeof showToast === 'function') showToast(message, 'error');
  };

  useEffect(() => {
    if (totpKeyRef.current) {
      totpKeyRef.current.focus();
    }
  }, []);

  // Focus initial, piège de focus, Échap (modale du dessus uniquement), retour du focus
  useDialogA11y(panelRef, { onEscape: onClose });

  // BUG CORRIGÉ : fermeture au « click » sur le fond, déclenché aussi par une sélection de texte
  // commencée dans le panneau et relâchée sur le fond. Il faut désormais mousedown ET mouseup
  // sur le fond, à moins de 5 px l'un de l'autre.
  const handleOverlayMouseDown = (e) => {
    overlayDownRef.current = e.target === e.currentTarget ? { x: e.clientX, y: e.clientY } : null;
  };
  const handleOverlayMouseUp = (e) => {
    const start = overlayDownRef.current;
    overlayDownRef.current = null;
    if (!start || e.target !== e.currentTarget) return;
    if (Math.abs(e.clientX - start.x) < CLICK_TOLERANCE_PX && Math.abs(e.clientY - start.y) < CLICK_TOLERANCE_PX) onClose();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!totpKey.trim()) {
      notifyError(t('error.totpRequired'));
      return;
    }

    // Validation du format base32
    if (!/^[A-Z2-7]+=*$/i.test(totpKey.trim())) {
      notifyError(t('error.totpInvalidFormat'));
      return;
    }

    setGenerating(true);
    try {
      const config = {
        account_name: accountName.trim() || secretName,
        key: totpKey.trim().toUpperCase(), // S'assurer que la clé est en majuscules (base32 standard)
        algorithm: algorithm || 'SHA1',
        digits: Number(digits) || 6,
        period: Number(period) || 30
      };
      await onSave(config);
    } catch (err) {
      // Pas de log du secret TOTP (l'erreur est déjà affichée par onSave via toast)
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="modal-overlay" onMouseDown={handleOverlayMouseDown} onMouseUp={handleOverlayMouseUp}>
      <div
        ref={panelRef}
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={{ maxWidth: '500px', maxHeight: '80vh' }}
      >
        <div className="modal-header" style={{ padding: 'var(--sp-6)' }}>
          <h2 id={titleId}>{t('totp.configure')}</h2>
        </div>

        {/* UI-34 : .modal-form = maillon de la colonne flex du panneau (corps défilant, pied
            fixe) ; sans elle, à 1280×800 les boutons sortaient du panneau (overflow hidden) */}
        <form onSubmit={handleSubmit} className="modal-form">
          <div className="modal-body" style={{ padding: 'var(--sp-6)' }}>
            <div className="form-group-vertical">
              <label className="modal-label" htmlFor={keyFieldId}>
                {t('editSecret.totpKey')}
              </label>
              <textarea
                id={keyFieldId}
                ref={totpKeyRef}
                value={totpKey}
                onChange={(e) => {
                  // Supprimer tous les espaces, tabs, retours à la ligne
                  const cleaned = e.target.value.replace(/\s/g, '');
                  setTotpKey(cleaned);
                }}
                className="modal-textarea"
                placeholder={t('editSecret.totpPlaceholder')}
                rows="3"
                required
              />
              <div className="form-hint">
                {t('editSecret.totpHint')}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)', marginBottom: 'var(--sp-4)' }}>
              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={digitsFieldId}>
                  {t('editSecret.totpDigits')}
                </label>
                <select
                  id={digitsFieldId}
                  value={digits}
                  onChange={(e) => setDigits(e.target.value)}
                  className="modal-input"
                >
                  <option value="6">6</option>
                  <option value="8">8</option>
                </select>
              </div>

              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={periodFieldId}>
                  {t('editSecret.totpPeriod')}
                </label>
                <input
                  id={periodFieldId}
                  type="number"
                  value={period}
                  onChange={(e) => setPeriod(e.target.value)}
                  className="modal-input"
                  min="10"
                  max="120"
                />
              </div>
            </div>

            <div className="info-box">
              <div className="info-box-title">{t('totp.keyName')}</div>
              <div className="info-box-content">
                <code style={{ background: 'var(--bg-surface)', padding: '4px var(--sp-3)', borderRadius: 'var(--radius-sm)' }}>
                  {totpKeyName || secretName}
                </code>
                <div style={{ marginTop: 'var(--sp-3)' }}>
                  {t('totp.keyCreatedIn')} <strong>totp/</strong> {t('totp.withPrefix')} <strong>{engineName}</strong>
                </div>
              </div>
            </div>
          </div>

          <div className="modal-footer" style={{ padding: 'var(--sp-6)' }}>
            <button
              type="button"
              onClick={onClose}
              className="btn btn-secondary"
            >
              {t('common.cancel')}
            </button>
            <button
              type="submit"
              disabled={generating}
              className="btn btn-success"
            >
              {generating ? t('totp.configuring') : t('totp.configureBtn')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
