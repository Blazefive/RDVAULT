// src/TotpDisplayModal.jsx
// Affiche un code TOTP avec compte à rebours et rafraîchissement automatique.
//
// Props :
// - secretName, totpCode, onClose, onCopy, onRefresh
// - period : période TOTP en secondes (défaut 30, configurable pour les clés à 60 s par ex.)
//
// Squelette commun Modal : role="dialog" + aria-modal + nom accessible (titre), focus initial,
// piège de focus, retour du focus, Échap (modale du dessus uniquement) et fermeture sur le fond
// seulement si mousedown ET mouseup y tombent (une sélection du code qui déborde ne ferme plus).
import React, { useState, useEffect, useRef } from 'react';
import { useTranslation } from './i18n';
import secureLogger from './secureLogger';
import Modal from './components/common/Modal';

const DEFAULT_TOTP_PERIOD = 30;

/** Numéro de la fenêtre TOTP (RFC 6238 : T = floor(temps Unix / période)) à l'instant `nowMs`. */
export function totpWindow(nowMs, period) {
  return Math.floor(nowMs / 1000 / period);
}

export default function TotpDisplayModal({ secretName, totpCode, onClose, onCopy, onRefresh, period = DEFAULT_TOTP_PERIOD }) {
  const { t } = useTranslation();
  // Garde : période invalide → 30 s
  const safePeriod = Number.isFinite(Number(period)) && Number(period) > 0 ? Number(period) : DEFAULT_TOTP_PERIOD;

  const [timeLeft, setTimeLeft] = useState(safePeriod);
  const [currentCode, setCurrentCode] = useState(totpCode);
  const intervalRef = useRef(null);
  // Fenêtre TOTP du code affiché : le code reçu à l'ouverture correspond à la fenêtre courante.
  // Initialisée une seule fois (pas à chaque relance de l'effet, sinon un changement de fenêtre
  // survenu juste avant la relance serait oublié).
  const windowRef = useRef(null);
  if (windowRef.current === null) windowRef.current = totpWindow(Date.now(), safePeriod);
  // Numéro de la dernière demande de rafraîchissement : une réponse tardive d'une demande
  // plus ancienne n'écrase pas un code plus récent.
  const refreshSeqRef = useRef(0);

  useEffect(() => {
    setCurrentCode(totpCode);
  }, [totpCode]);

  useEffect(() => {
    // Calculer le temps restant basé sur l'heure actuelle (cycle de `safePeriod` s)
    const updateTimer = () => {
      const nowMs = Date.now();
      const now = Math.floor(nowMs / 1000);
      const remaining = safePeriod - (now % safePeriod);
      setTimeLeft(remaining);

      // BUG CORRIGÉ : le rafraîchissement n'avait lieu que si un tick tombait exactement sur
      // `remaining === safePeriod`. Dans une fenêtre en arrière-plan, Chromium espace les
      // minuteurs (≥ 1 s, jusqu'à 1 min) : ce tick était souvent sauté et un code périmé restait
      // affiché tout un cycle. On compare désormais le numéro de fenêtre TOTP.
      const currentWindow = totpWindow(nowMs, safePeriod);
      if (currentWindow !== windowRef.current) {
        windowRef.current = currentWindow;
        if (onRefresh) {
          const seq = ++refreshSeqRef.current;
          Promise.resolve()
            .then(() => onRefresh())
            .then(newCode => {
              if (newCode && seq === refreshSeqRef.current) setCurrentCode(newCode);
            })
            .catch(() => {
              secureLogger.error('[TOTP] Erreur rafraîchissement du code');
            });
        }
      }
    };

    updateTimer();
    intervalRef.current = setInterval(updateTimer, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [onRefresh, safePeriod]);

  const progress = (timeLeft / safePeriod) * 100;
  const isExpiringSoon = timeLeft <= Math.min(10, Math.ceil(safePeriod / 3));

  return (
    <Modal
      title={t('totp.title')}
      onClose={onClose}
      maxWidth="500px"
      footer={(
        <>
          {currentCode && (
            <button
              onClick={() => {
                onCopy(currentCode);
                onClose();
              }}
              className="btn btn-primary"
              type="button"
            >
              {t('totp.copyCode')}
            </button>
          )}
          <button
            onClick={onClose}
            className="btn btn-secondary"
            type="button"
          >
            {t('common.close')}
          </button>
        </>
      )}
    >
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--sp-4)' }}>
        {t('totp.entry')} <strong>{secretName}</strong>
      </div>

      {currentCode ? (
        <>
          <div
            style={{
              fontSize: 'var(--text-4xl)',
              fontWeight: 'var(--weight-bold)',
              fontFamily: 'var(--font-mono)',
              textAlign: 'center',
              padding: 'var(--sp-6) 0',
              letterSpacing: '8px',
              color: isExpiringSoon ? 'var(--error)' : 'var(--text-primary)',
              userSelect: 'all',
              background: 'var(--bg-app)',
              borderRadius: 'var(--radius-lg)',
              border: `2px solid ${isExpiringSoon ? 'var(--error)' : 'var(--border)'}`,
              marginBottom: 'var(--sp-6)'
            }}
          >
            {currentCode}
          </div>

          <div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: 'var(--sp-3)',
              fontSize: 'var(--text-sm)',
              color: isExpiringSoon ? 'var(--error)' : 'var(--text-secondary)'
            }}>
              <span>{t('totp.expiresIn')}</span>
              <span style={{ fontWeight: 'var(--weight-bold)' }}>{timeLeft}{t('totp.seconds')}</span>
            </div>

            <div className="clipboard-progress">
              <div
                className="clipboard-progress-bar"
                style={{
                  width: `${progress}%`,
                  background: isExpiringSoon ? 'var(--error)' : 'var(--success)'
                }}
              />
            </div>
          </div>
        </>
      ) : (
        <div className="empty-state">
          {t('totp.noCode')}
        </div>
      )}
    </Modal>
  );
}
