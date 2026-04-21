// src/TotpDisplayModal.jsx
import React, { useState, useEffect, useRef } from 'react';

export default function TotpDisplayModal({ secretName, totpCode, onClose, onCopy, onRefresh }) {
  const [timeLeft, setTimeLeft] = useState(30);
  const [currentCode, setCurrentCode] = useState(totpCode);
  const intervalRef = useRef(null);
  const lastRefreshRef = useRef(Date.now());

  useEffect(() => {
    setCurrentCode(totpCode);
  }, [totpCode]);

  useEffect(() => {
    // Calculer le temps restant basé sur l'heure actuelle (cycle de 30s)
    const updateTimer = () => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = 30 - (now % 30);
      setTimeLeft(remaining);

      // Rafraîchir le code quand on passe à 30 (nouveau cycle)
      if (remaining === 30 && Date.now() - lastRefreshRef.current > 2000) {
        lastRefreshRef.current = Date.now();
        if (onRefresh) {
          onRefresh().then(newCode => {
            if (newCode) setCurrentCode(newCode);
          }).catch(err => {
            console.error('Erreur rafraîchissement TOTP');
          });
        }
      }
    };

    updateTimer();
    intervalRef.current = setInterval(updateTimer, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [onRefresh]);

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) onClose();
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') onClose();
  };

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const progress = (timeLeft / 30) * 100;
  const isExpiringSoon = timeLeft <= 10;

  return (
    <div className="modal-overlay" onClick={handleBackdropClick}>
      <div className="modal-panel" style={{ maxWidth: '500px' }}>
        <div className="modal-header">
          <h2>Code TOTP</h2>
        </div>

        <div className="modal-body">
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--sp-4)' }}>
            Entrée : <strong>{secretName}</strong>
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
                  <span>Expire dans</span>
                  <span style={{ fontWeight: 'var(--weight-bold)' }}>{timeLeft}s</span>
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
              Aucun code TOTP disponible
            </div>
          )}
        </div>

        <div className="modal-footer">
          {currentCode && (
            <button
              onClick={() => {
                onCopy(currentCode);
                onClose();
              }}
              className="btn btn-primary"
              type="button"
            >
              Copier le code
            </button>
          )}
          <button
            onClick={onClose}
            className="btn btn-secondary"
            type="button"
          >
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
}
