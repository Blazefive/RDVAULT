// src/TotpConfigModal.jsx
import React, { useState, useEffect, useRef } from 'react';

export default function TotpConfigModal({ secretName, totpKeyName, engineName, onClose, onSave }) {
  const [accountName, setAccountName] = useState(secretName || '');
  const [totpKey, setTotpKey] = useState('');
  const [algorithm, setAlgorithm] = useState('SHA1');
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);
  const [generating, setGenerating] = useState(false);

  const totpKeyRef = useRef(null);

  useEffect(() => {
    if (totpKeyRef.current) {
      totpKeyRef.current.focus();
    }
  }, []);

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

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!totpKey.trim()) {
      alert('La clé TOTP est obligatoire');
      return;
    }

    // Validation du format base32
    if (!/^[A-Z2-7]+=*$/i.test(totpKey.trim())) {
      alert('La clé TOTP n\'est pas au format base32 valide (caractères autorisés : A-Z, 2-7, =)');
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
      // Pas de log du secret TOTP
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={handleBackdropClick}>
      <div className="modal-panel" style={{ maxWidth: '500px', maxHeight: '80vh' }}>
        <div className="modal-header" style={{ padding: 'var(--sp-6)' }}>
          <h2>Configurer TOTP</h2>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body" style={{ padding: 'var(--sp-6)' }}>
            <div className="form-group-vertical">
              <label className="modal-label">
                Clé TOTP (Secret) <span style={{ color: 'var(--error)' }}>*</span>
              </label>
              <textarea
                ref={totpKeyRef}
                value={totpKey}
                onChange={(e) => {
                  // Supprimer tous les espaces, tabs, retours à la ligne
                  const cleaned = e.target.value.replace(/\s/g, '');
                  setTotpKey(cleaned);
                }}
                className="modal-textarea"
                placeholder="Entrez la clé secrète TOTP (base32)"
                rows="3"
                required
              />
              <div className="form-hint">
                Format base32 sans espaces (ex: JBSWY3DPEHPK3PXP)
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)', marginBottom: 'var(--sp-4)' }}>
              <div className="form-group-vertical">
                <label className="modal-label">
                  Chiffres
                </label>
                <select
                  value={digits}
                  onChange={(e) => setDigits(e.target.value)}
                  className="modal-input"
                >
                  <option value="6">6</option>
                  <option value="8">8</option>
                </select>
              </div>

              <div className="form-group-vertical">
                <label className="modal-label">
                  Période (s)
                </label>
                <input
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
              <div className="info-box-title">Nom de la clé TOTP</div>
              <div className="info-box-content">
                <code style={{ background: 'var(--bg-surface)', padding: '4px var(--sp-3)', borderRadius: 'var(--radius-sm)' }}>
                  {totpKeyName || secretName}
                </code>
                <div style={{ marginTop: 'var(--sp-3)' }}>
                  Cette clé sera créée dans <strong>totp/</strong> avec le préfixe du coffre <strong>{engineName}</strong>
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
              Annuler
            </button>
            <button
              type="submit"
              disabled={generating}
              className="btn btn-success"
            >
              {generating ? 'Configuration...' : 'Configurer'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
