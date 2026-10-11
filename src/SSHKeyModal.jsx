// src/SSHKeyModal.jsx
// Modale de création/édition d'une clé SSH.
//
// Props :
// - initial : clé existante (null = création)
// - onClose, onSave(key)
// - showToast : affichage des erreurs de validation (remplace alert(), non supporté par Electron).
//   Si absent, l'erreur est affichée dans la modale.
//
// Squelette commun Modal : role="dialog" + aria-modal + nom accessible (titre), focus initial
// (champ « Nom »), piège de focus, retour du focus, Échap réservé à la modale du dessus et
// fermeture sur le fond seulement si mousedown ET mouseup y tombent (une sélection de texte
// commencée dans une clé et relâchée sur le fond ne ferme plus la modale).
import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from './i18n';
import { copySecureWithAutoClear } from './utils/clipboard';
import Modal from './components/common/Modal';

export default function SSHKeyModal({ initial, onClose, onSave, showToast }) {
  const { t } = useTranslation();
  const [keyType, setKeyType] = useState(initial?.keyType || 'personal');
  const [error, setError] = useState('');
  const nameRef = useRef(null);
  const privateKeyRef = useRef(null);
  const publicKeyRef = useRef(null);
  const passphraseRef = useRef(null);
  const notesRef = useRef(null);

  const isCreate = !initial || !initial.name;

  useEffect(() => {
    nameRef.current?.focus();
  }, []);

  // Affiche une erreur de validation via toast (ou en ligne si pas de showToast)
  const notifyError = (message) => {
    setError(message);
    if (typeof showToast === 'function') showToast(message, 'error');
  };

  // SÉCURITÉ : copie avec auto-effacement du presse-papiers (12 s)
  const copyToClipboard = async (text) => {
    try {
      await copySecureWithAutoClear(text);
    } catch (err) {
      // Erreur silencieuse
    }
  };

  const save = () => {
    setError('');
    const name = (nameRef.current?.value ?? '').trim();
    const privateKey = (privateKeyRef.current?.value ?? '').trim();

    if (!name) {
      notifyError(t('sshKey.nameRequired'));
      return;
    }
    if (name.length > 512 || /\.\./.test(name) || /\\/.test(name)) {
      notifyError(t('sshKey.nameInvalid'));
      return;
    }
    // eslint-disable-next-line no-control-regex -- volontaire : nom avec caractère de contrôle refusé
    if (/[\x00-\x1F]/.test(name)) {
      notifyError(t('sshKey.nameControlChars'));
      return;
    }
    if (!privateKey) {
      notifyError(t('error.privateKeyRequired'));
      return;
    }
    if (privateKey.length > 16384) {
      notifyError(t('error.privateKeyTooLong'));
      return;
    }

    const publicKey = (publicKeyRef.current?.value ?? '').trim();
    const passphrase = (passphraseRef.current?.value ?? '').trim();
    const notes = (notesRef.current?.value ?? '').trim();

    if (publicKey.length > 32768) {
      notifyError(t('sshKey.publicKeyTooLong'));
      return;
    }
    if (passphrase.length > 512) {
      notifyError(t('sshKey.passphraseTooLong'));
      return;
    }
    if (notes.length > 2000) {
      notifyError(t('sshKey.notesTooLong'));
      return;
    }

    onSave({
      name,
      privateKey,
      publicKey,
      passphrase,
      notes,
      keyType,
    });
  };

  return (
    <Modal
      title={isCreate ? t('sshKey.newKey') : <>{t('sshKey.editKey')} <code>{initial?.name}</code></>}
      onClose={onClose}
      maxWidth="700px"
      footer={(
        <>
          <span className="form-hint" style={{ flex: 1, marginTop: 0, marginBottom: 0 }}>
            ⚠️ {t('sshKey.backupWarning')}
          </span>
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('common.cancel')}
          </button>
          <button onClick={save} className="btn btn-primary" type="button">
            {isCreate ? t('sshKey.create') : t('common.save')}
          </button>
        </>
      )}
    >
      {error && !showToast && (
        <div className="form-hint" style={{ color: 'var(--error)', marginBottom: 'var(--sp-3)' }}>
          {error}
        </div>
      )}

      <div className="form-group-vertical">
        <label className="modal-label">{t('sshKey.name')}</label>
        <input
          ref={nameRef}
          className="modal-input"
          defaultValue={initial?.name || ''}
          autoComplete="off"
          placeholder={t('sshKey.namePlaceholder')}
        />
      </div>

      <div className="form-group-vertical">
        <label className="modal-label">{t('sshKey.keyType')}</label>
        <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
          <label className="checkbox-label">
            <input
              type="radio"
              name="keyType"
              checked={keyType === 'personal'}
              onChange={() => setKeyType('personal')}
            />
            <span>🔐 {t('sshKey.personal')}</span>
          </label>
          <label className="checkbox-label">
            <input
              type="radio"
              name="keyType"
              checked={keyType === 'shared'}
              onChange={() => setKeyType('shared')}
            />
            <span>👥 {t('sshKey.shared')}</span>
          </label>
        </div>
        <div className="form-hint">
          {keyType === 'personal' ? t('sshKey.personalHint') : t('sshKey.sharedHint')}
        </div>
      </div>

      <div className="form-group-vertical">
        <label className="modal-label">{t('sshKey.privateKey')}</label>
        <div style={{ position: 'relative' }}>
          <textarea
            ref={privateKeyRef}
            className="modal-textarea"
            defaultValue={initial?.privateKey || ''}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
            style={{ fontFamily: 'monospace', fontSize: 'var(--text-sm)', minHeight: '120px' }}
          />
          <button
            onClick={() => copyToClipboard(privateKeyRef.current?.value)}
            className="btn btn-sm btn-secondary"
            type="button"
            style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
            title={t('sshKey.copyPrivate')}
          >
            📋 {t('sshKey.copy')}
          </button>
        </div>
      </div>

      <div className="form-group-vertical">
        <label className="modal-label">{t('sshKey.publicKey')}</label>
        <div style={{ position: 'relative' }}>
          <textarea
            ref={publicKeyRef}
            className="modal-textarea"
            defaultValue={initial?.publicKey || ''}
            placeholder="ssh-rsa AAAAB3NzaC1yc2EA..."
            style={{ fontFamily: 'monospace', fontSize: 'var(--text-sm)', minHeight: '80px' }}
          />
          <button
            onClick={() => copyToClipboard(publicKeyRef.current?.value)}
            className="btn btn-sm btn-secondary"
            type="button"
            style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
            title={t('sshKey.copyPublic')}
          >
            📋 {t('sshKey.copy')}
          </button>
        </div>
      </div>

      <div className="form-group-vertical">
        <label className="modal-label">{t('sshKey.passphrase')}</label>
        <input
          ref={passphraseRef}
          className="modal-input"
          type="password"
          defaultValue={initial?.passphrase || ''}
          autoComplete="off"
          placeholder={t('sshKey.passphrasePlaceholder')}
        />
      </div>

      <div className="form-group-vertical">
        <label className="modal-label">{t('sshKey.notes')}</label>
        <textarea
          ref={notesRef}
          className="modal-textarea"
          defaultValue={initial?.notes || ''}
          placeholder={t('sshKey.notesPlaceholder')}
        />
      </div>
    </Modal>
  );
}
