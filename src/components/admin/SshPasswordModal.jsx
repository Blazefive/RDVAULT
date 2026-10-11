// ========================================
// MODALE : Saisie du mot de passe SSH (lecture des logs d'audit distants)
// ========================================
// Remplace window.prompt() (non supporté par Electron) par un champ mot de passe.
// Le mot de passe n'est jamais stocké : il est transmis à l'appelant pour une
// seule lecture puis oublié.
//
// Props :
// - host, username : informations affichées (jamais le mot de passe)
// - onSubmit(password) : callback appelé avec le mot de passe saisi
// - onClose : annulation

import React, { useEffect, useRef, useState } from 'react';
import Modal from '../common/Modal';
import { useTranslation } from '../../i18n';
import { richText } from './i18nHelpers';

export default function SshPasswordModal({ host, username, onSubmit, onClose }) {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!password) return;
    onSubmit(password);
    setPassword('');
  };

  return (
    <Modal
      title={`🔐 ${t('admin.sshPassword')}`}
      onClose={onClose}
      maxWidth="460px"
      footer={(
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t('common.cancel')}
          </button>
          <button type="submit" form="ssh-password-form" className="btn btn-primary" disabled={!password}>
            {t('admin.sshPrompt.readLogs')}
          </button>
        </>
      )}
    >
      <form id="ssh-password-form" onSubmit={handleSubmit}>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-3)' }}>
          {/* Cible utilisateur@hôte : identifiant technique isolé, lu de gauche à droite */}
          {richText(t('admin.sshPrompt.intro'), { target: <strong dir="ltr" className="bidi-ltr">{username}@{host}</strong> })}
        </p>
        <div className="form-group-vertical">
          <label className="modal-label">{t('admin.sshPassword')}*</label>
          <input
            ref={inputRef}
            type="password"
            className="modal-input"
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t('admin.sshPassword')}
          />
        </div>
      </form>
    </Modal>
  );
}
