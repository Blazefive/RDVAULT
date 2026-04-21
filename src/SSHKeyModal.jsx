// src/SSHKeyModal.jsx
import React, { useEffect, useRef, useState } from 'react';

export default function SSHKeyModal({ initial, onClose, onSave }) {
  const [keyType, setKeyType] = useState(initial?.keyType || 'personal');
  const nameRef = useRef(null);
  const privateKeyRef = useRef(null);
  const publicKeyRef = useRef(null);
  const passphraseRef = useRef(null);
  const notesRef = useRef(null);

  const isCreate = !initial || !initial.name;

  useEffect(() => {
    nameRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  const copyToClipboard = async (text, label) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      // Erreur silencieuse
    }
  };

  const save = () => {
    const name = (nameRef.current?.value ?? '').trim();
    const privateKey = (privateKeyRef.current?.value ?? '').trim();

    if (!name) {
      alert('Le nom est obligatoire');
      return;
    }
    if (name.length > 512 || /\.\./.test(name) || /\\/.test(name)) {
      alert('Nom invalide (max 512 caractères, pas de .. ni \\)');
      return;
    }
    if (/[\x00-\x1F]/.test(name)) {
      alert('Le nom contient des caractères de contrôle non autorisés');
      return;
    }
    if (!privateKey) {
      alert('La clé privée est obligatoire');
      return;
    }
    if (privateKey.length > 16384) {
      alert('Clé privée trop longue (max 16384 caractères)');
      return;
    }

    const publicKey = (publicKeyRef.current?.value ?? '').trim();
    const passphrase = (passphraseRef.current?.value ?? '').trim();
    const notes = (notesRef.current?.value ?? '').trim();

    if (publicKey.length > 32768) {
      alert('Clé publique trop longue (max 32768 caractères)');
      return;
    }
    if (passphrase.length > 512) {
      alert('Passphrase trop longue (max 512 caractères)');
      return;
    }
    if (notes.length > 2000) {
      alert('Notes trop longues (max 2000 caractères)');
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
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '700px' }}
      >
        <div className="modal-header">
          <h2>
            {isCreate ? 'Nouvelle clé SSH' : <>Modifier : <code>{initial?.name}</code></>}
          </h2>
        </div>

        <div className="modal-body">
          <div className="form-group-vertical">
            <label className="modal-label">Nom*</label>
            <input
              ref={nameRef}
              className="modal-input"
              defaultValue={initial?.name || ''}
              autoComplete="off"
              placeholder="ex: github-deploy, server-prod"
            />
          </div>

          <div className="form-group-vertical">
            <label className="modal-label">Type de clé</label>
            <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
              <label className="checkbox-label">
                <input
                  type="radio"
                  name="keyType"
                  checked={keyType === 'personal'}
                  onChange={() => setKeyType('personal')}
                />
                <span>🔐 Personnel</span>
              </label>
              <label className="checkbox-label">
                <input
                  type="radio"
                  name="keyType"
                  checked={keyType === 'shared'}
                  onChange={() => setKeyType('shared')}
                />
                <span>👥 Partagé</span>
              </label>
            </div>
            <div className="form-hint">
              {keyType === 'personal' ? 'Accessible uniquement par vous' : 'Accessible par tous les membres de l\'équipe'}
            </div>
          </div>

          <div className="form-group-vertical">
            <label className="modal-label">Clé privée*</label>
            <div style={{ position: 'relative' }}>
              <textarea
                ref={privateKeyRef}
                className="modal-textarea"
                defaultValue={initial?.privateKey || ''}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                style={{ fontFamily: 'monospace', fontSize: 'var(--text-sm)', minHeight: '120px' }}
              />
              <button
                onClick={() => copyToClipboard(privateKeyRef.current?.value, 'Clé privée')}
                className="btn btn-sm btn-secondary"
                type="button"
                style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
                title="Copier la clé privée"
              >
                📋 Copier
              </button>
            </div>
          </div>

          <div className="form-group-vertical">
            <label className="modal-label">Clé publique</label>
            <div style={{ position: 'relative' }}>
              <textarea
                ref={publicKeyRef}
                className="modal-textarea"
                defaultValue={initial?.publicKey || ''}
                placeholder="ssh-rsa AAAAB3NzaC1yc2EA..."
                style={{ fontFamily: 'monospace', fontSize: 'var(--text-sm)', minHeight: '80px' }}
              />
              <button
                onClick={() => copyToClipboard(publicKeyRef.current?.value, 'Clé publique')}
                className="btn btn-sm btn-secondary"
                type="button"
                style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
                title="Copier la clé publique"
              >
                📋 Copier
              </button>
            </div>
          </div>

          <div className="form-group-vertical">
            <label className="modal-label">Passphrase (optionnel)</label>
            <input
              ref={passphraseRef}
              className="modal-input"
              type="password"
              defaultValue={initial?.passphrase || ''}
              autoComplete="off"
              placeholder="Passphrase de protection"
            />
          </div>

          <div className="form-group-vertical">
            <label className="modal-label">Notes</label>
            <textarea
              ref={notesRef}
              className="modal-textarea"
              defaultValue={initial?.notes || ''}
              placeholder="Serveurs utilisant cette clé, date d'expiration, etc."
            />
          </div>
        </div>

        <div className="modal-footer">
          <span className="form-hint" style={{ flex: 1, marginTop: 0, marginBottom: 0 }}>
            ⚠️ Assurez-vous de conserver une copie de sauvegarde de vos clés privées.
          </span>
          <button onClick={onClose} className="btn btn-secondary" type="button">
            Annuler
          </button>
          <button onClick={save} className="btn btn-primary" type="button">
            {isCreate ? 'Créer' : 'Sauvegarder'}
          </button>
        </div>
      </div>
    </div>
  );
}
