// ========================================
// COMPOSANT: EditSecretModal
// ========================================
// Modal de création/édition de secrets Vault.
//
// Supporte 3 types d'entrées:
// - secret: Mot de passe classique (username, password, URL)
// - ssh: Clé SSH (privateKey, publicKey, passphrase)
// - folder: Dossier vide pour organisation
//
// Mapping des champs SSH vers Vault:
// - privateKey → password (champ Vault standard)
// - publicKey → url (champ Vault standard)
// - passphrase → username (champ Vault standard)
// Ce mapping permet de réutiliser les champs KV existants sans modifier le schéma.
//
// Sécurité:
// - Validation des inputs avant sauvegarde
// - Protection contre les caractères dangereux
// - Limite de taille sur les fichiers joints (2 MB)

import React, { useEffect, useRef, useState } from 'react';
import PasswordGeneratorModal from './PasswordGeneratorModal';
import { analyzePassword } from './utils/passwordStrength';
import { validateSecretName, validateUsername, validatePassword, isValidUrl } from './validation';
import { useTranslation } from './i18n';

/**
 * Modal de création/édition de secrets Vault
 *
 * @param {Object} props - Props du composant
 * @param {Object} props.initial - Données initiales du secret (null pour création)
 * @param {Function} props.onClose - Callback de fermeture
 * @param {Function} props.onSave - Callback de sauvegarde avec les données validées
 * @param {boolean} props.totpExists - Si true, le nom ne peut pas être modifié (TOTP configuré)
 */
export default function EditSecretModal({ initial, onClose, onSave, totpExists = false, existingTags = [] }) {
  const { t } = useTranslation();
  const [showPasswordGenerator, setShowPasswordGenerator] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({ entropy: 0, strength: '', color: '', percentage: 0 });
  const [customFields, setCustomFields] = useState(initial?.customFields || []);
  const [attachments, setAttachments] = useState(initial?.attachments || []);
  const [entryType, setEntryType] = useState(initial?.entryType || 'secret'); // 'secret', 'ssh' ou 'folder'
  const [mouseDownPos, setMouseDownPos] = useState(null); // Position du mouseDown pour détecter drag
  const [validationErrors, setValidationErrors] = useState({}); // Erreurs de validation par champ
  const [tagSuggestions, setTagSuggestions] = useState([]); // Suggestions d'auto-complétion des tags
  const [showTagSuggestions, setShowTagSuggestions] = useState(false);
  const nameRef = useRef(null);
  const usernameRef = useRef(null);
  const passwordRef = useRef(null);
  const urlRef = useRef(null);
  const notesRef = useRef(null);
  const tagsRef = useRef(null);
  const fileInputRef = useRef(null);
  const privateKeyRef = useRef(null);
  const publicKeyRef = useRef(null);
  const passphraseRef = useRef(null);

  const isCreate = !initial || !initial.name || initial.name.endsWith('/');

  // Calculer la force du mot de passe initial
  useEffect(() => {
    if (initial?.password) {
      const analysis = analyzePassword(initial.password);
      setPasswordStrength(analysis);
    }
  }, [initial?.password]);

  // Mettre à jour la force quand le mot de passe change
  const handlePasswordChange = (e) => {
    const password = e.target.value;
    const analysis = analyzePassword(password);
    setPasswordStrength(analysis);
  };

  useEffect(() => {
    // Focus sur le premier champ quand la modale s'ouvre
    nameRef.current?.focus();
  }, []);

  useEffect(() => {
    // Fermer sur ESC, sans bloquer la saisie normale
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  // ========================================
  // GESTION DES CHAMPS PERSONNALISÉS
  // ========================================
  // Permet d'ajouter des paires clé/valeur supplémentaires
  // Les champs marqués "protected" sont masqués comme des mots de passe

  /** Ajoute un nouveau champ personnalisé vide */
  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '', protected: false }]);
  };

  /** Supprime un champ personnalisé par son index */
  const removeCustomField = (index) => {
    setCustomFields(customFields.filter((_, i) => i !== index));
  };

  /** Met à jour une propriété d'un champ personnalisé */
  const updateCustomField = (index, field, value) => {
    const updated = [...customFields];
    updated[index][field] = value;
    setCustomFields(updated);
  };

  const handleFileUpload = (e) => {
    const files = Array.from(e.target.files || []);
    const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB max par fichier (limite sécuritaire pour Vault)

    files.forEach(file => {
      if (file.size > MAX_FILE_SIZE) {
        alert(`Le fichier "${file.name}" est trop volumineux (${(file.size / 1024 / 1024).toFixed(2)} MB).\nTaille maximale: 2 MB`);
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        setAttachments(prev => [...prev, {
          name: file.name,
          size: file.size,
          type: file.type,
          data: event.target.result.split(',')[1] // Retirer le préfixe data:...;base64,
        }]);
      };
      reader.readAsDataURL(file);
    });
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const removeAttachment = (index) => {
    setAttachments(attachments.filter((_, i) => i !== index));
  };

  const downloadAttachment = (attachment) => {
    // SÉCURITÉ: Forcer application/octet-stream pour empêcher l'exécution de contenu actif
    // SÉCURITÉ: Sanitiser le nom de fichier (path traversal, caractères Windows interdits)
    const safeName = (attachment.name || 'attachment')
      .replace(/[/\\:*?"<>|]/g, '_')
      .replace(/\.\./g, '_')
      .replace(/^\.+/, '_')
      .slice(0, 200);
    const link = document.createElement('a');
    link.href = `data:application/octet-stream;base64,${attachment.data}`;
    link.download = safeName;
    link.click();
  };

  /**
   * Copie un texte dans le presse-papier
   * SÉCURITÉ: Ne pas logger le contenu copié
   */
  const copyToClipboard = async (text, label) => {
    try {
      // SÉCURITÉ: Utiliser le clipboard sécurisé avec auto-clear (12s) si disponible
      if (window.electronClipboard?.copySecure) {
        await window.electronClipboard.copySecure(text);
      } else {
        await navigator.clipboard.writeText(text);
      }
    } catch (err) {
      // Erreur copie presse-papier
    }
  };

  /**
   * Sauvegarde le secret après validation des champs
   * SÉCURITÉ: Valide tous les inputs avant de les envoyer à Vault
   */
  const save = () => {
    const name = nameRef.current?.value ?? '';
    const errors = {};

    // ========================================
    // VALIDATION DU NOM (obligatoire pour tous les types)
    // ========================================
    const nameValidation = validateSecretName(name);
    if (!nameValidation.valid) {
      errors.name = nameValidation.error;
    }

    // ========================================
    // VALIDATION SPÉCIFIQUE PAR TYPE
    // ========================================
    if (entryType === 'folder') {
      // Pour les dossiers, seul le nom est validé
      if (Object.keys(errors).length > 0) {
        setValidationErrors(errors);
        return;
      }
      setValidationErrors({});
      onSave({
        name,
        entryType: 'folder'
      });
      return;
    }

    if (entryType === 'ssh') {
      // Validation des champs SSH
      const privateKey = privateKeyRef.current?.value ?? '';
      const publicKey = publicKeyRef.current?.value ?? '';
      const passphrase = passphraseRef.current?.value ?? '';

      // La clé privée est obligatoire pour SSH
      if (!privateKey.trim()) {
        errors.privateKey = t('error.privateKeyRequired');
      } else if (privateKey.length > 10000) {
        errors.privateKey = t('error.privateKeyTooLong');
      }

      // Validation optionnelle de la passphrase
      if (passphrase) {
        const passphraseValidation = validatePassword(passphrase);
        if (!passphraseValidation.valid) {
          errors.passphrase = passphraseValidation.error;
        }
      }

      if (Object.keys(errors).length > 0) {
        setValidationErrors(errors);
        return;
      }

      setValidationErrors({});
      // Pour les clés SSH, on mappe les champs sur les champs standards
      // Mapping: privateKey → password, publicKey → url, passphrase → username
      onSave({
        name,
        username: passphrase, // Passphrase → username
        password: privateKey, // Clé privée → password
        url: publicKey, // Clé publique → url
        website: '', // Non utilisé pour SSH
        notes: notesRef.current?.value ?? '',
        tags: tagsRef.current?.value ?? '',
        customFields,
        attachments,
        entryType: 'ssh'
      });
    } else {
      // ========================================
      // VALIDATION DES SECRETS NORMAUX
      // ========================================
      const username = usernameRef.current?.value ?? '';
      const password = passwordRef.current?.value ?? '';
      const url = urlRef.current?.value ?? '';

      // Validation du username (optionnel mais si présent, doit être valide)
      if (username) {
        const usernameValidation = validateUsername(username);
        if (!usernameValidation.valid) {
          errors.username = usernameValidation.error;
        }
      }

      // Validation du password (optionnel mais si présent, doit être valide)
      if (password) {
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
          errors.password = passwordValidation.error;
        }
      }

      // Validation de l'URL (optionnelle mais si présente, doit être valide)
      if (url && !isValidUrl(url)) {
        errors.url = 'URL invalide (protocoles autorisés: http, https, ftp, ftps, ssh, rdp, sftp)';
      }

      // Validation des champs personnalisés
      customFields.forEach((field, index) => {
        if (field.key && field.key.length > 256) {
          errors[`customField_${index}_key`] = `Nom du champ ${index + 1} trop long`;
        }
        if (field.value && field.value.length > 10000) {
          errors[`customField_${index}_value`] = `Valeur du champ ${index + 1} trop longue`;
        }
      });

      if (Object.keys(errors).length > 0) {
        setValidationErrors(errors);
        return;
      }

      setValidationErrors({});
      // Secret normal
      onSave({
        name,
        username,
        password,
        url,
        notes: notesRef.current?.value ?? '',
        tags: tagsRef.current?.value ?? '',
        customFields,
        attachments,
        entryType: 'secret'
      });
    }
  };

  // ========================================
  // GESTION FERMETURE MODALE PAR CLIC OVERLAY
  // ========================================
  // Détecte les vrais clics (pas les drags) sur l'overlay pour fermer la modale
  // Évite les fermetures accidentelles lors de la sélection de texte

  /**
   * Enregistre la position du mouseDown sur l'overlay
   * Utilisé pour différencier un clic d'un drag
   */
  const handleOverlayMouseDown = (e) => {
    if (e.target.className === 'modal-overlay') {
      setMouseDownPos({ x: e.clientX, y: e.clientY });
    }
  };

  /**
   * Ferme la modale si le mouseUp est proche du mouseDown (< 5px)
   * Cela permet de distinguer un clic intentionnel d'un drag
   */
  const handleOverlayMouseUp = (e) => {
    if (e.target.className === 'modal-overlay' && mouseDownPos) {
      const deltaX = Math.abs(e.clientX - mouseDownPos.x);
      const deltaY = Math.abs(e.clientY - mouseDownPos.y);

      // Ne fermer que si le mouvement est inférieur à 5px (vrai clic, pas drag)
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
      >
        <div className="modal-header">
          <h2>
            {isCreate
              ? (initial?.name?.endsWith('/')
                ? <>{t('editSecret.newEntry')} <code style={{ fontWeight: 'normal', fontSize: '0.85em' }}>/{initial.name}</code></>
                : t('editSecret.newEntry'))
              : <>{t('editSecret.editEntry')} <code>{initial?.name}</code></>}
          </h2>
        </div>

        <div className="modal-body">
          {/* Sélecteur de type d'entrée */}
          {isCreate && (
            <div className="form-group-vertical">
              <label className="modal-label">{t('editSecret.entryType')}</label>
              <div style={{ display: 'flex', gap: 'var(--sp-5)', marginBottom: 'var(--sp-3)' }}>
                <label className="checkbox-label">
                  <input
                    type="radio"
                    name="entryType"
                    checked={entryType === 'secret'}
                    onChange={() => setEntryType('secret')}
                  />
                  <span>🔐 {t('editSecret.typeSecret')}</span>
                </label>
                <label className="checkbox-label">
                  <input
                    type="radio"
                    name="entryType"
                    checked={entryType === 'ssh'}
                    onChange={() => setEntryType('ssh')}
                  />
                  <span>🔑 {t('editSecret.typeSsh')}</span>
                </label>
                <label className="checkbox-label">
                  <input
                    type="radio"
                    name="entryType"
                    checked={entryType === 'folder'}
                    onChange={() => setEntryType('folder')}
                  />
                  <span>📁 {t('editSecret.typeFolder')}</span>
                </label>
              </div>
            </div>
          )}

          <div className="form-group-vertical">
            <label className="modal-label">{t('editSecret.name')}</label>
            <input
              ref={nameRef}
              className="modal-input"
              style={{
                background: totpExists && !isCreate ? 'var(--bg-surface-active)' : undefined,
                color: totpExists && !isCreate ? 'var(--text-disabled)' : undefined,
                cursor: totpExists && !isCreate ? 'not-allowed' : undefined,
                borderColor: validationErrors.name ? 'var(--error)' : undefined
              }}
              defaultValue={initial?.name || ''}
              autoComplete="off"
              placeholder={entryType === 'folder' ? t('editSecret.placeholderFolderName') : t('editSecret.placeholderName')}
              disabled={totpExists && !isCreate}
              readOnly={totpExists && !isCreate}
            />
            {validationErrors.name && (
              <div className="form-hint" style={{ color: 'var(--error)' }}>
                ⚠️ {validationErrors.name}
              </div>
            )}
            {!validationErrors.name && totpExists && !isCreate ? (
              <div className="form-hint" style={{ color: 'var(--error)' }}>
                ⚠️ {t('error.totpLocksName')}
              </div>
            ) : !validationErrors.name && isCreate && entryType !== 'folder' && (
              <div className="form-hint">
                💡 Utilisez "/" pour organiser vos secrets en dossiers (ex: "production/base-donnees/mysql")
              </div>
            )}
          </div>

          {/* Champs pour Secret */}
          {entryType === 'secret' && (
            <>
              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.username')}</label>
                <input
                  ref={usernameRef}
                  className="modal-input"
                  style={{ borderColor: validationErrors.username ? 'var(--error)' : undefined }}
                  defaultValue={initial?.username || ''}
                  autoComplete="off"
                />
                {validationErrors.username && (
                  <div className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.username}
                  </div>
                )}
              </div>

              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.password')}</label>
                <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                  <input
                    ref={passwordRef}
                    className="modal-input"
                    style={{
                      flex: '1',
                      minWidth: '200px',
                      marginBottom: 0,
                      borderColor: validationErrors.password ? 'var(--error)' : undefined
                    }}
                    defaultValue={initial?.password || ''}
                    autoComplete="off"
                    onChange={handlePasswordChange}
                  />
                  <button
                    onClick={() => setShowPasswordGenerator(true)}
                    className="btn btn-secondary"
                    type="button"
                  >
                    {t('editSecret.generatePassword')}
                  </button>
                </div>
                {validationErrors.password && (
                  <div className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.password}
                  </div>
                )}

                {/* Indicateur de force du mot de passe */}
                {passwordRef.current?.value && passwordStrength.entropy > 0 && (
                  <div style={{ marginTop: 'var(--sp-2)' }}>
                    <div className="clipboard-progress">
                      <div
                        className="clipboard-progress-bar"
                        style={{
                          width: `${passwordStrength.percentage}%`,
                          background: passwordStrength.color,
                          transition: 'width 0.3s, background 0.3s'
                        }}
                      />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 'var(--sp-1)' }}>
                      <span>{t('editSecret.strength')} <strong style={{ color: passwordStrength.color }}>{passwordStrength.strength}</strong></span>
                      <span>{t('editSecret.entropy')} <strong>{passwordStrength.entropy} bits</strong></span>
                    </div>
                  </div>
                )}
              </div>

              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.url')}</label>
                <input
                  ref={urlRef}
                  className="modal-input"
                  style={{ borderColor: validationErrors.url ? 'var(--error)' : undefined }}
                  defaultValue={initial?.url || ''}
                  autoComplete="off"
                />
                {validationErrors.url && (
                  <div className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.url}
                  </div>
                )}
              </div>
            </>
          )}

          {/* Champs pour Clé SSH */}
          {entryType === 'ssh' && (
            <>
              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.privateKey')}</label>
                <div style={{ position: 'relative' }}>
                  <textarea
                    ref={privateKeyRef}
                    className="modal-textarea"
                    defaultValue={initial?.password || ''}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                    style={{
                      fontFamily: 'monospace',
                      fontSize: 'var(--text-sm)',
                      minHeight: '120px',
                      borderColor: validationErrors.privateKey ? 'var(--error)' : undefined
                    }}
                  />
                  <button
                    onClick={() => copyToClipboard(privateKeyRef.current?.value, 'Clé privée')}
                    className="btn btn-sm btn-secondary"
                    type="button"
                    style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
                    title="Copier la clé privée"
                  >
                    📋
                  </button>
                </div>
                {validationErrors.privateKey && (
                  <div className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.privateKey}
                  </div>
                )}
              </div>

              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.publicKey')}</label>
                <div style={{ position: 'relative' }}>
                  <textarea
                    ref={publicKeyRef}
                    className="modal-textarea"
                    defaultValue={initial?.url || ''}
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
                    📋
                  </button>
                </div>
              </div>

              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.passphrase')}</label>
                <input
                  ref={passphraseRef}
                  className="modal-input"
                  type="password"
                  defaultValue={initial?.username || ''}
                  autoComplete="off"
                  placeholder="Passphrase de protection"
                  style={{ borderColor: validationErrors.passphrase ? 'var(--error)' : undefined }}
                />
                {validationErrors.passphrase && (
                  <div className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.passphrase}
                  </div>
                )}
              </div>
            </>
          )}

          {/* Notes, Tags, Champs personnalisés, Fichiers joints - masqués pour les dossiers */}
          {entryType !== 'folder' && (
            <>
              <div className="form-group-vertical">
                <label className="modal-label">{t('editSecret.notes')}</label>
                <textarea ref={notesRef} className="modal-textarea" defaultValue={initial?.notes || ''} />
              </div>

              <div className="form-group-vertical" style={{ position: 'relative' }}>
                <label className="modal-label">{t('editSecret.tags')}</label>
                <input
                  ref={tagsRef}
                  className="modal-input"
                  defaultValue={initial?.tags || ''}
                  autoComplete="off"
                  placeholder="ex: #dev #prod #important"
                  onChange={(e) => {
                    const value = e.target.value;
                    // Extraire le dernier mot en cours de saisie
                    const words = value.split(/\s+/);
                    const lastWord = words[words.length - 1] || '';
                    if (lastWord.length > 0 && existingTags.length > 0) {
                      const query = lastWord.replace(/^#/, '').toLowerCase();
                      const matches = existingTags.filter(t =>
                        t.replace(/^#/, '').toLowerCase().includes(query) && t.toLowerCase() !== lastWord.toLowerCase()
                      );
                      setTagSuggestions(matches.slice(0, 8));
                      setShowTagSuggestions(matches.length > 0);
                    } else {
                      setShowTagSuggestions(false);
                    }
                  }}
                  onFocus={() => {
                    const value = tagsRef.current?.value || '';
                    const words = value.split(/\s+/);
                    const lastWord = words[words.length - 1] || '';
                    if (lastWord.length > 0 && existingTags.length > 0) {
                      const query = lastWord.replace(/^#/, '').toLowerCase();
                      const matches = existingTags.filter(t =>
                        t.replace(/^#/, '').toLowerCase().includes(query)
                      );
                      setTagSuggestions(matches.slice(0, 8));
                      setShowTagSuggestions(matches.length > 0);
                    }
                  }}
                  onBlur={() => setTimeout(() => setShowTagSuggestions(false), 200)}
                />
                {showTagSuggestions && tagSuggestions.length > 0 && (
                  <div style={{
                    position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 100,
                    background: 'var(--bg-surface)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-md)', boxShadow: 'var(--shadow-lg)',
                    maxHeight: '160px', overflowY: 'auto'
                  }}>
                    {tagSuggestions.map((tag, i) => (
                      <div key={i}
                        style={{
                          padding: 'var(--sp-2) var(--sp-3)', cursor: 'pointer',
                          fontSize: 'var(--text-sm)', color: 'var(--text-primary)'
                        }}
                        onMouseEnter={(e) => e.target.style.background = 'var(--bg-hover)'}
                        onMouseLeave={(e) => e.target.style.background = 'transparent'}
                        onMouseDown={(e) => {
                          e.preventDefault();
                          const input = tagsRef.current;
                          if (!input) return;
                          const words = input.value.split(/\s+/);
                          words[words.length - 1] = tag;
                          input.value = words.join(' ') + ' ';
                          setShowTagSuggestions(false);
                          input.focus();
                        }}
                      >
                        {tag}
                      </div>
                    ))}
                  </div>
                )}
                <div className="form-hint">Séparez les tags par des espaces. Ex: #dev #prod</div>
              </div>

              {/* Champs personnalisés */}
              <div className="form-group-vertical">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
                  <label className="modal-label" style={{ marginBottom: 0 }}>{t('editSecret.customFields')}</label>
                  <button onClick={addCustomField} className="btn btn-sm btn-secondary" type="button">+ {t('editSecret.addField')}</button>
                </div>
                {customFields.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                    {customFields.map((field, index) => (
                      <div key={index} style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center', background: 'var(--bg-surface)', padding: 'var(--sp-2)', borderRadius: 'var(--radius)' }}>
                        <input
                          className="modal-input"
                          style={{ flex: '1', marginBottom: 0 }}
                          placeholder={t('editSecret.fieldKey')}
                          value={field.key}
                          onChange={(e) => updateCustomField(index, 'key', e.target.value)}
                        />
                        <input
                          className="modal-input"
                          style={{ flex: '2', marginBottom: 0 }}
                          type={field.protected ? 'password' : 'text'}
                          placeholder={t('editSecret.fieldValue')}
                          value={field.value}
                          onChange={(e) => updateCustomField(index, 'value', e.target.value)}
                        />
                        <label className="checkbox-label" style={{ marginBottom: 0, whiteSpace: 'nowrap' }}>
                          <input
                            type="checkbox"
                            checked={field.protected}
                            onChange={(e) => updateCustomField(index, 'protected', e.target.checked)}
                          />
                          <span>Protégé</span>
                        </label>
                        <button onClick={() => removeCustomField(index)} className="btn btn-sm btn-danger" type="button">×</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Fichiers joints */}
              <div className="form-group-vertical">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
                  <div>
                    <label className="modal-label" style={{ marginBottom: 0 }}>{t('editSecret.attachments')}</label>
                    <div className="form-hint" style={{ marginTop: 'var(--sp-1)' }}>Taille max: 2 MB par fichier</div>
                  </div>
                  <label className="btn btn-sm btn-secondary" style={{ cursor: 'pointer' }}>
                    + {t('editSecret.addAttachment')}
                    <input
                      ref={fileInputRef}
                      type="file"
                      multiple
                      style={{ display: 'none' }}
                      onChange={handleFileUpload}
                    />
                  </label>
                </div>
                {attachments.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                    {attachments.map((att, index) => (
                      <div key={index} style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center', background: 'var(--bg-surface)', padding: 'var(--sp-2)', borderRadius: 'var(--radius)' }}>
                        <span style={{ flex: 1, fontSize: 'var(--text-sm)' }}>📎 {att.name}</span>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                          {att.size > 1024 * 1024
                            ? `${(att.size / 1024 / 1024).toFixed(2)} MB`
                            : `${(att.size / 1024).toFixed(1)} KB`}
                        </span>
                        <button onClick={() => downloadAttachment(att)} className="btn btn-sm btn-secondary" type="button">⬇</button>
                        <button onClick={() => removeAttachment(index)} className="btn btn-sm btn-danger" type="button">×</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        <div className="modal-footer">
          <span className="form-hint" style={{ flex: 1, marginTop: 0, marginBottom: 0 }}>
            {entryType === 'folder'
              ? 'Un dossier vide sera créé dans le coffre sélectionné.'
              : 'Les clés seront écrites sur le moteur sélectionné (kv1/kv2 détecté automatiquement).'}
          </span>
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('editSecret.cancel')}
          </button>
          <button onClick={save} className="btn btn-primary" type="button">
            {t('editSecret.save')}
          </button>
        </div>
      </div>

      {/* Modal de génération de mot de passe */}
      {showPasswordGenerator && (
        <PasswordGeneratorModal
          onClose={() => setShowPasswordGenerator(false)}
          onAccept={(password) => {
            if (passwordRef.current) {
              passwordRef.current.value = password;
              // Mettre à jour la force
              const analysis = analyzePassword(password);
              setPasswordStrength(analysis);
            }
            setShowPasswordGenerator(false);
          }}
        />
      )}
    </div>
  );
}
