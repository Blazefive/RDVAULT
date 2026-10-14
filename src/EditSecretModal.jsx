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

import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import PasswordGeneratorModal from './PasswordGeneratorModal';
import { useDialogA11y, getFocusableElements } from './components/common/Modal';
import { analyzePassword, STRENGTH_LABEL_KEYS } from './utils/passwordStrength';
import { validateSecretName, validateUsername, validatePassword, isValidUrl, translateValidationError } from './validation';
import { copySecureWithAutoClear } from './utils/clipboard';
import { useTranslation } from './i18n';

// Longueur maximale des notes : même borne que validateSecret (validation.js), appliquée à
// l'écriture. Contrôlée dès la fiche pour afficher une erreur traduite sous le champ plutôt
// qu'un refus générique au moment de l'enregistrement.
const NOTES_MAX_LENGTH = 10000;

/**
 * I18N-34 : nombre formaté selon la langue de l'interface (séparateur décimal : « 1,5 » en
 * français / russe / allemand, « 1.5 » en anglais). Chiffres latins imposés (arabe compris) :
 * toute l'interface et ses traductions affichent des chiffres latins.
 */
function formatDecimal(value, lang, maximumFractionDigits) {
  try {
    return new Intl.NumberFormat(lang, { maximumFractionDigits, numberingSystem: 'latn' }).format(value);
  } catch {
    return String(Number(value.toFixed(maximumFractionDigits)));
  }
}

/** Taille de pièce jointe lisible : « 1,5 Mo », « 1.5 MB », « 512 KB »… (unité traduite) */
function formatFileSize(bytes, lang, t) {
  return bytes > 1024 * 1024
    ? t('editSecret.sizeMB', { size: formatDecimal(bytes / 1024 / 1024, lang, 2) })
    : t('editSecret.sizeKB', { size: formatDecimal(bytes / 1024, lang, 1) });
}

/**
 * Modal de création/édition de secrets Vault
 *
 * @param {Object} props - Props du composant
 * @param {Object} props.initial - Données initiales du secret (null pour création)
 * @param {Function} props.onClose - Callback de fermeture
 * @param {Function} props.onSave - Callback de sauvegarde avec les données validées
 * @param {boolean} props.totpExists - Si true, le nom ne peut pas être modifié (TOTP configuré)
 * @param {boolean} [props.totpPending] - Vérification TOTP en cours : nom d'une entrée existante en lecture seule
 * @param {Function} [props.showToast] - Affichage des messages (remplace alert(), non supporté par Electron)
 */
export default function EditSecretModal({ initial, onClose, onSave, totpExists = false, totpPending = false, existingTags = [], showToast }) {
  const { t, lang } = useTranslation();
  const [showPasswordGenerator, setShowPasswordGenerator] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({ entropy: 0, level: '', color: '', percentage: 0 });
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
  const panelRef = useRef(null);
  const generatorHostRef = useRef(null);
  // Libellés associés aux champs (htmlFor/id) : nom accessible + clic sur le libellé = focus du champ
  const ids = {
    title: useId(),
    entryType: useId(),
    name: useId(),
    username: useId(),
    password: useId(),
    url: useId(),
    privateKey: useId(),
    publicKey: useId(),
    passphrase: useId(),
    notes: useId(),
    tags: useId(),
    customFields: useId(),
    attachments: useId(),
    errors: useId(),
  };

  // UI-33 : message d'erreur relié à son champ (aria-describedby) et champ marqué invalide
  // (aria-invalid) ; sans erreur, aucun attribut (pas d'aria-invalid="false" superflu).
  const errorId = (key) => `${ids.errors}-${key}`;
  const fieldErrorProps = (key) => (validationErrors[key]
    ? { 'aria-invalid': true, 'aria-describedby': errorId(key) }
    : {});

  // UI-33 : après un enregistrement refusé, focus sur le premier champ en erreur (ordre du
  // formulaire) : le lecteur d'écran lit son libellé, l'état « invalide » et le message.
  useEffect(() => {
    if (Object.keys(validationErrors).length === 0) return;
    const first = panelRef.current?.querySelector('[aria-invalid="true"]:not([disabled])');
    if (first) first.focus();
  }, [validationErrors]);

  const isCreate = !initial || !initial.name || initial.name.endsWith('/');
  // Dossier parent (préfixe « a/b/ ») lors d'une création dans un sous-dossier, vide à la racine
  const parentPath = initial?.name?.endsWith('/') ? initial.name : '';

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

  // Nom verrouillé par un TOTP détecté APRÈS l'ouverture (la fiche s'affiche sans attendre la
  // vérification) : le champ devient désactivé ; s'il avait le focus, celui-ci passe au premier
  // élément focalisable de la fiche (comme à une ouverture avec un nom déjà verrouillé).
  const nameLocked = totpExists && !isCreate;
  useEffect(() => {
    if (!nameLocked) return;
    const active = document.activeElement;
    if (active !== nameRef.current && active && active !== document.body) return;
    const [first] = getFocusableElements(panelRef.current);
    if (first) first.focus();
  }, [nameLocked]);

  // Fermer sur ESC, sans bloquer la saisie normale ; focus initial, piège de focus et retour
  // du focus au déclencheur (hook du squelette commun Modal).
  // BUG CORRIGÉ : Échap pressé dans le générateur de mot de passe (sous-modale) fermait AUSSI
  // la fiche (saisie non enregistrée perdue) : la fiche ignore Échap tant que le générateur est
  // ouvert (le hook ne réagit de toute façon que pour le dialogue du dessus).
  useDialogA11y(panelRef, { onEscape: onClose, escapeDisabled: showPasswordGenerator });

  // Sous-modale du générateur (composant sans gestion du focus) : focus dedans à l'ouverture,
  // piège de focus, puis retour au bouton « Générer... » à la fermeture.
  const generatorPanelRef = useMemo(() => ({
    get current() { return generatorHostRef.current?.querySelector('.modal-panel') || null; }
  }), []);
  useDialogA11y(generatorPanelRef, { active: showPasswordGenerator });

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
        const message = t('editSecret.fileTooLarge', { name: file.name, size: formatDecimal(file.size / 1024 / 1024, lang, 2) });
        if (typeof showToast === 'function') showToast(message, 'error', 4000);
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
  const copyToClipboard = async (text) => {
    try {
      // SÉCURITÉ: presse-papiers sécurisé avec auto-effacement (12 s) + fallback navigateur
      await copySecureWithAutoClear(text);
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
    // Messages de validation.js affichés dans la langue de l'interface (I18N-28)
    const nameValidation = validateSecretName(name);
    if (!nameValidation.valid) {
      errors.name = translateValidationError(nameValidation, t);
    }

    // Notes (secrets et clés SSH ; champ absent pour un dossier)
    const notes = notesRef.current?.value ?? '';
    if (entryType !== 'folder' && notes.length > NOTES_MAX_LENGTH) {
      errors.notes = t('error.notesTooLong');
    }

    // ========================================
    // VALIDATION SPÉCIFIQUE PAR TYPE
    // ========================================
    if (entryType === 'folder') {
      // Pour les dossiers, seul le nom est validé.
      // En vue arborescence, le champ est pré-rempli avec le dossier courant (« a/b/ ») et
      // useSecrets (handleEditSecretSave) préfixe ENCORE ce dossier courant : on retire donc
      // le préfixe pré-rempli, sinon le dossier serait créé dans « a/b/a/b/x » au lieu de
      // « a/b/x » annoncé en pied de modale.
      const trimmedName = name.trim();
      const folderName = parentPath && trimmedName.startsWith(parentPath)
        ? trimmedName.slice(parentPath.length)
        : name;
      if (!errors.name && !folderName.replace(/\/+$/, '').trim()) {
        errors.name = t('error.nameRequired');
      }
      if (Object.keys(errors).length > 0) {
        setValidationErrors(errors);
        return;
      }
      setValidationErrors({});
      onSave({
        name: folderName,
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
          errors.passphrase = translateValidationError(passphraseValidation, t);
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
        notes,
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
          errors.username = translateValidationError(usernameValidation, t);
        }
      }

      // Validation du password (optionnel mais si présent, doit être valide)
      if (password) {
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.valid) {
          errors.password = translateValidationError(passwordValidation, t);
        }
      }

      // Validation de l'URL (optionnelle mais si présente, doit être valide)
      if (url && !isValidUrl(url)) {
        errors.url = t('error.invalidUrl');
      }

      // Validation des champs personnalisés (erreurs affichées sous chaque ligne de champ)
      customFields.forEach((field, index) => {
        if (field.key && field.key.length > 256) {
          errors[`customField_${index}_key`] = t('error.customFieldKeyTooLong', { index: index + 1 });
        }
        if (field.value && field.value.length > 10000) {
          errors[`customField_${index}_value`] = t('error.customFieldValueTooLong', { index: index + 1 });
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
        notes,
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
  // BUG CORRIGÉ : le test sur la classe « modal-overlay » visait aussi le fond du générateur
  // (même classe, rendu à l'intérieur de cet overlay) : un clic sur ce fond fermait la fiche.
  const handleOverlayMouseDown = (e) => {
    if (e.target === e.currentTarget) {
      setMouseDownPos({ x: e.clientX, y: e.clientY });
    }
  };

  /**
   * Ferme la modale si le mouseUp est proche du mouseDown (< 5px)
   * Cela permet de distinguer un clic intentionnel d'un drag
   */
  const handleOverlayMouseUp = (e) => {
    if (e.target === e.currentTarget && mouseDownPos) {
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
        ref={panelRef}
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={ids.title}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <h2 id={ids.title}>
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
              <div className="modal-label" id={ids.entryType}>{t('editSecret.entryType')}</div>
              <div role="radiogroup" aria-labelledby={ids.entryType} style={{ display: 'flex', gap: 'var(--sp-5)', marginBottom: 'var(--sp-3)' }}>
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
            <label className="modal-label" htmlFor={ids.name}>{t('editSecret.name')}</label>
            <input
              id={ids.name}
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
              disabled={nameLocked}
              readOnly={nameLocked || (totpPending && !isCreate)}
              aria-required="true"
              {...fieldErrorProps('name')}
            />
            {validationErrors.name && (
              <div id={errorId('name')} className="form-hint" style={{ color: 'var(--error)' }}>
                ⚠️ {validationErrors.name}
              </div>
            )}
            {!validationErrors.name && totpExists && !isCreate ? (
              <div className="form-hint" style={{ color: 'var(--error)' }}>
                ⚠️ {t('error.totpLocksName')}
              </div>
            ) : !validationErrors.name && isCreate && entryType !== 'folder' && (
              <div className="form-hint">
                💡 {t('editSecret.folderHint')}
              </div>
            )}
          </div>

          {/* Champs pour Secret */}
          {entryType === 'secret' && (
            <>
              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={ids.username}>{t('editSecret.username')}</label>
                <input
                  id={ids.username}
                  ref={usernameRef}
                  className="modal-input"
                  style={{ borderColor: validationErrors.username ? 'var(--error)' : undefined }}
                  defaultValue={initial?.username || ''}
                  autoComplete="off"
                  {...fieldErrorProps('username')}
                />
                {validationErrors.username && (
                  <div id={errorId('username')} className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.username}
                  </div>
                )}
              </div>

              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={ids.password}>{t('editSecret.password')}</label>
                <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                  <input
                    id={ids.password}
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
                    {...fieldErrorProps('password')}
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
                  <div id={errorId('password')} className="form-hint" style={{ color: 'var(--error)' }}>
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
                      <span>{t('editSecret.strength')} <strong style={{ color: passwordStrength.color }}>{t(STRENGTH_LABEL_KEYS[passwordStrength.level])}</strong></span>
                      <span>{t('editSecret.entropy')} <strong>{passwordStrength.entropy} {t('passwordGenerator.bits')}</strong></span>
                    </div>
                  </div>
                )}
              </div>

              {/* I18N-31 : URL et clés SSH sont des données techniques latines, saisies de gauche
                  à droite même dans l'interface arabe (dir="ltr" : sans effet dans les autres langues) */}
              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={ids.url}>{t('editSecret.url')}</label>
                <input
                  id={ids.url}
                  ref={urlRef}
                  className="modal-input"
                  dir="ltr"
                  style={{ borderColor: validationErrors.url ? 'var(--error)' : undefined }}
                  defaultValue={initial?.url || ''}
                  autoComplete="off"
                  {...fieldErrorProps('url')}
                />
                {validationErrors.url && (
                  <div id={errorId('url')} className="form-hint" style={{ color: 'var(--error)' }}>
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
                <label className="modal-label" htmlFor={ids.privateKey}>{t('editSecret.privateKey')}</label>
                <div style={{ position: 'relative' }}>
                  <textarea
                    id={ids.privateKey}
                    ref={privateKeyRef}
                    className="modal-textarea"
                    dir="ltr"
                    defaultValue={initial?.password || ''}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
                    style={{
                      fontFamily: 'monospace',
                      fontSize: 'var(--text-sm)',
                      minHeight: '120px',
                      borderColor: validationErrors.privateKey ? 'var(--error)' : undefined
                    }}
                    {...fieldErrorProps('privateKey')}
                  />
                  <button
                    onClick={() => copyToClipboard(privateKeyRef.current?.value)}
                    className="btn btn-sm btn-secondary"
                    type="button"
                    style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
                    title={t('editSecret.copyPrivateKey')}
                    aria-label={t('editSecret.copyPrivateKey')}
                  >
                    📋
                  </button>
                </div>
                {validationErrors.privateKey && (
                  <div id={errorId('privateKey')} className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.privateKey}
                  </div>
                )}
              </div>

              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={ids.publicKey}>{t('editSecret.publicKey')}</label>
                <div style={{ position: 'relative' }}>
                  <textarea
                    id={ids.publicKey}
                    ref={publicKeyRef}
                    className="modal-textarea"
                    dir="ltr"
                    defaultValue={initial?.url || ''}
                    placeholder="ssh-rsa AAAAB3NzaC1yc2EA..."
                    style={{ fontFamily: 'monospace', fontSize: 'var(--text-sm)', minHeight: '80px' }}
                  />
                  <button
                    onClick={() => copyToClipboard(publicKeyRef.current?.value)}
                    className="btn btn-sm btn-secondary"
                    type="button"
                    style={{ position: 'absolute', top: 'var(--sp-2)', right: 'var(--sp-2)' }}
                    title={t('editSecret.copyPublicKey')}
                    aria-label={t('editSecret.copyPublicKey')}
                  >
                    📋
                  </button>
                </div>
              </div>

              <div className="form-group-vertical">
                <label className="modal-label" htmlFor={ids.passphrase}>{t('editSecret.passphrase')}</label>
                <input
                  id={ids.passphrase}
                  ref={passphraseRef}
                  className="modal-input"
                  type="password"
                  defaultValue={initial?.username || ''}
                  autoComplete="off"
                  placeholder={t('sshKey.passphrasePlaceholder')}
                  style={{ borderColor: validationErrors.passphrase ? 'var(--error)' : undefined }}
                  {...fieldErrorProps('passphrase')}
                />
                {validationErrors.passphrase && (
                  <div id={errorId('passphrase')} className="form-hint" style={{ color: 'var(--error)' }}>
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
                <label className="modal-label" htmlFor={ids.notes}>{t('editSecret.notes')}</label>
                <textarea
                  id={ids.notes}
                  ref={notesRef}
                  className="modal-textarea"
                  defaultValue={initial?.notes || ''}
                  style={{ borderColor: validationErrors.notes ? 'var(--error)' : undefined }}
                  {...fieldErrorProps('notes')}
                />
                {validationErrors.notes && (
                  <div id={errorId('notes')} className="form-hint" style={{ color: 'var(--error)' }}>
                    ⚠️ {validationErrors.notes}
                  </div>
                )}
              </div>

              <div className="form-group-vertical" style={{ position: 'relative' }}>
                <label className="modal-label" htmlFor={ids.tags}>{t('editSecret.tags')}</label>
                <input
                  id={ids.tags}
                  ref={tagsRef}
                  className="modal-input"
                  defaultValue={initial?.tags || ''}
                  autoComplete="off"
                  placeholder={t('editSecret.tagsPlaceholder')}
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
                <div className="form-hint">{t('editSecret.tagsHint')}</div>
              </div>

              {/* Champs personnalisés */}
              <div className="form-group-vertical">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
                  <div className="modal-label" id={ids.customFields} style={{ marginBottom: 0 }}>{t('editSecret.customFields')}</div>
                  <button onClick={addCustomField} className="btn btn-sm btn-secondary" type="button">+ {t('editSecret.addField')}</button>
                </div>
                {customFields.length > 0 && (
                  <div role="group" aria-labelledby={ids.customFields} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                    {customFields.map((field, index) => (
                      <React.Fragment key={index}>
                        <div style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center', background: 'var(--bg-surface)', padding: 'var(--sp-2)', borderRadius: 'var(--radius)' }}>
                          <input
                            className="modal-input"
                            style={{ flex: '1', marginBottom: 0, borderColor: validationErrors[`customField_${index}_key`] ? 'var(--error)' : undefined }}
                            placeholder={t('editSecret.fieldKey')}
                            aria-label={t('editSecret.fieldKey')}
                            {...fieldErrorProps(`customField_${index}_key`)}
                            value={field.key}
                            onChange={(e) => updateCustomField(index, 'key', e.target.value)}
                          />
                          <input
                            className="modal-input"
                            style={{ flex: '2', marginBottom: 0, borderColor: validationErrors[`customField_${index}_value`] ? 'var(--error)' : undefined }}
                            type={field.protected ? 'password' : 'text'}
                            placeholder={t('editSecret.fieldValue')}
                            aria-label={t('editSecret.fieldValue')}
                            {...fieldErrorProps(`customField_${index}_value`)}
                            value={field.value}
                            onChange={(e) => updateCustomField(index, 'value', e.target.value)}
                          />
                          <label className="checkbox-label" style={{ marginBottom: 0, whiteSpace: 'nowrap' }}>
                            <input
                              type="checkbox"
                              checked={field.protected}
                              onChange={(e) => updateCustomField(index, 'protected', e.target.checked)}
                            />
                            <span>{t('editSecret.protectedField')}</span>
                          </label>
                          <button
                            onClick={() => removeCustomField(index)}
                            className="btn btn-sm btn-danger"
                            type="button"
                            aria-label={t('editSecret.removeField')}
                            title={t('editSecret.removeField')}
                          >
                            <span aria-hidden="true">×</span>
                          </button>
                        </div>
                        {/* Erreurs de validation de la ligne (sans affichage, Enregistrer échouait en silence) */}
                        {validationErrors[`customField_${index}_key`] && (
                          <div id={errorId(`customField_${index}_key`)} className="form-hint" style={{ color: 'var(--error)' }}>
                            ⚠️ {validationErrors[`customField_${index}_key`]}
                          </div>
                        )}
                        {validationErrors[`customField_${index}_value`] && (
                          <div id={errorId(`customField_${index}_value`)} className="form-hint" style={{ color: 'var(--error)' }}>
                            ⚠️ {validationErrors[`customField_${index}_value`]}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>

              {/* Fichiers joints */}
              <div className="form-group-vertical">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--sp-2)' }}>
                  <div>
                    <div className="modal-label" id={ids.attachments} style={{ marginBottom: 0 }}>{t('editSecret.attachments')}</div>
                    <div className="form-hint" style={{ marginTop: 'var(--sp-1)' }}>{t('editSecret.maxFileSize')}</div>
                  </div>
                  {/* Vrai bouton (focalisable, Entrée / Espace) qui ouvre le sélecteur de fichier
                      masqué : l'ancien <label> stylé en bouton n'était pas atteignable au clavier. */}
                  <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    + {t('editSecret.addAttachment')}
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    tabIndex={-1}
                    aria-hidden="true"
                    style={{ display: 'none' }}
                    onChange={handleFileUpload}
                  />
                </div>
                {attachments.length > 0 && (
                  <div role="group" aria-labelledby={ids.attachments} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                    {attachments.map((att, index) => (
                      <div key={index} style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center', background: 'var(--bg-surface)', padding: 'var(--sp-2)', borderRadius: 'var(--radius)' }}>
                        <span style={{ flex: 1, fontSize: 'var(--text-sm)' }}>📎 {att.name}</span>
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
                          {formatFileSize(att.size, lang, t)}
                        </span>
                        <button
                          onClick={() => downloadAttachment(att)}
                          className="btn btn-sm btn-secondary"
                          type="button"
                          aria-label={t('editSecret.downloadAttachment', { name: att.name })}
                          title={t('editSecret.downloadAttachment', { name: att.name })}
                        >
                          <span aria-hidden="true">⬇</span>
                        </button>
                        <button
                          onClick={() => removeAttachment(index)}
                          className="btn btn-sm btn-danger"
                          type="button"
                          aria-label={t('editSecret.removeAttachment', { name: att.name })}
                          title={t('editSecret.removeAttachment', { name: att.name })}
                        >
                          <span aria-hidden="true">×</span>
                        </button>
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
              ? <>{t('editSecret.folderWillBeCreatedIn')} <code>/{parentPath}</code></>
              : t('editSecret.keysWrittenToEngine')}
          </span>
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('editSecret.cancel')}
          </button>
          <button onClick={save} className="btn btn-primary" type="button">
            {t('editSecret.save')}
          </button>
        </div>
      </div>

      {/* Modal de génération de mot de passe (hôte sans boîte : sert à localiser son panneau) */}
      <div ref={generatorHostRef} style={{ display: 'contents' }}>
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
    </div>
  );
}
