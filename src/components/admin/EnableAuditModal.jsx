// ========================================
// MODALE : Activation d'un audit device (panneau admin)
// ========================================
// Extrait d'AdminPanel.jsx.
//
// Props :
// - onEnable(path, type, description, options) : active le device côté Vault
// - showToast, onClose
//
// Squelette commun Modal (hook useDialogA11y) : role="dialog" nommé par le titre, focus initial
// sur le premier champ, piège de focus, Échap (modale du dessus seulement), retour du focus au
// bouton déclencheur, fermeture sur le fond par mousedown + mouseup ; couleurs du thème.

import React, { useId } from 'react';
import Modal from '../common/Modal';
import { useTranslation } from '../../i18n';
import { ltrWhenFilled } from './i18nHelpers';

export default function EnableAuditModal({ onEnable, showToast, onClose }) {
  const { t } = useTranslation();
  const [deviceName, setDeviceName] = React.useState('file');
  const [deviceType, setDeviceType] = React.useState('file');
  const [description, setDescription] = React.useState('');
  const [filePath, setFilePath] = React.useState('/var/log/vault/vault_audit.log');
  const [useSSH, setUseSSH] = React.useState(false);
  const [sshHost, setSshHost] = React.useState('');
  const [sshPort, setSshPort] = React.useState('22');
  const [sshUsername, setSshUsername] = React.useState('root');
  const [sshPassword, setSshPassword] = React.useState('');
  const [sshHostFingerprint, setSshHostFingerprint] = React.useState('');
  // Libellés associés aux champs (htmlFor/id) : nom accessible + clic sur le libellé = focus du champ
  const ids = {
    name: useId(),
    type: useId(),
    description: useId(),
    filePath: useId(),
    sshHost: useId(),
    sshUser: useId(),
    sshPort: useId(),
    sshPassword: useId(),
    fingerprint: useId(),
  };

  const handleEnable = async () => {
    if (!deviceName.trim()) {
      showToast(t('admin.enableAudit.deviceNameRequired'), 'error');
      return;
    }

    let options = {};
    if (deviceType === 'file') {
      if (!filePath.trim()) {
        showToast(t('admin.enableAudit.filePathRequired'), 'error');
        return;
      }
      // SÉCURITÉ: Valider le chemin de fichier
      const trimmedPath = filePath.trim();
      // eslint-disable-next-line no-control-regex -- volontaire : chemin avec caractère de contrôle refusé
      if (trimmedPath.includes('..') || /[\x00-\x1F]/.test(trimmedPath)) {
        showToast(t('admin.enableAudit.filePathInvalid'), 'error');
        return;
      }
      options = { file_path: trimmedPath };
    }

    // Valider les informations SSH si activé
    if (useSSH) {
      const trimmedHost = sshHost.trim();
      const trimmedUsername = sshUsername.trim();
      if (!trimmedHost) {
        showToast(t('admin.enableAudit.sshHostRequired'), 'error');
        return;
      }
      // SÉCURITÉ: Valider le format du host SSH
      // eslint-disable-next-line no-control-regex -- volontaire : hôte SSH avec caractère de contrôle refusé
      if (trimmedHost.length > 253 || /[\x00-\x1F\s;|&`$(){}@#[\]\\]/.test(trimmedHost)) {
        showToast(t('admin.enableAudit.sshHostInvalid'), 'error');
        return;
      }
      if (!trimmedUsername) {
        showToast(t('admin.enableAudit.sshUserRequired'), 'error');
        return;
      }
      // SÉCURITÉ: Valider le format du username SSH
      if (!/^[a-zA-Z0-9._-]{1,64}$/.test(trimmedUsername)) {
        showToast(t('admin.enableAudit.sshUserInvalid'), 'error');
        return;
      }
      if (!sshPassword.trim()) {
        showToast(t('admin.enableAudit.sshPasswordRequired'), 'error');
        return;
      }
      const parsedPort = parseInt(sshPort) || 22;
      if (parsedPort < 1 || parsedPort > 65535) {
        showToast(t('admin.enableAudit.sshPortInvalid'), 'error');
        return;
      }
      // SÉCURITÉ: Empreinte de clé d'hôte épinglée (facultative) : « SHA256:<base64> », avec ou sans padding
      // (même format que la validation côté main.js)
      const trimmedFingerprint = sshHostFingerprint.trim();
      if (trimmedFingerprint && !/^(SHA256:)?[A-Za-z0-9+/]{43}=?$/i.test(trimmedFingerprint)) {
        showToast(t('admin.enableAudit.fingerprintInvalid'), 'error');
        return;
      }

      // SÉCURITÉ: Sanitiser le nom du device pour la clé localStorage
      const safeDeviceName = deviceName.trim().replace(/[^a-zA-Z0-9._-]/g, '_');

      // Stocker uniquement les infos non-sensibles (PAS le mot de passe)
      const sshConfig = {
        host: trimmedHost,
        port: parsedPort,
        username: trimmedUsername
      };
      // L'empreinte n'est transmise que si elle est renseignée (sinon mémorisation à la première connexion)
      if (trimmedFingerprint) sshConfig.hostFingerprint = trimmedFingerprint;
      localStorage.setItem(`vault-audit-ssh-${safeDeviceName}`, JSON.stringify(sshConfig));
    }

    await onEnable(deviceName.trim(), deviceType, description.trim(), options);
    onClose();
  };

  // Couleurs du thème (variables CSS) : l'ancien panneau blanc codé en dur restait blanc en
  // thème sombre, sous un titre en texte clair illisible.
  const hintStyle = { fontSize: 11, color: 'var(--text-tertiary)' };
  const fieldStyle = { marginBottom: 'var(--sp-4)' };

  return (
    <Modal
      title={`📊 ${t('admin.enableAudit.title')}`}
      onClose={onClose}
      maxWidth="500px"
      footer={(
        <>
          <button type="button" className="btn btn-secondary" onClick={() => onClose()}>
            {t('common.cancel')}
          </button>
          <button type="button" className="btn btn-success" onClick={handleEnable}>
            ✓ {t('admin.common.enable')}
          </button>
        </>
      )}
    >
      <label className="modal-label" htmlFor={ids.name}>{t('admin.enableAudit.nameLabel')}</label>
      {/* ADMIN-11 : valeurs techniques (nom de device = segment de chemin Vault, chemin de fichier,
          hôte, utilisateur, port, empreinte) de gauche à droite, y compris en arabe : sinon
          « /var/log/vault/vault_audit.log » s'affichait « var/log/vault/vault_audit.log/ ».
          Texte indicatif traduit (nom, hôte) : sens de la langue tant que le champ est vide. */}
      <input
        id={ids.name}
        type="text"
        dir={ltrWhenFilled(deviceName)}
        className="modal-input"
        style={fieldStyle}
        placeholder={t('admin.common.example', { value: 'file' })}
        value={deviceName}
        onChange={(e) => setDeviceName(e.target.value)}
      />

      <label className="modal-label" htmlFor={ids.type}>{t('admin.enableAudit.typeLabel')}</label>
      <select
        id={ids.type}
        className="modal-input"
        style={fieldStyle}
        value={deviceType}
        onChange={(e) => setDeviceType(e.target.value)}
      >
        <option value="file">{t('admin.enableAudit.typeFile')}</option>
        <option value="syslog">{t('admin.enableAudit.typeSyslog')}</option>
        <option value="socket">{t('admin.enableAudit.typeSocket')}</option>
      </select>

      <label className="modal-label" htmlFor={ids.description}>{t('admin.common.description')}</label>
      {/* Description : texte libre, garde le sens de la langue (pas de dir="auto" : champ vide, le
          texte indicatif arabe s'alignerait à gauche) */}
      <input
        id={ids.description}
        type="text"
        className="modal-input"
        style={fieldStyle}
        placeholder={t('admin.common.optional')}
        value={description}
        onChange={(e) => setDescription(e.target.value)}
      />

      {deviceType === 'file' && (
        <>
          <label className="modal-label" htmlFor={ids.filePath}>{t('admin.enableAudit.filePathLabel')}</label>
          <input
            id={ids.filePath}
            type="text"
            dir="ltr"
            className="modal-input"
            style={{ marginBottom: 'var(--sp-1)' }}
            placeholder="/var/log/vault/vault_audit.log"
            value={filePath}
            onChange={(e) => setFilePath(e.target.value)}
          />
          <div style={{ ...hintStyle, marginBottom: 12 }}>
            💡 {t('admin.enableAudit.filePathHint')}
          </div>

          {/* Option SSH */}
          <div style={{ marginTop: 16, marginBottom: 16 }}>
            <label className="checkbox-label" style={{ fontSize: 13 }}>
              <input
                type="checkbox"
                checked={useSSH}
                onChange={(e) => setUseSSH(e.target.checked)}
              />
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>📡 {t('admin.enableAudit.useSsh')}</span>
            </label>
            {/* ADMIN-16 : retrait logique sous le libellé (à droite en arabe) */}
            <div style={{ ...hintStyle, marginTop: 4, marginInlineStart: 32 }}>
              {t('admin.enableAudit.useSshHint')}
            </div>
          </div>

          {/* Champs SSH */}
          {useSSH && (
            <div style={{ background: 'var(--bg-app)', border: '1px solid var(--border)', borderRadius: 8, padding: 12, marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12, color: 'var(--text-secondary)' }}>
                {t('admin.sshConfig')}
              </div>

              <label className="modal-label" htmlFor={ids.sshHost}>{t('admin.sshHost')}*</label>
              <input
                id={ids.sshHost}
                type="text"
                dir={ltrWhenFilled(sshHost)}
                className="modal-input"
                style={fieldStyle}
                placeholder={t('admin.enableAudit.sshHostPlaceholder')}
                value={sshHost}
                onChange={(e) => setSshHost(e.target.value)}
              />

              <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: 12 }}>
                <div>
                  <label className="modal-label" htmlFor={ids.sshUser}>{t('admin.enableAudit.usernameLabel')}</label>
                  <input
                    id={ids.sshUser}
                    type="text"
                    dir="ltr"
                    className="modal-input"
                    style={fieldStyle}
                    placeholder="root"
                    value={sshUsername}
                    onChange={(e) => setSshUsername(e.target.value)}
                  />
                </div>
                <div>
                  <label className="modal-label" htmlFor={ids.sshPort}>{t('admin.enableAudit.portLabel')}</label>
                  <input
                    id={ids.sshPort}
                    type="text"
                    dir="ltr"
                    className="modal-input"
                    style={fieldStyle}
                    placeholder="22"
                    value={sshPort}
                    onChange={(e) => setSshPort(e.target.value)}
                  />
                </div>
              </div>

              <label className="modal-label" htmlFor={ids.sshPassword}>{t('admin.sshPassword')}*</label>
              <input
                id={ids.sshPassword}
                type="password"
                className="modal-input"
                style={fieldStyle}
                placeholder={t('admin.sshPassword')}
                value={sshPassword}
                onChange={(e) => setSshPassword(e.target.value)}
              />

              <label className="modal-label" htmlFor={ids.fingerprint}>{t('admin.enableAudit.fingerprintLabel')}</label>
              <input
                id={ids.fingerprint}
                type="text"
                dir="ltr"
                className="modal-input"
                style={{ marginBottom: 'var(--sp-1)' }}
                placeholder="SHA256:…"
                value={sshHostFingerprint}
                onChange={(e) => setSshHostFingerprint(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <div style={{ ...hintStyle, marginBottom: 12 }}>
                {t('admin.enableAudit.fingerprintHint')}
              </div>

              <div style={hintStyle}>
                🔒 {t('admin.enableAudit.storageHint')}
              </div>
            </div>
          )}
        </>
      )}

      <div style={{ background: 'var(--warning-bg)', border: '1px solid var(--warning-border)', borderRadius: 6, padding: 10, marginTop: 4 }}>
        <div style={{ fontSize: 12, color: 'var(--warning-text)' }}>
          ⚠️ <strong>{t('admin.enableAudit.importantLabel')}</strong> {t('admin.enableAudit.importantText')}
        </div>
      </div>
    </Modal>
  );
}
