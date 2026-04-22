import React from 'react';
import { buildSafeUrl, safeWindowOpen } from '../../utils/security';

/**
 * SecretContextMenu — menu contextuel principal pour les secrets
 * (clic droit sur un secret, zone vide, ou secret supprimé/RBI-Only)
 */
export default function SecretContextMenu({
  contextMenu,
  contextMenuRef,
  setContextMenu,
  selectedEngine,
  isCurrentEngineRbiOnly,
  isSecretRbiOnly,
  treeViewEnabled,
  currentPath,
  setEditSecret,
  setShowCreateFolderModal,
  setNewFolderName,
  undeleteSecret,
  confirmDeleteSecret,
  startClipboardTimer,
  getTotpKeyName,
  getTotpCode,
  handleShowTotp,
  handleCopyTotp,
  handleConfigureTotp,
  handleDeleteTotp,
  setShareRbiSecret,
  setVersionHistory,
  setMoveToFolder,
  setMigrateSecrets,
  selectedSecrets,
  secrets,
  installedBrowsers,
  appMode,
  showToast,
  t
}) {
  if (!contextMenu) return null;
  if (contextMenu.type === 'create' && (selectedEngine?.canWrite === false || isCurrentEngineRbiOnly)) return null;

  const isWebUrl = (url) =>
    url && (url.startsWith('http') || !url.includes('://')) &&
    !url.toLowerCase().startsWith('ssh:') &&
    !url.toLowerCase().startsWith('rdp:') &&
    !url.toLowerCase().startsWith('sftp:');

  const launchRbiSession = async (secret, { disableClipboard = true } = {}) => {
    const url = buildSafeUrl(secret.url);
    if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
    if (window.electronRBI?.launchSession) {
      let totpCode = null;
      try {
        const totpKey = getTotpKeyName(secret.name);
        totpCode = await getTotpCode(totpKey);
        if (totpCode) {
          showToast(t('toast.totpRetrieved'), 'info', 2000);
        } else {
          showToast(t('toast.launchingRbiNoTotp'), 'info', 2000);
        }
      } catch (e) {
        showToast(t('toast.launchingRbi'), 'info', 3000);
      }
      const result = await window.electronRBI.launchSession({
        url,
        username: secret.username,
        password: secret.password,
        totp: totpCode,
        skipOverlay: false,
        policies: {
          disableClipboard,
          disableNewTabs: true,
          disableDownloads: false
        }
      });
      if (result.success) {
        showToast(disableClipboard ? t('toast.rbiOpened') : t('toast.rbiAutoInject'), 'success', 3000);
      } else {
        showToast(result.error || t('error.rbiLaunch'), 'error');
      }
    } else {
      showToast(t('error.rbiUnavailable'), 'error');
    }
    setContextMenu(null);
  };

  const openInBrowser = async (urlValue, browser) => {
    const url = buildSafeUrl(urlValue);
    if (!url) { showToast(t('error.invalidUrl'), 'error'); setContextMenu(null); return; }
    if (window.electronBrowser?.openUrl) {
      await window.electronBrowser.openUrl(url, browser);
    } else {
      safeWindowOpen(url);
    }
    setContextMenu(null);
  };

  // Resolve secrets list for batch operations
  const getSecretsForBatch = () =>
    selectedSecrets.has(contextMenu.secret.name)
      ? secrets.filter(s => selectedSecrets.has(s.name))
      : [contextMenu.secret];

  const batchSuffix = selectedSecrets.has(contextMenu.secret?.name) && selectedSecrets.size > 1
    ? ` (${selectedSecrets.size})`
    : '';

  return (
    <div
      ref={contextMenuRef}
      className="context-menu"
      style={{ top: contextMenu.y, left: contextMenu.x }}
      onClick={(e) => e.stopPropagation()}
    >
      {contextMenu.type === 'create' ? (
        <>
          <button
            onClick={() => {
              const initialName = treeViewEnabled && currentPath ? `${currentPath}/` : '';
              setEditSecret({ name: initialName, username: '', password: '', url: '', notes: '' });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            + {t('toolbar.newEntry')}
          </button>
          {treeViewEnabled && (
            <button
              onClick={() => {
                setShowCreateFolderModal(true);
                setNewFolderName('');
                setContextMenu(null);
              }}
              className="context-menu-item"
              type="button"
            >
              {'\u{1F4C1}'} {t('editSecret.typeFolder')}
            </button>
          )}
        </>
      ) : contextMenu.secret?.deleted ? (
        <button
          onClick={async () => {
            await undeleteSecret(contextMenu.secret);
            setContextMenu(null);
          }}
          className="context-menu-item"
          type="button"
          style={{ color: 'var(--success)' }}
        >
          {'\u267B\uFE0F'} {t('contextMenu.restore')}
        </button>
      ) : contextMenu.secret && isSecretRbiOnly(contextMenu.secret.name) ? (
        <>
          {isWebUrl(contextMenu.secret?.url) && (
            <button
              onClick={() => launchRbiSession(contextMenu.secret)}
              className="context-menu-item"
              type="button"
              style={{ fontWeight: 'bold', color: 'var(--success)' }}
            >
              {'\u{1F512}'} {t('contextMenu.openSecureBrowser')}
            </button>
          )}
        </>
      ) : (
        <>
          <button
            onClick={async () => {
              const copyValue = contextMenu.field === 'password'
                ? contextMenu.secret?.password
                : contextMenu.value;
              if (copyValue) {
                const fieldName =
                  contextMenu.field === 'name' ? t('table.name') :
                  contextMenu.field === 'username' ? t('table.username') :
                  contextMenu.field === 'password' ? t('table.password') :
                  contextMenu.field === 'url' ? t('table.url') :
                  contextMenu.field === 'notes' ? t('table.notes') : t('table.customFields');
                await startClipboardTimer(fieldName, copyValue);
              }
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
            style={{
              opacity: (contextMenu.field === 'password' ? contextMenu.secret?.password : contextMenu.value) ? 1 : 0.4,
              cursor: (contextMenu.field === 'password' ? contextMenu.secret?.password : contextMenu.value) ? 'pointer' : 'default'
            }}
          >
            {t('toast.copied')}
          </button>

          <div className="context-menu-separator" />

          <button
            onClick={() => {
              setEditSecret(contextMenu.secret);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {'\u270F\uFE0F'} {t('contextMenu.edit')}
          </button>

          <button
            onClick={() => {
              const duplicated = {
                ...contextMenu.secret,
                name: `${contextMenu.secret.name}_copie`
              };
              setEditSecret(duplicated);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {'\u{1F4CB}'} {t('contextMenu.copyTo')}
          </button>

          <button
            onClick={() => {
              confirmDeleteSecret(contextMenu.secret);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {'\u{1F5D1}\uFE0F'} {t('contextMenu.delete')}
          </button>

          {/* Session Sécurisée */}
          {isWebUrl(contextMenu.secret?.url) && (
            <>
              <div className="context-menu-separator" />
              <button
                onClick={() => launchRbiSession(contextMenu.secret, { disableClipboard: false })}
                className="context-menu-item"
                type="button"
                style={{ fontWeight: 'bold', color: 'var(--success)' }}
              >
                {'\u{1F512}'} {t('contextMenu.openSecureBrowser')}
              </button>
            </>
          )}

          {/* Partager en RBI */}
          {appMode !== 'local' && isWebUrl(contextMenu.secret?.url) && (
            <button
              onClick={() => {
                setShareRbiSecret(contextMenu.secret);
                setContextMenu(null);
              }}
              className="context-menu-item"
              type="button"
            >
              {'\u{1F517}'} {t('contextMenu.shareRbi')}
            </button>
          )}

          {/* Ouvrir dans un navigateur */}
          {contextMenu.field === 'url' && contextMenu.value && (
            <>
              <div className="context-menu-separator" />
              <div className="context-menu-label">{t('contextMenu.openUrl')}</div>
              <button onClick={() => openInBrowser(contextMenu.value, 'default')} className="context-menu-item" type="button">
                {'\u{1F310}'} Navigateur par d\u00E9faut
              </button>
              {installedBrowsers.includes('chrome') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'chrome')} className="context-menu-item" type="button">
                  <span style={{ fontSize: '16px' }}>{'\u{1F535}'}</span> Google Chrome
                </button>
              )}
              {installedBrowsers.includes('firefox') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'firefox')} className="context-menu-item" type="button">
                  {'\u{1F98A}'} Mozilla Firefox
                </button>
              )}
              {installedBrowsers.includes('edge') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'edge')} className="context-menu-item" type="button">
                  <span style={{ fontSize: '16px' }}>{'\u{1F30A}'}</span> Microsoft Edge
                </button>
              )}
              {installedBrowsers.includes('brave') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'brave')} className="context-menu-item" type="button">
                  {'\u{1F981}'} Brave
                </button>
              )}
            </>
          )}

          <div className="context-menu-separator" />

          <div className="context-menu-label">{t('migrate.migrateTitle')}</div>
          <button
            onClick={() => {
              setMoveToFolder({ secrets: getSecretsForBatch() });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {'\u{1F4C1}'} {t('contextMenu.moveToFolder')}...{batchSuffix}
          </button>

          <div className="context-menu-label" style={{ fontSize: 'var(--text-xs)', opacity: 0.7 }}>{t('migrate.migrateTitle')}</div>
          <button
            onClick={() => {
              setMigrateSecrets({ secrets: getSecretsForBatch(), mode: 'copy' });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.copyTo')}...{batchSuffix}
          </button>
          <button
            onClick={() => {
              setMigrateSecrets({ secrets: getSecretsForBatch(), mode: 'move' });
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.migrate')}...{batchSuffix}
          </button>

          {selectedEngine?.version === 2 && (
            <button
              onClick={() => {
                setVersionHistory({ secretName: contextMenu.secret.name });
                setContextMenu(null);
              }}
              className="context-menu-item"
              type="button"
            >
              {t('contextMenu.history')}
            </button>
          )}

          <div className="context-menu-separator" />

          <div className="context-menu-label">{t('totp.title')}</div>
          <button
            onClick={async () => {
              await handleShowTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.showTotp')}
          </button>
          <button
            onClick={async () => {
              await handleCopyTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.copyField', { field: 'TOTP' })}
          </button>
          <button
            onClick={() => {
              if (!contextMenu.totpExists) {
                handleConfigureTotp(contextMenu.secret);
                setContextMenu(null);
              }
            }}
            disabled={contextMenu.totpExists}
            className="context-menu-item"
            type="button"
          >
            {t('contextMenu.configurTotp')} {contextMenu.totpExists && `(${t('contextMenu.showTotp')})`}
          </button>
          {contextMenu.totpExists && (
            <button
              onClick={async () => {
                await handleDeleteTotp(contextMenu.secret);
                setContextMenu(null);
              }}
              className="context-menu-item danger"
              type="button"
            >
              {t('contextMenu.deleteTotp')}
            </button>
          )}
        </>
      )}
    </div>
  );
}
