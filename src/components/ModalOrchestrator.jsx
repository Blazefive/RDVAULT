// ========================================
// COMPOSANT: ModalOrchestrator — Rendu de toutes les modales
// ========================================
import React from 'react';
import EditEngineModal from '../EditEngineModal';
import ConfirmModal from '../ConfirmModal.jsx';
import TotpDisplayModal from '../TotpDisplayModal.jsx';
import TotpConfigModal from '../TotpConfigModal.jsx';
import VersionHistoryModal from '../VersionHistoryModal.jsx';
import MigrateSecretModal from '../MigrateSecretModal.jsx';
import MoveToFolderModal from '../MoveToFolderModal.jsx';
import NotesPopupModal from '../NotesPopupModal.jsx';
import SettingsModal from '../SettingsModal.jsx';
import EditSecretModalWrapper from '../EditSecretModalWrapper.jsx';
import ShareRbiModal from '../ShareRbiModal.jsx';
import { sanitizeErrorMessage } from '../utils/security';

export default function ModalOrchestrator({
  // Engine modal
  showEngineModal, setShowEngineModal,
  createEngine, isAdmin,
  // Edit secret modal
  editSecret, handleEditSecretClose, handleEditSecretSave,
  selectedEngine, checkTotpExists, getTotpKeyName, discoveredTags,
  // Delete engine modal
  engineToDelete, setEngineToDelete, deletingEngine, deleteEngine,
  // Delete secret modal
  secretToDelete, setSecretToDelete, deletingSecret, deleteSecret,
  // Create folder modal
  showCreateFolderModal, setShowCreateFolderModal,
  newFolderName, setNewFolderName,
  currentPath, writeSecretV2, writeSecretV1,
  fetchSecrets, syncExtensionRef,
  // TOTP modals
  totpDisplay, setTotpDisplay, getTotpCode, startClipboardTimer,
  totpConfig, setTotpConfig, handleSaveTotpConfig,
  // Migrate modal
  migrateSecrets, setMigrateSecrets, handleMigrateSecrets,
  secretEngines,
  // Move to folder modal
  moveToFolder, setMoveToFolder, handleMoveToFolder, secrets,
  // Version history modal
  versionHistory, setVersionHistory, handleRestoreVersion,
  vaultUrl, baseHeaders, axiosConfig,
  // Notes popup
  notesPopup, setNotesPopup,
  // Settings modal
  showSettings, setShowSettings,
  darkMode, toggleDarkMode,
  visibleColumns, toggleColumn,
  isModerator, appMode, token,
  // Share RBI
  shareRbiSecret, setShareRbiSecret, rbiProxyUrl,
  receiveShareOpen, setReceiveShareOpen,
  // Utilitaires
  restoreFocus, showToast, t,
}) {
  return (
    <>
      {showEngineModal && (
        <EditEngineModal
          onClose={() => { setShowEngineModal(false); restoreFocus(); }}
          onCreate={createEngine}
          isAdmin={isAdmin}
        />
      )}

      {editSecret && (
        <EditSecretModalWrapper
          editSecret={editSecret}
          selectedEngine={selectedEngine}
          onClose={handleEditSecretClose}
          onSave={handleEditSecretSave}
          checkTotpExists={checkTotpExists}
          getTotpKeyName={getTotpKeyName}
          existingTags={discoveredTags}
        />
      )}

      {engineToDelete && (
        <ConfirmModal
          title={t('confirm.deleteEngine')}
          message={<>{t('confirm.deleteEngineMsg', { name: engineToDelete.name })}</>}
          confirmLabel={deletingEngine ? t('common.loading') : t('common.delete')}
          cancelLabel={t('common.cancel')}
          danger
          onConfirm={() => !deletingEngine && deleteEngine()}
          onCancel={() => { setEngineToDelete(null); restoreFocus(); }}
        />
      )}

      {secretToDelete && (
        <ConfirmModal
          title={t('confirm.deleteSecret')}
          message={<>{t('confirm.deleteSecretMsg', { name: secretToDelete.name })}</>}
          confirmLabel={deletingSecret ? t('common.loading') : t('common.delete')}
          cancelLabel={t('common.cancel')}
          danger
          onConfirm={() => !deletingSecret && deleteSecret()}
          onCancel={() => { setSecretToDelete(null); restoreFocus(); }}
        />
      )}

      {showCreateFolderModal && (
        <CreateFolderInlineModal
          newFolderName={newFolderName}
          setNewFolderName={setNewFolderName}
          currentPath={currentPath}
          selectedEngine={selectedEngine}
          writeSecretV2={writeSecretV2}
          writeSecretV1={writeSecretV1}
          fetchSecrets={fetchSecrets}
          syncExtensionRef={syncExtensionRef}
          onClose={() => setShowCreateFolderModal(false)}
          showToast={showToast}
          t={t}
        />
      )}

      {totpDisplay && (
        <TotpDisplayModal
          secretName={totpDisplay.secretName}
          totpCode={totpDisplay.code}
          onClose={() => { setTotpDisplay(null); restoreFocus(); }}
          onCopy={(code) => startClipboardTimer('Code TOTP', code)}
          onRefresh={async () => {
            try {
              return await getTotpCode(totpDisplay.totpKeyName);
            } catch (err) {
              return null;
            }
          }}
        />
      )}

      {totpConfig && (
        <TotpConfigModal
          secretName={totpConfig.name}
          totpKeyName={totpConfig.totpKeyName}
          engineName={totpConfig.engineName}
          onClose={() => { setTotpConfig(null); restoreFocus(); }}
          onSave={handleSaveTotpConfig}
        />
      )}

      {migrateSecrets && (
        <MigrateSecretModal
          secrets={migrateSecrets.secrets}
          engines={secretEngines}
          currentEngine={selectedEngine}
          mode={migrateSecrets.mode}
          onClose={() => { setMigrateSecrets(null); restoreFocus(); }}
          onConfirm={async (targetEngine) => {
            await handleMigrateSecrets(migrateSecrets.secrets, targetEngine, migrateSecrets.mode);
            setMigrateSecrets(null);
            restoreFocus();
          }}
        />
      )}

      {moveToFolder && (
        <MoveToFolderModal
          secretsToMove={moveToFolder.secrets}
          secrets={secrets}
          onClose={() => { setMoveToFolder(null); restoreFocus(); }}
          onConfirm={async (targetPath) => {
            await handleMoveToFolder(moveToFolder.secrets, targetPath);
            setMoveToFolder(null);
            restoreFocus();
          }}
        />
      )}

      {versionHistory && (
        <VersionHistoryModal
          secretName={versionHistory.secretName}
          engine={selectedEngine}
          vaultUrl={vaultUrl}
          baseHeaders={baseHeaders}
          axiosConfig={axiosConfig}
          onClose={() => { setVersionHistory(null); restoreFocus(); }}
          onRestore={handleRestoreVersion}
          showToast={showToast}
        />
      )}

      {notesPopup && (
        <NotesPopupModal
          notes={notesPopup.notes}
          onClose={() => setNotesPopup(null)}
        />
      )}

      {showSettings && (
        <SettingsModal
          darkMode={darkMode}
          onToggleDarkMode={toggleDarkMode}
          visibleColumns={visibleColumns}
          onToggleColumn={toggleColumn}
          discoveredTags={discoveredTags}
          isAdmin={isAdmin}
          isModerator={isModerator}
          appVersion="1.4.0"
          secretEngines={secretEngines}
          appMode={appMode}
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          baseHeaders={baseHeaders}
          showToast={showToast}
          onClose={() => setShowSettings(false)}
        />
      )}

      {shareRbiSecret && appMode !== 'local' && (
        <ShareRbiModal
          mode="send"
          secret={shareRbiSecret}
          totpKeyName={getTotpKeyName(shareRbiSecret.name)}
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          rbiProxyUrl={rbiProxyUrl}
          onClose={() => setShareRbiSecret(null)}
          showToast={showToast}
        />
      )}

      {receiveShareOpen && appMode !== 'local' && (
        <ShareRbiModal
          mode="receive"
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          rbiProxyUrl={rbiProxyUrl}
          onClose={() => setReceiveShareOpen(false)}
          showToast={showToast}
        />
      )}
    </>
  );
}

// Sous-composant : modal de création de dossier
function CreateFolderInlineModal({
  newFolderName, setNewFolderName,
  currentPath, selectedEngine,
  writeSecretV2, writeSecretV1,
  fetchSecrets, syncExtensionRef,
  onClose, showToast, t,
}) {
  const handleCreate = async () => {
    if (!newFolderName.trim() || !selectedEngine) return;
    const sanitizedName = newFolderName.trim().replace(/\//g, '-');
    const placeholderPath = (currentPath ? `${currentPath}/` : '') + sanitizedName + '/.placeholder';
    const placeholderEntry = {
      name: placeholderPath,
      username: '', password: '', url: '', website: '', notes: '', tags: '',
      entryType: 'placeholder'
    };
    try {
      if (selectedEngine.version === 2) await writeSecretV2(selectedEngine, placeholderEntry);
      else await writeSecretV1(selectedEngine, placeholderEntry);
      onClose();
      await fetchSecrets(selectedEngine);
      syncExtensionRef.current?.();
      showToast(t('toast.folderCreated'), 'success');
    } catch (err) {
      showToast(`${t('error.folderDelete')} ${sanitizeErrorMessage(err)}`, 'error');
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{'\uD83D\uDCC1'} {t('editSecret.typeFolder')}</h2>
          <button className="modal-close" onClick={onClose} type="button">{'\u00D7'}</button>
        </div>
        <div className="modal-body">
          <div className="form-group-vertical">
            <label className="form-label-vertical">{t('editSecret.placeholderFolderName')}</label>
            <input
              type="text"
              className="form-input-vertical"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              placeholder={t('editSecret.placeholderFolderName')}
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleCreate();
              }}
            />
            {currentPath && (
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', marginTop: 'var(--sp-2)' }}>
                Le dossier sera créé dans : <code>{currentPath}/</code>
              </p>
            )}
          </div>
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('common.cancel')}
          </button>
          <button
            onClick={handleCreate}
            className="btn btn-primary"
            disabled={!newFolderName.trim()}
            type="button"
          >
            {t('engine.create')}
          </button>
        </div>
      </div>
    </div>
  );
}
