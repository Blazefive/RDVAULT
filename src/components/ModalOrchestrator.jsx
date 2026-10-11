// ========================================
// COMPOSANT: ModalOrchestrator — Rendu de toutes les modales
// ========================================
import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import axios from 'axios';
import Modal from './common/Modal';
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
import PasswordHealthModal from './PasswordHealthModal.jsx';
import PasskeysModal from './PasskeysModal.jsx';
import { encodeEnginePath, sanitizeErrorMessage } from '../utils/security';

// APP-6 : délai après la dernière écriture observée avant la relecture (un import = une seule relecture)
export const SETTINGS_WRITES_REFRESH_MS = 1000;

const READ_METHODS = new Set(['get', 'head', 'options']);

/**
 * Coffre visé par une requête vers `${vaultUrl}/v1/<chemin du coffre>/…` (chemin encodé comme dans les
 * URL construites par l'application : encodeEnginePath), ou null. Plus long chemin de coffre d'abord.
 */
export function engineOfRequestUrl(url, vaultUrl, secretEngines) {
  if (typeof url !== 'string' || !vaultUrl) return null;
  const base = `${vaultUrl}/v1/`;
  if (!url.startsWith(base)) return null;
  const path = url.slice(base.length).split('?')[0];
  let found = null; // { prefix, name }
  for (const engine of secretEngines || []) {
    if (typeof engine?.name !== 'string' || !engine.name.replace(/^\/+|\/+$/g, '')) continue;
    const prefix = encodeEnginePath(engine.name);
    if ((path === prefix || path.startsWith(`${prefix}/`)) && (!found || prefix.length > found.prefix.length)) {
      found = { prefix, name: engine.name };
    }
  }
  return found ? found.name : null;
}

/**
 * APP-6 : coffres dont des entrées sont écrites pendant que `open` est vrai (Paramètres ouverts : import
 * CSV/XML). SettingsModal écrit directement avec axios, sans rappel : ses requêtes d'écriture (toute
 * méthode autre que GET/HEAD/OPTIONS) vers un coffre connu sont observées par un intercepteur de requête
 * axios posé seulement pendant l'ouverture (même technique que useTags pour tags-shared ; la requête
 * n'est pas modifiée). onWrites(noms des coffres) est appelé SETTINGS_WRITES_REFRESH_MS après la dernière
 * écriture et, pour les écritures encore en attente, à la fermeture (l'appelant vérifie la session).
 */
export function useEngineWritesWhileOpen(open, { vaultUrl, secretEngines, onWrites }) {
  const latestRef = useRef(null);
  latestRef.current = { vaultUrl, secretEngines, onWrites };

  useEffect(() => {
    const requests = axios.interceptors?.request;
    if (!open || typeof requests?.use !== 'function') return undefined;
    const pending = new Set();
    let timer = null;
    const flushWrites = () => {
      clearTimeout(timer);
      timer = null;
      if (pending.size === 0) return;
      const names = Array.from(pending);
      pending.clear();
      const notify = latestRef.current.onWrites;
      if (typeof notify === 'function') {
        try { notify(names); } catch { /* relecture best effort */ }
      }
    };
    const id = requests.use((config) => {
      try {
        const method = String(config?.method || 'get').toLowerCase();
        if (!READ_METHODS.has(method)) {
          const { vaultUrl: base, secretEngines: engines } = latestRef.current;
          const name = engineOfRequestUrl(config?.url, base, engines);
          if (name) {
            pending.add(name);
            clearTimeout(timer);
            timer = setTimeout(flushWrites, SETTINGS_WRITES_REFRESH_MS);
          }
        }
      } catch { /* observation seulement : la requête part telle quelle */ }
      return config;
    });
    return () => {
      if (typeof requests.eject === 'function') requests.eject(id);
      flushWrites();
    };
  }, [open]);
}

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
  // Suppression d'une clé TOTP (SECRETS-12) : { secret, engineName } en attente de confirmation
  totpToDelete, setTotpToDelete, handleDeleteTotp,
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
  // Settings modal ; onSettingsWrites(noms des coffres) : entrées écrites par les Paramètres (import, APP-6)
  showSettings, setShowSettings, onSettingsWrites,
  darkMode, toggleDarkMode,
  visibleColumns, toggleColumn,
  isModerator, appMode, token,
  // Share RBI
  shareRbiSecret, setShareRbiSecret, rbiProxyUrl,
  receiveShareOpen, setReceiveShareOpen,
  // Audit de santé des mots de passe
  showPasswordHealth, setShowPasswordHealth, vaultApi,
  // Gestion des passkeys
  showPasskeys, setShowPasskeys, authUser,
  // Utilitaires
  restoreFocus, showToast, t,
}) {
  // APP-6 : un import des Paramètres n'était suivi d'aucune relecture (tableau et extension périmés ;
  // « Modifier » + « Enregistrer » réécrivait l'ancienne valeur d'une entrée écrasée par l'import)
  useEngineWritesWhileOpen(!!showSettings, { vaultUrl, secretEngines, onWrites: onSettingsWrites });

  // Retour du focus à la fermeture d'une modale : le squelette Modal le rend à l'élément
  // déclencheur ; on ne le replace sur la recherche (restoreFocus d'App) que s'il a été perdu
  // (déclencheur disparu, modale sans gestion du focus). Auparavant restoreFocus était appelé
  // systématiquement (et écrasait le retour au déclencheur), ou pas du tout (Paramètres,
  // Notes, Dossier, Partage RBI : focus perdu sur <body>).
  const returnFocus = () => {
    const schedule = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (cb) => setTimeout(cb, 0);
    schedule(() => {
      const current = document.activeElement;
      if (!current || current === document.body || current === document.documentElement || !current.isConnected) {
        restoreFocus();
      }
    });
  };

  // Mémoïsé : TotpDisplayModal relance son intervalle de compte à rebours à chaque
  // changement de référence de onRefresh (dépendance d'effet).
  const totpKeyName = totpDisplay?.totpKeyName;
  const handleTotpRefresh = useCallback(async () => {
    try {
      return await getTotpCode(totpKeyName);
    } catch (err) {
      return null;
    }
  }, [getTotpCode, totpKeyName]);

  return (
    <>
      {showEngineModal && (
        <EditEngineModal
          onClose={() => { setShowEngineModal(false); returnFocus(); }}
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
          showToast={showToast}
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
          onCancel={() => { setEngineToDelete(null); returnFocus(); }}
        />
      )}

      {secretToDelete && (
        <ConfirmModal
          title={t('confirm.deleteSecret')}
          message={(
            <>
              {t('confirm.deleteSecretMsg', { name: secretToDelete.name })}
              {/* SECRETS-33 : sort de la clé TOTP de l'entrée (secretToDelete.totpExists, calculé à
                  l'ouverture). Même règle que deleteSecret (useSecrets) : KV v2 = suppression douce,
                  graine toujours conservée ; KV v1 = suppression définitive, graine détruite
                  seulement si la case est cochée (deleteTotp), sinon conservée. */}
              {secretToDelete.totpExists && selectedEngine?.version === 2 && (
                <p className="confirm-note">
                  {t('confirm.deleteSecretTotpKept', { action: t('contextMenu.restore') })}
                </p>
              )}
              {secretToDelete.totpExists && selectedEngine?.version !== 2 && (
                <>
                  <label className="checkbox-label confirm-checkbox">
                    <input
                      type="checkbox"
                      checked={secretToDelete.deleteTotp === true}
                      disabled={!!deletingSecret}
                      onChange={(e) => {
                        const checked = e.target.checked;
                        setSecretToDelete(p => (p ? { ...p, deleteTotp: checked } : p));
                      }}
                    />
                    <span>{t('confirm.deleteTotpToo')}</span>
                  </label>
                  {secretToDelete.deleteTotp !== true && (
                    <p className="confirm-note">{t('confirm.deleteSecretTotpOrphan')}</p>
                  )}
                </>
              )}
            </>
          )}
          confirmLabel={deletingSecret ? t('common.loading') : t('common.delete')}
          cancelLabel={t('common.cancel')}
          danger
          onConfirm={() => !deletingSecret && deleteSecret()}
          onCancel={() => { setSecretToDelete(null); returnFocus(); }}
        />
      )}

      {totpToDelete && (
        <DeleteTotpConfirm
          request={totpToDelete}
          selectedEngine={selectedEngine}
          handleDeleteTotp={handleDeleteTotp}
          onDone={() => { setTotpToDelete(null); returnFocus(); }}
          t={t}
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
          onClose={() => { setShowCreateFolderModal(false); returnFocus(); }}
          showToast={showToast}
          t={t}
        />
      )}

      {totpDisplay && (
        <TotpDisplayModal
          secretName={totpDisplay.secretName}
          totpCode={totpDisplay.code}
          period={totpDisplay.period}
          onClose={() => { setTotpDisplay(null); returnFocus(); }}
          onCopy={(code) => startClipboardTimer(t('totp.title'), code)}
          onRefresh={handleTotpRefresh}
        />
      )}

      {totpConfig && (
        <TotpConfigModal
          secretName={totpConfig.name}
          totpKeyName={totpConfig.totpKeyName}
          engineName={totpConfig.engineName}
          onClose={() => { setTotpConfig(null); returnFocus(); }}
          onSave={handleSaveTotpConfig}
          showToast={showToast}
        />
      )}

      {migrateSecrets && (
        <MigrateSecretModal
          secrets={migrateSecrets.secrets}
          engines={secretEngines}
          currentEngine={selectedEngine}
          mode={migrateSecrets.mode}
          onClose={() => { setMigrateSecrets(null); returnFocus(); }}
          onConfirm={async (targetEngine) => {
            await handleMigrateSecrets(migrateSecrets.secrets, targetEngine, migrateSecrets.mode);
            setMigrateSecrets(null);
            returnFocus();
          }}
        />
      )}

      {moveToFolder && (
        <MoveToFolderModal
          secretsToMove={moveToFolder.secrets}
          secrets={secrets}
          onClose={() => { setMoveToFolder(null); returnFocus(); }}
          onConfirm={async (targetPath) => {
            await handleMoveToFolder(moveToFolder.secrets, targetPath);
            setMoveToFolder(null);
            returnFocus();
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
          onClose={() => { setVersionHistory(null); returnFocus(); }}
          onRestore={handleRestoreVersion}
          showToast={showToast}
        />
      )}

      {notesPopup && (
        <NotesPopupModal
          notes={notesPopup.notes}
          onClose={() => { setNotesPopup(null); returnFocus(); }}
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
          appVersion="1.7.0"
          secretEngines={secretEngines}
          appMode={appMode}
          vaultUrl={vaultUrl}
          token={token}
          axiosConfig={axiosConfig}
          baseHeaders={baseHeaders}
          showToast={showToast}
          onClose={() => { setShowSettings(false); returnFocus(); }}
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
          onClose={() => { setShareRbiSecret(null); returnFocus(); }}
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
          onClose={() => { setReceiveShareOpen(false); returnFocus(); }}
          showToast={showToast}
        />
      )}

      {showPasswordHealth && (
        <PasswordHealthModal
          vaultApi={vaultApi}
          secretEngines={secretEngines}
          showToast={showToast}
          onClose={() => { setShowPasswordHealth(false); returnFocus(); }}
        />
      )}

      {showPasskeys && (
        <PasskeysModal
          vaultApi={vaultApi}
          vaultUrl={vaultUrl}
          secretEngines={secretEngines}
          authUser={authUser}
          showToast={showToast}
          onClose={() => { setShowPasskeys(false); returnFocus(); }}
        />
      )}
    </>
  );
}

// Sous-composant : confirmation de « Supprimer le TOTP » (SECRETS-12). La graine TOTP n'est ni
// versionnée ni relisible : sa suppression est définitive. Rien n'est supprimé avant le clic sur
// « Supprimer » ; handleDeleteTotp (useTotp) refuse encore une clé partagée avec un autre coffre
// ou invérifiable. La demande est liée au coffre sélectionné à l'ouverture : s'il a changé
// entre-temps, la clé calculée ne serait plus celle de l'entrée, rien n'est fait.
function DeleteTotpConfirm({ request, selectedEngine, handleDeleteTotp, onDone, t }) {
  const [busy, setBusy] = useState(false);
  const secret = request?.secret;
  const confirm = async () => {
    if (busy) return;
    if (!secret || !selectedEngine || selectedEngine.name !== request.engineName || typeof handleDeleteTotp !== 'function') {
      onDone();
      return;
    }
    setBusy(true);
    try {
      await handleDeleteTotp(secret, { confirmed: true });
    } finally {
      onDone();
    }
  };
  return (
    <ConfirmModal
      title={t('confirm.deleteTotp')}
      message={t('confirm.deleteTotpMsg', { name: secret?.name || '' })}
      confirmLabel={busy ? t('common.loading') : t('common.delete')}
      cancelLabel={t('common.cancel')}
      danger
      onConfirm={confirm}
      onCancel={() => { if (!busy) onDone(); }}
    />
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
  const inputId = useId();
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
      showToast(`${t('error.folderCreate')} ${sanitizeErrorMessage(err)}`, 'error');
    }
  };

  // Squelette commun Modal (BUG CORRIGÉ : seule modale qu'Échap ne fermait pas, sans role="dialog"
  // ni aria-modal, bouton de fermeture annoncé « × ») : Échap, clic hors zone, focus géré.
  return (
    <Modal
      title={<><span aria-hidden="true">{'\uD83D\uDCC1'}</span> {t('editSecret.typeFolder')}</>}
      onClose={onClose}
      headerExtra={(
        <button className="modal-close" onClick={onClose} type="button" aria-label={t('common.close')} title={t('common.close')}>
          <span aria-hidden="true">{'\u00D7'}</span>
        </button>
      )}
      footer={(
        <>
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
        </>
      )}
    >
          <div className="form-group-vertical">
            <label className="form-label-vertical" htmlFor={inputId}>{t('editSecret.placeholderFolderName')}</label>
            <input
              id={inputId}
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
                {t('editSecret.folderWillBeCreatedIn')} <code>{currentPath}/</code>
              </p>
            )}
          </div>
    </Modal>
  );
}
