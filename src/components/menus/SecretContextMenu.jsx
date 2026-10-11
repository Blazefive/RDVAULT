import React from 'react';
import { buildSafeUrl, safeWindowOpen } from '../../utils/security';
import { rbiLaunchErrorMessage, rbiWebsiteOption } from '../../utils/urlHandler';
import { buildTotpKeyName } from '../../hooks/useTotp';

// Ajoute « ... » sauf si le libellé traduit se termine déjà par des points de suspension
// (BUG CORRIGÉ : « Copier vers...... », « Migrer vers...... »)
const withEllipsis = (label) => (/(\.\.\.|…)$/.test(label) ? label : `${label}...`);

/**
 * SecretContextMenu — menu contextuel principal pour les secrets
 * (clic droit sur un secret, zone vide, ou secret supprimé/RBI-Only)
 *
 * Accessibilité : role="menu" / "menuitem" / "separator" ; focus, flèches et Échap sont gérés
 * par useContextMenus. Activer un élément rend d'abord le focus à l'élément d'origine (ligne du
 * tableau) : une modale ouverte par l'action le lui rendra à sa fermeture.
 *
 * Recherche multi-coffres (SEARCH-9 / SEARCH-31) : un résultat d'un AUTRE coffre que le coffre
 * sélectionné (secret.engineName) n'est jamais modifié via le coffre sélectionné. Les copies,
 * l'ouverture de l'URL et la session sécurisée (TOTP lu sur la clé du coffre de l'entrée) agissent
 * directement ; toutes les autres actions passent par runInEntryVault (App), qui ouvre d'abord le
 * coffre de l'entrée puis exécute l'action. Sans runInEntryVault, elles sont désactivées avec un
 * libellé explicite.
 *
 * « Supprimer le TOTP » (SECRETS-12) : la graine n'est pas relisible, sa destruction est définitive.
 * L'élément ouvre une boîte de confirmation (confirmDeleteTotp, App + ModalOrchestrator) qui seule
 * appelle handleDeleteTotp(secret, { confirmed: true }). Sans confirmDeleteTotp, repli sur la
 * confirmation par seconde demande de useTotp.
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
  confirmDeleteTotp,
  setShareRbiSecret,
  setVersionHistory,
  setMoveToFolder,
  setMigrateSecrets,
  runInEntryVault,
  selectedSecrets,
  secrets,
  installedBrowsers,
  appMode,
  showToast,
  t
}) {
  if (!contextMenu) return null;
  if (contextMenu.type === 'create' && (selectedEngine?.canWrite === false || isCurrentEngineRbiOnly)) return null;

  // Coffre de l'entrée (résultat de la recherche multi-coffres) s'il diffère du coffre sélectionné
  const entryEngineName = typeof contextMenu.secret?.engineName === 'string' && contextMenu.secret.engineName
    ? contextMenu.secret.engineName
    : null;
  const otherVault = !!entryEngineName && entryEngineName !== selectedEngine?.name;
  const canRunInEntryVault = otherVault && typeof runInEntryVault === 'function';
  // Libellé explicite : les actions ouvrent le coffre de l'entrée, ou sont indisponibles ici
  const otherVaultHint = !otherVault ? '' : t(canRunInEntryVault ? 'contextMenu.otherVaultHint' : 'contextMenu.otherVaultReadOnly', { engine: entryEngineName });
  // Propriétés d'un élément « dans le coffre de l'entrée » (désactivé si impossible)
  const entryItemProps = otherVault ? { disabled: !canRunInEntryVault, title: otherVaultHint } : {};
  // Lance l'action dans le coffre de l'entrée (App ouvre ce coffre puis l'exécute)
  const inEntryVault = (type, options) => {
    if (canRunInEntryVault) runInEntryVault(contextMenu.secret, type, options);
    setContextMenu(null);
  };
  // TOTP de l'entrée : pour un autre coffre, existence vérifiée sur la clé de SON coffre (App) ;
  // inconnue tant que la vérification n'a pas répondu (« Supprimer le TOTP » alors masqué)
  const totpExists = otherVault ? contextMenu.entryTotpExists === true : !!contextMenu.totpExists;
  // Version KV du coffre de l'entrée (historique des versions : KV v2 uniquement)
  const entryEngineVersion = otherVault ? contextMenu.secret?.engineVersion : selectedEngine?.version;

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
        // Résultat d'un autre coffre : clé TOTP de SON coffre (et non celle du coffre sélectionné)
        const totpKey = otherVault ? buildTotpKeyName(entryEngineName, secret.name) : getTotpKeyName(secret.name);
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
        // Adresse « website » de l'entrée : saisie autorisée aussi sur cet hôte (RBI-11)
        ...rbiWebsiteOption(secret),
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
      if (result?.success) {
        showToast(disableClipboard ? t('toast.rbiOpened') : t('toast.rbiAutoInject'), 'success', 3000);
      } else {
        // Motif traduit (ex. RBI_FOREIGN_ORIGIN) plutôt que le texte brut du processus principal
        showToast(rbiLaunchErrorMessage(result, t), 'error');
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

  // Entrées d'une opération par lot : la sélection (entrées du coffre sélectionné) si l'entrée
  // cliquée en fait partie, sinon l'entrée seule. La sélection indexe une entrée du coffre sélectionné
  // par son nom et un résultat d'un autre coffre par coffre + nom (entryKey, useSelection) : seules
  // les entrées de `secrets` (coffre sélectionné) entrent dans le lot. Un résultat d'un autre coffre
  // est toujours seul (ses actions passent par runInEntryVault).
  const selectedBatch = !otherVault && contextMenu.secret && selectedSecrets.has(contextMenu.secret.name)
    ? secrets.filter(s => selectedSecrets.has(s.name))
    : [];
  const getSecretsForBatch = () => (selectedBatch.length > 0 ? selectedBatch : [contextMenu.secret]);
  // Nombre d'entrées réellement traitées (avant : taille de la sélection, homonymes compris)
  const batchSuffix = selectedBatch.length > 1 ? ` (${selectedBatch.length})` : '';

  // Valeur copiée par l'action « Copier » et libellé explicite du champ
  // (BUG CORRIGÉ : l'élément affichait « Copié », message de confirmation, et restait actif
  //  — simplement grisé — quand le champ était vide)
  const copyValue = contextMenu.field === 'password' ? contextMenu.secret?.password : contextMenu.value;
  const copyLabel =
    contextMenu.field === 'name' ? t('contextMenu.copyName') :
    contextMenu.field === 'username' ? t('contextMenu.copyUsername') :
    contextMenu.field === 'password' ? t('contextMenu.copyPassword') :
    contextMenu.field === 'url' ? t('contextMenu.copyUrl') :
    contextMenu.field === 'notes' ? t('contextMenu.copyNotes') :
    t('contextMenu.copyField', { field: t('table.customFields') });

  // Rendre le focus à l'élément d'origine avant l'action (l'élément du menu va disparaître)
  const handleClickCapture = (e) => {
    const opener = contextMenu.opener;
    if (e.target.closest('button') && opener && opener.isConnected && typeof opener.focus === 'function') {
      opener.focus();
    }
  };

  return (
    <div
      ref={contextMenuRef}
      className="context-menu"
      role="menu"
      aria-label={contextMenu.secret?.name || t('toolbar.newEntry')}
      style={{ top: contextMenu.y, left: contextMenu.x }}
      onClick={(e) => e.stopPropagation()}
      onClickCapture={handleClickCapture}
    >
      {contextMenu.type === 'create' ? (
        <>
          <button
            onClick={() => {
              const initialName = treeViewEnabled && currentPath ? `${currentPath}/` : '';
              setEditSecret({ name: initialName, username: '', password: '', url: '', notes: '' });
              setContextMenu(null);
            }}
            role="menuitem"
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
              role="menuitem"
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
          role="menuitem"
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
              role="menuitem"
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
            role="menuitem"
            type="button"
            disabled={!copyValue}
          >
            {copyLabel}
          </button>

          {/* Menu ouvert sur la ligne (clavier : Entrée / touche Menu) ou sur le nom : copie directe
              de l'identifiant et du mot de passe, sans double-clic sur la cellule */}
          {contextMenu.field === 'name' && contextMenu.secret?.username && (
            <button
              onClick={async () => {
                await startClipboardTimer(t('table.username'), contextMenu.secret.username);
                setContextMenu(null);
              }}
              className="context-menu-item"
              role="menuitem"
              type="button"
            >
              {t('contextMenu.copyUsername')}
            </button>
          )}
          {contextMenu.field === 'name' && contextMenu.secret?.password && (
            <button
              onClick={async () => {
                await startClipboardTimer(t('table.password'), contextMenu.secret.password);
                setContextMenu(null);
              }}
              className="context-menu-item"
              role="menuitem"
              type="button"
            >
              {t('contextMenu.copyPassword')}
            </button>
          )}

          <div className="context-menu-separator" role="separator" />

          {/* Résultat d'un autre coffre : libellé explicite et ouverture de son coffre */}
          {otherVault && (
            <>
              <div className="context-menu-label">{otherVaultHint}</div>
              <button
                onClick={() => inEntryVault('open')}
                role="menuitem"
                className="context-menu-item"
                type="button"
                {...entryItemProps}
              >
                {'\u{1F4C2}'} {t('contextMenu.openInVault', { engine: entryEngineName })}
              </button>
            </>
          )}

          <button
            onClick={otherVault ? () => inEntryVault('edit') : () => {
              setEditSecret(contextMenu.secret);
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {'✏️'} {t('contextMenu.edit')}
          </button>

          <button
            onClick={otherVault ? () => inEntryVault('duplicate') : () => {
              const duplicated = {
                ...contextMenu.secret,
                name: `${contextMenu.secret.name}_copie`
              };
              setEditSecret(duplicated);
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {/* Duplication sur place (« _copie ») : libellé distinct de « Copier vers... » (autre coffre) */}
            {'\u{1F4CB}'} {t('contextMenu.duplicate')}
          </button>

          <button
            onClick={otherVault ? () => inEntryVault('delete') : () => {
              confirmDeleteSecret(contextMenu.secret);
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {'\u{1F5D1}️'} {t('contextMenu.delete')}
          </button>

          {/* Session Sécurisée (lecture seule : TOTP lu sur la clé du coffre de l'entrée) */}
          {isWebUrl(contextMenu.secret?.url) && (
            <>
              <div className="context-menu-separator" role="separator" />
              <button
                onClick={() => launchRbiSession(contextMenu.secret, { disableClipboard: false })}
                role="menuitem"
                className="context-menu-item"
                type="button"
                style={{ fontWeight: 'bold', color: 'var(--success)' }}
              >
                {'\u{1F512}'} {t('contextMenu.openSecureBrowser')}
              </button>
            </>
          )}

          {/* Partager en RBI (la modale lit la clé TOTP du coffre sélectionné) */}
          {appMode !== 'local' && isWebUrl(contextMenu.secret?.url) && (
            <button
              onClick={otherVault ? () => inEntryVault('shareRbi') : () => {
                setShareRbiSecret(contextMenu.secret);
                setContextMenu(null);
              }}
              role="menuitem"
              className="context-menu-item"
              type="button"
              {...entryItemProps}
            >
              {'\u{1F517}'} {t('contextMenu.shareRbi')}
            </button>
          )}

          {/* Ouvrir dans un navigateur */}
          {contextMenu.field === 'url' && contextMenu.value && (
            <>
              <div className="context-menu-separator" role="separator" />
              <div className="context-menu-label">{t('contextMenu.openUrl')}</div>
              <button onClick={() => openInBrowser(contextMenu.value, 'default')} role="menuitem" className="context-menu-item" type="button">
                {'\u{1F310}'} {t('contextMenu.defaultBrowser')}
              </button>
              {installedBrowsers.includes('chrome') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'chrome')} role="menuitem" className="context-menu-item" type="button">
                  <span style={{ fontSize: '16px' }}>{'\u{1F535}'}</span> Google Chrome
                </button>
              )}
              {installedBrowsers.includes('firefox') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'firefox')} role="menuitem" className="context-menu-item" type="button">
                  {'\u{1F98A}'} Mozilla Firefox
                </button>
              )}
              {installedBrowsers.includes('edge') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'edge')} role="menuitem" className="context-menu-item" type="button">
                  <span style={{ fontSize: '16px' }}>{'\u{1F30A}'}</span> Microsoft Edge
                </button>
              )}
              {installedBrowsers.includes('brave') && (
                <button onClick={() => openInBrowser(contextMenu.value, 'brave')} role="menuitem" className="context-menu-item" type="button">
                  {'\u{1F981}'} Brave
                </button>
              )}
            </>
          )}

          <div className="context-menu-separator" role="separator" />

          {/* BUG CORRIGÉ : l'en-tête « Migrer vers... » figurait aussi au-dessus de « Déplacer dans un dossier » (même coffre) */}
          <button
            onClick={otherVault ? () => inEntryVault('moveToFolder') : () => {
              setMoveToFolder({ secrets: getSecretsForBatch() });
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {'\u{1F4C1}'} {withEllipsis(t('contextMenu.moveToFolder'))}{batchSuffix}
          </button>

          {/* TABLE-20 : intertitre de section distinct (« Autre coffre ») ; « Migrer vers... » le répétait
              mot pour mot dans les 12 langues, juste au-dessus de l'action du même nom */}
          <div className="context-menu-label" style={{ fontSize: 'var(--text-xs)', opacity: 0.7 }}>{t('contextMenu.otherVaultSection')}</div>
          <button
            onClick={otherVault ? () => inEntryVault('migrate', { mode: 'copy' }) : () => {
              setMigrateSecrets({ secrets: getSecretsForBatch(), mode: 'copy' });
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {withEllipsis(t('contextMenu.copyTo'))}{batchSuffix}
          </button>
          <button
            onClick={otherVault ? () => inEntryVault('migrate', { mode: 'move' }) : () => {
              setMigrateSecrets({ secrets: getSecretsForBatch(), mode: 'move' });
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {withEllipsis(t('contextMenu.migrate'))}{batchSuffix}
          </button>

          {/* TABLE-20 : séparateur, l'historique ne fait pas partie de la section « Autre coffre »
              (rendu avec l'élément : jamais deux séparateurs de suite en KV v1) */}
          {entryEngineVersion === 2 && (
            <>
              <div className="context-menu-separator" role="separator" />
              <button
                onClick={otherVault ? () => inEntryVault('history') : () => {
                  setVersionHistory({ secretName: contextMenu.secret.name });
                  setContextMenu(null);
                }}
                role="menuitem"
                className="context-menu-item"
                type="button"
                {...entryItemProps}
              >
                {t('contextMenu.history')}
              </button>
            </>
          )}

          <div className="context-menu-separator" role="separator" />

          <div className="context-menu-label">{t('totp.title')}</div>
          <button
            onClick={otherVault ? () => inEntryVault('showTotp') : async () => {
              await handleShowTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {t('contextMenu.showTotp')}
          </button>
          <button
            onClick={otherVault ? () => inEntryVault('copyTotp') : async () => {
              await handleCopyTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            {...entryItemProps}
          >
            {t('contextMenu.copyField', { field: 'TOTP' })}
          </button>
          <button
            onClick={() => {
              if (totpExists) return;
              if (otherVault) { inEntryVault('configureTotp'); return; }
              handleConfigureTotp(contextMenu.secret);
              setContextMenu(null);
            }}
            role="menuitem"
            className="context-menu-item"
            type="button"
            title={otherVault ? otherVaultHint : undefined}
            disabled={totpExists || (otherVault && !canRunInEntryVault)}
          >
            {t('contextMenu.configurTotp')} {totpExists && `(${t('contextMenu.showTotp')})`}
          </button>
          {totpExists && (
            <button
              onClick={otherVault ? () => inEntryVault('deleteTotp') : async () => {
                // Boîte de confirmation (danger) : rien n'est supprimé avant validation explicite
                if (typeof confirmDeleteTotp === 'function') {
                  confirmDeleteTotp(contextMenu.secret);
                  setContextMenu(null);
                  return;
                }
                await handleDeleteTotp(contextMenu.secret);
                setContextMenu(null);
              }}
              role="menuitem"
              className="context-menu-item danger"
              type="button"
              {...entryItemProps}
            >
              {t('contextMenu.deleteTotp')}
            </button>
          )}
        </>
      )}
    </div>
  );
}
