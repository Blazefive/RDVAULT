// ========================================
// TESTS : menu contextuel des secrets — vague F
// ========================================
// - SECRETS-12 : « Supprimer le TOTP » ouvre la boîte de confirmation (confirmDeleteTotp) et ne
//   supprime rien directement ; sans confirmDeleteTotp, repli sur la confirmation par seconde
//   demande de useTotp (handleDeleteTotp sans { confirmed }).
// - RBI-11 : la session sécurisée reçoit aussi le champ « website » de l'entrée.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretContextMenu from './SecretContextMenu';
import fr from '../../locales/fr.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), fr);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

const SECRET = { name: 'banque', username: 'alice', password: 'pw-alice', url: 'https://banque.example', website: 'https://login.banque.example' };

function mount(contextMenu, props = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  const handlers = {
    setContextMenu: jest.fn(), setEditSecret: jest.fn(), startClipboardTimer: jest.fn(),
    setMoveToFolder: jest.fn(), setMigrateSecrets: jest.fn(), confirmDeleteSecret: jest.fn(),
    handleDeleteTotp: jest.fn(async () => false),
  };
  act(() => {
    mountInRoot(root, (
      <SecretContextMenu
        contextMenu={contextMenu}
        contextMenuRef={{ current: null }}
        selectedEngine={{ name: 'kv', version: 2 }}
        isCurrentEngineRbiOnly={false}
        isSecretRbiOnly={() => false}
        treeViewEnabled={false}
        currentPath=""
        setShowCreateFolderModal={jest.fn()}
        setNewFolderName={jest.fn()}
        undeleteSecret={jest.fn()}
        getTotpKeyName={(n) => `KV-${n}`}
        getTotpCode={jest.fn(async () => null)}
        handleShowTotp={jest.fn()}
        handleCopyTotp={jest.fn()}
        handleConfigureTotp={jest.fn()}
        setShareRbiSecret={jest.fn()}
        setVersionHistory={jest.fn()}
        selectedSecrets={new Set()}
        secrets={[SECRET]}
        installedBrowsers={[]}
        appMode="local"
        showToast={jest.fn()}
        t={t}
        {...handlers}
        {...props}
      />
    ));
  });
  mounted.push(root);
  return { host, handlers };
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  delete window.electronRBI;
});

const itemByText = (text) => Array.from(document.querySelectorAll('.context-menu [role="menuitem"]')).find(b => b.textContent.includes(text));

describe('SECRETS-12 — « Supprimer le TOTP »', () => {
  test('ouvre la boîte de confirmation ; aucune suppression directe', async () => {
    const confirmDeleteTotp = jest.fn();
    const { handlers } = mount({ x: 1, y: 1, secret: SECRET, field: 'name', value: 'banque', totpExists: true }, { confirmDeleteTotp });
    await act(async () => { itemByText(fr.contextMenu.deleteTotp).click(); });
    expect(confirmDeleteTotp).toHaveBeenCalledWith(SECRET);
    expect(handlers.handleDeleteTotp).not.toHaveBeenCalled(); // avant : appel direct
    expect(handlers.setContextMenu).toHaveBeenCalledWith(null);
  });

  test('sans confirmDeleteTotp : repli sur la confirmation par seconde demande de useTotp', async () => {
    const { handlers } = mount({ x: 1, y: 1, secret: SECRET, field: 'name', value: 'banque', totpExists: true });
    await act(async () => { itemByText(fr.contextMenu.deleteTotp).click(); });
    expect(handlers.handleDeleteTotp).toHaveBeenCalledWith(SECRET);
    expect(handlers.handleDeleteTotp.mock.calls[0][1]).toBeUndefined(); // jamais { confirmed: true } ici
  });
});

describe('RBI-11 — champ « website » transmis à la session sécurisée', () => {
  test('entrée avec website : launchSession reçoit url ET website', async () => {
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    mount({ x: 1, y: 1, secret: SECRET, field: 'name', value: 'banque' });
    await act(async () => { itemByText(fr.contextMenu.openSecureBrowser).click(); });
    expect(launchSession).toHaveBeenCalledTimes(1);
    expect(launchSession.mock.calls[0][0]).toEqual(expect.objectContaining({
      url: 'https://banque.example', website: 'https://login.banque.example', username: 'alice', password: 'pw-alice',
    }));
  });

  test('entrée sans website (ou vide) : aucune option website', async () => {
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    mount({ x: 1, y: 1, secret: { ...SECRET, website: '   ' }, field: 'name', value: 'banque' });
    await act(async () => { itemByText(fr.contextMenu.openSecureBrowser).click(); });
    expect('website' in launchSession.mock.calls[0][0]).toBe(false);
  });

  test('résultat d\'un autre coffre (recherche multi-coffres) : website de CETTE entrée', async () => {
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    const foreign = { ...SECRET, website: 'https://sso.beta.example', engineName: 'Beta', engineVersion: 2 };
    mount({ x: 1, y: 1, secret: foreign, field: 'name', value: 'banque' }, { runInEntryVault: jest.fn() });
    await act(async () => { itemByText(fr.contextMenu.openSecureBrowser).click(); });
    expect(launchSession.mock.calls[0][0].website).toBe('https://sso.beta.example');
  });
});
