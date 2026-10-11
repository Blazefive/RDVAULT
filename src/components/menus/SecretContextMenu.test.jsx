// ========================================
// TESTS : menu contextuel des secrets (rendu réel react-dom dans jsdom)
// ========================================
// A11Y-37 : libellé de copie explicite (et non « Copié »), élément réellement désactivé sur une
// valeur vide, « Dupliquer » distinct de « Copier vers... », pas de « ...... », en-tête de section
// « Autre coffre » unique (TABLE-20) ; rôles menu / menuitem ; focus rendu à la ligne avant l'action.

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

const SECRET = { name: 'sans-url', username: 'carol', password: 'pw-carol', url: '' };

function mount(contextMenu, props = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  const handlers = {
    setContextMenu: jest.fn(), setEditSecret: jest.fn(), startClipboardTimer: jest.fn(),
    setMoveToFolder: jest.fn(), setMigrateSecrets: jest.fn(), confirmDeleteSecret: jest.fn(),
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
        getTotpKeyName={(n) => n}
        getTotpCode={jest.fn()}
        handleShowTotp={jest.fn()}
        handleCopyTotp={jest.fn()}
        handleConfigureTotp={jest.fn()}
        handleDeleteTotp={jest.fn()}
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
});

const items = () => Array.from(document.querySelectorAll('.context-menu [role="menuitem"]'));
const labels = () => items().map(b => b.textContent.trim());

describe('A11Y-37 — libellés et état du menu', () => {
  test('clic droit sur l\'URL vide : « Copier l\'URL » désactivé (plus « Copié » grisé mais actif)', () => {
    mount({ x: 1, y: 1, secret: SECRET, field: 'url', value: '' });
    const copy = items()[0];
    expect(copy.textContent.trim()).toBe(fr.contextMenu.copyUrl);
    expect(copy.disabled).toBe(true);
    expect(labels()).not.toContain(fr.toast.copied);
  });

  test('copie de l\'identifiant : libellé explicite, actif, appelle le minuteur', async () => {
    const { handlers } = mount({ x: 1, y: 1, secret: SECRET, field: 'username', value: 'carol' });
    const copy = items()[0];
    expect(copy.textContent.trim()).toBe(fr.contextMenu.copyUsername);
    expect(copy.disabled).toBe(false);
    await act(async () => { copy.click(); });
    expect(handlers.startClipboardTimer).toHaveBeenCalledWith(fr.table.username, 'carol');
  });

  test('« Dupliquer » distinct de « Copier vers... » ; aucun « ...... »', () => {
    mount({ x: 1, y: 1, secret: SECRET, field: 'username', value: 'carol' });
    const all = labels();
    expect(all.some(l => l.endsWith(fr.contextMenu.duplicate))).toBe(true);
    expect(all.filter(l => l.includes(fr.contextMenu.copyTo)).length).toBe(1);
    expect(all.some(l => l.includes('......'))).toBe(false);
    expect(all.some(l => l.includes(`${fr.contextMenu.moveToFolder}...`))).toBe(true);
  });

  // TABLE-20 : l'en-tête unique de la section n'est plus « Migrer vers... » (doublon de l'action) mais « Autre coffre »
  test('en-tête de la section « autre coffre » présent une seule fois', () => {
    mount({ x: 1, y: 1, secret: SECRET, field: 'username', value: 'carol' });
    const headers = Array.from(document.querySelectorAll('.context-menu-label')).map(l => l.textContent.trim());
    expect(headers.filter(h => h === fr.contextMenu.otherVaultSection).length).toBe(1);
    expect(headers).not.toContain(fr.migrate.migrateTitle);
  });

  test('menu ouvert sur la ligne (champ nom) : copie directe de l\'identifiant et du mot de passe', () => {
    mount({ x: 1, y: 1, secret: SECRET, field: 'name', value: 'sans-url' });
    expect(labels()).toEqual(expect.arrayContaining([fr.contextMenu.copyName, fr.contextMenu.copyUsername, fr.contextMenu.copyPassword]));
  });

  test('« Navigateur par défaut » traduit', () => {
    mount({ x: 1, y: 1, secret: { ...SECRET, url: 'https://a.example.com' }, field: 'url', value: 'https://a.example.com' });
    expect(labels().some(l => l.endsWith(fr.contextMenu.defaultBrowser))).toBe(true);
  });

  test('rôles : role="menu", éléments menuitem, séparateurs separator', () => {
    mount({ x: 1, y: 1, secret: SECRET, field: 'username', value: 'carol' });
    expect(document.querySelector('.context-menu').getAttribute('role')).toBe('menu');
    expect(document.querySelectorAll('.context-menu .context-menu-item:not([role="menuitem"])').length).toBe(0);
    expect(document.querySelectorAll('.context-menu .context-menu-separator:not([role="separator"])').length).toBe(0);
  });

  test('lot : nombre d\'entrées réellement traitées (homonymes absents du coffre exclus)', () => {
    const a = { name: 'a', username: 'u', password: 'p', url: '' };
    const b = { name: 'b', username: 'u', password: 'p', url: '' };
    const { handlers } = mount(
      { x: 1, y: 1, secret: a, field: 'name', value: 'a' },
      { selectedSecrets: new Set(['a', 'b', 'seulement-ailleurs']), secrets: [a, b] }
    );
    const move = items().find(i => i.textContent.includes(fr.contextMenu.moveToFolder));
    expect(move.textContent.trim().endsWith('(2)')).toBe(true); // avant : (3), taille de la sélection
    act(() => { move.click(); });
    expect(handlers.setMoveToFolder).toHaveBeenCalledWith({ secrets: [a, b] });
  });

  test('activation d\'un élément : focus rendu à la ligne d\'origine avant l\'action', () => {
    const row = document.createElement('button');
    document.body.appendChild(row);
    let focusedDuringAction = null;
    const { handlers } = mount(
      { x: 1, y: 1, secret: SECRET, field: 'username', value: 'carol', opener: row },
      { setEditSecret: jest.fn(() => { focusedDuringAction = document.activeElement; }) }
    );
    const edit = items().find(b => b.textContent.includes(fr.contextMenu.edit));
    edit.focus();
    act(() => { edit.click(); });
    expect(focusedDuringAction).toBe(row);
    expect(handlers.setContextMenu).toHaveBeenCalledWith(null);
  });
});

// ========================================
// SEARCH-9 / SEARCH-31 : résultat d'un AUTRE coffre (recherche multi-coffres)
// ========================================
// Avant : Modifier, Dupliquer, Supprimer, TOTP, Historique, Déplacer, Copier/Migrer et Partager
// appelaient directement les actions du coffre SÉLECTIONNÉ (setEditSecret, confirmDeleteSecret,
// handleShowTotp…) : écriture d'une copie, suppression de l'homonyme et de sa graine TOTP.
describe('SEARCH-9 / SEARCH-31 — résultat d\'un autre coffre', () => {
  const fill = (s, vars) => s.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k]);
  const FOREIGN = { name: 'banque', username: 'bob', password: 'beta-pass', url: 'https://banque.example', engineName: 'Beta', engineVersion: 2 };
  const itemByText = (text) => items().find(b => b.textContent.includes(text));
  const directHandlers = () => ({
    setEditSecret: jest.fn(), confirmDeleteSecret: jest.fn(), setMoveToFolder: jest.fn(), setMigrateSecrets: jest.fn(),
    setVersionHistory: jest.fn(), handleShowTotp: jest.fn(), handleCopyTotp: jest.fn(), handleConfigureTotp: jest.fn(),
    handleDeleteTotp: jest.fn(), setShareRbiSecret: jest.fn(),
  });
  const unmountAll = () => {
    mounted.forEach(r => act(() => r.unmount()));
    mounted = [];
    document.body.innerHTML = '';
  };

  test('libellé explicite et « Ouvrir dans le coffre » ; chaque action passe par le coffre de l\'entrée', () => {
    const cases = [
      [fr.contextMenu.edit, 'edit', undefined],
      [fr.contextMenu.delete, 'delete', undefined],
      [fr.contextMenu.history, 'history', undefined],
      [fr.contextMenu.moveToFolder, 'moveToFolder', undefined],
      [fr.contextMenu.copyTo, 'migrate', { mode: 'copy' }],
      [fr.contextMenu.migrate, 'migrate', { mode: 'move' }],
      [fr.contextMenu.showTotp, 'showTotp', undefined],
      [fill(fr.contextMenu.copyField, { field: 'TOTP' }), 'copyTotp', undefined],
      [fr.contextMenu.shareRbi, 'shareRbi', undefined],
      [fill(fr.contextMenu.openInVault, { engine: 'Beta' }), 'open', undefined],
    ];
    for (const [label, type, options] of cases) {
      const runInEntryVault = jest.fn();
      const direct = directHandlers();
      mount(
        { x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque', totpExists: true },
        { ...direct, runInEntryVault, appMode: 'vault', selectedEngine: { name: 'Alpha', version: 2 } }
      );
      expect(document.querySelector('.context-menu').textContent).toContain(fill(fr.contextMenu.otherVaultHint, { engine: 'Beta' }));
      const item = itemByText(label);
      expect(item.disabled).toBe(false);
      act(() => { item.click(); });
      expect(runInEntryVault).toHaveBeenCalledWith(FOREIGN, type, options);
      Object.values(direct).forEach(fn => expect(fn).not.toHaveBeenCalled());
      unmountAll();
    }
  });

  test('« Dupliquer » : duplication faite dans le coffre de l\'entrée', () => {
    const runInEntryVault = jest.fn();
    const { handlers } = mount({ x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque' }, { runInEntryVault, selectedEngine: { name: 'Alpha', version: 2 } });
    act(() => { itemByText(fr.contextMenu.duplicate).click(); });
    expect(runInEntryVault).toHaveBeenCalledWith(FOREIGN, 'duplicate', undefined);
    expect(handlers.setEditSecret).not.toHaveBeenCalled();
  });

  test('lot : une sélection contenant le nom n\'entraîne jamais les homonymes du coffre sélectionné', () => {
    const runInEntryVault = jest.fn();
    mount({ x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque' }, {
      runInEntryVault,
      selectedEngine: { name: 'Alpha', version: 2 },
      selectedSecrets: new Set(['banque', 'autre']),
      secrets: [{ name: 'banque' }, { name: 'autre' }],
    });
    const move = itemByText(fr.contextMenu.moveToFolder);
    expect(move.textContent.trim().endsWith(')')).toBe(false); // pas de « (2) »
    act(() => { move.click(); });
    expect(runInEntryVault).toHaveBeenCalledWith(FOREIGN, 'moveToFolder', undefined);
  });

  test('sans runInEntryVault : actions désactivées avec un libellé explicite ; copies et session sécurisée actives', () => {
    const direct = directHandlers();
    mount({ x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque' }, { ...direct, selectedEngine: { name: 'Alpha', version: 2 } });
    const hint = fill(fr.contextMenu.otherVaultReadOnly, { engine: 'Beta' });
    expect(document.querySelector('.context-menu').textContent).toContain(hint);
    const labelsToCheck = [
      fr.contextMenu.edit, fr.contextMenu.duplicate, fr.contextMenu.delete, fr.contextMenu.moveToFolder,
      fr.contextMenu.copyTo, fr.contextMenu.migrate, fr.contextMenu.history, fr.contextMenu.showTotp, fr.contextMenu.configurTotp,
    ];
    for (const label of labelsToCheck) {
      const item = itemByText(label);
      expect(item.disabled).toBe(true);
      expect(item.getAttribute('title')).toBe(hint);
    }
    expect(itemByText(fr.contextMenu.copyPassword).disabled).toBe(false);
    expect(itemByText(fr.contextMenu.openSecureBrowser).disabled).toBe(false);
  });

  test('TOTP : état lu sur la clé du coffre de l\'entrée (entryTotpExists), pas sur celle du coffre sélectionné', () => {
    // totpExists (coffre sélectionné) vrai, TOTP de l'entrée encore inconnu : pas de « Supprimer le TOTP »
    mount(
      { x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque', totpExists: true },
      { runInEntryVault: jest.fn(), selectedEngine: { name: 'Alpha', version: 2 } }
    );
    expect(itemByText(fr.contextMenu.deleteTotp)).toBeUndefined();
    expect(itemByText(fr.contextMenu.configurTotp).disabled).toBe(false);
    unmountAll();
    // TOTP de l'entrée présent
    const runInEntryVault = jest.fn();
    mount(
      { x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque', totpExists: false, entryTotpExists: true },
      { runInEntryVault, selectedEngine: { name: 'Alpha', version: 2 } }
    );
    expect(itemByText(fr.contextMenu.configurTotp).disabled).toBe(true);
    act(() => { itemByText(fr.contextMenu.deleteTotp).click(); });
    expect(runInEntryVault).toHaveBeenCalledWith(FOREIGN, 'deleteTotp', undefined);
  });

  test('historique : proposé selon la version KV du coffre de l\'entrée', () => {
    mount(
      { x: 1, y: 1, secret: { ...FOREIGN, engineVersion: 1 }, field: 'name', value: 'banque' },
      { runInEntryVault: jest.fn(), selectedEngine: { name: 'Alpha', version: 2 } }
    );
    expect(itemByText(fr.contextMenu.history)).toBeUndefined();
    unmountAll();
    mount({ x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque' }, { runInEntryVault: jest.fn(), selectedEngine: { name: 'Alpha', version: 1 } });
    expect(itemByText(fr.contextMenu.history)).toBeDefined();
  });

  test('session sécurisée : code TOTP lu sur la clé du coffre de l\'entrée (BETA-banque), sans changer de coffre', async () => {
    const launchSession = jest.fn(async () => ({ success: true }));
    window.electronRBI = { launchSession };
    const getTotpCode = jest.fn(async () => '654321');
    const getTotpKeyName = jest.fn((n) => `ALPHA-${n}`);
    const runInEntryVault = jest.fn();
    try {
      mount(
        { x: 1, y: 1, secret: FOREIGN, field: 'name', value: 'banque' },
        { runInEntryVault, getTotpCode, getTotpKeyName, selectedEngine: { name: 'Alpha', version: 2 } }
      );
      await act(async () => { itemByText(fr.contextMenu.openSecureBrowser).click(); });
      expect(getTotpCode).toHaveBeenCalledWith('BETA-banque'); // avant : ALPHA-banque
      expect(getTotpKeyName).not.toHaveBeenCalled();
      expect(launchSession).toHaveBeenCalledWith(expect.objectContaining({ username: 'bob', password: 'beta-pass', totp: '654321' }));
      expect(runInEntryVault).not.toHaveBeenCalled();
    } finally {
      delete window.electronRBI;
    }
  });

  test('ligne du coffre sélectionné (recherche multi-coffres) : actions directes, comme avant', () => {
    const runInEntryVault = jest.fn();
    const own = { ...FOREIGN, engineName: 'kv' };
    const { handlers } = mount({ x: 1, y: 1, secret: own, field: 'name', value: 'banque' }, { runInEntryVault });
    expect(document.querySelector('.context-menu').textContent).not.toContain(fill(fr.contextMenu.otherVaultHint, { engine: 'kv' }));
    act(() => { itemByText(fr.contextMenu.edit).click(); });
    expect(handlers.setEditSecret).toHaveBeenCalledWith(own);
    expect(runInEntryVault).not.toHaveBeenCalled();
  });
});

describe('session sécurisée : motif d\'échec traduit', () => {
  test('RBI_FOREIGN_ORIGIN → message traduit (avant : texte brut français du processus principal)', async () => {
    window.electronRBI = {
      launchSession: jest.fn(async () => ({ success: false, error: 'Page de connexion hors du domaine de l\'entrée', code: 'RBI_FOREIGN_ORIGIN' })),
    };
    const showToast = jest.fn();
    try {
      mount(
        { x: 1, y: 1, secret: { ...SECRET, url: 'https://a.example.com' }, field: 'name', value: 'sans-url' },
        { showToast, getTotpCode: jest.fn(async () => null) }
      );
      await act(async () => { items().find(b => b.textContent.includes(fr.contextMenu.openSecureBrowser)).click(); });
      expect(showToast).toHaveBeenCalledWith(fr.error.rbiForeignOrigin, 'error');
    } finally {
      delete window.electronRBI;
    }
  });
});
