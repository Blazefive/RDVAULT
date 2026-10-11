// ========================================
// TESTS : tableau des secrets (rendu réel react-dom dans jsdom)
// ========================================
// - A11Y-27 : dossiers, lignes et lien URL utilisables au clavier (sans casser souris ni glisser-déposer).
// - A11Y-28 : bouton œil nommé (aria-label traduit + aria-pressed).
// - A11Y-36 : cliquer sur l'œil ne modifie plus la sélection de lignes.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretsTable from './SecretsTable';
import { handleUrlAction } from '../../utils/urlHandler';
import en from '../../locales/en.json';
import fr from '../../locales/fr.json';

jest.mock('../../utils/urlHandler', () => ({ handleUrlAction: jest.fn().mockResolvedValue(undefined) }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

const SECRETS = [
  { name: 'Dossier', displayName: 'Dossier', isFolder: true },
  { name: 'root-secret', username: 'alice', password: 'pw-alice', url: 'https://a.example.com', notes: '', tags: '' },
  { name: 'old', username: 'bob', password: 'pw-bob', url: '', notes: '', tags: '', deleted: true },
];

function mount(props = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  const handlers = {
    toggleSecretSelection: jest.fn(),
    setVisiblePasswords: jest.fn(),
    setCurrentPath: jest.fn(),
    handleCellRightClick: jest.fn(),
    handleFolderRightClick: jest.fn(),
    handleEmptyAreaRightClick: jest.fn(),
    handleTagCellRightClick: jest.fn(),
    handleColumnHeaderRightClick: jest.fn(),
    handleDragStart: jest.fn(),
    handleDragEnd: jest.fn(),
    handleDragOver: jest.fn(),
    handleDragLeave: jest.fn(),
    handleDropOnFolder: jest.fn(),
    startClipboardTimer: jest.fn(),
    setNotesPopup: jest.fn(),
  };
  const all = {
    filteredSecrets: SECRETS,
    secrets: SECRETS,
    allVaultSecrets: [],
    selectedEngine: { name: 'kv', version: 2 },
    loadingSecrets: false,
    multiVaultSearch: false,
    search: '',
    visiblePasswords: {},
    effectiveVisibleColumns: { name: true, username: true, password: true, url: true, notes: true, tags: true, customFields: false },
    columnWidths: {},
    resizingColumn: null,
    isCurrentEngineRbiOnly: false,
    token: 'tok',
    selectedSecrets: new Set(),
    isSecretSelected: () => false,
    displayedSecretsRef: { current: null },
    isDragging: false,
    dragOverTarget: null,
    handleColumnResizeStart: jest.fn(),
    autoFitColumn: jest.fn(),
    isSecretRbiOnly: () => false,
    getTagColor: () => '#888',
    getTotpKeyName: (n) => n,
    getTotpCode: jest.fn(),
    showToast: jest.fn(),
    t,
    ...handlers,
    ...props,
  };
  act(() => { mountInRoot(root, <SecretsTable {...all} />); });
  mounted.push(root);
  return { host, handlers };
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  jest.clearAllMocks();
});

const rows = () => Array.from(document.querySelectorAll('.secrets-table tbody tr'));
const keydown = (el, key, opts = {}) => {
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts });
  act(() => { el.dispatchEvent(ev); });
  return ev;
};

describe('A11Y-27 — dossiers et lignes au clavier', () => {
  test('ligne dossier focalisable ; Entrée ouvre le dossier', () => {
    const { handlers } = mount();
    const folder = rows()[0];
    expect(folder.tabIndex).toBe(0);
    folder.focus();
    expect(document.activeElement).toBe(folder);
    keydown(folder, 'Enter');
    expect(handlers.setCurrentPath).toHaveBeenCalledWith('Dossier');
  });

  test('ligne dossier : Espace ouvre aussi ; clic souris inchangé', () => {
    const { handlers } = mount();
    keydown(rows()[0], ' ');
    expect(handlers.setCurrentPath).toHaveBeenCalledTimes(1);
    act(() => { rows()[0].click(); });
    expect(handlers.setCurrentPath).toHaveBeenCalledTimes(2);
  });

  test('ligne secret focalisable ; Espace = sélection (Ctrl conservé)', () => {
    const { handlers } = mount();
    const row = rows()[1];
    expect(row.tabIndex).toBe(0);
    const ev = keydown(row, ' ', { ctrlKey: true });
    expect(ev.defaultPrevented).toBe(true); // pas de défilement de la page
    expect(handlers.toggleSecretSelection).toHaveBeenCalledWith('root-secret', true, false);
  });

  test('ligne secret : Entrée ouvre le menu contextuel de l\'entrée', () => {
    const { handlers } = mount();
    keydown(rows()[1], 'Enter');
    expect(handlers.handleCellRightClick).toHaveBeenCalledTimes(1);
    const [, secret, field] = handlers.handleCellRightClick.mock.calls[0];
    expect(secret.name).toBe('root-secret');
    expect(field).toBe('name');
  });

  test('ligne supprimée : Entrée ouvre le menu (Restaurer accessible), Espace ne sélectionne pas', () => {
    const { handlers } = mount();
    keydown(rows()[2], ' ');
    expect(handlers.toggleSecretSelection).not.toHaveBeenCalled();
    keydown(rows()[2], 'Enter');
    expect(handlers.handleCellRightClick.mock.calls[0][1].deleted).toBe(true);
  });

  test('touche Menu / Maj+F10 sur la ligne : menu de l\'entrée (et non « Nouvelle entrée » du tableau)', () => {
    const { handlers } = mount();
    act(() => { rows()[1].dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true })); });
    expect(handlers.handleCellRightClick).toHaveBeenCalledTimes(1);
    expect(handlers.handleEmptyAreaRightClick).not.toHaveBeenCalled();
  });

  test('flèches haut/bas : ligne voisine', () => {
    mount();
    rows()[1].focus();
    keydown(rows()[1], 'ArrowDown');
    expect(document.activeElement).toBe(rows()[2]);
    keydown(rows()[2], 'ArrowUp');
    expect(document.activeElement).toBe(rows()[1]);
  });

  test('glisser-déposer inchangé : la ligne reste draggable', () => {
    mount();
    expect(rows()[1].getAttribute('draggable')).toBe('true');
    expect(rows()[2].getAttribute('draggable')).toBe('false');
  });

  test('lien URL : vrai bouton, activable au clavier sans toucher la sélection', () => {
    const { handlers } = mount();
    const link = document.querySelector('.url-link');
    expect(link.tagName).toBe('BUTTON');
    expect(link.getAttribute('type')).toBe('button');
    // Entrée sur le bouton : la ligne ignore la touche (cible ≠ ligne)
    keydown(link, 'Enter');
    expect(handlers.handleCellRightClick).not.toHaveBeenCalled();
    act(() => { link.click(); });
    expect(handleUrlAction).toHaveBeenCalledTimes(1);
    expect(handlers.toggleSecretSelection).not.toHaveBeenCalled();
  });
});

describe('A11Y-28 / A11Y-36 — bouton œil', () => {
  test('nom accessible traduit et état aria-pressed', () => {
    mount();
    const eye = document.querySelector('.btn-action-view');
    expect(eye.getAttribute('aria-label')).toBe(en.table.showPassword);
    expect(eye.getAttribute('aria-pressed')).toBe('false');
  });

  test('mot de passe visible : aria-pressed="true", infobulle « Hide password »', () => {
    mount({ visiblePasswords: { 'root-secret': true } });
    const eye = document.querySelector('.btn-action-view');
    expect(eye.getAttribute('aria-pressed')).toBe('true');
    expect(eye.getAttribute('title')).toBe(en.table.hidePassword);
  });

  test('cliquer sur l\'œil n\'appelle pas toggleSecretSelection', () => {
    const { handlers } = mount();
    act(() => { document.querySelector('.btn-action-view').click(); });
    expect(handlers.setVisiblePasswords).toHaveBeenCalledTimes(1);
    expect(handlers.toggleSecretSelection).not.toHaveBeenCalled();
  });

  test('Espace sur l\'œil : la ligne ne change pas la sélection', () => {
    const { handlers } = mount();
    keydown(document.querySelector('.btn-action-view'), ' ');
    expect(handlers.toggleSecretSelection).not.toHaveBeenCalled();
  });
});

describe('Libellés traduits du tableau', () => {
  test('copie par double-clic : nom de champ traduit (plus « Username » en dur)', () => {
    const tFr = (key) => key.split('.').reduce((o, k) => (o ? o[k] : undefined), fr) || key;
    const { handlers } = mount({ t: tFr });
    const usernameCell = rows()[1].querySelectorAll('td')[1];
    act(() => { usernameCell.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })); });
    expect(handlers.startClipboardTimer).toHaveBeenCalledWith(fr.table.username, 'alice');
    expect(fr.table.username).not.toBe('Username');
  });

  test('cellule Tags vide : indication traduite', () => {
    mount();
    expect(document.querySelector('.secrets-table').textContent).toContain(en.table.rightClickToAddTag);
    expect(document.querySelector('.secrets-table').textContent).not.toContain('Clic droit pour ajouter');
  });
});
