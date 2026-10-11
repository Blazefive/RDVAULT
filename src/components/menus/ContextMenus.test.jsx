// ========================================
// TESTS : menus contextuels dossier / coffre / colonnes / tags (rendu réel react-dom dans jsdom)
// ========================================
// Suite C1 : rôles ARIA des menus (role="menu" nommé, éléments "menuitem" ou "menuitemcheckbox",
// séparateurs "separator") avec le vrai hook useContextMenus (focus, flèches, Échap) ;
// textes du menu des tags traduits (placeholder « #nouveau-tag », bouton « OK »).

import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import ContextMenus from './ContextMenus';
import { useContextMenus } from '../../hooks/useContextMenus';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
let api = null;
let handlers = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

function Harness() {
  api = useContextMenus({ getTotpKeyName: (n) => n, checkTotpExists: async () => false, discoveredTags: ['#prod', '#dev'] });
  const [visibleColumns, setVisibleColumns] = useState({ name: true, username: true, password: false, url: true, notes: false, tags: true, customFields: false });
  return (
    <div>
      <button type="button" id="row">ligne</button>
      <ContextMenus
        folderContextMenu={api.folderContextMenu}
        handleDeleteFolder={handlers.handleDeleteFolder}
        columnContextMenu={api.columnContextMenu}
        visibleColumns={visibleColumns}
        setVisibleColumns={setVisibleColumns}
        tagContextMenu={api.tagContextMenu}
        setTagContextMenu={api.setTagContextMenu}
        tagContextMenuRef={api.tagContextMenuRef}
        tagCreateMode={api.tagCreateMode}
        setTagCreateMode={api.setTagCreateMode}
        tagCreateValue={api.tagCreateValue}
        setTagCreateValue={api.setTagCreateValue}
        handleAddTagToSecret={handlers.handleAddTagToSecret}
        handleRemoveTagFromSecret={handlers.handleRemoveTagFromSecret}
        getTagColor={() => '#888'}
        engineContextMenu={api.engineContextMenu}
        setEngineContextMenu={api.setEngineContextMenu}
        setEngineToDelete={handlers.setEngineToDelete}
        t={t}
      />
    </div>
  );
}

function mount() {
  localStorage.setItem('vault-client.username', 'alice');
  handlers = {
    handleDeleteFolder: jest.fn(),
    handleAddTagToSecret: jest.fn(),
    handleRemoveTagFromSecret: jest.fn(),
    setEngineToDelete: jest.fn(),
  };
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <Harness />); });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  api = null;
  handlers = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const ev = (target) => ({ preventDefault() {}, stopPropagation() {}, clientX: 10, clientY: 10, target });
const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts })); });
};
const menu = () => document.querySelector('.context-menu');
const menuName = (el) => {
  const labelledby = el.getAttribute('aria-labelledby');
  if (labelledby) return document.getElementById(labelledby)?.textContent.trim();
  return el.getAttribute('aria-label');
};
// Rôles : tous les éléments de menu sont des menuitem(checkbox), tous les séparateurs des separator
const expectMenuRoles = () => {
  const m = menu();
  expect(m.getAttribute('role')).toBe('menu');
  expect(menuName(m)).toBeTruthy();
  expect(m.querySelectorAll('button.context-menu-item:not([role="menuitem"])').length).toBe(0);
  expect(m.querySelectorAll('.context-menu-separator:not([role="separator"])').length).toBe(0);
};

describe('menu du dossier', () => {
  test('role="menu" nommé par le dossier, élément menuitem ; flèches et Échap (hook)', () => {
    mount();
    const row = document.getElementById('row');
    row.focus();
    act(() => { api.handleFolderRightClick(ev(row), 'Projets/2026'); });
    expectMenuRoles();
    expect(menuName(menu())).toBe('Projets/2026');
    const item = menu().querySelector('[role="menuitem"]');
    expect(item.textContent).toContain(en.contextMenu.deleteFolder);
    expect(document.activeElement).toBe(item);
    // L'icône n'est pas lue
    expect(item.querySelector('[aria-hidden="true"]')).not.toBeNull();
    press('Escape');
    expect(menu()).toBeNull();
    expect(document.activeElement).toBe(row);
  });
});

describe('menu du coffre', () => {
  test('role="menu" nommé par le coffre, élément menuitem actionnable', () => {
    mount();
    act(() => { api.handleEngineRightClick(ev(document.body), { name: 'users/alice/Mes-Secrets' }); });
    expectMenuRoles();
    expect(menuName(menu())).toBe('users/alice/Mes-Secrets');
    act(() => { menu().querySelector('[role="menuitem"]').click(); });
    expect(handlers.setEngineToDelete).toHaveBeenCalledWith({ name: 'users/alice/Mes-Secrets' });
  });
});

describe('menu des colonnes', () => {
  test('role="menu" nommé par son intitulé ; cases menuitemcheckbox avec état coché', () => {
    mount();
    act(() => { api.handleColumnHeaderRightClick(ev(document.body)); });
    expectMenuRoles();
    expect(menuName(menu())).toBe(en.settings.columnsTitle);
    const boxes = Array.from(menu().querySelectorAll('input[type="checkbox"]'));
    expect(boxes).toHaveLength(7);
    for (const box of boxes) expect(box.getAttribute('role')).toBe('menuitemcheckbox');
    // Le libellé conteneur n'est pas un élément de menu (role="none")
    for (const label of menu().querySelectorAll('label')) expect(label.getAttribute('role')).toBe('none');
    const password = boxes[2];
    expect(password.checked).toBe(false);
    act(() => { password.click(); });
    expect(menu().querySelectorAll('input[type="checkbox"]')[2].checked).toBe(true);
  });

  test('flèches : navigation entre les cases', () => {
    mount();
    act(() => { api.handleColumnHeaderRightClick(ev(document.body)); });
    const boxes = Array.from(menu().querySelectorAll('[role="menuitemcheckbox"]'));
    expect(document.activeElement).toBe(boxes[0]);
    press('ArrowDown');
    expect(document.activeElement).toBe(boxes[1]);
    press('End');
    expect(document.activeElement).toBe(boxes[boxes.length - 1]);
  });
});

describe('menu des tags', () => {
  const SECRET = { name: 'gitlab', tags: '#prod' };

  test('rôles : menu nommé, menuitem, separator ; indicateur de défilement masqué', () => {
    mount();
    act(() => { api.handleTagCellRightClick(ev(document.body), SECRET); });
    expectMenuRoles();
    expect(menuName(menu())).toBe(en.table.tags);
    expect(menu().querySelectorAll('[role="separator"]').length).toBe(2);
    const labels = Array.from(menu().querySelectorAll('[role="menuitem"]')).map(b => b.textContent);
    expect(labels.some(l => l.includes(en.contextMenu.createTag))).toBe(true);
    expect(labels.some(l => l.includes('#dev') && l.includes(en.contextMenu.addTag))).toBe(true);
    expect(labels.some(l => l.includes('#prod') && l.includes(en.contextMenu.removeTag))).toBe(true);
    expect(menu().querySelector('.tag-menu-scroll-indicator').getAttribute('aria-hidden')).toBe('true');
  });

  test('création de tag : champ nommé, placeholder et bouton traduits', () => {
    mount();
    act(() => { api.handleTagCellRightClick(ev(document.body), SECRET); });
    const create = Array.from(menu().querySelectorAll('[role="menuitem"]')).find(b => b.textContent.includes(en.contextMenu.createTag));
    act(() => { create.click(); });
    const input = menu().querySelector('input[type="text"]');
    expect(input.getAttribute('aria-label')).toBe(en.contextMenu.createTag);
    expect(input.getAttribute('placeholder')).toBe(en.contextMenu.newTagPlaceholder);
    expect(input.getAttribute('placeholder')).not.toBe('#nouveau-tag');
    expect(Array.from(menu().querySelectorAll('button')).some(b => b.textContent.trim() === en.common.ok)).toBe(true);
  });

  test('ajout d\'un tag par le clavier : flèche puis Entrée sur un menuitem', () => {
    mount();
    act(() => { api.handleTagCellRightClick(ev(document.body), SECRET); });
    press('ArrowDown'); // de « Créer un tag » vers « Ajouter #dev »
    const focused = document.activeElement;
    expect(focused.getAttribute('role')).toBe('menuitem');
    expect(focused.textContent).toContain('#dev');
    act(() => { focused.click(); });
    expect(handlers.handleAddTagToSecret).toHaveBeenCalledWith(SECRET, '#dev');
  });
});
