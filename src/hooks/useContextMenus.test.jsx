// ========================================
// TESTS : hook useContextMenus (rendu réel react-dom dans jsdom)
// ========================================
// A11Y-34 : un seul menu ouvert à la fois, Échap ferme le menu et rend le focus à l'élément
// d'origine, focus déplacé dans le menu à l'ouverture, flèches pour naviguer.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useContextMenus } from './useContextMenus';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
let api = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

// Rendu minimal des menus ouverts (même classe que les vrais composants)
function Harness() {
  api = useContextMenus({ getTotpKeyName: (n) => n, checkTotpExists: async () => false, discoveredTags: ['#a'] });
  const open = api.contextMenu || api.engineContextMenu || api.folderContextMenu || api.columnContextMenu || api.tagContextMenu;
  return (
    <div>
      <button type="button" id="row">ligne</button>
      {open && (
        <div className="context-menu" ref={api.contextMenu ? api.contextMenuRef : undefined}>
          <button type="button" className="context-menu-item" id="first">un</button>
          <button type="button" className="context-menu-item" id="second">deux</button>
        </div>
      )}
      <div id="state">{JSON.stringify({
        cell: !!api.contextMenu, engine: !!api.engineContextMenu, folder: !!api.folderContextMenu,
        column: !!api.columnContextMenu, tag: !!api.tagContextMenu,
      })}</div>
    </div>
  );
}

function mount() {
  localStorage.setItem('vault-client.username', 'a11y');
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
  document.body.innerHTML = '';
  localStorage.clear();
});

const state = () => JSON.parse(document.getElementById('state').textContent);
const openCount = () => Object.values(state()).filter(Boolean).length;
const ev = (target) => ({ preventDefault() {}, stopPropagation() {}, clientX: 10, clientY: 10, target });
const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts })); });
};

describe('A11Y-34 — menus contextuels', () => {
  test('menu du coffre puis menu de cellule : un seul menu reste ouvert', async () => {
    mount();
    act(() => { api.handleEngineRightClick(ev(document.body), { name: 'users/a11y/Mes-Secrets' }); });
    expect(state().engine).toBe(true);
    await act(async () => { await api.handleCellRightClick(ev(document.body), { name: 'root-secret' }, 'name', 'root-secret'); });
    expect(state().cell).toBe(true);
    expect(state().engine).toBe(false);
    expect(openCount()).toBe(1);
  });

  test('menu de dossier puis colonne puis tags : exclusifs', () => {
    mount();
    act(() => { api.handleFolderRightClick(ev(document.body), 'Dossier'); });
    act(() => { api.handleColumnHeaderRightClick(ev(document.body)); });
    expect(openCount()).toBe(1);
    expect(state().column).toBe(true);
    act(() => { api.handleTagCellRightClick(ev(document.body), { name: 's', tags: '' }); });
    expect(openCount()).toBe(1);
    expect(state().tag).toBe(true);
  });

  test('ouverture : focus sur le premier élément ; Échap ferme et rend le focus à la ligne', async () => {
    mount();
    const row = document.getElementById('row');
    row.focus();
    await act(async () => { await api.handleCellRightClick(ev(row), { name: 'root-secret' }, 'name', 'root-secret'); });
    expect(document.activeElement.id).toBe('first');
    press('Escape');
    expect(openCount()).toBe(0);
    expect(document.activeElement).toBe(row);
  });

  test('flèches : navigation dans le menu ; Tab ferme et rend le focus', () => {
    mount();
    const row = document.getElementById('row');
    row.focus();
    act(() => { api.handleFolderRightClick(ev(row), 'Dossier'); });
    expect(document.activeElement.id).toBe('first');
    press('ArrowDown');
    expect(document.activeElement.id).toBe('second');
    press('ArrowDown');
    expect(document.activeElement.id).toBe('first');
    press('End');
    expect(document.activeElement.id).toBe('second');
    press('Tab');
    expect(openCount()).toBe(0);
    expect(document.activeElement).toBe(row);
  });

  test('clic extérieur : fermeture (comportement conservé)', () => {
    mount();
    act(() => { api.handleFolderRightClick(ev(document.body), 'Dossier'); });
    act(() => { document.body.click(); });
    expect(openCount()).toBe(0);
  });
});
