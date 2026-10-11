// ========================================
// TESTS : barre d'outils
// ========================================
// - Bouton « Vue liste » actif : fond `var(--accent-fill, var(--accent))` (violet de remplissage en
//   thème sombre sous texte blanc ; identique à --accent en clair) au lieu de `var(--accent)`.
// - Champ de recherche nommé (aria-label = libellé affiché en placeholder).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { TextEncoder } from 'util';
import Toolbar from './Toolbar';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu en chaîne (react-dom/server) : les styles inline y sont conservés tels quels, alors que le
// parseur CSS de jsdom ignore les valeurs var() imbriquées. react-dom/server requiert TextEncoder.
if (!global.TextEncoder) global.TextEncoder = TextEncoder;
const { renderToStaticMarkup: markupOf } = require('react-dom/server');

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key) => key.split('.').reduce((o, k) => (o ? o[k] : undefined), en) || key;

const baseProps = () => ({
  selectedEngine: { name: 'kv', version: 2, canWrite: true },
  isCurrentEngineRbiOnly: false,
  treeViewEnabled: false,
  currentPath: '',
  setEditSecret: jest.fn(),
  searchRef: { current: null },
  searchInput: '',
  setSearchInput: jest.fn(),
  debouncedSearch: jest.fn(),
  multiVaultSearch: false,
  setMultiVaultSearch: jest.fn(),
  search: '',
  setVisiblePasswords: jest.fn(),
  loadingAllSecrets: false,
  showDeleted: false,
  setShowDeleted: jest.fn(),
  appMode: 'local',
  setReceiveShareOpen: jest.fn(),
  setTreeViewEnabled: jest.fn(),
  setCurrentPath: jest.fn(),
  t,
});

function mount(props = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <Toolbar {...baseProps()} {...props} />); });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

describe('Toolbar', () => {
  test('vue arborescence active : fond « accent-fill » (repli --accent), plus de `background: var(--accent);` brut', () => {
    const markup = markupOf(<Toolbar {...baseProps()} treeViewEnabled />);
    const buttons = markup.match(/<button[^>]*>[^<]*<\/button>/g) || [];
    const toggle = buttons.find(b => b.includes(en.toolbar.listView)) || '';
    expect(toggle).toContain('background:var(--accent-fill, var(--accent))');
    expect(toggle).not.toMatch(/background:var\(--accent\);/);
    expect(toggle).toContain('type="button"');
  });

  test('champ de recherche nommé', () => {
    const host = mount();
    expect(host.querySelector('.search-input').getAttribute('aria-label')).toBe(en.toolbar.search);
  });
});

// SEARCH-16 : une fois la recherche vidée, la case « tous les coffres » restait cochée ET
// désactivée (impossible à décocher, arborescence perdue).
describe('Toolbar — case « Rechercher dans tous les coffres » (SEARCH-16)', () => {
  const multiBox = (host) => host.querySelector('label.checkbox-label input[type="checkbox"]');

  test('cochée avec une recherche vide : reste décochable', () => {
    const setMultiVaultSearch = jest.fn();
    const setVisiblePasswords = jest.fn();
    const host = mount({ multiVaultSearch: true, search: '', setMultiVaultSearch, setVisiblePasswords });
    const box = multiBox(host);
    expect(box.checked).toBe(true);
    expect(box.disabled).toBe(false); // avant : true
    act(() => { box.click(); });
    expect(setMultiVaultSearch).toHaveBeenCalledWith(false);
    expect(setVisiblePasswords).toHaveBeenCalledWith({});
  });

  test('cochée pendant le chargement de tous les coffres : décochable (chargement annulable)', () => {
    const host = mount({ multiVaultSearch: true, search: 'web', loadingAllSecrets: true });
    expect(multiBox(host).disabled).toBe(false);
  });

  test('décochée : impossible à cocher sans recherche ou pendant un chargement', () => {
    expect(multiBox(mount({ search: '' })).disabled).toBe(true);
    expect(multiBox(mount({ search: '   ' })).disabled).toBe(true);
    expect(multiBox(mount({ search: 'web', loadingAllSecrets: true })).disabled).toBe(true);
    expect(multiBox(mount({ search: 'web' })).disabled).toBe(false);
  });
});
