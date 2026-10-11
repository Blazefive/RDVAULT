// ========================================
// TESTS : tableau des secrets — re-rendus limités aux lignes concernées (PERF-7)
// ========================================
// Avant : chaque rendu d'App (frappe dans la recherche, clic de sélection, survol d'une cible
// de glisser-déposer, redimensionnement de colonne, toast) re-rendait TOUTES les lignes
// (plus d'une seconde de gel à 5 000 entrées). Mesure : getTagColor est appelée une fois par
// tag pendant le rendu d'une ligne → nombre d'appels = nombre de lignes re-rendues.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretsTable from './SecretsTable';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

const t = (key) => key.split('.').reduce((o, k) => (o ? o[k] : undefined), en) || key;
const N = 2000;
const SECRETS = [
  { name: 'Dossier', displayName: 'Dossier', isFolder: true },
  ...Array.from({ length: N }, (_, i) => ({ name: `entree-${i}`, username: `u${i}`, password: `p${i}`, url: '', notes: '', tags: 'prod' })),
];

let root; let host; let tagColorCalls;
const getTagColor = () => { tagColorCalls++; return '#888'; };

// Props telles qu'App les fournit : callbacks recréés à chaque rendu (nouvelles identités)
function props(over = {}) {
  const selected = over.selectedSecrets || new Set();
  return {
    filteredSecrets: SECRETS, secrets: SECRETS, allVaultSecrets: [],
    selectedEngine: { name: 'kv', version: 2 }, loadingSecrets: false, multiVaultSearch: false, search: '',
    visiblePasswords: {}, setVisiblePasswords: jest.fn(),
    effectiveVisibleColumns: { name: true, username: true, password: true, url: true, notes: true, tags: true, customFields: false },
    columnWidths: {}, resizingColumn: null, isCurrentEngineRbiOnly: false, token: 'tok',
    selectedSecrets: selected, isSecretSelected: (n) => selected.has(n), toggleSecretSelection: jest.fn(),
    displayedSecretsRef: { current: null },
    isDragging: false, dragOverTarget: null,
    handleDragStart: jest.fn(), handleDragEnd: jest.fn(), handleDragOver: jest.fn(), handleDragLeave: jest.fn(), handleDropOnFolder: jest.fn(),
    handleColumnResizeStart: jest.fn(), autoFitColumn: jest.fn(), handleColumnHeaderRightClick: jest.fn(),
    handleEmptyAreaRightClick: jest.fn(), handleCellRightClick: jest.fn(), handleFolderRightClick: jest.fn(), handleTagCellRightClick: jest.fn(),
    isSecretRbiOnly: () => false, startClipboardTimer: jest.fn(), setNotesPopup: jest.fn(), setCurrentPath: jest.fn(),
    getTagColor, getTotpKeyName: (n) => n, getTotpCode: jest.fn(), showToast: jest.fn(), t,
    ...over,
  };
}

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const paint = (p) => act(() => { mountInRoot(root, <SecretsTable {...p} />); });
const rowEl = (name) => Array.from(host.querySelectorAll('tbody tr')).find(r => (r.querySelector('td.cell-name')?.textContent || '').replace('✓', '') === name);

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  tagColorCalls = 0;
  paint(props());
  expect(tagColorCalls).toBe(N); // premier rendu : toutes les lignes
  tagColorCalls = 0;
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
});

test('rendu d\'App sans changement des lignes (frappe, toast) : aucune ligne re-rendue', () => {
  paint(props()); // nouvelles identités pour tous les callbacks
  expect(tagColorCalls).toBe(0); // avant : 2 000
});

test('sélection d\'une ligne : seule cette ligne est re-rendue', () => {
  paint(props({ selectedSecrets: new Set(['entree-10']) }));
  expect(tagColorCalls).toBe(1);
  expect(rowEl('entree-10').className).toBe('row-selected');
  tagColorCalls = 0;
  // Deuxième ligne sélectionnée : la coche apparaît aussi sur la première
  paint(props({ selectedSecrets: new Set(['entree-10', 'entree-11']) }));
  expect(tagColorCalls).toBe(2);
  expect(rowEl('entree-10').textContent).toContain('✓');
});

test('redimensionnement d\'une colonne : aucune ligne re-rendue, largeur portée par l\'en-tête', () => {
  paint(props({ columnWidths: { name: 240 } }));
  expect(tagColorCalls).toBe(0); // avant : 2 000 lignes re-rendues à chaque mouvement de souris
  // table-layout: fixed : l'en-tête fixe la largeur de la colonne (aucun style par cellule à recalculer)
  expect(host.querySelector('thead th').style.width).toBe('240px');
  expect(host.querySelector('.secrets-table').getAttribute('style')).toBeNull();
  expect(host.querySelector('tbody td.cell-name').style.width).toBe('');
});

test('survol d\'un dossier pendant un glisser-déposer : seule la ligne dossier change', () => {
  paint(props({ isDragging: true, dragOverTarget: 'folder:Dossier' }));
  expect(tagColorCalls).toBe(0);
  expect(host.querySelector('.folder-row').textContent).toContain(en.table.dropHere);
});

test('mot de passe révélé : seule la ligne concernée est re-rendue', () => {
  paint(props({ visiblePasswords: { 'entree-5': true } }));
  expect(tagColorCalls).toBe(1);
  expect(rowEl('entree-5').textContent).toContain('p5');
});

test('les lignes non re-rendues appellent toujours les DERNIERS callbacks (pas de fermeture périmée)', () => {
  const p = props();
  paint(p);
  act(() => { rowEl('entree-3').click(); });
  expect(p.toggleSecretSelection).toHaveBeenCalledWith('entree-3', false, false);
  act(() => { rowEl('entree-3').dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true })); });
  expect(p.handleCellRightClick).toHaveBeenCalledTimes(1);
  expect(tagColorCalls).toBe(0);
});

test('liste filtrée puis rétablie : les lignes conservées ne sont pas re-rendues (clés stables)', () => {
  paint(props({ filteredSecrets: SECRETS.slice(0, 101) }));
  expect(tagColorCalls).toBe(0); // avant : clés avec index → lignes remontées
  paint(props());
  expect(tagColorCalls).toBe(N - 100); // seules les lignes réapparues sont montées
});
