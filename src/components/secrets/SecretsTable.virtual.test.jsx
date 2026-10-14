// ========================================
// TESTS : tableau des secrets virtualisé (seules les lignes visibles + marge dans le DOM)
// ========================================
// Avant : les 1 200 / 5 000 lignes d'un gros coffre étaient toutes dans le DOM (5 à 9 ms de fil
// principal par image d'animation, ≈ 65 ms de mise en page à 5 000 lignes). Attendu : au-delà de
// VIRTUALIZE_THRESHOLD lignes, une fenêtre de lignes rendues entre deux espaceurs qui conservent la
// hauteur totale ; clavier, focus, sélection, menus, glisser-déposer inchangés ; sous le seuil, rendu
// complet strictement identique (aucun espaceur ni attribut ajouté).
// jsdom ne met rien en page : la géométrie (conteneur défilant de 600 px, en-tête de 40 px, hauteur
// des lignes) est simulée par getBoundingClientRect / clientHeight / scrollTop.
import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import SecretsTable from './SecretsTable';
import { useSelection } from '../../hooks/useSelection';
import { VIRTUALIZE_THRESHOLD, DEFAULT_ROW_HEIGHT } from './virtualRows';
import en from '../../locales/en.json';

jest.mock('../../utils/urlHandler', () => ({ handleUrlAction: jest.fn().mockResolvedValue(undefined) }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const t = (key) => key.split('.').reduce((o, k) => (o ? o[k] : undefined), en) || key;
const make = (n, prefix = 'entree') => Array.from({ length: n }, (_, i) => ({
  name: `${prefix}-${String(i).padStart(5, '0')}`, username: `u${i}`, password: `p${i}`, url: '', notes: '', tags: 'prod',
}));
const BIG = 5000;
const VIEW = 600; // hauteur du conteneur défilant
const HEADER = 40; // hauteur de l'en-tête collant

// ─── Géométrie simulée ───
let host; let root; let scrollTop; let rowHeight; let realRect;
beforeAll(() => { realRect = Element.prototype.getBoundingClientRect; });
beforeEach(() => {
  scrollTop = 0;
  rowHeight = 0; // 0 = « non mis en page » : hauteur estimée (DEFAULT_ROW_HEIGHT)
  Element.prototype.getBoundingClientRect = function rect() {
    const box = (top, height) => ({ top, bottom: top + height, left: 0, right: 800, width: 800, height, x: 0, y: top });
    if (this.tagName === 'TBODY') return box(HEADER - scrollTop, 0);
    if (this.tagName === 'THEAD') return box(0, HEADER);
    if (this.tagName === 'TR' && this.hasAttribute('aria-rowindex') && this.parentElement?.tagName === 'TBODY') return box(0, rowHeight);
    if (this === host) return box(0, VIEW);
    return realRect.call(this);
  };
  host = document.createElement('div');
  host.style.overflowY = 'auto';
  Object.defineProperty(host, 'clientHeight', { configurable: true, get: () => VIEW });
  Object.defineProperty(host, 'scrollTop', { configurable: true, get: () => scrollTop, set: (v) => { scrollTop = Math.max(0, v); } });
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  Element.prototype.getBoundingClientRect = realRect;
});

function props(over = {}) {
  const list = over.filteredSecrets || make(BIG);
  const selected = over.selectedSecrets || new Set();
  const noop = () => {};
  return {
    filteredSecrets: list, secrets: list, allVaultSecrets: [],
    selectedEngine: { name: 'kv', version: 2 }, loadingSecrets: false, multiVaultSearch: false, search: '',
    visiblePasswords: {}, setVisiblePasswords: noop,
    effectiveVisibleColumns: { name: true, username: true, password: true, url: true, notes: true, tags: true, customFields: false },
    columnWidths: {}, resizingColumn: null, isCurrentEngineRbiOnly: false, token: 'tok',
    selectedSecrets: selected, isSecretSelected: (k) => selected.has(k), toggleSecretSelection: jest.fn(),
    displayedSecretsRef: { current: null }, isDragging: false, dragOverTarget: null,
    handleDragStart: jest.fn(), handleDragEnd: jest.fn(), handleDragOver: noop, handleDragLeave: noop, handleDropOnFolder: jest.fn(),
    handleColumnResizeStart: noop, autoFitColumn: noop, handleColumnHeaderRightClick: noop,
    handleEmptyAreaRightClick: jest.fn(), handleCellRightClick: jest.fn(), handleFolderRightClick: jest.fn(), handleTagCellRightClick: noop,
    isSecretRbiOnly: () => false, startClipboardTimer: noop, setNotesPopup: noop, setCurrentPath: jest.fn(),
    getTagColor: () => '#888', getTotpKeyName: (n) => n, getTotpCode: noop, showToast: noop, t,
    ...over,
  };
}
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const paint = (p) => { act(() => { mountInRoot(root, <SecretsTable {...p} />); }); return p; };

const bodyRows = () => Array.from(host.querySelectorAll('tbody > tr'));
const dataRows = () => bodyRows().filter(tr => tr.hasAttribute('aria-rowindex'));
const spacers = () => bodyRows().filter(tr => tr.classList.contains('virtual-spacer'));
const indexOf = (tr) => Number(tr.getAttribute('aria-rowindex')) - 2;
const rowAt = (i) => host.querySelector(`tbody tr[aria-rowindex="${i + 2}"]`);
const spacerHeight = (tr) => parseFloat(tr.firstChild.style.height);
const nextFrame = () => new Promise(r => requestAnimationFrame(() => r()));
async function scrollTo(y) {
  scrollTop = y;
  await act(async () => { host.dispatchEvent(new Event('scroll')); await nextFrame(); });
}
const focusRow = (el) => { act(() => { el.focus(); }); };
const keydown = (el, key, opts = {}) => {
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts });
  act(() => { el.dispatchEvent(ev); });
  return ev;
};

describe('seuil', () => {
  test(`${VIRTUALIZE_THRESHOLD} lignes ou moins : rendu complet inchangé (ni espaceur ni attribut ARIA ajouté)`, () => {
    paint(props({ filteredSecrets: make(VIRTUALIZE_THRESHOLD) }));
    expect(bodyRows()).toHaveLength(VIRTUALIZE_THRESHOLD);
    expect(spacers()).toHaveLength(0);
    expect(host.querySelector('[aria-rowindex]')).toBeNull();
    expect(host.querySelector('table').hasAttribute('aria-rowcount')).toBe(false);
  });

  test('franchissement du seuil (entrées ajoutées) : passage en rendu fenêtré', () => {
    paint(props({ filteredSecrets: make(100) }));
    expect(bodyRows()).toHaveLength(100);
    paint(props({ filteredSecrets: make(1200) }));
    expect(dataRows().length).toBeLessThan(60);
    expect(host.querySelector('table').getAttribute('aria-rowcount')).toBe('1201');
  });
});

describe('fenêtre rendue', () => {
  test('5 000 lignes : seules les lignes visibles + marge dans le DOM, hauteur totale conservée', () => {
    paint(props());
    const rows = dataRows();
    expect(rows.length).toBeGreaterThan(VIEW / DEFAULT_ROW_HEIGHT); // la zone visible est couverte
    expect(rows.length).toBeLessThan(60);
    // aria-rowcount = lignes de données + en-tête ; aria-rowindex consécutifs à partir de 2
    expect(host.querySelector('table').getAttribute('aria-rowcount')).toBe(String(BIG + 1));
    expect(host.querySelector('thead tr').getAttribute('aria-rowindex')).toBe('1');
    rows.forEach((tr, k) => expect(indexOf(tr)).toBe(k));
    // Espaceur bas : hauteur des lignes absentes ; total = 5 000 lignes estimées
    expect(spacers()).toHaveLength(1);
    const bottom = spacers()[0];
    expect(bottom.getAttribute('aria-hidden')).toBe('true');
    expect(bottom.firstChild.getAttribute('colspan')).toBe('6');
    expect(spacerHeight(bottom)).toBeCloseTo((BIG - rows.length) * DEFAULT_ROW_HEIGHT, 3);
  });

  test('défilement : la fenêtre suit, espaceurs haut + bas, hauteur totale inchangée', async () => {
    paint(props());
    await scrollTo(2000 * DEFAULT_ROW_HEIGHT);
    const rows = dataRows();
    const first = indexOf(rows[0]);
    const last = indexOf(rows[rows.length - 1]);
    expect(first).toBeLessThanOrEqual(2000);
    expect(last).toBeGreaterThanOrEqual(2000 + Math.ceil(VIEW / DEFAULT_ROW_HEIGHT));
    expect(rowAt(0)).toBeNull();
    const [top, bottom] = spacers();
    expect(spacerHeight(top)).toBeCloseTo(first * DEFAULT_ROW_HEIGHT, 3);
    expect(spacerHeight(top) + rows.length * DEFAULT_ROW_HEIGHT + spacerHeight(bottom)).toBeCloseTo(BIG * DEFAULT_ROW_HEIGHT, 3);
    // Retour en haut : espaceur haut retiré, première ligne sans espaceur avant elle
    await scrollTo(0);
    expect(bodyRows()[0]).toBe(rowAt(0));
  });

  test('hauteurs mesurées : estimation = moyenne des lignes rendues, positions recalculées', async () => {
    rowHeight = 50;
    paint(props());
    const rows = dataRows();
    expect(spacerHeight(spacers()[0])).toBeCloseTo((BIG - rows.length) * 50, 3);
    await scrollTo(1000 * 50);
    expect(rowAt(1000)).not.toBeNull();
    expect(spacerHeight(spacers()[0])).toBeCloseTo(indexOf(dataRows()[0]) * 50, 3);
  });

  test('entrée « tardive » ajoutée en tête pendant l\'affichage : index et total mis à jour', () => {
    const list = make(BIG);
    paint(props({ filteredSecrets: list }));
    paint(props({ filteredSecrets: [{ name: 'aaa-tardive', username: 'x', password: 'y', url: '', notes: '', tags: '' }, ...list] }));
    expect(host.querySelector('table').getAttribute('aria-rowcount')).toBe(String(BIG + 2));
    expect(rowAt(0).querySelector('td.cell-name').textContent).toContain('aaa-tardive');
    expect(rowAt(1).querySelector('td.cell-name').textContent).toContain('entree-00000');
  });

  test('vue arborescence : dossiers indexés, Entrée ouvre, flèche bas vers l\'entrée suivante, dépôt sur un dossier', () => {
    const folders = Array.from({ length: 30 }, (_, i) => ({ name: `dossier-${i}`, displayName: `dossier-${i}`, isFolder: true }));
    const p = paint(props({ filteredSecrets: [...folders, ...make(300)] }));
    expect(rowAt(0).className).toBe('folder-row');
    keydown(rowAt(0), 'Enter');
    expect(p.setCurrentPath).toHaveBeenCalledWith('dossier-0');
    // Dernier dossier (hors de la fenêtre initiale) puis flèche bas : première entrée
    focusRow(rowAt(0));
    for (let i = 0; i < 29; i++) keydown(document.activeElement, 'ArrowDown');
    expect(document.activeElement.textContent).toContain('dossier-29');
    keydown(document.activeElement, 'ArrowDown');
    expect(document.activeElement.querySelector('td.cell-name').textContent).toContain('entree-00000');
    // Dépôt sur un dossier rendu après défilement
    act(() => { rowAt(29).dispatchEvent(new Event('drop', { bubbles: true })); });
    expect(p.handleDropOnFolder).toHaveBeenCalledWith(expect.anything(), 'dossier-29');
  });

  test('colonnes masquées / coffre affiché : colspan de l\'espaceur = colonnes visibles', () => {
    paint(props({ effectiveVisibleColumns: { name: true, username: false, password: false, url: true, notes: false, tags: false, customFields: false } }));
    expect(spacers()[0].firstChild.getAttribute('colspan')).toBe('2');
  });
});

describe('clavier et focus', () => {
  test('Fin : la dernière ligne (jamais rendue) est rendue, focalisée et défilée en vue', () => {
    paint(props());
    focusRow(rowAt(0));
    const ev = keydown(rowAt(0), 'End');
    expect(ev.defaultPrevented).toBe(true);
    expect(rowAt(BIG - 1)).not.toBeNull();
    expect(document.activeElement).toBe(rowAt(BIG - 1));
    // Défilé en vue : bas de la dernière ligne = bas de la zone visible
    expect(scrollTop).toBeCloseTo(BIG * DEFAULT_ROW_HEIGHT + HEADER - VIEW, 3);
    // Début : retour à la première ligne, défilée sous l'en-tête
    keydown(document.activeElement, 'Home');
    expect(document.activeElement).toBe(rowAt(0));
    expect(scrollTop).toBe(0);
  });

  test('Flèche bas depuis la dernière ligne rendue : ligne suivante rendue et focalisée', () => {
    paint(props());
    const rows = dataRows();
    const lastRendered = rows[rows.length - 1];
    const i = indexOf(lastRendered);
    expect(rowAt(i + 1)).toBeNull();
    focusRow(lastRendered);
    keydown(lastRendered, 'ArrowDown');
    expect(document.activeElement).toBe(rowAt(i + 1));
    expect(scrollTop).toBeGreaterThan(0);
    keydown(document.activeElement, 'ArrowUp');
    expect(document.activeElement).toBe(rowAt(i));
  });

  test('Page suiv. / Page préc. : une page de lignes (zone visible sous l\'en-tête)', () => {
    paint(props());
    focusRow(rowAt(0));
    const page = Math.floor((VIEW - HEADER) / DEFAULT_ROW_HEIGHT) - 1;
    keydown(rowAt(0), 'PageDown');
    expect(document.activeElement).toBe(rowAt(page));
    keydown(rowAt(page), 'PageDown');
    expect(document.activeElement).toBe(rowAt(2 * page));
    keydown(rowAt(2 * page), 'PageUp');
    expect(document.activeElement).toBe(rowAt(page));
  });

  test('Flèche haut sur la première ligne : rien (touche non consommée)', () => {
    paint(props());
    focusRow(rowAt(0));
    const ev = keydown(rowAt(0), 'ArrowUp');
    expect(ev.defaultPrevented).toBe(false);
    expect(document.activeElement).toBe(rowAt(0));
  });

  test('ligne focalisée hors de la zone visible : reste rendue (focus jamais perdu)', async () => {
    paint(props());
    focusRow(rowAt(3));
    await scrollTo(3000 * DEFAULT_ROW_HEIGHT);
    expect(rowAt(3)).not.toBeNull();
    expect(document.activeElement).toBe(rowAt(3));
    // Ligne isolée entre deux espaceurs : hauteur totale toujours exacte
    const total = bodyRows().reduce((sum, tr) => sum + (tr.classList.contains('virtual-spacer') ? spacerHeight(tr) : DEFAULT_ROW_HEIGHT), 0);
    expect(total).toBeCloseTo(BIG * DEFAULT_ROW_HEIGHT, 3);
    // Flèche bas depuis cette ligne : ligne 4, rendue et focalisée
    keydown(rowAt(3), 'ArrowDown');
    expect(document.activeElement).toBe(rowAt(4));
  });

  test('Tab / Maj+Tab vers une ligne voisine non rendue : rendue et focalisée (ordre de tabulation conservé)', async () => {
    paint(props());
    focusRow(rowAt(3));
    await scrollTo(3000 * DEFAULT_ROW_HEIGHT);
    expect(rowAt(4)).toBeNull();
    // Tab sur la ligne elle-même : ordre natif (vers le bouton œil de la ligne), rien d'intercepté
    expect(keydown(rowAt(3), 'Tab').defaultPrevented).toBe(false);
    // Tab depuis le dernier élément focalisable de la ligne (bouton œil) : ligne 4
    const eye = rowAt(3).querySelector('.btn-action-view');
    act(() => { eye.focus(); });
    expect(keydown(eye, 'Tab').defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(rowAt(4));
    // Maj+Tab depuis la ligne 4 : retour sur la ligne 3 (de nouveau rendue)
    await scrollTo(3000 * DEFAULT_ROW_HEIGHT);
    expect(keydown(rowAt(4), 'Tab', { shiftKey: true }).defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(rowAt(3));
    // Voisine rendue : ordre natif
    expect(keydown(rowAt(3), 'Tab', { shiftKey: true }).defaultPrevented).toBe(false);
  });

  test('Entrée sur une ligne atteinte au clavier : menu contextuel de la bonne entrée', () => {
    const p = paint(props());
    focusRow(rowAt(0));
    keydown(rowAt(0), 'End');
    keydown(document.activeElement, 'Enter');
    expect(p.handleCellRightClick).toHaveBeenCalledTimes(1);
    expect(p.handleCellRightClick.mock.calls[0][1].name).toBe(`entree-${String(BIG - 1).padStart(5, '0')}`);
  });

  test('sous le seuil : Page suiv. déplace aussi le focus (10 lignes sans géométrie)', () => {
    rowHeight = 0;
    paint(props({ filteredSecrets: make(40) }));
    const rows = bodyRows();
    focusRow(rows[0]);
    keydown(rows[0], 'PageDown');
    expect(document.activeElement).toBe(rows[10]);
    keydown(rows[10], 'End');
    expect(document.activeElement).toBe(rows[39]);
  });
});

describe('souris, menus, glisser-déposer', () => {
  test('clic droit sur une ligne après défilement : menu de l\'entrée correspondante', async () => {
    const p = paint(props());
    await scrollTo(4000 * DEFAULT_ROW_HEIGHT);
    act(() => { rowAt(4002).dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true })); });
    expect(p.handleCellRightClick.mock.calls[0][1].name).toBe('entree-04002');
    expect(p.handleEmptyAreaRightClick).not.toHaveBeenCalled();
    act(() => { rowAt(4003).click(); });
    expect(p.toggleSecretSelection).toHaveBeenCalledWith('entree-04003', false, false);
  });

  test('glisser : la ligne source reste rendue pendant le défilement jusqu\'à dragend', async () => {
    const p = paint(props());
    const src = rowAt(2);
    act(() => { src.dispatchEvent(new Event('dragstart', { bubbles: true })); });
    expect(p.handleDragStart).toHaveBeenCalledTimes(1);
    await scrollTo(2500 * DEFAULT_ROW_HEIGHT);
    expect(rowAt(2)).toBe(src); // même élément, toujours connecté
    act(() => { src.dispatchEvent(new Event('dragend', { bubbles: true })); });
    expect(p.handleDragEnd).toHaveBeenCalledTimes(1);
    expect(rowAt(2)).toBeNull();
  });

  test('sélection affichée sur une ligne rendue plus tard (sélection hors DOM conservée)', async () => {
    paint(props({ selectedSecrets: new Set(['entree-03000']) }));
    expect(rowAt(3000)).toBeNull();
    await scrollTo(2995 * DEFAULT_ROW_HEIGHT);
    expect(rowAt(3000).className).toBe('row-selected');
    expect(rowAt(2999).className).toBe('');
  });
});

describe('sélection réelle (useSelection) de lignes non rendues', () => {
  function Harness({ list }) {
    const sel = useSelection({ selectedEngineNameRef: { current: 'kv' } });
    const [, force] = useState(0);
    Harness.sel = sel;
    Harness.force = force;
    return (
      <SecretsTable
        {...props({ filteredSecrets: list })}
        selectedSecrets={sel.selectedSecrets}
        isSecretSelected={sel.isSecretSelected}
        toggleSecretSelection={sel.toggleSecretSelection}
        displayedSecretsRef={sel.displayedSecretsRef}
      />
    );
  }

  test('Maj+clic après défilement : la plage inclut les lignes jamais rendues', async () => {
    const list = make(BIG);
    act(() => { mountInRoot(root, <Harness list={list} />); });
    act(() => { rowAt(2).click(); });
    await scrollTo(3000 * DEFAULT_ROW_HEIGHT);
    act(() => { rowAt(3003).dispatchEvent(new MouseEvent('click', { bubbles: true, shiftKey: true })); });
    const selected = Harness.sel.selectedSecrets;
    expect(selected.size).toBe(3002);
    expect(selected.has('entree-01500')).toBe(true); // jamais rendue
    expect(rowAt(3003).className).toBe('row-selected');
    expect(rowAt(3003).textContent).toContain('✓');
    // Retour en haut : la ligne d'ancrage et ses voisines s'affichent sélectionnées
    await scrollTo(0);
    expect(rowAt(2).className).toBe('row-selected');
    expect(rowAt(1).className).toBe('');
  });
});
