// ========================================
// TESTS : useColumns — ajustement automatique, redimensionnement par image, sens RTL
// ========================================
// - TREE-20 : l'ajustement automatique (double-clic sur la poignée) affichait le toast « Copié »
//   sans aucune copie, et mesurait les mots de passe EN CLAIR (largeur = longueur du plus long).
// - Redimensionnement : un setState + une écriture localStorage à CHAQUE mousemove ; désormais
//   au plus un recalcul par image (requestAnimationFrame) et un seul enregistrement au relâchement.
// - RTL (I18N-31) : la colonne s'étend vers la gauche ; tirer la poignée vers la fin de ligne doit
//   l'élargir (delta selon le sens), sans inverser le geste d'une poignée restée au bord droit.
import { act } from 'react';
import { useColumns, resizeDirection } from './useColumns';
import { renderHook } from './testUtils/fakeVault';

global.IS_REACT_ACT_ENVIRONMENT = true;

// File d'images d'animation pilotée par le test
let frames;
let originalRaf;
let originalCaf;
beforeEach(() => {
  localStorage.clear();
  frames = new Map();
  let next = 1;
  originalRaf = window.requestAnimationFrame;
  originalCaf = window.cancelAnimationFrame;
  window.requestAnimationFrame = (cb) => { const id = next++; frames.set(id, cb); return id; };
  window.cancelAnimationFrame = (id) => { frames.delete(id); };
});
afterEach(() => {
  window.requestAnimationFrame = originalRaf;
  window.cancelAnimationFrame = originalCaf;
  document.documentElement.removeAttribute('dir');
  document.body.innerHTML = '';
  localStorage.clear();
  jest.restoreAllMocks();
});
const runFrames = () => act(() => {
  const pending = Array.from(frames.values());
  frames.clear();
  pending.forEach(cb => cb(performance.now()));
});

// Poignée réelle dans un en-tête de tableau (géométrie facultative)
function makeHandle({ thRect, handleRect } = {}) {
  const table = document.createElement('table');
  const tr = table.insertRow();
  const th = document.createElement('th');
  const handle = document.createElement('div');
  handle.className = 'column-resizer';
  th.appendChild(handle);
  tr.appendChild(th);
  document.body.appendChild(table);
  if (thRect) th.getBoundingClientRect = () => ({ ...thRect, width: thRect.right - thRect.left });
  if (handleRect) handle.getBoundingClientRect = () => ({ ...handleRect, width: handleRect.right - handleRect.left });
  return handle;
}
const mouse = (type, clientX) => document.dispatchEvent(new MouseEvent(type, { clientX, bubbles: true }));
const startEvent = (handle, clientX) => ({ preventDefault() {}, stopPropagation() {}, clientX, currentTarget: handle, target: handle });

describe('TREE-20 — ajustement automatique', () => {
  test('aucun toast (avant : « Copié ») ; largeur enregistrée', () => {
    const showToast = jest.fn();
    const { result, unmount } = renderHook(() => useColumns(showToast, (k) => k));
    act(() => { result.current.handleColumnAutoFit(startEvent(null, 0), 'name', { dataSource: [{ name: 'abc' }] }); });
    expect(showToast).not.toHaveBeenCalled();
    expect(JSON.parse(localStorage.getItem('rdvault-column-widths')).name).toBe(result.current.columnWidths.name);
    unmount();
  });

  test('colonne mot de passe : largeur indépendante de la longueur des mots de passe', () => {
    // Largeur mesurée simulée : 10 px par caractère du texte mesuré
    jest.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function width() { return (this.textContent || '').length * 10; });
    const { result, unmount } = renderHook(() => useColumns(jest.fn(), (k) => k));
    act(() => { result.current.handleColumnAutoFit(startEvent(null, 0), 'password', { dataSource: [{ name: 'a', password: 'x' }] }); });
    const short = result.current.columnWidths.password;
    act(() => { result.current.handleColumnAutoFit(startEvent(null, 0), 'password', { dataSource: [{ name: 'a', password: 'y'.repeat(45) }] }); });
    expect(result.current.columnWidths.password).toBe(short); // avant : 450 + 80 → 530 (longueur révélée)
    unmount();
  });
});

describe('redimensionnement limité à une image', () => {
  test('dix mouvements avant une image : une seule mise à jour ; enregistrement unique au relâchement', () => {
    const setItem = jest.spyOn(Storage.prototype, 'setItem');
    let commits = 0;
    const { result, unmount } = renderHook(() => { commits++; return useColumns(jest.fn(), (k) => k); });
    const handle = makeHandle();
    act(() => { result.current.handleColumnResizeStart(startEvent(handle, 100), 'name', 150); });
    const commitsAtStart = commits;
    act(() => { for (let x = 101; x <= 110; x++) mouse('mousemove', x); });
    expect(commits).toBe(commitsAtStart);          // avant : un rendu par mouvement
    expect(frames.size).toBe(1);                   // une seule image demandée
    runFrames();
    expect(result.current.columnWidths.name).toBe(160); // dernière position appliquée
    expect(commits).toBe(commitsAtStart + 1);
    expect(setItem.mock.calls.filter(c => c[0] === 'rdvault-column-widths')).toHaveLength(0);

    act(() => { mouse('mousemove', 140); });
    act(() => { mouse('mouseup', 140); });          // relâché avant l'image : position finale appliquée
    expect(result.current.columnWidths.name).toBe(190);
    expect(frames.size).toBe(0);
    const writes = setItem.mock.calls.filter(c => c[0] === 'rdvault-column-widths');
    expect(writes).toHaveLength(1);
    expect(JSON.parse(writes[0][1]).name).toBe(190);
    // Geste terminé : les mouvements suivants sont ignorés
    act(() => { mouse('mousemove', 400); });
    runFrames();
    expect(result.current.columnWidths.name).toBe(190);
    unmount();
  });

  test('colonne en largeur automatique : le geste part de la largeur affichée (pas de saut à 150 px)', () => {
    const { result, unmount } = renderHook(() => useColumns(jest.fn(), (k) => k));
    const handle = makeHandle({ thRect: { left: 0, right: 171 }, handleRect: { left: 163, right: 171 } });
    act(() => { result.current.handleColumnResizeStart(startEvent(handle, 171), 'name', undefined); });
    act(() => { mouse('mousemove', 231); mouse('mouseup', 231); });
    expect(result.current.columnWidths.name).toBe(231); // avant : 150 + 60 = 210
    unmount();
  });

  test('bornes 80 / 600 px conservées', () => {
    const { result, unmount } = renderHook(() => useColumns(jest.fn(), (k) => k));
    const handle = makeHandle();
    act(() => { result.current.handleColumnResizeStart(startEvent(handle, 500), 'url', 200); });
    act(() => { mouse('mousemove', 0); });
    runFrames();
    expect(result.current.columnWidths.url).toBe(80);
    act(() => { mouse('mousemove', 2000); });
    runFrames();
    expect(result.current.columnWidths.url).toBe(600);
    act(() => { mouse('mouseup', 2000); });
    unmount();
  });
});

describe('sens du geste (RTL)', () => {
  test('LTR : tirer vers la droite élargit la colonne', () => {
    const { result, unmount } = renderHook(() => useColumns(jest.fn(), (k) => k));
    const handle = makeHandle();
    act(() => { result.current.handleColumnResizeStart(startEvent(handle, 300), 'name', 150); });
    act(() => { mouse('mousemove', 350); mouse('mouseup', 350); });
    expect(result.current.columnWidths.name).toBe(200);
    unmount();
  });

  test('document RTL : tirer vers la gauche (fin de ligne) élargit la colonne', () => {
    document.documentElement.setAttribute('dir', 'rtl');
    const { result, unmount } = renderHook(() => useColumns(jest.fn(), (k) => k));
    const handle = makeHandle();
    act(() => { result.current.handleColumnResizeStart(startEvent(handle, 300), 'name', 150); });
    act(() => { mouse('mousemove', 250); mouse('mouseup', 250); });
    expect(result.current.columnWidths.name).toBe(200); // avant : 100 (geste inversé)
    unmount();
  });

  test('RTL, poignée au bord gauche de l\'en-tête (feuille de style en miroir) : geste inversé', () => {
    document.documentElement.setAttribute('dir', 'rtl');
    const handle = makeHandle({ thRect: { left: 100, right: 300 }, handleRect: { left: 100, right: 108 } });
    expect(resizeDirection(handle)).toBe(-1);
  });

  test('RTL, poignée restée au bord droit : geste non inversé (pas d\'élargissement à rebours)', () => {
    document.documentElement.setAttribute('dir', 'rtl');
    const handle = makeHandle({ thRect: { left: 100, right: 300 }, handleRect: { left: 292, right: 300 } });
    expect(resizeDirection(handle)).toBe(1);
  });

  test('LTR, poignée au bord droit : +1 ; sans poignée ni sens : +1', () => {
    expect(resizeDirection(makeHandle({ thRect: { left: 0, right: 200 }, handleRect: { left: 192, right: 200 } }))).toBe(1);
    expect(resizeDirection(null)).toBe(1);
  });
});
