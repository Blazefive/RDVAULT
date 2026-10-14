// ========================================
// TESTS : fenêtrage du tableau des secrets (fonctions pures de virtualRows.js)
// ========================================
import {
  computeOffsets, indexAt, computeRange, renderedIndices, averageHeight, findScrollContainer, RANGE_STEP,
} from './virtualRows';

const keys = (n) => Array.from({ length: n }, (_, i) => `k${i}`);

test('positions cumulées : hauteurs mesurées, estimation pour les autres', () => {
  const heights = new Map([['k1', 80], ['k3', 0]]); // 0 = non mesurée
  const off = computeOffsets(keys(4), heights, 50);
  expect(Array.from(off)).toEqual([0, 50, 130, 180, 230]);
});

test('indexAt : ligne contenant l\'ordonnée, bornée', () => {
  const off = computeOffsets(keys(10), new Map(), 10);
  expect(indexAt(off, -5)).toBe(0);
  expect(indexAt(off, 0)).toBe(0);
  expect(indexAt(off, 9.9)).toBe(0);
  expect(indexAt(off, 10)).toBe(1);
  expect(indexAt(off, 95)).toBe(9);
  expect(indexAt(off, 1e9)).toBe(9);
  expect(indexAt(new Float64Array([0]), 10)).toBe(0);
});

test('computeRange : zone visible + marge, bornes arrondies au pas', () => {
  const off = computeOffsets(keys(1000), new Map(), 10);
  const r = computeRange(off, 5000, 300, { overscan: 100, step: 8 });
  expect(r.start).toBeLessThanOrEqual(490);
  expect(r.start % 8).toBe(0);
  expect(r.end).toBeGreaterThanOrEqual(541);
  expect(r.end % 8).toBe(0);
  // Bas de liste : fin bornée au nombre de lignes
  expect(computeRange(off, 9900, 300, { overscan: 0, step: 8 }).end).toBe(1000);
  // Liste vide
  expect(computeRange(new Float64Array([0]), 0, 300)).toEqual({ start: 0, end: 0 });
  // Petit défilement : fenêtre inchangée (moins de rendus pendant le défilement)
  const a = computeRange(off, 5000, 300, { overscan: 100, step: RANGE_STEP });
  const b = computeRange(off, 5010, 300, { overscan: 100, step: RANGE_STEP });
  expect(b).toEqual(a);
});

test('renderedIndices : fenêtre + lignes épinglées hors fenêtre, triées, sans doublon', () => {
  expect(renderedIndices(10, 14, [], 100)).toEqual([10, 11, 12, 13]);
  expect(renderedIndices(10, 14, [2, 12, 99, 2, -1, 500], 100)).toEqual([2, 10, 11, 12, 13, 99]);
  expect(renderedIndices(95, 120, [], 100)).toEqual([95, 96, 97, 98, 99]);
});

test('averageHeight : moyenne des hauteurs mesurées, hauteurs nulles ignorées', () => {
  expect(averageHeight([0, 0])).toBeNull();
  expect(averageHeight([57, 0, 84, 57])).toBe(66);
  expect(averageHeight([50, 60])).toBe(55);
});

test('findScrollContainer : premier ancêtre défilant, sinon la fenêtre', () => {
  const outer = document.createElement('div');
  outer.style.overflowY = 'auto';
  const inner = document.createElement('div');
  const table = document.createElement('table');
  inner.appendChild(table);
  outer.appendChild(inner);
  document.body.appendChild(outer);
  expect(findScrollContainer(table)).toBe(outer);
  const lone = document.createElement('table');
  document.body.appendChild(lone);
  expect(findScrollContainer(lone)).toBe(window);
  document.body.innerHTML = '';
});
