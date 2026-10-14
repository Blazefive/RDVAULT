// ========================================
// FENÊTRAGE DU TABLEAU DES SECRETS (virtualisation maison, sans dépendance)
// ========================================
// Au-delà de VIRTUALIZE_THRESHOLD lignes, SecretsTable ne place dans le DOM que les lignes visibles
// (plus une marge) : deux lignes « espaceurs » (hauteur = somme des lignes absentes) conservent la
// hauteur totale du tableau, donc la taille et la position de la barre de défilement.
// Les hauteurs sont MESURÉES sur les lignes rendues (une cellule Tags ou Champs personnalisés peut
// passer sur deux lignes) ; une ligne jamais rendue compte pour une hauteur estimée (moyenne des
// premières mesures). Fonctions pures : testées sans DOM (virtualRows.test.js).

// Sous ce seuil : rendu complet, strictement inchangé (aucun espaceur, aucun attribut ajouté)
export const VIRTUALIZE_THRESHOLD = 150;
// Marge rendue au-dessus et au-dessous de la zone visible (px) : un défilement rapide ne découvre
// pas de zone vide avant la mise à jour (déclenchée à l'image suivante)
export const OVERSCAN_PX = 1000;
// Bornes de la fenêtre arrondies à ce pas : la fenêtre ne change qu'une fois toutes les RANGE_STEP
// lignes défilées (moins de rendus pendant le défilement). MESURÉ (Chromium en rendu logiciel comme
// l'application, molette à 2 500 px/s, 5 000 lignes) : chaque mise à jour de la fenêtre coûte une
// image ; marge 600 px / pas 8 → 20 images > 20 ms par geste (avant virtualisation : 13) ; marge
// 1 000 px / pas 16 → 11, au niveau du tableau complet, pour ≈ 30 à 60 lignes dans le DOM.
export const RANGE_STEP = 16;
// Lignes rendues avant la première mesure (premier rendu, avant le calcul de la zone visible)
export const INITIAL_ROWS = 40;
// Hauteur estimée d'une ligne avant toute mesure (padding --sp-4 × 2 + une ligne de texte + bordure)
export const DEFAULT_ROW_HEIGHT = 57;
// Hauteur de zone visible retenue quand le conteneur n'en a pas (élément masqué, environnement de test)
export const FALLBACK_VIEWPORT = 800;

/**
 * Positions cumulées des lignes : offsets[i] = haut de la ligne i (offsets[n] = hauteur totale).
 * @param {string[]} keys - Clé stable de chaque ligne
 * @param {Map<string, number>} heights - Hauteurs mesurées (par clé)
 * @param {number} estimate - Hauteur retenue pour une ligne non mesurée
 * @returns {Float64Array}
 */
export function computeOffsets(keys, heights, estimate) {
  const n = keys.length;
  const offsets = new Float64Array(n + 1);
  let y = 0;
  for (let i = 0; i < n; i++) {
    offsets[i] = y;
    const h = heights.get(keys[i]);
    y += h > 0 ? h : estimate;
  }
  offsets[n] = y;
  return offsets;
}

/**
 * Index de la ligne qui contient l'ordonnée y (bornée à [0, n - 1]), recherche dichotomique.
 * @param {Float64Array} offsets
 * @param {number} y
 * @returns {number}
 */
export function indexAt(offsets, y) {
  const n = offsets.length - 1;
  if (n <= 0) return 0;
  if (y <= 0) return 0;
  if (y >= offsets[n]) return n - 1;
  let lo = 0;
  let hi = n - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (offsets[mid] <= y) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/**
 * Lignes à rendre [start, end[ pour une zone visible donnée (coordonnées relatives au haut du tbody).
 * @param {Float64Array} offsets
 * @param {number} viewTop - Haut de la zone visible
 * @param {number} viewHeight - Hauteur de la zone visible
 * @param {{ overscan?: number, step?: number }} [opts]
 * @returns {{ start: number, end: number }}
 */
export function computeRange(offsets, viewTop, viewHeight, { overscan = OVERSCAN_PX, step = RANGE_STEP } = {}) {
  const n = offsets.length - 1;
  if (n <= 0) return { start: 0, end: 0 };
  const first = indexAt(offsets, viewTop - overscan);
  const last = indexAt(offsets, viewTop + Math.max(0, viewHeight) + overscan);
  const start = Math.max(0, Math.floor(first / step) * step);
  const end = Math.min(n, Math.ceil((last + 1) / step) * step);
  return { start, end: Math.max(end, Math.min(n, start + 1)) };
}

/**
 * Index rendus : la fenêtre [start, end[ plus les lignes « épinglées » hors fenêtre (ligne qui a le
 * focus, ligne en cours de glisser), triés. Une ligne épinglée reste dans le DOM quand on défile :
 * le focus clavier n'est jamais perdu et l'événement dragend atteint toujours la ligne source.
 * @param {number} start
 * @param {number} end
 * @param {number[]} pinned - Index épinglés (les index invalides sont ignorés)
 * @param {number} n - Nombre total de lignes
 * @returns {number[]}
 */
export function renderedIndices(start, end, pinned, n) {
  const out = [];
  const s = Math.max(0, Math.min(start, n));
  const e = Math.max(s, Math.min(end, n));
  const extra = Array.from(new Set(pinned.filter(i => Number.isInteger(i) && i >= 0 && i < n && (i < s || i >= e))))
    .sort((a, b) => a - b);
  let k = 0;
  while (k < extra.length && extra[k] < s) out.push(extra[k++]);
  for (let i = s; i < e; i++) out.push(i);
  while (k < extra.length) out.push(extra[k++]);
  return out;
}

/**
 * Moyenne des hauteurs mesurées : hauteur estimée des lignes non encore rendues. La moyenne (et non
 * la médiane) tient compte des lignes plus hautes (tags sur deux lignes) : hauteur totale et taille
 * de la barre de défilement plus justes avant que toutes les lignes aient été mesurées.
 * @param {number[]} values
 * @returns {number|null}
 */
export function averageHeight(values) {
  const v = values.filter(x => x > 0);
  if (!v.length) return null;
  return v.reduce((a, b) => a + b, 0) / v.length;
}

/**
 * Conteneur qui fait défiler le tableau : premier ancêtre en overflow-y auto / scroll
 * (.main-body dans l'application), sinon la fenêtre.
 * @param {Element|null} el
 * @returns {Element|Window}
 */
export function findScrollContainer(el) {
  for (let p = el ? el.parentElement : null; p; p = p.parentElement) {
    let oy = '';
    try { oy = window.getComputedStyle(p).overflowY; } catch { oy = ''; }
    if (oy === 'auto' || oy === 'scroll' || oy === 'overlay') return p;
  }
  return window;
}
