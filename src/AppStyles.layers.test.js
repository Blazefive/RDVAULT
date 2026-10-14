// ========================================
// TESTS : UI-39 — les menus passent au-dessus des notifications (minuteur du presse-papiers)
// ========================================
// Avant : .clipboard-timer (z-index --z-toast = 500) recouvrait .context-menu (--z-dropdown =
// 100) pendant 12 s après une copie : éléments du menu masqués, et un clic sur « Afficher le
// code TOTP » tombait sur « Effacer maintenant » (presse-papiers vidé au lieu du code).
// Attendu : menus contextuels au-dessus des notifications (nouvelle couche --z-popover = 550).
// Aucun menu contextuel ne s'ouvre par-dessus une modale (le fond de la modale couvre le
// tableau), l'ordre retenu est donc : dropdown (100) < modal (400) < toast (500) < popover (550).

const fs = require('fs');
const path = require('path');

const CSS = fs.readFileSync(path.join(__dirname, 'AppStyles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
const block = (selector) => {
  const start = CSS.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`bloc introuvable : ${selector}`);
  const open = CSS.indexOf('{', start);
  return CSS.slice(open + 1, CSS.indexOf('}', open));
};
const ROOT = {};
for (const m of block(':root').matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) ROOT[m[1]] = m[2].trim();
const zIndex = (selector) => {
  const v = block(selector).match(/z-index:\s*([^;]+);/)[1].trim();
  const ref = v.match(/^var\((--[\w-]+)\)$/);
  return Number(ref ? ROOT[ref[1]] : v);
};

test('.context-menu au-dessus de .clipboard-timer et de .toast', () => {
  expect(zIndex('.context-menu')).toBeGreaterThan(zIndex('.clipboard-timer'));
  expect(zIndex('.context-menu')).toBeGreaterThan(zIndex('.toast'));
});

test('le minuteur reste au-dessus des modales (copie depuis une modale : visible)', () => {
  expect(zIndex('.clipboard-timer')).toBeGreaterThan(zIndex('.modal-overlay'));
});
