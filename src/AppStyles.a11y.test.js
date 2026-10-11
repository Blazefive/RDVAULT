// ========================================
// TESTS : AppStyles.css — variables utilisées par les composants et focus clavier visible
// ========================================
// 1. Toute variable CSS référencée SANS valeur de repli dans les sources (styles inline JSX et
//    feuilles CSS) doit être définie dans :root : sinon la déclaration est invalide au calcul
//    (bordures, coins arrondis, couleurs de Paramètres / fiche d'édition / partage RBI perdus).
// 2. A11Y-31 : l'indicateur de focus clavier des boutons .btn contraste ≥ 3:1 (WCAG 1.4.11)
//    avec les surfaces, en thème clair comme en sombre.
// 3. A11Y-30 (vérification) : --brand-violet-400 est défini, le bouton primaire sombre est valide
//    (contrôle détaillé dans AppStyles.theme.test.js).

const fs = require('fs');
const path = require('path');

const SRC = __dirname;
const CSS = fs.readFileSync(path.join(SRC, 'AppStyles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

function block(selector) {
  const start = CSS.indexOf(selector + ' {');
  if (start < 0) throw new Error('bloc introuvable : ' + selector);
  const open = CSS.indexOf('{', start);
  return CSS.slice(open + 1, CSS.indexOf('}', open));
}
function tokens(body) {
  const out = {};
  for (const m of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}
const ROOT = tokens(block(':root'));
const DARK = { ...ROOT, ...tokens(block('[data-theme="dark"]')) };

// Résolution récursive de var(--x[, repli]) ; null si invalide
function resolve(value, toks, depth = 0) {
  if (depth > 20) return null;
  const m = value.match(/var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*(?:\([^()]*\)[^()]*)*))?\)/);
  if (!m) return value;
  const [whole, name, fallback] = m;
  let r = toks[name] !== undefined ? resolve(toks[name], toks, depth + 1) : (fallback !== undefined ? resolve(fallback.trim(), toks, depth + 1) : null);
  if (r === null) return null;
  return resolve(value.replace(whole, r), toks, depth + 1);
}

function lum(hex) {
  const h = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map(i => {
    const v = parseInt(h.slice(i, i + 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const ratio = (a, b) => { const la = lum(a), lb = lum(b); return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05); };

// Fichiers sources de l'application (hors tests)
function sourceFiles(dir) {
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (fs.statSync(p).isDirectory()) { if (f !== 'locales') out.push(...sourceFiles(p)); }
    else if (/\.(jsx?|css)$/.test(f) && !/\.test\./.test(f)) out.push(p);
  }
  return out;
}

describe('Variables CSS référencées par les composants', () => {
  test('toute var(--x) sans repli utilisée dans src/ est définie dans :root', () => {
    const missing = {};
    for (const file of sourceFiles(SRC)) {
      const text = fs.readFileSync(file, 'utf8');
      for (const m of text.matchAll(/var\(\s*(--[A-Za-z0-9-]+)\s*\)/g)) {
        if (ROOT[m[1]] === undefined) (missing[m[1]] = missing[m[1]] || []).push(path.relative(SRC, file));
      }
    }
    expect(missing).toEqual({});
  });

  test.each([
    ['--border-color', '--border'],
    ['--radius', '--radius-md'],
    ['--bg-hover', '--bg-surface-hover'],
    ['--danger', '--error'],
    ['--bg-danger', '--error-bg'],
    ['--primary', '--accent'],
    ['--accent-primary', '--accent'],
    ['--border-subtle', '--border'],
    ['--bg-input', '--bg-app'],
    ['--bg-primary', '--bg-surface'],
    ['--bg-secondary', '--bg-surface'],
  ])('alias %s = %s dans les deux thèmes', (alias, target) => {
    expect(ROOT[target]).toBeDefined();
    expect(resolve(`var(${alias})`, ROOT)).toBe(resolve(`var(${target})`, ROOT));
    expect(resolve(`var(${alias})`, DARK)).toBe(resolve(`var(${target})`, DARK));
  });
});

describe('A11Y-31 — focus clavier visible des boutons .btn', () => {
  const rule = block('.btn:focus-visible');

  test('contour réel (pas « outline: none » + anneau quasi invisible)', () => {
    expect(rule).not.toMatch(/outline\s*:\s*none/);
    expect(rule).toMatch(/outline\s*:\s*2px solid var\(--border-focus\)/);
    expect(rule).toMatch(/outline-offset\s*:\s*2px/);
  });

  test.each([['clair', ROOT], ['sombre', DARK]])('thème %s : contour ≥ 3:1 sur les surfaces', (_, toks) => {
    const color = resolve('var(--border-focus)', toks);
    for (const s of ['--bg-surface', '--bg-app', '--bg-surface-hover']) {
      expect(ratio(color, resolve(`var(${s})`, toks))).toBeGreaterThanOrEqual(3);
    }
  });
});

// ADMIN-18 : les boutons de fenêtre du panneau d'administration gardaient --text-secondary
// (#525252 / #d4d4d4) sur le bandeau en dégradé violet → cyan : 1,8 à 2,8:1 mesurés.
describe('ADMIN-18 — boutons de fenêtre lisibles sur le bandeau d\'administration', () => {
  const rgbaToHex = (v) => {
    const m = v.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
    return m ? '#' + m.slice(1, 4).map(n => Number(n).toString(16).padStart(2, '0')).join('') : v;
  };

  test('icônes blanches dans le bandeau, survol clair, survol rouge de « fermer » conservé', () => {
    const rule = block('.admin-header .window-controls button');
    expect(rule).toMatch(/color:\s*rgba\(255,\s*255,\s*255,\s*0\.95\)/);
    const hover = block('.admin-header .window-controls button:not(.btn-close):hover');
    expect(hover).toMatch(/background:\s*rgba\(255,\s*255,\s*255,\s*0\.18\)/);
    // Aucune règle du bandeau ne cible le bouton « fermer » (seulement :not(.btn-close)) :
    // son survol rouge reste celui de .window-controls .btn-close:hover
    expect(CSS).not.toMatch(/\.admin-header[^{]*[^(]\.btn-close[^{]*\{/);
    expect(block('.window-controls .btn-close:hover')).toMatch(/background:\s*#e81123/);
  });

  test.each([['clair', ROOT], ['sombre', DARK]])('thème %s : icône ≥ 3:1 sur les deux extrémités du dégradé', (_, toks) => {
    const icon = rgbaToHex(block('.admin-header .window-controls button').match(/color:\s*([^;]+);/)[1]);
    const header = block('.admin-header');
    const stops = header.match(/linear-gradient\(135deg,\s*(var\([^;]*?\)\)?),\s*(var\(--[\w-]+\))\)/);
    expect(stops).not.toBeNull();
    for (const stop of [stops[1], stops[2]]) {
      const bg = resolve(stop, toks);
      expect([stop, ratio(icon, bg) >= 3]).toEqual([stop, true]);
    }
    // Avant : --text-secondary sous 3:1 sur l'extrémité cyan
    expect(ratio(resolve('var(--text-secondary)', toks), resolve(stops[2], toks))).toBeLessThan(3);
  });
});

describe('A11Y-30 — vérification (déjà corrigé)', () => {
  test('--brand-violet-400 défini ; --accent-hover sombre résolu', () => {
    expect(ROOT['--brand-violet-400']).toBe('#a78bfa');
    expect(resolve('var(--accent-hover)', DARK)).toMatch(/^#[0-9a-f]{6}$/i);
  });
});
