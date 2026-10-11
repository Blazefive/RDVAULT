// ========================================
// TESTS : jetons de thème de AppStyles.css (thèmes clair et sombre)
// ========================================
// 1. Aucune variable CSS référencée sans valeur de repli ne doit être indéfinie : une seule
//    référence indéfinie invalide toute la déclaration (ex. --accent-hover → --brand-violet-400
//    manquant rendait le bouton primaire TRANSPARENT en thème sombre).
// 2. Contrastes WCAG AA du thème sombre (texte ≥ 4.5:1, composants d'interface ≥ 3:1).
// 3. Le thème clair du bouton primaire reste strictement inchangé.
// 4. Fond de sélection (--bg-selection) violet dans les deux thèmes, texte des lignes
//    sélectionnées ≥ 4.5:1 ; encadrés info / avertissement lisibles dans les deux thèmes.

const fs = require('fs');
const path = require('path');

const CSS = fs.readFileSync(path.join(__dirname, 'AppStyles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

// Contenu du bloc { … } qui suit exactement `selector {`
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

// Découpe `var( … )` en nom + repli (virgule de premier niveau)
function parseVar(inner) {
  let depth = 0;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (c === ',' && depth === 0) return { name: inner.slice(0, i).trim(), fallback: inner.slice(i + 1).trim() };
  }
  return { name: inner.trim(), fallback: null };
}
// Toutes les occurrences var(...) d'une chaîne : { start, end, inner }
function findVars(s) {
  const out = [];
  let i = s.indexOf('var(');
  while (i >= 0) {
    let depth = 0, j = i + 3;
    for (; j < s.length; j++) {
      if (s[j] === '(') depth++;
      else if (s[j] === ')' && --depth === 0) break;
    }
    out.push({ start: i, end: j + 1, inner: s.slice(i + 4, j) });
    i = s.indexOf('var(', j + 1);
  }
  return out;
}
// Résout récursivement les var() comme le navigateur ; null = valeur invalide au calcul
function resolve(value, toks, depth = 0) {
  if (depth > 20) return null;
  const vars = findVars(value);
  if (!vars.length) return value;
  let out = '', last = 0;
  for (const v of vars) {
    const { name, fallback } = parseVar(v.inner);
    let r = null;
    if (toks[name] !== undefined) r = resolve(toks[name], toks, depth + 1);
    else if (fallback !== null) r = resolve(fallback, toks, depth + 1);
    if (r === null) return null;
    out += value.slice(last, v.start) + r;
    last = v.end;
  }
  return out + value.slice(last);
}

function lum(hex) {
  const h = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map(i => {
    const v = parseInt(h.slice(i, i + 2), 16) / 255;
    return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a, b) {
  const la = lum(a), lb = lum(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}
// rgba(r, g, b, a) composé sur un fond opaque → #rrggbb
function over(rgba, bgHex) {
  const m = rgba.match(/rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)/);
  const a = Number(m[4]);
  const bg = [0, 2, 4].map(i => parseInt(bgHex.replace('#', '').slice(i, i + 2), 16));
  return '#' + [1, 2, 3].map((k, i) => Math.round(Number(m[k]) * a + bg[i] * (1 - a)).toString(16).padStart(2, '0')).join('');
}
const hexes = (s) => s.match(/#[0-9a-fA-F]{6}\b/g) || [];
const dark = (name) => resolve(`var(${name})`, DARK);

describe('AppStyles.css — variables CSS', () => {
  test('toute variable référencée sans repli est définie dans :root', () => {
    const undefinedRefs = new Set();
    for (const v of findVars(CSS)) {
      const { name, fallback } = parseVar(v.inner);
      if (fallback === null && ROOT[name] === undefined) undefinedRefs.add(name);
    }
    expect([...undefinedRefs]).toEqual([]);
  });

  test('les jetons du thème sombre se résolvent tous en une valeur valide', () => {
    const invalid = Object.keys(tokens(block('[data-theme="dark"]'))).filter(n => dark(n) === null);
    expect(invalid).toEqual([]);
  });
});

describe('AppStyles.css — bouton primaire', () => {
  const background = (block('.btn-primary').match(/background\s*:\s*([^;]+);/) || [])[1];

  test('thème sombre : dégradé violet valide, texte blanc ≥ 4.5:1 et bouton / carte ≥ 3:1', () => {
    const resolved = resolve(background, DARK);
    expect(resolved).not.toBeNull(); // avant correctif : var(--brand-violet-400) indéfini → transparent
    const stops = hexes(resolved);
    expect(stops.length).toBeGreaterThanOrEqual(2);
    const surface = dark('--bg-surface');
    for (const c of stops) {
      expect(ratio('#ffffff', c)).toBeGreaterThanOrEqual(4.5);
      expect(ratio(c, surface)).toBeGreaterThanOrEqual(3);
    }
  });

  test('thème clair : rendu strictement inchangé (violet-600 → violet-700)', () => {
    expect(resolve(background, ROOT).replace(/\s+/g, ' ')).toBe('linear-gradient(135deg, #7c3aed, #6d28d9)');
  });

  test('thème sombre : le fond de remplissage `var(--accent-fill, var(--accent))` sous texte blanc ≥ 4.5:1', () => {
    expect(ratio('#ffffff', resolve('var(--accent-fill, var(--accent))', DARK))).toBeGreaterThanOrEqual(4.5);
    // Thème clair : --accent-fill n'existe pas, le repli --accent rend le même violet qu'avant
    expect(resolve('var(--accent-fill, var(--accent))', ROOT)).toBe(resolve('var(--accent)', ROOT));
  });
});

// Les styles inline (JS/JSX) qui posent un fond accent sous un texte blanc doivent utiliser
// `var(--accent-fill, var(--accent…))` : la règle passerelle `[style*="background: var(--accent);"]`
// de AppStyles.css a été retirée (elle ne couvrait d'ailleurs pas `var(--accent, #…)`).
describe('Styles inline — fond accent en thème sombre', () => {
  function sources(dir) {
    const out = [];
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'testUtils') out.push(...sources(p)); }
      else if (/\.(js|jsx)$/.test(e.name) && !/\.test\.(js|jsx)$/.test(e.name)) out.push(p);
    }
    return out;
  }

  test('aucun fond `var(--accent)` brut (sans --accent-fill) dans les sources', () => {
    const offenders = [];
    for (const file of sources(__dirname)) {
      fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
        if (!/background/i.test(line)) return;
        for (const m of line.matchAll(/var\(--accent(?=[,)])/g)) {
          if (!/var\(--accent-fill,\s*$/.test(line.slice(0, m.index))) {
            offenders.push(`${path.relative(__dirname, file)}:${i + 1}`);
          }
        }
      });
    }
    expect(offenders).toEqual([]);
  });

  test('la règle passerelle `[style*="background: var(--accent);"]` a été retirée', () => {
    expect(CSS.includes('[style*="background: var(--accent);"]')).toBe(false);
  });
});

// Toutes les règles dont la liste de sélecteurs contient exactement `selector` (corps fusionnés)
function rulesFor(selector) {
  let out = '';
  for (const m of CSS.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (m[1].split(',').map(s => s.trim()).includes(selector)) out += m[2];
  }
  return out;
}

describe('AppStyles.css — fond de sélection (--bg-selection)', () => {
  // Avant : --bg-selection jamais défini → repli bleu rgba(59, 130, 246, …) (lignes sélectionnées
  // et cibles de dépôt bleues dans un thème violet).
  test('défini dans les deux thèmes, teinte violette de l\'accent', () => {
    expect(ROOT['--bg-selection']).toBeDefined();
    expect(resolve('var(--bg-selection)', ROOT)).toBe(resolve('var(--brand-violet-100)', ROOT));
    expect(dark('--bg-selection')).toMatch(/^rgba\(139, 92, 246, 0\.\d+\)$/);
  });

  test('.row-selected et .drop-target : fond du thème, plus aucun repli bleu', () => {
    for (const sel of ['.row-selected', '.drop-target']) {
      const body = rulesFor(sel);
      expect(body).toMatch(/background\s*:\s*var\(--bg-selection\)/);
      expect(body).not.toMatch(/59,\s*130,\s*246|#3b82f6/i);
    }
  });

  // Jetons de texte utilisés dans une ligne du tableau (nom, cellules, aides en italique, lien URL)
  const ROW_TEXT = ['--text-primary', '--text-secondary', '--text-tertiary', '--accent'];

  test('thème clair : texte des lignes sélectionnées ≥ 4.5:1 sur le fond de sélection', () => {
    const row = { ...ROOT, ...tokens(rulesFor('.row-selected')) };
    const bg = resolve('var(--bg-selection)', row);
    for (const tok of ROW_TEXT) {
      expect([tok, ratio(resolve(`var(${tok})`, row), bg) >= 4.5]).toEqual([tok, true]);
    }
  });

  test('thème sombre : texte des lignes sélectionnées ≥ 4.5:1 (fond translucide sur les surfaces)', () => {
    const row = { ...DARK, ...tokens(rulesFor('.row-selected')) };
    for (const surface of ['--bg-surface', '--bg-app']) {
      const bg = over(resolve('var(--bg-selection)', row), dark(surface));
      for (const tok of ROW_TEXT) {
        expect([tok, surface, ratio(resolve(`var(${tok})`, row), bg) >= 4.5]).toEqual([tok, surface, true]);
      }
    }
  });

  test('cibles de dépôt : même renfort du texte atténué que les lignes sélectionnées', () => {
    expect(tokens(rulesFor('.drop-target'))['--text-tertiary']).toBe('var(--text-secondary)');
  });
});

describe('AppStyles.css — encadrés info / avertissement (styles inline du panneau admin)', () => {
  test('thème clair : texte d\'encadré ≥ 4.5:1 sur son fond', () => {
    expect(ratio(resolve('var(--info-text)', ROOT), resolve('var(--info-bg)', ROOT))).toBeGreaterThanOrEqual(4.5);
    expect(ratio(resolve('var(--warning-text)', ROOT), resolve('var(--warning-bg)', ROOT))).toBeGreaterThanOrEqual(4.5);
  });

  test('thème sombre : fonds translucides, texte d\'encadré et texte principal ≥ 4.5:1', () => {
    for (const [bgTok, textTok] of [['--info-bg', '--info-text'], ['--warning-bg', '--warning-text']]) {
      for (const surface of ['--bg-surface', '--bg-app']) {
        const bg = over(dark(bgTok), dark(surface));
        expect(ratio(dark(textTok), bg)).toBeGreaterThanOrEqual(4.5);
        expect(ratio(dark('--text-primary'), bg)).toBeGreaterThanOrEqual(4.5);
      }
    }
  });
});

describe('AppStyles.css — contrastes WCAG AA du thème sombre', () => {
  const surfaces = ['--bg-surface', '--bg-app', '--bg-surface-hover'];

  test.each(['--text-primary', '--text-secondary', '--text-tertiary', '--text-disabled', '--accent'])(
    'texte %s ≥ 4.5:1 sur toutes les surfaces', (tok) => {
      for (const s of surfaces) expect(ratio(dark(tok), dark(s))).toBeGreaterThanOrEqual(4.5);
    });

  test('accent (texte) ≥ 4.5:1 sur la carte de coffre active (fond accent-subtle)', () => {
    const activeCard = over(dark('--accent-subtle'), dark('--bg-surface'));
    expect(ratio(dark('--accent'), activeCard)).toBeGreaterThanOrEqual(4.5);
  });

  test('contour des champs de saisie ≥ 3:1 sur les surfaces', () => {
    const control = resolve('var(--border-control, var(--border))', DARK);
    for (const s of surfaces) expect(ratio(control, dark(s))).toBeGreaterThanOrEqual(3);
  });

  test('séparateur barre latérale / zone principale nettement visible (≥ 1.5:1 des deux côtés)', () => {
    expect(ratio(dark('--border'), dark('--bg-surface'))).toBeGreaterThanOrEqual(1.5);
    expect(ratio(dark('--border'), dark('--bg-app'))).toBeGreaterThanOrEqual(1.5);
  });
});
