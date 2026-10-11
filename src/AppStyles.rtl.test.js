// ========================================
// TESTS : AppStyles.css — mise en page miroir en arabe (I18N-31)
// ========================================
// Avec <html dir="rtl"> (arabe), les marges, retraits, bordures, alignements et positions
// doivent suivre le sens d'écriture. Les règles utilisent donc les propriétés logiques
// (margin-inline-*, padding-inline-*, border-inline-*, inset-inline-*, text-align: start),
// strictement équivalentes aux propriétés physiques en LTR : rendu inchangé dans les 11 autres
// langues. Les rares propriétés physiques restantes sont listées et justifiées ci-dessous.

const fs = require('fs');
const path = require('path');

const CSS = fs.readFileSync(path.join(__dirname, 'AppStyles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

// Découpe la feuille en règles { selector, body } (les @media sont aplatis)
function rules(css) {
  const out = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(css))) out.push({ selector: m[1].replace(/@media[^{]*\{/, '').trim(), body: m[2] });
  return out;
}

// Propriétés physiques tolérées : décor symétrique ou sans effet de sens
const ALLOWED = [
  // Halo décoratif (dégradé radial 200 % × 200 %) : symétrique, aucune incidence en RTL
  { selector: '.login-header::before', prop: 'right' },
  { selector: '.admin-header::before', prop: 'right' },
  // Soulignement d'onglet : left: 0 + right: 0 (pleine largeur, symétrique)
  { selector: '.admin-tab::after', prop: 'left' },
  { selector: '.admin-tab::after', prop: 'right' },
  // Indicateur de défilement : retraits gauche/droite identiques
  { selector: '.tag-menu-scroll-indicator', prop: 'padding-left' },
  { selector: '.tag-menu-scroll-indicator', prop: 'padding-right' },
  // Poignée de redimensionnement des colonnes : bord droit en LTR, ramenée au bord gauche (fin de
  // ligne) en RTL par la règle propre :root[dir="rtl"]. useColumns.resizeDirection lit le côté où la
  // poignée est affichée : le geste reste juste dans les deux cas.
  { selector: '.column-resizer', prop: 'right' },
  { selector: ':root[dir="rtl"] .column-resizer', prop: 'right' },
  { selector: ':root[dir="rtl"] .column-resizer', prop: 'left' },
  // Centrage horizontal (left: 50 % + translateX(-50 %)) : symétrique
  { selector: '.tab-button::before', prop: 'left' },
];
const PHYSICAL = /(?:^|;|\s)((?:margin|padding|border)-(?:left|right)(?:-[a-z]+)?|left|right)\s*:/g;

test('aucune propriété physique gauche/droite hors liste justifiée', () => {
  const offenders = [];
  for (const { selector, body } of rules(CSS)) {
    for (const m of body.matchAll(PHYSICAL)) {
      const prop = m[1];
      if (!ALLOWED.some(a => a.prop === prop && selector.split(',').map(s => s.trim()).includes(a.selector))) {
        offenders.push(`${selector} { ${prop} }`);
      }
    }
  }
  expect(offenders).toEqual([]);
});

test('aucun text-align: left / right hors règles propres au RTL (start / end suivent le sens d\'écriture)', () => {
  const offenders = rules(CSS)
    .filter(r => /text-align:\s*(left|right)\b/.test(r.body) && !/^:root\[dir="rtl"\]/.test(r.selector))
    .map(r => r.selector);
  expect(offenders).toEqual([]);
});

// ADMIN-11 / SETTINGS : identifiants techniques (chemins, noms de policies, DN LDAP, commandes)
// marqués <bdi dir="ltr" class="bidi-ltr"> : sens de gauche à droite ET isolation explicites,
// quel que soit le sens de la page (sans effet visible en LTR)
test('classe .bidi-ltr : direction ltr et isolation bidi, dans toutes les langues', () => {
  const rule = rules(CSS).find(r => r.selector === '.bidi-ltr');
  expect(rule).toBeDefined();
  expect(rule.body).toMatch(/direction:\s*ltr/);
  expect(rule.body).toMatch(/unicode-bidi:\s*isolate/);
});

test('en RTL, cellules du tableau : sens selon le contenu (plaintext), alignées à droite', () => {
  const cell = rules(CSS).find(r => r.selector === ':root[dir="rtl"] .secrets-table td');
  expect(cell).toBeDefined();
  expect(cell.body).toMatch(/unicode-bidi:\s*plaintext/);
  expect(cell.body).toMatch(/text-align:\s*right/);
});

test('en RTL, URL et code restent de gauche à droite (isolés du texte arabe)', () => {
  const rtl = rules(CSS).filter(r => /\[dir="rtl"\]/.test(r.selector));
  const isolated = rtl.filter(r => /direction:\s*ltr/.test(r.body) && /unicode-bidi:\s*isolate/.test(r.body));
  const selectors = isolated.map(r => r.selector).join(' ');
  for (const sel of ['.url-link', 'code', 'pre', 'kbd']) expect(selectors).toContain(sel);
});

test('effet de survol des cartes de coffre inversé en RTL (décalage vers l\'intérieur)', () => {
  const hover = rules(CSS).find(r => r.selector.includes('[dir="rtl"] .engine-card:hover'));
  expect(hover).toBeDefined();
  expect(hover.body).toMatch(/translateX\(-4px\)/);
});

test('en RTL, poignée de redimensionnement des colonnes au bord de fin de l\'en-tête (gauche)', () => {
  const rule = rules(CSS).find(r => r.selector === ':root[dir="rtl"] .column-resizer');
  expect(rule).toBeDefined();
  expect(rule.body).toMatch(/right:\s*auto/);
  expect(rule.body).toMatch(/(^|[;\s])left:\s*0/);
  // En LTR, la poignée reste au bord droit
  const base = rules(CSS).find(r => r.selector === '.column-resizer');
  expect(base.body).toMatch(/right:\s*0/);
});

test('content-visibility sur les lignes : plus de promesse de « gain majeur » (mesuré sans effet)', () => {
  const raw = fs.readFileSync(path.join(__dirname, 'AppStyles.css'), 'utf8');
  expect(raw).not.toMatch(/Gain majeur/i);
  expect(raw).toMatch(/content-visibility sur <tr> : MESURÉ SANS EFFET/);
});
