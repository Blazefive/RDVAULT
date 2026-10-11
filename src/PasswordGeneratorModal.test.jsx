// ========================================
// TESTS : générateur de mot de passe (src/PasswordGeneratorModal.jsx)
// ========================================
// GENERATOR-24 : jeu de caractères unique, dédoublonné par points de code (caractères
//   personnalisés dupliqués ou déjà présents dans une classe cochée, emoji hors BMP) ;
//   distribution uniforme vérifiée par un test du chi² sur 100 000 tirages ; entropie affichée
//   calculée à partir de ce même jeu.
// GENERATOR-25 : minimums bornés par la longueur, génération en O(n) (plus de gel du renderer),
//   contraintes impossibles signalées (message traduit) au lieu d'être violées en silence.
// Rendu réel react-dom dans jsdom (pas de @testing-library).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'crypto';
import PasswordGeneratorModal, {
  buildGeneratorPlan, generatePasswordFromPlan, secureRandomInt, DEFAULT_GENERATOR_OPTIONS,
} from './PasswordGeneratorModal';
import { I18nProvider } from './i18n';
import { getPasswordStrength } from './utils/passwordStrength';
import en from './locales/en.json';
import fr from './locales/fr.json';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Le générateur utilise crypto.getRandomValues (absent de jsdom)
if (!global.crypto || !global.crypto.getRandomValues) {
  Object.defineProperty(global, 'crypto', { value: webcrypto, configurable: true });
}

// ---------- Outils statistiques ----------

// Valeur critique du chi² (approximation de Wilson–Hilferty), z = 4,753 ↔ risque 1e-6 :
// un générateur uniforme ne fait échouer le test qu'une fois sur un million.
function chi2Critical(df, z = 4.753) {
  const h = 2 / (9 * df);
  return df * (1 - h + z * Math.sqrt(h)) ** 3;
}
function chi2Uniform(counts, categories) {
  const total = categories.reduce((s, c) => s + (counts.get(c) || 0), 0);
  const expected = total / categories.length;
  return categories.reduce((s, c) => s + ((counts.get(c) || 0) - expected) ** 2 / expected, 0);
}
function countCodePoints(strings) {
  const counts = new Map();
  for (const s of strings) for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  return counts;
}
const LONE_SURROGATE = /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF]))|(?:(?<![\uD800-\uDBFF])[\uDC00-\uDFFF])/;
const opts = (over) => ({ ...DEFAULT_GENERATOR_OPTIONS, ...over });
const ONLY = { includeUpperCase: false, includeLowerCase: false, includeDigits: false, includeSpecial: false,
  includeBrackets: false, includeMinus: false, includeUnderline: false, includeLatin1: false };

// ---------- Logique pure ----------

describe('buildGeneratorPlan — jeu de caractères unique (GENERATOR-24)', () => {
  test('caractères personnalisés dupliqués : chaque caractère une seule fois dans le jeu', () => {
    const plan = buildGeneratorPlan(opts({ ...ONLY, includeLowerCase: true, customChars: 'a'.repeat(50) }));
    expect(plan.pool).toHaveLength(26);
    expect(new Set(plan.pool).size).toBe(26);
    // « a » appartient déjà aux minuscules : aucune catégorie personnalisée à forcer
    expect(plan.categories.map(c => c.id)).toEqual(['lower']);
    // Entropie = 20 × log2(26), et non 20 × log2(27)
    expect(plan.entropy).toBe(Math.floor(20 * Math.log2(26)));
  });

  test('chevauchement avec les classes cochées : « - », « _ », « ! » ne pèsent pas double', () => {
    const plan = buildGeneratorPlan(opts({ customChars: '-_!.' }));
    expect(plan.pool).toHaveLength(78); // 26 + 26 + 10 + 13 + 1 + 1 + « . »
    expect(new Set(plan.pool).size).toBe(plan.pool.length);
    expect(plan.categories.find(c => c.id === 'custom').chars).toEqual(['.']);
  });

  test('emoji hors BMP : un élément du jeu = un point de code complet', () => {
    const plan = buildGeneratorPlan(opts({ ...ONLY, customChars: '😀🔐😀' }));
    expect(plan.pool).toEqual(['😀', '🔐']);
    for (let i = 0; i < 50; i++) {
      const pwd = generatePasswordFromPlan(plan);
      expect(LONE_SURROGATE.test(pwd)).toBe(false);
      expect(Array.from(pwd)).toHaveLength(20);
      // Aller-retour UTF-8 sans perte (plus de U+FFFD)
      expect(Buffer.from(pwd, 'utf8').toString('utf8')).toBe(pwd);
    }
    expect(plan.entropy).toBe(20);
  });

  test('surrogates isolés et caractères de contrôle ignorés dans les caractères personnalisés', () => {
    const plan = buildGeneratorPlan(opts({ ...ONLY, customChars: 'x\uD83D\u0000\ty' }));
    expect(plan.pool).toEqual(['x', 'y']);
  });

  test('aucun caractère sélectionné : mot de passe vide, entropie nulle', () => {
    const plan = buildGeneratorPlan(opts({ ...ONLY }));
    expect(plan.pool).toEqual([]);
    expect(plan.empty).toBe(true);
    expect(plan.impossible).toBe(false);
    expect(generatePasswordFromPlan(plan)).toBe('');
    expect(plan.entropy).toBe(0);
    expect(buildGeneratorPlan(opts()).empty).toBe(false);
  });

  test('caractères personnalisés décomposés (NFD) et marques combinantes isolées', () => {
    // « e » + accent combinant → « é » (un seul caractère, pas un accent tiré seul)
    expect(buildGeneratorPlan(opts({ ...ONLY, customChars: 'éà' })).pool).toEqual(['é', 'à']);
    // Cœur + sélecteur de variante U+FE0F : le sélecteur invisible n'entre pas dans le jeu
    expect(buildGeneratorPlan(opts({ ...ONLY, customChars: '❤️' })).pool).toEqual(['❤']);
    // Accent combinant isolé, saisi seul
    expect(buildGeneratorPlan(opts({ ...ONLY, customChars: '́x' })).pool).toEqual(['x']);
  });

  test('Latin-1 : uniquement des caractères stables en NFC et NFKC, sans doublon', () => {
    const plan = buildGeneratorPlan(opts({ ...ONLY, includeLatin1: true, ensureOneFromEach: false }));
    expect(plan.pool.length).toBeGreaterThan(150);
    expect(new Set(plan.pool).size).toBe(plan.pool.length);
    const unstable = plan.pool.filter(c => c.normalize('NFKC') !== c || c.normalize('NFC') !== c);
    expect(unstable).toEqual([]); // avant : ŉ, Ĳ, ĳ, Ŀ, ŀ
  });

  test('minimum d\'une classe non cochée ignoré (pas de contrainte fantôme)', () => {
    const plan = buildGeneratorPlan(opts({ includeUpperCase: false, minUpperCase: 15 }));
    expect(plan.impossible).toBe(false);
    expect(plan.categories.map(c => c.id)).not.toContain('upper');
    expect(generatePasswordFromPlan(plan)).not.toMatch(/[A-Z]/);
  });
});

describe('secureRandomInt — bornes', () => {
  test('borne > 2^32 ou non entière : RangeError au lieu d\'une boucle infinie', () => {
    expect(() => secureRandomInt(2 ** 32 + 1)).toThrow(RangeError);
    expect(() => secureRandomInt(2.5)).toThrow(RangeError);
    expect(() => secureRandomInt(Infinity)).toThrow(RangeError);
  });
  test('bornes limites valides', () => {
    expect(secureRandomInt(0)).toBe(0);
    expect(secureRandomInt(1)).toBe(0);
    for (let i = 0; i < 100; i++) {
      const v = secureRandomInt(2 ** 32);
      expect(Number.isInteger(v) && v >= 0 && v < 2 ** 32).toBe(true);
    }
  });
});

describe('distribution uniforme — chi² sur 100 000 tirages (GENERATOR-24)', () => {
  function drawChars(plan, total) {
    const out = [];
    let n = 0;
    while (n < total) {
      const pwd = generatePasswordFromPlan(plan);
      out.push(pwd);
      n += Array.from(pwd).length;
    }
    return out;
  }

  // Configurations sans caractère forcé hors du jeu complet : chaque position doit être un
  // tirage uniforme parmi les caractères distincts du jeu (les catégories forcées, elles,
  // surreprésentent volontairement leurs caractères).
  test.each([
    ['options par défaut (sans caractère forcé)', { ensureOneFromEach: false }],
    ['minuscules + 50 « a » personnalisés', { ...ONLY, includeLowerCase: true, customChars: 'a'.repeat(50) }],
    ['défauts + « -_!-_! » personnalisés (déjà cochés)', { customChars: '-_!-_!', ensureOneFromEach: false }],
    ['emoji seuls (hors BMP)', { ...ONLY, customChars: '😀🔐🎉😀' }],
    ['Latin-1 étendu + ambigus exclus', { includeLatin1: true, excludeAmbiguous: true, ensureOneFromEach: false, length: 64 }],
  ])('%s', (_name, over) => {
    const plan = buildGeneratorPlan(opts(over));
    for (const cat of plan.categories) expect(cat.chars).toEqual(plan.pool);
    const counts = countCodePoints(drawChars(plan, 100000));
    // Aucun caractère hors du jeu, chaque caractère du jeu tiré
    expect([...counts.keys()].every(ch => plan.pool.includes(ch))).toBe(true);
    expect(counts.size).toBe(plan.pool.length);
    const chi2 = chi2Uniform(counts, plan.pool);
    expect(chi2).toBeLessThan(chi2Critical(plan.pool.length - 1));
  });

  test('secureRandomInt : rejet du biais modulo (borne défavorable 2^31 + 1)', () => {
    const max = 2 ** 31 + 1;
    let low = 0;
    const N = 100000;
    for (let i = 0; i < N; i++) if (secureRandomInt(max) < max / 2) low++;
    // Sans rejet : P(moitié basse) ≈ 2/3. Avec rejet : 1/2 (écart-type 0,0016)
    expect(Math.abs(low / N - 0.5)).toBeLessThan(0.01);
  });
});

describe('minimums et contraintes (GENERATOR-25)', () => {
  test('minimums bornés par la longueur : 1 000 000 majuscules demandées → 20, génération instantanée', () => {
    const t0 = Date.now();
    const plan = buildGeneratorPlan(opts({ minUpperCase: 1000000, ensureOneFromEach: false }));
    const pwd = generatePasswordFromPlan(plan);
    expect(Date.now() - t0).toBeLessThan(200);
    expect(plan.impossible).toBe(false);
    expect(pwd).toMatch(/^[A-Z]{20}$/);
  });

  test('génération linéaire : longueur 256 avec minimums élevés', () => {
    const t0 = Date.now();
    for (let i = 0; i < 200; i++) {
      const plan = buildGeneratorPlan(opts({ length: 256, minUpperCase: 100, minLowerCase: 100, minDigits: 50 }));
      expect(Array.from(generatePasswordFromPlan(plan))).toHaveLength(256);
    }
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  test('minimums respectés à chaque tirage', () => {
    const plan = buildGeneratorPlan(opts({ length: 12, minUpperCase: 3, minDigits: 3, minSpecial: 2 }));
    for (let i = 0; i < 300; i++) {
      const pwd = generatePasswordFromPlan(plan);
      expect(pwd).toHaveLength(12);
      expect((pwd.match(/[A-Z]/g) || []).length).toBeGreaterThanOrEqual(3);
      expect((pwd.match(/[0-9]/g) || []).length).toBeGreaterThanOrEqual(3);
      expect((pwd.match(/[!@#$%&*+=?^~,]/g) || []).length).toBeGreaterThanOrEqual(2);
      expect(pwd).toMatch(/[a-z]/); // « au moins un de chaque » (par défaut)
    }
  });

  test('contraintes impossibles : signalées, aucun mot de passe tronqué en silence', () => {
    // Longueur 3, « au moins un de chaque » avec 4 classes cochées
    const plan = buildGeneratorPlan(opts({ length: 3 }));
    expect(plan.impossible).toBe(true);
    expect(plan.required).toBe(4);
    expect(generatePasswordFromPlan(plan)).toBe('');
    expect(plan.entropy).toBe(0);
    // Somme des minimums > longueur
    const plan2 = buildGeneratorPlan(opts({ length: 20, minUpperCase: 15, minDigits: 10 }));
    expect(plan2.impossible).toBe(true);
    expect(plan2.required).toBe(27); // 15 + 10 + 1 minuscule + 1 symbole
  });

  test('entropie affichée cohérente avec les caractères forcés', () => {
    // 18 majuscules forcées sur 20 : bien moins que 20 × log2(77)
    const plan = buildGeneratorPlan(opts({ minUpperCase: 18, ensureOneFromEach: false }));
    expect(plan.entropy).toBeLessThan(Math.floor(20 * Math.log2(77)) - 15);
    expect(plan.entropy).toBeGreaterThan(Math.floor(18 * Math.log2(26) + 2 * Math.log2(77)) - 1);
    // Sans caractère forcé : exactement longueur × log2(taille du jeu)
    expect(buildGeneratorPlan(opts({ ensureOneFromEach: false })).entropy).toBe(Math.floor(20 * Math.log2(77)));
  });
});

// ---------- Rendu réel ----------

// Rendu d'un root React 18 (hors Testing Library) : même convention que les autres tests du
// projet, la règle testing-library/no-unnecessary-act prenant root.render pour un utilitaire RTL
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root = null;
function mount({ lang = 'en', onAccept = () => {}, onClose = () => {} } = {}) {
  localStorage.setItem('rdvault-lang', lang);
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><PasswordGeneratorModal onClose={onClose} onAccept={onAccept} /></I18nProvider>); });
  return host;
}
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const btn = (txt) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
const pwd = () => document.querySelector('[style*="user-select: all"]').textContent;
const entropyBits = () => {
  const span = Array.from(document.querySelectorAll('span')).find(s => s.textContent.startsWith(en.passwordGenerator.entropy));
  return parseInt(span.querySelector('strong').textContent, 10);
};
const checkbox = (labelTxt) => Array.from(document.querySelectorAll('label.checkbox-label'))
  .find(l => l.textContent.trim() === labelTxt).querySelector('input');
const uncheck = (labelTxt) => { const c = checkbox(labelTxt); if (c.checked) act(() => { c.click(); }); };
function setInput(input, value) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  act(() => { setter.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); });
}
const lengthInput = () => document.querySelector('input[type="number"][max="256"]');
const customInput = () => document.querySelector(`input[placeholder="${en.passwordGenerator.customCharsPlaceholder}"]`);
const minInputs = () => Array.from(document.querySelectorAll('input[type="number"]')); // onglet Avancé
const expectedWarning = (dict, required, length) => dict.passwordGenerator.constraintsImpossible
  .replace('{{required}}', String(required)).replace('{{length}}', String(length));

describe('PasswordGeneratorModal — rendu', () => {
  test('caractères personnalisés dupliqués : entropie affichée = jeu réel, tirages uniformes', () => {
    mount();
    const g = en.passwordGenerator;
    for (const l of [g.uppercase, g.numbers, g.symbols, g.minus, g.underline]) uncheck(l);
    setInput(customInput(), 'a'.repeat(50));
    expect(entropyBits()).toBe(Math.floor(20 * Math.log2(26))); // 94 (95 avant : 27 « caractères »)
    setInput(lengthInput(), '256');
    const samples = [];
    for (let i = 0; i < 40; i++) {
      act(() => { btn(g.regenerate).click(); });
      samples.push(pwd());
    }
    const letters = Array.from('abcdefghijklmnopqrstuvwxyz');
    const counts = countCodePoints(samples);
    expect(counts.size).toBe(26);
    // Avant : P(a) ≈ 0,67 au lieu de 1/26 (chi² ≈ 600 000)
    expect(chi2Uniform(counts, letters)).toBeLessThan(chi2Critical(25));
  });

  test('emoji personnalisés : aucun surrogate isolé, longueur en caractères', () => {
    mount();
    const g = en.passwordGenerator;
    for (const l of [g.uppercase, g.lowercase, g.numbers, g.symbols, g.minus, g.underline]) uncheck(l);
    setInput(customInput(), '😀🔐');
    for (let i = 0; i < 30; i++) {
      act(() => { btn(g.regenerate).click(); });
      expect(LONE_SURROGATE.test(pwd())).toBe(false);
      expect(Array.from(pwd())).toHaveLength(20);
    }
    expect(entropyBits()).toBe(20);
  });

  test('minimum démesuré : borné à la longueur, sans gel de l\'interface', () => {
    mount();
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    const minUpper = minInputs()[0];
    const t0 = Date.now();
    setInput(minUpper, '20000');
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(minUpper.value).toBe('20');
    expect(minUpper.getAttribute('max')).toBe('20');
    // 20 majuscules exigées + 1 minuscule, 1 chiffre, 1 symbole forcés : impossible en 20 caractères
    expect(document.querySelector('[role="alert"]').textContent).toBe(expectedWarning(en, 23, 20));
  });

  test('contraintes impossibles : message traduit, aucun mot de passe, « Accepter » désactivé', () => {
    const onAccept = jest.fn();
    mount({ onAccept });
    setInput(lengthInput(), '3');
    const alert = document.querySelector('[role="alert"]');
    expect(alert).not.toBeNull();
    expect(alert.textContent).toBe(expectedWarning(en, 4, 3));
    expect(pwd()).toBe(en.passwordGenerator.none);
    const accept = btn(en.passwordGenerator.accept);
    expect(accept.disabled).toBe(true);
    act(() => { accept.click(); });
    expect(onAccept).not.toHaveBeenCalled();
    // Longueur suffisante : le message disparaît, le mot de passe revient
    setInput(lengthInput(), '4');
    expect(document.querySelector('[role="alert"]')).toBeNull();
    expect(pwd()).toHaveLength(4);
    expect(btn(en.passwordGenerator.accept).disabled).toBe(false);
  });

  test('message de contraintes impossibles traduit (français)', () => {
    mount({ lang: 'fr' });
    setInput(lengthInput(), '2');
    expect(document.querySelector('[role="alert"]').textContent).toBe(expectedWarning(fr, 4, 2));
  });

  test('réduire la longueur borne les minimums déjà saisis', () => {
    mount();
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    setInput(minInputs()[0], '15');
    expect(minInputs()[0].value).toBe('15');
    act(() => { btn(en.passwordGenerator.tabSettings).click(); });
    setInput(lengthInput(), '10');
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    expect(minInputs()[0].value).toBe('10');
  });

  test('frappe intermédiaire dans la longueur : le minimum saisi n\'est pas perdu', () => {
    mount();
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    setInput(minInputs()[0], '15');
    act(() => { btn(en.passwordGenerator.tabSettings).click(); });
    // L'utilisateur tape « 30 » : la longueur passe par « 3 » avant « 30 »
    setInput(lengthInput(), '3');
    setInput(lengthInput(), '30');
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    expect(minInputs()[0].value).toBe('15'); // avant : 3
    expect((pwd().match(/[A-Z]/g) || []).length).toBeGreaterThanOrEqual(15);
  });

  test('classe non cochée : son minimum est désactivé et vaut 0', () => {
    mount();
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    setInput(minInputs()[0], '12');
    act(() => { btn(en.passwordGenerator.tabSettings).click(); });
    uncheck(en.passwordGenerator.uppercase);
    act(() => { btn(en.passwordGenerator.tabAdvanced).click(); });
    expect(minInputs()[0].disabled).toBe(true);
    expect(minInputs()[0].value).toBe('0');
    expect(minInputs()[1].disabled).toBe(false);
    expect(pwd()).not.toMatch(/[A-Z]/);
    expect(document.querySelector('[role="alert"]')).toBeNull();
  });

  test('jeu de caractères vide : message traduit au lieu de « (none) » seul', () => {
    mount({ lang: 'fr' });
    const g = fr.passwordGenerator;
    for (const l of [g.uppercase, g.lowercase, g.numbers, g.symbols, g.minus, g.underline]) uncheck(l);
    expect(document.querySelector('[role="alert"]').textContent).toBe(g.noCharacterSet);
    expect(pwd()).toBe(g.none);
    expect(btn(g.accept).disabled).toBe(true);
  });

  test('force affichée : paliers et libellés communs (getPasswordStrength)', () => {
    mount();
    const plan = buildGeneratorPlan(DEFAULT_GENERATOR_OPTIONS);
    const s = getPasswordStrength(plan.entropy);
    expect(entropyBits()).toBe(plan.entropy);
    const label = Array.from(document.querySelectorAll('span')).find(x => x.textContent.startsWith(en.passwordGenerator.strength));
    expect(label.querySelector('strong').textContent).toBe(en.passwordGenerator.strengthVeryStrong);
    expect(document.querySelector('.clipboard-progress-bar').style.width).toBe(`${s.percentage}%`);
    // Longueur 8 : palier moyen ou faible, même libellé que la fiche
    setInput(lengthInput(), '8');
    const s8 = getPasswordStrength(entropyBits());
    expect(label.querySelector('strong').textContent).toBe(en.passwordGenerator[
      { weak: 'strengthWeak', medium: 'strengthMedium', strong: 'strengthStrong', veryStrong: 'strengthVeryStrong' }[s8.level]]);
  });

  test('« Accepter » transmet le mot de passe affiché', () => {
    const onAccept = jest.fn();
    mount({ onAccept });
    const shown = pwd();
    expect(shown).toHaveLength(20);
    act(() => { btn(en.passwordGenerator.accept).click(); });
    expect(onAccept).toHaveBeenCalledWith(shown);
  });
});
