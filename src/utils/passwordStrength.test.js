// ========================================
// TESTS : force des mots de passe (src/utils/passwordStrength.js)
// ========================================
// Entropie, paliers de force (niveau neutre, jamais un libellé traduit) et
// correspondance niveau → clé i18n présente dans les locales fr/en.
// GENERATOR-18 : l'estimation reconnaît les motifs (répétitions, suites, clavier, dates,
// mots de passe et mots courants, substitutions l33t) au lieu de compter les classes de
// caractères, et donne un poids aux caractères hors ASCII (cyrillique, CJK, emoji...).

import { calculateEntropy, getPasswordStrength, analyzePassword, STRENGTH_LABEL_KEYS } from './passwordStrength';
import { analyzeVault, WEAK_ENTROPY_THRESHOLD } from './passwordHealth';
import fs from 'fs';
import path from 'path';
import fr from '../locales/fr.json';
import en from '../locales/en.json';

const LEVELS = ['weak', 'medium', 'strong', 'veryStrong'];

// Générateur pseudo-aléatoire déterministe (mulberry32) : vecteurs « aléatoires » reproductibles
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function randomString(rng, alphabet, len) {
  const chars = Array.from(alphabet);
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(rng() * chars.length)];
  return s;
}
// Jeu de caractères par défaut du générateur (majuscules, minuscules, chiffres, symboles, - et _)
const GENERATOR_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*+=?^~,-_';

describe('calculateEntropy', () => {
  it('renvoie 0 pour un mot de passe vide', () => {
    expect(calculateEntropy('')).toBe(0);
    expect(calculateEntropy(null)).toBe(0);
    expect(calculateEntropy(undefined)).toBe(0);
  });
  it('croît avec la longueur et la variété des caractères', () => {
    expect(calculateEntropy('aaaa')).toBeLessThan(calculateEntropy('aaaaaaaa'));
    expect(calculateEntropy('abcdefgh')).toBeLessThan(calculateEntropy('Abc1!fgh'));
  });
  it('renvoie un entier positif', () => {
    for (const p of ['a', 'Password123!', 'Gh7$kLm2!pQ9xZr4&vB1', 'жЩфЁъПрЮзщ']) {
      const e = calculateEntropy(p);
      expect(Number.isInteger(e)).toBe(true);
      expect(e).toBeGreaterThan(0);
    }
  });
});

describe('calculateEntropy — motifs reconnus (GENERATOR-18)', () => {
  // Vecteurs de la chasse aux bugs : tous notés « moyen » à « très fort » par l'ancienne heuristique
  const TRIVIAL = [
    'aaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaaaaaa',
    'Password123!',
    'P@ssw0rd2024',
    'azertyuiop123',
    'Azerty123456!',
    'qwertyuiopasdfgh',
    'Motdepasse2024!',
  ];
  it.each(TRIVIAL)('« %s » est faible', (p) => {
    const r = analyzePassword(p);
    expect(r.level).toBe('weak');
    expect(r.entropy).toBeLessThan(WEAK_ENTROPY_THRESHOLD);
  });

  it.each([
    'abcabcabcabcabc', 'xyxyxyxyxyxyxyxyxyxy', '1111111111111111', 'Aa1!Aa1!Aa1!Aa1!Aa1!',
  ])('répétition « %s » : faible', (p) => {
    expect(analyzePassword(p).level).toBe('weak');
  });

  it('une répétition vaut à peine plus que son motif', () => {
    // 'a' répété : log2(26) + log2(nombre de répétitions), et non longueur × log2(26)
    expect(calculateEntropy('aaaaaaaaaaaaaaaaaaaa')).toBeLessThan(15);
    expect(calculateEntropy('Gh7$kL'.repeat(4))).toBeLessThan(calculateEntropy('Gh7$kL') + 5);
  });

  it.each([
    'abcdefghijklmnop', '0123456789', '9876543210', 'zyxwvutsrqponm', 'ABCDEFGHIJKL', '13579bdfhj',
  ])('suite alphabétique ou numérique « %s » : faible', (p) => {
    expect(analyzePassword(p).level).toBe('weak');
  });

  it.each([
    'qwertyuiop', 'azertyuiop', 'QWERTZUIOP', '1qaz2wsx3edc', 'poiuytreza', 'asdfghjkl;', 'wxcvbn123456', '789456123',
  ])('motif clavier « %s » : faible', (p) => {
    expect(analyzePassword(p).level).toBe('weak');
  });

  it.each([
    '19/04/1987', '1987-04-19', '19041987', '04.19.1987', 'Soleil1987!', 'Julie2024',
  ])('date ou année « %s » : faible', (p) => {
    expect(analyzePassword(p).level).toBe('weak');
  });

  it.each([
    'iloveyou', 'PASSWORD', 'drowssap', 'S0l3il2024!', 'M0td3p@ss3', 'Dr@g0n!!', 'Bonjour2025', 'Chocolat!123',
    'Welcome1!', 'W3lc0m3!', 'Football1892', 'пароль123',
  ])('mot de passe ou mot courant (casse, l33t, inversion) « %s » : faible', (p) => {
    expect(analyzePassword(p).level).toBe('weak');
  });

  it('un mot de passe aléatoire du générateur reste fort (500 tirages déterministes)', () => {
    const rng = mulberry32(0xC0FFEE);
    const tooLow = [];
    for (let i = 0; i < 500; i++) {
      const p = randomString(rng, GENERATOR_ALPHABET, 20);
      if (calculateEntropy(p) < 90) tooLow.push([p, calculateEntropy(p)]);
    }
    expect(tooLow).toEqual([]);
  });

  it('un mot de passe aléatoire alphanumérique de 16 caractères reste au moins « fort »', () => {
    const rng = mulberry32(42);
    const tooLow = [];
    for (let i = 0; i < 300; i++) {
      const p = randomString(rng, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 16);
      if (!['strong', 'veryStrong'].includes(analyzePassword(p).level)) tooLow.push([p, calculateEntropy(p)]);
    }
    expect(tooLow).toEqual([]);
  });

  it('les caractères hors classes ASCII comptent (cyrillique, ponctuation, emoji) au lieu de 0 bit', () => {
    // 24 lettres cyrilliques aléatoires : 0 bit avec l'ancienne heuristique
    const cyr = randomString(mulberry32(7), 'абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ', 24);
    expect(analyzePassword(cyr).level).toBe('veryStrong');
    // 22 signes de ponctuation ASCII « non listés » tirés au hasard
    const punct = randomString(mulberry32(11), './;:\'"|\\`', 22);
    expect(calculateEntropy(punct)).toBeGreaterThanOrEqual(WEAK_ENTROPY_THRESHOLD);
    // Le vecteur de la chasse (motif de 9 signes répété) n'est plus à 0 bit
    expect(calculateEntropy('./;:\'"|\\`./;:\'"|\\`./;:')).toBeGreaterThan(0);
    // Idéogrammes, emoji, espace
    expect(calculateEntropy('龍虎鳳凰麒麟')).toBeGreaterThan(30);
    expect(calculateEntropy('😀🔐🎉🚀')).toBeGreaterThan(0);
    expect(calculateEntropy('   ')).toBeGreaterThan(0);
  });

  it('compte les caractères hors BMP comme un seul caractère', () => {
    // Un emoji (paire de substitution UTF-16) pèse comme une lettre cyrillique : un seul caractère
    expect(calculateEntropy('😀')).toBe(calculateEntropy('ж'));
    expect(calculateEntropy('😀🔐🎉')).toBe(calculateEntropy('жщф'));
  });

  it('reste rapide sur une saisie très longue (pas de comportement quadratique)', () => {
    const rng = mulberry32(3);
    const long = randomString(rng, GENERATOR_ALPHABET, 20000);
    const t0 = Date.now();
    expect(calculateEntropy(long)).toBeGreaterThan(1000);
    expect(calculateEntropy('ab'.repeat(10000))).toBeLessThan(WEAK_ENTROPY_THRESHOLD);
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

describe('calculateEntropy — revue E7 (accents, NFC, phrases de passe, temps, bundle)', () => {
  it('un accent ajouté à un mot courant ne coûte qu\'un bit (avant : « motdepassé » = 63 bits)', () => {
    expect(calculateEntropy('motdepassé')).toBeLessThanOrEqual(calculateEntropy('motdepasse') + 2);
    for (const p of ['motdepassé', 'MOTDEPASSÉ', 'Liberté2024', 'Trésor!1', 'Пароль!', 'Şifre2020']) {
      expect([p, analyzePassword(p).level]).toEqual([p, 'weak']);
    }
  });

  it('saisie décomposée (NFD) et composée (NFC) : même estimation', () => {
    expect(calculateEntropy('é')).toBe(calculateEntropy('é'));
    expect(calculateEntropy('Café-Màjor-9')).toBe(calculateEntropy('Café-Màjor-9'));
    expect(calculateEntropy('motdepassé')).toBe(calculateEntropy('motdepassé'));
  });

  it('une phrase de passe longue faite de mots aléatoires est très forte', () => {
    expect(analyzePassword('violet glacier anchor tundra orbit maple').level).toBe('veryStrong');
    // Mots tirés au hasard (lettres aléatoires) séparés par des tirets
    const rng = mulberry32(2026);
    for (let i = 0; i < 50; i++) {
      const words = Array.from({ length: 5 }, () => randomString(rng, 'abcdefghijklmnopqrstuvwxyz', 6));
      expect(analyzePassword(words.join('-')).level).toBe('veryStrong');
    }
  });

  it('des mots courants assemblés restent au-dessus d\'un mot de passe trivial', () => {
    expect(calculateEntropy('soleil-plage-hiver-montagne-cheval-papillon'))
      .toBeGreaterThan(calculateEntropy('Motdepasse2024!') + 30);
  });

  it('10 000 caractères adverses : aucun crash, temps borné', () => {
    const rng = mulberry32(5);
    const digits = randomString(rng, '0123456789', 10000);
    const emoji = Array.from({ length: 10000 }, () => String.fromCodePoint(0x1F600 + Math.floor(rng() * 64))).join('');
    const latinSeq = Array.from({ length: 10000 }, (_, i) => String.fromCodePoint(0x100 + (i % 128))).join('');
    const blocks = Array.from({ length: 50 }, () => randomString(rng, 'abcdefghijklmnopqrstuvwxyz', 100)).map(b => b + b).join('');
    const vectors = [
      '1'.repeat(10000), digits, 'p@55w0rd'.repeat(1250), '19/04/1987'.repeat(1000), '0123456789'.repeat(1000),
      emoji, '😀'.repeat(10000), latinSeq, blocks, '1l|!'.repeat(2500), 'é'.repeat(5000),
      randomString(rng, 'абвгдежзийклмнопрстуфхцчшщэюяАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЭЮЯ', 10000),
    ];
    const t0 = Date.now();
    for (const v of vectors) {
      const e = calculateEntropy(v);
      expect(Number.isInteger(e)).toBe(true);
      expect(e).toBeGreaterThan(0);
    }
    expect(Date.now() - t0).toBeLessThan(4000);
    // Hors BMP aléatoire : ~log2(100) bits par emoji, et non par demi-paire de substitution
    expect(calculateEntropy(emoji)).toBeGreaterThan(10000 * 5);
    expect(calculateEntropy(emoji)).toBeLessThan(10000 * 7);
  });

  it('accepte une valeur non textuelle sans planter', () => {
    expect(calculateEntropy(123456)).toBe(calculateEntropy('123456'));
  });

  it('source sans propriété Unicode \\p{…} (développée en Ko de plages par la compilation)', () => {
    const src = fs.readFileSync(path.join(__dirname, 'passwordStrength.js'), 'utf8');
    // Commentaires retirés : seul le code compte
    expect(src.replace(/^\s*(\/\/|\*|\/\*).*$/gm, '')).not.toMatch(/\\p\{/);
    expect(src.length).toBeLessThan(30000);
  });
});

describe('impact sur l\'audit de santé (passwordHealth.analyzeVault)', () => {
  it('les mots de passe triviaux sont désormais signalés faibles', () => {
    const vectors = ['aaaaaaaaaaaa', 'aaaaaaaaaaaaaaaaaaaa', 'Password123!', 'P@ssw0rd2024',
      'azertyuiop123', 'Azerty123456!', 'qwertyuiopasdfgh', 'Motdepasse2024!'];
    const report = analyzeVault(vectors.map((p, i) => ({ name: 'e' + i, password: p })));
    expect(report.weak).toHaveLength(8);
    expect(report.score).toBe(50); // 8 faibles, 0 réutilisé (100/100 avant le correctif)
  });

  it('des mots de passe aléatoires (dont non latins) ne sont pas signalés faibles', () => {
    const rng = mulberry32(99);
    const secrets = [
      ...Array.from({ length: 20 }, (_, i) => ({ name: 'g' + i, password: randomString(rng, GENERATOR_ALPHABET, 20) })),
      { name: 'cyr', password: randomString(rng, 'абвгдежзийклмнопрстуфхцчшщэюя', 24) },
      { name: 'fixture', password: 'Gh7$kLm2!pQ9xZr4&vB1' },
    ];
    const report = analyzeVault(secrets);
    expect(report.weak).toHaveLength(0);
    expect(report.score).toBe(100);
  });
});

describe('getPasswordStrength', () => {
  it('renvoie un niveau neutre selon les paliers d\'entropie', () => {
    expect(getPasswordStrength(0).level).toBe('weak');
    expect(getPasswordStrength(49).level).toBe('weak');
    expect(getPasswordStrength(50).level).toBe('medium');
    expect(getPasswordStrength(69).level).toBe('medium');
    expect(getPasswordStrength(70).level).toBe('strong');
    expect(getPasswordStrength(89).level).toBe('strong');
    expect(getPasswordStrength(90).level).toBe('veryStrong');
    expect(getPasswordStrength(200).level).toBe('veryStrong');
  });
  it('ne contient aucun libellé codé en dur', () => {
    for (const e of [10, 60, 80, 120]) {
      const res = getPasswordStrength(e);
      expect(LEVELS).toContain(res.level);
      expect(res.strength).toBeUndefined();
      expect(res.label).toBeUndefined();
    }
  });
  it('borne le pourcentage entre 0 et 100', () => {
    expect(getPasswordStrength(0).percentage).toBe(0);
    expect(getPasswordStrength(500).percentage).toBe(100);
  });
  it('valeur absente, négative ou NaN : palier faible (avant : NaN → « très forte »)', () => {
    for (const v of [undefined, null, NaN, -10, '80']) {
      expect(getPasswordStrength(v)).toEqual({ level: 'weak', color: 'var(--error)', percentage: 0 });
    }
  });
});

describe('STRENGTH_LABEL_KEYS', () => {
  it('couvre chaque niveau avec une clé traduite en fr et en', () => {
    const read = (obj, key) => key.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);
    for (const level of LEVELS) {
      const key = STRENGTH_LABEL_KEYS[level];
      expect(typeof key).toBe('string');
      expect(typeof read(fr, key)).toBe('string');
      expect(typeof read(en, key)).toBe('string');
    }
  });
});

describe('analyzePassword', () => {
  it('combine entropie, niveau, couleur et pourcentage', () => {
    const r = analyzePassword('Tr0ub4dor&3xyz!');
    expect(r.entropy).toBeGreaterThan(0);
    expect(LEVELS).toContain(r.level);
    expect(r.color).toMatch(/^var\(--/);
    expect(r.percentage).toBeGreaterThan(0);
  });
  it('renvoie le palier faible pour un mot de passe vide', () => {
    expect(analyzePassword('')).toEqual({ entropy: 0, level: 'weak', color: 'var(--error)', percentage: 0 });
  });
  it('conserve la forme de l\'objet renvoyé (API inchangée)', () => {
    expect(Object.keys(analyzePassword('Gh7$kLm2!pQ9xZr4&vB1')).sort()).toEqual(['color', 'entropy', 'level', 'percentage']);
  });
});
