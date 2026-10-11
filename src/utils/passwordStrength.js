// src/utils/passwordStrength.js
//
// GENERATOR-18 : estimation de l'entropie par reconnaissance de motifs (inspirée de zxcvbn,
// entièrement hors ligne et sans dépendance). L'ancienne heuristique multipliait la longueur
// par log2(somme des classes présentes) : « aaaaaaaaaaaaaaaaaaaa » valait 94 bits et
// « Motdepasse2024! » 93 bits, tandis qu'un mot de passe aléatoire en cyrillique valait 0 bit.
//
// Principe : le mot de passe est découpé en segments au coût minimal (programmation
// dynamique). Chaque segment est soit un caractère tiré au hasard (log2 du jeu de caractères
// du mot de passe), soit un motif reconnu, beaucoup moins coûteux à deviner :
//   - répétition d'un bloc (« aaaa », « abcabc », « Aa1!Aa1! ») ;
//   - suite alphabétique ou numérique, montante ou descendante, à pas constant ;
//   - parcours de clavier (AZERTY, QWERTY, QWERTZ, colonnes, pavé numérique) ;
//   - date (avec ou sans séparateurs) et année ;
//   - mot générique courant (casse, accents, substitutions l33t, inversion) ; la liste reste
//     courte : un mot absent est compté en force brute, ce qui SURESTIME les phrases de mots
//     usuels non listés (limite assumée d'un estimateur hors ligne sans gros dictionnaire).
// Tout caractère compte : la ponctuation ASCII, les lettres accentuées et les autres
// écritures (cyrillique, CJK, emoji...) ont chacune un poids ; un caractère hors BMP compte
// pour un seul caractère, et la saisie est normalisée en NFC. Temps quasi linéaire (budget
// borné pour les répétitions) : 10 000 caractères s'analysent en quelques dizaines de ms. L'API (calculateEntropy, getPasswordStrength, analyzePassword,
// STRENGTH_LABEL_KEYS) est inchangée.

const log2 = Math.log2;

// Année de référence fixe : les estimations restent reproductibles d'une année à l'autre
const REFERENCE_YEAR = 2026;
const MIN_YEAR_SPACE = 20;
// Longueurs minimales des motifs (en dessous, la force brute est plus juste)
const DICT_MIN_LENGTH = 4;
const SEQUENCE_MIN_LENGTH = 3;
const KEYBOARD_MIN_LENGTH = 4;
// Budget de comparaisons de la recherche de répétitions (évite tout comportement quadratique)
const REPEAT_COMPARISON_BUDGET = 2000000;

// ---------- Jeu de caractères (force brute) ----------

/** Taille du jeu de caractères déduite des classes présentes (points de code). */
function charsetSize(codes) {
  let lower = false; let upper = false; let digit = false; let ascii = false; let latin = false; let other = false;
  for (const c of codes) {
    if (c >= 97 && c <= 122) lower = true;
    else if (c >= 65 && c <= 90) upper = true;
    else if (c >= 48 && c <= 57) digit = true;
    else if (c >= 32 && c <= 126) ascii = true; // espace et 32 signes de ponctuation ASCII
    else if (c >= 0xA0 && c <= 0x24F) latin = true; // Latin-1 et Latin étendu (accents)
    else other = true; // cyrillique, grec, CJK, emoji, etc.
  }
  return (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (ascii ? 33 : 0)
    + (latin ? 128 : 0) + (other ? 100 : 0);
}

// ---------- Casse ----------

function binomial(n, k) {
  if (k < 0 || k > n) return 0;
  let r = 1;
  for (let i = 1; i <= k; i++) r = (r * (n - k + i)) / i;
  return r;
}

/** Bits ajoutés par la casse d'un motif (tout en minuscules : 0 ; initiale ou tout en majuscules : 1). */
function caseBits(chars) {
  let upper = 0; let lower = 0; let firstUpper = false; let lastUpper = false; let seen = false;
  for (const ch of chars) {
    const isUpper = ch !== ch.toLowerCase();
    const isLower = !isUpper && ch !== ch.toUpperCase();
    if (!isUpper && !isLower) continue;
    if (!seen) { firstUpper = isUpper; seen = true; }
    lastUpper = isUpper;
    if (isUpper) upper++; else lower++;
  }
  if (upper === 0) return 0;
  if (lower === 0) return 1;
  if (upper === 1 && (firstUpper || lastUpper)) return 1;
  let sum = 0;
  for (let k = 1; k <= Math.min(upper, lower); k++) sum += binomial(upper + lower, k);
  return log2(sum);
}

// ---------- Dictionnaire (mots génériques, par fréquence décroissante) ----------
// Liste volontairement COURTE et GÉNÉRIQUE : mots usuels (« password », « admin », noms
// communs, saisons, salutations...) et non une liste de mots de passe issus de fuites ni de
// prénoms. Les accents sont ignorés à la recherche (voir foldDiacritic) : une seule forme
// sans accent par mot suffit.

const COMMON_WORDS = [
  // Mots de passe génériques et comptes par défaut
  'password', 'admin', 'administrator', 'root', 'user', 'guest', 'test', 'login', 'welcome',
  'default', 'changeme', 'secret', 'master', 'qwerty', 'azerty', 'qwertz', 'hello', 'love',
  'lover', 'access', 'system', 'server', 'database', 'computer', 'internet',
  // Mots courants (anglais)
  'dragon', 'monkey', 'sunshine', 'princess', 'football', 'baseball', 'soccer', 'hockey',
  'tennis', 'summer', 'winter', 'spring', 'autumn', 'freedom', 'shadow', 'flower', 'angel',
  'money', 'family', 'friend', 'forever', 'music', 'guitar', 'rainbow', 'butterfly', 'tiger',
  'eagle', 'lucky', 'winner', 'champion', 'player', 'kitten', 'puppy', 'cookie', 'coffee',
  'chocolate', 'orange', 'banana', 'apple', 'silver', 'golden', 'diamond', 'purple', 'yellow',
  'house', 'happy', 'peace', 'heaven', 'thunder', 'island', 'ocean',
  // Mots courants (français)
  'motdepasse', 'bonjour', 'bonsoir', 'salut', 'coucou', 'bienvenue', 'merci', 'soleil',
  'amour', 'jetaime', 'chocolat', 'maison', 'famille', 'bonheur', 'liberte', 'vacances',
  'printemps', 'automne', 'hiver', 'chien', 'chaton', 'cheval', 'lapin', 'oiseau', 'poisson',
  'fleur', 'etoile', 'plage', 'montagne', 'ordinateur', 'papillon', 'tresor', 'princesse',
  'doudou', 'loulou', 'bisous', 'cheri', 'cherie', 'maman', 'papa',
  // Autres langues
  'passwort', 'hallo', 'liebe', 'sommer', 'contrasena', 'hola', 'amor', 'senha', 'parola',
  'ciao', 'amore', 'sifre', 'пароль', 'привет', 'любовь',
];

/** Trie des mots (rang = position dans la liste, 1 = le plus fréquent). */
const DICT_TRIE = (() => {
  const root = { next: new Map(), rank: 0 };
  COMMON_WORDS.forEach((word, idx) => {
    let node = root;
    for (const ch of word) {
      let child = node.next.get(ch);
      if (!child) { child = { next: new Map(), rank: 0 }; node.next.set(ch, child); }
      node = child;
    }
    if (!node.rank) node.rank = idx + 1;
  });
  return root;
})();

// Substitutions l33t courantes : symbole → lettre(s) qu'il remplace
const L33T = {
  '4': 'a', '@': 'a', '8': 'b', '(': 'c', '{': 'c', '[': 'c', '<': 'c', '3': 'e', '€': 'e',
  '6': 'g', '9': 'g', '1': 'il', '!': 'il', '|': 'il', '0': 'o', '$': 's', '5': 's', '+': 't',
  '7': 'tl', '%': 'x', '2': 'z',
};

// Diacritiques combinants (U+0300–U+036F) retirés après décomposition NFD
const COMBINING_DIACRITICS = /[̀-ͯ]/g;

/**
 * Lettre sans accent (« é » → « e », « ё » → « е », « ş » → « s »), ou null si le caractère
 * n'a pas d'accent. Un accent ajouté à un mot courant ne coûte qu'un bit, comme une
 * substitution l33t (« motdepassé » n'est pas plus sûr que « motdepasse »).
 */
function foldDiacritic(ch) {
  const folded = ch.normalize('NFD').replace(COMBINING_DIACRITICS, '');
  return folded !== ch && Array.from(folded).length === 1 ? folded : null;
}

/** Mots du dictionnaire présents dans `lower` (casse, accents et l33t ignorés), éventuellement à l'envers. */
function dictionaryMatches(lower, chars, reversed, emit) {
  const n = lower.length;
  const folded = lower.map(foldDiacritic);
  const visit = (start, node, k, subs) => {
    const len = k - start;
    if (node.rank && len >= DICT_MIN_LENGTH) {
      const i = reversed ? n - k : start;
      const j = reversed ? n - start : k;
      emit(i, j, log2(node.rank + 1) + caseBits(chars.slice(i, j)) + subs + (reversed ? 1 : 0));
    }
    if (k >= n) return;
    const ch = lower[k];
    const direct = node.next.get(ch);
    if (direct) visit(start, direct, k + 1, subs);
    const plain = folded[k] ? node.next.get(folded[k]) : null;
    if (plain) visit(start, plain, k + 1, subs + 1);
    const alts = L33T[ch];
    if (alts) {
      for (const a of alts) {
        const child = a !== ch ? node.next.get(a) : null;
        if (child) visit(start, child, k + 1, subs + 1);
      }
    }
  };
  for (let i = 0; i < n; i++) visit(i, DICT_TRIE, i, 0);
}

// ---------- Suites (abc, 13579, zyx, 9876...) ----------

/**
 * Rang d'un caractère pour les suites : chiffres et lettres ASCII sur une même échelle
 * (base 36 : « 13579bdfhj » est une suite de pas 2). La casse doit rester la même tout au long
 * de la suite (comme zxcvbn) : « FGh » n'est pas une suite, « ABC » et « abc » le sont.
 */
function sequenceRank(ch) {
  const c = ch.codePointAt(0);
  if (c >= 48 && c <= 57) return { domain: 'digit', rank: c - 48 };
  if (c >= 97 && c <= 122) return { domain: 'lower', rank: c - 87 };
  if (c >= 65 && c <= 90) return { domain: 'upper', rank: c - 55 };
  // Autres alphabets à casse (cyrillique, grec, latin étendu...) : test de casse plutôt que
  // /\p{L}/u, que la compilation pour les navigateurs cibles développe en ~8 Ko de plages
  if (c > 127 && ch.toLowerCase() !== ch.toUpperCase()) return { domain: 'other', rank: c };
  return null;
}

/** Deux caractères peuvent se suivre dans une suite : même domaine, ou chiffre ↔ lettre ASCII. */
function sameSequenceDomain(a, b) {
  if (a.domain === b.domain) return true;
  const ascii = (d) => d === 'digit' || d === 'lower' || d === 'upper';
  return ascii(a.domain) && ascii(b.domain) && (a.domain === 'digit' || b.domain === 'digit');
}

function sequenceMatches(chars, emit) {
  const n = chars.length;
  if (n < SEQUENCE_MIN_LENGTH) return;
  const ranks = chars.map(sequenceRank);
  const deltaAt = (k) => {
    const a = ranks[k - 1]; const b = ranks[k];
    if (!a || !b || !sameSequenceDomain(a, b)) return 0;
    const d = b.rank - a.rank;
    return Math.abs(d) <= 5 ? d : 0;
  };
  const flush = (i, j, delta) => {
    const len = j - i;
    if (!delta || len < SEQUENCE_MIN_LENGTH) return;
    const first = chars[i].toLowerCase();
    let base;
    if ('az019'.includes(first)) base = 4;
    else if (/[0-9]/.test(first)) base = 10;
    else base = 26;
    emit(i, j, log2(base * len) + (delta < 0 ? 1 : 0) + (Math.abs(delta) > 1 ? log2(Math.abs(delta)) : 0)
      + caseBits(chars.slice(i, j)));
  };
  let start = 0;
  let delta = deltaAt(1);
  for (let k = 2; k < n; k++) {
    const d = deltaAt(k);
    if (d === delta && d !== 0) continue;
    flush(start, k, delta);
    start = k - 1;
    delta = d;
  }
  flush(start, n, delta);
}

// ---------- Parcours de clavier ----------

const KEYBOARD_WALKS = [
  // QWERTY
  '`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./', 'qwertyuiopasdfghjklzxcvbnm',
  '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/', 'zaq1xsw2cde3vfr4bgt5nhy6mju7,ki8.lo9/;p0',
  // AZERTY
  '²&é"\'(-è_çà)=', 'azertyuiop^$', 'qsdfghjklmù*', '<wxcvbn,;:!', 'azertyuiopqsdfghjklmwxcvbn',
  '1aqw2zsx3edc4rfv5tgb6yhn7uj,8ik;9ol:0pm!',
  // QWERTZ
  'qwertzuiopü+', 'asdfghjklöä#', 'yxcvbnm,.-', 'qwertzuiopasdfghjklyxcvbnm',
  // ЙЦУКЕН (russe)
  'йцукенгшщзхъ', 'фывапролджэ', 'ячсмитьбю',
  // Pavé numérique
  '789456123', '147258369', '741852963',
];
const KEYBOARD_INDEX = (() => {
  const walks = [];
  for (const w of KEYBOARD_WALKS) {
    for (const s of [Array.from(w), Array.from(w).reverse()]) {
      walks.push({ length: s.length, index: new Map(s.map((ch, i) => [ch, i])) });
    }
  }
  return walks;
})();
const KEYBOARD_CHOICE_BITS = log2(KEYBOARD_INDEX.length);

function keyboardMatches(lower, chars, emit) {
  const n = lower.length;
  if (n < KEYBOARD_MIN_LENGTH) return;
  for (const walk of KEYBOARD_INDEX) {
    const flush = (i, j) => {
      const len = j - i;
      if (len >= KEYBOARD_MIN_LENGTH) emit(i, j, log2(walk.length * len) + KEYBOARD_CHOICE_BITS + caseBits(chars.slice(i, j)));
    };
    let start = 0;
    for (let k = 1; k < n; k++) {
      const prev = walk.index.get(lower[k - 1]);
      if (prev !== undefined && walk.index.get(lower[k]) === prev + 1) continue;
      flush(start, k);
      start = k;
    }
    flush(start, n);
  }
}

// ---------- Dates et années ----------

function yearBits(year) {
  return log2(Math.max(Math.abs(year - REFERENCE_YEAR), MIN_YEAR_SPACE));
}

function toYear(s) {
  const v = Number(s);
  if (s.length === 4) return v >= 1000 && v <= 2099 ? v : null;
  if (s.length === 2) return v > 50 ? 1900 + v : 2000 + v;
  return null;
}

/** Année d'une date plausible jour/mois/année (dans un ordre courant), sinon null. */
function plausibleDateYear(a, b, c) {
  const orders = [];
  if (a.length === 4) orders.push([c, b, a], [b, c, a]); // a-m-j, a-j-m
  if (c.length === 4 || c.length === 2) orders.push([a, b, c], [b, a, c]); // j-m-a, m-j-a
  if (a.length === 2 && c.length <= 2) orders.push([c, b, a]); // aa-mm-jj
  for (const [d, m, y] of orders) {
    if (d.length > 2 || m.length > 2) continue;
    const day = Number(d); const month = Number(m); const year = toYear(y);
    if (year !== null && day >= 1 && day <= 31 && month >= 1 && month <= 12) return year;
  }
  return null;
}

const DATE_WITH_SEPARATOR = /^(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})/;
const DATE_SPLITS = {
  8: [[0, 2, 4], [4, 6, 0]], // jjmmaaaa / mmjjaaaa, aaaammjj / aaaajjmm
  6: [[0, 2, 4], [4, 2, 0]], // jjmmaa / mmjjaa, aammjj
};

function dateMatches(lower, emit) {
  const n = lower.length;
  const isDigit = (k) => k < n && lower[k].length === 1 && lower[k] >= '0' && lower[k] <= '9';
  for (let i = 0; i < n; i++) {
    if (!isDigit(i)) continue;
    // Avec séparateurs : 19/04/1987, 1987-04-19, 04.19.1987
    const m = DATE_WITH_SEPARATOR.exec(lower.slice(i, i + 12).join(''));
    if (m) {
      const year = plausibleDateYear(m[1], m[3], m[4]);
      if (year !== null) emit(i, i + m[0].length, log2(31 * 12) + yearBits(year) + 2);
    }
    // Sans séparateur (dans une suite de chiffres) : 19041987, 870419
    for (const len of [6, 8]) {
      if (!isDigit(i + len - 1)) continue;
      let allDigits = true;
      for (let k = i; k < i + len; k++) if (!isDigit(k)) { allDigits = false; break; }
      if (!allDigits) continue;
      const s = lower.slice(i, i + len).join('');
      const yl = len === 8 ? 4 : 2;
      for (const [p1, p2, py] of DATE_SPLITS[len]) {
        const y = s.slice(py, py + yl);
        const x1 = s.slice(p1, p1 + 2); const x2 = s.slice(p2, p2 + 2);
        const year = plausibleDateYear(x1, x2, y);
        if (year !== null) { emit(i, i + len, log2(31 * 12) + yearBits(year)); break; }
      }
    }
    // Année seule : 1987, 2024
    if (isDigit(i + 3) && isDigit(i + 1) && isDigit(i + 2)) {
      const s = lower.slice(i, i + 4).join('');
      if (/^(1[89]|20)\d\d$/.test(s)) emit(i, i + 4, yearBits(Number(s)));
    }
  }
}

// ---------- Répétitions ----------

function repeatMatches(codes, chars, emit, estimate) {
  const n = codes.length;
  const maxPeriod = Math.min(Math.floor(n / 2), Math.max(16, Math.floor(REPEAT_COMPARISON_BUDGET / Math.max(1, n))));
  const flush = (start, regionLength, period) => {
    const reps = Math.floor(regionLength / period);
    if (reps < 2) return;
    const baseBits = estimate(chars.slice(start, start + period));
    emit(start, start + reps * period, baseBits + log2(reps));
  };
  for (let p = 1; p <= maxPeriod; p++) {
    let run = 0;
    for (let i = 0; i + p < n; i++) {
      if (codes[i] === codes[i + p]) { run++; continue; }
      if (run >= p) flush(i - run, run + p, p);
      run = 0;
    }
    if (run >= p) flush(n - p - run, run + p, p);
  }
}

// ---------- Estimation (segmentation au coût minimal) ----------

function estimateBits(chars, memo) {
  const key = chars.join('');
  if (memo.has(key)) return memo.get(key);
  const n = chars.length;
  const codes = chars.map(ch => ch.codePointAt(0));
  const lower = chars.map(ch => ch.toLowerCase());
  const bruteforceBits = log2(Math.max(1, charsetSize(codes)));

  // Meilleur coût de chaque motif, indexé par sa position de fin
  const best = new Map();
  const emit = (i, j, bits) => {
    if (j - i < 1 || !(bits >= 0)) return;
    const k = i * (n + 1) + j;
    const prev = best.get(k);
    if (prev === undefined || bits < prev) best.set(k, bits);
  };
  const estimate = (sub) => estimateBits(sub, memo);
  dictionaryMatches(lower, chars, false, emit);
  dictionaryMatches(lower.slice().reverse(), chars, true, emit);
  sequenceMatches(chars, emit);
  keyboardMatches(lower, chars, emit);
  dateMatches(lower, emit);
  repeatMatches(codes, chars, emit, estimate);

  const byEnd = new Array(n + 1);
  for (const [k, bits] of best) {
    const i = Math.floor(k / (n + 1)); const j = k % (n + 1);
    (byEnd[j] || (byEnd[j] = [])).push([i, bits]);
  }
  const cost = new Float64Array(n + 1);
  for (let j = 1; j <= n; j++) {
    let c = cost[j - 1] + bruteforceBits;
    const ending = byEnd[j];
    if (ending) for (const [i, bits] of ending) if (cost[i] + bits < c) c = cost[i] + bits;
    cost[j] = c;
  }
  memo.set(key, cost[n]);
  return cost[n];
}

/**
 * Calcule l'entropie estimée d'un mot de passe en bits (entier, motifs pris en compte)
 * @param {string} password - Le mot de passe à analyser
 * @returns {number} L'entropie en bits (0 pour un mot de passe vide, au moins 1 sinon)
 */
export const calculateEntropy = (password) => {
  if (!password) return 0;
  // Forme NFC : « e » + accent combinant (saisie décomposée, macOS) pèse comme « é ».
  // Découpage par points de code : un emoji (paire de substitution) compte pour un caractère
  const chars = Array.from(String(password).normalize('NFC'));
  if (chars.length === 0) return 0;
  return Math.max(1, Math.floor(estimateBits(chars, new Map())));
};

/**
 * Clés i18n des libellés de force, indexées par niveau (section passwordGenerator.*)
 * Les composants affichent t(STRENGTH_LABEL_KEYS[level]) : aucun libellé n'est codé en dur ici.
 */
export const STRENGTH_LABEL_KEYS = {
  weak: 'passwordGenerator.strengthWeak',
  medium: 'passwordGenerator.strengthMedium',
  strong: 'passwordGenerator.strengthStrong',
  veryStrong: 'passwordGenerator.strengthVeryStrong',
};

/**
 * Évalue la force d'un mot de passe basé sur son entropie
 * @param {number} entropy - L'entropie en bits
 * @returns {{ level: 'weak'|'medium'|'strong'|'veryStrong', color: string, percentage: number }}
 */
export const getPasswordStrength = (rawEntropy) => {
  let level, color, percentage;
  // Valeur absente, négative ou non numérique : palier le plus faible (jamais « très forte »
  // par défaut, ce que donnait NaN en tombant dans la dernière branche)
  const entropy = typeof rawEntropy === 'number' && rawEntropy > 0 ? rawEntropy : 0;

  if (entropy < 50) {
    level = 'weak';
    color = 'var(--error)';
    percentage = Math.min(100, (entropy / 50) * 25);
  } else if (entropy < 70) {
    level = 'medium';
    color = 'var(--warning)';
    percentage = 25 + ((entropy - 50) / 20) * 25;
  } else if (entropy < 90) {
    level = 'strong';
    color = 'var(--success)';
    percentage = 50 + ((entropy - 70) / 20) * 25;
  } else {
    level = 'veryStrong';
    color = 'var(--info)';
    percentage = Math.min(100, 75 + ((entropy - 90) / 30) * 25);
  }

  return { level, color, percentage };
};

/**
 * Analyse complète de la force d'un mot de passe
 * @param {string} password - Le mot de passe à analyser
 * @returns {{ entropy: number, level: string, color: string, percentage: number }}
 */
export const analyzePassword = (password) => {
  const entropy = calculateEntropy(password);
  const { level, color, percentage } = getPasswordStrength(entropy);
  return { entropy, level, color, percentage };
};
