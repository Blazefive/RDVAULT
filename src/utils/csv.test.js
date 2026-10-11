// ========================================
// TESTS : utilitaires CSV (src/utils/csv.js)
// ========================================
// Vérifie la neutralisation des formules tableur (CSV injection), l'opération
// inverse à l'import, et l'échappement des champs (guillemets, séparateur,
// sauts de ligne).

import { escapeCsvField, neutralizeCsvFormula, unescapeCsvFormula, parseCsv, detectCsvSeparator } from './csv';

describe('neutralizeCsvFormula', () => {
  it.each([
    ['=1+1', "'=1+1"],
    ['+33612', "'+33612"],
    ['-secret', "'-secret"],
    ['@SUM(A1)', "'@SUM(A1)"],
    ['|cmd', "'|cmd"],
    ['\tvaleur', "'\tvaleur"],
    ['\rvaleur', "'\rvaleur"],
  ])('préfixe %j par une apostrophe', (input, expected) => {
    expect(neutralizeCsvFormula(input)).toBe(expected);
  });

  it('ne modifie pas une valeur inoffensive', () => {
    expect(neutralizeCsvFormula('mot de passe')).toBe('mot de passe');
    expect(neutralizeCsvFormula('a=b')).toBe('a=b');
  });

  it('convertit null/undefined en chaîne vide', () => {
    expect(neutralizeCsvFormula(null)).toBe('');
    expect(neutralizeCsvFormula(undefined)).toBe('');
  });
});

describe('unescapeCsvFormula', () => {
  it("retire l'apostrophe de protection ajoutée à l'export", () => {
    expect(unescapeCsvFormula("'=1+1")).toBe('=1+1');
    expect(unescapeCsvFormula("'-x")).toBe('-x');
    expect(unescapeCsvFormula("'\tx")).toBe('\tx');
  });

  it("conserve une apostrophe légitime (non suivie d'un caractère de formule)", () => {
    expect(unescapeCsvFormula("'abc")).toBe("'abc");
    expect(unescapeCsvFormula("l'été")).toBe("l'été");
  });

  it('ne touche pas aux valeurs courtes ou non textuelles', () => {
    expect(unescapeCsvFormula("'")).toBe("'");
    expect(unescapeCsvFormula('')).toBe('');
    expect(unescapeCsvFormula(42)).toBe(42);
  });

  it('est l\'inverse de neutralizeCsvFormula', () => {
    for (const v of ['=x', '+x', '-x', '@x', '|x', 'plain', "'quoted"]) {
      expect(unescapeCsvFormula(neutralizeCsvFormula(v))).toBe(v);
    }
  });
});

describe('escapeCsvField', () => {
  it('retourne la valeur telle quelle si aucun échappement n\'est nécessaire', () => {
    expect(escapeCsvField('simple')).toBe('simple');
  });

  it('entoure de guillemets si le séparateur est présent (";" par défaut)', () => {
    expect(escapeCsvField('a;b')).toBe('"a;b"');
    // Avec un autre séparateur, ";" n'impose plus de guillemets
    expect(escapeCsvField('a;b', { separator: ',' })).toBe('a;b');
    expect(escapeCsvField('a,b', { separator: ',' })).toBe('"a,b"');
  });

  it('double les guillemets internes', () => {
    expect(escapeCsvField('dit "bonjour"')).toBe('"dit ""bonjour"""');
  });

  it('neutralise les formules avant l\'échappement', () => {
    expect(escapeCsvField('=HYPERLINK("x")')).toBe('"\'=HYPERLINK(""x"")"');
    expect(escapeCsvField('-1')).toBe("'-1");
  });

  it('toujours entre guillemets avec alwaysQuote', () => {
    expect(escapeCsvField('simple', { alwaysQuote: true })).toBe('"simple"');
    expect(escapeCsvField('', { alwaysQuote: true })).toBe('""');
  });

  it('remplace les sauts de ligne par des espaces avec flattenNewlines', () => {
    expect(escapeCsvField('ligne1\r\nligne2\nligne3', { flattenNewlines: true })).toBe('ligne1 ligne2 ligne3');
  });

  it('entoure de guillemets les sauts de ligne conservés', () => {
    expect(escapeCsvField('l1\nl2')).toBe('"l1\nl2"');
  });

  it('convertit null/undefined en chaîne vide', () => {
    expect(escapeCsvField(null)).toBe('');
    expect(escapeCsvField(undefined)).toBe('');
  });
});

// ========================================
// PARSEUR RFC 4180 + aller-retour export → import
// ========================================

describe('parseCsv', () => {
  it('lit un en-tête et des lignes simples, séparateur détecté', () => {
    const { header, rows, separator } = parseCsv('Name;Username\nsrv;root\n');
    expect(separator).toBe(';');
    expect(header).toEqual(['name', 'username']);
    expect(rows).toEqual([{ name: 'srv', username: 'root' }]);
  });

  it('ignore le BOM UTF-8 écrit par Excel', () => {
    const { rows } = parseCsv('\uFEFFName,Password\nsrv,secret');
    expect(rows[0].name).toBe('srv');
  });

  it('gère les guillemets doublés, séparateurs et sauts de ligne dans un champ guillemeté', () => {
    const csv = 'Name,Notes\n"srv","ligne 1, virgule\nligne 2 ""citée"""\n';
    const { rows } = parseCsv(csv);
    expect(rows).toHaveLength(1);
    expect(rows[0].notes).toBe('ligne 1, virgule\nligne 2 "citée"');
  });

  it("un guillemet au milieu d'un champ non guillemeté ne décale pas les colonnes", () => {
    const { rows } = parseCsv('Name,Password,URL\nsrv,pa"ss,https://x\n');
    expect(rows[0]).toEqual({ name: 'srv', password: 'pa"ss', url: 'https://x' });
  });

  it('ne tronque pas les valeurs (espaces conservés)', () => {
    const { rows } = parseCsv('Name,Password\nsrv, mot de passe \n');
    expect(rows[0].password).toBe(' mot de passe ');
  });

  it('accepte CRLF, lignes vides et lignes plus courtes que l\'en-tête', () => {
    const { rows } = parseCsv('Name,Username,Password\r\n\r\nsrv,root\r\n');
    expect(rows).toEqual([{ name: 'srv', username: 'root', password: '' }]);
  });

  it("retire l'apostrophe de protection anti-formule", () => {
    const { rows } = parseCsv('Name,Password\nsrv,"\'=cmd|calc"\n');
    expect(rows[0].password).toBe('=cmd|calc');
  });

  it('retourne vide sans ligne de données', () => {
    expect(parseCsv('Name,Password\n').rows).toEqual([]);
    expect(parseCsv('').rows).toEqual([]);
  });
});

describe('aller-retour export → import', () => {
  const tricky = [
    'simple', 'avec, virgule', 'avec; point-virgule', 'guillemet " interne', '"entouré"',
    '=formule()', "'apostrophe", "'=piège", '+33 6', '-tiret', '@arobase', 'ligne1\nligne2\r\nligne3',
    '  espaces  ', 'unicode é ✓', '', 'a""b', "''",
  ];
  it.each([',', ';'])('conserve exactement chaque valeur (séparateur %j)', (sep) => {
    const header = 'Name' + sep + 'Password';
    const lines = tricky.map((v, i) => [escapeCsvField('s' + i, { separator: sep, alwaysQuote: true }), escapeCsvField(v, { separator: sep, alwaysQuote: true })].join(sep));
    const csv = header + '\n' + lines.join('\n') + '\n';
    const { rows } = parseCsv(csv);
    expect(rows).toHaveLength(tricky.length);
    tricky.forEach((v, i) => expect(rows[i].password).toBe(v));
  });
});

describe('detectCsvSeparator', () => {
  it('choisit le séparateur le plus fréquent', () => {
    expect(detectCsvSeparator('a;b;c')).toBe(';');
    expect(detectCsvSeparator('a,b,c')).toBe(',');
    expect(detectCsvSeparator('a\tb')).toBe('\t');
    expect(detectCsvSeparator('a')).toBe(',');
  });
});
