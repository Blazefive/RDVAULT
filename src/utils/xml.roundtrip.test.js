// ========================================
// TESTS ADVERSARIAUX : round-trip XML export → import
// ========================================
// Échappe chaque champ (escapeXml) dans une balise, puis le relit (readXmlTag) et
// exige l'égalité exacte sur des valeurs qui ressemblent à des entités ou à des
// balises — pour détecter double-décodage, injection de balise ou perte.

import { escapeXml, unescapeXml, readXmlTag } from './xml';

const NASTY = [
  'simple',
  'a < b > c',
  'tom & jerry',
  'guillemets "doubles" et \'simples\'',
  '&lt;',                 // entité littérale (ne doit PAS devenir « < »)
  '&amp;',                // (ne doit PAS devenir « & »)
  '&gt; &quot; &apos;',
  '&#65;',                // entité numérique littérale (ne doit PAS devenir « A »)
  '&#x41;',
  '</password>',          // balise fermante dans la valeur
  '<script>alert(1)</script>',
  ']]>',                  // séquence de fin CDATA
  'ligne1\nligne2\r\nligne3',
  '  espaces de bord  ',
  'ünïcödé ✓ — «x» 🔐',
  '',
  '&amp;lt; double',      // piège de double-décodage
];

describe('round-trip XML : échappe puis relit sans perte ni double-décodage', () => {
  for (const v of NASTY) {
    it(`préserve exactement ${JSON.stringify(v)}`, () => {
      const block = `<password>${escapeXml(v)}</password>`;
      expect(readXmlTag(block, 'password')).toBe(v);
    });
  }

  it('escapeXml → unescapeXml est l\'identité sur les cas piégeux', () => {
    for (const v of NASTY) {
      expect(unescapeXml(escapeXml(v))).toBe(v);
    }
  });

  it('une valeur ne peut pas injecter une balise frère (pas de décalage de champ)', () => {
    const pwd = '</password><username>pirate</username>';
    const block = `<username>${escapeXml('legit')}</username><password>${escapeXml(pwd)}</password>`;
    expect(readXmlTag(block, 'username')).toBe('legit');
    expect(readXmlTag(block, 'password')).toBe(pwd);
  });

  it('lecture d\'une balise avec attributs et CDATA (XML externe)', () => {
    expect(readXmlTag('<url type="x">https://a.example</url>', 'url')).toBe('https://a.example');
    expect(readXmlTag('<notes><![CDATA[<b>brut</b> & co]]></notes>', 'notes')).toBe('<b>brut</b> & co');
  });

  it('balise absente → chaîne vide', () => {
    expect(readXmlTag('<a>x</a>', 'password')).toBe('');
  });

  it('entités numériques réelles décodées (import XML externe)', () => {
    expect(unescapeXml('&#65;&#x42;')).toBe('AB');
    expect(unescapeXml('&#9731;')).toBe('☃');
  });
});
