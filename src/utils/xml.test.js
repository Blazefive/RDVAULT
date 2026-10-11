// ========================================
// TESTS : utilitaires XML (src/utils/xml.js)
// ========================================

import { escapeXml, unescapeXml, readXmlTag, hasXmlTag } from './xml';

describe('hasXmlTag', () => {
  it('distingue une balise absente d\'une balise vide', () => {
    const block = '<name>x</name><notes></notes><tags/><url type="a">u</url>';
    expect(hasXmlTag(block, 'notes')).toBe(true);
    expect(hasXmlTag(block, 'tags')).toBe(true);
    expect(hasXmlTag(block, 'url')).toBe(true);
    expect(hasXmlTag(block, 'website')).toBe(false);
    // « <name> » ne doit pas faire croire à la présence de « <n> » ou « <names> »
    expect(hasXmlTag(block, 'n')).toBe(false);
    expect(hasXmlTag('<names>x</names>', 'name')).toBe(false);
    expect(hasXmlTag('<EntryType>ssh</EntryType>', 'entrytype')).toBe(true);
  });
});

describe('escapeXml / unescapeXml', () => {
  it('échappe les 5 caractères spéciaux', () => {
    expect(escapeXml(`a&b<c>d"e'f`)).toBe('a&amp;b&lt;c&gt;d&quot;e&apos;f');
  });

  it('est réversible, y compris pour des entités littérales dans la valeur', () => {
    for (const v of ['simple', 'a&b', '<script>', 'x&lt;y', '&amp;', '"quoted" & \'single\'', 'ligne1\nligne2']) {
      expect(unescapeXml(escapeXml(v))).toBe(v);
    }
  });

  it("décode &amp; en dernier (pas de double décodage)", () => {
    // Valeur d'origine « &lt; » exportée en « &amp;lt; » doit redonner « &lt; », pas « < »
    expect(unescapeXml('&amp;lt;')).toBe('&lt;');
  });

  it('décode les entités numériques', () => {
    expect(unescapeXml('&#233;t&#xE9;')).toBe('été');
  });
});

describe('readXmlTag', () => {
  it('lit une balise simple et décode son contenu', () => {
    expect(readXmlTag('<secret><name>a &amp; b</name><url></url></secret>', 'name')).toBe('a & b');
    expect(readXmlTag('<secret><name>x</name></secret>', 'url')).toBe('');
  });

  it('accepte CDATA et les attributs', () => {
    expect(readXmlTag('<notes type="text"><![CDATA[<b>gras</b> & co]]></notes>', 'notes')).toBe('<b>gras</b> & co');
  });
});
