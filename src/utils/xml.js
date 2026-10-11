// ========================================
// UTILITAIRES XML (export/import de secrets)
// ========================================
// L'ordre de décodage est important : `&amp;` doit être décodé EN DERNIER,
// sinon une valeur contenant littéralement « &lt; » (exportée en « &amp;lt; »)
// serait décodée deux fois et deviendrait « < ».

/**
 * Échappe une valeur pour un nœud texte XML
 * @param {*} value
 * @returns {string}
 */
export function escapeXml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Décode les entités XML prédéfinies et numériques (inverse exact de escapeXml)
 * @param {string} value
 * @returns {string}
 */
export function unescapeXml(value) {
  return String(value ?? '')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => safeFromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => safeFromCodePoint(parseInt(dec, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function safeFromCodePoint(cp) {
  try {
    return Number.isFinite(cp) && cp >= 0 && cp <= 0x10FFFF ? String.fromCodePoint(cp) : '';
  } catch {
    return '';
  }
}

/**
 * Indique si un bloc XML contient la balise (ouvrante, ou auto-fermante « <tag/> »).
 * Permet de distinguer une balise absente d'une balise présente mais vide
 * (readXmlTag renvoie '' dans les deux cas).
 * @param {string} block
 * @param {string} tag - Nom de balise (constante, pas d'entrée utilisateur)
 * @returns {boolean}
 */
export function hasXmlTag(block, tag) {
  return new RegExp(`<${tag}(?:\\s[^>]*)?/?>`, 'i').test(String(block ?? ''));
}

/**
 * Extrait le contenu texte d'une balise simple (première occurrence) dans un bloc XML
 * @param {string} block
 * @param {string} tag
 * @returns {string} Valeur décodée, ou chaîne vide si absente
 */
export function readXmlTag(block, tag) {
  const m = String(block ?? '').match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, 'i'));
  if (!m) return '';
  const inner = m[1];
  const cdata = inner.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/);
  return cdata ? cdata[1] : unescapeXml(inner);
}
