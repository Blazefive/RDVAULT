// ========================================
// UTILITAIRES XML (export/import de secrets)
// ========================================
// Le décodage se fait en UN SEUL passage (unescapeXml) : une valeur contenant
// littéralement « &lt; » (exportée en « &amp;lt; », ou « &#38;lt; » par un outil
// tiers) ne doit jamais être décodée deux fois et devenir « < ».

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

// Entités XML prédéfinies
const NAMED_ENTITIES = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' };

/**
 * Décode les entités XML prédéfinies et numériques (inverse exact de escapeXml)
 * @param {string} value
 * @returns {string}
 */
export function unescapeXml(value) {
  // IMPORT-7 : un seul passage. Chaque référence est remplacée une fois et le texte produit n'est
  // jamais relu : « &#38;lt; » donne « &lt; » (avant : les références numériques étaient décodées
  // d'abord, puis « &lt; » obtenu était redécodé en « < »).
  return String(value ?? '').replace(
    /&(?:#x([0-9a-fA-F]+)|#(\d+)|(lt|gt|quot|apos|amp));/g,
    (_, hex, dec, name) => {
      if (hex !== undefined) return safeFromCodePoint(parseInt(hex, 16));
      if (dec !== undefined) return safeFromCodePoint(parseInt(dec, 10));
      return NAMED_ENTITIES[name];
    }
  );
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
