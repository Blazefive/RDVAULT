// ========================================
// UTILITAIRES CSV
// ========================================
// Fonctions partagées par l'export admin (AdminPanel) et l'export/import
// utilisateur (SettingsModal).
//
// SÉCURITÉ : neutralisation de l'injection de formules tableur (CSV injection).
// Une valeur commençant par =, +, -, @, |, tabulation ou retour chariot est
// préfixée d'une apostrophe afin qu'Excel/LibreOffice ne l'interprète pas
// comme une formule. Pour que l'opération soit réversible sans perte, une
// valeur commençant déjà par une apostrophe est elle aussi préfixée ; l'import
// retire exactement une apostrophe dans ces deux cas.
//
// FIABILITÉ : le parseur suit la RFC 4180 (champs entre guillemets pouvant
// contenir séparateurs, sauts de ligne et guillemets doublés). Un guillemet au
// milieu d'un champ non guillemeté est un caractère ordinaire : il ne peut plus
// décaler les colonnes suivantes. Le BOM UTF-8 écrit par Excel est ignoré.

const FORMULA_START_RE = /^[=+\-@|\t\r]/;
const NEUTRALIZE_RE = /^[=+\-@|\t\r']/;

/**
 * Préfixe d'une apostrophe les valeurs qui seraient interprétées comme une formule
 * (et celles qui commencent déjà par une apostrophe, pour rester réversible)
 * @param {string} str
 * @returns {string}
 */
export function neutralizeCsvFormula(str) {
  const s = String(str ?? '');
  return NEUTRALIZE_RE.test(s) ? `'${s}` : s;
}

/**
 * Retire l'apostrophe de protection ajoutée à l'export (inverse exact de
 * neutralizeCsvFormula). Ne touche pas aux valeurs qui ne correspondent pas
 * au motif « ' + (caractère de formule | ') ».
 * @param {string} value
 * @returns {string}
 */
export function unescapeCsvFormula(value) {
  if (typeof value !== 'string' || value.length < 2) return value;
  if (value[0] === "'" && (FORMULA_START_RE.test(value.slice(1)) || value[1] === "'")) {
    return value.slice(1);
  }
  return value;
}

/**
 * Échappe un champ CSV :
 * - neutralise les formules tableur
 * - remplace optionnellement les sauts de ligne par des espaces (1 ligne = 1 secret)
 * - entoure de guillemets si nécessaire (ou toujours si alwaysQuote) et double les guillemets internes
 *
 * @param {*} field - Valeur à échapper (null/undefined → chaîne vide)
 * @param {Object} [options]
 * @param {string} [options.separator=';'] - Séparateur de colonnes utilisé
 * @param {boolean} [options.alwaysQuote=false] - Toujours entourer de guillemets
 * @param {boolean} [options.flattenNewlines=false] - Remplacer les sauts de ligne par des espaces
 * @returns {string}
 */
export function escapeCsvField(field, { separator = ';', alwaysQuote = false, flattenNewlines = false } = {}) {
  let str = String(field ?? '');
  if (flattenNewlines) {
    str = str.replace(/\r?\n/g, ' ').replace(/\r/g, ' ');
  }
  str = neutralizeCsvFormula(str);
  const needsQuote = alwaysQuote || str.includes(separator) || str.includes('"') || /[\r\n]/.test(str);
  return needsQuote ? `"${str.replace(/"/g, '""')}"` : str;
}

/**
 * Détecte le séparateur d'un en-tête CSV (le plus fréquent parmi ; , tab)
 * @param {string} headerLine
 * @returns {string}
 */
export function detectCsvSeparator(headerLine) {
  const line = String(headerLine ?? '');
  const candidates = [';', ',', '\t'];
  let best = ',';
  let bestCount = 0;
  for (const c of candidates) {
    const count = line.split(c).length - 1;
    if (count > bestCount) { best = c; bestCount = count; }
  }
  return best;
}

/**
 * Parse un document CSV (RFC 4180) en enregistrements indexés par en-tête.
 *
 * - BOM UTF-8 ignoré ; fins de ligne \n, \r\n et \r acceptées
 * - champs entre guillemets : peuvent contenir séparateur, sauts de ligne et "" (guillemet littéral)
 * - un guillemet au milieu d'un champ non guillemeté est un caractère ordinaire
 * - les valeurs ne sont PAS tronquées (les espaces d'un mot de passe sont conservés) ;
 *   les noms de colonnes sont normalisés (trim + minuscules)
 * - l'apostrophe de protection anti-formule est retirée de chaque valeur
 * - les lignes entièrement vides sont ignorées
 *
 * @param {string} content
 * @param {Object} [options]
 * @param {string} [options.separator] - Forcer le séparateur (sinon détection sur l'en-tête)
 * @returns {{ header: string[], rows: Array<Object>, separator: string }}
 *   Chaque ligne est un objet { <colonne>: valeur } ; `__extra` contient les valeurs
 *   excédentaires si une ligne a plus de champs que l'en-tête.
 */
export function parseCsv(content, { separator } = {}) {
  let text = String(content ?? '');
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);

  const firstBreak = text.search(/\r\n|\n|\r/);
  const headerLine = firstBreak === -1 ? text : text.slice(0, firstBreak);
  const sep = separator || detectCsvSeparator(headerLine);

  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let fieldStart = true;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"' && fieldStart) { inQuotes = true; fieldStart = false; continue; }
    if (c === sep) { row.push(field); field = ''; fieldStart = true; continue; }
    if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      fieldStart = true;
      continue;
    }
    field += c;
    fieldStart = false;
  }
  if (field !== '' || row.length > 0) { row.push(field); rows.push(row); }

  const nonEmpty = rows.filter(r => r.some(v => v.trim() !== ''));
  if (nonEmpty.length < 2) return { header: [], rows: [], separator: sep };

  const header = nonEmpty[0].map(h => h.trim().toLowerCase());
  const records = nonEmpty.slice(1).map(values => {
    const rec = {};
    header.forEach((h, idx) => { rec[h] = unescapeCsvFormula(values[idx] ?? ''); });
    Object.defineProperty(rec, '__extra', { value: values.length > header.length ? values.slice(header.length) : [], enumerable: false });
    return rec;
  });
  return { header, rows: records, separator: sep };
}
