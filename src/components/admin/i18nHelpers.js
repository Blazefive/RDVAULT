// ========================================
// I18N : utilitaires du panneau d'administration
// ========================================
// - richText : insère des éléments React (<code>, <strong>…) dans une traduction
// - tPlural  : choisit la variante singulier/pluriel d'une clé selon la langue
// - formatDateTime : date/heure au format de la langue de l'application
// - Ltr / ltrIsolate / richLtr / ltrWhenFilled : identifiants techniques isolés et lus de gauche
//   à droite (arabe)

import React from 'react';

/**
 * Identifiant technique (chemin de coffre, nom de policy, DN LDAP, hôte…) toujours lu de gauche à
 * droite et isolé du texte qui l'entoure : <bdi dir="ltr" class="bidi-ltr"> (AppStyles.css :
 * direction: ltr, unicode-bidi: isolate). Sans effet visible en LTR. En arabe, sans isolation,
 * l'algorithme bidi déplaçait la barre oblique (« Comptabilite/ » affiché « /Comptabilite »).
 */
export function Ltr({ children }) {
  return React.createElement('bdi', { dir: 'ltr', className: 'bidi-ltr' }, children);
}

/**
 * Même isolation pour un texte brut (contenu d'un <option>, qui n'accepte pas d'élément) :
 * caractères LRI (U+2066) … PDI (U+2069), invisibles.
 */
export const ltrIsolate = (text) => `\u2066${text}\u2069`;

/**
 * Isolat \u00ab sens du contenu \u00bb pour un texte brut : caract\u00e8res FSI (U+2068) \u2026 PDI (U+2069), invisibles.
 * Texte libre (nom d'entr\u00e9e, tag) : s\u00e9par\u00e9 du texte qui l'entoure, il garde son propre sens (arabe de
 * droite \u00e0 gauche, latin de gauche \u00e0 droite), comme dir="auto".
 */
export const autoIsolate = (text) => `\u2068${text}\u2069`;

/** true si l'interface est affich\u00e9e de droite \u00e0 gauche (<html dir="rtl">, pos\u00e9 par I18nProvider) */
export function isRtlDocument() {
  try {
    return typeof document !== 'undefined' && !!document.documentElement && document.documentElement.dir === 'rtl';
  } catch {
    return false;
  }
}

/**
 * Valeur interpol\u00e9e par t() dans un texte BRUT (toast) : isol\u00e9e seulement quand l'interface est en RTL.
 * En LTR, le texte reste identique (aucun caract\u00e8re invisible ajout\u00e9).
 * @param {*} value - Valeur ins\u00e9r\u00e9e dans la traduction
 * @param {'ltr'|'auto'} [mode='ltr'] - 'ltr' : identifiant technique (chemin, nom de coffre, de policy,
 *   cl\u00e9 TOTP), lu de gauche \u00e0 droite ; 'auto' : texte libre (nom d'entr\u00e9e), dans son propre sens
 */
export function isolateInRtl(value, mode = 'ltr') {
  if (value === null || value === undefined || value === '' || !isRtlDocument()) return value;
  return mode === 'auto' ? autoIsolate(value) : ltrIsolate(value);
}

/**
 * Attribut dir d'un champ de saisie technique dont le texte indicatif est TRADUIT : ltr dès que le
 * champ contient une valeur (nom de policy, hôte…), sens de la langue tant qu'il est vide. Forcé en
 * ltr, un texte indicatif arabe mêlé de chiffres (« hachi أو 192.168.1.x ») s'affichait désordonné
 * (« hachi 192.168.1 أو.x »). Les champs à texte indicatif technique littéral restent en dir="ltr".
 */
export const ltrWhenFilled = (value) => (value ? 'ltr' : undefined);

/**
 * richText pour un modèle contenant un identifiant technique {{nom}} : la valeur est isolée en ltr
 * et la barre oblique qui suit éventuellement le marqueur (« Coffre: {{path}}/ ») est rattachée à
 * l'isolat, sinon elle resterait dans le texte arabe et changerait de côté.
 * Le texte rendu est identique à t(clé, { nom: valeur }).
 */
export function richLtr(template, name, value) {
  const marker = `{{${name}}}`;
  const tpl = String(template);
  const withSlash = tpl.includes(`${marker}/`);
  return richText(withSlash ? tpl.split(`${marker}/`).join(marker) : tpl, {
    [name]: React.createElement(Ltr, null, withSlash ? `${value}/` : value),
  });
}

/**
 * Rend une traduction contenant des marqueurs {{nom}} en remplaçant chaque marqueur
 * par l'élément React correspondant (t() n'interpole que du texte).
 * La chaîne doit venir de t(clé) appelé SANS variables : les marqueurs sont alors conservés.
 * Un marqueur sans élément fourni est laissé tel quel.
 */
export function richText(template, elements = {}) {
  return String(template).split(/\{\{(\w+)\}\}/).map((part, i) => {
    if (i % 2 === 0) return part; // texte entre deux marqueurs
    return Object.prototype.hasOwnProperty.call(elements, part)
      ? React.createElement(React.Fragment, { key: i }, elements[part])
      : `{{${part}}}`;
  });
}

/**
 * Modèle traduit (t(clé) appelé SANS variables) rendu avec chaque valeur ISOLÉE dans un <bdi> : le texte
 * rendu est identique à t(clé, values), sans caractère ajouté. Les variables nommées dans `ltrNames`
 * (identifiants techniques : chemin, nom de coffre, de policy) sont lues de gauche à droite (<Ltr>, barre
 * oblique qui suit rattachée comme dans richLtr) ; les autres (texte libre) gardent leur propre sens
 * (<bdi>, sens automatique). Variable absente (null / undefined) : marqueur conservé, comme t().
 * @param {string} template
 * @param {Object} [values]
 * @param {string[]} [ltrNames]
 * @returns {Array} Nœuds React
 */
export function richIsolated(template, values = {}, ltrNames = []) {
  const pieces = String(template).split(/\{\{(\w+)\}\}/);
  const ltr = Array.isArray(ltrNames) ? ltrNames : [];
  const nodes = [];
  for (let i = 0; i < pieces.length; i += 1) {
    if (i % 2 === 0) {
      if (pieces[i]) nodes.push(pieces[i]);
      continue;
    }
    const name = pieces[i];
    const value = values && Object.prototype.hasOwnProperty.call(values, name) ? values[name] : undefined;
    if (value === null || value === undefined) {
      nodes.push(`{{${name}}}`);
    } else if (ltr.includes(name)) {
      const next = pieces[i + 1] || '';
      const slash = next.startsWith('/') ? '/' : '';
      if (slash) pieces[i + 1] = next.slice(1);
      nodes.push(React.createElement(Ltr, { key: `v${i}` }, `${value}${slash}`));
    } else {
      nodes.push(React.createElement('bdi', { key: `v${i}` }, String(value)));
    }
  }
  return nodes;
}

// Paires de guillemets entourant une valeur dans les traductions (« », " ", “ ”, „ “, 「 」, 『 』) ;
// \s couvre aussi les espaces insécables (U+00A0, U+202F) placées dans les chevrons français
const QUOTED = /(«\s*)([^«»]+?)(\s*»)|(")([^"]+)(")|(“)([^“”]+)(”)|(„)([^„“]+)(“)|(「)([^「」]+)(」)|(『)([^『』]+)(』)/g;

/**
 * Message DÉJÀ interpolé (texte brut) : chaque passage entre guillemets est isolé dans son propre sens
 * (<bdi>), sans changer le texte rendu. Les valeurs que les traductions placent entre guillemets (nom de
 * coffre, de policy, d'entrée, chemin) ne se mêlent plus à la phrase en arabe (barre oblique ou guillemet
 * déplacés). Sans guillemets : texte renvoyé tel quel.
 * @param {string} text
 * @returns {string|Array}
 */
export function isolateQuoted(text) {
  const s = String(text);
  const nodes = [];
  let last = 0;
  let match;
  QUOTED.lastIndex = 0;
  while ((match = QUOTED.exec(s)) !== null) {
    // Groupes de la paire trouvée : ouverture, contenu, fermeture
    const groups = match.slice(1).filter(g => g !== undefined);
    const [open, inner, close] = groups;
    nodes.push(s.slice(last, match.index) + open);
    nodes.push(React.createElement('bdi', { key: `q${match.index}` }, inner));
    last = match.index + match[0].length;
    nodes.push(close);
  }
  if (!nodes.length) return text;
  nodes.push(s.slice(last));
  return nodes.filter(n => n !== '');
}

/**
 * Traduit la variante « <clé>One » ou « <clé>Many » selon les règles de pluriel
 * de la langue (Intl.PluralRules : en français 0 et 1 sont au singulier).
 * Repli si la langue est inconnue : pluriel au-delà de 1.
 */
export function tPlural(t, lang, baseKey, count, vars = {}) {
  let one = count <= 1;
  try {
    one = new Intl.PluralRules(lang).select(count) === 'one';
  } catch { /* code de langue invalide : règle par défaut */ }
  return t(`${baseKey}${one ? 'One' : 'Many'}`, { count, ...vars });
}

/**
 * Date/heure lisible dans la langue de l'application (au lieu de 'fr-FR' en dur).
 * Repli sur la locale du système si le code de langue est invalide.
 */
export function formatDateTime(value, lang) {
  const date = new Date(value);
  try {
    return date.toLocaleString(lang);
  } catch {
    return date.toLocaleString();
  }
}
