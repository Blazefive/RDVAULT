// src/PasswordGeneratorModal.jsx
// Générateur de mot de passe (ouvert depuis la fiche d'une entrée, par-dessus EditSecretModal).
//
// Accessibilité (hook useDialogA11y du squelette commun Modal) : role="dialog" + aria-modal +
// aria-labelledby (titre), focus initial, piège de focus, retour du focus au bouton
// « Générer », Échap réservé à la modale du dessus (la fiche reste ouverte). Fermeture sur le
// fond seulement si mousedown ET mouseup y tombent : une sélection du mot de passe généré qui
// déborde du panneau ne ferme plus le générateur.
import React, { useState, useEffect, useCallback, useId, useRef, useMemo } from 'react';
import { useTranslation } from './i18n';
import { copySecureWithAutoClear } from './utils/clipboard';
import { useDialogA11y } from './components/common/Modal';
import { getPasswordStrength, STRENGTH_LABEL_KEYS } from './utils/passwordStrength';

// Tolérance de déplacement (px) d'un clic sur le fond (même valeur que components/common/Modal)
const CLICK_TOLERANCE_PX = 5;

/** Retourne un entier cryptographiquement sûr dans [0, max) sans biais modulo */
export function secureRandomInt(max) {
  if (max <= 0) return 0;
  // Au-delà de 2^32 (ou pour une borne non entière), la limite de rejet vaudrait 0 ou ne
  // serait pas un multiple entier de max : boucle infinie ou résultat non entier. Refus explicite.
  if (!Number.isInteger(max) || max > 0x100000000) {
    throw new RangeError('secureRandomInt : borne entière dans [1, 2^32] attendue');
  }
  // SÉCURITÉ: Rejection sampling pour éliminer le biais modulo
  const limit = Math.floor(0x100000000 / max) * max;
  const array = new Uint32Array(1);
  let value;
  do {
    crypto.getRandomValues(array);
    value = array[0];
  } while (value >= limit);
  return value % max;
}

/** Mélange Fisher-Yates avec crypto.getRandomValues */
function secureShuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// ---------- Jeu de caractères et plan de génération (logique pure, testée) ----------
// GENERATOR-24 : un jeu de caractères UNIQUE, dédoublonné et découpé en points de code (un emoji
// est un seul élément, jamais deux surrogates tirés séparément). Les caractères personnalisés
// déjà présents dans une classe cochée ne pèsent plus double. Le tirage, le mélange et
// l'entropie affichée reposent tous sur ce même jeu.
// GENERATOR-25 : minimums bornés par la longueur, génération en O(longueur) (plus de re-scan
// de la chaîne à chaque caractère ajouté) et contraintes impossibles signalées au lieu d'être
// tronquées en silence après le mélange.

export const MAX_PASSWORD_LENGTH = 256;
const UPPER_CASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER_CASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SPECIAL = '!@#$%&*+=?^~,';
const BRACKETS = '[]{}()<>';
const LATIN1_SOURCE = 'ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽž';
// Seuls les caractères stables en NFKC sont gardés : « ŉ », « Ĳ », « ĳ », « Ŀ », « ŀ » sont des
// caractères de compatibilité qu'un site normalisant la saisie (NFKC, SASLprep) transformerait
// en deux caractères, rendant le mot de passe enregistré différent de celui saisi ailleurs.
const LATIN1 = Array.from(LATIN1_SOURCE).filter(c => c.normalize('NFKC') === c).join('');
const AMBIGUOUS = 'lI1O0';
// Caractères personnalisés refusés : contrôle, format (invisibles, bidi), surrogates isolés,
// séparateurs de ligne et de paragraphe
const REJECTED_CUSTOM_CHAR = /^[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]$/u;
// Marques combinantes isolées (accents combinants, sélecteurs de variante U+FE0F...) : seules,
// elles sont invisibles ou s'accrochent au caractère voisin. Expression construite à
// l'exécution : un littéral \p{M} serait développé par la compilation en ~3 Ko de plages.
const COMBINING_MARK = (() => {
  try { return new RegExp('^\\p{M}$', 'u'); } catch { return /^[̀-ͯ᪰-᫿᷀-᷿⃐-⃿︀-️︠-︯]$/; }
})();

/** Options par défaut du générateur (état initial de la modale) */
export const DEFAULT_GENERATOR_OPTIONS = Object.freeze({
  length: 20,
  includeUpperCase: true,
  includeLowerCase: true,
  includeDigits: true,
  includeSpecial: true,
  includeBrackets: false,
  includeMinus: true,
  includeUnderline: true,
  includeLatin1: false,
  customChars: '',
  excludeAmbiguous: false,
  ensureOneFromEach: true,
  minUpperCase: 0,
  minLowerCase: 0,
  minDigits: 0,
  minSpecial: 0,
});

/** Entier borné dans [lo, hi] (lo si la valeur n'est pas un nombre) */
function clampInt(value, lo, hi) {
  const n = Math.floor(Number(value));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : lo;
}

/**
 * Construit le plan de génération à partir des options.
 * @returns {{ length: number, pool: string[], categories: Array<{ id: string, chars: string[], min: number }>,
 *   required: number, impossible: boolean, empty: boolean, entropy: number }}
 *   pool : jeu complet, un point de code par élément, sans doublon ;
 *   categories : catégories dont des caractères sont imposés (min > 0), disjointes ;
 *   required : nombre de caractères imposés ; impossible : required > length ;
 *   empty : jeu vide ; entropy : bits du tirage (0 si impossible ou jeu vide).
 *   Les minimums sont bornés par la longueur et ignorés pour une classe non cochée.
 */
export function buildGeneratorPlan(options) {
  const o = { ...DEFAULT_GENERATOR_OPTIONS, ...options };
  const length = clampInt(o.length, 1, MAX_PASSWORD_LENGTH);
  const unambiguous = (str) => (o.excludeAmbiguous ? Array.from(str).filter(c => !AMBIGUOUS.includes(c)).join('') : str);
  const atLeastOne = o.ensureOneFromEach ? 1 : 0;
  const forcedMin = (min) => Math.max(clampInt(min, 0, length), atLeastOne);
  const classes = [
    { id: 'upper', on: o.includeUpperCase, chars: unambiguous(UPPER_CASE), min: forcedMin(o.minUpperCase) },
    { id: 'lower', on: o.includeLowerCase, chars: unambiguous(LOWER_CASE), min: forcedMin(o.minLowerCase) },
    { id: 'digits', on: o.includeDigits, chars: unambiguous(DIGITS), min: forcedMin(o.minDigits) },
    { id: 'special', on: o.includeSpecial, chars: SPECIAL, min: forcedMin(o.minSpecial) },
    { id: 'brackets', on: o.includeBrackets, chars: BRACKETS, min: 0 },
    { id: 'minus', on: o.includeMinus, chars: '-', min: 0 },
    { id: 'underline', on: o.includeUnderline, chars: '_', min: 0 },
    { id: 'latin1', on: o.includeLatin1, chars: LATIN1, min: 0 },
    // Caractères personnalisés : au moins un imposé (comportement historique). Forme NFC :
    // « e » + accent combinant (saisie décomposée) devient « é », un seul caractère
    { id: 'custom', on: true, chars: typeof o.customChars === 'string' ? o.customChars.normalize('NFC') : '', min: 1, custom: true },
  ];

  const pool = [];
  const seen = new Set();
  const categories = [];
  for (const cls of classes) {
    if (!cls.on) continue;
    const own = [];
    for (const ch of cls.chars) { // for...of : découpage par point de code
      if (cls.custom && (REJECTED_CUSTOM_CHAR.test(ch) || COMBINING_MARK.test(ch))) continue;
      if (seen.has(ch)) continue; // doublon, ou déjà fourni par une classe cochée
      seen.add(ch);
      pool.push(ch);
      own.push(ch);
    }
    if (cls.min > 0 && own.length > 0) categories.push({ id: cls.id, chars: own, min: cls.min });
  }

  const required = categories.reduce((sum, c) => sum + c.min, 0);
  const impossible = required > length;
  let entropy = 0;
  if (!impossible && pool.length > 0) {
    // Chaque position imposée est tirée dans sa catégorie, les autres dans le jeu complet
    // (estimation prudente : le gain apporté par le mélange des positions est ignoré)
    const positionsBySize = new Map();
    const addPositions = (size, count) => positionsBySize.set(size, (positionsBySize.get(size) || 0) + count);
    for (const c of categories) addPositions(c.chars.length, c.min);
    addPositions(pool.length, length - required);
    let bits = 0;
    for (const [size, count] of positionsBySize) bits += count * Math.log2(size);
    entropy = Math.floor(bits);
  }
  // empty : aucun caractère disponible (aucune classe cochée, pas de caractère personnalisé valide)
  return { length, pool, categories, required, impossible, empty: pool.length === 0, entropy };
}

/**
 * Tire un mot de passe selon le plan (chaîne vide si le plan est impossible ou le jeu vide).
 * Complexité linéaire en la longueur ; la longueur est comptée en points de code.
 */
export function generatePasswordFromPlan(plan) {
  if (!plan || plan.impossible || plan.pool.length === 0) return '';
  const chars = [];
  for (const cat of plan.categories) {
    for (let k = 0; k < cat.min; k++) chars.push(cat.chars[secureRandomInt(cat.chars.length)]);
  }
  while (chars.length < plan.length) chars.push(plan.pool[secureRandomInt(plan.pool.length)]);
  // Mélange du tableau de points de code (jamais de split('') qui couperait un emoji)
  return secureShuffle(chars).join('');
}

export default function PasswordGeneratorModal({ onClose, onAccept }) {
  const { t } = useTranslation();
  const panelRef = useRef(null);
  const overlayDownRef = useRef(null);
  const titleId = useId();
  // Onglets
  const [activeTab, setActiveTab] = useState('settings');

  // Options Character Set
  const [length, setLength] = useState(DEFAULT_GENERATOR_OPTIONS.length);
  const [includeUpperCase, setIncludeUpperCase] = useState(DEFAULT_GENERATOR_OPTIONS.includeUpperCase);
  const [includeLowerCase, setIncludeLowerCase] = useState(DEFAULT_GENERATOR_OPTIONS.includeLowerCase);
  const [includeDigits, setIncludeDigits] = useState(DEFAULT_GENERATOR_OPTIONS.includeDigits);
  const [includeSpecial, setIncludeSpecial] = useState(DEFAULT_GENERATOR_OPTIONS.includeSpecial);
  const [includeBrackets, setIncludeBrackets] = useState(DEFAULT_GENERATOR_OPTIONS.includeBrackets);
  const [includeMinus, setIncludeMinus] = useState(DEFAULT_GENERATOR_OPTIONS.includeMinus);
  const [includeUnderline, setIncludeUnderline] = useState(DEFAULT_GENERATOR_OPTIONS.includeUnderline);
  const [includeLatin1, setIncludeLatin1] = useState(DEFAULT_GENERATOR_OPTIONS.includeLatin1);
  const [customChars, setCustomChars] = useState(DEFAULT_GENERATOR_OPTIONS.customChars);

  // Options Advanced
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(DEFAULT_GENERATOR_OPTIONS.excludeAmbiguous);
  const [ensureOneFromEach, setEnsureOneFromEach] = useState(DEFAULT_GENERATOR_OPTIONS.ensureOneFromEach);
  const [minUpperCase, setMinUpperCase] = useState(DEFAULT_GENERATOR_OPTIONS.minUpperCase);
  const [minLowerCase, setMinLowerCase] = useState(DEFAULT_GENERATOR_OPTIONS.minLowerCase);
  const [minDigits, setMinDigits] = useState(DEFAULT_GENERATOR_OPTIONS.minDigits);
  const [minSpecial, setMinSpecial] = useState(DEFAULT_GENERATOR_OPTIONS.minSpecial);

  // Mot de passe généré
  const [generatedPassword, setGeneratedPassword] = useState('');

  // Plan de génération : jeu de caractères unique, catégories imposées, entropie (GENERATOR-24/25)
  const plan = useMemo(() => buildGeneratorPlan({
    length, includeUpperCase, includeLowerCase, includeDigits,
    includeSpecial, includeBrackets, includeMinus, includeUnderline, includeLatin1,
    customChars, excludeAmbiguous,
    ensureOneFromEach, minUpperCase, minLowerCase, minDigits, minSpecial,
  }), [
    length, includeUpperCase, includeLowerCase, includeDigits,
    includeSpecial, includeBrackets, includeMinus, includeUnderline, includeLatin1,
    customChars, excludeAmbiguous,
    ensureOneFromEach, minUpperCase, minLowerCase, minDigits, minSpecial,
  ]);

  // Générer au chargement et à chaque changement d'option (chaîne vide si contraintes impossibles)
  useEffect(() => {
    setGeneratedPassword(generatePasswordFromPlan(plan));
  }, [plan]);

  const regenerate = () => setGeneratedPassword(generatePasswordFromPlan(plan));

  // GENERATOR-25 : longueur bornée. Les minimums saisis ne sont PAS réécrits ici : chaque
  // frappe produit une longueur intermédiaire (« 3 » avant « 32 ») qui les aurait ramenés
  // définitivement à 3. Ils sont bornés à l'affichage et dans le plan (effectiveMin).
  const handleLengthChange = (e) => {
    setLength(Math.min(MAX_PASSWORD_LENGTH, Math.max(1, parseInt(e.target.value, 10) || 1)));
  };
  // GENERATOR-25 : un minimum ne peut dépasser la longueur (« 100000 » gelait l'interface)
  const minChangeHandler = (setMin) => (e) => {
    setMin(Math.min(length, Math.max(0, parseInt(e.target.value, 10) || 0)));
  };
  // Minimum réellement appliqué : 0 pour une classe non cochée (champ désactivé), borné par la longueur
  const effectiveMin = (enabled, min) => (enabled ? Math.min(min, length) : 0);

  // Focus initial, piège de focus, Échap (modale du dessus uniquement), retour du focus
  useDialogA11y(panelRef, { onEscape: onClose });

  // BUG CORRIGÉ : fermeture au « click » sur le fond, déclenché aussi par une sélection de texte
  // commencée dans le panneau et relâchée sur le fond. Il faut désormais mousedown ET mouseup
  // sur le fond, à moins de 5 px l'un de l'autre.
  const handleOverlayMouseDown = (e) => {
    overlayDownRef.current = e.target === e.currentTarget ? { x: e.clientX, y: e.clientY } : null;
  };
  const handleOverlayMouseUp = (e) => {
    const start = overlayDownRef.current;
    overlayDownRef.current = null;
    if (!start || e.target !== e.currentTarget) return;
    if (Math.abs(e.clientX - start.x) < CLICK_TOLERANCE_PX && Math.abs(e.clientY - start.y) < CLICK_TOLERANCE_PX) onClose();
  };

  const [copied, setCopied] = useState(false);
  const copiedTimerRef = useRef(null);
  // Minuterie « Copié » annulée à la fermeture (pas de mise à jour d'état après démontage)
  useEffect(() => () => clearTimeout(copiedTimerRef.current), []);

  // SÉCURITÉ : copie via le presse-papiers sécurisé avec auto-effacement (12 s,
  // durée commune à toute l'application) — fallback navigateur inclus.
  const copyToClipboard = useCallback((text) => {
    copySecureWithAutoClear(text).catch(() => {});
    setCopied(true);
    clearTimeout(copiedTimerRef.current);
    copiedTimerRef.current = setTimeout(() => setCopied(false), 2000);
  }, []);

  // Force : entropie du tirage, calculée sur le même jeu de caractères que la génération ;
  // paliers, couleurs et libellés communs avec la fiche et l'audit (getPasswordStrength)
  const entropy = generatedPassword ? plan.entropy : 0;
  const strengthInfo = getPasswordStrength(entropy);
  const strength = t(STRENGTH_LABEL_KEYS[strengthInfo.level]);
  const strengthColor = strengthInfo.color;

  return (
    <div className="modal-overlay" onMouseDown={handleOverlayMouseDown} onMouseUp={handleOverlayMouseUp}>
      <div
        ref={panelRef}
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '560px' }}
      >
        {/* Header */}
        <div className="modal-header">
          <h2 id={titleId}>{t('passwordGenerator.title')}</h2>
        </div>

        <div style={{ padding: 'var(--sp-6)', borderBottom: '2px solid var(--border)' }}>
          {/* Mot de passe généré */}
          <div
            onClick={() => { if (generatedPassword) copyToClipboard(generatedPassword); }}
            style={{
              background: 'var(--bg-app)',
              border: '2px solid var(--accent)',
              borderRadius: 'var(--radius-lg)',
              padding: 'var(--sp-4)',
              fontFamily: 'var(--font-mono)',
              fontSize: 'var(--text-lg)',
              fontWeight: 'var(--weight-bold)',
              color: 'var(--text-primary)',
              marginBottom: 'var(--sp-4)',
              wordBreak: 'break-all',
              userSelect: 'all',
              cursor: 'pointer'
            }}
          >
            {generatedPassword || t('passwordGenerator.none')}
          </div>
          {/* GENERATOR-25 : contraintes impossibles ou jeu de caractères vide signalés
              (visible quel que soit l'onglet) */}
          {(plan.impossible || plan.empty) && (
            <div
              role="alert"
              style={{
                color: 'var(--error)',
                fontSize: 'var(--text-sm)',
                fontWeight: 'var(--weight-medium)',
                marginBottom: 'var(--sp-3)'
              }}
            >
              {plan.empty
                ? t('passwordGenerator.noCharacterSet')
                : t('passwordGenerator.constraintsImpossible', { required: plan.required, length: plan.length })}
            </div>
          )}
          {copied && (
            <div style={{
              textAlign: 'center',
              color: 'var(--success)',
              fontSize: 'var(--text-sm)',
              fontWeight: 'var(--weight-medium)',
              marginBottom: 'var(--sp-2)',
              transition: 'opacity 0.3s ease'
            }}>
              {t('passwordGenerator.copied')}
            </div>
          )}

          {/* Indicateur de force */}
          <div>
            <div className="clipboard-progress">
              <div
                className="clipboard-progress-bar"
                style={{
                  width: `${strengthInfo.percentage}%`,
                  background: strengthColor,
                  transition: 'width 0.3s, background 0.3s'
                }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
              <span>{t('passwordGenerator.strength')} <strong style={{ color: strengthColor }}>{strength}</strong></span>
              <span>{t('passwordGenerator.entropy')} <strong>{entropy} {t('passwordGenerator.bits')}</strong></span>
            </div>
          </div>
        </div>

        {/* Body scrollable */}
        <div className="modal-body">
          {/* Onglets */}
          <div style={{ display: 'flex', gap: 'var(--sp-2)', borderBottom: '2px solid var(--border)', marginBottom: 'var(--sp-6)' }}>
            <button
              onClick={() => setActiveTab('settings')}
              className={activeTab === 'settings' ? 'admin-tab active' : 'admin-tab'}
            >
              {t('passwordGenerator.tabSettings')}
            </button>
            <button
              onClick={() => setActiveTab('advanced')}
              className={activeTab === 'advanced' ? 'admin-tab active' : 'admin-tab'}
            >
              {t('passwordGenerator.tabAdvanced')}
            </button>
          </div>

        {/* Contenu Settings */}
        {activeTab === 'settings' && (
          <div style={{ padding: 'var(--sp-4)', background: 'var(--bg-app)', borderRadius: 'var(--radius-lg)', marginBottom: 'var(--sp-6)' }}>
            <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)' }}>{t('passwordGenerator.options')}</div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
              <label style={{ fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-bold)' }}>{t('passwordGenerator.lengthLabel')}</label>
              <input
                type="number"
                min="1"
                max={MAX_PASSWORD_LENGTH}
                value={length}
                onChange={handleLengthChange}
                className="modal-input"
                style={{ width: '100px', marginBottom: 0 }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 'var(--sp-3)' }}>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeUpperCase}
                  onChange={(e) => setIncludeUpperCase(e.target.checked)}
                />
                <span>{t('passwordGenerator.uppercase')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeLowerCase}
                  onChange={(e) => setIncludeLowerCase(e.target.checked)}
                />
                <span>{t('passwordGenerator.lowercase')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeDigits}
                  onChange={(e) => setIncludeDigits(e.target.checked)}
                />
                <span>{t('passwordGenerator.numbers')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeSpecial}
                  onChange={(e) => setIncludeSpecial(e.target.checked)}
                />
                <span>{t('passwordGenerator.symbols')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeBrackets}
                  onChange={(e) => setIncludeBrackets(e.target.checked)}
                />
                <span>{t('passwordGenerator.brackets')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeMinus}
                  onChange={(e) => setIncludeMinus(e.target.checked)}
                />
                <span>{t('passwordGenerator.minus')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeUnderline}
                  onChange={(e) => setIncludeUnderline(e.target.checked)}
                />
                <span>{t('passwordGenerator.underline')}</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeLatin1}
                  onChange={(e) => setIncludeLatin1(e.target.checked)}
                />
                <span>{t('passwordGenerator.latin1')}</span>
              </label>
            </div>

            <div style={{ marginTop: 'var(--sp-4)' }}>
              <label className="modal-label">
                {t('passwordGenerator.customChars')}
              </label>
              <input
                type="text"
                value={customChars}
                onChange={(e) => setCustomChars(e.target.value)}
                placeholder={t('passwordGenerator.customCharsPlaceholder')}
                className="modal-input"
              />
            </div>
          </div>
        )}

        {/* Contenu Advanced */}
        {activeTab === 'advanced' && (
          <div style={{ padding: 'var(--sp-4)', background: 'var(--bg-app)', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)' }}>{t('passwordGenerator.advancedOptions')}</div>

            <label className="checkbox-label" style={{ marginBottom: 'var(--sp-3)' }}>
              <input
                type="checkbox"
                checked={excludeAmbiguous}
                onChange={(e) => setExcludeAmbiguous(e.target.checked)}
              />
              <span>{t('passwordGenerator.excludeAmbiguous')}</span>
            </label>

            <label className="checkbox-label" style={{ marginBottom: 'var(--sp-5)' }}>
              <input
                type="checkbox"
                checked={ensureOneFromEach}
                onChange={(e) => setEnsureOneFromEach(e.target.checked)}
              />
              <span>{t('passwordGenerator.ensureOneFromEach')}</span>
            </label>

            <div>
              <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-3)', fontSize: 'var(--text-sm)' }}>{t('passwordGenerator.minRequirements')}</div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>{t('passwordGenerator.minUppercase')}</label>
                  <input
                    type="number"
                    min="0"
                    max={length}
                    value={effectiveMin(includeUpperCase, minUpperCase)}
                    onChange={minChangeHandler(setMinUpperCase)}
                    disabled={!includeUpperCase}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>{t('passwordGenerator.minLowercase')}</label>
                  <input
                    type="number"
                    min="0"
                    max={length}
                    value={effectiveMin(includeLowerCase, minLowerCase)}
                    onChange={minChangeHandler(setMinLowerCase)}
                    disabled={!includeLowerCase}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>{t('passwordGenerator.minDigits')}</label>
                  <input
                    type="number"
                    min="0"
                    max={length}
                    value={effectiveMin(includeDigits, minDigits)}
                    onChange={minChangeHandler(setMinDigits)}
                    disabled={!includeDigits}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>{t('passwordGenerator.minSpecial')}</label>
                  <input
                    type="number"
                    min="0"
                    max={length}
                    value={effectiveMin(includeSpecial, minSpecial)}
                    onChange={minChangeHandler(setMinSpecial)}
                    disabled={!includeSpecial}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>
              </div>
            </div>
          </div>
        )}
        </div>

        {/* Actions */}
        <div className="modal-footer" style={{ justifyContent: 'space-between' }}>
          <button
            onClick={regenerate}
            className="btn btn-secondary"
            type="button"
          >
            {t('passwordGenerator.regenerate')}
          </button>
          <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
            <button
              onClick={onClose}
              className="btn btn-secondary"
              type="button"
            >
              {t('common.cancel')}
            </button>
            <button
              onClick={() => { if (generatedPassword) onAccept(generatedPassword); }}
              className="btn btn-primary"
              type="button"
              disabled={!generatedPassword}
            >
              {t('passwordGenerator.accept')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
