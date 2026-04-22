// src/PasswordGeneratorModal.jsx
import React, { useState, useEffect, useCallback } from 'react';

/** Retourne un entier cryptographiquement sûr dans [0, max) sans biais modulo */
function secureRandomInt(max) {
  if (max <= 0) return 0;
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

export default function PasswordGeneratorModal({ onClose, onAccept }) {
  // Onglets
  const [activeTab, setActiveTab] = useState('settings');

  // Options Character Set
  const [length, setLength] = useState(20);
  const [includeUpperCase, setIncludeUpperCase] = useState(true);
  const [includeLowerCase, setIncludeLowerCase] = useState(true);
  const [includeDigits, setIncludeDigits] = useState(true);
  const [includeSpecial, setIncludeSpecial] = useState(true);
  const [includeBrackets, setIncludeBrackets] = useState(false);
  const [includeMinus, setIncludeMinus] = useState(true);
  const [includeUnderline, setIncludeUnderline] = useState(true);
  const [includeLatin1, setIncludeLatin1] = useState(false);
  const [customChars, setCustomChars] = useState('');

  // Options Advanced
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);
  const [ensureOneFromEach, setEnsureOneFromEach] = useState(true);
  const [minUpperCase, setMinUpperCase] = useState(0);
  const [minLowerCase, setMinLowerCase] = useState(0);
  const [minDigits, setMinDigits] = useState(0);
  const [minSpecial, setMinSpecial] = useState(0);

  // Mot de passe généré
  const [generatedPassword, setGeneratedPassword] = useState('');

  // Générer au chargement et à chaque changement
  useEffect(() => {
    generatePassword();
  }, [
    length, includeUpperCase, includeLowerCase, includeDigits,
    includeSpecial, includeBrackets, includeMinus, includeUnderline, includeLatin1,
    customChars, excludeAmbiguous,
    ensureOneFromEach, minUpperCase, minLowerCase, minDigits, minSpecial
  ]);

  // Fermer sur ESC
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  // Calculer l'entropie (basé sur la taille réelle du pool de caractères)
  const calculateEntropy = (password) => {
    if (!password) return 0;

    const ambiguous = 'lI1O0';
    const countFiltered = (str) => excludeAmbiguous
      ? str.split('').filter(c => !ambiguous.includes(c)).length
      : str.length;

    let poolSize = 0;
    if (includeUpperCase) poolSize += countFiltered('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (includeLowerCase) poolSize += countFiltered('abcdefghijklmnopqrstuvwxyz');
    if (includeDigits) poolSize += countFiltered('0123456789');
    if (includeSpecial) poolSize += '!@#$%&*+=?^~,'.length; // 13 chars
    if (includeBrackets) poolSize += '[]{}()<>'.length; // 8 chars
    if (includeMinus) poolSize += 1;
    if (includeUnderline) poolSize += 1;
    if (includeLatin1) poolSize += 'ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽž'.length;
    if (customChars) poolSize += new Set(customChars).size; // dédupliquer

    if (poolSize === 0) return 0;
    return Math.floor(password.length * Math.log2(poolSize));
  };

  // Générer mot de passe
  const generatePassword = () => {
    const pwd = generateFromCharset();
    setGeneratedPassword(pwd);
  };

  const generateFromCharset = () => {
    let chars = '';
    const ambiguous = 'lI1O0';

    const upperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowerCase = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const special = '!@#$%&*+=?^~,';
    const brackets = '[]{}()<>';
    const minus = '-';
    const underline = '_';
    const latin1 = 'ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽž';

    const categories = [];

    if (includeUpperCase) {
      const filtered = excludeAmbiguous ? upperCase.split('').filter(c => !ambiguous.includes(c)).join('') : upperCase;
      chars += filtered;
      categories.push({ chars: filtered, min: minUpperCase });
    }
    if (includeLowerCase) {
      const filtered = excludeAmbiguous ? lowerCase.split('').filter(c => !ambiguous.includes(c)).join('') : lowerCase;
      chars += filtered;
      categories.push({ chars: filtered, min: minLowerCase });
    }
    if (includeDigits) {
      const filtered = excludeAmbiguous ? digits.split('').filter(c => !ambiguous.includes(c)).join('') : digits;
      chars += filtered;
      categories.push({ chars: filtered, min: minDigits });
    }
    if (includeSpecial) {
      chars += special;
      categories.push({ chars: special, min: minSpecial });
    }
    if (includeBrackets) chars += brackets;
    if (includeMinus) chars += minus;
    if (includeUnderline) chars += underline;
    if (includeLatin1) chars += latin1;
    if (customChars) {
      chars += customChars;
      categories.push({ chars: customChars, min: 1 }); // Forcer au moins 1 caractère personnalisé
    }

    if (chars.length === 0) return '';

    let result = '';

    // Si ensureOneFromEach, on force au moins un caractère de chaque catégorie
    if (ensureOneFromEach) {
      for (const cat of categories) {
        if (cat.chars.length > 0) {
          result += cat.chars[secureRandomInt(cat.chars.length)];
        }
      }
    }

    // Respecter les minimums
    for (const cat of categories) {
      while (result.split('').filter(c => cat.chars.includes(c)).length < cat.min) {
        result += cat.chars[secureRandomInt(cat.chars.length)];
      }
    }

    // Remplir le reste
    while (result.length < length) {
      result += chars[secureRandomInt(chars.length)];
    }

    // Mélanger (Fisher-Yates cryptographique)
    return secureShuffle(result.split('')).join('').substring(0, length);
  };

  const [copied, setCopied] = useState(false);

  // Copier dans le presse-papiers via Electron (auto-clear) ou fallback navigateur
  const copyToClipboard = useCallback((text) => {
    if (window.electronClipboard?.copySecure) {
      window.electronClipboard.copySecure(text, 30000);
    } else {
      navigator.clipboard.writeText(text).catch(() => {});
      // SÉCURITÉ: Auto-clear du fallback après 30s
      setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, 30000);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);

  // Calculer la force
  const entropy = calculateEntropy(generatedPassword);
  const strength = entropy < 50 ? 'Faible' : entropy < 70 ? 'Moyenne' : entropy < 90 ? 'Forte' : 'Très forte';
  const strengthColor = entropy < 50 ? 'var(--error)' : entropy < 70 ? 'var(--warning)' : entropy < 90 ? 'var(--success)' : 'var(--info)';

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '560px' }}
      >
        {/* Header */}
        <div className="modal-header">
          <h2>Générateur de mots de passe</h2>
        </div>

        <div style={{ padding: 'var(--sp-6)', borderBottom: '2px solid var(--border)' }}>
          {/* Mot de passe généré */}
          <div
            onClick={() => copyToClipboard(generatedPassword)}
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
            {generatedPassword || '(aucun)'}
          </div>
          {copied && (
            <div style={{
              textAlign: 'center',
              color: 'var(--success)',
              fontSize: 'var(--text-sm)',
              fontWeight: 'var(--weight-medium)',
              marginBottom: 'var(--sp-2)',
              transition: 'opacity 0.3s ease'
            }}>
              Copié dans le presse-papier !
            </div>
          )}

          {/* Indicateur de force */}
          <div>
            <div className="clipboard-progress">
              <div
                className="clipboard-progress-bar"
                style={{
                  width: `${Math.min(100, (entropy / 120) * 100)}%`,
                  background: strengthColor,
                  transition: 'width 0.3s, background 0.3s'
                }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
              <span>Force : <strong style={{ color: strengthColor }}>{strength}</strong></span>
              <span>Entropie : <strong>{entropy} bits</strong></span>
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
              Settings
            </button>
            <button
              onClick={() => setActiveTab('advanced')}
              className={activeTab === 'advanced' ? 'admin-tab active' : 'admin-tab'}
            >
              Advanced
            </button>
          </div>

        {/* Contenu Settings */}
        {activeTab === 'settings' && (
          <div style={{ padding: 'var(--sp-4)', background: 'var(--bg-app)', borderRadius: 'var(--radius-lg)', marginBottom: 'var(--sp-6)' }}>
            <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)' }}>Options</div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
              <label style={{ fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-bold)' }}>Longueur :</label>
              <input
                type="number"
                min="1"
                max="256"
                value={length}
                onChange={(e) => setLength(Math.min(256, Math.max(1, parseInt(e.target.value) || 1)))}
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
                <span>Majuscules (A–Z)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeLowerCase}
                  onChange={(e) => setIncludeLowerCase(e.target.checked)}
                />
                <span>Minuscules (a–z)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeDigits}
                  onChange={(e) => setIncludeDigits(e.target.checked)}
                />
                <span>Chiffres (0–9)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeSpecial}
                  onChange={(e) => setIncludeSpecial(e.target.checked)}
                />
                <span>Spéciaux (!@#$%&...)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeBrackets}
                  onChange={(e) => setIncludeBrackets(e.target.checked)}
                />
                <span>Parenthèses ([]{}()...)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeMinus}
                  onChange={(e) => setIncludeMinus(e.target.checked)}
                />
                <span>Tiret (-)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeUnderline}
                  onChange={(e) => setIncludeUnderline(e.target.checked)}
                />
                <span>Underscore (_)</span>
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={includeLatin1}
                  onChange={(e) => setIncludeLatin1(e.target.checked)}
                />
                <span>Latin-1 (Å, μ, ...)</span>
              </label>
            </div>

            <div style={{ marginTop: 'var(--sp-4)' }}>
              <label className="modal-label">
                Caractères personnalisés :
              </label>
              <input
                type="text"
                value={customChars}
                onChange={(e) => setCustomChars(e.target.value)}
                placeholder="ex: @€#_"
                className="modal-input"
              />
            </div>
          </div>
        )}

        {/* Contenu Advanced */}
        {activeTab === 'advanced' && (
          <div style={{ padding: 'var(--sp-4)', background: 'var(--bg-app)', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)' }}>Options avancées</div>

            <label className="checkbox-label" style={{ marginBottom: 'var(--sp-3)' }}>
              <input
                type="checkbox"
                checked={excludeAmbiguous}
                onChange={(e) => setExcludeAmbiguous(e.target.checked)}
              />
              <span>Exclure caractères ambigus (l, 1, I, 0, O)</span>
            </label>

            <label className="checkbox-label" style={{ marginBottom: 'var(--sp-5)' }}>
              <input
                type="checkbox"
                checked={ensureOneFromEach}
                onChange={(e) => setEnsureOneFromEach(e.target.checked)}
              />
              <span>Forcer au moins un caractère de chaque catégorie sélectionnée</span>
            </label>

            <div>
              <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-3)', fontSize: 'var(--text-sm)' }}>Exigences minimales</div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>Min. majuscules :</label>
                  <input
                    type="number"
                    min="0"
                    value={minUpperCase}
                    onChange={(e) => setMinUpperCase(parseInt(e.target.value) || 0)}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>Min. minuscules :</label>
                  <input
                    type="number"
                    min="0"
                    value={minLowerCase}
                    onChange={(e) => setMinLowerCase(parseInt(e.target.value) || 0)}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>Min. chiffres :</label>
                  <input
                    type="number"
                    min="0"
                    value={minDigits}
                    onChange={(e) => setMinDigits(parseInt(e.target.value) || 0)}
                    className="modal-input"
                    style={{ width: '80px', marginBottom: 0 }}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)' }}>
                  <label style={{ fontSize: 'var(--text-sm)', minWidth: '140px' }}>Min. spéciaux :</label>
                  <input
                    type="number"
                    min="0"
                    value={minSpecial}
                    onChange={(e) => setMinSpecial(parseInt(e.target.value) || 0)}
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
            onClick={generatePassword}
            className="btn btn-secondary"
            type="button"
          >
            Régénérer
          </button>
          <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
            <button
              onClick={onClose}
              className="btn btn-secondary"
              type="button"
            >
              Annuler
            </button>
            <button
              onClick={() => onAccept(generatedPassword)}
              className="btn btn-primary"
              type="button"
            >
              Accepter
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
