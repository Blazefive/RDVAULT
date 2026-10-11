// ========================================
// TESTS : parité des 12 locales (src/locales/*.json)
// ========================================
// Chaque locale doit avoir exactement les mêmes clés que en.json, dans le même
// ordre, avec des valeurs non vides et les mêmes variables {{...}}.

import ar from './locales/ar.json';
import de from './locales/de.json';
import en from './locales/en.json';
import es from './locales/es.json';
import fr from './locales/fr.json';
import it from './locales/it.json';
import ja from './locales/ja.json';
import ko from './locales/ko.json';
import pt from './locales/pt.json';
import ru from './locales/ru.json';
import tr from './locales/tr.json';
import zh from './locales/zh.json';

const locales = { ar, de, es, fr, it, ja, ko, pt, ru, tr, zh };

// Aplatit { a: { b: 'x' } } en [['a.b', 'x']] en conservant l'ordre des clés
const flatten = (obj, prefix = '') => Object.entries(obj).flatMap(([k, v]) =>
  (v && typeof v === 'object') ? flatten(v, `${prefix}${k}.`) : [[`${prefix}${k}`, v]]);
const placeholders = (s) => (String(s).match(/\{\{\w+\}\}/g) || []).sort();

const enEntries = flatten(en);
const enKeys = enEntries.map(([k]) => k);
const enMap = Object.fromEntries(enEntries);

describe.each(Object.keys(locales))('locale %s', (code) => {
  const entries = flatten(locales[code]);
  const map = Object.fromEntries(entries);

  test('mêmes clés que en.json, dans le même ordre', () => {
    expect(entries.map(([k]) => k)).toEqual(enKeys);
  });

  test('valeurs non vides et mêmes variables {{...}} que en.json', () => {
    for (const key of enKeys) {
      expect(typeof map[key]).toBe('string');
      expect(map[key].trim()).not.toBe('');
      expect([key, placeholders(map[key])]).toEqual([key, placeholders(enMap[key])]);
    }
  });
});

test('les clés ajoutées pour EditSecretModal / ModalOrchestrator / SettingsModal sont traduites (pas de copie anglaise)', () => {
  const added = [
    'editSecret.folderHint', 'editSecret.tagsPlaceholder', 'editSecret.tagsHint',
    'editSecret.protectedField', 'editSecret.maxFileSize',
    'error.folderCreate', 'error.customFieldKeyTooLong', 'error.customFieldValueTooLong',
    'export.allFiles',
  ];
  for (const key of added) {
    expect(typeof enMap[key]).toBe('string');
    for (const code of Object.keys(locales)) {
      const value = Object.fromEntries(flatten(locales[code]))[key];
      expect([code, key, value === enMap[key]]).toEqual([code, key, false]);
    }
  }
});
