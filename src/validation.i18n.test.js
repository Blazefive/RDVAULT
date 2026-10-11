// ========================================
// TESTS : validation.js — codes de traduction des messages d'erreur (I18N-28)
// ========================================
// Les validateurs affichés à l'utilisateur gardent leur texte français historique `error`
// (compatibilité : journaux, validateSecret, vaultApi) et ajoutent un `code` stable traduit dans
// les 12 locales via translateValidationError.

import { validateSecretName, validateUsername, validatePassword, translateValidationError } from './validation';
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

const LOCALES = { ar, de, en, es, fr, it, ja, ko, pt, ru, tr, zh };
const LANGS = Object.keys(LOCALES);
const lookup = (obj, key) => key.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);
// Traducteur minimal équivalent à i18n.js (variables {{x}})
const translator = (lang) => (key, vars = {}) => {
  const v = lookup(LOCALES[lang], key);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? `{{${n}}}`) : key;
};

const FAILURES = [
  ['nameRequired', validateSecretName('')],
  ['nameTooLong', validateSecretName('a'.repeat(513))],
  ['nameForbiddenChars', validateSecretName('../x')],
  ['nameControlChars', validateSecretName('a\u0001b')],
  ['usernameRequired', validateUsername('')],
  ['usernameTooLong', validateUsername('u'.repeat(257))],
  ['usernameControlChars', validateUsername('u\u0000')],
  ['passwordRequired', validatePassword('')],
  ['passwordTooLong', validatePassword('p'.repeat(1025))],
  ['passwordControlChars', validatePassword('p\u001F')],
];

test('chaque échec garde son texte français historique et porte un code stable', () => {
  for (const [code, res] of FAILURES) {
    expect(res.valid).toBe(false);
    expect(res.code).toBe(code);
    expect(typeof res.error).toBe('string');
  }
  expect(validateSecretName('').error).toBe('Le nom est requis');
  expect(validatePassword('p'.repeat(1025)).params).toEqual({ max: 1024 });
  // Un résultat valide reste exactement { valid: true }
  expect(validateUsername('john')).toEqual({ valid: true });
});

test.each(LANGS)('%s : chaque code a une traduction (bornes substituées, aucune clé brute)', (lang) => {
  const t = translator(lang);
  for (const [code, res] of FAILURES) {
    const key = code === 'nameRequired' ? 'error.nameRequired' : `validation.${code}`;
    // La clé existe dans la locale (sinon translateValidationError retomberait sur le français)
    expect([lang, key, typeof lookup(LOCALES[lang], key)]).toEqual([lang, key, 'string']);
    const msg = translateValidationError(res, t);
    expect(msg).toBe(t(key, res.params));
    expect(msg).not.toMatch(/\{\{/);
    // Borne substituée (« max 1024 ») ; hors français, plus jamais le texte français historique
    expect(msg.includes(String(res.params?.max ?? ''))).toBe(true);
    expect([lang, code, msg === res.error]).toEqual([lang, code, lang === 'fr' && msg === res.error]);
  }
});

test('repli : sans code ou sans traducteur, le texte historique est renvoyé', () => {
  expect(translateValidationError({ valid: false, error: 'Ancien message' }, translator('en'))).toBe('Ancien message');
  expect(translateValidationError(validateSecretName(''), undefined)).toBe('Le nom est requis');
  expect(translateValidationError({ valid: true }, translator('en'))).toBe('');
  // Clé absente des locales : texte historique plutôt que la clé brute
  expect(translateValidationError({ valid: false, error: 'X', code: 'inconnu' }, translator('en'))).toBe('X');
});
