// ========================================
// TESTS : sens d'écriture du document (I18N-31)
// ========================================
// En arabe, I18nProvider ne posait que lang : la direction de base restait LTR, les phrases
// mêlant arabe et termes latins (« kv1/kv2 », exemples mvault, parenthèses) étaient réordonnées
// par l'algorithme bidi et la mise en page n'était pas inversée. <html dir> suit désormais la
// langue : « rtl » pour l'arabe, « ltr » pour les 11 autres.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider, useTranslation, LANGUAGES, isRtlLanguage } from './i18n';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
let ctx = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function Probe() { ctx = useTranslation(); return null; }

function mount() {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><Probe /></I18nProvider>); });
  mounted.push(root);
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  ctx = null;
  document.documentElement.removeAttribute('dir');
  document.documentElement.lang = 'en';
  localStorage.clear();
});

test('arabe au démarrage : <html dir="rtl">', () => {
  localStorage.setItem('rdvault-lang', 'ar');
  mount();
  expect(document.documentElement.dir).toBe('rtl');
  expect(document.documentElement.lang).toBe('ar');
});

test('changement de langue : arabe → anglais → arabe', () => {
  localStorage.setItem('rdvault-lang', 'fr');
  mount();
  expect(document.documentElement.dir).toBe('ltr');
  act(() => { ctx.setLang('ar'); });
  expect(document.documentElement.dir).toBe('rtl');
  act(() => { ctx.setLang('en'); });
  expect(document.documentElement.dir).toBe('ltr');
});

test('seul l\'arabe est RTL parmi les langues proposées', () => {
  expect(LANGUAGES.filter(l => isRtlLanguage(l.code)).map(l => l.code)).toEqual(['ar']);
  expect(isRtlLanguage('ar-MA')).toBe(true);
  expect(isRtlLanguage(undefined)).toBe(false);
});
