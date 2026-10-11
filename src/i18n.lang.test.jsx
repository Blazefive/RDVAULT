// ========================================
// TESTS : langue du document suivant la langue de l'interface (i18n.js)
// ========================================
// <html lang="en"> était statique alors que l'interface est en français par défaut : les lecteurs
// d'écran prononçaient le français avec une voix anglaise. I18nProvider met désormais à jour
// document.documentElement.lang à chaque changement de langue.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider, useTranslation, useOptionalTranslation } from './i18n';
import LoadingSpinner from './LoadingSpinner';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
let ctx = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function Probe() {
  ctx = useTranslation();
  return null;
}

function mount(element) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, element); });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  ctx = null;
  document.body.innerHTML = '';
  document.documentElement.lang = 'en';
  localStorage.clear();
});

describe('document.documentElement.lang', () => {
  test('langue initiale (préférence enregistrée « fr ») appliquée au document', () => {
    document.documentElement.lang = 'en';
    localStorage.setItem('rdvault-lang', 'fr');
    mount(<I18nProvider><Probe /></I18nProvider>);
    expect(document.documentElement.lang).toBe('fr');
  });

  test('changement de langue : lang mis à jour', () => {
    localStorage.setItem('rdvault-lang', 'fr');
    mount(<I18nProvider><Probe /></I18nProvider>);
    act(() => { ctx.setLang('ja'); });
    expect(document.documentElement.lang).toBe('ja');
    act(() => { ctx.setLang('ar'); });
    expect(document.documentElement.lang).toBe('ar');
  });
});

describe('LoadingSpinner', () => {
  test('role="status" et libellé « Chargement... » traduit pour les lecteurs d\'écran', () => {
    localStorage.setItem('rdvault-lang', 'fr');
    const host = mount(<I18nProvider><LoadingSpinner /></I18nProvider>);
    const status = host.querySelector('[role="status"]');
    expect(status).not.toBeNull();
    expect(status.querySelector('.sr-only').textContent).toBe('Chargement...');
  });

  test('hors I18nProvider : rendu sans erreur (repli anglais)', () => {
    let optional = 'non appelé';
    function OptionalProbe() { optional = useOptionalTranslation(); return null; }
    const host = mount(<><OptionalProbe /><LoadingSpinner message="Patientez" /></>);
    expect(optional).toBeNull();
    expect(host.textContent).toContain('Patientez');
  });
});
