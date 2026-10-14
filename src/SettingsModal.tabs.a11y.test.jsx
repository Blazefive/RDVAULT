// ========================================
// TESTS : SettingsModal — sémantique d'onglets (IMPORT-37, motif WAI-ARIA APG « Tabs »)
// ========================================
// Avant : 7 <button class="tab-button"> dans un <div> neutre ; l'onglet actif n'était signalé que
// par la classe tab-button-active (aucun rôle tab/tablist/tabpanel, aucun aria-selected). Un
// lecteur d'écran ne savait ni quel onglet était affiché, ni que ces boutons changeaient le contenu.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SettingsModal from './SettingsModal';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;
let host = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  host = null;
  document.body.innerHTML = '';
  document.documentElement.removeAttribute('dir');
  localStorage.clear();
});

function mount() {
  localStorage.setItem('rdvault-lang', 'fr');
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <SettingsModal onClose={() => {}} visibleColumns={{}} />
      </I18nProvider>
    ));
  });
}

const LABELS = [
  fr.settings.appearance, fr.settings.columns, fr.settings.cli, fr.settings.language,
  fr.export.title, fr.extensionTab.tab, fr.settings.security, fr.settings.about
];
const tabs = () => Array.from(host.querySelectorAll('[role="tab"]'));
const tab = (label) => tabs().find(b => b.textContent.trim() === label);
const selected = () => tabs().filter(b => b.getAttribute('aria-selected') === 'true').map(b => b.textContent.trim());
const key = (el, k, init = {}) => {
  const e = new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...init });
  act(() => { el.dispatchEvent(e); });
  return e;
};

test('barre d\'onglets : tablist nommée, 8 onglets (Extension et Sécurité compris), un seul sélectionné, tabpanel relié', () => {
  mount();
  const list = host.querySelector('[role="tablist"]');
  expect(list).not.toBeNull();
  const title = host.querySelector('[role="dialog"] h2');
  expect(list.getAttribute('aria-labelledby')).toBe(title.id);
  expect(tabs().map(b => b.textContent.trim())).toEqual(LABELS);
  expect(selected()).toEqual([fr.settings.appearance]);

  const panel = host.querySelector('[role="tabpanel"]');
  expect(panel).not.toBeNull();
  for (const b of tabs()) {
    expect(b.id).toBeTruthy();
    expect(b.getAttribute('aria-controls')).toBe(panel.id);
    expect(b.parentElement).toBe(list);
  }
  expect(panel.getAttribute('aria-labelledby')).toBe(tab(fr.settings.appearance).id);
  // Apparence inchangée : mêmes classes qu'avant
  expect(tab(fr.settings.appearance).className).toBe('tab-button tab-button-active');
  expect(tab(fr.export.title).className).toBe('tab-button');
});

test('clic sur Export puis Extension : seul l\'onglet affiché a aria-selected="true" et tabIndex 0', () => {
  mount();
  act(() => { tab(fr.export.title).click(); });
  expect(selected()).toEqual([fr.export.title]);
  expect(tabs().filter(b => b.tabIndex === 0).map(b => b.textContent.trim())).toEqual([fr.export.title]);
  expect(host.querySelector('[role="tabpanel"]').getAttribute('aria-labelledby')).toBe(tab(fr.export.title).id);
  expect(host.querySelector('[role="tabpanel"] h3').textContent).toBe(fr.export.title);

  act(() => { tab(fr.extensionTab.tab).click(); });
  expect(selected()).toEqual([fr.extensionTab.tab]);
  expect(host.querySelector('[role="tabpanel"]').getAttribute('aria-labelledby')).toBe(tab(fr.extensionTab.tab).id);
});

test('flèches gauche/droite (avec bouclage), Début et Fin : focus et sélection suivent', () => {
  mount();
  const first = tab(fr.settings.appearance);
  act(() => { first.focus(); });
  let e = key(first, 'ArrowRight');
  expect(e.defaultPrevented).toBe(true);
  expect(selected()).toEqual([fr.settings.columns]);
  expect(document.activeElement).toBe(tab(fr.settings.columns));

  key(document.activeElement, 'ArrowLeft');
  key(document.activeElement, 'ArrowLeft'); // boucle : premier → dernier
  expect(selected()).toEqual([fr.settings.about]);
  expect(document.activeElement).toBe(tab(fr.settings.about));

  key(document.activeElement, 'ArrowRight'); // boucle : dernier → premier
  expect(selected()).toEqual([fr.settings.appearance]);

  key(document.activeElement, 'End');
  expect(selected()).toEqual([fr.settings.about]);
  key(document.activeElement, 'Home');
  expect(selected()).toEqual([fr.settings.appearance]);

  // Autre touche : sans effet
  e = key(document.activeElement, 'a');
  expect(e.defaultPrevented).toBe(false);
  expect(selected()).toEqual([fr.settings.appearance]);
});

test('arabe (dir="rtl") : la flèche gauche va à l\'onglet suivant', () => {
  mount();
  document.documentElement.dir = 'rtl';
  const first = tab(fr.settings.appearance);
  act(() => { first.focus(); });
  key(first, 'ArrowLeft');
  expect(selected()).toEqual([fr.settings.columns]);
  key(document.activeElement, 'ArrowRight');
  expect(selected()).toEqual([fr.settings.appearance]);
});

test('Maj+Tab depuis l\'onglet actif (pas le premier du DOM) : le focus reste dans la modale', () => {
  mount();
  act(() => { tab(fr.settings.about).click(); });
  const active = tab(fr.settings.about);
  act(() => { active.focus(); });
  const e = key(active, 'Tab', { shiftKey: true });
  // Les onglets inactifs (tabIndex -1) ne sont plus dans l'ordre de tabulation : sans cette prise en
  // charge, le navigateur sortait de la modale (le piège de focus attendait le premier onglet du DOM).
  expect(e.defaultPrevented).toBe(true);
  const dialog = host.querySelector('[role="dialog"]');
  expect(dialog.contains(document.activeElement)).toBe(true);
  expect(document.activeElement).not.toBe(active);
});

// UI-35 : les <select> de coffre (export et import) n'avaient pas de libellé relié : nom
// accessible vide, le libellé visible n'était qu'un texte voisin.
test('UI-35 : coffre d\'export et coffre d\'import reliés à leur libellé ; format en radiogroup nommé', () => {
  mount();
  act(() => { tab(fr.export.title).click(); });
  const labelFor = (text) => Array.from(host.querySelectorAll('label')).find(l => l.textContent.trim() === text);
  const exportSelect = labelFor(fr.export.selectVault).control;
  const importSelect = labelFor(fr.export.importSelectVault).control;
  expect(exportSelect && exportSelect.tagName).toBe('SELECT');
  expect(importSelect && importSelect.tagName).toBe('SELECT');
  expect(exportSelect).not.toBe(importSelect);
  const group = host.querySelector('[role="radiogroup"]');
  expect(document.getElementById(group.getAttribute('aria-labelledby')).textContent.trim()).toBe(fr.export.format);
  expect(group.querySelectorAll('input[type="radio"][name="exportFormat"]')).toHaveLength(2);
});
