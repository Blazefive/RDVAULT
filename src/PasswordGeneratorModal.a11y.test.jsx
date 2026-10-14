// ========================================
// TESTS : accessibilité du générateur de mot de passe
// ========================================
// - UI-35 : « Longueur » et les quatre minimums (onglet Avancé) n'avaient pas de libellé relié
//   (spinbutton sans nom).
// - UI-36 : « Caractères personnalisés » : nom accessible issu du texte indicatif (« ex: @€#_ »).
// - Onglets Paramètres / Avancé : sémantique d'onglets (tablist / tab / aria-selected / tabpanel).
// - UI-32 : « Copié dans le presse-papier ! » annoncé (région role="status" toujours présente).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'crypto';
import PasswordGeneratorModal from './PasswordGeneratorModal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

// Fonction simple (et non jest.fn) : resetMocks de react-scripts effacerait son implémentation
jest.mock('./utils/clipboard', () => ({ copySecureWithAutoClear: () => Promise.resolve() }));

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
if (!global.crypto || !global.crypto.getRandomValues) {
  Object.defineProperty(global, 'crypto', { value: webcrypto, configurable: true });
}

let root = null;
let host = null;
function mount() {
  localStorage.setItem('rdvault-lang', 'en');
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <PasswordGeneratorModal onClose={() => {}} onAccept={() => {}} />
      </I18nProvider>
    ));
  });
}
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const labelControl = (text) => {
  const label = Array.from(document.querySelectorAll('label')).find(l => l.textContent.trim() === text);
  return label ? label.control : null;
};
const tabs = () => Array.from(host.querySelectorAll('[role="tab"]'));
const keydown = (el, key) => act(() => { el.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })); });

test('UI-35 : « Longueur » relié à son champ numérique', () => {
  mount();
  const input = labelControl(en.passwordGenerator.lengthLabel);
  expect(input).not.toBeNull();
  expect(input.type).toBe('number');
});

test('UI-36 : « Caractères personnalisés » relié à son champ (le texte indicatif reste un exemple)', () => {
  mount();
  const input = labelControl(en.passwordGenerator.customChars);
  expect(input).not.toBeNull();
  expect(input.placeholder).toBe(en.passwordGenerator.customCharsPlaceholder);
});

test('UI-35 : les quatre minimums de l\'onglet Avancé sont reliés à leur libellé', () => {
  mount();
  act(() => { tabs()[1].click(); });
  for (const key of ['minUppercase', 'minLowercase', 'minDigits', 'minSpecial']) {
    const input = labelControl(en.passwordGenerator[key]);
    expect([key, input && input.type]).toEqual([key, 'number']);
  }
});

test('onglets : tablist, aria-selected, tabindex itinérant, flèches, panneau relié', () => {
  mount();
  expect(host.querySelector('[role="tablist"]')).not.toBeNull();
  const [settings, advanced] = tabs();
  expect(settings.textContent).toBe(en.passwordGenerator.tabSettings);
  expect(settings.getAttribute('aria-selected')).toBe('true');
  expect(advanced.getAttribute('aria-selected')).toBe('false');
  expect([settings.tabIndex, advanced.tabIndex]).toEqual([0, -1]);
  const panel = host.querySelector('[role="tabpanel"]');
  expect(panel.getAttribute('aria-labelledby')).toBe(settings.id);
  settings.focus();
  keydown(settings, 'ArrowRight');
  expect(document.activeElement).toBe(tabs()[1]);
  expect(tabs()[1].getAttribute('aria-selected')).toBe('true');
  expect(host.querySelector('[role="tabpanel"]').getAttribute('aria-labelledby')).toBe(tabs()[1].id);
  keydown(document.activeElement, 'ArrowRight');
  expect(document.activeElement).toBe(tabs()[0]);
});

test('UI-32 : « Copié » écrit dans une région role="status" présente avant la copie', () => {
  mount();
  const status = host.querySelector('[role="status"]');
  expect(status).not.toBeNull();
  expect(status.textContent).toBe('');
  const display = host.querySelector('.generator-password');
  act(() => { display.click(); });
  expect(host.querySelector('[role="status"]')).toBe(status);
  expect(status.textContent).toBe(en.passwordGenerator.copied);
});

// J1-e : avant, le mot de passe généré était un simple <div> sans focus : copie à la souris seulement.
describe('J1-e : copie du mot de passe généré au clavier', () => {
  const display = () => host.querySelector('.generator-password');
  const status = () => host.querySelector('[role="status"]');
  const press = (el, key) => {
    const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });
    act(() => { el.dispatchEvent(ev); });
    return ev;
  };

  test('role="button" focalisable, nommé « Copier le mot de passe », décrit par le mot de passe', () => {
    mount();
    const el = display();
    expect(el.getAttribute('role')).toBe('button');
    expect(el.tabIndex).toBe(0);
    expect(el.getAttribute('aria-label')).toBe(en.contextMenu.copyPassword);
    const desc = document.getElementById(el.getAttribute('aria-describedby'));
    expect(desc).not.toBeNull();
    expect(el.contains(desc)).toBe(true);
    expect(desc.textContent.length).toBe(20); // longueur par défaut
    // Apparence inchangée : même classe, curseur main
    expect(el.className).toBe('generator-password');
    expect(el.style.cursor).toBe('pointer');
  });

  test('Entrée puis Espace copient (annonce « Copié »), Espace sans défilement', () => {
    mount();
    const el = display();
    act(() => { el.focus(); });
    expect(press(el, 'Enter').defaultPrevented).toBe(true);
    expect(status().textContent).toBe(en.passwordGenerator.copied);
    expect(press(el, ' ').defaultPrevented).toBe(true);
    expect(status().textContent).toBe(en.passwordGenerator.copied);
    // Autre touche : sans effet
    expect(press(el, 'a').defaultPrevented).toBe(false);
  });

  test('Espace seule copie aussi', () => {
    mount();
    const el = display();
    act(() => { el.focus(); });
    press(el, ' ');
    expect(status().textContent).toBe(en.passwordGenerator.copied);
  });

  test('focus initial inchangé (onglet actif) ; Maj+Tab depuis l\'onglet atteint le mot de passe', () => {
    mount();
    expect(document.activeElement).toBe(tabs()[0]);
    const ev = new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true, cancelable: true });
    act(() => { tabs()[0].dispatchEvent(ev); });
    // Le piège de focus ne l'intercepte pas : le navigateur irait à l'élément précédent, le mot de passe
    expect(ev.defaultPrevented).toBe(false);
    const panel = host.querySelector('[role="dialog"]');
    const order = Array.from(panel.querySelectorAll('[tabindex="0"], button:not([disabled]):not([tabindex="-1"]), input:not([disabled])'));
    expect(order[order.indexOf(tabs()[0]) - 1]).toBe(display());
  });
});
