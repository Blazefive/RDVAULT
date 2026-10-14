// ========================================
// TESTS : accessibilité de la modale de création de coffre (EditEngineModal)
// ========================================
// UI-36 : « Chemin* » et « Description » étaient des <label> sans htmlFor : champ et zone de texte
// sans nom accessible (seul le texte indicatif était lu).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import EditEngineModal from './EditEngineModal';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;
let host = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  host = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

function mount(props = {}) {
  localStorage.setItem('rdvault-lang', 'fr');
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <EditEngineModal onClose={() => {}} onCreate={async () => {}} isAdmin {...props} />
      </I18nProvider>
    ));
  });
}

const labelControl = (text) => {
  const label = Array.from(host.querySelectorAll('label')).find(l => l.textContent.trim() === text);
  return label ? label.control : null;
};

test('UI-36 : « Chemin* » relié au champ du chemin (obligatoire), qui garde le focus initial', () => {
  mount();
  const input = labelControl(fr.engine.path);
  expect(input).not.toBeNull();
  expect(input.tagName).toBe('INPUT');
  expect(input.getAttribute('aria-required')).toBe('true');
  expect(document.activeElement).toBe(input);
});

test('UI-36 : « Description » reliée à la zone de texte', () => {
  mount({ isAdmin: false });
  const area = labelControl(fr.engine.description);
  expect(area).not.toBeNull();
  expect(area.tagName).toBe('TEXTAREA');
});
