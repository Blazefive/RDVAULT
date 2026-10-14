// ========================================
// TESTS : générateur ouvert depuis le menu utilisateur (sans fiche à remplir)
// ========================================
// Sans onAccept : « Copier » remplace « Utiliser ce mot de passe » et « Fermer » remplace « Annuler ».
// Avec onAccept (fiche d'entrée) : comportement inchangé.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'crypto';
import PasswordGeneratorModal from './PasswordGeneratorModal';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';

const mockCopied = [];
// Fonction simple (et non jest.fn) : resetMocks de react-scripts effacerait son implémentation
jest.mock('./utils/clipboard', () => ({ copySecureWithAutoClear: (text) => { mockCopied.push(text); return Promise.resolve(); } }));

global.IS_REACT_ACT_ENVIRONMENT = true;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
if (!global.crypto || !global.crypto.getRandomValues) {
  Object.defineProperty(global, 'crypto', { value: webcrypto, configurable: true });
}

let root = null;
function mount(props) {
  localStorage.setItem('rdvault-lang', 'fr');
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><PasswordGeneratorModal {...props} /></I18nProvider>); });
  return host;
}
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  mockCopied.length = 0;
  document.body.innerHTML = '';
  localStorage.clear();
});

const footerButtons = (host) => Array.from(host.querySelectorAll('.modal-footer button')).map((b) => b.textContent.trim());

test('autonome : boutons « Copier » et « Fermer » ; Copier copie le mot de passe affiché', () => {
  let closed = 0;
  const host = mount({ onClose: () => { closed += 1; } });
  expect(footerButtons(host)).toEqual([fr.passwordGenerator.regenerate, fr.common.close, fr.passwordGenerator.copy]);
  const shown = host.querySelector('.generator-password span').textContent;
  expect(shown.length).toBeGreaterThan(0);
  const copyBtn = Array.from(host.querySelectorAll('.modal-footer button')).find((b) => b.textContent.trim() === fr.passwordGenerator.copy);
  act(() => { copyBtn.click(); });
  expect(mockCopied).toEqual([shown]);
  expect(closed).toBe(0);
});

test('depuis une fiche (onAccept) : « Annuler » et « Utiliser » inchangés', () => {
  const accepted = [];
  const host = mount({ onClose: () => {}, onAccept: (p) => accepted.push(p) });
  expect(footerButtons(host)).toEqual([fr.passwordGenerator.regenerate, fr.common.cancel, fr.passwordGenerator.accept]);
  const useBtn = Array.from(host.querySelectorAll('.modal-footer button')).find((b) => b.textContent.trim() === fr.passwordGenerator.accept);
  act(() => { useBtn.click(); });
  expect(accepted).toHaveLength(1);
  expect(mockCopied).toEqual([]);
});
