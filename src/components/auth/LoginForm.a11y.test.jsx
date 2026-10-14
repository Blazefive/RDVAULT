// ========================================
// TESTS : UI-36 — « Nom d'utilisateur » relié à son champ (formulaire de connexion)
// ========================================
// Avant : <label> sans htmlFor ; le nom accessible du champ venait du texte indicatif
// (« Votre identifiant ») et différait du libellé visible (WCAG 2.5.3, 1.3.1).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import LoginForm from './LoginForm';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
});

const t = (key) => key;

function mount(props = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <LoginForm authUser="" setAuthUser={() => {}} password="" setPassword={() => {}}
        rememberMe={false} setRememberMe={() => {}} onLogin={() => {}} t={t} setupMode={false} {...props} />
    ));
  });
  return host;
}

const labelControl = (host, text) => {
  const label = Array.from(host.querySelectorAll('label')).find(l => l.textContent.trim() === text);
  return label ? label.control : null;
};

test('libellé « Nom d\'utilisateur » relié au champ (nom accessible = libellé visible)', () => {
  const host = mount();
  const input = labelControl(host, 'login.username');
  expect(input).not.toBeNull();
  expect(input.placeholder).toBe('login.placeholderUser');
  expect(input.getAttribute('autocomplete')).toBe('username');
});

test('mot de passe toujours relié (non-régression) ; confirmation en erreur décrite par son message', () => {
  const host = mount({ setupMode: true, password: 'abcdefgh' });
  expect(labelControl(host, 'login.password')).not.toBeNull();
  const confirm = labelControl(host, 'login.confirmPassword');
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  act(() => {
    setter.call(confirm, 'autre');
    confirm.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(confirm.getAttribute('aria-invalid')).toBe('true');
  const describedBy = confirm.getAttribute('aria-describedby');
  expect(describedBy).toBeTruthy();
  expect(document.getElementById(describedBy).textContent).toBe('login.setupMismatchHint');
});
