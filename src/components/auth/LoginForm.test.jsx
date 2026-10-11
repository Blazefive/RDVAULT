// ========================================
// TESTS : LoginForm — création du compte administrateur au premier démarrage (AUTH-14)
// ========================================
// Coffre local vide : le premier « Se connecter » crée le compte administrateur avec le mot de
// passe saisi. Le formulaire doit alors passer en mode création (confirmation du mot de passe,
// règle des 8 caractères, indicateur de force) et transmettre la confirmation à onLogin.
// Le mode est détecté par GET /v1/sys/init (route Vault) sur le serveur local uniquement.

import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import LoginForm from './LoginForm';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  axios.get.mockReset();
  delete window.electronConfig;
});

const t = (key, vars) => (vars ? `${key}:${JSON.stringify(vars)}` : key);

async function flush() {
  for (let i = 0; i < 5; i++) {
    // eslint-disable-next-line no-await-in-loop -- volontaire : vidage successif des microtâches
    await act(async () => { await Promise.resolve(); });
  }
}

async function mountForm({ config, props = {} } = {}) {
  if (config) window.electronConfig = { getConfig: jest.fn(async () => ({ success: true, config })) };
  const onLogin = jest.fn();
  function Harness() {
    const [authUser, setAuthUser] = useState('');
    const [password, setPassword] = useState('');
    const [rememberMe, setRememberMe] = useState(false);
    return (
      <LoginForm
        authUser={authUser} setAuthUser={setAuthUser}
        password={password} setPassword={setPassword}
        rememberMe={rememberMe} setRememberMe={setRememberMe}
        onLogin={onLogin} t={t} {...props}
      />
    );
  }
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const mountInRoot = (reactRoot, element) => reactRoot.render(element); // hors Testing Library
  await act(async () => { mountInRoot(root, <Harness />); });
  await flush();
  return { host, onLogin };
}

// Saisie contrôlée React : passe par le setter natif puis déclenche « input »
function type(input, value) {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

const LOCAL = { APP_MODE: 'local', VAULT_URL: 'http://127.0.0.1:51234' };

test('coffre local vide : mode création (confirmation, règle, force) et confirmation transmise', async () => {
  axios.get.mockResolvedValue({ status: 200, data: { initialized: false } });
  const { host, onLogin } = await mountForm({ config: LOCAL });
  expect(axios.get).toHaveBeenCalledWith('http://127.0.0.1:51234/v1/sys/init', expect.objectContaining({ timeout: expect.any(Number) }));

  const passwords = host.querySelectorAll('input[type="password"]');
  expect(passwords).toHaveLength(2);
  expect(host.textContent).toContain('login.setupTitle');
  expect(host.textContent).toContain('login.setupHint');
  expect(host.textContent).toContain('login.setupRule:{"min":8}');

  type(host.querySelector('input:not([type])'), 'admin');
  type(passwords[0], 'Tournesol-Bleu-2025');
  // Indicateur de force (libellés du générateur, traduits)
  expect(host.querySelector('[data-testid="setup-strength"]')).not.toBeNull();
  expect(host.textContent).toMatch(/passwordGenerator\.strength(Weak|Medium|Strong|VeryStrong)/);

  type(passwords[1], 'Tournesol-Bleu-2026');
  expect(host.textContent).toContain('login.setupMismatchHint');

  act(() => { host.querySelector('button.btn-login').click(); });
  expect(onLogin).toHaveBeenCalledTimes(1);
  expect(onLogin).toHaveBeenCalledWith({ setup: true, confirmPassword: 'Tournesol-Bleu-2026' });
  expect(host.querySelector('button.btn-login').textContent).toContain('login.setupSubmit');

  // Entrée dans le champ de confirmation : même envoi
  act(() => { passwords[1].dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); });
  expect(onLogin).toHaveBeenLastCalledWith({ setup: true, confirmPassword: 'Tournesol-Bleu-2026' });
});

test('coffre local déjà initialisé : formulaire de connexion habituel', async () => {
  axios.get.mockResolvedValue({ status: 200, data: { initialized: true } });
  const { host, onLogin } = await mountForm({ config: LOCAL });
  expect(host.querySelectorAll('input[type="password"]')).toHaveLength(1);
  expect(host.textContent).not.toContain('login.setupTitle');
  act(() => { host.querySelector('button.btn-login').click(); });
  expect(onLogin).toHaveBeenCalledWith();
});

test('serveur local sans la route /v1/sys/init (403) : formulaire habituel', async () => {
  axios.get.mockRejectedValue({ response: { status: 403 } });
  const { host } = await mountForm({ config: LOCAL });
  expect(host.querySelectorAll('input[type="password"]')).toHaveLength(1);
});

test('mode entreprise (Vault distant) : aucune requête /v1/sys/init', async () => {
  const { host } = await mountForm({ config: { APP_MODE: 'enterprise', VAULT_URL: 'https://vault.example.com:8200' } });
  expect(axios.get).not.toHaveBeenCalled();
  expect(host.querySelectorAll('input[type="password"]')).toHaveLength(1);
});

test('hors Electron (pas de electronConfig) : formulaire habituel', async () => {
  const { host } = await mountForm();
  expect(axios.get).not.toHaveBeenCalled();
  expect(host.querySelectorAll('input[type="password"]')).toHaveLength(1);
});

test('mode imposé par la prop setupMode (sans détection)', async () => {
  const { host } = await mountForm({ config: LOCAL, props: { setupMode: true } });
  expect(axios.get).not.toHaveBeenCalled();
  expect(host.querySelectorAll('input[type="password"]')).toHaveLength(2);
});
