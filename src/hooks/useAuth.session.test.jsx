// ========================================
// TESTS : useAuth — fin de session (SESSION-46)
// ========================================
// Après l'expiration de la session d'un admin (inactivité / PC verrouillé),
// l'utilisateur suivant ne doit hériter ni de isAdmin ni de la vue admin :
// AdminPanel ne doit pas être monté avec son jeton, et l'en-tête principal
// (menu utilisateur : déconnexion, paramètres) doit rester accessible.

import React, { act, useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { useAuth } from './useAuth';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;

const noop = () => {};
let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
  sessionStorage.clear();
});

test('expiration de la session d\'un admin puis connexion d\'un non-admin', async () => {
  const api = { current: null };
  const renders = [];
  function Harness() {
    const [currentView, setCurrentView] = useState('vault');
    const auth = useAuth({
      vaultUrl: 'https://vault.test', ldapAuthPath: 'auth/ldap', showToast: noop, t: (k) => k,
      vaultApiRef: { current: { baseHeaders: () => ({}), axiosConfig: (c) => c } },
      fetchEnginesLikeUiRef: { current: async () => {} }, setSecretEngines: noop, setSelectedEngine: noop, setSecrets: noop,
      setCurrentView, setVisiblePasswords: noop, setAllVaultSecrets: noop, setDiscoveredTags: noop,
      setMultiVaultSearch: noop, setSelectedSecrets: noop, setSearchState: { setSearch: noop, setSearchInput: noop },
    });
    api.current = { ...auth, currentView };
    // Conditions de rendu d'App.jsx (en-tête principal et AdminPanel)
    useEffect(() => {
      renders.push({
        token: auth.token, isAdmin: auth.isAdmin, currentView,
        adminPanelMounted: !!auth.token && currentView === 'admin' && (auth.isAdmin || auth.isModerator),
        mainHeaderShown: !!auth.token && currentView !== 'admin',
      });
    });
    return null;
  }
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const mountInRoot = (reactRoot, element) => reactRoot.render(element); // hors Testing Library
  await act(async () => { mountInRoot(root, <Harness />); });

  // 1) alice (policy admin) se connecte → vue admin
  axios.post.mockResolvedValueOnce({ data: { auth: { client_token: 'tok-alice' } } });
  axios.get.mockImplementation(async (url) => {
    if (url.endsWith('/lookup-self')) return { data: { data: { entity_name: 'alice', policies: ['admin'] } } };
    return { data: { data: { policy: 'path "*" { capabilities = ["sudo"] }' } } };
  });
  await act(async () => { api.current.setAuthUser('alice'); api.current.setPassword('alice-pass-1'); });
  await act(async () => { await api.current.handleLogin(); });
  expect(api.current.isAdmin).toBe(true);
  expect(api.current.currentView).toBe('admin');

  // 2) la session expire
  await act(async () => { api.current.handleSessionExpired(); });
  expect(api.current.token).toBe('');
  expect(api.current.isAdmin).toBe(false);
  expect(api.current.isModerator).toBe(false);
  expect(api.current.currentView).toBe('vault');

  // 3) bob (non admin) se connecte ; lookup-self en attente
  let releaseLookup;
  axios.post.mockResolvedValueOnce({ data: { auth: { client_token: 'tok-bob' } } });
  axios.get.mockImplementation((url) => {
    if (url.endsWith('/lookup-self')) {
      return new Promise((r) => { releaseLookup = () => r({ data: { data: { entity_name: 'bob', policies: ['default'] } } }); });
    }
    return Promise.resolve({ data: { data: { policy: '' } } });
  });
  await act(async () => { api.current.setAuthUser('bob'); api.current.setPassword('bob-pass-123'); });
  let loginDone;
  await act(async () => { loginDone = api.current.handleLogin(); await new Promise(r => setTimeout(r, 0)); });
  const during = renders.filter(r => r.token === 'tok-bob');
  expect(during.length).toBeGreaterThan(0);
  expect(during.some(r => r.adminPanelMounted)).toBe(false);

  await act(async () => { releaseLookup(); await loginDone; });
  const last = renders[renders.length - 1];
  expect(last.isAdmin).toBe(false);
  expect(last.currentView).toBe('vault');
  expect(last.mainHeaderShown).toBe(true);
  expect(last.adminPanelMounted).toBe(false);
});
