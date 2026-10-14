// ========================================
// TESTS : UI-38 — version choisie dans l'historique exposée (aria-current)
// ========================================
// Avant : seule la classe « selected » (bordure, fond) marquait la version affichée.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import VersionHistoryModal from './VersionHistoryModal';
import { I18nProvider } from './i18n';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
});

const flush = async () => {
  for (let i = 0; i < 6; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
  }
};

test('la version affichée porte aria-current="true", les autres non', async () => {
  axios.get.mockImplementation(async (url) => {
    if (url.includes('/metadata/')) {
      return { data: { data: { versions: { 1: { created_time: '2026-01-01T00:00:00Z' }, 2: { created_time: '2026-02-01T00:00:00Z' } } } } };
    }
    return { data: { data: { data: { Username: 'u' } } } };
  });
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    mountInRoot(root, (
      <I18nProvider defaultLang="en">
        <VersionHistoryModal secretName="s" engine={{ name: 'kv', version: 2 }} vaultUrl="https://v" baseHeaders={() => ({})}
          axiosConfig={(c) => c} onClose={() => {}} showToast={() => {}} />
      </I18nProvider>
    ));
  });
  await flush();
  const items = () => Array.from(document.querySelectorAll('.version-item'));
  expect(items().length).toBe(2);
  expect(items().some(b => b.hasAttribute('aria-current'))).toBe(false);
  await act(async () => { items()[1].click(); });
  await flush();
  expect(items()[1].getAttribute('aria-current')).toBe('true');
  expect(items()[0].hasAttribute('aria-current')).toBe(false);
});
