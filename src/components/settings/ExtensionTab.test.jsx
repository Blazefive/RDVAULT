// ========================================
// TESTS : onglet « Extension » des Paramètres (rendu réel react-dom dans jsdom)
// ========================================
// L'extension livrée avec l'application : dossier affiché, ouverture du dossier, copie des valeurs
// non secrètes (chemin, page des extensions) par l'API du processus principal, état « introuvable ».

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ExtensionTab from './ExtensionTab';
import { I18nProvider } from '../../i18n';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });

async function mount(api) {
  localStorage.setItem('rdvault-lang', 'en');
  window.electronExtension = api;
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><ExtensionTab /></I18nProvider>); });
  mounted.push({ root, host });
  await flush();
  return host;
}

const makeApi = (info) => ({
  info: jest.fn(async () => info),
  openFolder: jest.fn(async () => ({ success: true })),
  copy: jest.fn(async () => ({ success: true })),
});

const button = (host, text) => Array.from(host.querySelectorAll('button')).find((b) => b.textContent.includes(text));

afterEach(() => {
  mounted.forEach(({ root, host }) => { act(() => root.unmount()); host.remove(); });
  mounted = [];
  delete window.electronExtension;
});

test('extension disponible : dossier, version, identifiant et les 4 étapes traduites', async () => {
  const api = makeApi({ available: true, folder: 'C:\\Program Files\\RDVAULT\\resources\\chrome-extension', id: 'cndjkmkhndclfcpcgeocmfdjnefhhhba', version: '1.7.0' });
  const host = await mount(api);
  expect(host.querySelector('[data-testid="extension-folder"]').textContent).toBe('C:\\Program Files\\RDVAULT\\resources\\chrome-extension');
  expect(host.textContent).toContain('1.7.0');
  expect(host.textContent).toContain('cndjkmkhndclfcpcgeocmfdjnefhhhba');
  for (const k of ['title', 'intro', 'step1', 'step2', 'step3', 'step4', 'update', 'sharedWarning']) {
    expect(host.textContent).toContain(en.extensionTab[k]);
  }
  expect(host.textContent).not.toMatch(/extensionTab\./);
});

test('boutons : ouvrir le dossier, copier le chemin et la page des extensions (liste fermée)', async () => {
  const api = makeApi({ available: true, folder: 'C:\\x\\chrome-extension', id: null, version: '1.7.0' });
  const host = await mount(api);
  act(() => { button(host, en.extensionTab.openFolder).click(); });
  expect(api.openFolder).toHaveBeenCalledTimes(1);
  await act(async () => { button(host, en.extensionTab.copyPath).click(); });
  expect(api.copy).toHaveBeenLastCalledWith('folder');
  expect(host.textContent).toContain(en.extensionTab.copied);
  await act(async () => { button(host, 'chrome://extensions').click(); });
  expect(api.copy).toHaveBeenLastCalledWith('chrome');
  await act(async () => { button(host, 'edge://extensions').click(); });
  expect(api.copy).toHaveBeenLastCalledWith('edge');
});

test('extension introuvable (ou API absente) : message explicite, aucun bouton d\'action', async () => {
  const host = await mount(makeApi({ available: false, folder: 'x', id: null, version: '' }));
  expect(host.querySelector('[role="alert"]').textContent).toBe(en.extensionTab.unavailable);
  expect(button(host, en.extensionTab.openFolder)).toBeUndefined();
  act(() => { mounted[0].root.unmount(); }); mounted[0].host.remove(); mounted = [];
  const host2 = await mount(undefined);
  expect(host2.textContent).toContain(en.extensionTab.unavailable);
});
