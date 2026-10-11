// ========================================
// TESTS : titre de la barre latérale (I18N-33)
// ========================================
// En russe, « Просмотр хранилища » était tronqué (« Просмотр хранили… ») par la règle
// nowrap + ellipsis de .sidebar-header h2, sans aucun moyen de lire le texte complet.
// - Le titre porte un attribut title (infobulle) avec le libellé complet.
// - Le titre de la barre latérale a sa propre clé (sidebar.title) : en russe, libellé court
//   « Хранилища » qui tient dans les 171 px disponibles ; « Просмотр хранилища » reste l'action
//   du menu utilisateur (toolbar.vaultView), où la place ne manque pas.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Sidebar from './Sidebar';
import { I18nProvider, useTranslation } from '../../i18n';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const ENGINES = [{ name: 'users/i18n/Mes-Secrets', version: 2, canWrite: true }];

function WithT() {
  const { t } = useTranslation();
  return (
    <Sidebar
      secretEngines={ENGINES} selectedEngine={ENGINES[0]} isDragging={false} dragOverTarget={null}
      isAdmin={false} sidebarOpen={false} t={t} onSelectEngine={() => {}} onEngineRightClick={() => {}}
      onDragOver={() => {}} onDragLeave={() => {}} onDropOnEngine={() => {}} onCreateEngine={() => {}}
    />
  );
}

function mount(lang) {
  localStorage.setItem('rdvault-lang', lang);
  localStorage.setItem('vault-client.username', 'i18n');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><WithT /></I18nProvider>); });
  mounted.push(root);
  return host.querySelector('.sidebar-header h2');
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

test('russe : libellé court et infobulle avec le texte complet', () => {
  const h2 = mount('ru');
  expect(h2.textContent).toBe('Хранилища');
  expect(h2.getAttribute('title')).toBe('Хранилища');
});

test('les autres langues gardent leur libellé (« Vue coffre-fort », « Vault View »)', () => {
  expect(mount('fr').textContent).toBe('Vue coffre-fort');
  const h2 = mount('en');
  expect(h2.textContent).toBe('Vault View');
  expect(h2.getAttribute('title')).toBe('Vault View');
});
