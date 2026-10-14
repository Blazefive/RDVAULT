// ========================================
// TESTS : panneau d'administration utilisable au clavier (UI-31, UI-38, onglets)
// ========================================
// - UI-31 : les éléments des listes Coffres / Policies / Audit étaient des <li onClick> sans
//   focus ni touche : impossible d'ouvrir une policy, de gérer un coffre ou de lire un journal
//   d'audit au clavier. « Modifier » / « Supprimer » d'une policy n'étaient proposés qu'au clic
//   droit. Les boutons « ✕ » n'avaient que « ✕ » pour nom.
// - UI-38 : élément sélectionné exposé (aria-current) et pas seulement par la couleur.
// - Barre d'onglets : sémantique d'onglets (tablist / tab / aria-selected / tabpanel, flèches).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import AdminPanel from './AdminPanel';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

jest.mock('axios', () => {
  const fn = jest.fn();
  fn.get = jest.fn();
  fn.post = jest.fn();
  fn.put = jest.fn();
  fn.delete = jest.fn();
  return { __esModule: true, default: fn };
});

global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const noop = () => {};
let root = null;
let host = null;

beforeEach(() => {
  axios.mockReset();
  axios.get.mockReset();
  axios.delete.mockReset();
  // LIST des policies et des groupes LDAP
  axios.mockImplementation(async ({ url }) => {
    if (url.endsWith('/v1/sys/policies/acl')) return { data: { data: { keys: ['default', 'app-read', 'ops'] } } };
    return { data: { data: { keys: [] } } };
  });
  axios.get.mockImplementation(async (url) => {
    const u = url.replace(VAULT, '');
    if (u === '/v1/sys/mounts') return { data: { data: { 'Eng/': { type: 'kv', options: { version: '2' } }, 'Ops/': { type: 'kv', options: { version: '1' } } } } };
    if (u === '/v1/sys/audit') return { data: { data: { 'file/': { type: 'file', options: { file_path: '/var/log/audit.log' } } } } };
    if (u.startsWith('/v1/sys/policies/acl/')) return { data: { data: { policy: `path "x/*" { capabilities = ["read"] }` } } };
    const e = new Error('404'); e.response = { status: 404 }; throw e;
  });
});

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const flush = async () => {
  for (let i = 0; i < 6; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
  }
};
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

async function renderPanel(props = {}) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    mountInRoot(root, (
      <I18nProvider defaultLang="en">
        <AdminPanel vaultUrl={VAULT} token="tok" baseHeaders={() => ({})} axiosConfig={(c) => c}
          username="u" onLogout={noop} onToggleAdminView={noop} onToggleDarkMode={noop}
          showToast={jest.fn()} isAdmin isModerator={false} {...props} />
      </I18nProvider>
    ));
  });
  await flush();
}

const tabs = () => Array.from(host.querySelectorAll('[role="tab"]'));
const tabByLabel = (label) => tabs().find(b => b.textContent.includes(label));
const keydown = async (el, key, opts = {}) => {
  await act(async () => { el.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts })); });
  await flush();
};
// Activation clavier d'un bouton natif : Entrée / Espace produisent un « click » (navigateur)
const activate = async (el) => { await act(async () => { el.click(); }); await flush(); };
const isKeyboardReachable = (el) => !!el && el.tabIndex >= 0 && !el.disabled
  && (el.tagName === 'BUTTON' || el.tagName === 'A' || el.getAttribute('tabindex') === '0');
const itemButtons = () => Array.from(host.querySelectorAll('.admin-items-list .admin-item button.admin-item-select'));

describe('Onglets du panneau d\'administration', () => {
  test('tablist nommée, onglets role="tab" avec aria-selected et tabindex itinérant', async () => {
    await renderPanel();
    const list = host.querySelector('[role="tablist"]');
    expect(list).not.toBeNull();
    expect(list.getAttribute('aria-label')).toBeTruthy();
    const all = tabs();
    expect(all.length).toBe(6);
    const selected = all.filter(tb => tb.getAttribute('aria-selected') === 'true');
    expect(selected.map(tb => tb.textContent)).toEqual([expect.stringContaining(en.admin.tab.mounts)]);
    expect(all.map(tb => tb.tabIndex)).toEqual([0, -1, -1, -1, -1, -1]);
    // Panneau relié à l'onglet actif
    const panel = host.querySelector('[role="tabpanel"]');
    expect(panel.getAttribute('aria-labelledby')).toBe(selected[0].id);
    expect(selected[0].getAttribute('aria-controls')).toBe(panel.id);
  });

  test('flèche droite / gauche, Début / Fin : onglet suivant activé et focalisé', async () => {
    await renderPanel();
    const first = tabByLabel(en.admin.tab.mounts);
    first.focus();
    await keydown(first, 'ArrowRight');
    expect(document.activeElement).toBe(tabByLabel(en.admin.tab.policies));
    expect(tabByLabel(en.admin.tab.policies).getAttribute('aria-selected')).toBe('true');
    await keydown(document.activeElement, 'End');
    expect(document.activeElement).toBe(tabByLabel(en.admin.tab.export));
    await keydown(document.activeElement, 'ArrowRight'); // boucle
    expect(document.activeElement).toBe(tabByLabel(en.admin.tab.mounts));
    await keydown(document.activeElement, 'ArrowLeft');
    expect(document.activeElement).toBe(tabByLabel(en.admin.tab.export));
    await keydown(document.activeElement, 'Home');
    expect(document.activeElement).toBe(tabByLabel(en.admin.tab.mounts));
  });
});

describe('UI-31 — listes utilisables au clavier', () => {
  test('Coffres : chaque coffre est un bouton focalisable ; activation = sélection (aria-current)', async () => {
    await renderPanel();
    const items = itemButtons();
    expect(items.length).toBe(2);
    items.forEach(b => expect(isKeyboardReachable(b)).toBe(true));
    const eng = items.find(b => b.textContent.includes('Eng/'));
    eng.focus();
    await activate(eng);
    expect(host.querySelector('.admin-editor h3').textContent).toContain('Eng');
    expect(itemButtons().find(b => b.textContent.includes('Eng/')).getAttribute('aria-current')).toBe('true');
    expect(itemButtons().find(b => b.textContent.includes('Ops/')).hasAttribute('aria-current')).toBe(false);
  });

  test('Coffres : bouton « ✕ » nommé avec le coffre', async () => {
    await renderPanel();
    const names = Array.from(host.querySelectorAll('.admin-item .btn-mini')).map(b => b.getAttribute('aria-label'));
    expect(names).toEqual([
      en.admin.mount.deleteNamed.replace('{{path}}', 'Eng'),
      en.admin.mount.deleteNamed.replace('{{path}}', 'Ops'),
    ]);
  });

  test('Policies : activation clavier = ouverture de l\'éditeur ; « Supprimer » visible sans clic droit', async () => {
    await renderPanel();
    await activate(tabByLabel(en.admin.tab.policies));
    const items = itemButtons();
    expect(items.map(b => b.textContent)).toEqual([expect.stringContaining('app-read'), expect.stringContaining('ops')]);
    await activate(items[0]);
    expect(host.querySelector('.admin-editor textarea')).not.toBeNull();
    expect(itemButtons()[0].getAttribute('aria-current')).toBe('true');
    const header = host.querySelector('.admin-editor-header');
    const del = Array.from(header.querySelectorAll('button')).find(b => b.textContent.includes(en.common.delete));
    expect(del).toBeDefined();
    await activate(del);
    // Confirmation de suppression affichée (même flux que le menu contextuel)
    expect(document.body.textContent).toContain(en.admin.confirm.deletePolicyTitle);
  });

  test('Policies : touche Menu / Maj+F10 sur une policy → menu clavier (focus, flèches, Échap)', async () => {
    await renderPanel();
    await activate(tabByLabel(en.admin.tab.policies));
    const item = itemButtons()[1];
    item.focus();
    // Touche Menu : le navigateur émet « contextmenu » sur l'élément focalisé (coordonnées 0, 0)
    await act(async () => { item.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 0, clientY: 0 })); });
    await flush();
    const menu = document.querySelector('[role="menu"]');
    expect(menu).not.toBeNull();
    const menuItems = Array.from(menu.querySelectorAll('[role="menuitem"]'));
    expect(menuItems.map(b => b.textContent)).toEqual([expect.stringContaining(en.admin.common.edit), expect.stringContaining(en.common.delete)]);
    expect(document.activeElement).toBe(menuItems[0]);
    await keydown(document.activeElement, 'ArrowDown');
    expect(document.activeElement).toBe(menuItems[1]);
    await keydown(document.activeElement, 'ArrowDown');
    expect(document.activeElement).toBe(menuItems[0]);
    await keydown(document.activeElement, 'Escape');
    expect(document.querySelector('[role="menu"]')).toBeNull();
    expect(document.activeElement).toBe(itemButtons()[1]);
  });

  test('Audit : device focalisable, activation = lecture du journal ; « ✕ » nommé', async () => {
    const tailLogFile = jest.fn(async () => ({ success: true, lines: [] }));
    window.electronAudit = { tailLogFile };
    try {
      await renderPanel();
      await activate(tabByLabel(en.admin.tab.audit));
      const items = itemButtons();
      expect(items.length).toBe(1);
      expect(isKeyboardReachable(items[0])).toBe(true);
      await activate(items[0]);
      expect(itemButtons()[0].getAttribute('aria-current')).toBe('true');
      expect(tailLogFile).toHaveBeenCalled();
      const x = host.querySelector('.admin-item .btn-mini');
      expect(x.getAttribute('aria-label')).toBe(en.admin.audit.disableNamed.replace('{{path}}', 'file'));
    } finally {
      delete window.electronAudit;
    }
  });
});
