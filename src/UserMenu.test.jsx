// ========================================
// TESTS : menu utilisateur (rendu réel react-dom dans jsdom)
// ========================================
// A11Y-33 : aria-haspopup / aria-expanded, nom accessible sans les initiales, Échap ferme le menu
// et rend le focus au déclencheur, fermeture quand le focus quitte le menu, flèches, rôles menu.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import UserMenu from './UserMenu';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(props = {}) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const outside = document.createElement('button');
  outside.textContent = 'dehors';
  document.body.appendChild(outside);
  const root = createRoot(host);
  const handlers = { onLogout: jest.fn(), onOpenSettings: jest.fn(), onOpenPasswordHealth: jest.fn(), onOpenPasskeys: jest.fn(), onToggleAdminView: jest.fn() };
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <UserMenu username="a11y" isAdmin={false} isModerator={false} currentView="vault" {...handlers} {...props} />
      </I18nProvider>
    ));
  });
  mounted.push(root);
  return { host, handlers, outside };
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

const trigger = () => document.querySelector('.user-menu-trigger');
const dropdown = () => document.querySelector('.user-menu-dropdown');
const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts })); });
};

describe('A11Y-33 — menu utilisateur', () => {
  test('déclencheur : aria-haspopup, aria-expanded, nom « Connected as a11y » (sans initiales)', () => {
    mount();
    expect(trigger().getAttribute('aria-haspopup')).toBe('menu');
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    expect(trigger().getAttribute('aria-label')).toBe(en.user.connectedAs.replace('{{name}}', 'a11y'));
    expect(document.querySelector('.user-avatar').getAttribute('aria-hidden')).toBe('true');
  });

  test('ouverture : aria-expanded="true", role="menu", focus sur le premier élément', () => {
    mount();
    trigger().focus();
    act(() => { trigger().click(); });
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    expect(dropdown().getAttribute('role')).toBe('menu');
    const items = dropdown().querySelectorAll('[role="menuitem"]');
    expect(items.length).toBe(4);
    expect(document.activeElement).toBe(items[0]);
  });

  test('Échap ferme le menu et rend le focus au déclencheur', () => {
    mount();
    trigger().focus();
    act(() => { trigger().click(); });
    press('Escape');
    expect(dropdown()).toBeNull();
    expect(document.activeElement).toBe(trigger());
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
  });

  test('flèches : navigation circulaire entre les éléments', () => {
    mount();
    act(() => { trigger().click(); });
    const items = () => dropdown().querySelectorAll('[role="menuitem"]');
    press('ArrowDown');
    expect(document.activeElement).toBe(items()[1]);
    press('ArrowUp');
    press('ArrowUp');
    expect(document.activeElement).toBe(items()[items().length - 1]);
    press('Home');
    expect(document.activeElement).toBe(items()[0]);
  });

  test('le focus quitte le menu (Tab vers l\'extérieur) : menu fermé', () => {
    const { outside } = mount();
    act(() => { trigger().click(); });
    act(() => { outside.focus(); });
    expect(dropdown()).toBeNull();
  });

  test('action : focus rendu au déclencheur puis action appelée (la modale le lui rendra)', () => {
    const { handlers } = mount();
    act(() => { trigger().click(); });
    const settings = Array.from(dropdown().querySelectorAll('[role="menuitem"]')).find(b => b.textContent.includes(en.toolbar.settings));
    act(() => { settings.click(); });
    expect(handlers.onOpenSettings).toHaveBeenCalledTimes(1);
    expect(dropdown()).toBeNull();
    expect(document.activeElement).toBe(trigger());
  });

  test('flèche bas sur le déclencheur fermé : ouverture du menu', () => {
    mount();
    trigger().focus();
    press('ArrowDown');
    expect(dropdown()).not.toBeNull();
  });
});
