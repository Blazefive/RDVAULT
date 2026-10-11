// ========================================
// TESTS : barre latérale des coffres (rendu réel react-dom dans jsdom)
// ========================================
// A11Y-24 : chaque carte de coffre est atteignable au clavier (role="button", tabIndex 0) ;
// Entrée / Espace sélectionne le coffre ; la souris (clic, clic droit) et le glisser-déposer
// restent inchangés. Le badge « Partagé » est traduit.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { TextEncoder } from 'util';
import Sidebar from './Sidebar';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu en chaîne (styles inline conservés tels quels ; le parseur CSS de jsdom ignore les var()
// imbriquées) : react-dom/server requiert TextEncoder
if (!global.TextEncoder) global.TextEncoder = TextEncoder;
const { renderToStaticMarkup: markupOf } = require('react-dom/server');

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key) => key.split('.').reduce((o, k) => (o ? o[k] : undefined), en) || key;

const ENGINES = [
  { name: 'users/a11y/Mes-Secrets', version: 2, canWrite: true },
  { name: 'users/a11y/Second', version: 2, canWrite: true },
  { name: 'partage-equipe', version: 2, canWrite: false },
];

function mount(props = {}) {
  localStorage.setItem('vault-client.username', 'a11y');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  const handlers = {
    onSelectEngine: jest.fn(),
    onEngineRightClick: jest.fn(),
    onDragOver: jest.fn(),
    onDragLeave: jest.fn(),
    onDropOnEngine: jest.fn(),
    onCreateEngine: jest.fn(),
  };
  act(() => {
    mountInRoot(root, (
      <Sidebar
        secretEngines={ENGINES}
        selectedEngine={ENGINES[0]}
        isDragging={false}
        dragOverTarget={null}
        isAdmin={false}
        sidebarOpen={false}
        t={t}
        {...handlers}
        {...props}
      />
    ));
  });
  mounted.push(root);
  return { host, handlers };
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

const cards = () => Array.from(document.querySelectorAll('.engine-card'));
const keydown = (el, key) => act(() => { el.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })); });

describe('A11Y-24 — cartes de coffre utilisables au clavier', () => {
  test('cartes focalisables, rôle bouton, coffre actif signalé par aria-current', () => {
    mount();
    for (const card of cards()) {
      expect(card.getAttribute('role')).toBe('button');
      expect(card.tabIndex).toBe(0);
    }
    expect(cards()[0].getAttribute('aria-current')).toBe('true');
    expect(cards()[1].hasAttribute('aria-current')).toBe(false);
  });

  test('focus sur la 2e carte + Entrée : onSelectEngine(coffre « Second »)', () => {
    const { handlers } = mount();
    cards()[1].focus();
    expect(document.activeElement).toBe(cards()[1]);
    keydown(cards()[1], 'Enter');
    expect(handlers.onSelectEngine).toHaveBeenCalledWith(ENGINES[1]);
  });

  test('Espace sélectionne aussi le coffre ; une autre touche ne fait rien', () => {
    const { handlers } = mount();
    keydown(cards()[2], 'a');
    expect(handlers.onSelectEngine).not.toHaveBeenCalled();
    keydown(cards()[2], ' ');
    expect(handlers.onSelectEngine).toHaveBeenCalledWith(ENGINES[2]);
  });

  test('souris inchangée : clic = sélection, clic droit = menu du coffre', () => {
    const { handlers } = mount();
    act(() => { cards()[1].click(); });
    expect(handlers.onSelectEngine).toHaveBeenCalledWith(ENGINES[1]);
    act(() => { cards()[1].dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true })); });
    expect(handlers.onEngineRightClick).toHaveBeenCalledTimes(1);
    expect(handlers.onEngineRightClick.mock.calls[0][1]).toBe(ENGINES[1]);
  });

  test('glisser-déposer inchangé : dépôt accepté sur un coffre accessible en écriture', () => {
    const { handlers } = mount();
    act(() => { cards()[1].dispatchEvent(new Event('drop', { bubbles: true })); });
    expect(handlers.onDropOnEngine).toHaveBeenCalledTimes(1);
    act(() => { cards()[2].dispatchEvent(new Event('drop', { bubbles: true })); });
    expect(handlers.onDropOnEngine).toHaveBeenCalledTimes(1); // coffre en lecture seule : refusé
  });

  test('pastille de dépôt (glisser en cours) : fond « accent-fill » sous texte blanc', () => {
    localStorage.setItem('vault-client.username', 'a11y');
    const markup = markupOf(
      <Sidebar
        secretEngines={ENGINES} selectedEngine={ENGINES[0]} isDragging dragOverTarget={null} isAdmin={false}
        sidebarOpen={false} t={t} onSelectEngine={() => {}} onEngineRightClick={() => {}} onDragOver={() => {}}
        onDragLeave={() => {}} onDropOnEngine={() => {}} onCreateEngine={() => {}}
      />
    );
    const badges = markup.match(/<span class="badge"[^>]*>/g) || [];
    expect(badges.length).toBe(2); // les deux coffres accessibles en écriture
    for (const badge of badges) {
      expect(badge).toContain('background:var(--accent-fill, var(--accent))');
      expect(badge).not.toMatch(/background:var\(--accent\);/);
    }
  });

  test('badge « Partagé » traduit (plus de texte français en dur)', () => {
    mount({ isAdmin: true });
    expect(document.querySelector('.badge-shared').textContent.trim()).toBe(en.engine.shared);
  });
});
