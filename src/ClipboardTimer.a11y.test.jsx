// ========================================
// TESTS : UI-32 — copie annoncée aux lecteurs d'écran (ClipboardTimer)
// ========================================
// Avant : la carte « Mot de passe copié » n'avait ni role="status" ni aria-live : aucune
// confirmation de la copie ni du délai d'effacement n'était annoncée. Une région live insérée
// déjà remplie n'est de plus pas annoncée par la plupart des lecteurs d'écran : la région est
// montée vide, puis le message y est écrit. Le compte à rebours (chaque seconde) n'est pas annoncé.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ClipboardTimer from './ClipboardTimer';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root = null;
beforeEach(() => { jest.useFakeTimers(); });
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
  jest.useRealTimers();
});

function mount() {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <ClipboardTimer fieldName="Password" duration={12000} startTime={Date.now()} onClear={() => {}} onExpire={() => {}} />
      </I18nProvider>
    ));
  });
  return host;
}

test('région role="status" aria-live="polite" montée vide puis remplie avec « copié » et le délai', () => {
  const host = mount();
  const status = host.querySelector('[role="status"]');
  expect(status).not.toBeNull();
  expect(status.getAttribute('aria-live')).toBe('polite');
  // Montée vide : le message n'y est écrit qu'après coup (annonce fiable)
  expect(status.textContent).toBe('');
  act(() => { jest.advanceTimersByTime(200); });
  expect(status.textContent).toContain(en.toast.copiedField.replace('{{field}}', 'Password'));
  expect(status.textContent).toContain(en.clipboard.autoClear.replace('{{seconds}}', '12'));
});

test('le compte à rebours n\'est pas dans une région live (pas d\'annonce chaque seconde)', () => {
  const host = mount();
  const countdown = host.querySelector('.clipboard-timer-countdown');
  expect(countdown.closest('[aria-live], [role="status"], [role="alert"]')).toBeNull();
  const status = host.querySelector('[role="status"]');
  act(() => { jest.advanceTimersByTime(200); });
  const first = status.textContent;
  act(() => { jest.advanceTimersByTime(3000); });
  expect(status.textContent).toBe(first);
});
