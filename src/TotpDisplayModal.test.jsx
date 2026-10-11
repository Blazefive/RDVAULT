// ========================================
// TESTS : TotpDisplayModal — rafraîchissement du code à chaque nouvelle fenêtre TOTP
// ========================================
// BUG CORRIGÉ : le code n'était rafraîchi que si un tick de l'intervalle (1 s) tombait
// exactement sur `remaining === période`. Fenêtre en arrière-plan : Chromium espace les
// minuteurs, ce tick est sauté et un code périmé reste affiché tout un cycle. Le
// rafraîchissement suit désormais floor(Date.now() / 1000 / période). Horloge simulée
// (minuteurs factices « modern » de Jest : Date.now() et setInterval).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import TotpDisplayModal, { totpWindow } from './TotpDisplayModal';
import { I18nProvider } from './i18n';

global.IS_REACT_ACT_ENVIRONMENT = true;

const PERIOD = 30;
// Début d'une fenêtre TOTP de 30 s (multiple de 30 000 ms)
const WINDOW_START = 1_800_000_000_000 - (1_800_000_000_000 % (PERIOD * 1000));

let root = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(props) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <TotpDisplayModal secretName="gitlab" totpCode="111111" onClose={() => {}} onCopy={() => {}} period={PERIOD} {...props} />
      </I18nProvider>
    ));
  });
  return host;
}

// Fait avancer l'horloge simulée et exécute les minuteurs échus, puis les promesses
const tick = async (ms) => {
  await act(async () => { jest.advanceTimersByTime(ms); });
  await act(async () => { await Promise.resolve(); });
};
const code = () => document.querySelector('.modal-body').textContent;

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
  jest.useRealTimers();
});

test('totpWindow : numéro de fenêtre RFC 6238', () => {
  expect(totpWindow(WINDOW_START, PERIOD)).toBe(WINDOW_START / 1000 / PERIOD);
  expect(totpWindow(WINDOW_START + 29_999, PERIOD)).toBe(WINDOW_START / 1000 / PERIOD);
  expect(totpWindow(WINDOW_START + 30_000, PERIOD)).toBe(WINDOW_START / 1000 / PERIOD + 1);
});

test('tick sauté (fenêtre en arrière-plan) : le code est quand même rafraîchi', async () => {
  // Ouverture 2 s avant la fin de la fenêtre
  jest.setSystemTime(WINDOW_START + 28_000);
  const onRefresh = jest.fn().mockResolvedValue('222222');
  mount({ onRefresh });
  expect(code()).toContain('111111');
  expect(onRefresh).not.toHaveBeenCalled();

  // Minuteurs bridés : aucun tick pendant 5 s, l'horloge franchit la frontière de fenêtre.
  // Le tick suivant tombe à 27 s restantes (jamais sur « 30 s restantes »).
  jest.setSystemTime(WINDOW_START + 33_000);
  await tick(1000);
  expect(onRefresh).toHaveBeenCalledTimes(1);
  expect(code()).toContain('222222');
  expect(code()).not.toContain('111111');
});

test('ticks réguliers : un seul rafraîchissement par fenêtre, aucun avant la frontière', async () => {
  jest.setSystemTime(WINDOW_START + 25_000);
  const onRefresh = jest.fn().mockResolvedValue('333333');
  mount({ onRefresh });
  await tick(4000); // 29 s : même fenêtre
  expect(onRefresh).not.toHaveBeenCalled();
  await tick(1000); // 30 s : nouvelle fenêtre
  expect(onRefresh).toHaveBeenCalledTimes(1);
  expect(code()).toContain('333333');
  await tick(10_000); // reste de la fenêtre
  expect(onRefresh).toHaveBeenCalledTimes(1);
  await tick(20_000); // fenêtre suivante
  expect(onRefresh).toHaveBeenCalledTimes(2);
});

test('nouvelle référence de onRefresh juste après la frontière : le rafraîchissement n\'est pas perdu', async () => {
  jest.setSystemTime(WINDOW_START + 29_500);
  const first = jest.fn().mockResolvedValue('444444');
  mount({ onRefresh: first });
  // La frontière est franchie, puis le parent fournit une nouvelle fonction (relance de l'effet)
  jest.setSystemTime(WINDOW_START + 30_200);
  const second = jest.fn().mockResolvedValue('555555');
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <TotpDisplayModal secretName="gitlab" totpCode="111111" onClose={() => {}} onCopy={() => {}} period={PERIOD} onRefresh={second} />
      </I18nProvider>
    ));
  });
  await act(async () => { await Promise.resolve(); });
  expect(first.mock.calls.length + second.mock.calls.length).toBe(1);
  expect(code()).toContain('555555');
});

test('réponse tardive d\'une demande plus ancienne : le code le plus récent est conservé', async () => {
  jest.setSystemTime(WINDOW_START + 29_000);
  let resolveSlow;
  const onRefresh = jest.fn()
    .mockImplementationOnce(() => new Promise((resolve) => { resolveSlow = resolve; }))
    .mockResolvedValueOnce('777777');
  mount({ onRefresh });
  await tick(1000); // fenêtre N+1 : demande lente en attente
  jest.setSystemTime(WINDOW_START + 60_000);
  await tick(1000); // fenêtre N+2 : réponse immédiate
  expect(code()).toContain('777777');
  await act(async () => { resolveSlow('666666'); });
  expect(code()).toContain('777777');
});

test('compte à rebours : temps restant affiché d\'après l\'horloge', async () => {
  jest.setSystemTime(WINDOW_START + 12_000);
  mount({ onRefresh: jest.fn().mockResolvedValue('000000') });
  expect(document.body.textContent).toContain('18s');
  await tick(3000);
  expect(document.body.textContent).toContain('15s');
});
