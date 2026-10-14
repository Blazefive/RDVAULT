// ========================================
// TESTS : Paramètres › Sécurité — délai de verrouillage automatique
// ========================================
// - choix proposés (1 min → 4 h), 15 min par défaut ;
// - le choix est mémorisé et appliqué aussitôt au minuteur d'inactivité (useSessionTimeout) ;
// - une valeur stockée invalide retombe sur 15 min (jamais « pas de verrouillage »).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecurityTab from './SecurityTab';
import { I18nProvider } from '../../i18n';
import fr from '../../locales/fr.json';
import {
  IDLE_TIMEOUT_STORAGE_KEY,
  getIdleTimeoutMinutes,
  setIdleTimeoutMinutes,
  useIdleTimeoutMs,
} from '../../hooks/useIdleTimeout';
import { useSessionTimeout, DEFAULT_LOCKED_TIMEOUT_MS } from '../../useSessionTimeout';

global.IS_REACT_ACT_ENVIRONMENT = true;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let roots = [];
function mount(element) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, element); });
  roots.push(root);
  return host;
}
afterEach(() => {
  roots.forEach((r) => act(() => r.unmount()));
  roots = [];
  document.body.innerHTML = '';
  localStorage.clear();
  jest.useRealTimers();
});

test('valeur par défaut 15 min ; valeurs stockées invalides ignorées', () => {
  expect(getIdleTimeoutMinutes()).toBe(15);
  for (const bad of ['0', '-5', '7', 'abc', '1e9', '', ' 30', '99999']) {
    localStorage.setItem(IDLE_TIMEOUT_STORAGE_KEY, bad);
    expect(getIdleTimeoutMinutes()).toBe(15);
  }
  localStorage.setItem(IDLE_TIMEOUT_STORAGE_KEY, '60');
  expect(getIdleTimeoutMinutes()).toBe(60);
  expect(setIdleTimeoutMinutes(7)).toBe(false);
  expect(localStorage.getItem(IDLE_TIMEOUT_STORAGE_KEY)).toBe('60');
});

test('onglet : liste des délais traduite, 15 min sélectionné par défaut, choix mémorisé', () => {
  localStorage.setItem('rdvault-lang', 'fr');
  const host = mount(<I18nProvider><SecurityTab /></I18nProvider>);
  const select = host.querySelector('[data-testid="idle-timeout-select"]');
  // Libellé relié au champ (nom accessible)
  expect(select.labels[0].textContent).toBe(fr.settings.autoLockLabel);
  const options = Array.from(select.options).map((o) => o.textContent);
  expect(options).toEqual([
    '1 minute', '5 minutes', '10 minutes', `15 minutes (${fr.settings.autoLockDefault})`,
    '30 minutes', '1 heure', '2 heures', '4 heures',
  ]);
  expect(select.value).toBe('15');

  act(() => {
    select.value = '60';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  expect(select.value).toBe('60');
  expect(localStorage.getItem(IDLE_TIMEOUT_STORAGE_KEY)).toBe('60');
});

test('un nouveau délai réarme aussitôt le minuteur d\'inactivité de la session', () => {
  jest.useFakeTimers();
  const onTimeout = jest.fn();
  function Probe() {
    const idleMs = useIdleTimeoutMs();
    useSessionTimeout(onTimeout, DEFAULT_LOCKED_TIMEOUT_MS, idleMs, true);
    return null;
  }
  mount(<Probe />);

  // Défaut : rien à 14 min 59 s
  act(() => { jest.advanceTimersByTime(14 * 60000 + 59000); });
  expect(onTimeout).not.toHaveBeenCalled();

  // Passage à 5 min : le minuteur repart de zéro avec le nouveau délai
  act(() => { setIdleTimeoutMinutes(5); });
  act(() => { jest.advanceTimersByTime(4 * 60000 + 59000); });
  expect(onTimeout).not.toHaveBeenCalled();
  act(() => { jest.advanceTimersByTime(2000); });
  expect(onTimeout).toHaveBeenCalledWith('idle');
});
