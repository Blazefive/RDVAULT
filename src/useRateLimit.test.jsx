// ========================================
// TESTS : useDebounce / useThrottle — annulation et nettoyage au démontage (vague F)
// ========================================
// Avant : aucun moyen d'annuler l'appel en attente et aucun nettoyage au démontage : le rappel
// s'exécutait après la disparition du composant (setState sur un composant démonté, recherche
// appliquée après une déconnexion…).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useDebounce, useThrottle } from './useRateLimit';

global.IS_REACT_ACT_ENVIRONMENT = true;

const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function renderHook(useHook) {
  const result = { current: null };
  function Harness() { result.current = useHook(); return null; }
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <Harness />); });
  return {
    result,
    rerender: () => act(() => { mountInRoot(root, <Harness />); }),
    unmount: () => act(() => { root.unmount(); }),
  };
}

beforeEach(() => { jest.useFakeTimers(); });
afterEach(() => {
  jest.useRealTimers();
  document.body.innerHTML = '';
});

describe('useDebounce', () => {
  test('un seul appel, avec les derniers arguments, après le délai', () => {
    const cb = jest.fn();
    const { result } = renderHook(() => useDebounce(cb, 300));
    result.current('a');
    result.current('ab');
    act(() => { jest.advanceTimersByTime(299); });
    expect(cb).not.toHaveBeenCalled();
    act(() => { jest.advanceTimersByTime(1); });
    expect(cb).toHaveBeenCalledTimes(1);
    expect(cb).toHaveBeenCalledWith('ab');
  });

  test('cancel() annule l\'appel en attente ; un nouvel appel reste possible', () => {
    const cb = jest.fn();
    const { result } = renderHook(() => useDebounce(cb, 300));
    expect(typeof result.current.cancel).toBe('function');
    result.current('x');
    result.current.cancel();
    act(() => { jest.advanceTimersByTime(1000); });
    expect(cb).not.toHaveBeenCalled();
    result.current('y');
    act(() => { jest.advanceTimersByTime(300); });
    expect(cb).toHaveBeenCalledWith('y');
  });

  test('démontage : l\'appel en attente n\'est jamais exécuté', () => {
    const cb = jest.fn();
    const { result, unmount } = renderHook(() => useDebounce(cb, 300));
    result.current('après-démontage');
    unmount();
    act(() => { jest.advanceTimersByTime(1000); });
    expect(cb).not.toHaveBeenCalled(); // avant : appelé après le démontage
  });

  test('fonction stable tant que le rappel et le délai ne changent pas', () => {
    const cb = jest.fn();
    const { result, rerender } = renderHook(() => useDebounce(cb, 300));
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });
});

describe('useThrottle', () => {
  test('démontage : l\'appel différé en attente n\'est jamais exécuté', () => {
    const cb = jest.fn();
    const { result, unmount } = renderHook(() => useThrottle(cb, 1000));
    result.current(1); // immédiat
    result.current(2); // différé
    expect(cb).toHaveBeenCalledTimes(1);
    unmount();
    act(() => { jest.advanceTimersByTime(2000); });
    expect(cb).toHaveBeenCalledTimes(1);
  });
});
