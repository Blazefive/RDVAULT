// ========================================
// TESTS : hook useSessionTimeout (timers factices)
// ========================================
// Vérifie la garde sur les durées (≥ 60 s sinon valeur par défaut), le
// timeout d'inactivité, sa réinitialisation sur activité, la désactivation,
// et la bascule inactivité ↔ verrouillage via electronPowerMonitor.

import React, { act, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import {
  useSessionTimeout,
  sanitizeTimeoutMs,
  DEFAULT_IDLE_TIMEOUT_MS,
  DEFAULT_LOCKED_TIMEOUT_MS,
} from './useSessionTimeout';

// Indique à React qu'on est dans un environnement de test avec act()
global.IS_REACT_ACT_ENVIRONMENT = true;

// Rendu / démontage d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const unmountRoot = (reactRoot) => reactRoot.unmount();

describe('sanitizeTimeoutMs', () => {
  it('accepte un nombre fini ≥ 60000', () => {
    expect(sanitizeTimeoutMs(60000, 1)).toBe(60000);
    expect(sanitizeTimeoutMs(900000, 1)).toBe(900000);
  });

  it('retombe sur la valeur par défaut pour toute valeur invalide', () => {
    expect(sanitizeTimeoutMs(59999, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(0, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(-1, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(NaN, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(Infinity, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(true, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs('600000', 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(undefined, 900000)).toBe(900000);
    expect(sanitizeTimeoutMs(null, 900000)).toBe(900000);
  });

  it('expose des valeurs par défaut cohérentes (15 min / 3 h)', () => {
    expect(DEFAULT_IDLE_TIMEOUT_MS).toBe(15 * 60 * 1000);
    expect(DEFAULT_LOCKED_TIMEOUT_MS).toBe(3 * 60 * 60 * 1000);
  });
});

// Composant de test : monte le hook et expose son API via onReady
function Harness({ onTimeout, lockedTimeoutMs, idleTimeoutMs, enabled, onReady }) {
  const api = useSessionTimeout(onTimeout, lockedTimeoutMs, idleTimeoutMs, enabled);
  useEffect(() => { onReady && onReady(api); });
  return null;
}

describe('useSessionTimeout', () => {
  let container;
  let root;
  let warnSpy;

  const mount = (props) => {
    act(() => {
      mountInRoot(root, <Harness {...props} />);
    });
  };

  const advance = (ms) => {
    act(() => {
      jest.advanceTimersByTime(ms);
    });
  };

  const fireActivity = (type = 'mousemove') => {
    act(() => {
      window.dispatchEvent(new Event(type));
    });
  };

  beforeEach(() => {
    jest.useFakeTimers();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    delete window.electronPowerMonitor;
  });

  afterEach(() => {
    act(() => { unmountRoot(root); });
    container.remove();
    delete window.electronPowerMonitor;
    warnSpy.mockRestore();
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it("déconnecte après la durée d'inactivité", () => {
    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 3600000, idleTimeoutMs: 60000, enabled: true });

    advance(59999);
    expect(onTimeout).not.toHaveBeenCalled();
    advance(1);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it("réinitialise le timer d'inactivité sur interaction utilisateur", () => {
    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 3600000, idleTimeoutMs: 60000, enabled: true });

    advance(45000);
    fireActivity('keydown');
    advance(45000); // 90 s au total mais seulement 45 s depuis la dernière activité
    expect(onTimeout).not.toHaveBeenCalled();
    advance(15000);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('ne fait rien quand enabled = false', () => {
    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 3600000, idleTimeoutMs: 60000, enabled: false });

    advance(DEFAULT_LOCKED_TIMEOUT_MS + 1);
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it("retombe sur 15 min si idleTimeoutMs est invalide (< 60 s ou non numérique)", () => {
    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 3600000, idleTimeoutMs: 1000, enabled: true });

    advance(DEFAULT_IDLE_TIMEOUT_MS - 1);
    expect(onTimeout).not.toHaveBeenCalled();
    advance(1);
    expect(onTimeout).toHaveBeenCalledTimes(1);

    // Régression App.jsx : `true` passé à la place de idleTimeoutMs ne doit pas
    // désactiver le timeout d'inactivité (ancienne signature à 3 arguments)
    const onTimeout2 = jest.fn();
    mount({ onTimeout: onTimeout2, lockedTimeoutMs: 3600000, idleTimeoutMs: true, enabled: true });
    advance(DEFAULT_IDLE_TIMEOUT_MS);
    expect(onTimeout2).toHaveBeenCalledTimes(1);
  });

  it('bascule sur le timer verrouillé lors du lock screen, et revient en inactivité au unlock', () => {
    const listeners = {};
    window.electronPowerMonitor = {
      onLockScreen: (cb) => { listeners.lock = cb; },
      onUnlockScreen: (cb) => { listeners.unlock = cb; },
      removeAllListeners: jest.fn(),
    };

    const onTimeout = jest.fn();
    let api = null;
    mount({ onTimeout, lockedTimeoutMs: 120000, idleTimeoutMs: 60000, enabled: true, onReady: (a) => { api = a; } });

    expect(api.isLocked()).toBe(false);

    // Verrouillage : le timer d'inactivité est arrêté
    act(() => { listeners.lock(); });
    expect(api.isLocked()).toBe(true);
    advance(60000);
    expect(onTimeout).not.toHaveBeenCalled();

    // Déverrouillage avant expiration du timer verrouillé : pas de déconnexion
    act(() => { listeners.unlock(); });
    expect(api.isLocked()).toBe(false);
    advance(59999);
    expect(onTimeout).not.toHaveBeenCalled(); // timer verrouillé annulé (≈120 s écoulées au total)

    // Le timer d'inactivité a redémarré au unlock : expiration 60 s après
    advance(1);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('déconnecte après lockedTimeoutMs si le PC reste verrouillé', () => {
    const listeners = {};
    window.electronPowerMonitor = {
      onLockScreen: (cb) => { listeners.lock = cb; },
      onUnlockScreen: (cb) => { listeners.unlock = cb; },
      removeAllListeners: jest.fn(),
    };

    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 120000, idleTimeoutMs: 60000, enabled: true });

    act(() => { listeners.lock(); });
    advance(119999);
    expect(onTimeout).not.toHaveBeenCalled();
    advance(1);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  // SESSION-13 : après une expiration « PC verrouillé », la session se termine
  // (enabled=false → écouteurs retirés) : le déverrouillage Windows n'est donc
  // plus reçu. La session suivante ne doit pas hériter de l'état « verrouillé »
  // (sinon aucun délai d'inactivité n'est armé et isLocked() reste vrai).
  it("réarme l'inactivité à la session suivante après une expiration « PC verrouillé »", () => {
    const listeners = {};
    window.electronPowerMonitor = {
      onLockScreen: (cb) => { listeners.lock = cb; },
      onUnlockScreen: (cb) => { listeners.unlock = cb; },
      removeAllListeners: () => { listeners.lock = null; listeners.unlock = null; },
    };
    const onTimeout = jest.fn();
    let api = null;
    const props = { onTimeout, lockedTimeoutMs: 120000, idleTimeoutMs: 60000, onReady: (a) => { api = a; } };

    mount({ ...props, enabled: true });
    act(() => { listeners.lock(); });
    advance(120000);
    expect(onTimeout).toHaveBeenCalledTimes(1);

    // Session terminée : plus d'écouteur, le déverrouillage du matin n'est pas reçu
    mount({ ...props, enabled: false });
    expect(listeners.unlock).toBeNull();

    // Reconnexion : le poste est forcément déverrouillé (connexion interactive)
    mount({ ...props, enabled: true });
    expect(api.isLocked()).toBe(false);
    expect(api.hasActiveTimer()).toBe(true);
    advance(60000);
    expect(onTimeout).toHaveBeenCalledTimes(2);
  });

  it('indique la cause de l\'expiration (inactivité ou poste verrouillé)', () => {
    const listeners = {};
    window.electronPowerMonitor = {
      onLockScreen: (cb) => { listeners.lock = cb; },
      onUnlockScreen: (cb) => { listeners.unlock = cb; },
      removeAllListeners: jest.fn(),
    };
    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 120000, idleTimeoutMs: 60000, enabled: true });
    advance(60000);
    expect(onTimeout).toHaveBeenLastCalledWith('idle');
    act(() => { listeners.lock(); });
    advance(120000);
    expect(onTimeout).toHaveBeenLastCalledWith('locked');
  });

  it('conserve le délai « verrouillé » si l\'effet est relancé pendant le verrouillage', () => {
    const listeners = {};
    window.electronPowerMonitor = {
      onLockScreen: (cb) => { listeners.lock = cb; },
      onUnlockScreen: (cb) => { listeners.unlock = cb; },
      removeAllListeners: () => { listeners.lock = null; listeners.unlock = null; },
    };
    const onTimeout = jest.fn();
    const onTimeout2 = jest.fn();
    let api = null;
    mount({ onTimeout, lockedTimeoutMs: 120000, idleTimeoutMs: 60000, enabled: true, onReady: (a) => { api = a; } });
    act(() => { listeners.lock(); });
    // Nouvelle référence de callback pendant le verrouillage : l'effet est relancé
    mount({ onTimeout: onTimeout2, lockedTimeoutMs: 120000, idleTimeoutMs: 60000, enabled: true, onReady: (a) => { api = a; } });
    expect(api.isLocked()).toBe(true);
    expect(api.hasActiveTimer()).toBe(true);
    advance(120000);
    expect(onTimeout2).toHaveBeenCalledTimes(1);
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it('nettoie les timers et les listeners au démontage', () => {
    window.electronPowerMonitor = {
      onLockScreen: jest.fn(),
      onUnlockScreen: jest.fn(),
      removeAllListeners: jest.fn(),
    };
    const onTimeout = jest.fn();
    mount({ onTimeout, lockedTimeoutMs: 3600000, idleTimeoutMs: 60000, enabled: true });

    act(() => { unmountRoot(root); });
    // Nouveau root pour que l'afterEach puisse démonter proprement
    root = createRoot(container);

    expect(window.electronPowerMonitor.removeAllListeners).toHaveBeenCalled();
    advance(60000);
    expect(onTimeout).not.toHaveBeenCalled();
  });
});
