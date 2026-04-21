// ========================================
// HOOK: Session Timeout avec Auto-déconnexion
// ========================================
// Timeout de session basé sur le verrouillage du PC:
// - PC verrouillé pendant plus de 3 heures → auto-déconnexion
//
// Sécurité:
// - Protection contre abandon de poste verrouillé
// - Basé sur les événements système (lock-screen/unlock-screen)

import { useEffect, useRef } from 'react';

/**
 * Hook React pour gérer le timeout de session avec auto-déconnexion
 *
 * @param {Function} onTimeout - Callback appelé lors du timeout (déconnexion)
 * @param {number} lockedTimeoutMs - Durée avant timeout si PC verrouillé (défaut: 3 heures)
 * @param {boolean} enabled - Active/désactive le monitoring (défaut: true)
 */
export function useSessionTimeout(onTimeout, lockedTimeoutMs = 10800000, enabled = true) {
  const timeoutRef = useRef(null);
  const isLockedRef = useRef(false);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    // Fonction pour démarrer le timer verrouillé
    const startLockedTimer = () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }

      if (!isLockedRef.current) return;

      timeoutRef.current = setTimeout(() => {
        console.warn('[SessionTimeout] Session expirée (PC verrouillé 3h)');
        onTimeout();
      }, lockedTimeoutMs);
    };

    // SÉCURITÉ: Détecter verrouillage/déverrouillage du PC
    const handleLockScreen = () => {
      isLockedRef.current = true;
      startLockedTimer();
    };

    const handleUnlockScreen = () => {
      isLockedRef.current = false;
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };

    // Écouter les événements de verrouillage (via Electron)
    if (window.electronPowerMonitor) {
      window.electronPowerMonitor.onLockScreen(handleLockScreen);
      window.electronPowerMonitor.onUnlockScreen(handleUnlockScreen);
    }

    // Nettoyage au démontage
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      if (window.electronPowerMonitor) {
        window.electronPowerMonitor.removeAllListeners();
      }
    };
  }, [onTimeout, lockedTimeoutMs, enabled]);

  return {
    isLocked: () => isLockedRef.current,
    hasActiveTimer: () => timeoutRef.current !== null
  };
}
