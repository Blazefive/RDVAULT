// ========================================
// HOOK: Session Timeout avec Auto-déconnexion
// ========================================
// Deux modes de timeout :
// - PC verrouillé pendant plus de 3 heures → auto-déconnexion
// - Inactivité (pas de souris/clavier) pendant 15 minutes → auto-déconnexion

import { useEffect, useRef } from 'react';

/**
 * Hook React pour gérer le timeout de session avec auto-déconnexion
 *
 * @param {Function} onTimeout - Callback appelé lors du timeout (déconnexion)
 * @param {number} lockedTimeoutMs - Durée avant timeout si PC verrouillé (défaut: 3 heures)
 * @param {number} idleTimeoutMs - Durée avant timeout si inactif (défaut: 15 minutes)
 * @param {boolean} enabled - Active/désactive le monitoring (défaut: true)
 */
export function useSessionTimeout(onTimeout, lockedTimeoutMs = 10800000, idleTimeoutMs = 900000, enabled = true) {
  const lockedTimerRef = useRef(null);
  const idleTimerRef = useRef(null);
  const isLockedRef = useRef(false);

  useEffect(() => {
    if (!enabled) return;

    // ========================================
    // INACTIVITY TIMEOUT (15 min sans interaction)
    // ========================================
    const resetIdleTimer = () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      // Ne pas démarrer le timer d'inactivité si le PC est verrouillé (le timer verrouillé prend le relais)
      if (isLockedRef.current) return;
      idleTimerRef.current = setTimeout(() => {
        console.warn('[SessionTimeout] Session expirée (inactivité 15min)');
        onTimeout();
      }, idleTimeoutMs);
    };

    // Écouter les interactions utilisateur
    const activityEvents = ['mousedown', 'keydown', 'mousemove', 'touchstart', 'scroll', 'wheel'];
    activityEvents.forEach(evt => window.addEventListener(evt, resetIdleTimer, { passive: true }));
    resetIdleTimer(); // Démarrer le premier timer

    // ========================================
    // LOCK-SCREEN TIMEOUT (3h verrouillé)
    // ========================================
    const handleLockScreen = () => {
      isLockedRef.current = true;
      // Arrêter le timer d'inactivité (le timer verrouillé prend le relais)
      if (idleTimerRef.current) { clearTimeout(idleTimerRef.current); idleTimerRef.current = null; }
      // Démarrer le timer verrouillé
      if (lockedTimerRef.current) clearTimeout(lockedTimerRef.current);
      lockedTimerRef.current = setTimeout(() => {
        console.warn('[SessionTimeout] Session expirée (PC verrouillé 3h)');
        onTimeout();
      }, lockedTimeoutMs);
    };

    const handleUnlockScreen = () => {
      isLockedRef.current = false;
      if (lockedTimerRef.current) { clearTimeout(lockedTimerRef.current); lockedTimerRef.current = null; }
      // Redémarrer le timer d'inactivité
      resetIdleTimer();
    };

    if (window.electronPowerMonitor) {
      window.electronPowerMonitor.onLockScreen(handleLockScreen);
      window.electronPowerMonitor.onUnlockScreen(handleUnlockScreen);
    }

    // Nettoyage
    return () => {
      if (lockedTimerRef.current) { clearTimeout(lockedTimerRef.current); lockedTimerRef.current = null; }
      if (idleTimerRef.current) { clearTimeout(idleTimerRef.current); idleTimerRef.current = null; }
      activityEvents.forEach(evt => window.removeEventListener(evt, resetIdleTimer));
      if (window.electronPowerMonitor) window.electronPowerMonitor.removeAllListeners();
    };
  }, [onTimeout, lockedTimeoutMs, idleTimeoutMs, enabled]);

  return {
    isLocked: () => isLockedRef.current,
    hasActiveTimer: () => lockedTimerRef.current !== null || idleTimerRef.current !== null
  };
}
