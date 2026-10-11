// ========================================
// HOOK: Session Timeout avec Auto-déconnexion
// ========================================
// Deux modes de timeout :
// - PC verrouillé pendant plus de 3 heures → auto-déconnexion
// - Inactivité (pas de souris/clavier) pendant 15 minutes → auto-déconnexion

import { useEffect, useRef } from 'react';

export const DEFAULT_LOCKED_TIMEOUT_MS = 10800000; // 3 heures
export const DEFAULT_IDLE_TIMEOUT_MS = 900000;     // 15 minutes
const MIN_TIMEOUT_MS = 60000;                      // 1 minute minimum

/**
 * SÉCURITÉ (défense en profondeur) : garantit qu'une durée de timeout est un
 * nombre fini ≥ 60 s. Toute valeur invalide (booléen, NaN, undefined, trop
 * petite…) retombe sur la valeur par défaut au lieu de désactiver ou de
 * casser le timer.
 */
export function sanitizeTimeoutMs(value, fallback) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= MIN_TIMEOUT_MS) return value;
  return fallback;
}

/**
 * Hook React pour gérer le timeout de session avec auto-déconnexion
 *
 * @param {Function} onTimeout - Callback appelé lors du timeout (déconnexion), avec la cause :
 *   'idle' (inactivité) ou 'locked' (PC verrouillé trop longtemps)
 * @param {number} lockedTimeoutMs - Durée avant timeout si PC verrouillé (défaut: 3 heures)
 * @param {number} idleTimeoutMs - Durée avant timeout si inactif (défaut: 15 minutes)
 * @param {boolean} enabled - Active/désactive le monitoring (défaut: true)
 */
export function useSessionTimeout(onTimeout, lockedTimeoutMs = DEFAULT_LOCKED_TIMEOUT_MS, idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS, enabled = true) {
  const lockedTimerRef = useRef(null);
  const idleTimerRef = useRef(null);
  const isLockedRef = useRef(false);

  // Garde : valeurs invalides → valeurs par défaut
  const safeLockedTimeoutMs = sanitizeTimeoutMs(lockedTimeoutMs, DEFAULT_LOCKED_TIMEOUT_MS);
  const safeIdleTimeoutMs = sanitizeTimeoutMs(idleTimeoutMs, DEFAULT_IDLE_TIMEOUT_MS);

  useEffect(() => {
    if (!enabled) {
      // Session terminée : les écouteurs verrouillage/déverrouillage sont retirés,
      // un déverrouillage ultérieur ne serait donc jamais reçu. Une nouvelle session
      // démarre toujours par une connexion interactive (poste déverrouillé) : ne pas
      // lui transmettre un état « verrouillé » périmé (plus de délai d'inactivité,
      // liens de partage refusés).
      isLockedRef.current = false;
      return;
    }

    // ========================================
    // INACTIVITY TIMEOUT (15 min sans interaction)
    // ========================================
    const resetIdleTimer = () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      // Ne pas démarrer le timer d'inactivité si le PC est verrouillé (le timer verrouillé prend le relais)
      if (isLockedRef.current) return;
      idleTimerRef.current = setTimeout(() => {
        console.warn('[SessionTimeout] Session expirée (inactivité)');
        onTimeout('idle');
      }, safeIdleTimeoutMs);
    };

    // Écouter les interactions utilisateur
    const activityEvents = ['mousedown', 'keydown', 'mousemove', 'touchstart', 'scroll', 'wheel'];
    activityEvents.forEach(evt => window.addEventListener(evt, resetIdleTimer, { passive: true }));

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
        console.warn('[SessionTimeout] Session expirée (PC verrouillé)');
        onTimeout('locked');
      }, safeLockedTimeoutMs);
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

    // Démarrer le premier timer. Si l'effet est relancé pendant que le poste est
    // verrouillé (le nettoyage précédent a annulé le timer verrouillé), réarmer le
    // timer verrouillé : sinon aucun timer ne tournerait jusqu'au déverrouillage.
    if (isLockedRef.current) handleLockScreen();
    else resetIdleTimer();

    // Nettoyage
    return () => {
      if (lockedTimerRef.current) { clearTimeout(lockedTimerRef.current); lockedTimerRef.current = null; }
      if (idleTimerRef.current) { clearTimeout(idleTimerRef.current); idleTimerRef.current = null; }
      activityEvents.forEach(evt => window.removeEventListener(evt, resetIdleTimer));
      if (window.electronPowerMonitor) window.electronPowerMonitor.removeAllListeners();
    };
  }, [onTimeout, safeLockedTimeoutMs, safeIdleTimeoutMs, enabled]);

  return {
    isLocked: () => isLockedRef.current,
    hasActiveTimer: () => lockedTimerRef.current !== null || idleTimerRef.current !== null
  };
}
