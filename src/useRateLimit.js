// ========================================
// HOOK: Rate Limiting
// ========================================
// Limite le nombre d'appels à une fonction dans un intervalle de temps donné.
//
// Cas d'usage:
// - Recherche en temps réel (debouncing)
// - Copie de mots de passe (throttling)
// - Génération TOTP (throttling)
// - Appels API (rate limiting)
//
// Sécurité:
// - Protection contre abus (DoS local)
// - Évite surcharge CPU/Mémoire
// - Prévient spam d'actions sensibles

import { useRef, useCallback } from 'react';

/**
 * Hook pour debouncing (attendre que l'utilisateur arrête de taper)
 *
 * @param {Function} callback - Fonction à appeler après le délai
 * @param {number} delay - Délai en ms (défaut: 300ms)
 * @returns {Function} Fonction debouncée
 *
 * @example
 * const debouncedSearch = useDebounce(handleSearch, 300);
 */
export function useDebounce(callback, delay = 300) {
  const timeoutRef = useRef(null);

  return useCallback((...args) => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }

    timeoutRef.current = setTimeout(() => {
      callback(...args);
    }, delay);
  }, [callback, delay]);
}

/**
 * Hook pour throttling (limiter la fréquence d'exécution)
 *
 * @param {Function} callback - Fonction à appeler
 * @param {number} limit - Intervalle minimum entre appels en ms (défaut: 1000ms)
 * @returns {Function} Fonction throttlée
 *
 * @example
 * const throttledCopy = useThrottle(handleCopy, 1000);
 */
export function useThrottle(callback, limit = 1000) {
  const lastCallRef = useRef(0);
  const timeoutRef = useRef(null);

  return useCallback((...args) => {
    const now = Date.now();
    const timeSinceLastCall = now - lastCallRef.current;

    if (timeSinceLastCall >= limit) {
      lastCallRef.current = now;
      callback(...args);
    } else {
      // Planifier l'appel pour après le limit
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      timeoutRef.current = setTimeout(() => {
        lastCallRef.current = Date.now();
        callback(...args);
      }, limit - timeSinceLastCall);
    }
  }, [callback, limit]);
}

/**
 * Hook pour rate limiting avec compteur (limite X appels par intervalle)
 *
 * @param {number} maxCalls - Nombre maximum d'appels autorisés
 * @param {number} interval - Intervalle en ms (défaut: 60000ms = 1 minute)
 * @returns {Object} { canCall, registerCall, reset, getRemaining }
 *
 * @example
 * const rateLimit = useRateLimit(10, 60000); // 10 appels/minute
 * if (rateLimit.canCall()) {
 *   rateLimit.registerCall();
 *   doSomething();
 * }
 */
export function useRateLimit(maxCalls = 10, interval = 60000) {
  const callTimesRef = useRef([]);

  const cleanOldCalls = useCallback(() => {
    const now = Date.now();
    callTimesRef.current = callTimesRef.current.filter(time => now - time < interval);
  }, [interval]);

  const canCall = useCallback(() => {
    cleanOldCalls();
    return callTimesRef.current.length < maxCalls;
  }, [maxCalls, cleanOldCalls]);

  const registerCall = useCallback(() => {
    cleanOldCalls();
    if (callTimesRef.current.length < maxCalls) {
      callTimesRef.current.push(Date.now());
      return true;
    }
    return false;
  }, [maxCalls, cleanOldCalls]);

  const reset = useCallback(() => {
    callTimesRef.current = [];
  }, []);

  const getRemaining = useCallback(() => {
    cleanOldCalls();
    return maxCalls - callTimesRef.current.length;
  }, [maxCalls, cleanOldCalls]);

  return { canCall, registerCall, reset, getRemaining };
}
