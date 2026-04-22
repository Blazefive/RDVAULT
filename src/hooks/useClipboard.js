import { useState, useRef } from 'react';

/**
 * Hook useClipboard — gère la copie sécurisée avec auto-effacement
 * @param {Function} showToast - Fonction d'affichage des toasts
 * @param {Function} t - Fonction de traduction i18n
 * @returns {{ clipboardTimer, clearClipboardNow, handleClipboardExpire, startClipboardTimer }}
 */
export function useClipboard(showToast, t) {
  const [clipboardTimer, setClipboardTimer] = useState(null);
  const clipboardTimerRef = useRef(null);

  const clearClipboardNow = async () => {
    if (clipboardTimerRef.current) {
      clearTimeout(clipboardTimerRef.current);
      clipboardTimerRef.current = null;
    }

    try {
      if (window.electronClipboard?.clearNow) {
        await window.electronClipboard.clearNow();
      }
    } catch (err) {}

    setClipboardTimer(null);
    showToast(t('toast.clipboardCleared'), 'info', 1500);
  };

  const handleClipboardExpire = () => {
    setClipboardTimer(null);
  };

  const startClipboardTimer = async (fieldName, text) => {
    if (clipboardTimerRef.current) clearTimeout(clipboardTimerRef.current);

    const duration = 12000;
    const startTime = Date.now();

    // Stocker startTime pour que le composant ClipboardTimer puisse calculer le temps restant de façon stable
    setClipboardTimer({ duration, fieldName, startTime });

    if (window.electronClipboard?.copySecure) {
      try {
        await window.electronClipboard.copySecure(text, duration);
      } catch (err) {
        await navigator.clipboard.writeText(text);
        // SÉCURITÉ: Auto-clear du fallback après la durée
        setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, duration);
      }
    } else {
      await navigator.clipboard.writeText(text);
      // SÉCURITÉ: Auto-clear du fallback après la durée
      setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, duration);
    }

    // Timer de secours pour fermer le composant si nécessaire
    clipboardTimerRef.current = setTimeout(() => {
      setClipboardTimer(null);
    }, duration + 500);
  };

  return { clipboardTimer, clearClipboardNow, handleClipboardExpire, startClipboardTimer };
}
