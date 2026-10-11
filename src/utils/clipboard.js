// ========================================
// UTILITAIRE PRESSE-PAPIERS SÉCURISÉ
// ========================================
// Copie un texte dans le presse-papiers avec effacement automatique.
// - Passe par window.electronClipboard.copySecure(text, duration) quand disponible
//   (l'effacement est alors géré côté Electron)
// - Sinon fallback navigator.clipboard + effacement après `duration` ms
//
// SÉCURITÉ : la durée par défaut est de 12 s, imposée partout dans l'application.

export const CLIPBOARD_AUTO_CLEAR_MS = 12000;

/**
 * Copie sécurisée avec auto-effacement.
 * @param {string} text - Texte à copier
 * @param {number} [duration=CLIPBOARD_AUTO_CLEAR_MS] - Durée avant effacement (ms)
 * @returns {Promise<void>}
 */
export async function copySecureWithAutoClear(text, duration = CLIPBOARD_AUTO_CLEAR_MS) {
  const value = String(text ?? '');

  const fallback = async () => {
    await navigator.clipboard.writeText(value);
    // SÉCURITÉ : auto-effacement du fallback après la durée
    setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, duration);
  };

  if (window.electronClipboard?.copySecure) {
    try {
      await window.electronClipboard.copySecure(value, duration);
      return;
    } catch {
      // Le canal Electron a échoué → fallback navigateur
    }
  }
  await fallback();
}
