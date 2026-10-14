// ========================================
// HOOK : délai de verrouillage automatique (inactivité) choisi par l'utilisateur
// ========================================
// Paramètres › Sécurité : l'utilisateur choisit le délai sans activité dans RDVAULT au bout duquel
// la session est fermée (useSessionTimeout). Préférence du poste (comme le thème), conservée après
// la déconnexion. Seules les valeurs de la liste fermée sont acceptées : une valeur absente,
// modifiée à la main ou invalide retombe sur 15 minutes (valeur historique), jamais sur « aucun
// verrouillage ».

import { useEffect, useState } from 'react';

export const IDLE_TIMEOUT_STORAGE_KEY = 'rdvault-idle-timeout-min';
export const IDLE_TIMEOUT_CHANGED_EVENT = 'rdvault-idle-timeout-changed';
// Choix proposés, en minutes (4 h au plus : un gestionnaire de mots de passe ne reste pas ouvert indéfiniment)
export const IDLE_TIMEOUT_CHOICES_MIN = Object.freeze([1, 5, 10, 15, 30, 60, 120, 240]);
export const DEFAULT_IDLE_TIMEOUT_MIN = 15;

/** Délai enregistré, en minutes (valeur de la liste, sinon 15). */
export function getIdleTimeoutMinutes() {
  try {
    const raw = localStorage.getItem(IDLE_TIMEOUT_STORAGE_KEY);
    if (raw !== null && /^\d{1,4}$/.test(raw)) {
      const value = Number(raw);
      if (IDLE_TIMEOUT_CHOICES_MIN.includes(value)) return value;
    }
  } catch { /* stockage indisponible : valeur par défaut */ }
  return DEFAULT_IDLE_TIMEOUT_MIN;
}

/**
 * Enregistre un nouveau délai (minutes) et prévient l'application, qui réarme aussitôt le minuteur.
 * @returns {boolean} false si la valeur n'est pas dans la liste (rien n'est modifié)
 */
export function setIdleTimeoutMinutes(minutes) {
  if (!IDLE_TIMEOUT_CHOICES_MIN.includes(minutes)) return false;
  try { localStorage.setItem(IDLE_TIMEOUT_STORAGE_KEY, String(minutes)); } catch { /* ignoré */ }
  try { window.dispatchEvent(new CustomEvent(IDLE_TIMEOUT_CHANGED_EVENT, { detail: minutes })); } catch { /* ignoré */ }
  return true;
}

/** Délai d'inactivité courant en millisecondes, mis à jour quand il change dans les Paramètres. */
export function useIdleTimeoutMs() {
  const [minutes, setMinutes] = useState(getIdleTimeoutMinutes);
  useEffect(() => {
    const refresh = () => setMinutes(getIdleTimeoutMinutes());
    window.addEventListener(IDLE_TIMEOUT_CHANGED_EVENT, refresh);
    window.addEventListener('storage', refresh);
    return () => {
      window.removeEventListener(IDLE_TIMEOUT_CHANGED_EVENT, refresh);
      window.removeEventListener('storage', refresh);
    };
  }, []);
  return minutes * 60000;
}
