import React, { useState, useRef } from 'react';

/**
 * Composant Toast — affiche un message temporaire
 */
export function Toast({ toast }) {
  if (!toast?.visible) return null;
  return (
    <div
      className={`toast toast-${toast.type}`}
      style={{ pointerEvents: 'none' }}
      tabIndex={-1}
      aria-live="polite"
      aria-atomic="true"
    >
      {toast.message}
    </div>
  );
}

/**
 * Hook useToast — gère l'état et l'affichage des toasts
 * @returns {{ toast: Object, showToast: Function }}
 */
export function useToast() {
  const [toast, setToast] = useState({ visible: false, type: 'info', message: '' });
  const toastTimer = useRef(null);

  const showToast = (message, type = 'info', duration = 2300) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ visible: true, type, message });
    toastTimer.current = setTimeout(() => setToast(t => ({ ...t, visible: false })), duration);
  };

  return { toast, showToast };
}
