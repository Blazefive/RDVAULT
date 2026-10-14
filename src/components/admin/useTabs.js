// ========================================
// HOOK : useTabs — barre d'onglets accessible (motif WAI-ARIA APG « Tabs », activation automatique)
// ========================================
// Utilisé par le panneau d'administration et par le générateur de mot de passe.
// - tablist / tab (aria-selected, aria-controls) / tabpanel (aria-labelledby) ;
// - tabindex itinérant : seul l'onglet actif est dans l'ordre de tabulation ;
// - flèches gauche / droite (inversées en arabe, dir="rtl"), Début / Fin, avec bouclage :
//   l'onglet atteint est activé et reçoit le focus.
import { useId } from 'react';

/** Sens d'écriture effectif de l'élément (rtl en arabe) */
function isRtl(el) {
  try {
    return typeof window !== 'undefined' && window.getComputedStyle(el).direction === 'rtl';
  } catch {
    return false;
  }
}

/**
 * @param {string[]} keys - clés des onglets affichés, dans l'ordre
 * @param {string} active - clé de l'onglet actif
 * @param {(key: string) => void} onSelect - activation d'un onglet
 * @returns {{ tabProps: (key: string) => Object, panelProps: (key: string) => Object }}
 */
export default function useTabs(keys, active, onSelect) {
  const base = useId();
  const tabId = (key) => `${base}tab-${key}`;
  const panelId = (key) => `${base}panel-${key}`;

  const onKeyDown = (e) => {
    const index = keys.indexOf(active);
    if (index < 0 || keys.length === 0) return;
    const forward = isRtl(e.currentTarget) ? 'ArrowLeft' : 'ArrowRight';
    const backward = forward === 'ArrowRight' ? 'ArrowLeft' : 'ArrowRight';
    let next;
    if (e.key === forward) next = (index + 1) % keys.length;
    else if (e.key === backward) next = (index - 1 + keys.length) % keys.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = keys.length - 1;
    else return;
    e.preventDefault();
    onSelect(keys[next]);
    // Tous les onglets sont rendus : le suivant existe déjà dans le DOM
    if (typeof document !== 'undefined') document.getElementById(tabId(keys[next]))?.focus();
  };

  const tabProps = (key) => {
    const selected = key === active;
    return {
      type: 'button',
      role: 'tab',
      id: tabId(key),
      'aria-selected': selected,
      // Seul le panneau actif est rendu : aria-controls ne désigne jamais un élément absent
      'aria-controls': selected ? panelId(key) : undefined,
      tabIndex: selected ? 0 : -1,
      onClick: () => onSelect(key),
      onKeyDown,
    };
  };

  const panelProps = (key) => ({
    role: 'tabpanel',
    id: panelId(key),
    'aria-labelledby': tabId(key),
  });

  return { tabProps, panelProps };
}
