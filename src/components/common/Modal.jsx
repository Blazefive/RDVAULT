// ========================================
// COMPOSANT COMMUN : Modal
// ========================================
// Squelette réutilisable pour les modales simples :
// - Overlay (classe .modal-overlay) + panneau (.modal-panel)
// - Fermeture sur Escape (uniquement par la modale du dessus : une sous-modale ouverte
//   par-dessus garde l'Échap pour elle)
// - Fermeture au clic hors du panneau (mouseDown + mouseUp au même endroit,
//   pour ne pas fermer lors d'une sélection de texte qui déborde de la modale)
// - Titre optionnel (.modal-header), corps (.modal-body), pied optionnel (.modal-footer)
// - Accessibilité (hook useDialogA11y, réutilisable par les modales « maison ») :
//   role="dialog" + aria-modal + aria-labelledby (titre), focus initial dans le panneau,
//   piège de focus (Tab / Maj+Tab bouclent dans la modale), retour du focus à l'élément
//   déclencheur à la fermeture.
//
// Les classes CSS existantes sont réutilisées : aucun changement de style.
//
// Props :
// - title        : contenu du <h2> (omis si undefined) ; sert de nom accessible au dialogue
// - ariaLabel    : nom accessible si aucun titre n'est affiché
// - children     : contenu du corps
// - footer       : contenu du pied de modale (omis si absent)
// - onClose      : callback de fermeture (Escape, clic hors zone)
// - disableClose : si true, Escape et clic hors zone sont ignorés (ex. pendant un chargement)
// - maxWidth     : largeur max du panneau (ex. '460px')
// - panelStyle / overlayStyle / bodyStyle : styles inline additionnels
// - headerExtra  : élément additionnel dans l'en-tête (bouton fermer, etc.)

import React, { useEffect, useId, useRef } from 'react';

const CLICK_TOLERANCE_PX = 5;

// Éléments atteignables au clavier (Tab). tabindex="-1" est exclu de CHAQUE sélecteur : un bouton
// à tabindex itinérant (onglet inactif, élément de menu) reste focalisable par programme mais n'est
// pas dans l'ordre de tabulation. Auparavant, seul le sélecteur générique l'excluait : le piège de
// focus prenait un onglet inactif pour premier / dernier élément et laissait sortir le focus.
const NOT_REMOVED = ':not([tabindex="-1"])';
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  '[contenteditable="true"]',
  '[tabindex]',
].map((selector) => selector + NOT_REMOVED).join(',');

// Élément masqué par un style inline / attribut hidden (jsdom n'a pas de mise en page)
function hiddenByMarkup(el, stop) {
  for (let node = el; node && node !== stop; node = node.parentElement) {
    if (node.hidden || node.getAttribute('aria-hidden') === 'true') return true;
    if (node.style && (node.style.display === 'none' || node.style.visibility === 'hidden')) return true;
  }
  return false;
}

/**
 * Liste ordonnée des éléments focalisables visibles d'un conteneur.
 * Dans un vrai navigateur, un élément sans boîte (display:none, ex. <input type="file"> masqué)
 * est exclu : le focaliser échouerait et laisserait le focus s'échapper de la modale.
 */
export function getFocusableElements(container) {
  if (!container) return [];
  const hasLayout = typeof container.getClientRects === 'function' && container.getClientRects().length > 0;
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR)).filter((el) => {
    if (hiddenByMarkup(el, container)) return false;
    if (hasLayout && el.getClientRects().length === 0) return false;
    return true;
  });
}

/** Vrai si `panel` est le dialogue modal le plus haut (le dernier dans l'ordre du document). */
export function isTopmostDialog(panel) {
  if (!panel || !panel.isConnected) return false;
  const dialogs = document.querySelectorAll('[aria-modal="true"]');
  return dialogs.length > 0 && dialogs[dialogs.length - 1] === panel;
}

function focusElement(el) {
  if (!el || typeof el.focus !== 'function') return;
  try { el.focus({ preventScroll: true }); } catch { el.focus(); }
}

function focusIsLost(panel) {
  const current = document.activeElement;
  return !current || current === document.body || current === document.documentElement
    || !current.isConnected || (panel && panel.contains(current));
}

/**
 * Accessibilité clavier d'un dialogue modal (WAI-ARIA APG « Dialog (Modal) ») :
 * - focus initial dans le panneau (premier élément focalisable, à défaut le panneau lui-même),
 *   sauf si le contenu a déjà placé le focus (autoFocus, focus programmatique) ;
 * - piège de focus : Tab / Maj+Tab bouclent dans le panneau ;
 * - Échap → onEscape, uniquement si ce dialogue est celui du dessus ;
 * - à la fermeture (ou désactivation), focus rendu à l'élément qui l'avait à l'ouverture
 *   s'il existe encore et si le focus n'a pas été placé ailleurs entre-temps.
 *
 * @param {{ current: HTMLElement|null }} panelRef - panneau du dialogue (porte aria-modal="true")
 * @param {Object} [options]
 * @param {boolean} [options.active=true] - dialogue ouvert
 * @param {Function} [options.onEscape] - appelé sur Échap (dialogue du dessus seulement)
 * @param {boolean} [options.escapeDisabled=false] - ignore Échap (ex. chargement en cours)
 */
export function useDialogA11y(panelRef, { active = true, onEscape, escapeDisabled = false } = {}) {
  // Élément focalisé au moment de l'ouverture : capturé pendant le rendu, AVANT que
  // autoFocus ou les effets du contenu ne déplacent le focus dans le dialogue.
  const openerRef = useRef(null);
  const wasActiveRef = useRef(false);
  if (active && !wasActiveRef.current && typeof document !== 'undefined') {
    openerRef.current = document.activeElement;
  }
  wasActiveRef.current = active;

  const onEscapeRef = useRef(onEscape);
  const escapeDisabledRef = useRef(escapeDisabled);
  useEffect(() => {
    onEscapeRef.current = onEscape;
    escapeDisabledRef.current = escapeDisabled;
  });

  useEffect(() => {
    if (!active) return undefined;
    const panel = panelRef.current;
    const opener = openerRef.current;

    // Focus initial (si le contenu ne l'a pas déjà placé dans le panneau)
    if (panel && !panel.contains(document.activeElement)) {
      const [first] = getFocusableElements(panel);
      if (first) focusElement(first);
      else {
        if (!panel.hasAttribute('tabindex')) panel.setAttribute('tabindex', '-1');
        focusElement(panel);
      }
    }

    const onKeyDown = (e) => {
      const current = panelRef.current;
      if (!current || !isTopmostDialog(current)) return;
      if (e.key === 'Escape') {
        if (escapeDisabledRef.current || !onEscapeRef.current) return;
        e.preventDefault();
        onEscapeRef.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const items = getFocusableElements(current);
      const focused = document.activeElement;
      if (items.length === 0) {
        e.preventDefault();
        focusElement(current);
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (!current.contains(focused)) {
        // Focus sorti du dialogue (ex. clic sur le fond) : on le ramène dedans
        e.preventDefault();
        focusElement(e.shiftKey ? last : first);
      } else if (e.shiftKey && (focused === first || focused === current)) {
        e.preventDefault();
        focusElement(last);
      } else if (!e.shiftKey && focused === last) {
        e.preventDefault();
        focusElement(first);
      }
    };
    // Capture : passe avant les champs de saisie (comportement d'Échap inchangé)
    window.addEventListener('keydown', onKeyDown, true);

    return () => {
      window.removeEventListener('keydown', onKeyDown, true);
      // Retour du focus au déclencheur s'il existe encore et que le focus a été perdu
      if (opener && opener !== document.body && opener.isConnected && focusIsLost(panel)) {
        focusElement(opener);
      }
    };
  }, [active, panelRef]);
}

export default function Modal({
  title,
  ariaLabel,
  children,
  footer,
  onClose,
  disableClose = false,
  maxWidth,
  panelStyle,
  overlayStyle,
  bodyStyle,
  headerExtra,
}) {
  const mouseDownPosRef = useRef(null);
  const panelRef = useRef(null);
  const titleId = useId();

  // Focus initial, piège de focus, Échap (modale du dessus), retour du focus
  useDialogA11y(panelRef, { onEscape: onClose, escapeDisabled: disableClose });

  const handleOverlayMouseDown = (e) => {
    if (e.target === e.currentTarget) {
      mouseDownPosRef.current = { x: e.clientX, y: e.clientY };
    }
  };

  const handleOverlayMouseUp = (e) => {
    const start = mouseDownPosRef.current;
    mouseDownPosRef.current = null;
    if (!start || disableClose || e.target !== e.currentTarget) return;
    const deltaX = Math.abs(e.clientX - start.x);
    const deltaY = Math.abs(e.clientY - start.y);
    // Fermer seulement si déplacement < 5px (clic réel, pas drag)
    if (deltaX < CLICK_TOLERANCE_PX && deltaY < CLICK_TOLERANCE_PX) {
      onClose && onClose();
    }
  };

  const computedPanelStyle = {
    ...(maxWidth ? { maxWidth } : {}),
    ...(panelStyle || {}),
  };

  return (
    <div
      className="modal-overlay"
      onMouseDown={handleOverlayMouseDown}
      onMouseUp={handleOverlayMouseUp}
      style={overlayStyle}
    >
      <div
        ref={panelRef}
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={title !== undefined ? titleId : undefined}
        aria-label={title === undefined ? ariaLabel : undefined}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={computedPanelStyle}
      >
        {title !== undefined && (
          <div className="modal-header">
            <h2 id={titleId}>{title}</h2>
            {headerExtra}
          </div>
        )}
        <div className="modal-body" style={bodyStyle}>
          {children}
        </div>
        {footer && (
          <div className="modal-footer">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
