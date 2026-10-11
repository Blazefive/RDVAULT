// ========================================
// TESTS : accessibilité du squelette commun Modal (rendu réel react-dom dans jsdom)
// ========================================
// A11Y-26 : focus initial dans le panneau, piège de focus (Tab / Maj+Tab), nom accessible
// (aria-labelledby = titre), retour du focus à l'élément déclencheur, Échap réservé à la
// modale du dessus (une sous-modale ne ferme pas sa modale parente).

import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import Modal from './Modal';
import ConfirmModal from '../../ConfirmModal';
import { I18nProvider } from '../../i18n';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(element) {
  localStorage.setItem('rdvault-lang', 'fr');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
  return { host, root };
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

// Touche clavier envoyée à l'élément actif (comme le ferait le navigateur)
const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts });
  act(() => { target.dispatchEvent(ev); });
  return ev;
};
// Nom accessible (sous-ensemble suffisant de l'algorithme accname)
const accessibleName = (el) => {
  const labelledby = el.getAttribute('aria-labelledby');
  if (labelledby) return labelledby.split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ').trim();
  return (el.getAttribute('aria-label') || el.textContent || '').trim();
};
const btn = (txt) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === txt);

describe('Modal — rôle et nom accessible', () => {
  test('role="dialog", aria-modal et nom accessible égal au titre', () => {
    mount(<Modal title="Supprimer l'entrée" onClose={() => {}} footer={<button type="button">OK</button>}>corps</Modal>);
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(accessibleName(dialog)).toBe("Supprimer l'entrée");
  });
});

describe('Modal — focus initial et piège de focus', () => {
  const footer = (
    <>
      <button type="button">Annuler</button>
      <button type="button">Supprimer</button>
    </>
  );

  test('à l\'ouverture, le focus est placé dans le panneau (premier élément focalisable)', () => {
    const opener = document.createElement('button');
    opener.textContent = 'ouvrir';
    document.body.appendChild(opener);
    opener.focus();
    mount(<Modal title="T" onClose={() => {}} footer={footer}>message</Modal>);
    const panel = document.querySelector('.modal-panel');
    expect(panel.contains(document.activeElement)).toBe(true);
    expect(document.activeElement.textContent).toBe('Annuler');
  });

  test('un champ autoFocus du contenu garde le focus', () => {
    mount(<Modal title="T" onClose={() => {}} footer={footer}><input autoFocus aria-label="nom" /></Modal>);
    expect(document.activeElement.getAttribute('aria-label')).toBe('nom');
  });

  test('Tab depuis le dernier élément revient au premier ; Maj+Tab depuis le premier va au dernier', () => {
    mount(<Modal title="T" onClose={() => {}} footer={footer}>message</Modal>);
    btn('Supprimer').focus();
    const ev = press('Tab');
    expect(ev.defaultPrevented).toBe(true);
    expect(document.activeElement.textContent).toBe('Annuler');
    const ev2 = press('Tab', { shiftKey: true });
    expect(ev2.defaultPrevented).toBe(true);
    expect(document.activeElement.textContent).toBe('Supprimer');
  });

  test('focus sorti de la modale (arrière-plan) : Tab le ramène dans le panneau', () => {
    const background = document.createElement('button');
    background.textContent = 'Nouveau coffre';
    document.body.appendChild(background);
    mount(<Modal title="T" onClose={() => {}} footer={footer}>message</Modal>);
    background.focus();
    press('Tab');
    expect(document.querySelector('.modal-panel').contains(document.activeElement)).toBe(true);
  });

  test('les éléments masqués (display:none) ne font pas partie du cycle', () => {
    mount(
      <Modal title="T" onClose={() => {}} footer={footer}>
        <input type="file" style={{ display: 'none' }} aria-label="fichier" />
      </Modal>
    );
    btn('Supprimer').focus();
    press('Tab');
    expect(document.activeElement.textContent).toBe('Annuler');
  });
});

describe('Modal — retour du focus à l\'élément déclencheur', () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button type="button" onClick={() => setOpen(true)}>Déclencheur</button>
        {open && (
          <Modal title="T" onClose={() => setOpen(false)} footer={<button type="button" onClick={() => setOpen(false)}>Fermer</button>}>x</Modal>
        )}
      </>
    );
  }

  test('fermeture (bouton) : le focus revient au déclencheur', () => {
    mount(<Harness />);
    const trigger = btn('Déclencheur');
    trigger.focus();
    act(() => { trigger.click(); });
    expect(document.querySelector('.modal-panel').contains(document.activeElement)).toBe(true);
    act(() => { btn('Fermer').click(); });
    expect(document.querySelector('.modal-panel')).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  test('fermeture par Échap : le focus revient au déclencheur', () => {
    mount(<Harness />);
    const trigger = btn('Déclencheur');
    trigger.focus();
    act(() => { trigger.click(); });
    press('Escape');
    expect(document.querySelector('.modal-panel')).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});

describe('Modal — Échap réservé à la modale du dessus', () => {
  test('une sous-modale ouverte : Échap ne ferme qu\'elle', () => {
    const outerClose = jest.fn();
    const innerClose = jest.fn();
    mount(
      <Modal title="Parent" onClose={outerClose}>
        <Modal title="Enfant" onClose={innerClose}>y</Modal>
      </Modal>
    );
    press('Escape');
    expect(innerClose).toHaveBeenCalledTimes(1);
    expect(outerClose).not.toHaveBeenCalled();
  });

  test('disableClose : Échap ignoré', () => {
    const onClose = jest.fn();
    mount(<Modal title="T" onClose={onClose} disableClose>x</Modal>);
    press('Escape');
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe('ConfirmModal (squelette Modal)', () => {
  test('focus initial sur « Annuler » (action sûre) ; nom accessible = titre', () => {
    const onCancel = jest.fn();
    const onConfirm = jest.fn();
    mount(<ConfirmModal title="Supprimer l'entrée" message="Sûr ?" confirmLabel="Supprimer" cancelLabel="Annuler" danger onCancel={onCancel} onConfirm={onConfirm} />);
    expect(document.activeElement.textContent).toBe('Annuler');
    expect(accessibleName(document.querySelector('[role="dialog"]'))).toBe("Supprimer l'entrée");
  });
});
