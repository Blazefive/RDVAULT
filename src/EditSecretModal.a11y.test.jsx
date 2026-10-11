// ========================================
// TESTS : accessibilité de EditSecretModal (rendu réel react-dom dans jsdom)
// ========================================
// - A11Y-25 : Échap ou clic sur le fond du générateur de mot de passe ne ferme QUE le générateur
//             (la fiche et sa saisie non enregistrée restent).
// - A11Y-26 : nom accessible du dialogue, focus dans le générateur puis retour au bouton.
// - A11Y-28 : boutons-icônes (×, ⬇) nommés.
// - A11Y-29 : libellés associés aux champs (htmlFor/id).
// - « Ajouter une pièce jointe » : vrai bouton, atteignable et activable au clavier.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'crypto';
import EditSecretModal from './EditSecretModal';
import { getFocusableElements } from './components/common/Modal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Le générateur utilise crypto.getRandomValues (absent de jsdom)
if (!global.crypto || !global.crypto.getRandomValues) {
  Object.defineProperty(global, 'crypto', { value: webcrypto, configurable: true });
}

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(props) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <EditSecretModal initial={null} onClose={() => {}} onSave={() => {}} {...props} />
      </I18nProvider>
    ));
  });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts })); });
};
const buttonByText = (txt) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
const panels = () => document.querySelectorAll('.modal-panel');
const nameInput = () => document.querySelector('input.modal-input');
// Contrôle associé à un libellé (équivalent getByLabelText)
const controlForLabel = (text) => {
  const label = Array.from(document.querySelectorAll('label')).find(l => l.textContent.trim() === text);
  if (!label) return null;
  return label.htmlFor ? document.getElementById(label.htmlFor) : label.querySelector('input, textarea, select');
};
// Clic réel : mousedown, mouseup et click sont des tâches distinctes (rendu React entre chacune)
const clickAt = (el) => {
  for (const type of ['mousedown', 'mouseup', 'click']) {
    act(() => { el.dispatchEvent(new MouseEvent(type, { bubbles: true, clientX: 8, clientY: 300 })); });
  }
};

describe('A11Y-25 — sous-modale « Générateur de mot de passe »', () => {
  test('Échap dans le générateur ne ferme que le générateur (saisie conservée)', () => {
    const onClose = jest.fn();
    mount({ onClose });
    nameInput().value = 'brouillon-important';
    act(() => { buttonByText(en.editSecret.generatePassword).click(); });
    expect(panels().length).toBe(2);
    press('Escape');
    expect(onClose).not.toHaveBeenCalled();
    expect(panels().length).toBe(1);
    expect(nameInput().value).toBe('brouillon-important');
    // Second Échap : la fiche se ferme normalement
    press('Escape');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('clic sur le fond du générateur : la fiche reste ouverte', () => {
    const onClose = jest.fn();
    mount({ onClose });
    act(() => { buttonByText(en.editSecret.generatePassword).click(); });
    const overlays = document.querySelectorAll('.modal-overlay');
    expect(overlays.length).toBe(2);
    clickAt(overlays[1]);
    expect(onClose).not.toHaveBeenCalled();
    expect(panels().length).toBe(1);
  });

  test('clic sur le fond de la fiche : fermeture (comportement conservé)', () => {
    const onClose = jest.fn();
    mount({ onClose });
    clickAt(document.querySelector('.modal-overlay'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('focus déplacé dans le générateur puis rendu au bouton « Générer... » à sa fermeture', () => {
    mount({});
    const genButton = buttonByText(en.editSecret.generatePassword);
    genButton.focus();
    act(() => { genButton.click(); });
    expect(panels()[1].contains(document.activeElement)).toBe(true);
    press('Escape');
    expect(document.activeElement).toBe(genButton);
  });
});

describe('A11Y-26 — dialogue nommé', () => {
  test('aria-labelledby désigne le titre « New entry »', () => {
    mount({});
    const dialog = panels()[0];
    expect(dialog.getAttribute('role')).toBe('dialog');
    expect(document.getElementById(dialog.getAttribute('aria-labelledby')).textContent.trim()).toBe(en.editSecret.newEntry);
  });
});

describe('A11Y-29 — libellés associés aux champs', () => {
  test.each([
    ['name', 'INPUT'],
    ['username', 'INPUT'],
    ['password', 'INPUT'],
    ['url', 'INPUT'],
    ['notes', 'TEXTAREA'],
    ['tags', 'INPUT'],
  ])('libellé editSecret.%s → champ associé', (key, tag) => {
    mount({});
    const control = controlForLabel(en.editSecret[key]);
    expect(control).not.toBeNull();
    expect(control.tagName).toBe(tag);
  });

  test('clés SSH : clé privée, clé publique, phrase de passe associées', () => {
    mount({ initial: { name: 'srv', entryType: 'ssh', password: 'k', url: 'p', username: '' } });
    expect(controlForLabel(en.editSecret.privateKey)?.tagName).toBe('TEXTAREA');
    expect(controlForLabel(en.editSecret.publicKey)?.tagName).toBe('TEXTAREA');
    expect(controlForLabel(en.editSecret.passphrase)?.tagName).toBe('INPUT');
  });

  test('groupe radio « Type d\'entrée » nommé', () => {
    mount({});
    const group = document.querySelector('[role="radiogroup"]');
    expect(group).not.toBeNull();
    expect(document.getElementById(group.getAttribute('aria-labelledby')).textContent.trim()).toBe(en.editSecret.entryType);
  });
});

describe('A11Y-28 — boutons-icônes nommés', () => {
  test('suppression d\'un champ personnalisé : nom « Remove field »', () => {
    mount({});
    act(() => { buttonByText(`+ ${en.editSecret.addField}`).click(); });
    const remove = Array.from(document.querySelectorAll('button')).find(b => b.getAttribute('aria-label') === en.editSecret.removeField);
    expect(remove).toBeDefined();
  });

  test('pièce jointe : boutons Télécharger / Retirer nommés avec le fichier', () => {
    mount({ initial: { name: 'srv', attachments: [{ name: 'cle.pem', size: 10, type: 'text/plain', data: 'eA==' }] } });
    const labels = Array.from(document.querySelectorAll('button')).map(b => b.getAttribute('aria-label'));
    expect(labels).toContain(en.editSecret.downloadAttachment.replace('{{name}}', 'cle.pem'));
    expect(labels).toContain(en.editSecret.removeAttachment.replace('{{name}}', 'cle.pem'));
  });
});

describe('Pièces jointes — « Ajouter une pièce jointe » atteignable au clavier', () => {
  // Avant : <label> stylé en bouton autour d'un <input type="file"> masqué (display:none) —
  // ni le libellé ni le champ n'étaient focalisables, impossible d'ajouter un fichier au clavier.
  test('vrai <button type="button"> dans le cycle de tabulation de la fiche', () => {
    mount({});
    const add = buttonByText(`+ ${en.editSecret.addAttachment}`);
    expect(add).toBeDefined();
    expect(add.getAttribute('type')).toBe('button');
    expect(getFocusableElements(panels()[0])).toContain(add);
    add.focus();
    expect(document.activeElement).toBe(add);
  });

  test('activation du bouton (Entrée / Espace = click) : ouvre le sélecteur de fichier masqué', () => {
    const onClose = jest.fn();
    const onSave = jest.fn();
    mount({ onClose, onSave });
    const input = document.querySelector('input[type="file"]');
    expect(input).not.toBeNull();
    const pick = jest.spyOn(input, 'click').mockImplementation(() => {});
    act(() => { buttonByText(`+ ${en.editSecret.addAttachment}`).click(); });
    expect(pick).toHaveBeenCalledTimes(1);
    // Ni enregistrement ni fermeture de la fiche
    expect(onSave).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  test('fichier choisi : ajouté à la liste des pièces jointes', async () => {
    mount({});
    const input = document.querySelector('input[type="file"]');
    const file = new File(['bonjour'], 'notes.txt', { type: 'text/plain' });
    Object.defineProperty(input, 'files', { value: [file], configurable: true });
    await act(async () => {
      input.dispatchEvent(new Event('change', { bubbles: true }));
      await new Promise(r => setTimeout(r, 50)); // FileReader asynchrone
    });
    const labels = Array.from(document.querySelectorAll('button')).map(b => b.getAttribute('aria-label'));
    expect(labels).toContain(en.editSecret.removeAttachment.replace('{{name}}', 'notes.txt'));
  });
});
