// ========================================
// TESTS : MoveToFolderModal et ShareRbiModal (squelette Modal, libellés traduits)
// ========================================
// - Déplacement : plus de texte français en dur (« Aucun sous-dossier », « (dossier actuel) »,
//   « Destination : », infobulle) ; fil d'Ariane avec aria-current.
// - Partage RBI : squelette commun (dialogue nommé, Échap), champ ID associé à son libellé,
//   options exposées comme boutons bascule (aria-pressed), erreur annoncée (role="alert").

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MoveToFolderModal from './MoveToFolderModal';
import ShareRbiModal from './ShareRbiModal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(element) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

const press = (key) => {
  const target = document.activeElement || document.body;
  act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })); });
};

describe('MoveToFolderModal — libellés traduits', () => {
  test('anglais : aucun texte français en dur', () => {
    const secrets = [{ name: 'Dossier/a' }, { name: 'b' }];
    const host = mount(<MoveToFolderModal secretsToMove={[{ name: 'b' }]} secrets={secrets} onClose={() => {}} onConfirm={() => {}} />);
    const text = host.ownerDocument.body.textContent;
    expect(text).toContain(en.migrate.destination);
    expect(text).not.toMatch(/Destination :|Aucun sous-dossier|dossier actuel/);
    // Racine = dossier courant : bouton Déplacer désactivé avec infobulle traduite
    const move = Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === en.migrate.move);
    expect(move.disabled).toBe(true);
    expect(move.title).toBe(en.migrate.alreadyInFolder);
    // Fil d'Ariane : position courante signalée
    expect(document.querySelector('[aria-current="location"]').textContent.trim()).toBe(en.migrate.root);
  });

  test('sous-dossier vide et sélection multiple : messages traduits', () => {
    const secrets = [{ name: 'x/y' }];
    mount(<MoveToFolderModal secretsToMove={[{ name: 'x/y' }, { name: 'z' }]} secrets={secrets} onClose={() => {}} onConfirm={() => {}} />);
    act(() => { Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('x')).click(); });
    const text = document.body.textContent;
    expect(text).toContain(en.migrate.noSubfolders);
    expect(text).toContain(en.migrate.moveCountTo.replace('{{count}}', '2'));
  });
});

describe('ShareRbiModal — squelette commun et libellés', () => {
  test('mode réception : dialogue nommé, champ ID associé et focalisé, Échap ferme', () => {
    const onClose = jest.fn();
    mount(<ShareRbiModal mode="receive" onClose={onClose} showToast={() => {}} />);
    const dialog = document.querySelector('[role="dialog"]');
    expect(document.getElementById(dialog.getAttribute('aria-labelledby')).textContent).toBe(en.share.titleReceive);
    const label = Array.from(document.querySelectorAll('label')).find(l => l.textContent.trim() === en.share.shareIdLabel);
    const input = document.getElementById(label.htmlFor);
    expect(input.tagName).toBe('INPUT');
    expect(document.activeElement).toBe(input);
    press('Escape');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('mode envoi : options en groupes nommés, état sélectionné exposé (aria-pressed)', () => {
    mount(<ShareRbiModal mode="send" secret={{ name: 's', url: 'https://a.example.com' }} onClose={() => {}} showToast={() => {}} />);
    const groups = document.querySelectorAll('[role="group"]');
    expect(groups.length).toBe(2);
    expect(document.getElementById(groups[0].getAttribute('aria-labelledby')).textContent.trim()).toBe(en.share.expiration);
    const pressed = Array.from(groups[0].querySelectorAll('button')).filter(b => b.getAttribute('aria-pressed') === 'true');
    expect(pressed.map(b => b.textContent.trim())).toEqual([en.share.ttl8h]);
  });
});
