// ========================================
// TESTS : ModalOrchestrator (rendu réel react-dom dans jsdom)
// ========================================
// - Échec de création de dossier : message « création », pas « suppression ».
// - Copie du code TOTP : libellé traduit (totp.title) et non « Code TOTP » en dur.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ModalOrchestrator from './ModalOrchestrator';
import { I18nProvider, useTranslation } from '../i18n';
import en from '../locales/en.json';
import ja from '../locales/ja.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé, aucun appel réseau ici
jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

// Indique à React qu'on est dans un environnement de test avec act()
global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

// ModalOrchestrator reçoit `t` en prop (comme dans App.jsx)
function WithT(props) {
  const { t } = useTranslation();
  return <ModalOrchestrator restoreFocus={() => {}} t={t} {...props} />;
}

function mount(lang, props) {
  localStorage.setItem('rdvault-lang', lang);
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <WithT {...props} />
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

const buttonByText = (host, txt) => Array.from(host.querySelectorAll('button')).find(b => b.textContent.trim() === txt);

describe('Création de dossier (modale inline)', () => {
  test('échec d\'écriture : toast « erreur de création », jamais « erreur de suppression »', async () => {
    const showToast = jest.fn();
    const writeSecretV2 = jest.fn().mockRejectedValue(new Error('read-only'));
    const host = mount('en', {
      showCreateFolderModal: true,
      setShowCreateFolderModal: jest.fn(),
      newFolderName: 'test',
      setNewFolderName: jest.fn(),
      currentPath: '',
      selectedEngine: { name: 'kv', version: 2 },
      writeSecretV2,
      writeSecretV1: jest.fn(),
      fetchSecrets: jest.fn(),
      syncExtensionRef: { current: null },
      showToast,
    });
    await act(async () => { buttonByText(host, en.engine.create).click(); });
    expect(writeSecretV2).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledTimes(1);
    const [message, type] = showToast.mock.calls[0];
    expect(type).toBe('error');
    expect(typeof en.error.folderCreate).toBe('string');
    expect(message.startsWith(en.error.folderCreate)).toBe(true);
    expect(message).not.toContain(en.error.folderDelete);
  });
});

describe('Affichage TOTP', () => {
  test('copie du code : libellé traduit transmis au minuteur du presse-papiers', () => {
    const startClipboardTimer = jest.fn();
    const host = mount('ja', {
      totpDisplay: { secretName: 'github', code: '123456', period: 30, totpKeyName: 'github' },
      setTotpDisplay: jest.fn(),
      getTotpCode: jest.fn().mockResolvedValue(null),
      startClipboardTimer,
    });
    act(() => { buttonByText(host, ja.totp.copyCode).click(); });
    expect(startClipboardTimer).toHaveBeenCalledWith(ja.totp.title, '123456');
    expect(startClipboardTimer.mock.calls[0][0]).not.toBe('Code TOTP');
  });
});

// ========================================
// Accessibilité (A11Y-35, A11Y-26)
// ========================================
const folderProps = (extra = {}) => ({
  showCreateFolderModal: true,
  setShowCreateFolderModal: jest.fn(),
  newFolderName: '',
  setNewFolderName: jest.fn(),
  currentPath: '',
  selectedEngine: { name: 'kv', version: 2 },
  writeSecretV2: jest.fn(),
  writeSecretV1: jest.fn(),
  fetchSecrets: jest.fn(),
  syncExtensionRef: { current: null },
  showToast: jest.fn(),
  ...extra,
});
const pressKey = (key) => {
  const target = document.activeElement || document.body;
  act(() => { target.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })); });
};
const nextFrames = () => act(async () => { await new Promise(r => setTimeout(r, 60)); });

describe('A11Y-35 — modale « Dossier » (squelette commun)', () => {
  test('role="dialog" + aria-modal, nommée par son titre', () => {
    mount('en', folderProps());
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(document.getElementById(dialog.getAttribute('aria-labelledby')).textContent).toContain(en.editSecret.typeFolder);
  });

  test('Échap ferme la modale', () => {
    const setShowCreateFolderModal = jest.fn();
    mount('en', folderProps({ setShowCreateFolderModal }));
    pressKey('Escape');
    expect(setShowCreateFolderModal).toHaveBeenCalledWith(false);
  });

  test('bouton de fermeture nommé « Close » (et non « × ») ; champ associé à son libellé', () => {
    mount('en', folderProps());
    const close = document.querySelector('.modal-close');
    expect(close.getAttribute('aria-label')).toBe(en.common.close);
    const label = document.querySelector('.modal-panel label');
    expect(document.getElementById(label.htmlFor).tagName).toBe('INPUT');
    expect(document.activeElement).toBe(document.getElementById(label.htmlFor)); // autoFocus conservé
  });
});

// Déclencheur → Notes (état réel) ; `triggerVanishes` : le déclencheur disparaît à l'ouverture
// (cas d'un élément de menu contextuel)
function NotesHarness({ restoreFocus, triggerVanishes = false }) {
  const { t } = useTranslation();
  const [notesPopup, setNotesPopup] = React.useState(null);
  return (
    <>
      {(!triggerVanishes || !notesPopup) && (
        <button type="button" id="trigger" onClick={() => setNotesPopup({ notes: 'n1' })}>open</button>
      )}
      <ModalOrchestrator restoreFocus={restoreFocus} t={t} notesPopup={notesPopup} setNotesPopup={setNotesPopup} />
    </>
  );
}
function mountNotes(props) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><NotesHarness {...props} /></I18nProvider>); });
  mounted.push(root);
  return host;
}

describe('A11Y-26 — retour du focus à la fermeture', () => {
  test('Notes : focus rendu au déclencheur ; la recherche (restoreFocus) n\'est pas forcée', async () => {
    const restoreFocus = jest.fn();
    const host = mountNotes({ restoreFocus });
    const trigger = document.getElementById('trigger');
    trigger.focus();
    act(() => { trigger.click(); });
    expect(document.querySelector('.modal-panel').contains(document.activeElement)).toBe(true);
    act(() => { buttonByText(host, en.notes.close).click(); });
    expect(document.querySelector('.modal-panel')).toBeNull();
    await nextFrames();
    expect(document.activeElement).toBe(trigger);
    expect(restoreFocus).not.toHaveBeenCalled();
  });

  test('déclencheur disparu (élément de menu) : repli sur restoreFocus (focus sur la recherche)', async () => {
    const restoreFocus = jest.fn();
    const host = mountNotes({ restoreFocus, triggerVanishes: true });
    const trigger = document.getElementById('trigger');
    trigger.focus();
    act(() => { trigger.click(); });
    expect(document.getElementById('trigger')).toBeNull();
    act(() => { buttonByText(host, en.notes.close).click(); });
    await nextFrames();
    expect(restoreFocus).toHaveBeenCalledTimes(1);
  });
});
