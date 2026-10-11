// ========================================
// TESTS : accessibilité et fermeture des modales utilisateur (rendu réel react-dom dans jsdom)
// ========================================
// Suite C1 — pour chaque modale « maison » (TOTP, configuration TOTP, générateur de mot de passe,
// historique des versions, paramètres, clé SSH) :
// - role="dialog" + aria-modal + nom accessible = titre (aria-labelledby) ;
// - focus initial dans le panneau, piège de focus (Tab / Maj+Tab bouclent) ;
// - Échap ferme la modale du dessus uniquement (pas sous une autre modale) ;
// - retour du focus à l'élément déclencheur à la fermeture ;
// - fond : un vrai clic ferme, une sélection de texte commencée dans le panneau et relâchée
//   sur le fond ne ferme pas.
// Plus : textes traduits de VersionHistoryModal et MigrateSecretModal (plus de français en dur).

import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'crypto';
import axios from 'axios';
import TotpDisplayModal from './TotpDisplayModal';
import TotpConfigModal from './TotpConfigModal';
import PasswordGeneratorModal from './PasswordGeneratorModal';
import VersionHistoryModal from './VersionHistoryModal';
import SettingsModal from './SettingsModal';
import SSHKeyModal from './SSHKeyModal';
import MigrateSecretModal from './MigrateSecretModal';
import NotesPopupModal from './NotesPopupModal';
import ConfirmModal from './ConfirmModal';
import ShareRbiModal from './ShareRbiModal';
import { getFocusableElements } from './components/common/Modal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';
import fr from './locales/fr.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé, aucun appel réseau ici
jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;
// Le générateur utilise crypto.getRandomValues (absent de jsdom)
if (!global.crypto || !global.crypto.getRandomValues) {
  Object.defineProperty(global, 'crypto', { value: webcrypto, configurable: true });
}

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(element, lang = 'en') {
  localStorage.setItem('rdvault-lang', lang);
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
  return host;
}

// Montage puis fin des chargements asynchrones (historique des versions : requête simulée)
async function mountSettled(element, lang) {
  const host = mount(element, lang);
  await act(async () => { await Promise.resolve(); });
  return host;
}

beforeEach(() => {
  // Historique des versions : métadonnées KV v2 (une version)
  axios.get.mockReset();
  axios.get.mockResolvedValue({ data: { data: { versions: { 1: { created_time: '2026-01-02T03:04:05Z', deletion_time: '', destroyed: false } } } } });
});

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

// Touche envoyée à l'élément actif (comme le ferait le navigateur)
const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts });
  act(() => { target.dispatchEvent(ev); });
  return ev;
};
// Événement souris réel (chaque phase est une tâche distincte : rendu React entre chacune)
const mouse = (el, type, x = 8, y = 300) => {
  act(() => { el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: y })); });
};
// Texte visible par les technologies d'assistance (nœuds aria-hidden exclus)
const accessibleText = (node) => {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent;
  if (node.nodeType !== Node.ELEMENT_NODE || node.getAttribute('aria-hidden') === 'true') return '';
  return Array.from(node.childNodes).map(accessibleText).join('');
};
const accessibleName = (el) => {
  const labelledby = el.getAttribute('aria-labelledby');
  if (labelledby) {
    return labelledby.split(/\s+/).map(id => {
      const target = document.getElementById(id);
      return target ? accessibleText(target) : '';
    }).join(' ').replace(/\s+/g, ' ').trim();
  }
  return (el.getAttribute('aria-label') || '').trim();
};
const panel = () => document.querySelector('.modal-panel');
const overlay = () => document.querySelector('.modal-overlay');
const buttonByText = (txt) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === txt);

const VERSION_ENGINE = { name: 'kv', version: 2 };

// [nom, fabrique (props) => élément, titre attendu (anglais)]
const MODALS = [
  ['TotpDisplayModal', (p) => <TotpDisplayModal secretName="gitlab" totpCode="123456" onCopy={() => {}} {...p} />, en.totp.title],
  ['TotpConfigModal', (p) => <TotpConfigModal secretName="gitlab" totpKeyName="KV-gitlab" engineName="kv" onSave={() => {}} {...p} />, en.totp.configure],
  ['PasswordGeneratorModal', (p) => <PasswordGeneratorModal onAccept={() => {}} {...p} />, en.passwordGenerator.title],
  ['VersionHistoryModal', (p) => (
    <VersionHistoryModal
      secretName="gitlab" engine={VERSION_ENGINE} vaultUrl="http://vault.test"
      baseHeaders={() => ({})} axiosConfig={(c) => c} showToast={() => {}} {...p}
    />
  ), en.versionHistory.title],
  ['SettingsModal', (p) => <SettingsModal visibleColumns={{}} {...p} />, en.settings.title],
  ['SSHKeyModal', (p) => <SSHKeyModal initial={null} onSave={() => {}} {...p} />, en.sshKey.newKey],
  // Modales déjà construites sur le squelette commun Modal : mêmes garanties vérifiées
  ['NotesPopupModal', (p) => <NotesPopupModal notes="ligne 1" {...p} />, en.notes.title],
  ['ConfirmModal', ({ onClose, ...p }) => <ConfirmModal title="Supprimer ?" message="Sûr ?" onConfirm={() => {}} onCancel={onClose} {...p} />, 'Supprimer ?'],
  ['MigrateSecretModal', (p) => (
    <MigrateSecretModal
      secrets={[{ name: 'gitlab' }]} engines={[{ name: 'a', canWrite: true, version: 2 }, { name: 'b', canWrite: true, version: 2 }]}
      currentEngine={{ name: 'a', version: 2 }} mode="move" onConfirm={() => {}} {...p}
    />
  ), en.migrate.migrateTitle],
  ['ShareRbiModal', (p) => (
    <ShareRbiModal
      mode="send" secret={{ name: 'gitlab', url: 'gitlab.example.com' }} vaultUrl="http://vault.test" token="t"
      axiosConfig={(c) => c} showToast={() => {}} {...p}
    />
  ), en.share.titleSend],
];

describe.each(MODALS)('%s — dialogue accessible', (name, render, title) => {
  test('role="dialog", aria-modal et nom accessible = titre', async () => {
    await mountSettled(render({ onClose: () => {} }));
    const dialog = document.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(accessibleName(dialog)).toBe(title);
  });

  test('focus initial dans le panneau', async () => {
    const opener = document.createElement('button');
    document.body.appendChild(opener);
    opener.focus();
    await mountSettled(render({ onClose: () => {} }));
    expect(panel().contains(document.activeElement)).toBe(true);
  });

  test('piège de focus : Tab sur le dernier élément revient au premier, Maj+Tab l\'inverse', async () => {
    await mountSettled(render({ onClose: () => {} }));
    const items = getFocusableElements(panel());
    expect(items.length).toBeGreaterThan(0);
    const first = items[0];
    const last = items[items.length - 1];
    last.focus();
    const ev = press('Tab');
    expect(ev.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(first);
    press('Tab', { shiftKey: true });
    expect(document.activeElement).toBe(last);
  });

  test('Échap : ignoré sous une autre modale, ferme quand la modale est au-dessus', async () => {
    const onClose = jest.fn();
    await mountSettled(render({ onClose }));
    // Sous-modale ouverte par-dessus (dernier dialogue modal du document)
    const above = document.createElement('div');
    above.setAttribute('role', 'dialog');
    above.setAttribute('aria-modal', 'true');
    document.body.appendChild(above);
    press('Escape');
    expect(onClose).not.toHaveBeenCalled();
    above.remove();
    press('Escape');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('fermeture par Échap : le focus revient au déclencheur', async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Déclencheur</button>
          {open && render({ onClose: () => setOpen(false) })}
        </>
      );
    }
    mount(<Harness />);
    const trigger = buttonByText('Déclencheur');
    trigger.focus();
    await act(async () => { trigger.click(); });
    expect(panel()).not.toBeNull();
    // Le focus est passé dans la modale (sinon le test serait trivialement vrai)
    expect(panel().contains(document.activeElement)).toBe(true);
    press('Escape');
    expect(panel()).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  test('fond : une sélection de texte qui déborde ne ferme pas ; un vrai clic ferme', async () => {
    const onClose = jest.fn();
    await mountSettled(render({ onClose }));
    // Sélection : mousedown dans le panneau, mouseup sur le fond → le navigateur émet « click »
    // sur l'ancêtre commun, c'est-à-dire le fond
    const inside = panel().querySelector('h2');
    mouse(inside, 'mousedown', 300, 200);
    mouse(overlay(), 'mouseup', 8, 300);
    mouse(overlay(), 'click', 8, 300);
    expect(onClose).not.toHaveBeenCalled();
    // Glisser sur le fond (déplacement ≥ 5 px) : pas un clic
    mouse(overlay(), 'mousedown', 8, 300);
    mouse(overlay(), 'mouseup', 40, 300);
    expect(onClose).not.toHaveBeenCalled();
    // Vrai clic sur le fond
    mouse(overlay(), 'mousedown', 8, 300);
    mouse(overlay(), 'mouseup', 8, 300);
    mouse(overlay(), 'click', 8, 300);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe('PasswordGeneratorModal — sous-modale', () => {
  test('ouverte par-dessus une modale : Échap ne ferme que le générateur', () => {
    const outerClose = jest.fn();
    const innerClose = jest.fn();
    mount(
      <>
        <TotpConfigModal secretName="a" totpKeyName="K-a" engineName="kv" onSave={() => {}} onClose={outerClose} />
        <PasswordGeneratorModal onAccept={() => {}} onClose={innerClose} />
      </>
    );
    press('Escape');
    expect(innerClose).toHaveBeenCalledTimes(1);
    expect(outerClose).not.toHaveBeenCalled();
  });
});

describe('TotpConfigModal — champs nommés', () => {
  test('clé, chiffres et période associés à leur libellé', () => {
    mount(<TotpConfigModal secretName="a" totpKeyName="K-a" engineName="kv" onSave={() => {}} onClose={() => {}} />);
    for (const label of [en.editSecret.totpKey, en.editSecret.totpDigits, en.editSecret.totpPeriod]) {
      const el = Array.from(document.querySelectorAll('label')).find(l => l.textContent.trim() === label);
      expect(el).toBeDefined();
      const control = document.getElementById(el.htmlFor);
      expect(control).not.toBeNull();
      expect(['TEXTAREA', 'SELECT', 'INPUT']).toContain(control.tagName);
    }
  });
});

describe('VersionHistoryModal — textes traduits', () => {
  test('coffre KV v1 : message « KV v2 uniquement » traduit (anglais), modale fermée', async () => {
    const showToast = jest.fn();
    const onClose = jest.fn();
    mount(
      <VersionHistoryModal
        secretName="gitlab" engine={{ name: 'kv1', version: 1 }} vaultUrl="http://vault.test"
        baseHeaders={() => ({})} axiosConfig={(c) => c} showToast={showToast} onClose={onClose}
      />
    );
    await act(async () => { await Promise.resolve(); });
    expect(showToast).toHaveBeenCalledWith(en.versionHistory.kvV2Only, 'error');
    expect(onClose).toHaveBeenCalled();
    expect(axios.get).not.toHaveBeenCalled();
  });

  test('invite de sélection traduite, aucun texte français en dur', async () => {
    mount(
      <VersionHistoryModal
        secretName="gitlab" engine={VERSION_ENGINE} vaultUrl="http://vault.test"
        baseHeaders={() => ({})} axiosConfig={(c) => c} showToast={() => {}} onClose={() => {}}
      />
    );
    await act(async () => { await Promise.resolve(); });
    const text = document.body.textContent;
    expect(text).toContain(en.versionHistory.selectPrompt);
    expect(text).not.toMatch(/Sélectionnez une version|Impossible de charger/);
  });

  test('données de version illisibles : message traduit', async () => {
    axios.get
      .mockResolvedValueOnce({ data: { data: { versions: { 1: { created_time: '2026-01-02T03:04:05Z' } } } } })
      .mockRejectedValueOnce(new Error('403'));
    mount(
      <VersionHistoryModal
        secretName="gitlab" engine={VERSION_ENGINE} vaultUrl="http://vault.test"
        baseHeaders={() => ({})} axiosConfig={(c) => c} showToast={() => {}} onClose={() => {}}
      />
    );
    await act(async () => { await Promise.resolve(); });
    const versionButton = document.querySelector('button.version-item');
    await act(async () => { versionButton.click(); });
    expect(document.body.textContent).toContain(en.versionHistory.loadFailed);
  });
});

describe('MigrateSecretModal — phrase traduite', () => {
  const engines = [{ name: 'perso', canWrite: true, version: 2 }, { name: 'equipe', canWrite: true, version: 2 }];

  test('anglais : une entrée, nom et coffre en gras, aucun français en dur', () => {
    mount(<MigrateSecretModal secrets={[{ name: 'gitlab' }]} engines={engines} currentEngine={engines[0]} mode="move" onClose={() => {}} onConfirm={() => {}} />);
    const body = document.querySelector('.modal-body');
    expect(body.textContent).toContain('Move entry gitlab from perso to:');
    expect(Array.from(body.querySelectorAll('strong')).map(s => s.textContent)).toEqual(expect.arrayContaining(['gitlab', 'perso']));
    expect(body.textContent).not.toMatch(/Déplacer|depuis|vers :/);
  });

  test('anglais : plusieurs entrées (copie)', () => {
    mount(<MigrateSecretModal secrets={[{ name: 'a' }, { name: 'b' }, { name: 'c' }]} engines={engines} currentEngine={engines[0]} mode="copy" onClose={() => {}} onConfirm={() => {}} />);
    const body = document.querySelector('.modal-body');
    expect(body.textContent).toContain('Copy 3 entries from perso to:');
    expect(Array.from(body.querySelectorAll('strong')).map(s => s.textContent)).toEqual(expect.arrayContaining(['3 entries', 'perso']));
  });

  test('français : rendu identique à l\'ancien texte', () => {
    mount(<MigrateSecretModal secrets={[{ name: 'a' }, { name: 'b' }]} engines={engines} currentEngine={engines[0]} mode="move" onClose={() => {}} onConfirm={() => {}} />, 'fr');
    const body = document.querySelector('.modal-body');
    expect(body.textContent).toContain('Déplacer 2 entrées depuis perso vers :');
    expect(fr.migrate.moveManyFrom).toBe('Déplacer {{entries}} depuis {{engine}} vers :');
  });
});
