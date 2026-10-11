// ========================================
// TESTS : accessibilité et thème des modales du panneau admin (rendu réel react-dom dans jsdom)
// ========================================
// CreatePolicyModal, EnableAuditModal, PolicyBuilderModal reposent sur le squelette commun
// Modal (hook useDialogA11y) :
// - role="dialog", aria-modal, nom accessible = titre ;
// - focus initial dans le panneau, piège de focus (Tab / Maj+Tab), retour du focus au déclencheur ;
// - Échap ne ferme que la modale du dessus (une sous-modale garde l'Échap pour elle) ;
// - fermeture sur le fond par mousedown + mouseup au même endroit seulement (une sélection de
//   texte commencée dans le panneau et relâchée sur le fond ne ferme plus la modale) ;
// - aucune couleur codée en dur (fonds blancs illisibles en thème sombre) : variables du thème.

import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import CreatePolicyModal from './CreatePolicyModal';
import EnableAuditModal from './EnableAuditModal';
import PolicyBuilderModal from './PolicyBuilderModal';
import Modal from '../common/Modal';
import { I18nProvider } from '../../i18n';
import en from '../../locales/en.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé
jest.mock('axios', () => {
  const fn = jest.fn();
  fn.get = jest.fn();
  fn.post = jest.fn();
  fn.put = jest.fn();
  fn.delete = jest.fn();
  return { __esModule: true, default: fn };
});

global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const MOUNTS = [{ path: 'kv', type: 'kv', version: 2, description: '' }];

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

beforeEach(() => {
  axios.get.mockReset();
  axios.get.mockResolvedValue({ data: { data: { keys: [] } } });
});

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

const flush = async () => {
  for (let i = 0; i < 5; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
  }
};

// Touche envoyée à l'élément actif (comme le ferait le navigateur)
const press = (key, opts = {}) => {
  const target = document.activeElement || document.body;
  const ev = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, ...opts });
  act(() => { target.dispatchEvent(ev); });
  return ev;
};
// Événement souris réel : chaque type est une tâche distincte (rendu React entre chacun)
const mouse = (el, type, x = 5, y = 5) => {
  act(() => { el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: y })); });
};
const accessibleName = (el) => {
  const labelledby = el.getAttribute('aria-labelledby');
  if (labelledby) return labelledby.split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ').trim();
  return (el.getAttribute('aria-label') || '').trim();
};
const dialogs = () => Array.from(document.querySelectorAll('[role="dialog"]'));
const buttonContaining = (txt) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes(txt));
// Éléments focalisables visibles du panneau, dans l'ordre du document
const focusables = (panel) => Array.from(panel.querySelectorAll('button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled])'))
  .filter(el => el.style.display !== 'none');

// Les trois modales, rendues avec des props minimales
const MODALS = [
  {
    name: 'CreatePolicyModal',
    title: en.admin.newPolicy,
    render: (props) => <CreatePolicyModal savePolicy={jest.fn().mockResolvedValue(true)} onCreated={jest.fn()} showToast={jest.fn()} {...props} />,
  },
  {
    name: 'EnableAuditModal',
    title: en.admin.enableAudit.title,
    render: (props) => <EnableAuditModal onEnable={jest.fn()} showToast={jest.fn()} {...props} />,
  },
  {
    name: 'PolicyBuilderModal',
    title: en.admin.builder.title,
    render: (props) => (
      <PolicyBuilderModal allMounts={MOUNTS} loadAllMounts={jest.fn()} editPolicyName={null} vaultUrl={VAULT}
        axiosConfig={(c) => c} baseHeaders={() => ({})} savePolicy={jest.fn()} showToast={jest.fn()} {...props} />
    ),
  },
];

describe.each(MODALS)('$name — dialogue accessible', ({ title, render }) => {
  test('role="dialog", aria-modal et nom accessible = titre', async () => {
    mount(render({ onClose: jest.fn() }));
    await flush();
    const [dialog] = dialogs();
    expect(dialog).toBeDefined();
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(accessibleName(dialog)).toContain(title);
  });

  test('focus initial dans le panneau ; Tab / Maj+Tab bouclent dans la modale', async () => {
    const outside = document.createElement('button');
    outside.textContent = 'arrière-plan';
    document.body.appendChild(outside);
    outside.focus();
    mount(render({ onClose: jest.fn() }));
    await flush();
    const [dialog] = dialogs();
    expect(dialog.contains(document.activeElement)).toBe(true);
    const items = focusables(dialog);
    expect(items.length).toBeGreaterThan(1);
    items[items.length - 1].focus();
    const ev = press('Tab');
    expect(ev.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(items[0]);
    const ev2 = press('Tab', { shiftKey: true });
    expect(ev2.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(items[items.length - 1]);
  });

  test('Échap ferme la modale', async () => {
    const onClose = jest.fn();
    mount(render({ onClose }));
    await flush();
    press('Escape');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('Échap avec une sous-modale ouverte : seule la sous-modale se ferme', async () => {
    const onClose = jest.fn();
    const onSubClose = jest.fn();
    mount(<>{render({ onClose })}<Modal title="Sous-modale" onClose={onSubClose}>x</Modal></>);
    await flush();
    press('Escape');
    expect(onSubClose).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
  });

  test('clic sur le fond (mousedown + mouseup au même endroit) : fermeture', async () => {
    const onClose = jest.fn();
    mount(render({ onClose }));
    await flush();
    const overlay = dialogs()[0].parentElement;
    mouse(overlay, 'mousedown');
    mouse(overlay, 'mouseup');
    mouse(overlay, 'click');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('sélection commencée dans le panneau et relâchée sur le fond : pas de fermeture', async () => {
    const onClose = jest.fn();
    mount(render({ onClose }));
    await flush();
    const dialog = dialogs()[0];
    const overlay = dialog.parentElement;
    const input = dialog.querySelector('input');
    mouse(input, 'mousedown', 200, 200);
    mouse(overlay, 'mouseup', 5, 5);
    // Le navigateur émet « click » sur l'ancêtre commun (le fond)
    mouse(overlay, 'click', 5, 5);
    expect(onClose).not.toHaveBeenCalled();
  });

  test('clic dans le panneau : pas de fermeture', async () => {
    const onClose = jest.fn();
    mount(render({ onClose }));
    await flush();
    const input = dialogs()[0].querySelector('input');
    mouse(input, 'mousedown');
    mouse(input, 'mouseup');
    mouse(input, 'click');
    expect(onClose).not.toHaveBeenCalled();
  });

  test('fermeture : le focus revient au bouton déclencheur', async () => {
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
    const trigger = buttonContaining('Déclencheur');
    trigger.focus();
    act(() => { trigger.click(); });
    await flush();
    expect(dialogs()[0].contains(document.activeElement)).toBe(true);
    act(() => { buttonContaining(en.common.cancel).click(); });
    expect(dialogs()).toHaveLength(0);
    expect(document.activeElement).toBe(trigger);
  });
});

describe('CreatePolicyModal — validation au clavier', () => {
  test('Entrée dans le champ (soumission du formulaire) crée la policy', async () => {
    const savePolicy = jest.fn().mockResolvedValue(true);
    const onClose = jest.fn();
    mount(<CreatePolicyModal savePolicy={savePolicy} onCreated={jest.fn()} showToast={jest.fn()} onClose={onClose} />);
    const input = dialogs()[0].querySelector('input');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'app-ro');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => {
      input.form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });
    await flush();
    expect(savePolicy).toHaveBeenCalledTimes(1);
    expect(savePolicy.mock.calls[0][0]).toBe('app-ro');
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  test('clic sur « Créer » (bouton du pied relié au formulaire) crée la policy une seule fois', async () => {
    const savePolicy = jest.fn().mockResolvedValue(true);
    mount(<CreatePolicyModal savePolicy={savePolicy} onCreated={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
    const input = dialogs()[0].querySelector('input');
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'team-rw');
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await act(async () => { buttonContaining(en.admin.common.create).click(); });
    await flush();
    expect(savePolicy).toHaveBeenCalledTimes(1);
    expect(savePolicy.mock.calls[0][0]).toBe('team-rw');
  });

  test('bouton « Créer » désactivé tant que le nom est vide', () => {
    mount(<CreatePolicyModal savePolicy={jest.fn()} onCreated={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
    expect(buttonContaining(en.admin.common.create).disabled).toBe(true);
  });
});

// Couleur littérale (#hex, rgb()) dans un style inline : jsdom convertit les #hex en rgb()
const LITERAL_COLOR = /#[0-9a-f]{3,8}\b|rgba?\(/i;
const literalColorElements = (root) => [root, ...root.querySelectorAll('*')]
  .filter(el => LITERAL_COLOR.test(el.getAttribute('style') || ''))
  .map(el => `${el.tagName.toLowerCase()}[style="${el.getAttribute('style')}"]`);

describe('Thème : aucune couleur codée en dur dans les modales admin', () => {
  test('création de policy', () => {
    mount(<CreatePolicyModal savePolicy={jest.fn()} onCreated={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
    expect(dialogs()[0].className).toContain('modal-panel');
    expect(literalColorElements(document.body)).toEqual([]);
  });

  test('activation d\'audit, section SSH dépliée', async () => {
    mount(<EnableAuditModal onEnable={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
    await act(async () => { dialogs()[0].querySelector('input[type="checkbox"]').click(); });
    expect(document.body.textContent).toContain(en.admin.sshConfig);
    expect(literalColorElements(document.body)).toEqual([]);
  });

  test('builder : règle « RBI uniquement » avec TOTP et préfixe partagé, aperçu HCL', async () => {
    const mounts = [{ path: 'web', type: 'kv', version: 2 }, { path: 'web-prod', type: 'kv', version: 2 }];
    mount(
      <PolicyBuilderModal allMounts={mounts} loadAllMounts={jest.fn()} editPolicyName={null} vaultUrl={VAULT}
        axiosConfig={(c) => c} baseHeaders={() => ({})} savePolicy={jest.fn()} showToast={jest.fn()} onClose={() => {}} />
    );
    const setSelect = async (select, value) => {
      await act(async () => {
        Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(select, value);
        select.dispatchEvent(new Event('change', { bubbles: true }));
      });
    };
    const selects = () => Array.from(document.querySelectorAll('select'));
    await setSelect(selects().find(s => s.options[0]?.textContent === en.admin.builder.selectVault), 'web');
    await flush();
    await setSelect(selects().find(s => s.querySelector('option[value="rbi-only"]')), 'rbi-only');
    await act(async () => { buttonContaining(en.admin.builder.addRule).click(); });
    // Avertissements, encadré TOTP, règle supprimable et aperçu tous présents
    expect(document.body.textContent).toContain(en.admin.builder.rbiVaultLimit);
    expect(document.body.textContent).toContain(en.admin.builder.includeTotp);
    expect(buttonContaining(en.admin.builder.remove)).toBeDefined();
    expect(document.querySelector('pre')).not.toBeNull();
    expect(literalColorElements(document.body)).toEqual([]);
  });

  test('builder : policy non représentable (avertissement)', async () => {
    axios.get.mockImplementation(async (url) => {
      if (url.includes('/sys/policies/acl/')) return { data: { data: { policy: 'path "secret/data/x" { capabilities = ["read"] }' } } };
      return { data: { data: { keys: [] } } };
    });
    mount(
      <PolicyBuilderModal allMounts={MOUNTS} loadAllMounts={jest.fn()} editPolicyName="hand" vaultUrl={VAULT}
        axiosConfig={(c) => c} baseHeaders={() => ({})} savePolicy={jest.fn()} showToast={jest.fn()} onClose={() => {}} />
    );
    await flush();
    expect(document.body.textContent).toContain(en.admin.builder.unsupportedTitle);
    expect(literalColorElements(document.body)).toEqual([]);
  });
});
