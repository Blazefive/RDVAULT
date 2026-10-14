// ========================================
// TESTS : UI-33 — erreurs de validation de la fiche d'entrée accessibles
// ========================================
// Avant : après « Enregistrer » refusé, le focus restait sur le bouton, les messages
// (<div class="form-hint">) n'étaient reliés à aucun champ, et les champs n'étaient pas
// marqués invalides : le lecteur d'écran n'annonçait rien.
// Attendu : aria-invalid + aria-describedby (message) sur chaque champ en erreur, aria-required
// sur « Nom », focus sur le premier champ en erreur, état levé quand l'erreur est corrigée.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'crypto';
import EditSecretModal from './EditSecretModal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
if (!global.crypto || !global.crypto.getRandomValues) {
  Object.defineProperty(global, 'crypto', { value: webcrypto, configurable: true });
}

let mounted = [];
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

const buttonByText = (txt) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
const controlForLabel = (text) => {
  const label = Array.from(document.querySelectorAll('label')).find(l => l.textContent.trim() === text);
  return label && label.htmlFor ? document.getElementById(label.htmlFor) : null;
};
const description = (el) => (el.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean)
  .map(id => document.getElementById(id)?.textContent || '').join(' ');

test('« Nom » obligatoire : aria-required', () => {
  mount({});
  expect(controlForLabel(en.editSecret.name).getAttribute('aria-required')).toBe('true');
});

test('nom vide + URL invalide : champs invalides, messages reliés, focus sur le premier champ en erreur', () => {
  const onSave = jest.fn();
  mount({ onSave });
  const name = controlForLabel(en.editSecret.name);
  const url = controlForLabel(en.editSecret.url);
  url.value = ['javascript', 'alert(1)'].join(':');
  const save = buttonByText(en.editSecret.save);
  save.focus();
  act(() => { save.click(); });
  expect(onSave).not.toHaveBeenCalled();

  expect(name.getAttribute('aria-invalid')).toBe('true');
  expect(description(name)).toContain(en.error.nameRequired);
  expect(url.getAttribute('aria-invalid')).toBe('true');
  expect(description(url)).toContain(en.error.invalidUrl);
  // Champs valides : pas d'état invalide
  expect(controlForLabel(en.editSecret.username).hasAttribute('aria-invalid')).toBe(false);
  // Focus déplacé sur le premier champ en erreur (le lecteur d'écran lit libellé + erreur)
  expect(document.activeElement).toBe(name);
});

test('seule l\'URL est invalide : focus sur l\'URL ; correction puis enregistrement : état levé', () => {
  const onSave = jest.fn();
  mount({ onSave });
  const name = controlForLabel(en.editSecret.name);
  const url = controlForLabel(en.editSecret.url);
  name.value = 'banque';
  url.value = ['javascript', 'alert(1)'].join(':');
  act(() => { buttonByText(en.editSecret.save).click(); });
  expect(document.activeElement).toBe(url);
  expect(name.hasAttribute('aria-invalid')).toBe(false);

  url.value = 'https://banque.example';
  act(() => { buttonByText(en.editSecret.save).click(); });
  expect(onSave).toHaveBeenCalledTimes(1);
  expect(url.hasAttribute('aria-invalid')).toBe(false);
  expect(url.hasAttribute('aria-describedby')).toBe(false);
});

test('clé SSH : clé privée manquante reliée au champ et focalisée', () => {
  mount({ initial: { name: 'srv', entryType: 'ssh', password: '', url: '', username: '' } });
  act(() => { buttonByText(en.editSecret.save).click(); });
  const priv = controlForLabel(en.editSecret.privateKey);
  expect(priv.getAttribute('aria-invalid')).toBe('true');
  expect(description(priv)).toContain(en.error.privateKeyRequired);
  expect(document.activeElement).toBe(priv);
});

test('champ personnalisé trop long : erreur reliée au champ de la ligne', () => {
  mount({});
  controlForLabel(en.editSecret.name).value = 'ok';
  act(() => { buttonByText(`+ ${en.editSecret.addField}`).click(); });
  const keyInput = document.querySelector(`input[aria-label="${en.editSecret.fieldKey}"]`);
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  act(() => {
    setter.call(keyInput, 'k'.repeat(300));
    keyInput.dispatchEvent(new Event('input', { bubbles: true }));
  });
  act(() => { buttonByText(en.editSecret.save).click(); });
  const k = document.querySelector(`input[aria-label="${en.editSecret.fieldKey}"]`);
  expect(k.getAttribute('aria-invalid')).toBe('true');
  expect(description(k)).toContain(en.error.customFieldKeyTooLong.replace('{{index}}', '1'));
  expect(document.activeElement).toBe(k);
});
