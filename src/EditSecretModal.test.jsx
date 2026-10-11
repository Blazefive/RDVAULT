// ========================================
// TESTS : EditSecretModal (rendu réel react-dom dans jsdom)
// ========================================
// - Création de dossier dans un sous-dossier (vue arborescence) : le chemin
//   pré-rempli n'est pas préfixé deux fois (useSecrets rajoute le dossier courant).
// - Erreurs de validation des champs personnalisés réellement affichées.
// - Notes limitées à 10 000 caractères dès la fiche (même borne que validateSecret).
// - Aucun texte français codé en dur : tout passe par les locales.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import EditSecretModal from './EditSecretModal';
import { I18nProvider } from './i18n';
import { validateSecret } from './validation';
import en from './locales/en.json';
import fr from './locales/fr.json';
import ru from './locales/ru.json';

// Indique à React qu'on est dans un environnement de test avec act()
global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

// Saisie dans un champ contrôlé : setter natif + événement « input » (déclenche onChange React)
const setNative = (input, value) => {
  const proto = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(input, value);
  input.dispatchEvent(new Event('input', { bubbles: true }));
};
const buttonByText = (host, txt) => Array.from(host.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
const nameInput = (host) => host.querySelector('input.modal-input');
const entryTypeRadios = (host) => host.querySelectorAll('input[name="entryType"]');

function mount(lang, props) {
  localStorage.setItem('rdvault-lang', lang);
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

// Reproduction de l'expression de useSecrets.handleEditSecretSave (branche dossier)
const placeholderWrittenByUseSecrets = (folderNameFromModal, currentPath) =>
  (currentPath ? `${currentPath}/` : '') + folderNameFromModal.trim().replace(/\/+$/, '') + '/.placeholder';

describe('Création de dossier depuis un sous-dossier (champ nom pré-rempli « dossier/courant/ »)', () => {
  const initialInSubfolder = { name: 'prod/db/', username: '', password: '', url: '', notes: '' };

  test('le préfixe pré-rempli est retiré : le dossier atterrit là où l\'indique la modale', () => {
    const onSave = jest.fn();
    const host = mount('en', { initial: initialInSubfolder, onSave });
    act(() => { entryTypeRadios(host)[2].click(); });
    // Indication affichée en pied de modale
    expect(host.querySelector('.modal-footer code').textContent).toBe('/prod/db/');
    nameInput(host).value = 'prod/db/x';
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledWith({ name: 'x', entryType: 'folder' });
    // useSecrets préfixe le dossier courant : clé finale cohérente avec l'indication
    expect(placeholderWrittenByUseSecrets(onSave.mock.calls[0][0].name, 'prod/db')).toBe('prod/db/x/.placeholder');
  });

  test('un nom saisi sans le préfixe (champ vidé puis retapé) est conservé tel quel', () => {
    const onSave = jest.fn();
    const host = mount('en', { initial: initialInSubfolder, onSave });
    act(() => { entryTypeRadios(host)[2].click(); });
    nameInput(host).value = 'x';
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledWith({ name: 'x', entryType: 'folder' });
  });

  test('seul le préfixe pré-rempli (aucun nom de dossier) : refus avec message traduit', () => {
    const onSave = jest.fn();
    const host = mount('en', { initial: initialInSubfolder, onSave });
    act(() => { entryTypeRadios(host)[2].click(); });
    nameInput(host).value = 'prod/db/';
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(host.textContent).toContain(en.error.nameRequired);
  });

  test('à la racine (aucun préfixe), le nom saisi est transmis tel quel', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    act(() => { entryTypeRadios(host)[2].click(); });
    expect(host.querySelector('.modal-footer code').textContent).toBe('/');
    nameInput(host).value = 'a/b';
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledWith({ name: 'a/b', entryType: 'folder' });
  });

  test('création d\'un secret (non dossier) dans un sous-dossier : chemin complet inchangé', () => {
    const onSave = jest.fn();
    const host = mount('en', { initial: initialInSubfolder, onSave });
    nameInput(host).value = 'prod/db/mysql';
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave.mock.calls[0][0].name).toBe('prod/db/mysql');
  });
});

describe('Validation des champs personnalisés', () => {
  const addFieldAndType = (host, which, value) => {
    act(() => { buttonByText(host, `+ ${en.editSecret.addField}`).click(); });
    const placeholder = which === 'key' ? en.editSecret.fieldKey : en.editSecret.fieldValue;
    const input = Array.from(host.querySelectorAll('input')).find(i => i.placeholder === placeholder);
    act(() => { setNative(input, value); });
  };

  test('nom de champ trop long : enregistrement bloqué ET erreur traduite affichée', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    nameInput(host).value = 'mysecret';
    addFieldAndType(host, 'key', 'k'.repeat(300));
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(typeof en.error.customFieldKeyTooLong).toBe('string');
    expect(host.textContent).toContain(en.error.customFieldKeyTooLong.replace('{{index}}', '1'));
    expect(host.textContent).not.toContain('trop long');
  });

  test('valeur de champ trop longue : enregistrement bloqué ET erreur traduite affichée', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    nameInput(host).value = 'mysecret';
    addFieldAndType(host, 'value', 'v'.repeat(10001));
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(typeof en.error.customFieldValueTooLong).toBe('string');
    expect(host.textContent).toContain(en.error.customFieldValueTooLong.replace('{{index}}', '1'));
    expect(host.textContent).not.toContain('trop longue');
  });

  test('champ valide : enregistrement normal', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    nameInput(host).value = 'mysecret';
    addFieldAndType(host, 'key', 'Port');
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave.mock.calls[0][0].customFields).toEqual([{ key: 'Port', value: '', protected: false }]);
  });
});

describe('Notes : limite de 10 000 caractères à l\'enregistrement (comme validateSecret)', () => {
  // Avant : la fiche transmettait les notes sans contrôle ; l'écriture était ensuite refusée par
  // validateSecret avec une erreur générique (en français, sans indiquer le champ fautif).
  const notesField = (host) => {
    const label = Array.from(host.querySelectorAll('label')).find(l => l.textContent.trim() === en.editSecret.notes);
    return document.getElementById(label.htmlFor);
  };

  test('10 001 caractères : enregistrement bloqué, erreur traduite affichée sous les notes', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    nameInput(host).value = 'mysecret';
    const tooLong = 'n'.repeat(10001);
    notesField(host).value = tooLong;
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(typeof en.error.notesTooLong).toBe('string');
    expect(host.textContent).toContain(en.error.notesTooLong);
    expect(host.textContent).not.toContain('trop longues');
    // Même borne que la validation finale (sinon refus générique à l'écriture)
    expect(validateSecret({ name: 'mysecret', notes: tooLong }).valid).toBe(false);
  });

  test('10 000 caractères exactement : accepté, notes transmises intactes', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    nameInput(host).value = 'mysecret';
    const max = 'n'.repeat(10000);
    notesField(host).value = max;
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(onSave.mock.calls[0][0].notes).toBe(max);
    expect(validateSecret({ name: 'mysecret', notes: max }).valid).toBe(true);
  });

  test('clé SSH : même limite sur les notes', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave, initial: { name: 'srv', entryType: 'ssh', password: 'PRIVATE', url: '', username: '' } });
    notesField(host).value = 'n'.repeat(10001);
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(host.textContent).toContain(en.error.notesTooLong);
  });

  test('français : message de la locale', () => {
    const onSave = jest.fn();
    const host = mount('fr', { onSave });
    nameInput(host).value = 'mysecret';
    const label = Array.from(host.querySelectorAll('label')).find(l => l.textContent.trim() === fr.editSecret.notes);
    document.getElementById(label.htmlFor).value = 'n'.repeat(10001);
    act(() => { buttonByText(host, fr.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(host.textContent).toContain(fr.error.notesTooLong);
  });

  test('erreur corrigée : l\'enregistrement suivant passe et l\'erreur disparaît', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    nameInput(host).value = 'mysecret';
    notesField(host).value = 'n'.repeat(10001);
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    notesField(host).value = 'courte';
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).toHaveBeenCalledTimes(1);
    expect(host.textContent).not.toContain(en.error.notesTooLong);
  });
});

describe('Aucun texte français codé en dur (UI en anglais / russe)', () => {
  test('URL invalide : message de la locale (error.invalidUrl)', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    const inputs = Array.from(host.querySelectorAll('input.modal-input'));
    // Ordre : nom, utilisateur, mot de passe, URL, tags
    inputs[0].value = 'mysecret';
    inputs[3].value = ['javascript', 'alert(1)'].join(':'); // schéma interdit
    act(() => { buttonByText(host, en.editSecret.save).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(host.textContent).toContain(en.error.invalidUrl);
    expect(host.textContent).not.toContain('URL invalide');
  });

  test('aides, placeholder des tags, case « Protégé » et taille max traduits', () => {
    const host = mount('en', {});
    const text = host.textContent;
    for (const key of ['folderHint', 'tagsHint', 'tagsPlaceholder', 'protectedField', 'maxFileSize']) {
      expect(typeof en.editSecret[key]).toBe('string');
    }
    expect(text).toContain(en.editSecret.folderHint);
    expect(text).toContain(en.editSecret.tagsHint);
    expect(text).toContain(en.editSecret.maxFileSize);
    expect(Array.from(host.querySelectorAll('input')).some(i => i.placeholder === en.editSecret.tagsPlaceholder)).toBe(true);
    act(() => { buttonByText(host, `+ ${en.editSecret.addField}`).click(); });
    expect(host.textContent).toContain(en.editSecret.protectedField);
    // Plus aucune des anciennes chaînes françaises
    for (const fr of ['Utilisez "/"', 'Séparez les tags', 'Taille max', 'Protégé']) {
      expect(host.textContent).not.toContain(fr);
    }
    expect(Array.from(host.querySelectorAll('input')).some(i => i.placeholder.startsWith('ex: '))).toBe(false);
  });

  test('russe : unité d\'entropie traduite et placeholder de passphrase SSH traduit', () => {
    const host = mount('ru', {});
    const pwd = Array.from(host.querySelectorAll('input.modal-input'))[2];
    act(() => { setNative(pwd, 'Abcdef123!xyz'); });
    expect(host.textContent).toContain(ru.editSecret.entropy);
    expect(host.textContent).toMatch(new RegExp(`\\d+ ${ru.passwordGenerator.bits}`));
    expect(host.textContent).not.toMatch(/\d+ bits/);
    act(() => { entryTypeRadios(host)[1].click(); });
    const passphrase = host.querySelector('input[type="password"]');
    expect(passphrase.placeholder).toBe(ru.sshKey.passphrasePlaceholder);
  });
});
