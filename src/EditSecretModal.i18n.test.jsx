// ========================================
// TESTS : EditSecretModal — erreurs de validation et tailles de fichiers traduites
// ========================================
// - I18N-28 : les erreurs de validation.js (nom requis / trop long / caractères interdits,
//   identifiant, mot de passe, passphrase) s'affichaient en français dans toutes les langues
//   (« ⚠️ Le nom est requis » en anglais, allemand, arabe…).
// - I18N-34 : la taille des pièces jointes était formatée par toFixed() avec « MB / KB » codés
//   en dur (« 1.50 MB » en français et en russe) ; elle suit désormais la langue (séparateur
//   décimal et unité traduite).
// - I18N-31 : les champs techniques (URL, clés SSH) restent saisis de gauche à droite en arabe.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import EditSecretModal from './EditSecretModal';
import { I18nProvider } from './i18n';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const buttonByText = (host, txt) => Array.from(host.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
const hints = (host) => Array.from(host.querySelectorAll('.form-hint')).map(el => el.textContent.trim());
const norm = (s) => s.replace(/\s+/g, ' ').trim();

function mount(lang, props = {}) {
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

const SAVE = { en: 'Save', de: 'Speichern', ar: 'حفظ', fr: 'Enregistrer', ja: '保存' };

describe('I18N-28 : erreurs de validation de la fiche dans la langue de l\'interface', () => {
  test('anglais : « Enregistrer » avec un nom vide → « The \'Name\' field is required. »', () => {
    const onSave = jest.fn();
    const host = mount('en', { onSave });
    act(() => { buttonByText(host, SAVE.en).click(); });
    expect(onSave).not.toHaveBeenCalled();
    expect(hints(host)).toContain('⚠️ The \'Name\' field is required.');
    expect(host.textContent).not.toContain('Le nom est requis');
  });

  test('allemand : nom contenant « .. » → message allemand', () => {
    const host = mount('de');
    host.querySelector('input.modal-input').value = '../etc';
    act(() => { buttonByText(host, SAVE.de).click(); });
    expect(hints(host)).toContain('⚠️ Der Name enthält unzulässige Zeichen (.., \\)');
  });

  test('arabe : nom trop long → message arabe avec la borne', () => {
    const host = mount('ar');
    host.querySelector('input.modal-input').value = 'a'.repeat(513);
    act(() => { buttonByText(host, SAVE.ar).click(); });
    expect(hints(host)).toContain('⚠️ الاسم طويل جدًا (الحد الأقصى 512 حرفًا)');
  });

  test('japonais : identifiant et mot de passe avec caractère de contrôle', () => {
    const host = mount('ja', { initial: { name: 'srv', username: 'a\u0001b', password: 'p\u0002w', url: '', notes: '' } });
    act(() => { buttonByText(host, SAVE.ja).click(); });
    const h = hints(host);
    expect(h).toContain('⚠️ ユーザー名に制御文字が含まれています');
    expect(h).toContain('⚠️ パスワードに制御文字が含まれています');
  });

  test('français : le message reste en français', () => {
    const host = mount('fr');
    act(() => { buttonByText(host, SAVE.fr).click(); });
    expect(hints(host)).toContain('⚠️ Le champ « Nom » est requis.');
  });
});

describe('I18N-34 : taille des pièces jointes selon la langue', () => {
  const initialWith = (size) => ({
    name: 'srv', username: '', password: '', url: '', notes: '',
    attachments: [{ name: 'f.bin', size, type: 'application/octet-stream', data: 'AA==' }],
  });
  const sizeText = (host) => {
    const row = Array.from(host.querySelectorAll('span')).find(s => s.textContent.includes('f.bin'));
    return norm(row.nextElementSibling.textContent);
  };

  test('français : 1 572 864 octets → « 1,5 Mo »', () => {
    expect(sizeText(mount('fr', { initial: initialWith(1572864) }))).toBe('1,5 Mo');
  });

  test('anglais : 1 572 864 octets → « 1.5 MB » ; 1 536 octets → « 1.5 KB »', () => {
    expect(sizeText(mount('en', { initial: initialWith(1572864) }))).toBe('1.5 MB');
    expect(sizeText(mount('en', { initial: initialWith(1536) }))).toBe('1.5 KB');
  });

  test('russe : unité « МБ » de la locale (comme « Макс. размер: 2 МБ »)', () => {
    expect(sizeText(mount('ru', { initial: initialWith(1572864) }))).toBe('1,5 МБ');
  });

  test('allemand : 2 048 octets → « 2 KB »', () => {
    expect(sizeText(mount('de', { initial: initialWith(2048) }))).toBe('2 KB');
  });
});

describe('I18N-31 : champs techniques en LTR', () => {
  test('URL et clés SSH : dir="ltr" (saisie lisible dans une interface arabe)', () => {
    const host = mount('ar', { initial: { name: 'srv', username: '', password: '', url: 'https://a.example.com', notes: '' } });
    const url = Array.from(host.querySelectorAll('input.modal-input')).find(i => i.value === 'https://a.example.com');
    expect(url.getAttribute('dir')).toBe('ltr');
    const sshHost = mount('ar', { initial: { name: 'k', entryType: 'ssh', username: '', password: 'KEY', url: 'ssh-rsa AAA', notes: '' } });
    const areas = Array.from(sshHost.querySelectorAll('textarea.modal-textarea'));
    expect(areas.find(a => a.value === 'KEY').getAttribute('dir')).toBe('ltr');
    expect(areas.find(a => a.value === 'ssh-rsa AAA').getAttribute('dir')).toBe('ltr');
  });
});
