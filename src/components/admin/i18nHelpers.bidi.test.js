// ========================================
// TESTS : i18nHelpers — isolation bidi des valeurs (toasts, confirmations)
// ========================================
// - isolateInRtl : texte brut (toast) isolé seulement en RTL (LRI … PDI ou FSI … PDI), inchangé en LTR.
// - richIsolated : modèle traduit rendu avec chaque valeur dans un <bdi> (texte identique à t()).
// - isolateQuoted : passages entre guillemets d'un message déjà interpolé isolés dans un <bdi>.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { autoIsolate, isRtlDocument, isolateInRtl, isolateQuoted, ltrIsolate, richIsolated } from './i18nHelpers';

global.IS_REACT_ACT_ENVIRONMENT = true;

const LRI = String.fromCharCode(0x2066);
const FSI = String.fromCharCode(0x2068);
const PDI = String.fromCharCode(0x2069);

let roots = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function mountNodes(nodes) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, React.createElement('div', null, nodes)); });
  roots.push(root);
  return host;
}

afterEach(() => {
  roots.forEach(r => act(() => r.unmount()));
  roots = [];
  document.body.innerHTML = '';
  document.documentElement.dir = '';
});

describe('isolateInRtl', () => {
  test('LTR (ou sens non défini) : valeur renvoyée telle quelle', () => {
    expect(isRtlDocument()).toBe(false);
    expect(isolateInRtl('users/alice/')).toBe('users/alice/');
    document.documentElement.dir = 'ltr';
    expect(isolateInRtl('banque', 'auto')).toBe('banque');
  });

  test('RTL : identifiant technique entre LRI et PDI, texte libre entre FSI et PDI', () => {
    document.documentElement.dir = 'rtl';
    expect(isRtlDocument()).toBe(true);
    expect(isolateInRtl('users/alice/')).toBe(`${LRI}users/alice/${PDI}`);
    expect(isolateInRtl('بنك 2', 'auto')).toBe(`${FSI}بنك 2${PDI}`);
    expect(ltrIsolate('x')).toBe(`${LRI}x${PDI}`);
    expect(autoIsolate('x')).toBe(`${FSI}x${PDI}`);
  });

  test('RTL : valeur vide ou absente non modifiée', () => {
    document.documentElement.dir = 'rtl';
    expect(isolateInRtl('')).toBe('');
    expect(isolateInRtl(undefined)).toBeUndefined();
    expect(isolateInRtl(null)).toBeNull();
  });
});

describe('richIsolated', () => {
  test('valeurs dans des <bdi> ; texte identique au modèle interpolé', () => {
    const host = mountNodes(richIsolated('Supprimer « {{name}} » du coffre {{path}} ?', { name: 'banque', path: 'users/a/perso' }, ['path']));
    const [free, tech] = host.querySelectorAll('bdi');
    expect(free.getAttribute('dir')).toBeNull();
    expect(free.textContent).toBe('banque');
    expect(tech.getAttribute('dir')).toBe('ltr');
    expect(tech.className).toBe('bidi-ltr');
    expect(host.textContent).toBe('Supprimer « banque » du coffre users/a/perso ?');
  });

  test('barre oblique qui suit un identifiant technique : rattachée à l\'isolat', () => {
    const host = mountNodes(richIsolated('Coffre : {{path}}/', { path: 'Compta' }, ['path']));
    expect(host.querySelector('bdi').textContent).toBe('Compta/');
    expect(host.textContent).toBe('Coffre : Compta/');
  });

  test('variable absente ou nulle : marqueur conservé, comme t()', () => {
    const host = mountNodes(richIsolated('{{a}} et {{b}}', { a: null }));
    expect(host.textContent).toBe('{{a}} et {{b}}');
    expect(host.querySelector('bdi')).toBeNull();
  });

  test('nombre : rendu en texte', () => {
    expect(mountNodes(richIsolated('{{n}} entrées', { n: 3 })).textContent).toBe('3 entrées');
  });
});

describe('isolateQuoted', () => {
  test.each([
    ['guillemets droits', 'حذف الخزنة "users/alice/perso/"؟', 'users/alice/perso/'],
    ['chevrons avec espaces insécables', 'Supprimer « banque » ?', 'banque'],
    ['chevrons arabes collés', 'مفتاح TOTP الخاص بـ «banque» نهائيًا', 'banque'],
    ['guillemets anglais', 'Delete “prod/db”?', 'prod/db'],
    ['guillemets allemands', 'Löschen „prod/db“?', 'prod/db'],
    ['crochets japonais', '「prod/db」を削除しますか？', 'prod/db'],
  ])('%s : contenu isolé, texte inchangé', (_label, text, inner) => {
    const host = mountNodes(isolateQuoted(text));
    expect(host.querySelector('bdi').textContent).toBe(inner);
    expect(host.textContent).toBe(text);
  });

  test('plusieurs valeurs : chacune isolée', () => {
    const text = 'Ouvrir "https://intranet.example" en tant que « svc » ?';
    const host = mountNodes(isolateQuoted(text));
    expect(Array.from(host.querySelectorAll('bdi')).map(b => b.textContent)).toEqual(['https://intranet.example', 'svc']);
    expect(host.textContent).toBe(text);
  });

  test('sans guillemets ou guillemet non fermé : texte renvoyé tel quel', () => {
    expect(isolateQuoted('Sûr ?')).toBe('Sûr ?');
    expect(isolateQuoted('Taille 5" maximum')).toBe('Taille 5" maximum');
  });
});
