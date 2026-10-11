// ========================================
// TESTS : utilitaires i18n du panneau d'administration
// ========================================
// - tPlural : en français, résultat identique aux anciens messages codés en dur
//   (singulier pour 0 et 1) ; règles de pluriel propres à chaque langue ailleurs.
// - richText : insertion d'éléments React dans une traduction.
// - formatDateTime : langue de l'application, repli sans exception si code invalide.
// - Ltr / richLtr / ltrIsolate / ltrWhenFilled : identifiants techniques en ltr (ADMIN-11).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider, useTranslation } from '../../i18n';
import { richText, tPlural, formatDateTime, Ltr, ltrIsolate, richLtr, ltrWhenFilled } from './i18nHelpers';

global.IS_REACT_ACT_ENVIRONMENT = true;

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

// Récupère la vraie fonction t() du fournisseur i18n pour une langue donnée
function getT(lang) {
  localStorage.setItem('rdvault-lang', lang);
  let captured = null;
  function Capture() {
    captured = useTranslation().t;
    return null;
  }
  const root = createRoot(document.createElement('div'));
  act(() => { mountInRoot(root, <I18nProvider><Capture /></I18nProvider>); });
  act(() => root.unmount());
  localStorage.clear();
  return captured;
}

describe('tPlural', () => {
  test('français : mêmes messages que l\'ancien code (pluriel au-delà de 1)', () => {
    const t = getT('fr');
    const tp = (key, n) => tPlural(t, 'fr', key, n);
    // Ancien code : `${n} secret${n > 1 ? 's' : ''} exporté${n > 1 ? 's' : ''}`
    const old = (n) => `${n} secret${n > 1 ? 's' : ''} exporté${n > 1 ? 's' : ''}`;
    for (const n of [0, 1, 2, 37]) expect(tp('admin.toast.secretsExported', n)).toBe(old(n));
    expect(t('admin.toast.exportPartial', {
      exported: tp('admin.toast.secretsExported', 3),
      unreadable: tp('admin.toast.unreadable', 1),
    })).toBe('Export partiel : 3 secrets exportés, 1 illisible');
    expect(t('admin.toast.migrationDone', { added: tp('admin.toast.tagsAdded', 2), total: 5 }))
      .toBe('Migration terminée : 2 tags ajoutés aux tags partagés (5 tags trouvés dans les coffres)');
    expect(tp('admin.ldap.groupsConfigured', 0)).toBe('groupe configuré dans Vault');
    expect(tp('admin.ldap.groupsConfigured', 4)).toBe('groupes configurés dans Vault');
  });

  test('anglais et russe : règles de pluriel de la langue', () => {
    const tEn = getT('en');
    expect(tPlural(tEn, 'en', 'admin.toast.secretsExported', 1)).toBe('1 secret exported');
    expect(tPlural(tEn, 'en', 'admin.toast.secretsExported', 0)).toBe('0 secrets exported');
    const tRu = getT('ru');
    expect(tPlural(tRu, 'ru', 'admin.policy.groupCount', 21)).toBe('(21 группа)');
    expect(tPlural(tRu, 'ru', 'admin.policy.groupCount', 5)).toBe('(групп: 5)');
  });

  test('code de langue invalide : repli (pluriel au-delà de 1), sans exception', () => {
    const t = (key, vars) => `${key}:${vars.count}`;
    expect(tPlural(t, 'fr_FR!', 'k', 1)).toBe('kOne:1');
    expect(tPlural(t, 'fr_FR!', 'k', 2)).toBe('kMany:2');
  });
});

test('richText : remplace les marqueurs par des éléments, conserve les inconnus', () => {
  const host = document.createElement('div');
  const root = createRoot(host);
  act(() => {
    mountInRoot(root, <p>{richText('A {{x}} B {{y}} C', { x: <code>X</code> })}</p>);
  });
  expect(host.innerHTML).toBe('<p>A <code>X</code> B {{y}} C</p>');
  act(() => root.unmount());
});

// ADMIN-11 : identifiants techniques isolés et lus de gauche à droite (arabe)
describe('isolation des identifiants techniques', () => {
  const toHtml = (element) => {
    const host = document.createElement('div');
    const root = createRoot(host);
    act(() => { mountInRoot(root, element); });
    const html = host.innerHTML;
    act(() => root.unmount());
    return html;
  };

  test('Ltr : <bdi dir="ltr" class="bidi-ltr">', () => {
    expect(toHtml(<Ltr>Comptabilite/</Ltr>)).toBe('<bdi dir="ltr" class="bidi-ltr">Comptabilite/</bdi>');
  });

  test('richLtr : barre oblique qui suit le marqueur rattachée à l\'isolat, texte inchangé', () => {
    const t = getT('ar');
    const html = toHtml(<h3>{richLtr(t('admin.mount.title'), 'path', 'users/hunt/Mes-Secrets')}</h3>);
    expect(html).toBe('<h3>الخزنة: <bdi dir="ltr" class="bidi-ltr">users/hunt/Mes-Secrets/</bdi></h3>');
    // Sans barre oblique dans le modèle : la valeur seule est isolée
    expect(toHtml(<p>{richLtr('Policy: {{name}}', 'name', 'app-ro')}</p>))
      .toBe('<p>Policy: <bdi dir="ltr" class="bidi-ltr">app-ro</bdi></p>');
    // Dans les 12 langues, le titre de coffre rendu est identique à t(clé, { path })
    for (const lang of ['ar', 'de', 'en', 'es', 'fr', 'it', 'ja', 'ko', 'pt', 'ru', 'tr', 'zh']) {
      const tl = getT(lang);
      const host = document.createElement('div');
      const root = createRoot(host);
      act(() => { mountInRoot(root, <h3>{richLtr(tl('admin.mount.title'), 'path', 'kv')}</h3>); });
      expect([lang, host.textContent]).toEqual([lang, tl('admin.mount.title', { path: 'kv' })]);
      act(() => root.unmount());
    }
  });

  test('ltrIsolate : LRI … PDI pour un texte brut (<option>)', () => {
    expect(ltrIsolate('kv/ (KV v2)')).toBe('\u2066kv/ (KV v2)\u2069');
  });

  test('ltrWhenFilled : ltr dès qu\'une valeur est saisie, sens de la langue si vide', () => {
    expect(ltrWhenFilled('10.0.0.5')).toBe('ltr');
    expect(ltrWhenFilled('')).toBeUndefined();
    expect(ltrWhenFilled(undefined)).toBeUndefined();
  });
});

test('formatDateTime : langue de l\'application, repli si code invalide', () => {
  const iso = '2026-03-05T14:07:09Z';
  expect(formatDateTime(iso, 'en')).toBe(new Date(iso).toLocaleString('en'));
  expect(formatDateTime(iso, 'fr')).toBe(new Date(iso).toLocaleString('fr-FR'));
  expect(() => formatDateTime(iso, 'fr_FR!')).not.toThrow();
  expect(formatDateTime(iso, 'fr_FR!')).toBe(new Date(iso).toLocaleString());
});
