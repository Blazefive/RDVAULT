// ========================================
// TESTS : UI-34 — « Configurer le TOTP » : pied (Annuler / Configurer) toujours visible
// ========================================
// Avant : le <form> enveloppait le corps et le pied sans être un maillon de la colonne flex du
// panneau (overflow hidden, max-height 80vh) : le corps ne défilait plus et, à 1280×800, les
// boutons tombaient hors du panneau (inatteignables à la souris). Le formulaire porte désormais
// la classe .modal-form (colonne flex, min-height 0) : corps défilant, pied fixe.
// jsdom ne calcule pas la mise en page : on vérifie la structure et la règle CSS ; la mesure
// réelle à 1280×800 est faite sur le build (captures).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import fs from 'fs';
import path from 'path';
import TotpConfigModal from './TotpConfigModal';
import { I18nProvider } from './i18n';

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

const CSS = fs.readFileSync(path.join(__dirname, 'AppStyles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
const block = (selector) => {
  const start = CSS.indexOf(`${selector} {`);
  if (start < 0) return null;
  const open = CSS.indexOf('{', start);
  return CSS.slice(open + 1, CSS.indexOf('}', open));
};

let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
});

test('le formulaire est un maillon flex du panneau : corps défilant entre en-tête et pied', () => {
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider defaultLang="en">
        <TotpConfigModal secretName="s" totpKeyName="s" engineName="kv" onClose={() => {}} onSave={async () => {}} />
      </I18nProvider>
    ));
  });
  const form = host.querySelector('.modal-panel > form');
  expect(form).not.toBeNull();
  expect(form.classList.contains('modal-form')).toBe(true);
  expect(Array.from(form.children).map(c => c.className)).toEqual(['modal-body', 'modal-footer']);

  const rule = block('.modal-form');
  expect(rule).not.toBeNull();
  expect(rule).toMatch(/display:\s*flex/);
  expect(rule).toMatch(/flex-direction:\s*column/);
  expect(rule).toMatch(/min-height:\s*0/);
  expect(rule).toMatch(/flex:\s*1/);
  // Le corps garde son défilement interne ; le pied ne rétrécit pas
  expect(block('.modal-body')).toMatch(/overflow-y:\s*auto/);
  expect(block('.modal-footer')).toMatch(/flex-shrink:\s*0/);
});
