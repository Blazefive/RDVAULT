// ========================================
// TESTS : SettingsModal — dialogue d'import (rendu réel react-dom dans jsdom)
// ========================================
// Le filtre « tous les fichiers » du dialogue système est traduit (export.allFiles)
// au lieu d'être codé en dur en anglais.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SettingsModal from './SettingsModal';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé, aucun appel réseau ici
jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

// Indique à React qu'on est dans un environnement de test avec act()
global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
  delete window.electronExport;
});

test('import : le filtre « tous les fichiers » du dialogue suit la langue de l\'interface', async () => {
  localStorage.setItem('rdvault-lang', 'fr');
  const openFile = jest.fn().mockResolvedValue({ success: false, canceled: true });
  window.electronExport = { openFile };
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <SettingsModal onClose={() => {}} />
      </I18nProvider>
    ));
  });
  const button = (txt) => Array.from(host.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
  act(() => { button(fr.export.title).click(); });
  await act(async () => { button(fr.export.importSelectFile).click(); });
  expect(openFile).toHaveBeenCalledTimes(1);
  const { filters } = openFile.mock.calls[0][0];
  expect(typeof fr.export.allFiles).toBe('string');
  expect(filters).toContainEqual({ name: fr.export.allFiles, extensions: ['*'] });
  expect(filters.some(f => f.name === 'All Files')).toBe(false);
});

// Monte la modale avec des props par défaut (langue française)
function mountSettings(props = {}) {
  localStorage.setItem('rdvault-lang', 'fr');
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <SettingsModal onClose={() => {}} visibleColumns={{}} {...props} />
      </I18nProvider>
    ));
  });
  return host;
}

// SETTINGS-32 : les radios de thème étaient en display:none, donc hors de l'ordre de tabulation
test('apparence : les radios de thème restent focalisables et changent le thème au clavier', () => {
  const onToggleDarkMode = jest.fn();
  const host = mountSettings({ darkMode: false, onToggleDarkMode });
  const radios = Array.from(host.querySelectorAll('input[type="radio"][name="theme"]'));
  expect(radios).toHaveLength(2);
  for (const r of radios) {
    expect(r.style.display).not.toBe('none');
    expect(r.style.visibility).not.toBe('hidden');
    expect(r.hidden).toBe(false);
    expect(r.tabIndex).toBeGreaterThanOrEqual(0);
  }
  // Focus clavier sur « Mode sombre » : la carte affiche un anneau de focus
  const darkCard = radios[1].closest('label');
  expect(darkCard.style.outline).toBe('');
  act(() => { radios[1].focus(); });
  expect(document.activeElement).toBe(radios[1]);
  expect(darkCard.style.outline).not.toBe('');
  // Espace / flèche sur un radio = activation (click) → change → bascule du thème
  act(() => { radios[1].click(); });
  expect(onToggleDarkMode).toHaveBeenCalledTimes(1);
  act(() => { radios[1].blur(); });
  expect(darkCard.style.outline).toBe('');
});

// SETTINGS-38 : une sélection de texte qui déborde du panneau ne doit pas fermer la modale
test('fond : une sélection commencée dans le panneau et relâchée sur le fond ne ferme pas', () => {
  const onClose = jest.fn();
  const host = mountSettings({ onClose });
  const overlay = host.querySelector('.modal-overlay');
  const title = host.querySelector('.modal-header h2');
  const fire = (el, type, x, y) => el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: y }));
  act(() => {
    fire(title, 'mousedown', 100, 40);
    fire(overlay, 'mouseup', 900, 40);
    fire(overlay, 'click', 900, 40); // Chromium envoie le click à l'ancêtre commun : le fond
  });
  expect(onClose).not.toHaveBeenCalled();
  // Glisser sur le fond lui-même (> 5 px) : pas une fermeture non plus
  act(() => {
    fire(overlay, 'mousedown', 5, 5);
    fire(overlay, 'mouseup', 60, 5);
    fire(overlay, 'click', 60, 5);
  });
  expect(onClose).not.toHaveBeenCalled();
  // Vrai clic sur le fond : fermeture
  act(() => {
    fire(overlay, 'mousedown', 5, 5);
    fire(overlay, 'mouseup', 6, 5);
    fire(overlay, 'click', 6, 5);
  });
  expect(onClose).toHaveBeenCalledTimes(1);
});

// SETTINGS-12 : en nowrap + overflow-x auto, la barre débordait dès 1280×800 dans 9 langues sur 12
// (barre de défilement de 15 px, « О програ… » coupé en russe). Désormais : onglets plus compacts
// (tiennent sur une ligne dans les 12 langues à la taille par défaut, vérifié par captures) et
// retour à la ligne propre en dernier recours (fenêtre étroite) ; un libellé ne se coupe jamais.
test('onglets : retour à la ligne en dernier recours, jamais de défilement horizontal (SETTINGS-12)', () => {
  const host = mountSettings();
  const bar = host.querySelector('.tab-button').parentElement;
  expect(bar.style.flexWrap).toBe('wrap');
  expect(bar.style.overflowX).toBe('');
  expect(bar.style.whiteSpace).toBe('');
  // Libellé sur une ligne et marge intérieure réduite : règle .tab-button de la feuille de style
  const fs = require('fs');
  const path = require('path');
  const css = fs.readFileSync(path.join(__dirname, 'AppStyles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  const rule = css.match(/\.tab-button\s*\{([^}]*)\}/)[1];
  expect(rule).toMatch(/white-space:\s*nowrap/);
  expect(rule).toMatch(/padding:\s*var\(--sp-3\)\s+var\(--sp-3\)/);
});

// SETTINGS-13 : les onglets partagent le même corps défilant ; sa position était conservée d'un
// onglet à l'autre (l'onglet Export s'ouvrait défilé, titre caché)
test('changement d\'onglet : le contenu repart du haut (SETTINGS-13)', () => {
  const host = mountSettings();
  const tab = (txt) => Array.from(host.querySelectorAll('.tab-button')).find(b => b.textContent.trim() === txt);
  act(() => { tab(fr.settings.language).click(); });
  const body = host.querySelector('.modal-body');
  body.scrollTop = 93; // jsdom conserve la valeur affectée
  expect(body.scrollTop).toBe(93);
  act(() => { tab(fr.export.title).click(); });
  expect(host.querySelector('.modal-body').scrollTop).toBe(0);
  expect(host.querySelector('.modal-body h3').textContent).toBe(fr.export.title);
  // Re-cliquer l'onglet actif ne remet pas la lecture à zéro
  host.querySelector('.modal-body').scrollTop = 40;
  act(() => { tab(fr.export.title).click(); });
  expect(host.querySelector('.modal-body').scrollTop).toBe(40);
});

// Notes UI : texte blanc sur fond d'accent → jeton --accent-fill (contraste du thème sombre).
// jsdom (cssstyle) ignore les valeurs `background: var(...)` : vérification sur le source.
test('interrupteurs CLI : fond actif sur var(--accent-fill, var(--accent))', () => {
  const fs = require('fs');
  const path = require('path');
  const src = fs.readFileSync(path.join(__dirname, 'SettingsModal.jsx'), 'utf8');
  expect(src).not.toMatch(/background:\s*[^\n]*\?\s*'var\(--accent\)'/);
  expect((src.match(/\? 'var\(--accent-fill, var\(--accent\)\)'/g) || []).length).toBe(2);
});
