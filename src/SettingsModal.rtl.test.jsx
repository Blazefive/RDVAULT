// ========================================
// TESTS : SettingsModal — écriture de droite à gauche (suite I18N-31, SETTINGS-10, SETTINGS-14)
// ========================================
// Le bloc « Utilisation rapide » mêlait commandes (toujours de gauche à droite) et commentaires
// traduits avec un marginLeft fixe : en arabe, le « # commentaire » collait à la commande mvault et
// s'affichait en police à chasse fixe. Les exemples sont désormais isolés en dir="ltr" et les
// commentaires ont leur propre sens (dir="auto") et la police du texte.
// SETTINGS-10 : la marge logique portée par le commentaire (marginInlineStart) devenait une marge
// DROITE en arabe (commentaire en rtl) : 0 px entre la commande et le commentaire. L'espacement est
// maintenant porté par la commande <code>, toujours de gauche à droite (marge de fin = droite).
// SETTINGS-14 : la coche de la langue choisie (marginLeft: auto) se collait au nom en arabe et le
// bouton était aligné à gauche (textAlign: left) : propriétés logiques désormais.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SettingsModal from './SettingsModal';
import { I18nProvider } from './i18n';
import ar from './locales/ar.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

// Monte la modale en arabe
function mountAr(props = {}) {
  localStorage.setItem('rdvault-lang', 'ar');
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <SettingsModal onClose={() => {}} visibleColumns={{}} secretEngines={[]} {...props} />
      </I18nProvider>
    ));
  });
  return host;
}
const openTab = (host, label) => {
  const tab = Array.from(host.querySelectorAll('button')).find(b => b.textContent.trim() === label);
  expect(tab).toBeTruthy();
  act(() => { tab.click(); });
};

test('onglet CLI (arabe) : exemples en dir="ltr", espacement porté par la commande (SETTINGS-10)', () => {
  const host = mountAr();
  openTab(host, ar.settings.cli);

  const heading = Array.from(host.querySelectorAll('h4')).find(h => h.textContent.trim() === ar.cli.quickUsage);
  expect(heading).toBeTruthy();
  const block = heading.nextElementSibling;
  expect(block.getAttribute('dir')).toBe('ltr');

  const lines = Array.from(block.children);
  expect(lines).toHaveLength(3);
  const comments = [ar.cli.listEngines, ar.cli.readSecret, ar.cli.extractField];
  lines.forEach((line, i) => {
    const code = line.querySelector('code');
    expect(code).toBeTruthy();
    expect(code.textContent.startsWith('mvault ')).toBe(true);
    // La commande est dans un bloc dir="ltr" (et isolée en ltr par la feuille de style en RTL) :
    // sa marge de fin est toujours à droite, entre la commande et le commentaire
    expect(code.style.marginInlineEnd).toBe('16px');
    const comment = Array.from(line.querySelectorAll('span')).find(s => s.textContent === comments[i]);
    expect(comment).toBeTruthy();
    expect(comment.getAttribute('dir')).toBe('auto');
    // Plus aucune marge sur le commentaire : en rtl, elle partait du mauvais côté (0 px d'écart)
    expect(comment.style.marginInlineStart).toBe('');
    expect(comment.style.marginLeft).toBe('');
    expect(comment.style.marginRight).toBe('');
  });
});

test('onglet CLI (arabe) : noms de coffres isolés en ltr, interrupteurs en propriétés logiques', () => {
  const host = mountAr({ secretEngines: [{ name: 'users/hunt/Mes-Secrets/', version: 2 }] });
  openTab(host, ar.settings.cli);
  // « users/hunt/Mes-Secrets » : sans isolation, la barre oblique passait du mauvais côté
  const name = Array.from(host.querySelectorAll('bdi')).find(b => b.textContent === 'users/hunt/Mes-Secrets');
  expect(name).toBeTruthy();
  expect(name.getAttribute('dir')).toBe('ltr');
  expect(name.classList.contains('bidi-ltr')).toBe(true);
  // Pastille des interrupteurs : position de début de ligne (à droite en arabe), plus de « left »
  const knobs = Array.from(host.querySelectorAll('button[title] > span'));
  expect(knobs.length).toBe(2);
  for (const knob of knobs) {
    expect(knob.style.left).toBe('');
    expect(knob.style.insetInlineStart).toBe('2px');
  }
});

// Vérification visuelle (arabe) : l'en-tête étroit « جلب تلقائي (get, ssh, winrm) » passait à la ligne
// au milieu des parenthèses, inversées (« (WINRM »). La liste de commandes est isolée en ltr.
test('onglet CLI (arabe) : commandes entre parenthèses de l\'en-tête isolées en ltr', () => {
  const host = mountAr({ secretEngines: [{ name: 'Comptabilite/', version: 2 }] });
  openTab(host, ar.settings.cli);
  const header = Array.from(host.querySelectorAll('.modal-body div')).find(d => d.textContent === ar.cli.autoGet && d.children.length === 1);
  expect(header).toBeTruthy();
  const paren = header.querySelector('bdi');
  expect(paren.getAttribute('dir')).toBe('ltr');
  expect(paren.classList.contains('bidi-ltr')).toBe(true);
  expect(paren.textContent).toBe('(get, ssh, winrm)');
});

test('onglet Langue (arabe) : coche en bout de bouton et alignement logique (SETTINGS-14)', () => {
  const host = mountAr();
  openTab(host, ar.settings.language);
  const selected = Array.from(host.querySelectorAll('button')).find(b => b.textContent.includes('العربية') && b.textContent.includes('✓'));
  expect(selected).toBeTruthy();
  expect(selected.style.textAlign).toBe('start');
  const check = Array.from(selected.querySelectorAll('span')).find(s => s.textContent === '✓');
  expect(check.style.marginLeft).toBe('');
  expect(check.style.marginInlineStart).toBe('auto');
  // Aucun bouton de langue n'est aligné physiquement à gauche
  const langButtons = Array.from(host.querySelectorAll('.modal-body button'));
  expect(langButtons.length).toBe(12);
  for (const b of langButtons) expect(b.style.textAlign).toBe('start');
});

test('onglet Export (arabe) : coffres des listes isolés en ltr, sens du nom de fichier selon son contenu', () => {
  const host = mountAr({ secretEngines: [{ name: 'Comptabilite/', version: 2 }], appMode: 'local' });
  openTab(host, ar.export.title);
  const options = Array.from(host.querySelectorAll('option')).filter(o => o.value === 'Comptabilite/');
  expect(options).toHaveLength(2);
  // LRI … PDI : en arabe, la parenthèse finale de « (KV v2) » ne passe plus en tête
  for (const o of options) expect(o.textContent).toBe('\u2066Comptabilite/ (KV v2)\u2069');
  // Nom du fichier à importer : sens selon son contenu (dir="auto"), ellipse du bon côté
  const noFile = Array.from(host.querySelectorAll('span')).find(s => s.textContent === ar.export.importNoFile);
  expect(noFile).toBeTruthy();
  expect(noFile.getAttribute('dir')).toBe('auto');
});

test('onglet À propos (arabe) : retrait de liste logique', () => {
  const host = mountAr();
  openTab(host, ar.settings.about);
  const list = host.querySelector('.modal-body ul');
  expect(list.style.paddingLeft).toBe('');
  expect(list.style.paddingInlineStart).toBe('var(--sp-4)');
});

test('aucune propriété physique gauche/droite dans les styles inline de SettingsModal', () => {
  const fs = require('fs');
  const path = require('path');
  const src = fs.readFileSync(path.join(__dirname, 'SettingsModal.jsx'), 'utf8');
  expect(src.match(/\b(margin|padding)(Left|Right)\s*:/g)).toBeNull();
  expect(src.match(/textAlign:\s*'(left|right)'/g)).toBeNull();
  expect(src.match(/[{,\s](left|right):\s/g)).toBeNull();
});
