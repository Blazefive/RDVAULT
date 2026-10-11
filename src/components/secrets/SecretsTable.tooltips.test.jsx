// ========================================
// TESTS : tableau des secrets — infobulles des cellules tronquées (TABLE-19)
// ========================================
// Les cellules ont white-space: nowrap + text-overflow: ellipsis (AppStyles.css) : un nom, un
// identifiant ou une URL longs s'affichaient « serveur-de-produc… » sans aucun moyen de lire le texte
// complet (hors redimensionnement de la colonne). Attendu : infobulle (title) avec le texte complet
// sur le nom, le coffre (recherche multi-coffres), l'identifiant, l'URL et les notes ; JAMAIS sur la
// cellule mot de passe (ni sur aucune autre : aucun mot de passe ni champ protégé dans un title).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretsTable from './SecretsTable';
import en from '../../locales/en.json';

jest.mock('../../utils/urlHandler', () => ({ handleUrlAction: jest.fn().mockResolvedValue(undefined) }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

const LONG_NAME = 'serveur-de-production-avec-un-nom-tres-long-pour-tester';
const LONG_NOTES = 'n'.repeat(5000);
const SECRETS = [
  { name: LONG_NAME, username: 'administrateur@entreprise.example', password: 'MDP-SECRET-1', url: 'https://srv.example.com:8443/admin', notes: 'note courte', tags: '' },
  { name: 'Banque/compte-courant', username: 'alice', password: 'MDP-SECRET-2', url: 'https://banque.example.com', notes: LONG_NOTES, tags: '' },
  { name: 'vide', username: '', password: 'MDP-SECRET-3', url: '', notes: '', tags: '', customFields: [{ key: 'PIN', value: 'PIN-PROTEGE', protected: true }, { key: 'Port', value: '22' }] },
  { name: 'rbi', username: 'cache@rbi.example', password: 'MDP-SECRET-4', url: 'https://rbi.example', notes: 'notes rbi', tags: '' },
  { name: 'old', username: 'bob', password: 'MDP-SECRET-5', url: '', notes: '', tags: '', deleted: true },
];

function mount(props = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  const noop = () => {};
  const all = {
    filteredSecrets: SECRETS, secrets: SECRETS, allVaultSecrets: [],
    selectedEngine: { name: 'kv', version: 2 },
    loadingSecrets: false, multiVaultSearch: false, search: '',
    visiblePasswords: {}, setVisiblePasswords: noop,
    effectiveVisibleColumns: { name: true, username: true, password: true, url: true, notes: true, tags: true, customFields: true },
    columnWidths: {}, resizingColumn: null, isCurrentEngineRbiOnly: false, token: 'tok',
    selectedSecrets: new Set(), isSecretSelected: () => false, toggleSecretSelection: noop, displayedSecretsRef: { current: null },
    isDragging: false, dragOverTarget: null,
    handleDragStart: noop, handleDragEnd: noop, handleDragOver: noop, handleDragLeave: noop, handleDropOnFolder: noop,
    handleColumnResizeStart: noop, autoFitColumn: noop, handleColumnHeaderRightClick: noop,
    handleEmptyAreaRightClick: noop, handleCellRightClick: noop, handleFolderRightClick: noop, handleTagCellRightClick: noop,
    isSecretRbiOnly: (name) => name === 'rbi',
    startClipboardTimer: noop, setNotesPopup: noop, setCurrentPath: noop, getTagColor: () => '#888',
    getTotpKeyName: (n) => n, getTotpCode: noop, showToast: noop, t,
    ...props,
  };
  act(() => { mountInRoot(root, <SecretsTable {...all} />); });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
});

// Colonnes : nom, identifiant, mot de passe, URL, notes, tags, champs personnalisés
const rowOf = (host, name) => Array.from(host.querySelectorAll('tbody tr')).find(tr => tr.querySelector('td.cell-name')?.textContent.includes(name.split('/').pop()));
const cells = (tr) => Array.from(tr.children);
const allTitles = (host) => Array.from(host.querySelectorAll('[title]')).map(el => el.getAttribute('title'));

describe('TABLE-19 — infobulles des cellules tronquées', () => {
  test('nom, identifiant et URL : texte complet en infobulle', () => {
    const host = mount();
    const [name, user, , url] = cells(rowOf(host, LONG_NAME));
    expect(name.getAttribute('title')).toBe(LONG_NAME);
    expect(user.getAttribute('title')).toBe('administrateur@entreprise.example');
    expect(url.querySelector('button.url-link').getAttribute('title')).toBe('https://srv.example.com:8443/admin');
  });

  test('nom dans un dossier (vue liste) : chemin complet en infobulle', () => {
    const host = mount();
    expect(cells(rowOf(host, 'Banque/compte-courant'))[0].getAttribute('title')).toBe('Banque/compte-courant');
  });

  test('notes : infobulle, bornée pour une note très longue', () => {
    const host = mount();
    expect(cells(rowOf(host, LONG_NAME))[4].getAttribute('title')).toBe('note courte');
    const long = cells(rowOf(host, 'Banque/compte-courant'))[4].getAttribute('title');
    expect(long.length).toBeLessThanOrEqual(1001);
    expect(long.startsWith('nnnn')).toBe(true);
    expect(long.endsWith('…')).toBe(true);
  });

  test('valeur vide : pas d\'attribut title vide', () => {
    const host = mount();
    const [, user, , url, notes] = cells(rowOf(host, 'vide'));
    expect(user.hasAttribute('title')).toBe(false);
    expect(url.hasAttribute('title')).toBe(false);
    expect(notes.hasAttribute('title')).toBe(false);
  });

  test('entrée « RBI uniquement » : identifiant et notes masqués, aucune infobulle les révélant', () => {
    const host = mount();
    const [name, user, , , notes] = cells(rowOf(host, 'rbi'));
    expect(name.getAttribute('title')).toBe('rbi');
    expect(user.hasAttribute('title')).toBe(false);
    expect(notes.hasAttribute('title')).toBe(false);
    expect(allTitles(host).some(v => v.includes('cache@rbi.example') || v.includes('notes rbi'))).toBe(false);
  });

  test('recherche multi-coffres : nom du coffre en infobulle', () => {
    const results = [{ ...SECRETS[0], engineName: 'users/jean.dupont/Coffre-de-production-tres-long' }];
    const host = mount({ multiVaultSearch: true, search: 'serveur', allVaultSecrets: results, filteredSecrets: results });
    const engineCell = cells(host.querySelector('tbody tr'))[1];
    expect(engineCell.getAttribute('title')).toBe('users/jean.dupont/Coffre-de-production-tres-long');
  });

  test.each([
    ['masqué', {}],
    ['révélé', { visiblePasswords: Object.fromEntries(SECRETS.map(s => [s.name, true])) }],
  ])('mot de passe %s : jamais en infobulle ; champ protégé non plus', (_, props) => {
    const host = mount(props);
    const titles = allTitles(host);
    expect(titles.some(v => /MDP-SECRET/.test(v))).toBe(false);
    expect(titles.some(v => v.includes('PIN-PROTEGE'))).toBe(false);
    // Cellule mot de passe : aucun title sur la cellule ni sur le texte (seul le bouton œil a son libellé)
    const pwd = cells(rowOf(host, LONG_NAME))[2];
    expect(pwd.hasAttribute('title')).toBe(false);
    expect(Array.from(pwd.querySelectorAll('[title]')).map(el => el.tagName)).toEqual(['BUTTON']);
  });
});
