// ========================================
// TESTS : error boundary racine (src/index.js) — TREE-10
// ========================================
// Sans error boundary, une exception de rendu démontait toute la racine React 18 : fenêtre vide,
// sans moyen d'en sortir. L'écran de secours est traduit, propose de recharger l'interface et
// n'affiche jamais le message ni la pile de l'erreur (ils peuvent contenir un secret).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';
import ar from './locales/ar.json';
import en from './locales/en.json';

// index.js importe App (et donc axios, publié en ESM) : simulé, aucun appel réseau ici
jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

// Import après le mock : sans élément #root, index.js ne monte rien (pas d'effet de bord)
const { RootErrorBoundary } = require('./index');

const SECRET = 'MDP-TRES-SECRET-42';
function Exploding() {
  throw new Error(`rendu impossible : mot de passe ${SECRET}`);
}

let root; let host; let consoleError;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  // React journalise l'erreur capturée : silencieux ici (le test vérifie l'écran, pas la console)
  consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  localStorage.clear();
  consoleError.mockRestore();
});

function render(lang, child) {
  localStorage.setItem('rdvault-lang', lang);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <RootErrorBoundary>{child}</RootErrorBoundary>
      </I18nProvider>
    ));
  });
}

test('sans erreur : les enfants sont rendus tels quels', () => {
  render('fr', <p className="contenu">contenu normal</p>);
  expect(host.querySelector('.contenu').textContent).toBe('contenu normal');
  expect(host.querySelector('.crash-screen')).toBeNull();
});

test('exception de rendu : écran de secours traduit (fr), jamais le texte de l\'erreur', () => {
  render('fr', <Exploding />);
  const screen = host.querySelector('.crash-screen');
  expect(screen).not.toBeNull(); // avant : racine démontée, conteneur vide
  expect(screen.getAttribute('role')).toBe('alert');
  expect(screen.textContent).toContain(fr.crash.title);
  expect(screen.textContent).toContain(fr.crash.message);
  expect(screen.querySelector('button').textContent).toBe(fr.crash.reload);
  expect(host.textContent).not.toContain(SECRET);
  expect(host.textContent).not.toContain('rendu impossible');
});

test('langue de l\'interface suivie (arabe)', () => {
  render('ar', <Exploding />);
  expect(host.querySelector('.crash-screen h1').textContent).toBe(ar.crash.title);
});

test('le bouton recharge l\'interface', () => {
  const reload = jest.fn();
  const original = window.location;
  delete window.location;
  window.location = { ...original, reload };
  try {
    render('fr', <Exploding />);
    act(() => { host.querySelector('.crash-screen button').click(); });
    expect(reload).toHaveBeenCalledTimes(1);
  } finally {
    window.location = original;
  }
});

test('hors I18nProvider : repli en anglais (jamais une clé brute)', () => {
  act(() => { mountInRoot(root, <RootErrorBoundary><Exploding /></RootErrorBoundary>); });
  expect(host.querySelector('.crash-screen h1').textContent).toBe(en.crash.title);
  expect(host.textContent).not.toContain('crash.');
});

test('le journal ne reçoit ni le message ni la pile de l\'erreur', () => {
  const logs = [];
  const spies = ['log', 'info', 'warn', 'debug'].map(m => jest.spyOn(console, m).mockImplementation((...a) => logs.push(a.join(' '))));
  try {
    render('fr', <Exploding />);
    // Les seuls messages de console autorisés à contenir l'erreur sont ceux de React (console.error,
    // mode développement) ; l'application elle-même (secureLogger) n'écrit rien de l'erreur.
    expect(logs.join('\n')).not.toContain(SECRET);
  } finally {
    spies.forEach(s => s.mockRestore());
  }
});
