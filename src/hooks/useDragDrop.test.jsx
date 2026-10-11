// ========================================
// TESTS : useDragDrop — libellé de l'image de glisser-déposer
// ========================================
// BUG CORRIGÉ : le libellé « N entrée(s) » était codé en dur en français. Il passe désormais par
// t() avec un singulier (table.dragCountOne) et un pluriel (table.dragCountMany).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useDragDrop } from './useDragDrop';
import { I18nProvider, useTranslation } from '../i18n';
import en from '../locales/en.json';
import fr from '../locales/fr.json';
import de from '../locales/de.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;
let api = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function Harness({ selected }) {
  const { t } = useTranslation();
  api = useDragDrop({
    selectedSecrets: selected,
    setSelectedSecrets: () => {},
    isSecretSelected: (name) => selected.has(name),
    migrateSecretsToEngine: jest.fn(),
    moveSecretsToFolder: jest.fn(),
    selectedEngine: { name: 'kv', version: 2 },
    secretEngines: [{ name: 'kv', version: 2, canWrite: true }],
    showToast: jest.fn(),
    t,
  });
  return null;
}

function mount(lang, selected) {
  localStorage.setItem('rdvault-lang', lang);
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider><Harness selected={selected} /></I18nProvider>); });
}

// Démarre un glisser et renvoie le texte de l'image de glisser (élément passé à setDragImage)
function dragGhostText(secretName) {
  let ghost = null;
  const event = {
    dataTransfer: {
      setData: jest.fn(),
      setDragImage: jest.fn((el) => { ghost = el; }),
      effectAllowed: '',
    },
  };
  act(() => { api.handleDragStart(event, { name: secretName }); });
  expect(event.dataTransfer.setDragImage).toHaveBeenCalledTimes(1);
  return ghost.textContent;
}

beforeEach(() => { jest.useFakeTimers(); });

afterEach(() => {
  act(() => { jest.runOnlyPendingTimers(); });
  jest.useRealTimers();
  if (root) act(() => root.unmount());
  root = null;
  api = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const fill = (template, count) => template.replace('{{count}}', String(count));

test('anglais : singulier pour une entrée', () => {
  mount('en', new Set());
  const text = dragGhostText('gitlab');
  expect(text).toContain(fill(en.table.dragCountOne, 1));
  expect(text).not.toMatch(/entrée/);
});

test('anglais : pluriel pour une sélection de plusieurs entrées', () => {
  mount('en', new Set(['a', 'b', 'c']));
  const text = dragGhostText('a');
  expect(text).toContain(fill(en.table.dragCountMany, 3));
  expect(text).toContain('3 entries');
  expect(text).not.toMatch(/entrée/);
});

test('français : libellés identiques à l\'ancien texte', () => {
  mount('fr', new Set(['a', 'b']));
  expect(dragGhostText('a')).toContain('2 entrées');
  expect(fill(fr.table.dragCountOne, 1)).toBe('1 entrée');
});

test('allemand : libellé traduit', () => {
  mount('de', new Set());
  expect(dragGhostText('x')).toContain(fill(de.table.dragCountOne, 1));
});

test('l\'image de glisser est retirée du document après usage', () => {
  mount('en', new Set());
  dragGhostText('gitlab');
  expect(document.querySelector('.drag-ghost')).not.toBeNull();
  act(() => { jest.runOnlyPendingTimers(); });
  expect(document.querySelector('.drag-ghost')).toBeNull();
});
