// ========================================
// TESTS : useDragDrop — filtre défensif du glisser (APP-4)
// ========================================
// La sélection est indexée par nom. Un glisser n'emporte que les entrées AFFICHÉES du coffre
// sélectionné : jamais un homonyme d'un autre coffre, une entrée masquée par la recherche ou le dossier
// ouvert, un dossier, une entrée supprimée ni la clé « coffre + nom » d'un résultat d'un autre coffre.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useDragDrop } from './useDragDrop';

global.IS_REACT_ACT_ENVIRONMENT = true;

let root = null;
let api = null;
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (k, v) => (v ? `${k} ${JSON.stringify(v)}` : k);
// Clé de sélection d'un résultat d'un autre coffre (useSelection : coffre + NUL + nom)
const foreignKey = (engine, name) => `${engine}${String.fromCharCode(0)}${name}`;

function Harness({ selected, displayedSecretsRef }) {
  api = useDragDrop({
    selectedSecrets: selected,
    setSelectedSecrets: () => {},
    isSecretSelected: (name) => selected.has(name),
    migrateSecretsToEngine: jest.fn(),
    moveSecretsToFolder: jest.fn(),
    selectedEngine: { name: 'Beta', version: 2 },
    secretEngines: [{ name: 'Beta', version: 2, canWrite: true }, { name: 'Gamma', version: 2, canWrite: true }],
    displayedSecretsRef,
    showToast: jest.fn(),
    t,
  });
  return null;
}

function mount(selected, displayed) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const displayedSecretsRef = displayed === undefined ? undefined : { current: displayed };
  act(() => { mountInRoot(root, <Harness selected={new Set(selected)} displayedSecretsRef={displayedSecretsRef} />); });
}

// Démarre un glisser sur `secret` ; renvoie les données posées (null si aucun glisser)
function drag(secret) {
  const store = {};
  const event = {
    preventDefault: jest.fn(),
    dataTransfer: { setData: (k, v) => { store[k] = v; }, setDragImage: () => {}, effectAllowed: '' },
  };
  act(() => { api.handleDragStart(event, secret); });
  return { data: store['application/json'] ? JSON.parse(store['application/json']) : null, event };
}

beforeEach(() => { jest.useFakeTimers(); });
afterEach(() => {
  act(() => { jest.runOnlyPendingTimers(); });
  jest.useRealTimers();
  if (root) act(() => root.unmount());
  root = null;
  api = null;
  document.body.innerHTML = '';
});

test('entrée sélectionnée puis masquée (recherche, autre dossier) : non emportée', () => {
  mount(['vpn', 'prod-db', 'cache'], [{ name: 'vpn' }, { name: 'prod-db' }]);
  const { data } = drag({ name: 'vpn' });
  expect(data.secrets).toEqual(['vpn', 'prod-db']);
  expect(data.sourceEngine).toBe('Beta');
});

test('homonyme affiché pour un AUTRE coffre (recherche multi-coffres) : non emporté', () => {
  mount(['vpn', 'prod-db'], [{ name: 'vpn' }, { name: 'prod-db', engineName: 'Alpha' }]);
  expect(drag({ name: 'vpn' }).data.secrets).toEqual(['vpn']);
});

test('résultat du coffre sélectionné en recherche multi-coffres (engineName = coffre sélectionné) : emporté', () => {
  mount(['vpn', 'wifi'], [{ name: 'vpn', engineName: 'Beta' }, { name: 'wifi', engineName: 'Beta' }]);
  expect(drag({ name: 'wifi', engineName: 'Beta' }).data.secrets).toEqual(['vpn', 'wifi']);
});

test('dossier et entrée supprimée de la liste affichée : jamais emportés', () => {
  mount(['vpn', 'prod', 'ancien'], [{ name: 'vpn' }, { name: 'prod', isFolder: true }, { name: 'ancien', deleted: true }]);
  expect(drag({ name: 'vpn' }).data.secrets).toEqual(['vpn']);
});

test('clé « coffre + nom » d\'un autre coffre dans la sélection : écartée, même sans liste affichée', () => {
  mount(['vpn', foreignKey('Alpha', 'vpn')]);
  expect(drag({ name: 'vpn' }).data.secrets).toEqual(['vpn']);
});

test('ligne glissée absente des lignes affichées du coffre sélectionné : aucun glisser', () => {
  mount(['vpn'], [{ name: 'wifi' }]);
  const { data, event } = drag({ name: 'vpn' });
  expect(data).toBeNull();
  expect(event.preventDefault).toHaveBeenCalled();
  expect(api.isDragging).toBe(false);
});

test('sans liste affichée fournie : comportement inchangé (toute la sélection)', () => {
  mount(['a', 'b', 'c']);
  expect(drag({ name: 'a' }).data.secrets).toEqual(['a', 'b', 'c']);
});

test('ligne hors sélection : glissée seule (comportement inchangé)', () => {
  mount(['a', 'b'], [{ name: 'a' }, { name: 'b' }, { name: 'c' }]);
  expect(drag({ name: 'c' }).data.secrets).toEqual(['c']);
});
