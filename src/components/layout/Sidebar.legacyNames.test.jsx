// ========================================
// TESTS : barre latérale — noms de coffres 1.5.0 enregistrés encodés (rendu réel react-dom dans jsdom)
// ========================================
// Le serveur local de la 1.5.0 ne décodait pas l'URL : certains coffres ont été enregistrés sous leur forme
// encodée (« Coffre%20%C3%A9quipe », « users/jean.dupont%40exemple.fr/Mes-Secrets »). Avant : la barre
// latérale affichait ce nom technique tel quel. Attendu : nom décodé à l'AFFICHAGE seulement ; la sélection,
// le menu contextuel, le glisser-déposer et les droits utilisent toujours le nom technique du serveur.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Sidebar, { engineDisplayName } from './Sidebar';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key) => key.split('.').reduce((o, k) => (o ? o[k] : undefined), en) || key;

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

describe('engineDisplayName : décodage d\'affichage sûr', () => {
  test.each([
    ['Coffre%20%C3%A9quipe', 'Coffre équipe'],
    ['users/jean.dupont%40exemple.fr/Mes-Secrets', 'users/jean.dupont@exemple.fr/Mes-Secrets'],
    ['Coffre%20(%C3%A9quipe)', 'Coffre (équipe)'],
    ['%D8%A7%D9%84%D9%85%D8%A7%D9%84%D9%8A%D8%A9', '\u0627\u0644\u0645\u0627\u0644\u064A\u0629'],
  ])('nom encodé « %s » → « %s »', (raw, shown) => {
    expect(engineDisplayName(raw)).toBe(shown);
  });

  test.each([
    'Banque',
    'Pro.Equipe',
    'users/alice/Mes-Secrets',
    'Taux 100%',        // « % » littéral, pas une séquence d'échappement
    '50%/z',
    'Coffre équipe%20', // espace brut : ce n'est pas une forme encodeURIComponent
    '%41',              // « A » n'est jamais encodé par encodeURIComponent
    'cl%c3%a9',         // hexadécimal minuscule : jamais produit par encodeURIComponent
    '%E9t%E9',          // UTF-8 invalide (Latin-1) : décodage impossible
    'a%2Fb',            // ferait apparaître une barre oblique dans un segment
    '%E2%80%AEevil',    // inversion de direction U+202E
    '%E2%81%A6x%E2%81%A9', // isolat LRI … PDI
    'x%00y',            // caractère de contrôle NUL
    'x%C2%85y',         // caractère de contrôle C1 (NEL)
  ])('« %s » reste affiché tel quel', (raw) => {
    expect(engineDisplayName(raw)).toBe(raw);
  });

  test('segments décodés indépendamment ; valeur non textuelle → texte', () => {
    expect(engineDisplayName('Taux 100%/Coffre%20%C3%A9quipe')).toBe('Taux 100%/Coffre équipe');
    expect(engineDisplayName(undefined)).toBe('');
    expect(engineDisplayName(null)).toBe('');
  });
});

describe('Sidebar : coffres 1.5.0 encodés affichés décodés, nom technique inchangé', () => {
  const ENGINES = [
    { name: 'Banque', version: 2, canWrite: true },
    { name: 'Coffre%20%C3%A9quipe', version: 2, canWrite: true },
    { name: 'users/jean.dupont%40exemple.fr/Mes-Secrets', version: 2, canWrite: true },
    { name: 'users/marie%40exemple.fr/Perso', version: 2, canWrite: true },
  ];

  function mount(props = {}) {
    // Nom du compte tel que le serveur l'a enregistré (lookup-self) : forme encodée pour un compte 1.5.0
    localStorage.setItem('vault-client.username', 'jean.dupont%40exemple.fr');
    const host = document.createElement('div');
    document.body.appendChild(host);
    const root = createRoot(host);
    const handlers = {
      onSelectEngine: jest.fn(),
      onEngineRightClick: jest.fn(),
      onDragOver: jest.fn(),
      onDragLeave: jest.fn(),
      onDropOnEngine: jest.fn(),
      onCreateEngine: jest.fn(),
    };
    act(() => {
      mountInRoot(root, (
        <Sidebar
          secretEngines={ENGINES}
          selectedEngine={ENGINES[1]}
          isDragging={false}
          dragOverTarget={null}
          isAdmin
          sidebarOpen={false}
          t={t}
          {...handlers}
          {...props}
        />
      ));
    });
    mounted.push(root);
    return { host, handlers };
  }

  const cards = () => Array.from(document.querySelectorAll('.engine-card'));
  const names = () => Array.from(document.querySelectorAll('.engine-name')).map(n => n.textContent);

  test('noms affichés décodés (avant : « Coffre%20%C3%A9quipe », « users/marie%40exemple.fr/Perso »)', () => {
    mount();
    expect(names()).toEqual(['Banque', 'Coffre équipe', 'Mes-Secrets', 'users/marie@exemple.fr/Perso']);
    expect(document.body.textContent).not.toContain('%20');
    expect(document.body.textContent).not.toContain('%40');
  });

  test('coffre actif, sélection, menu contextuel et dépôt : objet coffre et nom TECHNIQUES', () => {
    const { handlers } = mount();
    expect(cards()[1].getAttribute('aria-current')).toBe('true');
    act(() => { cards()[1].click(); });
    expect(handlers.onSelectEngine).toHaveBeenCalledWith(ENGINES[1]);
    expect(handlers.onSelectEngine.mock.calls[0][0].name).toBe('Coffre%20%C3%A9quipe');
    act(() => { cards()[1].dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true })); });
    expect(handlers.onEngineRightClick.mock.calls[0][1]).toBe(ENGINES[1]);
    act(() => { cards()[1].dispatchEvent(new Event('dragover', { bubbles: true })); });
    expect(handlers.onDragOver.mock.calls[0][1]).toBe('Coffre%20%C3%A9quipe');
    act(() => { cards()[1].dispatchEvent(new Event('drop', { bubbles: true })); });
    expect(handlers.onDropOnEngine.mock.calls[0][1]).toBe(ENGINES[1]);
  });

  test('droits inchangés : badge « Partagé » calculé sur le nom technique (coffre personnel exclu)', () => {
    mount();
    const shared = cards().map(c => !!c.querySelector('.badge-shared'));
    expect(shared).toEqual([true, true, false, true]);
  });

  test('cible de dépôt reconnue par le nom technique', () => {
    mount({ isDragging: true, dragOverTarget: 'Coffre%20%C3%A9quipe' });
    expect(cards().map(c => c.classList.contains('drop-target'))).toEqual([false, true, false, false]);
  });
});
