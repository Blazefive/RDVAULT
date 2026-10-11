// ========================================
// TESTS : useTreeView / buildTree — dossiers nommés comme une propriété d'Object.prototype (TREE-10)
// ========================================
// Avant : `folders: {}` (objet littéral) → « constructor », « toString », « valueOf »,
// « hasOwnProperty », « __proto__ » lus comme propriétés HÉRITÉES : dossier non créé, puis
// TypeError « Cannot read properties of undefined (reading 'push') » et rendu entier démonté.
import { act } from 'react';
import { buildTree, useTreeView } from './useTreeView';
import { renderHook } from './testUtils/fakeVault';

global.IS_REACT_ACT_ENVIRONMENT = true;

const PROTO_NAMES = ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__', 'isPrototypeOf'];

afterEach(() => {
  document.body.innerHTML = '';
  localStorage.clear();
});

describe('buildTree', () => {
  test.each(PROTO_NAMES)('dossier « %s » : créé comme un dossier ordinaire', (folder) => {
    const tree = buildTree([{ name: `${folder}/db` }, { name: 'prod/web' }, { name: 'racine' }]);
    expect(Object.keys(tree.folders).sort()).toEqual([folder, 'prod'].sort());
    expect(tree.folders[folder].secrets).toEqual([{ name: `${folder}/db`, displayName: 'db' }]);
    expect(tree.secrets).toEqual([{ name: 'racine' }]);
  });

  test('sous-dossier imbriqué « a/__proto__/constructor/x » et placeholders masqués', () => {
    const tree = buildTree([
      { name: 'a/__proto__/constructor/x' },
      { name: 'a/__proto__/.placeholder' },
      { name: '.placeholder' },
    ]);
    const nested = tree.folders.a.folders.__proto__;
    expect(Object.keys(tree.folders.a.folders)).toEqual(['__proto__']);
    expect(nested.secrets).toEqual([]);
    expect(nested.folders.constructor.secrets).toEqual([{ name: 'a/__proto__/constructor/x', displayName: 'x' }]);
    expect(tree.secrets).toEqual([]);
    // Aucun effet sur Object.prototype
    expect(({}).x).toBeUndefined();
  });
});

describe('useTreeView', () => {
  test('arborescence active : racine puis navigation dans le dossier « constructor »', () => {
    localStorage.setItem('rdvault-tree-view-enabled', 'true');
    const secrets = [{ name: 'constructor/serveur' }, { name: 'toString/db' }, { name: 'prod/web' }];
    const { result, unmount } = renderHook(() => useTreeView(secrets));
    expect(result.current.currentFolderContent.map(s => s.name).sort()).toEqual(['constructor', 'prod', 'toString']);
    act(() => { result.current.setCurrentPath('constructor'); });
    expect(result.current.currentFolderContent).toEqual([{ name: 'constructor/serveur', displayName: 'serveur' }]);
    // Chemin inexistant nommé comme une propriété héritée : retour à la racine, pas d'exception
    act(() => { result.current.setCurrentPath('hasOwnProperty'); });
    expect(result.current.currentPath).toBe('');
    unmount();
  });
});
