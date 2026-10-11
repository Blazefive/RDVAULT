// ========================================
// TESTS : useSelection — clés des lignes (recherche multi-coffres)
// ========================================
// Avant : sélection indexée par nom seul ; deux entrées homonymes de coffres différents étaient
// sélectionnées ensemble, et Maj+clic (plage) repérait la première ligne portant le nom.
import { entryKey, entryKeyEngine, ENTRY_KEY_SEPARATOR, useSelection } from './useSelection';
import { renderHook } from './testUtils/fakeVault';
import { act } from 'react';

global.IS_REACT_ACT_ENVIRONMENT = true;

describe('entryKey', () => {
  test('entrée du coffre sélectionné (vue normale ou multi-coffres) : son nom', () => {
    expect(entryKey({ name: 'banque' }, 'Alpha')).toBe('banque');
    expect(entryKey({ name: 'banque', engineName: 'Alpha' }, 'Alpha')).toBe('banque');
  });

  test('résultat d\'un autre coffre : coffre + séparateur + nom ; homonymes distincts', () => {
    const beta = entryKey({ name: 'banque', engineName: 'Beta' }, 'Alpha');
    const gamma = entryKey({ name: 'banque', engineName: 'Gamma' }, 'Alpha');
    expect(beta).toBe(`Beta${ENTRY_KEY_SEPARATOR}banque`);
    expect(new Set([beta, gamma, 'banque']).size).toBe(3);
    expect(entryKeyEngine(beta)).toBe('Beta');
    expect(entryKeyEngine('banque')).toBeNull();
  });

  test('aucune collision avec un nom d\'entrée (séparateur interdit dans les noms)', () => {
    // « Beta/banque » (dossier) dans le coffre sélectionné ≠ « banque » du coffre Beta
    expect(entryKey({ name: 'Beta/banque' }, 'Alpha')).not.toBe(entryKey({ name: 'banque', engineName: 'Beta' }, 'Alpha'));
    expect(/[\x00-\x1F]/.test(ENTRY_KEY_SEPARATOR)).toBe(true); // eslint-disable-line no-control-regex
  });
});

describe('useSelection — Maj+clic par clé', () => {
  test('plage entre deux homonymes de coffres différents', () => {
    const engineRef = { current: 'Alpha' };
    const { result } = renderHook(() => useSelection({ selectedEngineNameRef: engineRef }));
    const rows = [
      { name: 'banque', engineName: 'Alpha' },
      { name: 'banque', engineName: 'Beta' },
      { name: 'courrier', engineName: 'Beta' },
      { name: 'banque', engineName: 'Gamma' },
    ];
    result.current.displayedSecretsRef.current = rows;
    const keys = rows.map(r => entryKey(r, 'Alpha'));

    act(() => { result.current.toggleSecretSelection(keys[1]); });
    expect(Array.from(result.current.selectedSecrets)).toEqual([keys[1]]);
    act(() => { result.current.toggleSecretSelection(keys[3], false, true); });
    // avant : findIndex par nom → première ligne « banque » (Alpha) comme borne de départ
    expect(Array.from(result.current.selectedSecrets).sort()).toEqual([keys[1], keys[2], keys[3]].sort());
    expect(result.current.isSecretSelected(keys[0])).toBe(false);
  });

  test('vue normale (sans engineName) : clés = noms, comportement inchangé', () => {
    const { result } = renderHook(() => useSelection({ selectedEngineNameRef: { current: 'kv' } }));
    result.current.displayedSecretsRef.current = [{ name: 'a' }, { name: 'b' }, { name: 'c', deleted: true }, { name: 'd' }];
    act(() => { result.current.toggleSecretSelection('a'); });
    act(() => { result.current.toggleSecretSelection('d', false, true); });
    expect(Array.from(result.current.selectedSecrets)).toEqual(['a', 'b', 'd']);
    act(() => { result.current.toggleSecretSelection('b', true); });
    expect(Array.from(result.current.selectedSecrets)).toEqual(['a', 'd']);
  });
});
