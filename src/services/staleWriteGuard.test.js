// ========================================
// TESTS : staleWriteGuard — fusion d'une fiche ouverte sur une ligne périmée avec la version courante
// ========================================
import { sameStoredEntry, mergeOntoCurrent, isCasConflict, prepareEditWrite } from './staleWriteGuard';

const row = (extra = {}) => ({
  name: 'e', username: 'u', password: 'p1', url: '', website: '', notes: '', tags: 'a',
  Port: '', customFields: [], attachments: [], entryType: 'secret', ...extra,
});

test('propriétés d\'affichage ignorées, valeurs absentes ≡ valeurs par défaut', () => {
  expect(sameStoredEntry(row({ deleted: false, displayName: 'e', engineName: 'kv' }), row())).toBe(true);
  expect(sameStoredEntry({ name: 'e', username: 'u', password: 'p1', tags: 'a' }, row())).toBe(true);
  expect(sameStoredEntry(row({ customFields: [{ key: 'k', value: 'v' }] }), row())).toBe(false);
});

test('fusion : champs changés dans la fiche pris dans la fiche, les autres dans la version courante', () => {
  const base = row();
  const form = { ...base, notes: 'ma note' };
  const current = row({ password: 'p2-ailleurs', customFields: [{ key: 'Port', value: '2222' }], Port: '2222' });
  const merged = mergeOntoCurrent(form, base, current);
  expect(merged).toMatchObject({ name: 'e', notes: 'ma note', password: 'p2-ailleurs', Port: '2222' });
  expect(merged.customFields).toEqual([{ key: 'Port', value: '2222' }]);
});

test('même champ changé des deux côtés : la saisie de la fiche l\'emporte (choix explicite)', () => {
  const base = row();
  expect(mergeOntoCurrent({ ...base, password: 'mien' }, base, row({ password: 'autre' })).password).toBe('mien');
});

test('refus check-and-set reconnu (400 de Vault), autres erreurs non', () => {
  expect(isCasConflict({ response: { status: 400, data: { errors: ['check-and-set parameter did not match the current version'] } } })).toBe(true);
  expect(isCasConflict({ response: { status: 400, data: { errors: ['autre'] } } })).toBe(false);
  expect(isCasConflict({ response: { status: 500 } })).toBe(false);
});

describe('prepareEditWrite', () => {
  const engine = { name: 'kv', version: 2 };
  const api = (impl) => ({ readSecretV2Versioned: jest.fn(impl) });
  const httpErr = (status) => Object.assign(new Error(String(status)), { response: { status } });

  test('inchangée : fiche telle quelle, check-and-set sur la version relue', async () => {
    const base = row();
    const r = await prepareEditWrite(api(async () => ({ item: row(), version: 4 })), engine, 'e', base, { ...base, notes: 'n' });
    expect(r).toEqual({ ok: true, entry: { ...base, notes: 'n' }, cas: 4, merged: false });
  });

  test('changée ailleurs : fusion signalée', async () => {
    const base = row();
    const r = await prepareEditWrite(api(async () => ({ item: row({ password: 'p2' }), version: 5 })), engine, 'e', base, { ...base, notes: 'n' });
    expect(r).toMatchObject({ ok: true, cas: 5, merged: true, entry: { password: 'p2', notes: 'n' } });
  });

  test('supprimée ailleurs (404) : rien à écrire ; lecture refusée (403) : fiche telle quelle ; réseau : erreur', async () => {
    const base = row();
    expect(await prepareEditWrite(api(async () => { throw httpErr(404); }), engine, 'e', base, base)).toEqual({ ok: false, reason: 'gone' });
    expect(await prepareEditWrite(api(async () => { throw httpErr(403); }), engine, 'e', base, base)).toMatchObject({ ok: true, cas: undefined, merged: false });
    await expect(prepareEditWrite(api(async () => { throw new Error('réseau'); }), engine, 'e', base, base)).rejects.toThrow('réseau');
  });

  test('KV v1 : fusion sans check-and-set (pas de versions)', async () => {
    const base = row();
    const v1 = { readSecretV1: jest.fn(async () => row({ password: 'p2' })) };
    const r = await prepareEditWrite(v1, { name: 'old', version: 1 }, 'e', base, { ...base, notes: 'n' });
    expect(r).toMatchObject({ ok: true, cas: undefined, merged: true, entry: { password: 'p2', notes: 'n' } });
  });
});
