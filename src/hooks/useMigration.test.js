// ========================================
// TESTS : useMigration — déplacements, migrations, glisser-déposer
// ========================================
// Hook réel + createVaultApi réel contre un faux Vault en mémoire.
// - DATA-5 : aucune entrée homonyme n'est écrasée (renommage « _n », y compris dans un même lot) ;
//            le glisser-déposer supprime la source en douceur (historique conservé), comme la modale.
// - DATA-7 : une entrée avec TOTP n'est ni déplacée ni migrée (la graine TOTP n'est pas relisible
//            et le nom de la clé TOTP dépend du nom de l'entrée) ; la copie reste permise.
import { act } from 'react';
import { createFakeVault, renderHook, fakeT } from './testUtils/fakeVault';
import { createVaultApi } from '../services/vaultApi';
import { useMigration } from './useMigration';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

let vault;
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
  axios.post.mockImplementation(vault.axios.post);
  axios.put.mockImplementation(vault.axios.put);
  axios.delete.mockImplementation(vault.axios.delete);
});
afterEach(() => { document.body.innerHTML = ''; });

function mount(engine, engines, toasts) {
  const vaultApi = createVaultApi(vault.VAULT_URL, 'tok');
  return renderHook(() => useMigration({
    vaultApi, selectedEngine: engine, secretEngines: engines,
    fetchSecretsRef: { current: async () => {} }, showDeleted: false, clearSelection: () => {},
    syncExtensionRef: { current: null }, showToast: (m, k) => toasts.push([k, m]), t: fakeT
  }));
}
const run = (fn) => act(async () => { await fn(); });

describe('DATA-5 : pas d\'écrasement silencieux', () => {
  test('« Déplacer vers un dossier » vers la racine : l\'entrée homonyme est conservée, la déplacée est renommée', async () => {
    const E = vault.addEngine('kv');
    vault.writeRaw(E.name, 'github', { Username: 'perso', Password: 'MDP-RACINE' });
    vault.writeRaw(E.name, 'archive/github', { Username: 'pro', Password: 'MDP-ARCHIVE' });
    const toasts = [];
    const { result } = mount(E, [E], toasts);
    await run(() => result.current.handleMoveToFolder([{ name: 'archive/github' }], ''));

    expect(vault.latest(E.name, 'github')).toMatchObject({ version: 1, data: { Password: 'MDP-RACINE' } });
    expect(vault.latest(E.name, 'github_1')).toMatchObject({ data: { Password: 'MDP-ARCHIVE' } });
    expect(vault.isLive(E.name, 'archive/github')).toBe(false);
    expect(toasts[0][0]).toBe('success');
    expect(toasts[0][1]).toContain('migrate.renamedDuplicates');
  });

  test('deux entrées de même nom déplacées ensemble dans un dossier ne se réduisent pas à une seule', async () => {
    const E = vault.addEngine('kv');
    vault.writeRaw(E.name, 'a/x', { Password: 'A' });
    vault.writeRaw(E.name, 'b/x', { Password: 'B' });
    const toasts = [];
    const { result } = mount(E, [E], toasts);
    await run(() => result.current.handleMoveToFolder([{ name: 'a/x' }, { name: 'b/x' }], 'c'));
    expect(vault.latest(E.name, 'c/x').data.Password).toBe('A');
    expect(vault.latest(E.name, 'c/x_1').data.Password).toBe('B');
  });

  test('glisser-déposer vers un autre coffre : la cible homonyme est conservée, la source est supprimée en douceur', async () => {
    const A = vault.addEngine('A');
    const B = vault.addEngine('B');
    vault.writeRaw(A.name, 'github', { Username: 'a', Password: 'MDP-A' });
    vault.writeRaw(A.name, 'github', { Username: 'a', Password: 'MDP-A-v2' });
    vault.writeRaw(B.name, 'github', { Username: 'b', Password: 'MDP-B' });
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.migrateSecretsToEngine(['github'], A.name, 2, B));

    expect(vault.latest(B.name, 'github')).toMatchObject({ version: 1, data: { Password: 'MDP-B' } });
    expect(vault.latest(B.name, 'github_1').data.Password).toBe('MDP-A-v2');
    // Source : suppression douce (les 2 versions restent dans l'historique, restaurables)
    expect(vault.versionsOf(A.name, 'github')).toHaveLength(2);
    expect(vault.isLive(A.name, 'github')).toBe(false);
    expect(vault.calls.some(c => c.method === 'delete' && c.path === 'v1/A/metadata/github')).toBe(false);
    expect(toasts[0][0]).toBe('success');
  });

  test('glisser-déposer sur un dossier : pas d\'écrasement, source supprimée en douceur', async () => {
    const E = vault.addEngine('kv');
    vault.writeRaw(E.name, 'x', { Password: 'RACINE' });
    vault.writeRaw(E.name, 'c/x', { Password: 'DANS-C' });
    const toasts = [];
    const { result } = mount(E, [E], toasts);
    await run(() => result.current.moveSecretsToFolder(['x'], 'c'));
    expect(vault.latest(E.name, 'c/x')).toMatchObject({ version: 1, data: { Password: 'DANS-C' } });
    expect(vault.latest(E.name, 'c/x_1').data.Password).toBe('RACINE');
    expect(vault.versionsOf(E.name, 'x')).toHaveLength(1);
    expect(vault.isLive(E.name, 'x')).toBe(false);
  });

  test('migration (modale) : comportement de renommage inchangé, message traduit', async () => {
    const A = vault.addEngine('A');
    const B = vault.addEngine('B');
    vault.writeRaw(A.name, 'github', { Username: 'a', Password: 'MDP-A', EntryType: 'secret' });
    vault.writeRaw(B.name, 'github', { Username: 'b', Password: 'MDP-B', EntryType: 'secret' });
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'github' }], B, 'copy'));
    expect(vault.latest(B.name, 'github').data.Password).toBe('MDP-B');
    expect(vault.latest(B.name, 'github_1').data.Password).toBe('MDP-A');
    expect(toasts[0][1]).toContain('migrate.renamedDuplicates');
  });
});

describe('DATA-7 : entrée avec TOTP', () => {
  test('« Déplacer vers un dossier » refuse une entrée avec TOTP (ni orpheline, ni perdue)', async () => {
    const E = vault.addEngine('hunt-totp');
    vault.writeRaw(E.name, 'banque', { Username: 'u', Password: 'p' });
    vault.writeRaw(E.name, 'autre', { Username: 'u', Password: 'p' });
    vault.addTotp('HUNT-TOTP-banque');
    const toasts = [];
    const { result } = mount(E, [E], toasts);
    await run(() => result.current.handleMoveToFolder([{ name: 'banque' }, { name: 'autre' }], 'perso'));

    expect(vault.isLive(E.name, 'banque')).toBe(true);               // non déplacée
    expect(vault.latest(E.name, 'perso/banque')).toBeNull();
    expect(vault.isLive(E.name, 'perso/autre')).toBe(true);          // les autres le sont
    expect(vault.totp.has('HUNT-TOTP-banque')).toBe(true);
    expect(toasts[0][0]).toBe('warning');
    expect(toasts[0][1]).toContain('error.totpLocksMove');
  });

  test('glisser-déposer vers un autre coffre ou un dossier : refusé pour une entrée avec TOTP', async () => {
    const A = vault.addEngine('A');
    const B = vault.addEngine('B');
    vault.writeRaw(A.name, 'banque', { Password: 'p' });
    vault.addTotp('A-banque');
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.migrateSecretsToEngine(['banque'], A.name, 2, B));
    await run(() => result.current.moveSecretsToFolder(['banque'], 'dossier'));
    expect(vault.isLive(A.name, 'banque')).toBe(true);
    expect(vault.latest(B.name, 'banque')).toBeNull();
    expect(vault.latest(A.name, 'dossier/banque')).toBeNull();
    expect(toasts.every(([k, m]) => k === 'warning' && m.includes('error.totpLocksMove'))).toBe(true);
  });

  test('migration « move » refusée mais copie permise pour une entrée avec TOTP', async () => {
    const A = vault.addEngine('A');
    const B = vault.addEngine('B');
    vault.writeRaw(A.name, 'banque', { Password: 'p', EntryType: 'secret' });
    vault.addTotp('A-banque');
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'banque' }], B, 'move'));
    expect(vault.isLive(A.name, 'banque')).toBe(true);
    expect(vault.latest(B.name, 'banque')).toBeNull();
    expect(toasts[0][1]).toContain('error.totpLocksMove');

    await run(() => result.current.handleMigrateSecrets([{ name: 'banque' }], B, 'copy'));
    expect(vault.isLive(B.name, 'banque')).toBe(true);
    expect(vault.isLive(A.name, 'banque')).toBe(true);
    expect(toasts[1][0]).toBe('success');
  });

  test('migration vers un coffre de même préfixe TOTP sans renommage : la clé TOTP suit, déplacement permis', async () => {
    const A = vault.addEngine('Banque');
    const B = vault.addEngine('users/hunter/Banque');
    vault.writeRaw(A.name, 'github', { Password: 'p', EntryType: 'secret' });
    vault.addTotp('BANQUE-github');
    const toasts = [];
    const { result } = mount(A, [A, B], toasts);
    await run(() => result.current.handleMigrateSecrets([{ name: 'github' }], B, 'move'));
    expect(vault.isLive(B.name, 'github')).toBe(true);
    expect(vault.isLive(A.name, 'github')).toBe(false);
    expect(toasts[0][0]).toBe('success');
  });
});
