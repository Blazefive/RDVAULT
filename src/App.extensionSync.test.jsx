// ========================================
// TESTS : useMigration / useSync — état servi à l'extension (APP-7, APP-9)
// ========================================
// - APP-7 : un glisser-déposer vers un autre coffre resynchronise l'extension comme « Migrer vers… »
//   (l'entrée déplacée n'en disparaît plus).
// - APP-9 : suppression du dernier coffre : l'extension ne sert plus ses mots de passe.
import fr from './locales/fr.json';
import {
  act, setupVault, flush, settle, installBridges, removeBridges, createHost, renderApp, login,
  engineCard, rowByName, rightClick, quiet, fakeDataTransfer, dispatchDrag, lastExtensionState,
} from './hooks/testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let host; let root;
beforeEach(() => {
  jest.useFakeTimers();
  quiet();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  installBridges();
  ({ host, root } = createHost());
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  removeBridges();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

const names = () => lastExtensionState().secrets.map(s => s.split(':')[0]);

describe('APP-7 : glisser-déposer et extension', () => {
  function seed() {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'github', { Username: 'dev', Password: 'GH-PASS', URL: 'https://github.com' });
    vault.writeRaw('Alpha', 'jira', { Username: 'dev', Password: 'JIRA-PASS', URL: 'https://jira.example' });
    vault.writeRaw('Beta', 'wiki', { Username: 'w', Password: 'W', URL: 'https://wiki.example' });
    return vault;
  }

  test('glisser « github » d\'Alpha vers Beta : l\'extension sert Beta/github', async () => {
    const vault = seed();
    await renderApp(root);
    await login(host);
    await settle();
    expect(names()).toEqual(['Alpha/github', 'Alpha/jira', 'Beta/wiki']);

    const dt = fakeDataTransfer();
    await dispatchDrag(rowByName(host, 'github'), 'dragstart', dt);
    await dispatchDrag(engineCard(host, 'Beta'), 'drop', dt);
    await flush(150);
    await settle();
    expect(vault.isLive('Beta', 'github')).toBe(true);
    expect(vault.isLive('Alpha', 'github')).toBe(false);
    expect(names()).toEqual(['Alpha/jira', 'Beta/github', 'Beta/wiki']);
    expect(lastExtensionState().secrets).toContain('Beta/github:GH-PASS');
  });

  test('copie à destination en création seule (check-and-set 0)', async () => {
    const vault = seed();
    await renderApp(root);
    await login(host);
    const dt = fakeDataTransfer();
    await dispatchDrag(rowByName(host, 'github'), 'dragstart', dt);
    await dispatchDrag(engineCard(host, 'Beta'), 'drop', dt);
    await flush(150);
    const write = vault.calls.find(c => c.method === 'post' && c.path === 'v1/Beta/data/github');
    expect(write.body).toEqual({ options: { cas: 0 }, data: { Username: 'dev', Password: 'GH-PASS', URL: 'https://github.com' } });
  });
});

describe('APP-9 : suppression du dernier coffre', () => {
  async function deleteEngineViaMenu(cardName) {
    await rightClick(engineCard(host, cardName));
    const item = Array.from(document.querySelectorAll('.context-menu .context-menu-item')).find(b => b.textContent.includes(fr.confirm.deleteEngine));
    await act(async () => { item.click(); });
    await flush(10);
    await act(async () => { document.querySelector('[role="dialog"] .btn-danger').click(); });
    await flush(120);
  }

  test('seul coffre supprimé : état « connecté » vide publié', async () => {
    const vault = setupVault();
    vault.addEngine('users/alice/perso');
    vault.writeRaw('users/alice/perso', 'banque', { Username: 'alice', Password: 'MDP-BANQUE', URL: 'https://banque.example' });
    await renderApp(root);
    await login(host);
    await settle();
    expect(lastExtensionState()).toEqual({ connected: true, secrets: ['users/alice/perso/banque:MDP-BANQUE'] });

    await deleteEngineViaMenu('perso');
    await settle();
    expect(vault.engines.size).toBe(0);
    expect(lastExtensionState()).toEqual({ connected: true, secrets: [] });
  });

  test('connexion d\'un compte sans coffre : aucun état publié avant la liste des coffres (inchangé)', async () => {
    setupVault();
    await renderApp(root);
    await login(host);
    await settle();
    expect(window.electronSync.writeState).not.toHaveBeenCalled();
  });
});
