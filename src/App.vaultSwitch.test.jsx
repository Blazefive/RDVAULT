// ========================================
// TESTS : App.jsx / useEngines — changement de coffre affiché (APP-4, APP-8)
// ========================================
// Sélection et mots de passe révélés sont indexés par NOM d'entrée : ils sont remis à zéro à chaque
// changement de coffre. Supprimer ou créer un AUTRE coffre garde le coffre affiché.
import fr from './locales/fr.json';
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login,
  activeEngine, engineCard, rowByName, rightClick, quiet, fakeDataTransfer, dispatchDrag, toastText,
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

const click = async (el, opts = {}) => {
  await act(async () => { el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ...opts })); });
  await flush(10);
};

async function deleteEngineViaMenu(cardName) {
  await rightClick(engineCard(host, cardName));
  const item = Array.from(document.querySelectorAll('.context-menu .context-menu-item')).find(b => b.textContent.includes(fr.confirm.deleteEngine));
  await act(async () => { item.click(); });
  await flush(10);
  await act(async () => { document.querySelector('[role="dialog"] .btn-danger').click(); });
  await flush(120);
}

describe('APP-4 : sélection remise à zéro au changement de coffre', () => {
  test('sélection faite dans Alpha : aucune ligne de Beta sélectionnée ; glisser « vpn » ne déplace que « vpn »', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.addEngine('Gamma');
    vault.writeRaw('Alpha', 'prod-db', { Username: 'alpha-db', Password: 'A-DB' });
    vault.writeRaw('Alpha', 'vpn', { Username: 'alpha-vpn', Password: 'A-VPN' });
    vault.writeRaw('Beta', 'prod-db', { Username: 'beta-db', Password: 'B-DB' });
    vault.writeRaw('Beta', 'vpn', { Username: 'beta-vpn', Password: 'B-VPN' });

    await renderApp(root);
    await login(host);
    await click(rowByName(host, 'prod-db'), { ctrlKey: true });
    await click(rowByName(host, 'vpn'), { ctrlKey: true });
    expect(rowByName(host, 'prod-db').className).toContain('row-selected');

    await act(async () => { engineCard(host, 'Beta').click(); });
    await flush(80);
    expect(activeEngine(host)).toBe('Beta');
    expect(['prod-db', 'vpn'].filter(n => rowByName(host, n).className.includes('row-selected'))).toEqual([]);

    const dt = fakeDataTransfer();
    await dispatchDrag(rowByName(host, 'vpn'), 'dragstart', dt);
    await dispatchDrag(engineCard(host, 'Gamma'), 'drop', dt);
    await flush(150);
    expect(JSON.parse(dt.store['application/json']).secrets).toEqual(['vpn']);
    expect(vault.isLive('Gamma', 'vpn')).toBe(true);
    expect(vault.isLive('Gamma', 'prod-db')).toBe(false);
    expect(vault.isLive('Beta', 'prod-db')).toBe(true);
    expect(toastText()).not.toMatch(/échec|partiel/i);
  });

  test('multi-sélection dans le même coffre conservée (témoin) : le glisser emporte les deux lignes', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Gamma');
    vault.writeRaw('Alpha', 'prod-db', { Username: 'a', Password: 'A-DB' });
    vault.writeRaw('Alpha', 'vpn', { Username: 'a', Password: 'A-VPN' });
    await renderApp(root);
    await login(host);
    await click(rowByName(host, 'prod-db'), { ctrlKey: true });
    await click(rowByName(host, 'vpn'), { ctrlKey: true });
    const dt = fakeDataTransfer();
    await dispatchDrag(rowByName(host, 'vpn'), 'dragstart', dt);
    expect(JSON.parse(dt.store['application/json']).secrets.sort()).toEqual(['prod-db', 'vpn']);
  });
});

describe('APP-8 : suppression d\'un autre coffre', () => {
  function seed() {
    const vault = setupVault();
    vault.addEngine('Banque');
    vault.addEngine('users/alice/old');
    vault.addEngine('users/alice/perso');
    vault.writeRaw('Banque', 'gmail', { Username: 'compta@corp', Password: 'MDP-PARTAGE-BANQUE' });
    vault.writeRaw('users/alice/perso', 'gmail', { Username: 'alice', Password: 'MDP-PERSO' });
    return vault;
  }

  test('supprimer « old » depuis « perso » (gmail révélé) : « perso » reste affiché, le gmail homonyme de « Banque » n\'est jamais révélé', async () => {
    const vault = seed();
    await renderApp(root);
    await login(host);
    await act(async () => { engineCard(host, 'perso').click(); });
    await flush(60);
    expect(activeEngine(host)).toBe('perso');
    await act(async () => { rowByName(host, 'gmail').querySelector('button.btn-action-view').click(); });
    await flush(5);
    expect(rowByName(host, 'gmail').textContent).toContain('MDP-PERSO');

    await deleteEngineViaMenu('old');
    expect(vault.engines.has('users/alice/old')).toBe(false);
    expect(activeEngine(host)).toBe('perso');
    expect(document.body.textContent).not.toContain('MDP-PARTAGE-BANQUE');
    // Le mot de passe révélé par l'utilisateur dans CE coffre le reste (aucun changement de coffre)
    expect(rowByName(host, 'gmail').textContent).toContain('MDP-PERSO');
  });

  test('supprimer le coffre affiché : plus aucun coffre affiché (inchangé), le coffre ouvert ensuite n\'hérite de rien', async () => {
    const vault = seed();
    await renderApp(root);
    await login(host);
    await act(async () => { engineCard(host, 'perso').click(); });
    await flush(60);
    await act(async () => { rowByName(host, 'gmail').querySelector('button.btn-action-view').click(); });
    await flush(5);
    await deleteEngineViaMenu('perso');
    expect(vault.engines.has('users/alice/perso')).toBe(false);
    expect(activeEngine(host)).toBeUndefined();
    await act(async () => { engineCard(host, 'Banque').click(); });
    await flush(60);
    expect(rowByName(host, 'gmail').textContent).not.toContain('MDP-PARTAGE-BANQUE');
  });
});
