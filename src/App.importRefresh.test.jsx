// ========================================
// TESTS : ModalOrchestrator / App.jsx / useSync — relecture après un import des Paramètres (APP-6)
// ========================================
// SettingsModal écrit avec axios, sans rappel. Ses écritures (observées pendant que les Paramètres sont
// ouverts) déclenchent la relecture du coffre affiché (tableau + extension) et, pour un autre coffre, sa
// relecture complète par la synchro de l'extension (entrées écrasées comprises).
import React from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import fr from './locales/fr.json';
import {
  act, setupVault, flush, settle, installBridges, removeBridges, createHost, renderApp, login,
  engineCard, rowByName, rowNames, rightClick, menuItem, toastText, setInput, setSelect, quiet, lastExtensionState,
  mountInRoot,
} from './hooks/testUtils/appHarness.jsx';
import { useEngineWritesWhileOpen, engineOfRequestUrl, SETTINGS_WRITES_REFRESH_MS } from './components/ModalOrchestrator.jsx';

// axios simulé AVEC intercepteurs de requête (appelés par le harnais avant chaque requête). Fonctions
// simples et non jest.fn : resetMocks (configuration CRA) effacerait leur implémentation avant chaque test.
jest.mock('axios', () => {
  const handlers = [];
  return {
    __esModule: true,
    default: {
      get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(),
      interceptors: {
        request: { handlers, use: (fn) => handlers.push(fn) - 1, eject: (id) => { handlers[id] = null; } },
        response: { use: () => 0, eject: () => {} },
      },
    },
  };
});

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
  delete window.electronExport;
  jest.useRealTimers();
  jest.restoreAllMocks();
});

const btn = (scope, text) => Array.from(scope.querySelectorAll('button')).find(b => b.textContent.trim().includes(text)) || null;

async function openSettingsImport() {
  await act(async () => { host.querySelector('.user-menu-trigger').click(); });
  await flush(5);
  await act(async () => { btn(document, fr.toolbar.settings).click(); });
  await flush(10);
  const dialog = document.querySelector('[role="dialog"]');
  await act(async () => { btn(dialog, fr.export.title).click(); });
  await flush(5);
  return dialog;
}

async function importFile(engineName, content, { overwrite = false, close = true } = {}) {
  window.electronExport = { openFile: async () => ({ success: true, filePath: 'C:/x/import.csv', content }) };
  const dialog = await openSettingsImport();
  await act(async () => { setSelect(dialog.querySelectorAll('select')[1], engineName); });
  if (overwrite) await act(async () => { dialog.querySelectorAll('input[name="importDuplicate"]')[1].click(); });
  await act(async () => { btn(dialog, fr.export.importSelectFile).click(); });
  await flush(5);
  await act(async () => { btn(dialog, fr.export.importBtn).click(); });
  await flush(80);
  if (close) {
    await act(async () => { document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); });
    await flush(20);
  }
  return dialog;
}

describe('import dans le coffre affiché', () => {
  test('les entrées importées apparaissent dans le tableau et dans l\'extension', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'existante', { Username: 'u', Password: 'p' });
    await renderApp(root);
    await login(host);
    await settle();

    await importFile('Alpha', 'Name,Username,Password\n"github","dev","GH-1"\n"jira","dev","JI-1"\n');
    await settle();
    expect(vault.isLive('Alpha', 'github')).toBe(true);
    expect(rowNames(host).sort()).toEqual(['existante', 'github', 'jira']);
    expect(lastExtensionState().secrets).toEqual(['Alpha/existante:p', 'Alpha/github:GH-1', 'Alpha/jira:JI-1']);
  });

  test('import « écraser » puis « Modifier » + « Enregistrer » : la valeur importée est conservée', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'ANCIEN', Notes: '' });
    await renderApp(root);
    await login(host);

    await importFile('Alpha', 'Name,Username,Password\n"banque","alice","NOUVEAU-IMPORTE"\n', { overwrite: true });
    await settle();
    expect(vault.latest('Alpha', 'banque').data.Password).toBe('NOUVEAU-IMPORTE');

    await rightClick(rowByName(host, 'banque').querySelector('td.cell-name'));
    await act(async () => { menuItem(fr.contextMenu.edit).click(); });
    await flush(40);
    const modal = document.querySelector('[role="dialog"]');
    await act(async () => { setInput(modal.querySelector('textarea'), 'note ajoutée'); });
    const save = Array.from(modal.querySelectorAll('button')).find(b => b.textContent.trim() === fr.editSecret.save);
    await act(async () => { save.click(); });
    await flush(150);
    expect(toastText()).toBeTruthy();
    expect(vault.latest('Alpha', 'banque').data.Password).toBe('NOUVEAU-IMPORTE');
    expect(vault.latest('Alpha', 'banque').data.Notes).toBe('note ajoutée');
  });

  test('Paramètres restés ouverts : relecture SETTINGS_WRITES_REFRESH_MS après la dernière écriture', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    await renderApp(root);
    await login(host);
    await importFile('Alpha', 'Name,Username,Password\n"github","dev","GH-1"\n', { close: false });
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
    await act(async () => { jest.advanceTimersByTime(SETTINGS_WRITES_REFRESH_MS + 10); });
    await flush(80);
    expect(rowNames(host)).toEqual(['github']);
    expect(vault.isLive('Alpha', 'github')).toBe(true);
  });
});

describe('import dans un autre coffre', () => {
  test('entrée écrasée dans un coffre non affiché : l\'extension reçoit la nouvelle valeur', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'existante', { Username: 'u', Password: 'p' });
    vault.writeRaw('Beta', 'wiki', { Username: 'w', Password: 'W-ANCIEN', URL: 'https://wiki.example' });
    await renderApp(root);
    await login(host);
    await settle();
    expect(lastExtensionState().secrets).toContain('Beta/wiki:W-ANCIEN');

    await importFile('Beta', 'Name,Username,Password\n"wiki","w","W-NOUVEAU"\n', { overwrite: true });
    await settle();
    expect(vault.latest('Beta', 'wiki').data.Password).toBe('W-NOUVEAU');
    expect(lastExtensionState().secrets).toContain('Beta/wiki:W-NOUVEAU');
    expect(lastExtensionState().secrets).not.toContain('Beta/wiki:W-ANCIEN');
    // Coffre affiché inchangé
    expect(rowNames(host)).toEqual(['existante']);
    expect(engineCard(host, 'Alpha').className).toContain('active');
  });
});

// ── Observation des écritures (unitaire) ──
describe('engineOfRequestUrl', () => {
  const engines = [{ name: 'Alpha', version: 2 }, { name: 'users/bob/Coffre équipe', version: 2 }, { name: 'users/bob', version: 1 }];
  test('coffre visé par l\'URL (chemin encodé, plus long préfixe)', () => {
    expect(engineOfRequestUrl('http://v/v1/Alpha/data/github', 'http://v', engines)).toBe('Alpha');
    expect(engineOfRequestUrl(`http://v/v1/users/bob/${encodeURIComponent('Coffre équipe')}/data/a%2Fb`, 'http://v', engines)).toBe('users/bob/Coffre équipe');
    expect(engineOfRequestUrl('http://v/v1/users/bob/x', 'http://v', engines)).toBe('users/bob');
  });
  test('hors coffre : null', () => {
    expect(engineOfRequestUrl('http://v/v1/sys/mounts/Alpha', 'http://v', engines)).toBeNull();
    expect(engineOfRequestUrl('http://autre/v1/Alpha/data/x', 'http://v', engines)).toBeNull();
    expect(engineOfRequestUrl('http://v/v1/Alphabet/data/x', 'http://v', engines)).toBeNull();
    expect(engineOfRequestUrl(undefined, 'http://v', engines)).toBeNull();
  });
});

describe('useEngineWritesWhileOpen', () => {
  function Probe({ open, onWrites }) {
    useEngineWritesWhileOpen(open, { vaultUrl: 'http://v', secretEngines: [{ name: 'Alpha' }, { name: 'Beta' }], onWrites });
    return null;
  }
  const fire = (method, url) => {
    for (const h of axios.interceptors.request.handlers) if (typeof h === 'function') h({ method, url });
  };

  test('écritures regroupées, lectures ignorées, rien après la fermeture', async () => {
    const onWrites = jest.fn();
    const el = document.createElement('div');
    document.body.appendChild(el);
    const r = createRoot(el);
    await act(async () => { mountInRoot(r, <Probe open onWrites={onWrites} />); });
    fire('get', 'http://v/v1/Alpha/data/a');
    fire('post', 'http://v/v1/Alpha/data/a');
    fire('post', 'http://v/v1/Beta/data/b');
    expect(onWrites).not.toHaveBeenCalled();
    act(() => { jest.advanceTimersByTime(SETTINGS_WRITES_REFRESH_MS); });
    expect(onWrites).toHaveBeenCalledTimes(1);
    expect(onWrites.mock.calls[0][0].sort()).toEqual(['Alpha', 'Beta']);

    // Écriture en attente à la fermeture : transmise aussitôt ; plus aucune observation ensuite
    fire('post', 'http://v/v1/Alpha/data/c');
    await act(async () => { mountInRoot(r, <Probe open={false} onWrites={onWrites} />); });
    expect(onWrites).toHaveBeenCalledTimes(2);
    expect(onWrites.mock.calls[1][0]).toEqual(['Alpha']);
    fire('post', 'http://v/v1/Alpha/data/d');
    act(() => { jest.advanceTimersByTime(SETTINGS_WRITES_REFRESH_MS * 2); });
    expect(onWrites).toHaveBeenCalledTimes(2);
    act(() => r.unmount());
  });
});

test('déconnexion Paramètres ouverts avec écriture en attente : aucune relecture après la fin de session', async () => {
  const vault = setupVault();
  vault.addEngine('Alpha');
  await renderApp(root);
  await login(host);
  const dialog = await importFile('Alpha', 'Name,Username,Password\n"github","dev","GH-1"\n', { close: false });
  expect(dialog).not.toBeNull();
  const reads = () => axios.get.mock.calls.filter(c => String(c[0]).includes('/v1/Alpha/')).length;
  // Déconnexion (menu utilisateur) avant l'échéance du regroupement, Paramètres encore ouverts
  const before = reads();
  await act(async () => { host.querySelector('.user-menu-trigger').click(); });
  await flush(5);
  await act(async () => { Array.from(document.querySelectorAll('.user-menu-item')).pop().click(); });
  await flush(40);
  expect(host.querySelector('.login-form')).not.toBeNull();
  await act(async () => { jest.advanceTimersByTime(SETTINGS_WRITES_REFRESH_MS * 3); });
  await flush(40);
  expect(reads()).toBe(before);
});
