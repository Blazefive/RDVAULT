// ========================================
// TESTS : App.jsx / useTags / PasswordHealthModal — recherche vidée et listes partielles
// ========================================
// - Champ de recherche vidé : filtre en attente annulé, recherche vidée aussitôt (suite F3 n°1).
// - Coffre listé partiellement (borne LIST_TOO_DEEP / LIST_TOO_LARGE) : message précis
//   (error.listTooDeepPartial / error.listTooLargePartial) au lieu de error.secretsUnreadable, qui
//   attribue l'incomplétude à une erreur réseau (suite F3 n°2) ; recherche multi-coffres, audit, tags.
import React from 'react';
import { createRoot } from 'react-dom/client';
import fr from './locales/fr.json';
import { I18nProvider } from './i18n.js';
import {
  act, setupVault, flush, settle, installBridges, removeBridges, createHost, renderApp, login,
  typeSearch, multiBox, engineCard, rowNames, toastText, setInput, quiet, mountInRoot,
} from './hooks/testUtils/appHarness.jsx';
import { incompleteReadMessage, partialListMessages, unreadableCount } from './hooks/useTags';
import PasswordHealthModal from './components/PasswordHealthModal';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const fill = (s, vars) => Object.entries(vars).reduce((acc, [k, v]) => acc.split(`{{${k}}}`).join(String(v)), s);

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

describe('recherche vidée', () => {
  test('champ vidé : liste complète aussitôt (sans attendre l\'anti-rebond), rien de réappliqué ensuite', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.writeRaw('Alpha', 'github', { Username: 'a', Password: 'p' });
    vault.writeRaw('Alpha', 'jira', { Username: 'a', Password: 'p' });
    await renderApp(root);
    await login(host);
    await typeSearch(host, 'git');
    expect(rowNames(host)).toEqual(['github']);

    await act(async () => { setInput(host.querySelector('.search-input'), 'ji'); });
    await act(async () => { setInput(host.querySelector('.search-input'), ''); });
    await flush(10);
    expect(rowNames(host).sort()).toEqual(['github', 'jira']);
    await act(async () => { jest.advanceTimersByTime(1000); });
    await flush(10);
    expect(rowNames(host).sort()).toEqual(['github', 'jira']);
  });

  test('frappe en attente puis changement de coffre : aucun filtre appliqué au nouveau coffre', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'github', { Password: 'p' });
    vault.writeRaw('Beta', 'wiki', { Password: 'p' });
    await renderApp(root);
    await login(host);
    await act(async () => { setInput(host.querySelector('.search-input'), 'zzz'); });
    await act(async () => { engineCard(host, 'Beta').click(); });
    await flush(60);
    await act(async () => { jest.advanceTimersByTime(1000); });
    await flush(20);
    expect(host.querySelector('.search-input').value).toBe('');
    expect(rowNames(host)).toEqual(['wiki']);
  });
});

describe('liste partielle : message précis', () => {
  const deepKey = Array.from({ length: 21 }, (_, i) => `d${i + 1}`).join('/') + '/x';

  test('recherche multi-coffres avec un coffre trop profond : error.listTooDeepPartial (et non « erreur réseau »)', async () => {
    const vault = setupVault();
    vault.addEngine('Alpha');
    vault.addEngine('Beta');
    vault.writeRaw('Alpha', 'alpha-a', { Password: 'p' });
    vault.writeRaw('Beta', 'aaa', { Password: 'p' });
    vault.writeRaw('Beta', deepKey, { Password: 'p' });
    await renderApp(root);
    await login(host);
    await settle();
    await typeSearch(host, 'a');
    await act(async () => { multiBox(host).click(); });
    await flush(150);
    const expected = fill(fr.error.listTooDeepPartial, { max: 20, count: 1 });
    expect(toastText()).toContain(expected);
    expect(toastText()).not.toContain(fill(fr.error.secretsUnreadable, { count: 1 }));
  });

  test('fonctions de message : borne, autres échecs ajoutés, rien si complet', () => {
    const t = (k, v) => `${k}${v ? JSON.stringify(v) : ''}`;
    const partial = {
      failed: 2,
      failedEngines: ['Beta', 'Gamma'],
      partialEngines: [{ engine: 'Beta', code: 'LIST_TOO_LARGE', i18nVars: { max: 20000 }, listed: 20000 }],
    };
    expect(partialListMessages(partial, t)).toEqual(['error.listTooLargePartial{"max":20000,"count":20000}']);
    expect(unreadableCount(partial)).toBe(3);
    expect(incompleteReadMessage(partial, t)).toBe('error.listTooLargePartial{"max":20000,"count":20000} error.secretsUnreadable{"count":3}');
    expect(incompleteReadMessage({ failed: 0, failedEngines: [], partialEngines: [] }, t)).toBeNull();
    expect(incompleteReadMessage({ failed: 1, failedEngines: [] }, t)).toBe('error.secretsUnreadable{"count":1}');
  });

  test('audit de santé : coffre listé partiellement signalé avec la borne', async () => {
    jest.useRealTimers();
    const limitErr = Object.assign(new Error('deep'), {
      code: 'LIST_TOO_DEEP', i18nKey: 'error.listTooDeep', i18nVars: { max: 20 }, partialKeys: ['a', 'b'],
    });
    const vaultApi = {
      listKeysV2: async (engine) => { if (engine.name === 'Beta') throw limitErr; return ['c']; },
      listKeysV1: async () => [],
      readSecretV2: async (engine, key) => ({ name: key, password: `pw-${key}-Tr0ub4dor&3`, username: 'u' }),
      readSecretV1: async () => null,
    };
    const el = document.createElement('div');
    document.body.appendChild(el);
    const r = createRoot(el);
    await act(async () => {
      mountInRoot(r, (
        <I18nProvider defaultLang="fr">
          <PasswordHealthModal onClose={() => {}} vaultApi={vaultApi} secretEngines={[{ name: 'Alpha', version: 2 }, { name: 'Beta', version: 2 }]} showToast={() => {}} />
        </I18nProvider>
      ));
    });
    for (let i = 0; i < 30; i++) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { await new Promise(res => setTimeout(res, 0)); });
    }
    const status = el.querySelector('.password-health-partial');
    expect(status).not.toBeNull();
    expect(status.textContent).toContain(fill(fr.error.listTooDeepPartial, { max: 20, count: 2 }));
    expect(status.textContent).not.toContain(fill(fr.passwordHealth.partial, { count: 1 }));
    act(() => r.unmount());
  });
});
