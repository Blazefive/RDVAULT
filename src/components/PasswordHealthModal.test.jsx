// ========================================
// TESTS : modale « Santé des mots de passe » — annulation HIBP et rapport partiel (PERF-5 / PERF-9)
// ========================================
// Avant : la vérification HIBP continuait après la fermeture de la modale (et après la
// déconnexion) en gardant les mots de passe en clair ; un coffre lu partiellement donnait un
// rapport faux sans aucun avertissement.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import nodeCrypto from 'crypto';
import { TextEncoder } from 'util';
import { I18nProvider } from '../i18n';
import en from '../locales/en.json';
import PasswordHealthModal from './PasswordHealthModal';

// Rapport produit par analyzeVault (préfixe « mock » : autorisé dans la fabrique jest.mock)
const mockState = { lastReport: null };
jest.mock('../utils/passwordHealth', () => {
  const actual = jest.requireActual('../utils/passwordHealth');
  return { ...actual, analyzeVault: (...args) => { mockState.lastReport = actual.analyzeVault(...args); return mockState.lastReport; } };
});

global.IS_REACT_ACT_ENVIRONMENT = true;
if (typeof global.TextEncoder === 'undefined') global.TextEncoder = TextEncoder;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const flush = async (n = 20) => { for (let i = 0; i < n; i++) await act(async () => { await Promise.resolve(); }); };

// SHA-1 du renderer (Web Crypto) simulé avec le module crypto de Node
const realCrypto = global.crypto;
beforeAll(() => {
  Object.defineProperty(global, 'crypto', {
    configurable: true,
    value: {
      subtle: {
        digest: async (_a, data) => {
          const h = nodeCrypto.createHash('sha1').update(Buffer.from(data)).digest();
          return h.buffer.slice(h.byteOffset, h.byteOffset + h.byteLength);
        },
      },
    },
  });
});
afterAll(() => { Object.defineProperty(global, 'crypto', { configurable: true, value: realCrypto }); });

// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let root; let host; let fetchCalls; let toasts;
beforeEach(() => {
  fetchCalls = 0;
  toasts = [];
  mockState.lastReport = null;
  global.fetch = jest.fn(async () => {
    fetchCalls++;
    await sleep(5);
    return { ok: true, text: async () => '' };
  });
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  try { act(() => root.unmount()); } catch { /* déjà démonté */ }
  document.body.innerHTML = '';
  delete global.fetch;
});

function fakeVaultApi(n, failing = []) {
  const list = async () => Array.from({ length: n }, (_, i) => `site-${i}`);
  const read = async (engine, key) => {
    if (failing.includes(key)) throw Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });
    return { name: key, username: 'u', password: `Mot-de-passe-${key}-x9!`, url: '', notes: '' };
  };
  return { listKeysV2: list, listKeysV1: list, readSecretV2: read, readSecretV1: read };
}

async function open(vaultApi) {
  const engines = [{ name: 'kv', version: 2 }];
  await act(async () => {
    mountInRoot(root,
      <I18nProvider defaultLang="en">
        <PasswordHealthModal onClose={() => {}} vaultApi={vaultApi} secretEngines={engines} showToast={(m, k) => toasts.push([k, m])} />
      </I18nProvider>
    );
  });
  await flush();
}

const button = (label) => Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === label);

test('fermeture pendant la vérification : plus aucune requête HIBP, mots de passe effacés', async () => {
  await open(fakeVaultApi(40));
  expect(mockState.lastReport.items).toHaveLength(40);
  await act(async () => { button(en.passwordHealth.checkBreaches).click(); });
  await act(async () => { await sleep(250); });
  expect(fetchCalls).toBeGreaterThan(0);
  expect(fetchCalls).toBeLessThan(40);

  act(() => root.unmount()); // fermeture de la modale (ou déconnexion : la modale est démontée)
  const atClose = fetchCalls;
  await act(async () => { await sleep(400); });
  expect(fetchCalls).toBe(atClose); // avant : la boucle continuait
  expect(mockState.lastReport.items.every(i => i.password === '')).toBe(true);
});

test('bouton « Annuler » : vérification interrompue, reprise possible', async () => {
  await open(fakeVaultApi(30));
  await act(async () => { button(en.passwordHealth.checkBreaches).click(); });
  await act(async () => { await sleep(150); });
  const cancel = button(en.passwordHealth.cancelCheck);
  expect(cancel).toBeTruthy();
  await act(async () => { cancel.click(); });
  await flush();
  await act(async () => { await sleep(150); });
  const afterCancel = fetchCalls;
  await act(async () => { await sleep(300); });
  expect(fetchCalls).toBe(afterCancel);
  expect(toasts.some(([kind, msg]) => kind === 'info' && msg.startsWith('Breach check cancelled'))).toBe(true);
  // Items non vérifiés : mot de passe conservé pour une reprise, aucun marqué en erreur
  expect(mockState.lastReport.items.some(i => i.breachCount === null && i.password)).toBe(true);
  expect(mockState.lastReport.items.some(i => i.breachCount === -1)).toBe(false);
  expect(button(en.passwordHealth.checkBreaches).disabled).toBe(false);
});

test('vérification terminée : mots de passe effacés de la mémoire du rapport', async () => {
  await open(fakeVaultApi(3));
  await act(async () => { button(en.passwordHealth.checkBreaches).click(); });
  await act(async () => { await sleep(1000); });
  await flush();
  expect(mockState.lastReport.items.every(i => i.breachCount === 0)).toBe(true);
  expect(mockState.lastReport.items.every(i => i.password === '')).toBe(true);
  expect(toasts[toasts.length - 1][0]).toBe('success');
  // Plus rien à vérifier : bouton désactivé (au lieu d'un clic sans effet)
  expect(button(en.passwordHealth.checkBreaches).disabled).toBe(true);
});

test('PERF-5 : coffre lu partiellement → « rapport partiel » affiché', async () => {
  await open(fakeVaultApi(10, ['site-3']));
  await act(async () => { await sleep(1500); }); // relances (200 ms puis 600 ms)
  await flush();
  const notice = document.querySelector('.password-health-partial');
  expect(notice).not.toBeNull(); // avant : rapport sur 9 entrées présenté comme complet
  expect(notice.textContent).toContain('1');
  expect(mockState.lastReport.items).toHaveLength(9);
});

// UI-38 : cartes statistiques (filtres) = boutons bascule ; avant, le filtre actif n'était signalé
// que par la bordure colorée (aucun aria-pressed).
test('UI-38 : cartes filtres avec aria-pressed, un seul enfoncé, qui suit le clic', async () => {
  await open(fakeVaultApi(3));
  const cards = () => Array.from(document.querySelectorAll('button[aria-pressed]'));
  expect(cards()).toHaveLength(4);
  const pressed = () => cards().filter(b => b.getAttribute('aria-pressed') === 'true').map(b => b.textContent);
  expect(pressed()).toEqual([expect.stringContaining(en.passwordHealth.filterAll)]);
  const weak = cards().find(b => b.textContent.includes(en.passwordHealth.weak));
  await act(async () => { weak.click(); });
  expect(pressed()).toEqual([expect.stringContaining(en.passwordHealth.weak)]);
});
