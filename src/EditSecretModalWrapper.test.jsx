// ========================================
// TESTS : EditSecretModalWrapper — fiche affichée sans attendre la vérification TOTP
// ========================================
// Avant : le wrapper ne rendait rien tant que la requête « clé TOTP existante ? » n'avait pas
// répondu (≈ 65 ms avec le coffre local, un aller-retour réseau de plus avec un Vault distant) :
// « Modifier » semblait ne pas réagir. Désormais la fiche s'affiche immédiatement ; le nom d'une
// entrée existante reste en lecture seule pendant la vérification, puis est désactivé si un TOTP
// le verrouille (le focus quitte alors le champ désactivé).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import EditSecretModalWrapper from './EditSecretModalWrapper';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let roots = [];
// Rendu d'un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
afterEach(() => {
  for (const r of roots) act(() => r.unmount());
  roots = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

// Requête TOTP pilotée par le test
function deferredCheck() {
  const calls = [];
  const check = jest.fn((key) => new Promise((resolve) => { calls.push({ key, resolve }); }));
  return { check, calls };
}

function mount(props) {
  localStorage.setItem('rdvault-lang', 'fr');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  roots.push(root);
  const paint = (p) => act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <EditSecretModalWrapper
          onClose={() => {}}
          onSave={() => {}}
          getTotpKeyName={(n) => 'KV-' + n}
          {...p}
        />
      </I18nProvider>
    ));
  });
  paint(props);
  return { host, paint };
}

const nameInput = (host) => host.querySelector('input.modal-input');

test('entrée existante : fiche rendue tout de suite, nom en lecture seule pendant la vérification', async () => {
  const { check, calls } = deferredCheck();
  const { host } = mount({ editSecret: { name: 'web/site', username: 'u', password: 'p' }, checkTotpExists: check });
  // Fiche déjà présente alors que la requête n'a pas répondu
  expect(host.querySelector('[role="dialog"]')).not.toBeNull();
  expect(calls.map(c => c.key)).toEqual(['KV-web/site']);
  const input = nameInput(host);
  expect(input.value).toBe('web/site');
  expect(input.readOnly).toBe(true);
  expect(input.disabled).toBe(false);
  expect(host.textContent).not.toContain(fr.error.totpLocksName);
  // Pas de TOTP : nom modifiable
  await act(async () => { calls[0].resolve(false); });
  expect(nameInput(host).readOnly).toBe(false);
  expect(nameInput(host).disabled).toBe(false);
});

test('TOTP détecté après l\'ouverture : nom désactivé, avertissement, focus déplacé hors du champ', async () => {
  const { check, calls } = deferredCheck();
  const { host } = mount({ editSecret: { name: 'web/site', username: 'u', password: 'p' }, checkTotpExists: check });
  expect(document.activeElement).toBe(nameInput(host));
  await act(async () => { calls[0].resolve(true); });
  const input = nameInput(host);
  expect(input.disabled).toBe(true);
  expect(input.readOnly).toBe(true);
  expect(host.textContent).toContain(fr.error.totpLocksName);
  // Focus toujours dans la fiche, sur un élément actif
  const dialog = host.querySelector('[role="dialog"]');
  expect(dialog.contains(document.activeElement)).toBe(true);
  expect(document.activeElement).not.toBe(input);
});

test('nouvelle entrée : aucune requête, nom modifiable immédiatement', () => {
  const { check } = deferredCheck();
  const { host } = mount({ editSecret: { name: '', username: '', password: '' }, checkTotpExists: check });
  expect(check).not.toHaveBeenCalled();
  expect(nameInput(host).readOnly).toBe(false);
  expect(nameInput(host).disabled).toBe(false);
});

test('nouveaux rendus du parent : pas de nouvelle vérification ; réponse tardive d\'une autre entrée ignorée', async () => {
  const { check, calls } = deferredCheck();
  const first = { name: 'a', username: '', password: '' };
  const { host, paint } = mount({ editSecret: first, checkTotpExists: check });
  // Rendu du parent avec une nouvelle fonction de vérification : aucune requête supplémentaire
  paint({ editSecret: first, checkTotpExists: jest.fn(check) });
  expect(calls.length).toBe(1);
  // Autre entrée : nouvelle vérification ; la réponse de la première (TOTP) n'est pas appliquée
  paint({ editSecret: { name: 'b', username: '', password: '' }, checkTotpExists: check });
  expect(calls.map(c => c.key)).toEqual(['KV-a', 'KV-b']);
  await act(async () => { calls[0].resolve(true); });
  expect(nameInput(host).disabled).toBe(false);
  expect(nameInput(host).readOnly).toBe(true);
  await act(async () => { calls[1].resolve(false); });
  expect(nameInput(host).readOnly).toBe(false);
});
