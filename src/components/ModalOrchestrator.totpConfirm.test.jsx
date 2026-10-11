// ========================================
// TESTS : ModalOrchestrator — confirmations liées aux clés TOTP (vague F, SECRETS-12 / SECRETS-33)
// ========================================
// - SECRETS-12 : « Supprimer le TOTP » passe par une vraie boîte de confirmation (danger) qui seule
//   appelle handleDeleteTotp(secret, { confirmed: true }). Annuler : rien. Coffre changé entre
//   l'ouverture et la validation : rien (la clé calculée ne serait plus celle de l'entrée).
// - SECRETS-33 : suppression d'une entrée avec TOTP. KV v2 : la clé est annoncée conservée et
//   restaurable. KV v1 (suppression définitive) : case « Supprimer aussi la clé TOTP », décochée par
//   défaut, qui pose deleteTotp sur secretToDelete (lu par deleteSecret).
import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import ModalOrchestrator from './ModalOrchestrator';
import { I18nProvider, useTranslation } from '../i18n';
import fr from '../locales/fr.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé, aucun appel réseau ici
jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const fill = (s, vars) => s.replace(/\{\{(\w+)\}\}/g, (_, k) => vars[k]);
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

let mounted = [];
afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

function render(element) {
  localStorage.setItem('rdvault-lang', 'fr');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
  return host;
}

const dialog = () => document.querySelector('[role="dialog"]');
const buttonIn = (el, text) => Array.from(el.querySelectorAll('button')).find(b => b.textContent.trim() === text);

// ModalOrchestrator avec un état réel pour secretToDelete / totpToDelete (comme App)
function Harness({ initialSecretToDelete = null, initialTotpToDelete = null, selectedEngine, spies }) {
  const { t } = useTranslation();
  const [secretToDelete, setSecretToDeleteState] = useState(initialSecretToDelete);
  const [totpToDelete, setTotpToDeleteState] = useState(initialTotpToDelete);
  spies.secretToDelete = secretToDelete;
  const setSecretToDelete = (v) => { spies.setSecretToDelete(v); setSecretToDeleteState(v); };
  const setTotpToDelete = (v) => { spies.setTotpToDelete(v); setTotpToDeleteState(v); };
  return (
    <ModalOrchestrator
      restoreFocus={() => {}}
      t={t}
      selectedEngine={selectedEngine}
      secretToDelete={secretToDelete}
      setSecretToDelete={setSecretToDelete}
      deletingSecret={false}
      deleteSecret={() => spies.deleteSecret(spies.secretToDelete)}
      totpToDelete={totpToDelete}
      setTotpToDelete={setTotpToDelete}
      handleDeleteTotp={spies.handleDeleteTotp}
      getTotpKeyName={(n) => n}
      showToast={jest.fn()}
    />
  );
}
const newSpies = () => ({
  setSecretToDelete: jest.fn(), setTotpToDelete: jest.fn(), deleteSecret: jest.fn(),
  handleDeleteTotp: jest.fn(async () => true),
});

describe('SECRETS-12 : boîte de confirmation « Supprimer la clé TOTP »', () => {
  const request = { secret: { name: 'banque', username: 'u' }, engineName: 'kv' };

  test('affichée en danger avec le nom de l\'entrée ; rien n\'est supprimé avant validation', () => {
    const spies = newSpies();
    render(<Harness initialTotpToDelete={request} selectedEngine={{ name: 'kv', version: 2 }} spies={spies} />);
    expect(dialog()).not.toBeNull();
    expect(dialog().textContent).toContain(fr.confirm.deleteTotp);
    expect(dialog().textContent).toContain(fill(fr.confirm.deleteTotpMsg, { name: 'banque' }));
    expect(dialog().querySelector('.btn-danger').textContent).toBe(fr.common.delete);
    expect(spies.handleDeleteTotp).not.toHaveBeenCalled();
  });

  test('« Supprimer » : handleDeleteTotp(secret, { confirmed: true }) puis fermeture', async () => {
    const spies = newSpies();
    render(<Harness initialTotpToDelete={request} selectedEngine={{ name: 'kv', version: 2 }} spies={spies} />);
    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    expect(spies.handleDeleteTotp).toHaveBeenCalledTimes(1);
    expect(spies.handleDeleteTotp).toHaveBeenCalledWith(request.secret, { confirmed: true });
    expect(spies.setTotpToDelete).toHaveBeenLastCalledWith(null);
    expect(dialog()).toBeNull();
  });

  test('double clic sur « Supprimer » : une seule suppression', async () => {
    const spies = newSpies();
    let release;
    spies.handleDeleteTotp = jest.fn(() => new Promise((r) => { release = r; }));
    render(<Harness initialTotpToDelete={request} selectedEngine={{ name: 'kv', version: 2 }} spies={spies} />);
    const danger = dialog().querySelector('.btn-danger');
    await act(async () => { danger.click(); });
    expect(dialog().querySelector('.btn-danger').textContent).toBe(fr.common.loading);
    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    await act(async () => { release(true); });
    expect(spies.handleDeleteTotp).toHaveBeenCalledTimes(1);
  });

  test('« Annuler » : rien n\'est supprimé', async () => {
    const spies = newSpies();
    render(<Harness initialTotpToDelete={request} selectedEngine={{ name: 'kv', version: 2 }} spies={spies} />);
    await act(async () => { buttonIn(dialog(), fr.common.cancel).click(); });
    expect(spies.handleDeleteTotp).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
  });

  test('coffre sélectionné changé depuis l\'ouverture : rien n\'est supprimé', async () => {
    const spies = newSpies();
    render(<Harness initialTotpToDelete={request} selectedEngine={{ name: 'autre', version: 2 }} spies={spies} />);
    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    expect(spies.handleDeleteTotp).not.toHaveBeenCalled();
    expect(dialog()).toBeNull();
  });
});

describe('SECRETS-33 : suppression d\'une entrée qui a un TOTP', () => {
  test('KV v2 : clé TOTP annoncée conservée et restaurable, aucune case à cocher', () => {
    const spies = newSpies();
    render(<Harness initialSecretToDelete={{ name: 'banque', totpExists: true }} selectedEngine={{ name: 'kv', version: 2 }} spies={spies} />);
    expect(dialog().textContent).toContain(fill(fr.confirm.deleteSecretMsg, { name: 'banque' }));
    expect(dialog().textContent).toContain(fill(fr.confirm.deleteSecretTotpKept, { action: fr.contextMenu.restore }));
    expect(dialog().querySelector('input[type="checkbox"]')).toBeNull();
  });

  test('KV v1 : case « Supprimer aussi la clé TOTP » décochée par défaut ; cochée → deleteTotp transmis à deleteSecret', async () => {
    const spies = newSpies();
    render(<Harness initialSecretToDelete={{ name: 'banque', totpExists: true }} selectedEngine={{ name: 'kv1', version: 1 }} spies={spies} />);
    const box = dialog().querySelector('input[type="checkbox"]');
    expect(box).not.toBeNull();
    expect(box.checked).toBe(false);
    expect(box.closest('label').textContent).toBe(fr.confirm.deleteTotpToo);
    // Décochée : la conservation (et le rattachement à une entrée recréée) est annoncée
    expect(dialog().textContent).toContain(fr.confirm.deleteSecretTotpOrphan);

    await act(async () => { box.click(); });
    expect(dialog().querySelector('input[type="checkbox"]').checked).toBe(true);
    expect(spies.secretToDelete).toEqual({ name: 'banque', totpExists: true, deleteTotp: true });
    expect(dialog().textContent).not.toContain(fr.confirm.deleteSecretTotpOrphan);
    // Mise à jour fonctionnelle (setSecretToDelete(p => ({ ...p, deleteTotp })))
    expect(typeof spies.setSecretToDelete.mock.calls[0][0]).toBe('function');

    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    expect(spies.deleteSecret).toHaveBeenCalledWith({ name: 'banque', totpExists: true, deleteTotp: true });
  });

  test('KV v1 : case laissée décochée → deleteSecret sans deleteTotp (graine conservée)', async () => {
    const spies = newSpies();
    render(<Harness initialSecretToDelete={{ name: 'banque', totpExists: true }} selectedEngine={{ name: 'kv1', version: 1 }} spies={spies} />);
    await act(async () => { dialog().querySelector('.btn-danger').click(); });
    expect(spies.deleteSecret).toHaveBeenCalledWith({ name: 'banque', totpExists: true });
  });

  test('entrée sans TOTP : ni mention ni case', () => {
    const spies = newSpies();
    render(<Harness initialSecretToDelete={{ name: 'simple', totpExists: false }} selectedEngine={{ name: 'kv1', version: 1 }} spies={spies} />);
    expect(dialog().querySelector('input[type="checkbox"]')).toBeNull();
    expect(dialog().textContent).not.toContain(fr.confirm.deleteSecretTotpOrphan);
    expect(dialog().textContent).not.toContain(fr.confirm.deleteSecretTotpKept.split(':')[0]);
  });
});
