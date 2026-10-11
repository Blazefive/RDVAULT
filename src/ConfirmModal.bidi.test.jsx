// ========================================
// TESTS : ConfirmModal — valeurs techniques isolées (bidi, arabe)
// ========================================
// Une valeur insérée dans le message (chemin, nom de coffre, de policy, d'entrée) est isolée dans un
// <bdi> : en arabe, la barre oblique ou les guillemets ne changent plus de côté. Le texte rendu est
// identique à t(clé, valeurs) ; aucun caractère invisible n'est ajouté.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ConfirmModal from './ConfirmModal';
import { I18nProvider } from './i18n';
import ar from './locales/ar.json';
import fr from './locales/fr.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(lang, element) {
  localStorage.setItem('rdvault-lang', lang);
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
}

let consoleError;
beforeEach(() => { consoleError = jest.spyOn(console, 'error'); });
afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
  // Aucune alerte React (clé manquante…) pendant le rendu
  expect(consoleError).not.toHaveBeenCalled();
  consoleError.mockRestore();
});

const body = () => document.querySelector('[role="dialog"] .modal-body') || document.querySelector('[role="dialog"]');
const fill = (template, values) => template.replace(/\{\{(\w+)\}\}/g, (_, k) => values[k]);
const noop = () => {};

describe('messageKey / values / ltrValues', () => {
  test('arabe : chemin de coffre isolé de gauche à droite, texte identique à t(clé, valeurs)', () => {
    mount('ar', <ConfirmModal messageKey="admin.confirm.deleteMountMessage" values={{ path: 'users/alice/Compta/' }} ltrValues={['path']} onConfirm={noop} onCancel={noop} />);
    const bdi = body().querySelector('bdi[dir="ltr"]');
    expect(bdi).not.toBeNull();
    expect(bdi.textContent).toBe('users/alice/Compta/');
    expect(body().textContent).toContain(fill(ar.admin.confirm.deleteMountMessage, { path: 'users/alice/Compta/' }));
    expect(body().textContent).not.toMatch(new RegExp('[' + String.fromCharCode(0x2066) + '-' + String.fromCharCode(0x2069) + ']'));
  });

  test('valeur hors ltrValues (texte libre) : isolée dans son propre sens (<bdi> sans dir)', () => {
    mount('fr', <ConfirmModal messageKey="confirm.deleteSecretMsg" values={{ name: 'بنك 2' }} onConfirm={noop} onCancel={noop} />);
    const bdi = body().querySelector('bdi');
    expect(bdi.getAttribute('dir')).toBeNull();
    expect(bdi.textContent).toBe('بنك 2');
    expect(body().textContent).toContain(fill(fr.confirm.deleteSecretMsg, { name: 'بنك 2' }));
  });
});

describe('message texte existant : passages entre guillemets isolés automatiquement', () => {
  test('arabe, guillemets droits (nom de policy) : valeur dans un <bdi>, texte inchangé', () => {
    const message = fill(ar.admin.confirm.deletePolicyMessage, { name: 'admin-policy/' });
    mount('ar', <ConfirmModal message={message} onConfirm={noop} onCancel={noop} />);
    const bdi = body().querySelector('bdi');
    expect(bdi).not.toBeNull();
    expect(bdi.textContent).toBe('admin-policy/');
    expect(body().textContent).toContain(message);
  });

  test('français, guillemets « » : valeur isolée sans les espaces insécables', () => {
    const message = fill(fr.confirm.deleteTotpMsg, { name: 'banque' });
    mount('fr', <ConfirmModal message={message} onConfirm={noop} onCancel={noop} />);
    expect(body().querySelector('bdi').textContent).toBe('banque');
    expect(body().textContent).toContain(message);
  });

  test('fragment (comme ModalOrchestrator) : texte du fragment traité, autres nœuds conservés', () => {
    const text = fill(ar.confirm.deleteEngineMsg, { name: 'users/alice/perso' });
    mount('ar', (
      <ConfirmModal
        message={<>{text}<label className="extra">x</label>{false}</>}
        onConfirm={noop}
        onCancel={noop}
      />
    ));
    expect(body().querySelector('bdi').textContent).toBe('users/alice/perso');
    expect(body().querySelector('label.extra')).not.toBeNull();
    expect(body().textContent).toContain(text);
  });

  test('message sans guillemets : rendu tel quel, aucun <bdi>', () => {
    mount('fr', <ConfirmModal message="Sûr ?" onConfirm={noop} onCancel={noop} />);
    expect(body().querySelector('bdi')).toBeNull();
    expect(body().textContent).toContain('Sûr ?');
  });
});
