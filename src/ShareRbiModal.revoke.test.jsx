// ========================================
// TESTS : ShareRbiModal — vague F
// ========================================
// REMOTE-4 (seconde moitié) : /create-share reçoit le wrapping token, il ne peut donc être appelé
// qu'après le wrap. Si l'enregistrement sur le proxy échoue (injoignable, CSP, refus, réponse sans
// shareId), le wrapping token est aussitôt consommé (unwrap, usage unique) : avant, chaque essai
// laissait dans Vault, pendant le TTL, une copie emballée des identifiants avec un jeton que
// personne ne recevait.
// RBI-11 : le champ « website » de l'entrée voyage dans le partage et atteint la session RBI du
// destinataire.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import ShareRbiModal from './ShareRbiModal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const PROXY = 'https://proxy.test';
const USER_TOKEN = 'hvs.USER-TOKEN';
const WRAP = 'hvs.WRAPPING-TOKEN';

let roots = [];
// Rendu react-dom hors Testing Library (non installée)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function mount(element) {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  roots.push(root);
  return host;
}
const btn = (label) => Array.from(document.querySelectorAll('button')).find((b) => b.textContent.trim() === label);
const flush = () => act(async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); });
const alertText = () => document.querySelector('[role="alert"]')?.textContent || '';
const axiosConfig = (c) => ({ timeout: 30000, ...c });

afterEach(() => {
  act(() => { roots.forEach((r) => r.unmount()); });
  roots = [];
  document.body.innerHTML = '';
  localStorage.clear();
  axios.post.mockReset();
  axios.get.mockReset();
  delete window.electronRBI;
});

const SECRET = { name: 'gitlab', url: 'https://gitlab.example.com', username: 'alice', password: 'S3cret!' };
function mountSend(secret = SECRET) {
  return mount(
    <ShareRbiModal mode="send" secret={secret} totpKeyName="WEB-gitlab" vaultUrl={VAULT} token={USER_TOKEN}
      axiosConfig={axiosConfig} rbiProxyUrl={PROXY} onClose={() => {}} showToast={() => {}} />
  );
}
// Appels POST d'unwrap qui consomment le wrapping token créé par l'émetteur
const unwrapCallsWith = (token) => axios.post.mock.calls.filter(([url, , config]) => url === `${VAULT}/v1/sys/wrapping/unwrap` && config?.headers?.['X-Vault-Token'] === token);

describe('REMOTE-4 — wrapping token jamais laissé orphelin', () => {
  function backend(proxyBehaviour) {
    axios.post.mockImplementation((url) => {
      if (url === `${VAULT}/v1/sys/wrapping/wrap`) return Promise.resolve({ data: { wrap_info: { token: WRAP } } });
      if (url === `${PROXY}/create-share`) return proxyBehaviour();
      if (url === `${VAULT}/v1/sys/wrapping/unwrap`) return Promise.resolve({ data: { data: {} } });
      return Promise.reject(new Error(`appel inattendu ${url}`));
    });
  }

  test('proxy injoignable (ERR_NETWORK, ex. CSP) : wrapping token consommé, message « proxy injoignable »', async () => {
    backend(() => Promise.reject(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' })));
    mountSend();
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(unwrapCallsWith(WRAP)).toHaveLength(1); // avant : 0, jeton valable pendant tout le TTL
    expect(alertText()).toBe(en.share.errProxyUnreachable);
    // L'unwrap n'envoie rien d'autre que le jeton à consommer
    expect(unwrapCallsWith(WRAP)[0][1]).toBeNull();
  });

  test('proxy en erreur (500) : wrapping token consommé', async () => {
    backend(() => Promise.reject(Object.assign(new Error('500'), { response: { status: 500 } })));
    mountSend();
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(unwrapCallsWith(WRAP)).toHaveLength(1);
    expect(alertText()).toBe(en.share.errGenerate);
  });

  test('réponse du proxy sans shareId : wrapping token consommé', async () => {
    backend(() => Promise.resolve({ data: {} }));
    mountSend();
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(unwrapCallsWith(WRAP)).toHaveLength(1);
    expect(alertText()).toBe(en.share.errGenerate);
  });

  test('consommation impossible (Vault refuse) : erreur du partage affichée quand même', async () => {
    axios.post.mockImplementation((url) => {
      if (url === `${VAULT}/v1/sys/wrapping/wrap`) return Promise.resolve({ data: { wrap_info: { token: WRAP } } });
      if (url === `${PROXY}/create-share`) return Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' }));
      return Promise.reject(Object.assign(new Error('400'), { response: { status: 400 } }));
    });
    mountSend();
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(alertText()).toBe(en.share.errProxyUnreachable);
  });

  test('partage enregistré : le wrapping token n\'est PAS consommé (il appartient au proxy)', async () => {
    backend(() => Promise.resolve({ data: { shareId: 'share-ok' } }));
    mountSend();
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(unwrapCallsWith(WRAP)).toHaveLength(0);
    expect(document.body.textContent).toContain('share-ok');
  });

  test('wrap refusé : aucun appel au proxy ni unwrap', async () => {
    axios.post.mockImplementation((url) => (url === `${VAULT}/v1/sys/wrapping/wrap`
      ? Promise.reject(Object.assign(new Error('403'), { response: { status: 403 } }))
      : Promise.reject(new Error(`appel inattendu ${url}`))));
    mountSend();
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(alertText()).toBe(en.share.errGenerate);
  });
});

describe('RBI-11 — champ « website » partagé', () => {
  test('envoi : website de l\'entrée inclus dans les données emballées (jamais vers le proxy)', async () => {
    axios.post.mockImplementation((url) => Promise.resolve(url.endsWith('/v1/sys/wrapping/wrap')
      ? { data: { wrap_info: { token: WRAP } } } : { data: { shareId: 'share-1' } }));
    mountSend({ ...SECRET, website: 'https://sso.gitlab.example.com' });
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(axios.post.mock.calls[0][1]).toEqual({
      url: 'https://gitlab.example.com', website: 'https://sso.gitlab.example.com', username: 'alice', password: 'S3cret!', totpKeyName: 'WEB-gitlab',
    });
    expect(JSON.stringify(axios.post.mock.calls[1][1])).not.toContain('sso.gitlab');
  });

  test('réception : website déballé transmis à launchSession avec l\'url', async () => {
    axios.post.mockImplementation((url) => {
      if (url === `${PROXY}/unwrap-rbi`) return Promise.resolve({ data: { wrappingToken: WRAP } });
      if (url === `${VAULT}/v1/sys/wrapping/unwrap`) {
        return Promise.resolve({ data: { data: { url: 'https://app.example.com/login', website: 'https://sso.example.com', username: 'alice', password: 'S3cret!' } } });
      }
      return Promise.reject(new Error(`appel inattendu ${url}`));
    });
    const launchSession = jest.fn().mockResolvedValue({ success: true });
    window.electronRBI = { launchSession };
    mount(
      <ShareRbiModal mode="receive" vaultUrl={VAULT} token={USER_TOKEN} axiosConfig={axiosConfig}
        rbiProxyUrl={PROXY} onClose={() => {}} showToast={() => {}} />
    );
    const input = document.querySelector('input');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    act(() => { setter.call(input, 'share-123'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    act(() => { btn(en.share.open).click(); });
    await flush();
    act(() => { btn(en.confirm.open).click(); });
    await flush();
    expect(launchSession).toHaveBeenCalledTimes(1);
    expect(launchSession.mock.calls[0][0]).toEqual(expect.objectContaining({ url: 'https://app.example.com/login', website: 'https://sso.example.com' }));
  });

  test('réception : website invalide (caractère de contrôle) écarté', async () => {
    axios.post.mockImplementation((url) => {
      if (url === `${PROXY}/unwrap-rbi`) return Promise.resolve({ data: { wrappingToken: WRAP } });
      return Promise.resolve({ data: { data: { url: 'https://app.example.com', website: 'https://a.example\r\nX: y', username: 'u', password: 'p' } } });
    });
    const launchSession = jest.fn().mockResolvedValue({ success: true });
    window.electronRBI = { launchSession };
    mount(
      <ShareRbiModal mode="receive" vaultUrl={VAULT} token={USER_TOKEN} axiosConfig={axiosConfig}
        rbiProxyUrl={PROXY} onClose={() => {}} showToast={() => {}} />
    );
    const input = document.querySelector('input');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    act(() => { setter.call(input, 'share-123'); input.dispatchEvent(new Event('input', { bubbles: true })); });
    act(() => { btn(en.share.open).click(); });
    await flush();
    act(() => { btn(en.confirm.open).click(); });
    await flush();
    expect('website' in launchSession.mock.calls[0][0]).toBe(false);
  });
});
