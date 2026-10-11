// ========================================
// TESTS : ShareRbiModal — partage RBI conforme à DEPLOYMENT.md (étape 8)
// ========================================
// RBI-13 : chaque appel au proxy porte le jeton Vault du demandeur (X-Vault-Token) ; le proxy ne
// rend que le wrapping token, que le destinataire unwrappe lui-même ; confirmation (URL +
// identifiant) avant le lancement ; maxUses ≤ 5 sans « illimité », TTL ≤ 24 h ; code TOTP lu avec
// le jeton du destinataire, jamais fourni par le proxy.
// RBI-15 : URL d'entrée normalisée par buildSafeUrl (hôte « httpd.corp.local » → https://).

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
const buttons = () => Array.from(document.querySelectorAll('button'));
const btn = (label) => buttons().find((b) => b.textContent.trim() === label);
const flush = () => act(async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0)); });
const alertText = () => document.querySelector('[role="alert"]')?.textContent || '';

function typeShareId(value) {
  const input = document.querySelector('input');
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  act(() => { setter.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); });
}

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

function mountSend(secret, extra = {}) {
  return mount(
    <ShareRbiModal mode="send" secret={secret} totpKeyName="WEB-gitlab" vaultUrl={VAULT} token={USER_TOKEN}
      axiosConfig={axiosConfig} rbiProxyUrl={PROXY} onClose={() => {}} showToast={() => {}} {...extra} />
  );
}

function mountReceive(extra = {}) {
  return mount(
    <ShareRbiModal mode="receive" vaultUrl={VAULT} token={USER_TOKEN} axiosConfig={axiosConfig}
      rbiProxyUrl={PROXY} onClose={() => {}} showToast={() => {}} {...extra} />
  );
}

describe('RBI-13 — envoi', () => {
  test('options plafonnées : TTL ≤ 24 h, utilisations ≤ 5, jamais « illimité »', () => {
    mountSend({ name: 'gitlab', url: 'https://gitlab.example.com', username: 'u', password: 'p' });
    expect(btn(en.share.ttl48h)).toBeUndefined();
    expect(btn('10x')).toBeUndefined();
    expect(btn(en.share.unlimited)).toBeUndefined();
    for (const label of [en.share.ttl1h, en.share.ttl8h, en.share.ttl24h, '1x', '2x', '3x', '5x']) {
      expect(btn(label)).toBeTruthy();
    }
  });

  test('wrap Vault puis /create-share AUTHENTIFIÉ (X-Vault-Token), sans identifiants vers le proxy', async () => {
    axios.post.mockImplementation((url) => Promise.resolve(url.endsWith('/v1/sys/wrapping/wrap')
      ? { data: { wrap_info: { token: WRAP } } } : { data: { shareId: 'share-123' } }));
    mountSend({ name: 'gitlab', url: 'https://gitlab.example.com', username: 'alice', password: 'S3cret!' });
    act(() => { btn(en.share.ttl24h).click(); });
    act(() => { btn('5x').click(); });
    act(() => { btn(en.share.generate).click(); });
    await flush();

    const [wrapUrl, wrapData, wrapConfig] = axios.post.mock.calls[0];
    expect(wrapUrl).toBe(`${VAULT}/v1/sys/wrapping/wrap`);
    expect(wrapData).toEqual({ url: 'https://gitlab.example.com', username: 'alice', password: 'S3cret!', totpKeyName: 'WEB-gitlab' });
    expect(wrapConfig.headers['X-Vault-Token']).toBe(USER_TOKEN);
    expect(wrapConfig.headers['X-Vault-Wrap-TTL']).toBe('24h');

    const [proxyUrl, proxyData, proxyConfig] = axios.post.mock.calls[1];
    expect(proxyUrl).toBe(`${PROXY}/create-share`);
    expect(proxyData).toEqual({ wrappingToken: WRAP, maxUses: 5, ttl: '24h' });
    expect(proxyConfig.headers['X-Vault-Token']).toBe(USER_TOKEN);
    expect(JSON.stringify(proxyData)).not.toContain('S3cret!');
    expect(document.body.textContent).toContain('share-123');
  });

  test('RBI-15 : hôte « httpd.corp.local » enveloppé avec https:// (ouvrable chez le destinataire)', async () => {
    axios.post.mockImplementation((url) => Promise.resolve(url.endsWith('/v1/sys/wrapping/wrap')
      ? { data: { wrap_info: { token: WRAP } } } : { data: { shareId: 'share-1' } }));
    mountSend({ name: 'httpd', url: 'httpd.corp.local', username: 'u', password: 'p' });
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(axios.post.mock.calls[0][1].url).toBe('https://httpd.corp.local');
  });

  test('URL d\'entrée dangereuse : aucun wrap, erreur « URL invalide »', async () => {
    // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir refusée
    mountSend({ name: 'x', url: 'javascript:alert(1)', username: 'u', password: 'p' });
    act(() => { btn(en.share.generate).click(); });
    await flush();
    expect(axios.post).not.toHaveBeenCalled();
    expect(alertText()).toBe(en.error.invalidUrl);
  });
});

describe('RBI-13 — réception', () => {
  function conformantBackend({ unwrapData, totpCode = '123456', proxyError } = {}) {
    axios.post.mockImplementation((url) => {
      if (url === `${PROXY}/unwrap-rbi`) {
        return proxyError ? Promise.reject(proxyError) : Promise.resolve({ data: { wrappingToken: WRAP } });
      }
      if (url === `${VAULT}/v1/sys/wrapping/unwrap`) {
        return Promise.resolve({ data: { data: unwrapData || { url: 'https://app.example.com/login', username: 'alice', password: 'S3cret!', totpKeyName: 'WEB-app' } } });
      }
      return Promise.reject(new Error(`appel inattendu ${url}`));
    });
    axios.get.mockResolvedValue({ data: { data: { code: totpCode } } });
  }

  test('proxy authentifié → wrapping token unwrappé par le destinataire → confirmation → lancement', async () => {
    conformantBackend();
    const launchSession = jest.fn().mockResolvedValue({ success: true, sessionId: 's1' });
    window.electronRBI = { launchSession };
    const onClose = jest.fn();
    mountReceive({ onClose });
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();

    const [proxyUrl, proxyData, proxyConfig] = axios.post.mock.calls[0];
    expect(proxyUrl).toBe(`${PROXY}/unwrap-rbi`);
    expect(proxyData).toEqual({ shareId: 'share-123' });
    expect(proxyConfig.headers['X-Vault-Token']).toBe(USER_TOKEN);
    const [unwrapUrl, unwrapBody, unwrapConfig] = axios.post.mock.calls[1];
    expect(unwrapUrl).toBe(`${VAULT}/v1/sys/wrapping/unwrap`);
    expect(unwrapBody).toBeNull();
    expect(unwrapConfig.headers['X-Vault-Token']).toBe(WRAP);

    // Confirmation explicite avant toute session
    expect(launchSession).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain('https://app.example.com/login');
    expect(document.body.textContent).toContain('alice');
    expect(document.body.textContent).not.toContain('S3cret!');

    act(() => { btn(en.confirm.open).click(); });
    await flush();
    // TOTP lu avec le jeton du DESTINATAIRE (le proxy n'a aucun accès TOTP)
    const [totpUrl, totpConfig] = axios.get.mock.calls[0];
    expect(totpUrl).toBe(`${VAULT}/v1/TOTP/code/WEB-app`);
    expect(totpConfig.headers['X-Vault-Token']).toBe(USER_TOKEN);
    expect(launchSession).toHaveBeenCalledTimes(1);
    expect(launchSession.mock.calls[0][0]).toMatchObject({
      url: 'https://app.example.com/login', username: 'alice', password: 'S3cret!', totp: '123456',
    });
    expect(onClose).toHaveBeenCalled();
  });

  test('sans droit TOTP : session lancée sans code', async () => {
    conformantBackend();
    axios.get.mockRejectedValue({ response: { status: 403 } });
    const launchSession = jest.fn().mockResolvedValue({ success: true });
    window.electronRBI = { launchSession };
    mountReceive();
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();
    act(() => { btn(en.confirm.open).click(); });
    await flush();
    expect(launchSession.mock.calls[0][0].totp).toBeNull();
  });

  test('proxy non conforme qui renvoie des identifiants EN CLAIR : refusé, aucune session', async () => {
    axios.post.mockResolvedValue({ data: { url: 'https://app.example.com', username: 'alice', password: 'S3cret!', totpCode: '123456' } });
    const launchSession = jest.fn();
    window.electronRBI = { launchSession };
    mountReceive();
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(alertText()).toBe(en.share.errDataMissing);
    expect(launchSession).not.toHaveBeenCalled();
  });

  test('URL déballée non http(s) : refusée', async () => {
    // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir refusée
    conformantBackend({ unwrapData: { url: 'javascript:alert(1)', username: 'a', password: 'b' } });
    const launchSession = jest.fn();
    window.electronRBI = { launchSession };
    mountReceive();
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();
    expect(alertText()).toBe(en.error.shareUrlInvalid);
    expect(btn(en.confirm.open)).toBeUndefined();
    expect(launchSession).not.toHaveBeenCalled();
  });

  test('proxy 401 (jeton refusé) → message dédié', async () => {
    conformantBackend({ proxyError: { response: { status: 401 } } });
    window.electronRBI = { launchSession: jest.fn() };
    mountReceive();
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();
    expect(alertText()).toBe(en.share.errUnauthorized);
  });

  test('annulation à la confirmation : aucune session', async () => {
    conformantBackend();
    const launchSession = jest.fn();
    window.electronRBI = { launchSession };
    mountReceive();
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();
    act(() => { btn(en.common.cancel).click(); });
    await flush();
    expect(launchSession).not.toHaveBeenCalled();
    expect(btn(en.share.open)).toBeTruthy();
  });

  test('session refusée (page de connexion hors domaine) → motif traduit', async () => {
    conformantBackend();
    window.electronRBI = { launchSession: jest.fn().mockResolvedValue({ success: false, error: 'Page de connexion hors du domaine de l\'entrée', code: 'RBI_FOREIGN_ORIGIN' }) };
    mountReceive();
    typeShareId('share-123');
    act(() => { btn(en.share.open).click(); });
    await flush();
    act(() => { btn(en.confirm.open).click(); });
    await flush();
    expect(alertText()).toBe(en.error.rbiForeignOrigin);
  });
});
