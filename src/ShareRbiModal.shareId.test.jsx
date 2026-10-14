// ========================================
// TESTS : ShareRbiModal — format du shareId contrôlé dès l'émission (DOCS-17)
// ========================================
// Avant : tout shareId non vide renvoyé par /create-share était affiché tel quel ; seul le destinataire le
// refusait (« Format de l'ID de partage invalide ») : partage inutilisable découvert trop tard, wrapping
// token laissé dans Vault pendant tout le TTL. Attendu : même règle qu'à la réception (lettres, chiffres,
// « - », « _ », 128 caractères au plus, espaces de bord retirés comme à la réception) ; refus explicite et
// wrapping token consommé. Tout ID utilisable jusqu'ici (accepté par le destinataire) reste accepté.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import ShareRbiModal, { isValidShareId } from './ShareRbiModal';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const PROXY = 'https://proxy.test';
const USER_TOKEN = 'hvs.USER-TOKEN';
const WRAP = 'hvs.WRAPPING-TOKEN';
const SECRET = { name: 'gitlab', url: 'https://gitlab.example.com', username: 'alice', password: 'S3cret!' };

let roots = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function mountSend() {
  localStorage.setItem('rdvault-lang', 'en');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <ShareRbiModal mode="send" secret={SECRET} totpKeyName="WEB-gitlab" vaultUrl={VAULT} token={USER_TOKEN}
          axiosConfig={(c) => ({ timeout: 30000, ...c })} rbiProxyUrl={PROXY} onClose={() => {}} showToast={() => {}} />
      </I18nProvider>
    ));
  });
  roots.push(root);
  return host;
}
const btn = (label) => Array.from(document.querySelectorAll('button')).find((b) => b.textContent.trim() === label);
const flush = () => act(async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); });
const alertText = () => document.querySelector('[role="alert"]')?.textContent || '';
const unwrapCalls = () => axios.post.mock.calls.filter(([url, , config]) => url === `${VAULT}/v1/sys/wrapping/unwrap` && config?.headers?.['X-Vault-Token'] === WRAP);

function backend(shareId) {
  axios.post.mockImplementation((url) => {
    if (url === `${VAULT}/v1/sys/wrapping/wrap`) return Promise.resolve({ data: { wrap_info: { token: WRAP } } });
    if (url === `${PROXY}/create-share`) return Promise.resolve({ data: { shareId } });
    if (url === `${VAULT}/v1/sys/wrapping/unwrap`) return Promise.resolve({ data: { data: {} } });
    return Promise.reject(new Error(`appel inattendu ${url}`));
  });
}

async function generate(shareId) {
  backend(shareId);
  mountSend();
  act(() => { btn(en.share.generate).click(); });
  await flush();
}

afterEach(() => {
  act(() => { roots.forEach((r) => r.unmount()); });
  roots = [];
  document.body.innerHTML = '';
  localStorage.clear();
  axios.post.mockReset();
  axios.get.mockReset();
});

describe('DOCS-17 — shareId contrôlé à l\'émission', () => {
  test('règle commune : formats légitimes acceptés, le reste refusé', () => {
    // Identifiants produits par un proxy conforme (crypto.randomBytes(32) en hex ou base64url), UUID, court
    expect(isValidShareId('a'.repeat(64))).toBe(true);
    expect(isValidShareId('Qm9uam91ci1sZS1tb25kZV9wYXJ0YWdlLWlkLTAx-_')).toBe(true);
    expect(isValidShareId('3f2b6c1e-8d7a-4b2e-9c1d-0a1b2c3d4e5f')).toBe(true);
    expect(isValidShareId('share-123')).toBe(true);
    expect(isValidShareId('x'.repeat(128))).toBe(true);
    for (const bad of ['', 'x'.repeat(129), 'a b', 'a/b', '../etc', 'id\n', 'é', 'abc=', 42, null, undefined, {}]) {
      expect(isValidShareId(bad)).toBe(false);
    }
  });

  test('shareId hors format (« / », « = ») : refus explicite, aucun ID affiché, wrapping token consommé', async () => {
    await generate('abc/def==');
    expect(alertText()).toBe(en.share.errProxyInvalidShareId);
    expect(document.body.textContent).not.toContain('abc/def==');
    expect(unwrapCalls()).toHaveLength(1);
  });

  test('shareId trop long (129 caractères) ou non textuel : refusé', async () => {
    await generate('y'.repeat(129));
    expect(alertText()).toBe(en.share.errProxyInvalidShareId);
    expect(unwrapCalls()).toHaveLength(1);
    act(() => { roots.forEach((r) => r.unmount()); });
    roots = [];
    document.body.innerHTML = '';
    axios.post.mockReset();
    await generate({ id: 'objet' });
    expect(alertText()).toBe(en.share.errProxyInvalidShareId);
    expect(unwrapCalls()).toHaveLength(1);
  });

  test('shareId conforme (64 hex) : affiché, wrapping token NON consommé', async () => {
    const id = 'ab'.repeat(32);
    await generate(id);
    expect(alertText()).toBe('');
    expect(document.body.textContent).toContain(id);
    expect(unwrapCalls()).toHaveLength(0);
  });

  test('compatibilité : espaces de bord retirés (le destinataire les retirait déjà), ID affiché sans eux', async () => {
    await generate('  share-ok-42\n');
    expect(alertText()).toBe('');
    const code = Array.from(document.querySelectorAll('*')).find((el) => el.children.length === 0 && el.textContent === 'share-ok-42');
    expect(code).toBeTruthy();
    expect(unwrapCalls()).toHaveLength(0);
  });
});
