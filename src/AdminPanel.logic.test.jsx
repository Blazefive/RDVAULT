// ========================================
// TESTS : logique du panneau d'administration (rendu réel react-dom dans jsdom)
// ========================================
// - « Supprimer ce tag de toutes les entrées » : dossiers parcourus, appartenance exacte.
// - Onglet Coffres → « Policies liées » : règles par secret, listing et globs englobants.
// - Modérateur (non admin) : interface en consultation seule pour les objets système
//   (Vault refuse ces écritures avec la policy modérateur générée par le builder).
// - Policy au format JSON refusée par la validation modérateur (UX, Vault reste la barrière).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import AdminPanel from './AdminPanel';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

// axios 1.x est publié en ESM : simulé. AdminPanel l'appelle aussi comme une fonction (LIST).
jest.mock('axios', () => {
  const fn = jest.fn();
  fn.get = jest.fn();
  fn.post = jest.fn();
  fn.put = jest.fn();
  fn.delete = jest.fn();
  return { __esModule: true, default: fn };
});

global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const noop = () => {};
let root = null;
let host = null;

beforeEach(() => {
  axios.mockReset();
  axios.get.mockReset();
  axios.post.mockReset();
  axios.put.mockReset();
  axios.delete.mockReset();
});

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const flush = async () => {
  for (let i = 0; i < 6; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
  }
};

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

async function renderPanel(props) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    mountInRoot(root, (
      <I18nProvider defaultLang="en">
        <AdminPanel vaultUrl={VAULT} token="tok" baseHeaders={() => ({})} axiosConfig={(c) => c}
          username="u" onLogout={noop} onToggleAdminView={noop} onToggleDarkMode={noop} {...props} />
      </I18nProvider>
    ));
  });
  await flush();
}

const clickTab = async (label) => {
  const tab = Array.from(host.querySelectorAll('.admin-tab')).find(b => b.textContent.includes(label));
  await act(async () => { tab.click(); });
  await flush();
};
const buttons = () => Array.from(document.body.querySelectorAll('button'));
const buttonWith = (txt) => buttons().find(b => b.textContent.includes(txt));

test('suppression d\'un tag : dossiers parcourus (KV v1/v2), tags voisins non réécrits', async () => {
  // Coffre Eng (KV v2) et Ops (KV v1), avec des dossiers
  const ENG = { top: { Tags: 'obsolete web' }, 'folder/nested': { Tags: 'obsolete' }, prodlike: { Tags: 'obsolete-v2' } };
  const OPS = { a: { Tags: 'obsolete;x' }, 'd/b': { Tags: 'obsoletes' }, 'd/c': { Tags: 'y,obsolete' } };
  axios.get.mockImplementation(async (url) => {
    const u = url.replace(VAULT, '');
    if (u === '/v1/sys/mounts') {
      return { data: { data: { 'Eng/': { type: 'kv', options: { version: '2' } }, 'Ops/': { type: 'kv', options: { version: '1' } } } } };
    }
    if (u === '/v1/Eng/metadata/?list=true') return { data: { data: { keys: ['top', 'prodlike', 'folder/'] } } };
    if (u === '/v1/Eng/metadata/folder/?list=true') return { data: { data: { keys: ['nested'] } } };
    if (u === '/v1/Ops/?list=true') return { data: { data: { keys: ['a', 'd/'] } } };
    if (u === '/v1/Ops/d/?list=true') return { data: { data: { keys: ['b', 'c'] } } };
    let m = u.match(/^\/v1\/Eng\/data\/(.+)$/);
    if (m) return { data: { data: { data: { ...ENG[decodeURIComponent(m[1])] } } } };
    m = u.match(/^\/v1\/Ops\/(.+)$/);
    if (m) return { data: { data: { ...OPS[decodeURIComponent(m[1])] } } };
    if (u.includes('tags-shared')) { const e = new Error('404'); e.response = { status: 404 }; throw e; }
    throw new Error('GET inattendu ' + u);
  });
  axios.post.mockImplementation(async (url, body) => {
    const u = url.replace(VAULT, '');
    let m = u.match(/^\/v1\/Eng\/data\/(.+)$/);
    if (m) { ENG[decodeURIComponent(m[1])] = { ...body.data }; return { data: {} }; }
    m = u.match(/^\/v1\/Ops\/(.+)$/);
    if (m) { OPS[decodeURIComponent(m[1])] = { ...body }; return { data: {} }; }
    throw new Error('POST inattendu ' + u);
  });
  // vaultApi : listing récursif utilisé pour DÉCOUVRIR les tags
  const vaultApi = {
    listKeysV2: async () => Object.keys(ENG),
    listKeysV1: async () => Object.keys(OPS),
    readSecretV2: async (_e, k) => ({ name: k, tags: ENG[k].Tags }),
    readSecretV1: async (_e, k) => ({ name: k, tags: OPS[k].Tags }),
  };
  const showToast = jest.fn();
  await renderPanel({ vaultApi, showToast, isAdmin: true, isModerator: false });
  await clickTab(en.admin.tab.tags);
  const tagSpan = Array.from(host.querySelectorAll('span')).find(s => s.textContent.trim() === '🏷️ obsolete');
  expect(tagSpan).toBeTruthy();
  await act(async () => { Array.from(tagSpan.parentElement.querySelectorAll('button')).pop().click(); });
  await flush();
  const confirm = Array.from(document.querySelectorAll('.btn-danger')).pop();
  await act(async () => { confirm.click(); });
  await flush();

  const writes = axios.post.mock.calls.map(c => c[0].replace(VAULT, '')).sort();
  // Avant correctif : folder/nested et d/c ignorés, prodlike et d/b réécrits à tort
  expect(writes).toEqual(['/v1/Eng/data/folder/nested', '/v1/Eng/data/top', '/v1/Ops/a', '/v1/Ops/d/c']);
  expect(ENG.top.Tags).toBe('web');
  expect(ENG['folder/nested'].Tags).toBe('');
  expect(ENG.prodlike.Tags).toBe('obsolete-v2');
  expect(OPS.a.Tags).toBe('x');
  expect(OPS['d/b'].Tags).toBe('obsoletes');
  expect(OPS['d/c'].Tags).toBe('y');
  expect(showToast).toHaveBeenCalledWith(en.admin.toast.tagRemovedFromEntries.replace('{{tag}}', 'obsolete').replace('{{count}}', '4'), 'success');
  // Après rechargement, le tag n'est plus découvert
  expect(Array.from(host.querySelectorAll('span')).some(s => s.textContent.trim() === '🏷️ obsolete')).toBe(false);
});

test('policies liées à un coffre : règles par secret, listing et globs englobants détectés', async () => {
  const POLICIES = {
    // Sortie exacte du builder pour « Secret spécifique » Compta/paie en RW
    'compta-paie': '# Listing secrets du coffre Compta\npath "Compta/metadata" { capabilities = ["list"] }\n\n# Secret: Compta/paie (KV v2 RW)\npath "Compta/metadata/paie" { capabilities = ["read","delete"] }\npath "Compta/data/paie"     { capabilities = ["create","update","read","delete"] }\n',
    'compta-ro': 'path "Compta/data/*" { capabilities = ["read"] }',
    admin: 'path "*" { capabilities = ["create","read","update","delete","list","sudo"] }',
    'autre-coffre': 'path "Comptabilite/data/*" { capabilities = ["read"] }\npath "TOTP/code/COMPTA-*" { capabilities = ["read"] }',
    'refus-compta': 'path "Compta/data/*" { capabilities = ["deny"] }',
  };
  axios.mockImplementation(async (cfg) => {
    if (cfg.url.endsWith('/sys/policies/acl')) return { data: { data: { keys: Object.keys(POLICIES) } } };
    throw new Error('LIST ' + cfg.url);
  });
  axios.get.mockImplementation(async (url) => {
    if (url.endsWith('/sys/mounts')) {
      return { data: { data: { 'Compta/': { type: 'kv', options: { version: '2' } }, 'Comptabilite/': { type: 'kv', options: { version: '2' } } } } };
    }
    const p = url.match(/\/sys\/policies\/acl\/(.+)$/);
    if (p) return { data: { data: { policy: POLICIES[decodeURIComponent(p[1])] } } };
    throw new Error('GET ' + url);
  });
  await renderPanel({ vaultApi: null, showToast: noop, isAdmin: true, isModerator: false });
  const li = Array.from(host.querySelectorAll('.admin-items-list li')).find(l => l.textContent.trim().startsWith('📦 Compta/'));
  await act(async () => { li.click(); });
  await flush();
  const badges = Array.from(host.querySelectorAll('.policy-badge')).map(b => b.textContent.replace('✓', '').trim());
  // Avant correctif : seule « compta-ro » était listée
  expect(badges).toEqual(['compta-paie', 'compta-ro', 'admin']);
});

describe('modérateur (non admin) : consultation seule des objets système', () => {
  const POLICIES = {
    'moncoffre-rw': 'path "MonCoffre/data/*" { capabilities = ["create","read","update","delete","list"] }',
  };
  const mockModeratorVault = () => {
    axios.mockImplementation(async (cfg) => {
      if (cfg.url.endsWith('/sys/policies/acl')) return { data: { data: { keys: Object.keys(POLICIES) } } };
      if (cfg.url.endsWith('/auth/ldap/groups')) return { data: { data: { keys: ['moderateurs', 'equipe'] } } };
      throw new Error('LIST ' + cfg.url);
    });
    axios.get.mockImplementation(async (url) => {
      if (url.endsWith('/sys/mounts')) return { data: { data: { 'MonCoffre/': { type: 'kv', options: { version: '2' } } } } };
      const p = url.match(/\/sys\/policies\/acl\/(.+)$/);
      if (p) return { data: { data: { policy: POLICIES[decodeURIComponent(p[1])] } } };
      if (url.endsWith('/auth/ldap/groups/moderateurs')) return { data: { data: { policies: ['default', 'moderateur'] } } };
      if (url.endsWith('/auth/ldap/groups/equipe')) return { data: { data: { policies: ['moncoffre-rw'] } } };
      throw new Error('GET ' + url);
    });
  };

  test('aucune action d\'écriture système proposée ; bandeau explicatif', async () => {
    mockModeratorVault();
    await renderPanel({ vaultApi: null, showToast: noop, isAdmin: false, isModerator: true, moderatorEngines: ['MonCoffre'] });
    expect(host.textContent).toContain(en.admin.header.moderatorReadOnly);
    // Onglet Coffres : ni création ni suppression de coffre
    expect(buttonWith(en.admin.mount.new)).toBeUndefined();
    expect(host.querySelector('.admin-items-list .btn-danger')).toBeNull();
    // Onglet Policies : ni builder, ni création, ni sauvegarde, ni liaison de groupes
    await clickTab(en.admin.tab.policies);
    expect(buttonWith(en.admin.policy.builder)).toBeUndefined();
    expect(buttonWith(en.admin.policy.new)).toBeUndefined();
    const li = Array.from(host.querySelectorAll('.admin-items-list li')).find(l => l.textContent.includes('moncoffre-rw'));
    await act(async () => { li.click(); });
    await flush();
    expect(host.querySelector('textarea.admin-textarea').readOnly).toBe(true);
    expect(buttonWith(en.admin.common.save)).toBeUndefined();
    expect(buttonWith(en.admin.common.edit)).toBeUndefined();
    expect(buttons().some(b => /^\+ /.test(b.textContent.trim()))).toBe(false);
    expect(host.textContent).toContain('equipe');
    // Clic droit : pas de menu « Modifier / Supprimer »
    await act(async () => {
      li.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, clientX: 5, clientY: 5 }));
    });
    expect(buttonWith(en.common.delete)).toBeUndefined();
    expect(axios.put).not.toHaveBeenCalled();
    expect(axios.post).not.toHaveBeenCalled();
  });

  test('admin : actions d\'écriture toujours disponibles, pas de bandeau', async () => {
    mockModeratorVault();
    await renderPanel({ vaultApi: null, showToast: noop, isAdmin: true, isModerator: false });
    expect(host.textContent).not.toContain(en.admin.header.moderatorReadOnly);
    expect(buttonWith(en.admin.mount.new)).toBeTruthy();
    await clickTab(en.admin.tab.policies);
    expect(buttonWith(en.admin.policy.builder)).toBeTruthy();
    expect(buttonWith(en.admin.policy.new)).toBeTruthy();
  });

  test('validation modérateur : une policy au format JSON est refusée (aucune écriture)', async () => {
    mockModeratorVault();
    const showToast = jest.fn();
    // Admin ET modérateur : l'éditeur est disponible, la validation modérateur s'applique
    await renderPanel({ vaultApi: null, showToast, isAdmin: true, isModerator: true, moderatorEngines: ['MonCoffre'] });
    await clickTab(en.admin.tab.policies);
    const li = Array.from(host.querySelectorAll('.admin-items-list li')).find(l => l.textContent.includes('moncoffre-rw'));
    await act(async () => { li.click(); });
    await flush();
    const textarea = host.querySelector('textarea.admin-textarea');
    const setTA = (v) => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, v);
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    };
    await act(async () => { setTA('{"path":{"MonCoffre/data/*":{"capabilities":["read"]},"*":{"capabilities":["sudo"]}}}'); });
    await act(async () => { buttonWith(en.admin.common.save).click(); });
    await flush();
    // Avant correctif : la policy JSON (path "*" + sudo) était envoyée à Vault
    expect(axios.put).not.toHaveBeenCalled();
    expect(showToast).toHaveBeenCalledWith(en.admin.toast.policyForbiddenPaths, 'error');
  });
});
