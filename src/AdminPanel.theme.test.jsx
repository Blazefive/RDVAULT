// ========================================
// TESTS : couleurs du panneau d'administration en thème sombre (rendu réel react-dom dans jsdom)
// ========================================
// Les fonds, bordures et textes du panneau (onglet Tags notamment : #fff, #e5e7eb, #f3f4f6,
// #dbeafe…) étaient codés en dur en style inline : ils restaient clairs en thème sombre, sous un
// texte clair illisible. Ils passent désormais par les variables du thème (var(--…)).
// Seule exception volontaire : la console des logs d'audit, sombre dans les deux thèmes.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import AdminPanel from './AdminPanel';
import { I18nProvider } from './i18n';
import en from './locales/en.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé (appelé aussi comme fonction)
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

const flush = async () => {
  for (let i = 0; i < 5; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
};

const setupVaultMocks = () => {
  axios.mockReset();
  axios.get.mockReset();
  axios.mockImplementation(async ({ url }) => {
    if (url.endsWith('/v1/sys/policies/acl')) return { data: { data: { keys: ['app-ro', 'default'] } } };
    if (url.endsWith('/groups')) return { data: { data: { keys: ['grp-admins', 'grp-users'] } } };
    return { data: { data: { keys: [] } } };
  });
  axios.get.mockImplementation(async (url) => {
    if (url === `${VAULT}/v1/sys/mounts`) return { data: { data: { 'kv/': { type: 'kv', description: '', options: { version: '2' } } } } };
    if (url === `${VAULT}/v1/sys/audit`) return { data: { data: { 'file/': { type: 'file', description: '', options: { file_path: '/var/log/vault/audit.log' } } } } };
    if (url === `${VAULT}/v1/auth/ldap/config`) return { data: { data: { url: 'ldap://dc.example', groupdn: 'OU=g,DC=example' } } };
    if (url.startsWith(`${VAULT}/v1/auth/ldap/groups/`)) return { data: { data: { policies: url.endsWith('grp-admins') ? ['app-ro'] : [] } } };
    if (url.startsWith(`${VAULT}/v1/sys/policies/acl/`)) return { data: { data: { policy: 'path "kv/data/*" { capabilities = ["read"] }' } } };
    if (url === `${VAULT}/v1/tags-shared/data/tags`) return { data: { data: { data: { tags: ['shared-tag'] } } } };
    return { data: { data: {} } };
  });
};

// vaultApi minimal : un secret portant un tag non encore partagé (tags « découverts »)
const vaultApi = {
  listKeysV2: async () => ['s1'],
  listKeysV1: async () => [],
  readSecretV2: async () => ({ tags: 'legacy-tag' }),
  readSecretV1: async () => ({}),
};

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mountPanel(props = {}) {
  localStorage.setItem('rdvault-lang', 'en');
  document.documentElement.setAttribute('data-theme', 'dark');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <I18nProvider>
        <AdminPanel
          vaultUrl={VAULT}
          token="t"
          baseHeaders={() => ({})}
          axiosConfig={(c) => c}
          vaultApi={vaultApi}
          showToast={jest.fn()}
          username="admin"
          darkMode
          onToggleDarkMode={() => {}}
          currentView="admin"
          onToggleAdminView={() => {}}
          onLogout={() => {}}
          isAdmin
          {...props}
        />
      </I18nProvider>
    ));
  });
  mounted.push(root);
  return host;
}

beforeEach(() => {
  setupVaultMocks();
});

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  document.documentElement.removeAttribute('data-theme');
  localStorage.clear();
  delete window.electronAudit;
});

const clickTab = async (host, label) => {
  const tab = Array.from(host.querySelectorAll('.admin-tab')).find(b => b.textContent.includes(label));
  expect(tab).toBeTruthy();
  await act(async () => { tab.click(); });
  await flush();
};

// Couleur littérale (#hex, rgb()) dans un style inline (jsdom convertit les #hex en rgb())
const LITERAL_COLOR = /#[0-9a-f]{3,8}\b|rgba?\(/i;
// Console des logs d'audit : volontairement sombre dans les deux thèmes (exception documentée)
const isAuditConsole = (el) => !!el.closest('[data-testid="audit-log-console"]');
function literalColorElements(root) {
  return [root, ...root.querySelectorAll('*')]
    .filter(el => LITERAL_COLOR.test(el.getAttribute('style') || ''))
    // Dégradé translucide décoratif de l'en-tête (sur fond accent, identique dans les deux thèmes)
    .filter(el => !/radial-gradient\(circle, rgba\(255, ?255, ?255, ?0\.2\)/.test(el.getAttribute('style')))
    .filter(el => !isAuditConsole(el))
    .map(el => `${el.tagName.toLowerCase()}[style="${el.getAttribute('style')}"]`);
}

test('le détecteur repère bien une couleur claire codée en dur (contrôle du test)', () => {
  const div = document.createElement('div');
  div.innerHTML = '<div style="background: #fff; border: 1px solid #e5e7eb"></div><div style="background: var(--bg-surface)"></div>';
  expect(literalColorElements(div)).toHaveLength(1);
});

describe('AdminPanel — aucune couleur codée en dur (thème sombre)', () => {
  test('onglet Tags : création, tags partagés, tags découverts, encadrés', async () => {
    const host = mountPanel();
    await flush();
    await clickTab(host, en.admin.tab.tags);
    expect(host.textContent).toContain('shared-tag');
    expect(host.textContent).toContain('legacy-tag');
    expect(host.textContent).toContain(en.admin.tags.migrateInfo);
    expect(literalColorElements(host)).toEqual([]);
    // Le champ de création a un nom accessible
    const input = host.querySelector('input[name="newTag"]');
    expect(input.getAttribute('aria-label')).toBe(en.admin.tags.newTagPlaceholder);
  });

  test('onglets coffres, policies (et menu contextuel), LDAP, export', async () => {
    const host = mountPanel();
    await flush();
    const mountItem = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('kv/'));
    await act(async () => { mountItem.click(); });
    await flush();
    expect(literalColorElements(host)).toEqual([]);

    await clickTab(host, en.admin.tab.policies);
    const policyItem = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('app-ro'));
    await act(async () => { policyItem.click(); });
    await flush();
    await act(async () => {
      policyItem.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, clientX: 10, clientY: 10 }));
    });
    expect(host.textContent).toContain(en.common.delete);
    expect(literalColorElements(host)).toEqual([]);

    await clickTab(host, en.admin.tab.auth);
    expect(host.textContent).toContain(en.admin.ldap.serverConfig);
    expect(literalColorElements(host)).toEqual([]);

    await clickTab(host, en.admin.tab.export);
    expect(literalColorElements(host)).toEqual([]);
  });

  test('LDAP indisponible : encadré d\'avertissement aux couleurs du thème', async () => {
    axios.get.mockImplementation(async (url) => {
      if (url === `${VAULT}/v1/auth/ldap/config`) { const e = new Error('403'); e.response = { status: 403 }; throw e; }
      if (url === `${VAULT}/v1/sys/mounts`) return { data: { data: {} } };
      return { data: { data: {} } };
    });
    const host = mountPanel();
    await flush();
    await clickTab(host, en.admin.tab.auth);
    expect(host.textContent).toContain(en.admin.ldap.unavailableTitle);
    expect(literalColorElements(host)).toEqual([]);
  });

  test('onglet audit : encadré du device aux couleurs du thème, console de logs sombre conservée', async () => {
    window.electronAudit = {
      tailLogFile: jest.fn().mockResolvedValue({
        success: true,
        totalLines: 1,
        loadedLines: 1,
        logs: [{ time: '2026-03-05T14:07:09Z', auth: { display_name: 'alice' }, request: { operation: 'read', path: 'kv/data/x' }, response: { status_code: 500 }, error: 'boom' }],
      }),
    };
    const host = mountPanel();
    await flush();
    await clickTab(host, en.admin.tab.audit);
    const device = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('file/'));
    await act(async () => { device.click(); });
    await flush();
    const consoleEl = host.querySelector('[data-testid="audit-log-console"]');
    expect(consoleEl).not.toBeNull();
    expect(consoleEl.textContent).toContain('ERROR');
    expect(literalColorElements(host)).toEqual([]);
  });
});
