// ========================================
// TESTS : internationalisation du panneau d'administration (rendu réel react-dom dans jsdom)
// ========================================
// - Panneau rendu en anglais : aucun texte français codé en dur (onglets, toasts,
//   confirmations, aides, attributs title/placeholder), aucune clé non résolue.
// - Les dates des logs d'audit suivent la langue de l'application (plus de 'fr-FR' en dur).
// - Le rendu français reste en français.
// - Les modales admin (activation d'audit, création de policy, builder, mot de passe SSH).
// - Les 12 locales traduisent réellement les nouvelles clés admin.* (pas de copie anglaise).

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import AdminPanel from './AdminPanel';
import EnableAuditModal from './components/admin/EnableAuditModal';
import CreatePolicyModal from './components/admin/CreatePolicyModal';
import PolicyBuilderModal from './components/admin/PolicyBuilderModal';
import SshPasswordModal from './components/admin/SshPasswordModal';
import { I18nProvider } from './i18n';
import ar from './locales/ar.json';
import de from './locales/de.json';
import en from './locales/en.json';
import es from './locales/es.json';
import fr from './locales/fr.json';
import it from './locales/it.json';
import ja from './locales/ja.json';
import ko from './locales/ko.json';
import pt from './locales/pt.json';
import ru from './locales/ru.json';
import tr from './locales/tr.json';
import zh from './locales/zh.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé. AdminPanel l'appelle
// aussi comme une fonction (requêtes LIST), d'où un jest.fn() muni de get/post/put/delete.
jest.mock('axios', () => {
  const fn = jest.fn();
  fn.get = jest.fn();
  fn.post = jest.fn();
  fn.put = jest.fn();
  fn.delete = jest.fn();
  return { __esModule: true, default: fn };
});

// Indique à React qu'on est dans un environnement de test avec act()
global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const LOG_TIME = '2026-03-05T14:07:09Z';
// Sous-sections ajoutées à admin.* pour le panneau (les clés historiques ne sont pas concernées)
const NEW_SECTIONS = ['header', 'tab', 'common', 'mount', 'policy', 'ldap', 'audit', 'tags', 'export', 'confirm', 'toast', 'enableAudit', 'sshPrompt', 'builder'];

const flatten = (obj, prefix = '') => Object.entries(obj).flatMap(([k, v]) =>
  (v && typeof v === 'object') ? flatten(v, `${prefix}${k}.`) : [[`${prefix}${k}`, v]]);
const adminEntries = (locale) => flatten(locale.admin).filter(([k]) => NEW_SECTIONS.includes(k.split('.')[0]));

// Fragments français qui ne doivent jamais apparaître dans l'interface anglaise :
// toutes les nouvelles chaînes admin françaises (hors parties communes avec l'anglais)…
const enValues = flatten(en).map(([, v]) => v);
const FRENCH_FROM_LOCALE = adminEntries(fr)
  .flatMap(([, v]) => v.split(/\{\{\w+\}\}/))
  .map(s => s.trim())
  .filter(s => s.length >= 10 && !enValues.some(e => e.includes(s)));
// … plus quelques chaînes clés de l'ancien code en dur
const FRENCH_KEY_STRINGS = [
  'Panel Administration', 'Gestion complète', 'Coffres disponibles', 'Policies disponibles',
  'Chargement', 'Sélectionnez', 'Actualiser', 'Supprimer', 'Aucun', 'Groupes AD',
  'Activer', 'Exporter CSV', 'Gestion des Tags', 'Annuler', 'Mot de passe',
];

const expectNoFrench = (text) => {
  for (const fragment of [...FRENCH_KEY_STRINGS, ...FRENCH_FROM_LOCALE]) {
    expect([fragment, text.includes(fragment)]).toEqual([fragment, false]);
  }
  // Aucune clé non résolue ni marqueur {{…}} oublié
  expect(text).not.toMatch(/\badmin\.[A-Za-z]+\.[A-Za-z]+/);
  expect(text).not.toMatch(/\{\{\w+\}\}/);
};

// Texte visible + attributs title/placeholder ; les <pre> (contenu HCL de policy, donnée
// et non interface) sont exclus
const visibleText = () => {
  const clone = document.body.cloneNode(true);
  clone.querySelectorAll('pre').forEach(p => p.remove());
  const attrs = Array.from(clone.querySelectorAll('[title],[placeholder]'))
    .map(el => `${el.getAttribute('title') || ''} ${el.getAttribute('placeholder') || ''}`);
  return `${clone.textContent} ${attrs.join(' ')}`;
};

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

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

function mount(lang, element) {
  localStorage.setItem('rdvault-lang', lang);
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
  return host;
}

const mountPanel = (lang, showToast = jest.fn()) => mount(lang, (
  <AdminPanel
    vaultUrl={VAULT}
    token="t"
    baseHeaders={() => ({})}
    axiosConfig={(c) => c}
    vaultApi={vaultApi}
    showToast={showToast}
    username="admin"
    darkMode={false}
    onToggleDarkMode={() => {}}
    currentView="admin"
    onToggleAdminView={() => {}}
    onLogout={() => {}}
    isAdmin
  />
));

const clickTab = async (host, label) => {
  const tab = Array.from(host.querySelectorAll('.admin-tab')).find(b => b.textContent.includes(label));
  expect(tab).toBeTruthy();
  await act(async () => { tab.click(); });
  await flush();
};

const buttonContaining = (txt) => Array.from(document.body.querySelectorAll('button')).find(b => b.textContent.includes(txt));

beforeEach(() => {
  setupVaultMocks();
});

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
  delete window.electronAudit;
});

describe('AdminPanel rendu en anglais', () => {
  test('aucun texte français dans les onglets, confirmations, toasts et attributs', async () => {
    const showToast = jest.fn();
    window.electronAudit = {
      tailLogFile: jest.fn().mockResolvedValue({
        success: true,
        totalLines: 1,
        loadedLines: 1,
        logs: [{ time: LOG_TIME, auth: { display_name: 'alice' }, request: { operation: 'read', path: 'kv/data/x' }, response: { status_code: 200 } }],
      }),
    };
    const host = mountPanel('en', showToast);
    await flush();

    // Onglet « coffres » (par défaut)
    expect(visibleText()).toContain(en.admin.header.title);
    expect(visibleText()).toContain(en.admin.mount.available);
    expectNoFrench(visibleText());

    // Sélection d'un coffre puis confirmation de suppression
    const mountItem = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('kv/'));
    await act(async () => { mountItem.click(); });
    await flush();
    expect(visibleText()).toContain(en.admin.mount.linkedPolicies);
    await act(async () => { mountItem.querySelector('.btn-danger').click(); });
    expect(visibleText()).toContain(en.admin.confirm.deleteMountTitle);
    expectNoFrench(visibleText());
    await act(async () => { buttonContaining(en.common.cancel).click(); });

    // Onglet « policies » : liste, éditeur, groupes AD, menu contextuel
    await clickTab(host, en.admin.tab.policies);
    expect(visibleText()).toContain(en.admin.policy.available);
    const policyItem = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('app-ro'));
    await act(async () => { policyItem.click(); });
    await flush();
    expect(visibleText()).toContain(en.admin.policy.linkedGroups);
    expect(visibleText()).toContain(en.admin.policy.addGroup);
    await act(async () => {
      policyItem.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, clientX: 10, clientY: 10 }));
    });
    expect(visibleText()).toContain(en.common.delete);
    expectNoFrench(visibleText());

    // Onglet « auth » : aide LDAP avec éléments <code> insérés dans la traduction
    await clickTab(host, en.admin.tab.auth);
    expect(visibleText()).toContain(en.admin.ldap.serverConfig);
    const codes = Array.from(host.querySelectorAll('.admin-help code')).map(c => c.textContent);
    expect(codes).toEqual(expect.arrayContaining(['OU=VAULT,OU=Groupes,DC=lab,DC=proxmox', 'policy=default', '/var/log/vault_sync_ad_groups.log']));
    expectNoFrench(visibleText());

    // Onglet « audit » : lecture des logs, date au format de la langue de l'application
    await clickTab(host, en.admin.tab.audit);
    const device = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('file/'));
    await act(async () => { device.click(); });
    await flush();
    expect(window.electronAudit.tailLogFile).toHaveBeenCalledTimes(1);
    expect(visibleText()).toContain(new Date(LOG_TIME).toLocaleString('en'));
    expect(visibleText()).not.toContain(new Date(LOG_TIME).toLocaleString('fr-FR'));
    expectNoFrench(visibleText());

    // Onglet « tags » : tags partagés et tags découverts (migration)
    await clickTab(host, en.admin.tab.tags);
    expect(visibleText()).toContain('shared-tag');
    expect(visibleText()).toContain('legacy-tag');
    expect(visibleText()).toContain(en.admin.tags.migrateAll);
    expectNoFrench(visibleText());

    // Onglet « export »
    await clickTab(host, en.admin.tab.export);
    expect(visibleText()).toContain(en.admin.export.exportCsv);
    expectNoFrench(visibleText());

    // Toasts émis pendant le parcours : en anglais
    expect(showToast).toHaveBeenCalledWith('1 entries loaded', 'success');
    for (const [message] of showToast.mock.calls) expectNoFrench(String(message));
  });

  test('erreur de lecture des logs : toast traduit', async () => {
    const showToast = jest.fn();
    const host = mountPanel('en', showToast);
    await flush();
    await clickTab(host, en.admin.tab.audit);
    const device = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('file/'));
    await act(async () => { device.click(); });
    // window.electronAudit absent : fonctionnalité indisponible
    expect(showToast).toHaveBeenCalledWith(en.admin.toast.logReaderUnavailable, 'error');
  });
});

test('AdminPanel rendu en français : textes et format de date français conservés', async () => {
  window.electronAudit = {
    tailLogFile: jest.fn().mockResolvedValue({
      success: true, totalLines: 1, loadedLines: 1, logs: [{ time: LOG_TIME, request: {}, response: {} }],
    }),
  };
  const host = mountPanel('fr');
  await flush();
  // ADMIN-17 : titre et onglet d'authentification en français (plus de calque ni d'anglais)
  expect(visibleText()).toContain('Panneau d\'administration');
  expect(visibleText()).not.toContain('Panel Administration');
  const tabs = Array.from(host.querySelectorAll('.admin-tab')).map(b => b.textContent);
  expect(tabs.some(txt => txt.includes('Méthodes d\'authentification'))).toBe(true);
  expect(tabs.some(txt => txt.includes('Auth Methods'))).toBe(false);
  expect(visibleText()).toContain('Coffres disponibles');
  await clickTab(host, fr.admin.tab.audit);
  const device = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('file/'));
  await act(async () => { device.click(); });
  await flush();
  expect(visibleText()).toContain(new Date(LOG_TIME).toLocaleString('fr-FR'));
  expect(visibleText()).toContain('Logs d\'Audit');
});

describe('Modales admin rendues en anglais', () => {
  test('activation d\'un audit device : libellés et validation traduits', async () => {
    const showToast = jest.fn();
    mount('en', <EnableAuditModal onEnable={jest.fn()} showToast={showToast} onClose={() => {}} />);
    expect(visibleText()).toContain(en.admin.enableAudit.title);
    const sshCheckbox = document.body.querySelector('input[type="checkbox"]');
    await act(async () => { sshCheckbox.click(); });
    expect(visibleText()).toContain(en.admin.sshConfig);
    expectNoFrench(visibleText());
    await act(async () => { buttonContaining(en.admin.common.enable).click(); });
    expect(showToast).toHaveBeenCalledWith(en.admin.enableAudit.sshHostRequired, 'error');
  });

  test('création de policy', () => {
    mount('en', <CreatePolicyModal savePolicy={jest.fn()} onCreated={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
    expect(visibleText()).toContain(en.admin.newPolicy);
    expect(visibleText()).toContain('e.g. app-read-only');
    expectNoFrench(visibleText());
  });

  test('builder de policy (hors aperçu HCL, qui est le contenu de la policy)', async () => {
    mount('en', (
      <PolicyBuilderModal
        allMounts={[{ path: 'kv', type: 'kv', version: 2 }]}
        loadAllMounts={jest.fn()}
        editPolicyName={null}
        vaultUrl={VAULT}
        axiosConfig={(c) => c}
        baseHeaders={() => ({})}
        savePolicy={jest.fn()}
        showToast={jest.fn()}
        onClose={() => {}}
      />
    ));
    const select = Array.from(document.body.querySelectorAll('select'))
      .find(s => Array.from(s.options).some(o => o.value === 'kv'));
    await act(async () => {
      const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
      setter.call(select, 'kv');
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    expect(visibleText()).toContain(en.admin.builder.title);
    expect(visibleText()).toContain(en.admin.builder.includeTotp);
    expect(visibleText()).toContain(en.admin.builder.totpPrefix);
    expectNoFrench(visibleText());
  });

  test('mot de passe SSH : texte d\'introduction avec <strong> inséré', () => {
    mount('en', <SshPasswordModal host="srv" username="root" onSubmit={jest.fn()} onClose={() => {}} />);
    expect(document.body.querySelector('strong').textContent).toBe('root@srv');
    expect(visibleText()).toContain(en.admin.sshPrompt.readLogs);
    expectNoFrench(visibleText());
  });
});

test('les 12 locales traduisent réellement les phrases admin (pas de copie anglaise)', () => {
  const sentences = [
    'header.title', 'mount.available', 'mount.infoText', 'ldap.autoSyncText', 'audit.enableHint',
    'tags.migrateInfo', 'toast.exportDone', 'toast.migrationDone', 'confirm.deleteMountMessage',
    'enableAudit.importantText', 'builder.listMountsHint', 'sshPrompt.intro',
  ];
  const enMap = Object.fromEntries(adminEntries(en));
  const others = { ar, de, es, fr, it, ja, ko, pt, ru, tr, zh };
  expect(Object.keys(enMap).length).toBeGreaterThan(200);
  for (const [code, locale] of Object.entries(others)) {
    const map = Object.fromEntries(adminEntries(locale));
    expect(Object.keys(map)).toEqual(Object.keys(enMap));
    for (const key of sentences) {
      expect([code, key, map[key] === enMap[key]]).toEqual([code, key, false]);
    }
  }
});
