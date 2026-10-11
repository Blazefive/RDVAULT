// ========================================
// TESTS : panneau d'administration en écriture de droite à gauche (arabe)
// ========================================
// ADMIN-11 : chemins de coffres, chemin du journal d'audit, noms de policies, valeurs LDAP… étaient
//   affichés dans le sens rtl sans isolation : l'algorithme bidi déplaçait la barre oblique
//   (« Comptabilite/ » lu « /Comptabilite », « /var/log/…/vault_audit.log » lu « var/log/…log/ »).
//   Ils sont désormais isolés en ltr (<bdi dir="ltr" class="bidi-ltr">, LRI…PDI dans les <option>,
//   dir="ltr" sur les champs de saisie techniques et les zones de code HCL / journal).
// ADMIN-15 : en-têtes du tableau d'export alignés à gauche (textAlign: left) alors que les
//   cellules suivent le sens du document : propriétés logiques start / end.
// ADMIN-16 : marges physiques (marginLeft / marginRight) des cases à cocher, aides et badges :
//   propriétés logiques (margin-inline-start / margin-inline-end).
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
const AUDIT_FILE = '/var/log/vault/vault_audit.log';

const flush = async () => {
  for (let i = 0; i < 5; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await Promise.resolve(); });
  }
};

beforeEach(() => {
  axios.mockReset();
  axios.get.mockReset();
  axios.mockImplementation(async ({ url }) => {
    if (url.endsWith('/v1/sys/policies/acl')) return { data: { data: { keys: ['equipe-compta-lecture', 'default'] } } };
    if (url.endsWith('/groups')) return { data: { data: { keys: ['grp-compta'] } } };
    return { data: { data: { keys: [] } } };
  });
  axios.get.mockImplementation(async (url) => {
    if (url === `${VAULT}/v1/sys/mounts`) {
      return { data: { data: {
        'Comptabilite/': { type: 'kv', description: 'Coffre compta', options: { version: '2' } },
        'users/hunt/Mes-Secrets/': { type: 'kv', description: '', options: { version: '2' } },
      } } };
    }
    if (url === `${VAULT}/v1/sys/audit`) return { data: { data: { 'fichier-audit/': { type: 'file', description: '', options: { file_path: AUDIT_FILE } } } } };
    if (url === `${VAULT}/v1/auth/ldap/config`) return { data: { data: { url: 'ldaps://dc.example:636', userdn: 'OU=Users,DC=example', groupdn: 'OU=Groups,DC=example' } } };
    if (url.startsWith(`${VAULT}/v1/auth/ldap/groups/`)) return { data: { data: { policies: ['equipe-compta-lecture'] } } };
    if (url.startsWith(`${VAULT}/v1/sys/policies/acl/`)) return { data: { data: { policy: 'path "Comptabilite/data/*" { capabilities = ["read"] }' } } };
    return { data: { data: {} } };
  });
});

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
function mount(element) {
  localStorage.setItem('rdvault-lang', 'ar');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <I18nProvider>{element}</I18nProvider>); });
  mounted.push(root);
  return host;
}
afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
  localStorage.clear();
  delete window.electronAudit;
});

const mountPanel = (props = {}) => mount(
  <AdminPanel
    vaultUrl={VAULT}
    token="t"
    baseHeaders={() => ({})}
    axiosConfig={(c) => c}
    vaultApi={{ listKeysV2: async () => [], listKeysV1: async () => [], readSecretV2: async () => ({}), readSecretV1: async () => ({}) }}
    showToast={jest.fn()}
    username="admin"
    darkMode={false}
    onToggleDarkMode={() => {}}
    currentView="admin"
    onToggleAdminView={() => {}}
    onLogout={() => {}}
    isAdmin
    {...props}
  />
);
const clickTab = async (host, label) => {
  const tab = Array.from(host.querySelectorAll('.admin-tab')).find(b => b.textContent.includes(label));
  expect(tab).toBeTruthy();
  await act(async () => { tab.click(); });
  await flush();
};
// Saisie dans un champ contrôlé React (setter natif + événement input)
const typeInto = async (input, value) => {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
};
// Identifiant technique isolé en ltr
const ltrNodes = (root) => Array.from(root.querySelectorAll('bdi')).filter(b => b.getAttribute('dir') === 'ltr' && b.classList.contains('bidi-ltr'));
const ltrTexts = (root) => ltrNodes(root).map(b => b.textContent);

test('coffres : chemins isolés en ltr avec leur barre oblique, titre du coffre sélectionné (ADMIN-11)', async () => {
  const host = mountPanel({ hiddenEngines: ['Comptabilite'] });
  await flush();
  const items = Array.from(host.querySelectorAll('.admin-item'));
  expect(items).toHaveLength(2);
  // La barre oblique de fin fait partie de l'isolat : elle ne peut plus passer en tête
  expect(ltrTexts(host)).toEqual(expect.arrayContaining(['Comptabilite/', 'users/hunt/Mes-Secrets/']));
  // Badge « masqué » : marge logique (ADMIN-16)
  const hidden = Array.from(items[0].querySelectorAll('span')).find(s => s.textContent === ar.admin.mount.hidden);
  expect(hidden.style.marginLeft).toBe('');
  expect(hidden.style.marginInlineStart).toBe('8px');

  await act(async () => { items[0].click(); });
  await flush();
  const title = host.querySelector('.admin-editor-header h3');
  // « الخزنة: {{path}}/ » : barre oblique rattachée au chemin isolé, texte identique à la traduction
  expect(title.textContent).toBe(ar.admin.mount.title.replace('{{path}}', 'Comptabilite'));
  expect(ltrTexts(title)).toEqual(['Comptabilite/']);
  // Policies liées : nom isolé, badge à marge logique
  const badges = Array.from(host.querySelectorAll('.policy-badge'));
  expect(badges.length).toBeGreaterThan(0);
  for (const badge of badges) {
    expect(badge.style.marginRight).toBe('');
    expect(badge.style.marginInlineEnd).toBe('8px');
    expect(ltrTexts(badge)).toHaveLength(1);
  }
  expect(badges.flatMap(b => ltrTexts(b))).toContain('equipe-compta-lecture');
  const count = Array.from(host.querySelectorAll('h4 span')).find(s => s.style.fontWeight === 'normal');
  expect(count.style.marginLeft).toBe('');
  expect(count.style.marginInlineStart).toBe('12px');
});

test('policies : noms isolés, éditeur HCL en ltr, groupes isolés (ADMIN-11)', async () => {
  const host = mountPanel();
  await flush();
  await clickTab(host, ar.admin.tab.policies);
  expect(ltrTexts(host)).toEqual(expect.arrayContaining(['equipe-compta-lecture']));
  const item = Array.from(host.querySelectorAll('.admin-item')).find(li => li.textContent.includes('equipe-compta-lecture'));
  await act(async () => { item.click(); });
  await flush();
  const title = host.querySelector('.admin-editor-header h3');
  expect(title.textContent).toBe(ar.admin.policy.editorTitle.replace('{{name}}', 'equipe-compta-lecture'));
  expect(ltrTexts(title)).toEqual(['equipe-compta-lecture']);
  // Le contenu HCL est du code : toujours de gauche à droite
  expect(host.querySelector('textarea.admin-textarea').getAttribute('dir')).toBe('ltr');
  expect(ltrTexts(host)).toEqual(expect.arrayContaining(['grp-compta']));
  // Bouton de retrait d'un groupe : marge logique
  const remove = host.querySelector('[title="' + ar.admin.policy.removeGroup + '"]');
  expect(remove.style.marginLeft).toBe('');
  expect(remove.style.marginInlineStart).toBe('4px');
  // Menu contextuel : texte aligné en début de ligne
  await act(async () => {
    item.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, clientX: 10, clientY: 10 }));
  });
  const menuButtons = Array.from(document.body.querySelectorAll('button')).filter(b => b.textContent.includes(ar.admin.common.edit) || b.textContent.includes(ar.common.delete));
  expect(menuButtons.length).toBeGreaterThan(0);
  for (const b of menuButtons.filter(b => b.style.textAlign)) expect(b.style.textAlign).toBe('start');
});

test('authentification : valeurs LDAP isolées en ltr, retrait de liste logique', async () => {
  const host = mountPanel();
  await flush();
  await clickTab(host, ar.admin.tab.auth);
  expect(ltrTexts(host)).toEqual(expect.arrayContaining(['ldaps://dc.example:636', 'OU=Users,DC=example', 'OU=Groups,DC=example']));
  const ol = host.querySelector('.admin-help ol');
  expect(ol.style.marginLeft).toBe('');
  expect(ol.style.marginInlineStart).toBe('20px');
});

test('audit : chemin du device et du journal isolés, console du journal en ltr (ADMIN-11)', async () => {
  window.electronAudit = {
    tailLogFile: jest.fn().mockResolvedValue({
      success: true, totalLines: 1, loadedLines: 1,
      logs: [{ time: '2026-03-05T14:07:09Z', auth: { display_name: 'alice' }, request: { operation: 'read', path: 'Comptabilite/data/x' }, response: { status_code: 200 } }],
    }),
  };
  const host = mountPanel();
  await flush();
  await clickTab(host, ar.admin.tab.audit);
  const device = host.querySelector('.admin-item');
  expect(ltrTexts(device)).toEqual(['fichier-audit/', AUDIT_FILE]);
  await act(async () => { device.click(); });
  await flush();
  expect(ltrTexts(host.querySelector('.admin-editor'))).toEqual(expect.arrayContaining(['fichier-audit/']));
  expect(host.querySelector('[data-testid="audit-log-console"]').getAttribute('dir')).toBe('ltr');
});

test('export : en-têtes et cellules en alignement logique, chemins isolés (ADMIN-15)', async () => {
  const host = mountPanel();
  await flush();
  await clickTab(host, ar.admin.tab.export);
  const ths = Array.from(host.querySelectorAll('thead th'));
  expect(ths.map(th => th.style.textAlign)).toEqual(['start', 'start', 'start', 'end']);
  const rows = Array.from(host.querySelectorAll('tbody tr'));
  expect(rows).toHaveLength(2);
  expect(rows.map(r => ltrTexts(r))).toEqual([['Comptabilite'], ['users/hunt/Mes-Secrets']]);
  for (const r of rows) expect(r.lastElementChild.style.textAlign).toBe('end');
});

test('activation d\'audit : champs techniques en ltr, aide SSH en retrait logique (ADMIN-11, ADMIN-16)', async () => {
  mount(<EnableAuditModal onEnable={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
  const byPlaceholder = (p) => document.body.querySelector(`input[placeholder="${p}"]`);
  // Nom du device (segment de chemin Vault) et chemin du fichier
  const inputs = Array.from(document.body.querySelectorAll('input[type="text"]'));
  expect(inputs[0].getAttribute('dir')).toBe('ltr');
  const filePath = byPlaceholder(AUDIT_FILE);
  expect(filePath.getAttribute('dir')).toBe('ltr');
  // Description : texte libre, garde le sens de la langue (texte indicatif arabe aligné à droite)
  expect(inputs[1].getAttribute('dir')).toBeNull();
  const hint = Array.from(document.body.querySelectorAll('div')).find(d => d.textContent === ar.admin.enableAudit.useSshHint);
  expect(hint.style.marginLeft).toBe('');
  expect(hint.style.marginInlineStart).toBe('32px');
  await act(async () => { document.body.querySelector('input[type="checkbox"]').click(); });
  // Texte indicatif technique littéral : toujours ltr
  for (const p of ['root', '22', 'SHA256:…']) {
    expect([p, byPlaceholder(p).getAttribute('dir')]).toEqual([p, 'ltr']);
  }
  // Hôte : texte indicatif traduit (« hachi أو 192.168.1.x ») dans le sens de la langue tant que le
  // champ est vide (forcé en ltr, il s'affichait « hachi 192.168.1 أو.x ») ; ltr dès la saisie
  const host = byPlaceholder(ar.admin.enableAudit.sshHostPlaceholder);
  expect(host.getAttribute('dir')).toBeNull();
  await typeInto(host, '10.0.0.5');
  expect(host.getAttribute('dir')).toBe('ltr');
  // Nom du device vidé : texte indicatif traduit (« مثال: file ») dans le sens de la langue
  await typeInto(inputs[0], '');
  expect(inputs[0].getAttribute('dir')).toBeNull();
});

// Vérification visuelle (arabe) : même dans le sens de la langue, « hachi أو 192.168.1.x » s'affichait
// « x.192.168.1 » (chiffres après une lettre arabe = nombres arabes, point final rattaché au rtl).
// Les deux exemples techniques de la traduction arabe sont isolés (LRI … PDI, invisibles).
test('arabe : exemples d\'hôte SSH du texte indicatif isolés en ltr', () => {
  expect(ar.admin.enableAudit.sshHostPlaceholder).toBe('\u2066hachi\u2069 أو \u2066192.168.1.x\u2069');
});

test('builder de policy : cases et aides en marges logiques, coffres isolés dans la liste (ADMIN-16, ADMIN-11)', async () => {
  mount(
    <PolicyBuilderModal
      allMounts={[{ path: 'Comptabilite', type: 'kv', version: 2 }]}
      loadAllMounts={jest.fn()}
      editPolicyName={null}
      vaultUrl={VAULT}
      axiosConfig={(c) => c}
      baseHeaders={() => ({})}
      savePolicy={jest.fn()}
      showToast={jest.fn()}
      onClose={() => {}}
    />
  );
  // Nom de policy : texte indicatif traduit dans le sens de la langue, identifiant saisi en ltr
  const name = document.body.querySelector('input[type="text"]');
  expect(name.getAttribute('dir')).toBeNull();
  await typeInto(name, 'equipe-compta');
  expect(name.getAttribute('dir')).toBe('ltr');
  const listMounts = document.body.querySelector('input[type="checkbox"]');
  expect(listMounts.style.marginRight).toBe('');
  expect(listMounts.style.marginInlineEnd).toBe('8px');
  const hint = Array.from(document.body.querySelectorAll('div')).find(d => d.textContent === ar.admin.builder.listMountsHint);
  expect(hint.style.marginLeft).toBe('');
  expect(hint.style.marginInlineStart).toBe('24px');
  const option = Array.from(document.body.querySelectorAll('option')).find(o => o.value === 'Comptabilite');
  expect(option.textContent).toBe('\u2066Comptabilite/ (KV v2)\u2069');
  // Choix du coffre → bloc TOTP : case, mention et retrait en marges logiques
  const select = option.parentElement;
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
    setter.call(select, 'Comptabilite');
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  const totp = Array.from(document.body.querySelectorAll('input[type="checkbox"]'))[1];
  expect(totp.style.marginRight).toBe('');
  expect(totp.style.marginInlineEnd).toBe('8px');
  // TOTP inclus par défaut : bloc du préfixe de clé affiché, en retrait logique
  expect(totp.checked).toBe(true);
  const indent = document.body.querySelector('code').closest('div').parentElement;
  expect(indent.style.marginLeft).toBe('');
  expect(indent.style.marginInlineStart).toBe('24px');
});

test('nouvelle policy et mot de passe SSH : identifiants en ltr', async () => {
  mount(<CreatePolicyModal savePolicy={jest.fn()} onCreated={jest.fn()} showToast={jest.fn()} onClose={() => {}} />);
  const name = document.body.querySelector('input[type="text"]');
  expect(name.getAttribute('dir')).toBeNull();
  await typeInto(name, 'app-read-only');
  expect(name.getAttribute('dir')).toBe('ltr');
  act(() => mounted.pop().unmount());
  document.body.innerHTML = '';
  mount(<SshPasswordModal host="192.168.1.10" username="root" onSubmit={jest.fn()} onClose={() => {}} />);
  const target = document.body.querySelector('strong');
  expect(target.textContent).toBe('root@192.168.1.10');
  expect(target.getAttribute('dir')).toBe('ltr');
  expect(target.classList.contains('bidi-ltr')).toBe(true);
});

test('aucune propriété physique gauche/droite dans les styles inline du panneau et des modales admin', () => {
  const fs = require('fs');
  const path = require('path');
  const files = ['AdminPanel.jsx', ...fs.readdirSync(path.join(__dirname, 'components/admin'))
    .filter(f => /\.jsx$/.test(f) && !/\.test\./.test(f)).map(f => `components/admin/${f}`)];
  for (const f of files) {
    const src = fs.readFileSync(path.join(__dirname, f), 'utf8');
    expect([f, src.match(/\b(margin|padding)(Left|Right)\s*:/g)]).toEqual([f, null]);
    expect([f, src.match(/textAlign:\s*'(left|right)'/g)]).toEqual([f, null]);
  }
  // Seules exceptions : coordonnées du menu contextuel (position du pointeur, physique par nature)
  // et halo décoratif symétrique de l'en-tête
  const panel = fs.readFileSync(path.join(__dirname, 'AdminPanel.jsx'), 'utf8');
  expect(panel.match(/[{,\s](left|right):\s*[^,\n}]+/g).map(s => s.trim())).toEqual(["right: '-50%'", 'left: policyContextMenu.x']);
});
