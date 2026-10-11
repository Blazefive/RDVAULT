// ========================================
// TESTS : builder de policy — aller-retour fidèle et avertissements (rendu réel react-dom)
// ========================================
// - « Modifier » puis « Sauvegarder » sans rien changer réécrit EXACTEMENT la même policy
//   (règles par secret conservées, RBI-ONLY par coffre, TOTP non élargi, policy faite
//   uniquement de règles par secret ré-enregistrable).
// - Une policy que le builder ne sait pas représenter n'est jamais réécrite depuis le
//   builder (avertissement, enregistrement désactivé, HCL d'origine affiché).
// - Avertissements : « RBI uniquement » = restriction d'interface ; préfixe TOTP partagé.

import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import PolicyBuilderModal from './PolicyBuilderModal';
import { I18nProvider } from '../../i18n';
import en from '../../locales/en.json';

// axios 1.x est publié en ESM (non transformé par Jest/CRA) : simulé
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
const MOUNTS = [
  { path: 'A', type: 'kv', version: 2, description: '' },
  { path: 'B', type: 'kv', version: 2, description: '' },
  { path: 'L', type: 'kv', version: 1, description: '' },
];
const B = en.admin.builder;

let root = null;
let host = null;

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
});

const flush = async () => {
  for (let i = 0; i < 5; i++) {
    // eslint-disable-next-line no-await-in-loop
    await act(async () => { await new Promise(r => setTimeout(r, 0)); });
  }
};

function setValue(el, value) {
  const proto = el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
  el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
}

const selects = () => Array.from(host.querySelectorAll('select'));
const typeSelects = () => selects().filter(s => s.querySelector('option[value="secret"]'));
const coffreSelects = () => selects().filter(s => s.options[0]?.textContent === B.selectVault);
const secretSelects = () => selects().filter(s => s.options[0]?.textContent === B.selectSecret);
const accessSelects = () => selects().filter(s => s.querySelector('option[value="rbi-only"]'));
const button = (txt) => Array.from(host.querySelectorAll('button')).find(b => b.textContent.includes(txt));
const preview = () => Array.from(host.querySelectorAll('pre')).map(p => p.textContent).join('\n');

// Vault simulé : policies stockées + listing des secrets (s1, s2) de chaque coffre
function installAxios(policyStore = {}) {
  axios.get.mockReset();
  axios.get.mockImplementation(async (url) => {
    if (url.startsWith(`${VAULT}/v1/sys/policies/acl/`)) {
      const name = decodeURIComponent(url.split('/').pop());
      if (policyStore[name] === undefined) { const e = new Error('404'); e.response = { status: 404 }; throw e; }
      return { data: { data: { policy: policyStore[name] } } };
    }
    if (/\/v1\/[AB]\/metadata\?list=true$/.test(url)) return { data: { data: { keys: ['s1', 's2'] } } };
    if (/\/v1\/[AB]\/metadata\/s[12]$/.test(url)) return { data: { data: { current_version: 1, versions: { 1: { deletion_time: '' } } } } };
    if (/\/v1\/L\?list=true$/.test(url)) return { data: { data: { keys: ['s1', 's2'] } } };
    throw new Error('URL inattendue ' + url);
  });
}

async function render(props, mounts = MOUNTS) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    mountInRoot(root, (
      <I18nProvider defaultLang="en">
        <PolicyBuilderModal allMounts={mounts} loadAllMounts={() => {}} vaultUrl={VAULT}
          axiosConfig={(c) => c} baseHeaders={() => ({})} showToast={() => {}} onClose={() => {}} {...props} />
      </I18nProvider>
    ));
  });
  await flush();
}

// Construit une policy via l'UI du builder (création) et renvoie le HCL sauvegardé
async function buildPolicy(name, rules) {
  installAxios({});
  const savePolicy = jest.fn().mockResolvedValue(true);
  await render({ editPolicyName: null, savePolicy });
  await act(async () => { setValue(host.querySelector('input[type="text"]'), name); });
  for (let i = 0; i < rules.length; i++) {
    if (i > 0) await act(async () => { button(B.addRule).click(); });
    const r = rules[i];
    if (r.type === 'secret') await act(async () => { setValue(typeSelects()[i], 'secret'); });
    await act(async () => { setValue(coffreSelects()[i], r.coffre); });
    await flush();
    if (r.type === 'secret') {
      const secSel = secretSelects()[secretSelects().length - 1];
      await act(async () => { setValue(secSel, r.secret); });
    }
    await act(async () => { setValue(accessSelects()[i], r.access); });
  }
  await act(async () => { button(B.savePolicy).click(); });
  expect(savePolicy).toHaveBeenCalledTimes(1);
  act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  return savePolicy.mock.calls[0][1];
}

// Rouvre la policy en mode édition et clique « Sauvegarder » sans aucun changement
async function reopenAndSave(name, hcl, mounts = MOUNTS) {
  installAxios({ [name]: hcl });
  const savePolicy = jest.fn().mockResolvedValue(true);
  const showToast = jest.fn();
  await render({ editPolicyName: name, savePolicy, showToast }, mounts);
  const saveBtn = button(B.savePolicy);
  await act(async () => { saveBtn.click(); });
  await flush();
  return { saved: savePolicy.mock.calls.length ? savePolicy.mock.calls[0][1] : null, saveBtn, showToast };
}

describe('aller-retour « Modifier » → « Sauvegarder » sans changement', () => {
  test('RBI sur A + lecture seule sur B + secret B/s1 en RW : policy identique', async () => {
    const hcl1 = await buildPolicy('team', [
      { type: 'coffre', coffre: 'A', access: 'rbi-only' },
      { type: 'coffre', coffre: 'B', access: 'read-only' },
      { type: 'secret', coffre: 'B', secret: 's1', access: 'read-write' },
    ]);
    expect(hcl1).toContain('path "B/data/s1"     { capabilities = ["create","update","read","delete"] }');
    expect(hcl1).toMatch(/# KV v2 RO\npath "B\/metadata\/\*"/);
    const { saved } = await reopenAndSave('team', hcl1);
    // Avant correctif : B/s1 perdu et B relu comme RBI-ONLY (marqueur global)
    expect(saved).toBe(hcl1);
  });

  test('A en lecture seule + secret A/s1 en RW : TOTP non élargi au coffre entier', async () => {
    const hcl1 = await buildPolicy('ops', [
      { type: 'coffre', coffre: 'A', access: 'read-only' },
      { type: 'secret', coffre: 'A', secret: 's1', access: 'read-write' },
    ]);
    expect(hcl1).not.toContain('path "TOTP/keys/A-*"');
    expect(hcl1).toContain('path "TOTP/keys/A-s1"');
    const { saved } = await reopenAndSave('ops', hcl1);
    // Avant correctif : TOTP/keys/A-* (écriture sur toutes les clés TOTP du coffre) ajouté
    expect(saved).toBe(hcl1);
    expect(saved).not.toContain('path "TOTP/keys/A-*"');
  });

  test('policy faite uniquement de règles par secret : ré-enregistrable à l\'identique', async () => {
    const hcl1 = await buildPolicy('one', [{ type: 'secret', coffre: 'A', secret: 's1', access: 'read-only' }]);
    const { saved } = await reopenAndSave('one', hcl1);
    // Avant correctif : « Veuillez configurer au moins un coffre ou secret », rien n'était enregistré
    expect(saved).toBe(hcl1);
  });

  test('modérateur, KV v1, secret RBI : policy identique', async () => {
    const hcl1 = await buildPolicy('mix', [
      { type: 'coffre', coffre: 'A', access: 'moderator' },
      { type: 'coffre', coffre: 'L', access: 'read-write' },
      { type: 'secret', coffre: 'B', secret: 's2', access: 'rbi-only' },
    ]);
    expect(hcl1).toContain('# KV v2 MODERATOR (A)');
    const { saved } = await reopenAndSave('mix', hcl1);
    expect(saved).toBe(hcl1);
  });

  test('coffres chargés après l\'ouverture (allMounts vide au départ) : relecture une fois chargés', async () => {
    const hcl1 = await buildPolicy('late', [
      { type: 'coffre', coffre: 'B', access: 'read-write' },
      { type: 'secret', coffre: 'A', secret: 's1', access: 'read-only' },
    ]);
    installAxios({ late: hcl1 });
    const savePolicy = jest.fn().mockResolvedValue(true);
    function Harness() {
      const [mounts, setMounts] = useState([]);
      const loadAllMounts = async () => { await Promise.resolve(); setMounts(MOUNTS); };
      return (
        <PolicyBuilderModal allMounts={mounts} loadAllMounts={loadAllMounts} editPolicyName="late" vaultUrl={VAULT}
          axiosConfig={(c) => c} baseHeaders={() => ({})} savePolicy={savePolicy} showToast={() => {}} onClose={() => {}} />
      );
    }
    host = document.createElement('div');
    document.body.appendChild(host);
    root = createRoot(host);
    await act(async () => { mountInRoot(root, <I18nProvider defaultLang="en"><Harness /></I18nProvider>); });
    await flush();
    await act(async () => { button(B.savePolicy).click(); });
    await flush();
    expect(savePolicy).toHaveBeenCalledTimes(1);
    expect(savePolicy.mock.calls[0][1]).toBe(hcl1);
  });
});

describe('policy non représentable : jamais réécrite depuis le builder', () => {
  test('règle écrite à la main (chemin hors coffres connus) : avertissement, enregistrement désactivé', async () => {
    const hcl = 'path "A/data/*" { capabilities = ["read"] }\npath "A/metadata/*" { capabilities = ["list","read"] }\npath "secret/data/team/*" { capabilities = ["read"] }\n';
    const { saved, saveBtn } = await reopenAndSave('handmade', hcl);
    // Avant correctif : réécrite sans « secret/data/team/* » (perte de droits)
    expect(saved).toBeNull();
    expect(saveBtn.disabled).toBe(true);
    expect(host.textContent).toContain(B.unsupportedTitle);
    // L'aperçu montre la policy réelle, pas un HCL régénéré
    expect(preview()).toContain('secret/data/team/*');
  });

  test('ancien modèle « moderateur » (écriture sur sys/policies/acl/*) : non réécrit', async () => {
    const hcl = [
      '# MODERATOR: A',
      'path "A/metadata/*" { capabilities = ["list","read","delete"] }',
      'path "A/data/*"     { capabilities = ["create","update","read","delete","list"] }',
      '# Permissions modérateur : gestion policies, mounts, groupes AD',
      'path "sys/policies/acl/*"   { capabilities = ["read","create","update"] }',
    ].join('\n');
    const { saved, saveBtn } = await reopenAndSave('moderateur', hcl);
    expect(saved).toBeNull();
    expect(saveBtn.disabled).toBe(true);
  });

  test('policy au format JSON : non réécrite', async () => {
    const { saved } = await reopenAndSave('json', '{"path":{"A/data/*":{"capabilities":["read"]}}}');
    expect(saved).toBeNull();
    expect(host.textContent).toContain(B.unsupportedTitle);
  });
});

describe('avertissements du builder', () => {
  test('« RBI uniquement » : restriction d\'interface, pas de restriction Vault', async () => {
    installAxios({});
    await render({ editPolicyName: null, savePolicy: jest.fn() });
    await act(async () => { setValue(coffreSelects()[0], 'A'); });
    await flush();
    expect(host.textContent).not.toContain(B.rbiVaultLimit);
    await act(async () => { setValue(accessSelects()[0], 'rbi-only'); });
    expect(host.textContent).toContain(B.rbiVaultLimit);
  });

  test('préfixe TOTP partagé avec un autre coffre (web / web-prod) ou un coffre personnel', async () => {
    installAxios({});
    const mounts = [
      { path: 'web', type: 'kv', version: 2 },
      { path: 'web-prod', type: 'kv', version: 2 },
      { path: 'users/alice/perso', type: 'kv', version: 2 },
      { path: 'users/bob/perso', type: 'kv', version: 2 },
    ];
    await render({ editPolicyName: null, savePolicy: jest.fn() }, mounts);
    await act(async () => { setValue(coffreSelects()[0], 'web'); });
    await flush();
    const shared = en.admin.builder.totpPrefixShared.split('{{')[0].trim();
    expect(host.textContent).toContain(shared);
    expect(host.textContent).toContain('web-prod');
    await act(async () => { setValue(coffreSelects()[0], 'web-prod'); });
    await flush();
    expect(host.textContent).not.toContain(shared);
    await act(async () => { setValue(coffreSelects()[0], 'users/alice/perso'); });
    await flush();
    expect(host.textContent).toContain(shared);
    expect(host.textContent).toContain('users/bob/perso');
  });
});
