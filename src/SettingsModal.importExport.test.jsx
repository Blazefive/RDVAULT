// ========================================
// TESTS : SettingsModal — export / import de coffre (rendu réel react-dom dans jsdom)
// ========================================
// axios est remplacé par un petit coffre KV en mémoire (sémantique Vault KV v1/v2 :
// LIST des enfants directs, 404 « supprimé » avec metadata.deletion_time, versions).
// Les tests passent par la vraie interface (onglet Export, boutons, dialogues simulés).
//
// Couvre :
// - SETTINGS-1  : le secret interne « .rdvault-passkeys » n'est ni exporté ni écrasé par un import
// - SETTINGS-9  : aller-retour complet (Website, EntryType, champs personnalisés, pièces jointes)
//                 et fusion en mode « écraser les doublons » (rien n'est perdu)
// - SETTINGS-10 : noms « . », « /x », « x/ », « a//b » refusés et comptés en échec
// - SETTINGS-12 : une entrée supprimée (suppression douce) n'est pas comptée « illisible »
// - Import : un LIST par dossier remplace le GET d'existence par clé, même résultat

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SettingsModal from './SettingsModal';
import { I18nProvider } from './i18n';
import fr from './locales/fr.json';

const VAULT = 'http://vault.test';

// ---------- Coffre KV en mémoire ----------
const mockKv = { engines: new Map(), calls: [], listStatus: null, readFail: {} };

function mockHttpError(status, data) {
  const e = new Error('HTTP ' + status);
  e.response = { status, data };
  return e;
}

// Résout une URL de l'API en { engine, op, key } (segments décodés une fois, comme Vault)
function mockResolve(url) {
  const u = new URL(url);
  const path = u.pathname.replace(/^\/v1\//, '');
  const engines = Array.from(mockKv.engines.entries()).sort((a, b) => b[0].length - a[0].length);
  for (const [name, eng] of engines) {
    const encName = name.split('/').map(encodeURIComponent).join('/');
    if (path !== encName && !path.startsWith(encName + '/')) continue;
    const rest = path.slice(encName.length + 1);
    const isList = u.searchParams.get('list') === 'true';
    if (eng.version === 2) {
      const m = rest.match(/^(data|metadata)(?:\/(.*))?$/);
      if (!m) return null;
      return { eng, op: m[1], key: decodeURIComponent(m[2] || ''), isList };
    }
    return { eng, op: 'v1', key: decodeURIComponent(rest), isList };
  }
  return null;
}

function mockList(eng, prefix) {
  const out = new Set();
  for (const [key, entry] of eng.keys) {
    if (entry.destroyed) continue;
    if (!key.startsWith(prefix)) continue;
    const rel = key.slice(prefix.length);
    if (!rel) continue;
    const i = rel.indexOf('/');
    out.add(i === -1 ? rel : rel.slice(0, i + 1));
  }
  return Array.from(out).sort();
}

async function mockGet(url) {
  const r = mockResolve(url);
  if (!r) throw mockHttpError(404, { errors: ['engine not found'] });
  if (r.isList) {
    mockKv.calls.push({ kind: 'list', key: r.key });
    if (mockKv.listStatus) throw mockHttpError(mockKv.listStatus, { errors: ['permission denied'] });
    const keys = mockList(r.eng, r.key);
    if (keys.length === 0) throw mockHttpError(404, { errors: [] });
    return { data: { data: { keys } } };
  }
  mockKv.calls.push({ kind: 'read', key: r.key });
  // Lecture en échec injectée : statut HTTP, ou 'network' (aucune réponse)
  const fail = mockKv.readFail[r.key];
  if (fail === 'network') throw Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });
  if (fail) throw mockHttpError(fail, { errors: ['decryption failed'] });
  const entry = r.eng.keys.get(r.key);
  if (!entry || entry.ghost) throw mockHttpError(404, { errors: [] });
  const v = entry.versions[entry.versions.length - 1];
  if (r.eng.version === 2 && v.deletion_time) {
    throw mockHttpError(404, { data: { data: null, metadata: { deletion_time: v.deletion_time, destroyed: false, version: entry.versions.length } } });
  }
  const data = JSON.parse(JSON.stringify(v.data));
  return r.eng.version === 2
    ? { data: { data: { data, metadata: { version: entry.versions.length } } } }
    : { data: { data } };
}

async function mockPost(url, body) {
  const r = mockResolve(url);
  if (!r) throw mockHttpError(404, { errors: ['engine not found'] });
  mockKv.calls.push({ kind: 'write', key: r.key });
  const data = r.eng.version === 2 ? body.data : body;
  const entry = r.eng.keys.get(r.key) || { versions: [] };
  entry.versions.push({ data: JSON.parse(JSON.stringify(data)), deletion_time: '' });
  r.eng.keys.set(r.key, entry);
  return { data: { data: { version: entry.versions.length } } };
}

jest.mock('axios', () => ({
  __esModule: true,
  default: {
    get: (...a) => mockGet(...a),
    post: (...a) => mockPost(...a),
    put: jest.fn(),
    delete: jest.fn()
  }
}));

global.IS_REACT_ACT_ENVIRONMENT = true;

// ---------- Outils ----------
function addEngine(name, version = 2) {
  mockKv.engines.set(name, { version, keys: new Map() });
  return { name, version, canWrite: true, canList: true };
}
function seed(engineName, key, data, { deleted = false, ghost = false } = {}) {
  mockKv.engines.get(engineName).keys.set(key, {
    ghost,
    versions: [{ data: JSON.parse(JSON.stringify(data)), deletion_time: deleted ? '2026-10-01T00:00:00Z' : '' }]
  });
}
function current(engineName, key) {
  const entry = mockKv.engines.get(engineName).keys.get(key);
  if (!entry) return undefined;
  return entry.versions[entry.versions.length - 1].data;
}
function versionCount(engineName, key) {
  return mockKv.engines.get(engineName).keys.get(key)?.versions.length || 0;
}
// Vue normalisée, telle que l'application la lit (vaultApi.readSecretV2)
function view(d) {
  return {
    Username: d.Username || '', Password: d.Password || '', URL: d.URL || '', Website: d.Website || '',
    Notes: d.Notes || '', Tags: d.Tags || '', EntryType: d.EntryType || 'secret',
    CustomFields: d.CustomFields || [], Attachments: d.Attachments || []
  };
}

let root = null;
let host = null;

beforeEach(() => {
  mockKv.engines.clear();
  mockKv.calls.length = 0;
  mockKv.listStatus = null;
  mockKv.readFail = {};
  localStorage.setItem('rdvault-lang', 'fr');
});

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  host = null;
  document.body.innerHTML = '';
  localStorage.clear();
  delete window.electronExport;
});

// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const tick = () => new Promise(r => setTimeout(r, 0));
const flush = () => act(async () => { await tick(); });
const button = (txt) => Array.from(host.querySelectorAll('button')).find(b => b.textContent.trim() === txt);
const setSelect = (sel, v) => {
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(sel, v);
  sel.dispatchEvent(new Event('change', { bubbles: true }));
};

function mountSettings(engines, toasts) {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  act(() => {
    mountInRoot(root,
      <I18nProvider>
        <SettingsModal
          onClose={() => {}}
          secretEngines={engines}
          appMode="local"
          vaultUrl={VAULT}
          token="tok"
          showToast={(m, k) => toasts.push([k, m])}
        />
      </I18nProvider>
    );
  });
  act(() => { button(fr.export.title).click(); });
}

async function waitToast(toasts, n = 1) {
  for (let i = 0; i < 200 && toasts.length < n; i++) await flush();
}

async function exportVia(engine, engines, format = 'csv') {
  const toasts = [];
  let saved = null;
  window.electronExport = { saveFile: async (o) => { saved = o.content; return { success: true }; } };
  mountSettings(engines, toasts);
  act(() => { setSelect(host.querySelectorAll('select')[0], engine.name); });
  if (format === 'xml') act(() => { host.querySelector('input[name="exportFormat"][value="xml"]').click(); });
  await act(async () => { button(fr.export.exportBtn).click(); });
  await waitToast(toasts);
  act(() => root.unmount());
  root = null;
  return { content: saved, toasts };
}

async function importVia(engine, engines, fileName, content, mode = 'skip') {
  const toasts = [];
  window.electronExport = { openFile: async () => ({ success: true, filePath: 'C:\\x\\' + fileName, content }) };
  mountSettings(engines, toasts);
  act(() => { setSelect(host.querySelectorAll('select')[1], engine.name); });
  if (mode === 'overwrite') act(() => { host.querySelectorAll('input[name="importDuplicate"]')[1].click(); });
  await act(async () => { button(fr.export.importSelectFile).click(); });
  await act(async () => { button(fr.export.importBtn).click(); });
  await waitToast(toasts);
  act(() => root.unmount());
  root = null;
  return toasts;
}

const fmt = (s, vars) => Object.entries(vars).reduce((acc, [k, v]) => acc.replace(`{{${k}}}`, String(v)), s);

const PASSKEYS = { items: { 'example.com': [{ credentialId: 'cred-1', rpId: 'example.com', userName: 'moi', privateKeyJwk: { kty: 'EC', d: 'SECRET' }, signCount: 3 }] } };
const PRIV = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----';
const FULL = {
  Username: 'admin', Password: 'p@ss', URL: 'https://x.example', Website: 'https://www.x.example',
  Notes: 'ligne 1\nligne 2', Tags: 'prod',
  CustomFields: [{ key: 'Port', value: '2222' }, { key: 'Clé API', value: 'sk-123', protected: true }],
  Attachments: [{ name: 'cert.pem', size: 3, type: 'text/plain', data: 'YWJj' }],
  EntryType: 'secret'
};
const SSH = { Username: 'phrase', Password: PRIV, URL: 'ssh-ed25519 AAAAC3Nza user@pc', Notes: '', Tags: '', EntryType: 'ssh' };

// ========================================
// SETTINGS-1 : stockage interne des passkeys
// ========================================
describe('SETTINGS-1 : le secret interne .rdvault-passkeys', () => {
  test.each(['csv', 'xml'])('n\'apparaît pas dans un export %s', async (format) => {
    const E = addEngine('perso');
    seed('perso', '.rdvault-passkeys', PASSKEYS);
    seed('perso', 'web', { Username: 'u', Password: 'p' });
    const { content, toasts } = await exportVia(E, [E], format);
    expect(content).not.toContain('.rdvault');
    expect(content).toContain('web');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.success, { count: 1 })]);
  });

  test('un import « écraser les doublons » d\'un ancien export qui contient la ligne ne l\'écrase pas', async () => {
    const E = addEngine('perso');
    seed('perso', '.rdvault-passkeys', PASSKEYS);
    seed('perso', 'web', { Username: 'u', Password: 'p' });
    const oldFile = 'Name,Username,Password,URL,Notes,Tags,Port\n'
      + '".rdvault-passkeys","","","","","",""\n'
      + '"web","u2","p2","","","",""';
    const toasts = await importVia(E, [E], 'ancien.csv', oldFile, 'overwrite');
    expect(current('perso', '.rdvault-passkeys')).toEqual(PASSKEYS);
    expect(versionCount('perso', '.rdvault-passkeys')).toBe(1);
    expect(current('perso', 'web').Password).toBe('p2');
    expect(toasts[0]).toEqual(['warning', fmt(fr.export.importPartial, { count: 1, failed: 1 })]);
  });

  // COMPAT-2 : seuls les noms internes EXACTS sont réservés. Avant : tout nom commençant par « .rdvault »
  // était refusé (« .rdvault-autre » compté en échec, toast « error »).
  test('un import ne crée pas non plus de secret réservé dans un coffre qui n\'en a pas ; « .rdvault-autre » est une entrée ordinaire', async () => {
    const E = addEngine('perso');
    const csv = 'Name,Username,Password\n".rdvault-passkeys",x,y\n".rdvault-autre",x,y\n';
    const toasts = await importVia(E, [E], 'f.csv', csv, 'skip');
    expect(Array.from(mockKv.engines.get('perso').keys.keys())).toEqual(['.rdvault-autre']);
    expect(current('perso', '.rdvault-autre')).toMatchObject({ Username: 'x', Password: 'y' });
    expect(toasts[0]).toEqual(['warning', fmt(fr.export.importPartial, { count: 1, failed: 1 })]);
  });

  test('aller-retour export → réimport « écraser » dans le même coffre : passkeys intactes', async () => {
    const E = addEngine('perso');
    seed('perso', '.rdvault-passkeys', PASSKEYS);
    seed('perso', 'web', { Username: 'u', Password: 'p' });
    const { content } = await exportVia(E, [E], 'csv');
    const toasts = await importVia(E, [E], 'perso-export.csv', content, 'overwrite');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 1 })]);
    expect(current('perso', '.rdvault-passkeys')).toEqual(PASSKEYS);
    expect(versionCount('perso', '.rdvault-passkeys')).toBe(1);
  });
});

// ========================================
// COMPAT-2 : noms réservés exacts, entrées utilisateur « .rdvault… » de la 1.5.0
// ========================================
// La 1.5.0 ne réservait aucun nom : une entrée « .rdvault-notes » ou « .rdvault » à la racine d'un coffre
// est une entrée ordinaire (affichée par le tableau). Avant : elle manquait à l'export et son import était
// refusé. Seuls « .rdvault-passkeys » et « .rdvault-keycheck » (secrets internes) restent exclus.
describe('COMPAT-2 : export / import des noms « .rdvault… »', () => {
  const KEYCHECK = { purpose: 'rdvault-key-check' };
  const internalReads = () => mockKv.calls
    .filter(c => c.kind === 'read' && (c.key === '.rdvault-passkeys' || c.key === '.rdvault-keycheck'));

  test.each(['csv', 'xml'])('export %s : entrées utilisateur « .rdvault… » exportées, secrets internes exclus', async (format) => {
    const E = addEngine('perso');
    seed('perso', '.rdvault-passkeys', PASSKEYS);
    seed('perso', '.rdvault-keycheck', KEYCHECK);
    seed('perso', '.rdvault-notes', { Username: 'notes', Password: 'pn', Notes: 'pense-bête' });
    seed('perso', '.rdvault', { Username: 'racine', Password: 'pr' });
    seed('perso', 'dossier/.rdvault-passkeys', { Username: 'd', Password: 'pd' });
    const { content, toasts } = await exportVia(E, [E], format);
    expect(toasts[0]).toEqual(['success', fmt(fr.export.success, { count: 3 })]); // avant : 1
    expect(content).toContain('.rdvault-notes');
    expect(content).toContain('pense-bête');
    expect(content).toContain('dossier/.rdvault-passkeys');
    expect(content).not.toContain('SECRET'); // clé privée des passkeys jamais exportée
    expect(content).not.toContain('rdvault-key-check');
    expect(internalReads()).toEqual([]); // secrets internes jamais lus
  });

  test('aller-retour « écraser » vers un autre coffre : « .rdvault-notes » réimportée, secrets internes intacts', async () => {
    const S = addEngine('source');
    const T = addEngine('cible');
    seed('source', '.rdvault-notes', { Username: 'notes', Password: 'pn' });
    seed('source', '.rdvault-passkeys', PASSKEYS);
    seed('cible', '.rdvault-passkeys', PASSKEYS);
    seed('cible', '.rdvault-keycheck', KEYCHECK);
    const { content } = await exportVia(S, [S, T], 'csv');
    const toasts = await importVia(T, [S, T], 'source.csv', content, 'overwrite');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 1 })]);
    expect(view(current('cible', '.rdvault-notes'))).toEqual(view({ Username: 'notes', Password: 'pn' }));
    expect(current('cible', '.rdvault-passkeys')).toEqual(PASSKEYS);
    expect(versionCount('cible', '.rdvault-passkeys')).toBe(1);
    expect(versionCount('cible', '.rdvault-keycheck')).toBe(1);
  });

  test('import : « .rdvault-keycheck » refusé comme « .rdvault-passkeys » ; « .rdvault », « .rdvault-passkeys-old » et un dossier acceptés', async () => {
    const E = addEngine('perso');
    seed('perso', '.rdvault-keycheck', KEYCHECK);
    const csv = 'Name,Username,Password\n'
      + '".rdvault-keycheck",x,y\n".rdvault-passkeys",x,y\n".rdvault",u1,p1\n".rdvault-passkeys-old",u2,p2\n"dossier/.rdvault-keycheck",u3,p3\n';
    const toasts = await importVia(E, [E], 'f.csv', csv, 'overwrite');
    expect(toasts[0]).toEqual(['warning', fmt(fr.export.importPartial, { count: 3, failed: 2 })]);
    expect(current('perso', '.rdvault-keycheck')).toEqual(KEYCHECK);
    expect(versionCount('perso', '.rdvault-keycheck')).toBe(1);
    expect(current('perso', '.rdvault-passkeys')).toBeUndefined();
    expect(current('perso', '.rdvault').Password).toBe('p1');
    expect(current('perso', '.rdvault-passkeys-old').Password).toBe('p2');
    expect(current('perso', 'dossier/.rdvault-keycheck').Password).toBe('p3');
  });
});

// ========================================
// COMPAT 1.5.0 : nom de coffre enregistré encodé (affichage seulement)
// ========================================
test('sélecteurs export / import : nom de coffre 1.5.0 encodé affiché décodé, requêtes sur le nom technique', async () => {
  const E = addEngine('Coffre%20%C3%A9quipe');
  seed('Coffre%20%C3%A9quipe', 'web', { Username: 'u', Password: 'p' });
  const toasts = [];
  window.electronExport = { saveFile: async () => ({ success: true }) };
  mountSettings([E], toasts);
  const labels = Array.from(host.querySelectorAll('select')).map(s => Array.from(s.options).map(o => o.textContent));
  expect(labels[0]).toEqual(['--', '\u2066Coffre équipe (KV v2)\u2069']); // avant : « Coffre%20%C3%A9quipe (KV v2) »
  expect(labels[1]).toEqual(['--', '\u2066Coffre équipe (KV v2)\u2069']);
  expect(host.querySelectorAll('select')[0].options[1].value).toBe('Coffre%20%C3%A9quipe');
  act(() => { setSelect(host.querySelectorAll('select')[0], 'Coffre%20%C3%A9quipe'); });
  await act(async () => { button(fr.export.exportBtn).click(); });
  await waitToast(toasts);
  expect(toasts[0]).toEqual(['success', fmt(fr.export.success, { count: 1 })]);
  expect(mockKv.calls.filter(c => c.kind === 'read').map(c => c.key)).toEqual(['web']);
});

// ========================================
// SETTINGS-9 : aller-retour complet et fusion
// ========================================
describe('SETTINGS-9 : aller-retour export / import sans perte', () => {
  test.each(['csv', 'xml'])('%s : Website, type SSH, champs personnalisés (protégés) et pièces jointes conservés', async (format) => {
    const S = addEngine('source');
    const T = addEngine('cible');
    seed('source', 'web', FULL);
    seed('source', 'srv-ssh', SSH);
    seed('source', 'dossier/simple', { Username: 'a', Password: 'b', URL: '', Notes: '', Tags: '' });
    const exp = await exportVia(S, [S, T], format);
    expect(exp.toasts[0]).toEqual(['success', fmt(fr.export.success, { count: 3 })]);
    const imp = await importVia(T, [S, T], 'export.' + format, exp.content);
    expect(imp[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 3 })]);
    expect(view(current('cible', 'web'))).toEqual(view(FULL));
    expect(current('cible', 'web').CustomFields).toEqual(FULL.CustomFields); // ordre et drapeau « protected » conservés
    expect(view(current('cible', 'srv-ssh'))).toEqual(view(SSH));
    expect(current('cible', 'srv-ssh').EntryType).toBe('ssh');
    expect(view(current('cible', 'dossier/simple'))).toEqual(view({ Username: 'a', Password: 'b' }));
  });

  test('le CSV exporté garde les 7 premières colonnes historiques puis ajoute les colonnes étendues', async () => {
    const E = addEngine('source');
    seed('source', 'web', FULL);
    const { content } = await exportVia(E, [E], 'csv');
    expect(content.split('\n')[0]).toBe('Name,Username,Password,URL,Notes,Tags,Port,Website,EntryType,CustomFields,Attachments');
  });

  test('« écraser les doublons » fusionne : les colonnes absentes du fichier ne sont pas effacées', async () => {
    const T = addEngine('cible');
    seed('cible', 'web', FULL);
    const csv = 'Name,Username,Password\nweb,nouvel-id,nouveau-mdp\n';
    const toasts = await importVia(T, [T], 'tiers.csv', csv, 'overwrite');
    expect(toasts[0][0]).toBe('success');
    expect(current('cible', 'web')).toEqual({ ...FULL, Username: 'nouvel-id', Password: 'nouveau-mdp' });
  });

  test('« écraser les doublons » avec un ancien export (7 colonnes) : pièces jointes et champs personnalisés conservés, Port mis à jour', async () => {
    const T = addEngine('cible');
    seed('cible', 'web', FULL);
    const csv = 'Name,Username,Password,URL,Notes,Tags,Port\n"web","admin","p@ss2","https://x.example","n","prod","2223"';
    await importVia(T, [T], 'ancien.csv', csv, 'overwrite');
    expect(current('cible', 'web')).toEqual({
      ...FULL, Password: 'p@ss2', Notes: 'n',
      CustomFields: [{ key: 'Port', value: '2223' }, { key: 'Clé API', value: 'sk-123', protected: true }]
    });
  });

  test('un ancien export (7 colonnes) importé dans un coffre vide donne exactement les mêmes données qu\'avant', async () => {
    const T = addEngine('cible');
    const csv = 'Name,Username,Password,URL,Notes,Tags,Port\n"web","u","p","https://a.example","n","t","22"\n"sans-port","u","p","","","",""';
    const toasts = await importVia(T, [T], 'ancien.csv', csv);
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 2 })]);
    expect(current('cible', 'web')).toEqual({ Username: 'u', Password: 'p', URL: 'https://a.example', Notes: 'n', Tags: 't', CustomFields: [{ key: 'Port', value: '22' }] });
    expect(current('cible', 'sans-port')).toEqual({ Username: 'u', Password: 'p', URL: '', Notes: '', Tags: '' });
  });

  test('un JSON de champs personnalisés ou de pièces jointes invalide : ligne refusée et comptée, les autres importées', async () => {
    const T = addEngine('cible');
    const csv = 'Name,Username,Password,URL,Notes,Tags,Port,Website,EntryType,CustomFields,Attachments\n'
      + '"ok","u","p","","","","","","","",""\n'
      + '"cf-casse","u","p","","","","","","","[{""key"": ",""\n'
      + '"pj-casse","u","p","","","","","","","","[{""name"":""a"",""data"":""pas du base64 !""}]"';
    const toasts = await importVia(T, [T], 'f.csv', csv);
    expect(toasts[0]).toEqual(['warning', fmt(fr.export.importPartial, { count: 1, failed: 2 })]);
    expect(current('cible', 'ok')).toBeDefined();
    expect(current('cible', 'cf-casse')).toBeUndefined();
    expect(current('cible', 'pj-casse')).toBeUndefined();
  });

  test('colonnes url et website : chacune dans son champ ; une colonne website seule reste l\'URL (fichiers tiers)', async () => {
    const T = addEngine('cible');
    await importVia(T, [T], 'a.csv', 'name,url,website,password\nboth,https://login.example,https://www.example,p\n');
    expect(current('cible', 'both')).toMatchObject({ URL: 'https://login.example', Website: 'https://www.example' });
    await importVia(T, [T], 'b.csv', 'name,website,password\nseul,https://site.example,p\n');
    expect(current('cible', 'seul').URL).toBe('https://site.example');
    expect(current('cible', 'seul').Website).toBeUndefined();
  });

  test('un type d\'entrée inconnu ou « folder » n\'est pas écrit', async () => {
    const T = addEngine('cible');
    const csv = 'Name,Password,EntryType\nx,p,folder\ny,p,<script>\nz,p,ssh\n';
    await importVia(T, [T], 'f.csv', csv);
    expect(current('cible', 'x').EntryType).toBeUndefined();
    expect(current('cible', 'y').EntryType).toBeUndefined();
    expect(current('cible', 'z').EntryType).toBe('ssh');
  });
});

// ========================================
// SETTINGS-10 : noms invalides
// ========================================
test('SETTINGS-10 : les noms « . », « /x », « x/ », « a//b » et « a\\b » sont refusés et comptés en échec', async () => {
  const T = addEngine('cible');
  const csv = 'Name,Username,Password\n".",u1,p1\n"/racine",u2,p2\n"dossier/",u3,p3\n"a//b",u4,p4\n"a\\b",u5,p5\n"bon/nom",u6,p6\n';
  const toasts = await importVia(T, [T], 'noms.csv', csv);
  expect(toasts[0]).toEqual(['warning', fmt(fr.export.importPartial, { count: 1, failed: 5 })]);
  expect(Array.from(mockKv.engines.get('cible').keys.keys())).toEqual(['bon/nom']);
});

// ========================================
// SETTINGS-12 : entrées supprimées à l'export
// ========================================
describe('SETTINGS-12 : export et suppression douce', () => {
  test('une entrée supprimée (404 + deletion_time) est ignorée sans être comptée « illisible »', async () => {
    const E = addEngine('kv');
    seed('kv', 'garde', { Password: 'a' });
    seed('kv', 'jete', { Password: 'b' }, { deleted: true });
    seed('kv', 'dossier-supprime/.placeholder', { EntryType: 'placeholder' }, { deleted: true });
    const { toasts, content } = await exportVia(E, [E], 'csv');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.success, { count: 1 })]);
    expect(content).not.toContain('jete');
  });

  test('un 404 sans métadonnée de suppression reste signalé comme illisible', async () => {
    const E = addEngine('kv');
    seed('kv', 'garde', { Password: 'a' });
    seed('kv', 'fantome', { Password: 'b' }, { ghost: true });
    const { toasts } = await exportVia(E, [E], 'csv');
    expect(toasts[0]).toEqual(['warning', fmt(fr.export.partialSuccess, { count: 1, failed: 1 })]);
  });
});

// ========================================
// Import : LIST par dossier au lieu d'un GET par clé, même résultat
// ========================================
describe('import : test d\'existence par LIST', () => {
  const CSV = 'Name,Username,Password\n'
    + 'garde,u,nouveau\n'          // existe : ignoré en mode « ignorer »
    + 'jete,u,nouveau\n'           // supprimé (suppression douce) : réimporté, comme avant
    + 'nouveau1,u,p1\n'
    + 'dossier/nouveau2,u,p2\n'
    + 'double,u,premier\n'
    + 'double,u,second\n';         // doublon dans le fichier : la 2e ligne est ignorée, comme avant

  function seedVault() {
    seed('kv', 'garde', { Username: 'u', Password: 'ancien' });
    seed('kv', 'jete', { Username: 'u', Password: 'ancien' }, { deleted: true });
  }
  function expectSkipResult(toasts) {
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 4 })]);
    expect(current('kv', 'garde').Password).toBe('ancien');
    expect(current('kv', 'jete').Password).toBe('nouveau');
    expect(current('kv', 'nouveau1').Password).toBe('p1');
    expect(current('kv', 'dossier/nouveau2').Password).toBe('p2');
    expect(current('kv', 'double').Password).toBe('premier');
  }

  test('mode « ignorer » : aucun GET pour les noms absents du listing', async () => {
    const E = addEngine('kv');
    seedVault();
    const toasts = await importVia(E, [E], 'f.csv', CSV);
    expectSkipResult(toasts);
    const reads = mockKv.calls.filter(c => c.kind === 'read').map(c => c.key);
    expect(reads.sort()).toEqual(['double', 'garde', 'jete']);
    expect(mockKv.calls.filter(c => c.kind === 'list').map(c => c.key).sort()).toEqual(['', 'dossier/']);
  });

  test('LIST refusé (403) : repli sur le GET par clé, même résultat', async () => {
    const E = addEngine('kv');
    seedVault();
    mockKv.listStatus = 403;
    const toasts = await importVia(E, [E], 'f.csv', CSV);
    expectSkipResult(toasts);
  });

  test('KV v1 : même résultat en mode « ignorer »', async () => {
    const E = addEngine('kv', 1);
    seed('kv', 'garde', { Username: 'u', Password: 'ancien' });
    const toasts = await importVia(E, [E], 'f.csv', 'Name,Password\ngarde,nouveau\nneuf,p\n');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 1 })]);
    expect(current('kv', 'garde').Password).toBe('ancien');
    expect(current('kv', 'neuf').Password).toBe('p');
    expect(mockKv.calls.filter(c => c.kind === 'read').map(c => c.key)).toEqual(['garde']);
  });

  test('mode « écraser » : les noms nouveaux sont écrits sans GET préalable', async () => {
    const E = addEngine('kv');
    seed('kv', 'garde', { Username: 'u', Password: 'ancien' });
    const toasts = await importVia(E, [E], 'f.csv', 'Name,Password\ngarde,nouveau\nneuf1,a\nneuf2,b\n', 'overwrite');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 3 })]);
    expect(current('kv', 'garde')).toEqual({ Username: 'u', Password: 'nouveau' });
    expect(mockKv.calls.filter(c => c.kind === 'read').map(c => c.key)).toEqual(['garde']);
  });
});

// ========================================
// Import : seule une 404 signifie « absente » (suite LOCALVAULT-3)
// ========================================
// Avant : toute erreur de lecture (500 « decryption failed », réseau, 403…) faisait considérer
// l'entrée comme absente : le mode « ignorer » l'ÉCRASAIT, le mode « écraser » la remplaçait sans
// fusion. Désormais l'entrée existante illisible n'est jamais écrite et la ligne est comptée en échec.
describe('import : entrée existante illisible', () => {
  test.each([
    ['skip', 500],
    ['overwrite', 500],
    ['skip', 'network'],
    ['skip', 403],
  ])('mode %s, lecture en échec (%s) : entrée existante intacte, ligne comptée en échec', async (mode, failure) => {
    const E = addEngine('kv');
    seed('kv', 'abimee', { Username: 'u', Password: 'ancien', Notes: 'codes de secours' });
    mockKv.readFail = { abimee: failure };
    const toasts = await importVia(E, [E], 'f.csv', 'Name,Password\nabimee,nouveau\nneuf,p\n', mode);
    expect(versionCount('kv', 'abimee')).toBe(1);
    expect(current('kv', 'abimee').Password).toBe('ancien');
    expect(current('kv', 'neuf').Password).toBe('p');
    expect(toasts[0]).toEqual(['warning', fmt(fr.export.importPartial, { count: 1, failed: 1 })]);
  });

  test('404 (entrée listée mais supprimée en douceur) : toujours considérée absente et réimportée', async () => {
    const E = addEngine('kv');
    seed('kv', 'jete', { Password: 'ancien' }, { deleted: true });
    const toasts = await importVia(E, [E], 'f.csv', 'Name,Password\njete,nouveau\n');
    expect(toasts[0]).toEqual(['success', fmt(fr.export.importSuccess, { count: 1 })]);
    expect(current('kv', 'jete').Password).toBe('nouveau');
  });
});
