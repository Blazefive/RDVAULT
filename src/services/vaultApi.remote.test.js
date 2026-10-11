// ========================================
// TESTS : vaultApi — Vault distant (vague E, cluster E3)
// ========================================
// REMOTE-1 : format réel de GET /v1/sys/internal/ui/mounts (Vault 2.1.2) : { data: { auth, secret: { 'kv/': … } } }
// REMOTE-8 : délai réseau de 30 s aussi sur les lectures / écritures / suppressions de migration
// Suites  : échec de listage d'un sous-dossier et dépassement de la borne signalés (plus de perte silencieuse) ;
//           erreurs de validation porteuses de codes traduisibles (clés SSH comprises).
import { createVaultApi, MAX_LIST_KEYS } from './vaultApi';
import { sanitizeErrorMessage } from '../utils/security';
import en from '../locales/en.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

// Réponse RÉELLE de Vault 2.1.2 pour un jeton sans droit sur sys/mounts (policy « coffre-nolist »),
// capturée par la chasse hunt3-remote-vault (champs non utilisés retirés)
const REAL_UI_MOUNTS = {
  request_id: '6e0ef4ea-b2c1-130e-ea0a-2a42e740023c',
  lease_id: '', renewable: false, lease_duration: 0,
  data: {
    auth: {
      'token/': { accessor: 'auth_token_cab1b2fa', description: 'token based credentials', local: false, options: null, type: 'token' },
    },
    secret: {
      'MonEquipe/': { accessor: 'kv_306a73bb', deprecation_status: 'supported', description: '', local: false, options: { version: '2' }, type: 'kv' },
      'cubbyhole/': { accessor: 'cubbyhole_b66bcfbc', description: 'per-token private secret storage', local: true, options: null, type: 'cubbyhole' },
      'identity/': { accessor: 'identity_0e9c21ea', description: 'identity store', local: false, options: null, type: 'identity' },
      'sys/': { accessor: 'system_b7a284ac', description: 'system endpoints used for control, policy and debugging', local: false, options: null, type: 'system' },
    },
  },
  wrap_info: null,
  warnings: ['Endpoint ignored these unrecognized parameters: [filter]'],
  auth: null,
  mount_type: '',
};

let api;
beforeEach(() => {
  axios.get.mockReset();
  axios.post.mockReset();
  axios.delete.mockReset();
  api = createVaultApi('https://vault.test', 'tok');
});

describe('REMOTE-1 : parseFromUiMounts lit le format réel de Vault', () => {
  test('réponse réelle (data.secret objet) → le coffre KV v2 est trouvé, cubbyhole/identity/sys écartés', () => {
    expect(api.parseFromUiMounts(REAL_UI_MOUNTS)).toEqual([{ name: 'MonEquipe', version: 2, source: 'ui' }]);
  });

  test('KV v1 et ancien type « generic » reconnus ; totp, pki et tags-shared toujours exclus', () => {
    const payload = { data: { secret: {
      'Equipe-v1/': { type: 'kv', options: { version: '1' } },
      'ancien/': { type: 'generic', options: null },
      'totp/': { type: 'totp' },
      'TOTP/': { type: 'kv', options: { version: '2' } },
      'pki/': { type: 'pki' },
      'tags-shared/': { type: 'kv', options: { version: '2' } },
      'transit/': { type: 'transit' },
    } } };
    expect(api.parseFromUiMounts(payload)).toEqual([
      { name: 'Equipe-v1', version: 1, source: 'ui' },
      { name: 'ancien', version: 1, source: 'ui' },
    ]);
  });

  test('format « plat » du coffre local toujours accepté', () => {
    const flat = { 'users/alice/Mes-Secrets/': { type: 'kv', description: '', options: { version: '2' }, accessor: 'kv_x' } };
    expect(api.parseFromUiMounts(flat)).toEqual([{ name: 'users/alice/Mes-Secrets', version: 2, source: 'ui' }]);
  });

  test('montage non KV au type connu, même avec une barre finale, n\'est plus pris pour un coffre KV v1', () => {
    expect(api.parseFromUiMounts({ 'cubbyhole/': { type: 'cubbyhole' }, 'secret/': { type: 'kv', options: { version: '2' } } }))
      .toEqual([{ name: 'secret', version: 2, source: 'ui' }]);
  });

  test('fetchEnginesRaw : utilisateur sans droit sur sys/mounts → le coffre est quand même découvert', async () => {
    axios.get.mockImplementation(async (url) => {
      if (url.includes('/v1/sys/internal/ui/mounts')) return { status: 200, data: REAL_UI_MOUNTS };
      if (url.endsWith('/v1/sys/mounts')) throw Object.assign(new Error('403'), { response: { status: 403, data: { errors: ['permission denied'] } } });
      if (url.includes('/v1/MonEquipe/metadata?list=true')) return { status: 200, data: { data: { keys: ['github'] } } };
      throw new Error('inattendu ' + url);
    });
    axios.post.mockResolvedValue({ status: 200, data: { data: { 'MonEquipe/data/*': ['read', 'list'] } } });
    const { engines } = await api.fetchEnginesRaw('tok');
    expect(engines.map(e => e.name)).toEqual(['MonEquipe']);
    expect(engines[0]).toMatchObject({ version: 2, canList: true, canWrite: false });
  });
});

describe('REMOTE-8 : délai réseau de 30 s sur les opérations de migration', () => {
  const engine2 = { name: 'kv', version: 2 };
  const engine1 = { name: 'kv1', version: 1 };

  test('readSecretForMigration (KV v2 et v1)', async () => {
    axios.get.mockResolvedValue({ data: { data: { data: { Password: 'x' } } } });
    await api.readSecretForMigration(engine2, 'a');
    await api.readSecretForMigration(engine1, 'a');
    expect(axios.get).toHaveBeenCalledTimes(2);
    for (const call of axios.get.mock.calls) {
      expect(call[1]).toMatchObject({ timeout: 30000, headers: { 'X-Vault-Token': 'tok' } });
    }
  });

  test('writeSecretToEngine (KV v2 et v1)', async () => {
    axios.post.mockResolvedValue({ status: 200 });
    expect(await api.writeSecretToEngine(engine2, 'a', { Password: 'x' })).toBe(true);
    expect(await api.writeSecretToEngine(engine1, 'a', { Password: 'x' })).toBe(true);
    for (const call of axios.post.mock.calls) {
      expect(call[2]).toMatchObject({ timeout: 30000, headers: { 'X-Vault-Token': 'tok' } });
    }
  });

  test('deleteSecretFromEngine (KV v2 et v1)', async () => {
    axios.delete.mockResolvedValue({ status: 204 });
    expect(await api.deleteSecretFromEngine(engine2, 'a')).toBe(true);
    expect(await api.deleteSecretFromEngine(engine1, 'a')).toBe(true);
    for (const call of axios.delete.mock.calls) {
      expect(call[1]).toMatchObject({ timeout: 30000, headers: { 'X-Vault-Token': 'tok' } });
    }
  });
});

describe('listKeysV2 : plus de perte silencieuse', () => {
  const engine = { name: 'kv', version: 2 };
  const listing = (tree) => async (url) => {
    const m = url.match(/\/metadata\/?(.*)\?list=true$/);
    const path = m ? decodeURIComponent(m[1] || '') : null;
    const entry = tree[path];
    if (entry instanceof Error) throw entry;
    if (!entry) throw Object.assign(new Error('404'), { response: { status: 404 } });
    return { data: { data: { keys: entry } } };
  };

  test('sous-dossiers listés récursivement', async () => {
    axios.get.mockImplementation(listing({ '': ['a', 'dossier/'], 'dossier/': ['b', 'sous/'], 'dossier/sous/': ['c'] }));
    await expect(api.listKeysV2(engine)).resolves.toEqual(['a', 'dossier/b', 'dossier/sous/c']);
  });

  test('échec réseau / serveur sur un sous-dossier : l\'erreur remonte (l\'appelant la signale et relance)', async () => {
    const netErr = Object.assign(new Error('timeout of 30000ms exceeded'), { code: 'ECONNABORTED' });
    axios.get.mockImplementation(listing({ '': ['a', 'dossier/'], 'dossier/': netErr }));
    await expect(api.listKeysV2(engine)).rejects.toBe(netErr);
    const err500 = Object.assign(new Error('500'), { response: { status: 500 } });
    axios.get.mockImplementation(listing({ '': ['a', 'dossier/'], 'dossier/': err500 }));
    await expect(api.listKeysV2(engine)).rejects.toBe(err500);
  });

  test('sous-dossier interdit (403, policy par dossier) ou disparu (404) : ignoré comme avant', async () => {
    const forbidden = Object.assign(new Error('403'), { response: { status: 403 } });
    axios.get.mockImplementation(listing({ '': ['a', 'prive/', 'parti/'], 'prive/': forbidden }));
    await expect(api.listKeysV2(engine)).resolves.toEqual(['a']);
  });

  test('plus de 5 000 entrées : liste complète (l\'ancienne borne tronquait en silence)', async () => {
    const keys = Array.from({ length: 6000 }, (_, i) => `e${i}`);
    axios.get.mockImplementation(listing({ '': keys }));
    const listed = await api.listKeysV2(engine);
    expect(listed).toHaveLength(6000);
  });

  test('au-delà de la borne : erreur traduite LIST_TOO_LARGE (avec les clés déjà listées), jamais de troncature muette', async () => {
    const perFolder = Array.from({ length: 9000 }, (_, i) => `e${i}`);
    axios.get.mockImplementation(listing({ '': ['d1/', 'd2/', 'd3/'], 'd1/': perFolder, 'd2/': perFolder, 'd3/': perFolder }));
    let caught = null;
    try { await api.listKeysV2(engine); } catch (err) { caught = err; }
    expect(caught).not.toBeNull();
    expect(caught.code).toBe('LIST_TOO_LARGE');
    expect(caught.i18nKey).toBe('error.listTooLarge');
    expect(Array.isArray(caught.partialKeys)).toBe(true);
    expect(caught.partialKeys.length).toBe(MAX_LIST_KEYS);
    expect(sanitizeErrorMessage(caught, undefined, (k, v) => (k === 'error.listTooLarge' ? `trop:${v.max}` : k))).toBe(`trop:${MAX_LIST_KEYS}`);
  });

  test('profondeur excessive : erreur LIST_TOO_DEEP au lieu d\'un dossier ignoré en silence', async () => {
    const tree = { '': ['n/'] };
    let p = 'n/';
    for (let i = 0; i < 25; i++) { tree[p] = ['n/']; p += 'n/'; }
    axios.get.mockImplementation(listing(tree));
    await expect(api.listKeysV2(engine)).rejects.toMatchObject({ code: 'LIST_TOO_DEEP', i18nKey: 'error.listTooDeep' });
  });
});

describe('Validation avant écriture : codes traduisibles', () => {
  const sshEntry = (over = {}) => ({ name: 'srv', username: '', password: '-----BEGIN KEY-----\nabc\n-----END KEY-----\n', url: 'ssh-ed25519 AAAA', notes: '', entryType: 'ssh', ...over });
  const tEn = (key, vars) => {
    const raw = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
    return typeof raw === 'string' ? raw.replace(/\{\{(\w+)\}\}/g, (_, n) => String(vars?.[n] ?? '')) : key;
  };

  test('clé privée trop longue : code privateKeyTooLong, message anglais via sanitizeErrorMessage', async () => {
    let caught;
    try { await api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ password: 'A'.repeat(20000) })); } catch (err) { caught = err; }
    expect(caught.code).toBe('VALIDATION');
    expect(caught.validationErrors).toEqual([{ field: 'password', code: 'privateKeyTooLong', params: { max: 16384 } }]);
    expect(caught.message).toMatch(/^Validation échouée/); // texte historique conservé pour les journaux
    expect(sanitizeErrorMessage(caught, undefined, tEn)).toBe('The private key is too long (max 16384 characters)');
  });

  test('clé publique avec caractère de contrôle : code publicKeyControlChars', async () => {
    let caught;
    try { await api.writeSecretV1({ name: 'kv1', version: 1 }, sshEntry({ url: 'ssh-ed25519 A\u001b[31m' })); } catch (err) { caught = err; }
    expect(caught.validationErrors).toEqual([{ field: 'url', code: 'publicKeyControlChars' }]);
    expect(sanitizeErrorMessage(caught, undefined, tEn)).toBe('The public key contains control characters');
  });

  test('entrée classique : URL refusée → urlInvalid ; notes trop longues → error.notesTooLong', async () => {
    let caught;
    try { await api.writeSecretV2({ name: 'kv', version: 2 }, { name: 'a', password: 'x', url: ['javascript', 'alert(1)'].join(':'), notes: '' }); } catch (err) { caught = err; }
    expect(caught.validationErrors).toEqual([{ field: 'url', code: 'urlInvalid' }]);
    expect(sanitizeErrorMessage(caught, undefined, tEn)).toBe(en.validation.urlInvalid);
    caught = null;
    try { await api.writeSecretV2({ name: 'kv', version: 2 }, { name: 'a', notes: 'n'.repeat(10001) }); } catch (err) { caught = err; }
    expect(caught.validationErrors).toEqual([{ field: 'notes', code: 'notesTooLong', params: { max: 10000 } }]);
    expect(sanitizeErrorMessage(caught, undefined, tEn)).toBe(en.error.notesTooLong);
    expect(axios.post).not.toHaveBeenCalled();
  });
});
