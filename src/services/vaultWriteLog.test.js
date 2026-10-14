// ========================================
// TESTS : journal des écritures (invalidation ciblée des listes gardées par coffre)
// ========================================
import {
  noteVaultWrite, vaultWriteSeq, vaultWritesSince, forgetVaultWrites, ensureVaultWriteObserver, trackVaultWrite,
  ALL_KEYS, READ_ONLY_REQUEST_FLAG,
} from './vaultWriteLog';

jest.mock('axios', () => {
  const handlers = [];
  const responseHandlers = [];
  return {
    __esModule: true,
    default: {
      get: jest.fn(), post: jest.fn(),
      // Fonction simple (et non jest.fn) : resetMocks de react-scripts n'efface pas son implémentation
      interceptors: {
        request: { handlers, use: (fn) => handlers.push(fn) - 1 },
        response: { handlers: responseHandlers, use: (ok, ko) => responseHandlers.push([ok, ko]) - 1 },
      },
    },
  };
});
// eslint-disable-next-line import/first
import axios from 'axios';

const V = 'http://127.0.0.1:8200';
const kv2 = { name: 'users/alice/Mes-Secrets', version: 2 };
const kv1 = { name: 'legacy', version: 1 };
const keysOf = (r) => (r === ALL_KEYS ? r : Array.from(r).sort());

test('lectures ignorées ; écritures KV v2 (data, delete, undelete, destroy, metadata) reconnues par coffre', () => {
  const since = vaultWriteSeq();
  noteVaultWrite('get', `${V}/v1/users/alice/Mes-Secrets/data/lu`);
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/data/banque`);
  noteVaultWrite('POST', `${V}/v1/users/alice/Mes-Secrets/delete/dossier%2Fvpn`);
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/undelete/a%20b`);
  noteVaultWrite('delete', `${V}/v1/users/alice/Mes-Secrets/metadata/d%C3%A9tail`);
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/destroy/x`);
  // Clé encodée segment par segment (panneau d'administration) : même entrée
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/data/dossier/ssh?x=1`);
  noteVaultWrite('post', `${V}/v1/autre/data/banque`);
  expect(keysOf(vaultWritesSince(kv2, since))).toEqual(['a b', 'banque', 'dossier/ssh', 'dossier/vpn', 'détail', 'x']);
  expect(keysOf(vaultWritesSince({ name: 'autre', version: 2 }, since))).toEqual(['banque']);
  // Rien depuis la dernière écriture
  expect(keysOf(vaultWritesSince(kv2, vaultWriteSeq()))).toEqual([]);
});

test('KV v1 : clé directe ; opération ou chemin inconnus, coffre supprimé / recréé, droits : tout est relu', () => {
  let since = vaultWriteSeq();
  noteVaultWrite('delete', `${V}/v1/legacy/vieux%2Fmot`);
  expect(keysOf(vaultWritesSince(kv1, since))).toEqual(['vieux/mot']);

  since = vaultWriteSeq();
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/config`);
  expect(vaultWritesSince(kv2, since)).toBe(ALL_KEYS);

  since = vaultWriteSeq();
  noteVaultWrite('delete', `${V}/v1/sys/mounts/users/alice/Mes-Secrets`);
  expect(vaultWritesSince(kv2, since)).toBe(ALL_KEYS);
  expect(keysOf(vaultWritesSince(kv1, since))).toEqual([]); // autre coffre : non concerné

  since = vaultWriteSeq();
  noteVaultWrite('put', `${V}/v1/sys/policies/acl/lecteurs`);
  expect(vaultWritesSince(kv1, since)).toBe(ALL_KEYS);

  since = vaultWriteSeq();
  noteVaultWrite('post', `${V}/v1/sys/capabilities-self`); // lecture en POST : sans effet
  noteVaultWrite('post', `${V}/v1/auth/ldap/login/alice`);
  noteVaultWrite('post', `${V}/v1/TOTP/keys/MES-SECRETS-banque`);
  expect(keysOf(vaultWritesSince(kv2, since))).toEqual([]);

  since = vaultWriteSeq();
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/data/%E0%A4%A`); // encodage invalide
  expect(vaultWritesSince(kv2, since)).toBe(ALL_KEYS);
});

test('journal dépassé ou oublié (fin de session) : relecture complète, jamais d\'entrée périmée gardée', () => {
  const since = vaultWriteSeq();
  for (let i = 0; i < 5001; i++) noteVaultWrite('post', `${V}/v1/autre/data/k${i}`);
  expect(vaultWritesSince(kv2, since)).toBe(ALL_KEYS);
  const recent = vaultWriteSeq();
  noteVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/data/n`);
  expect(keysOf(vaultWritesSince(kv2, recent))).toEqual(['n']);
  forgetVaultWrites();
  expect(vaultWritesSince(kv2, recent)).toBe(ALL_KEYS);
  expect(keysOf(vaultWritesSince(kv2, vaultWriteSeq()))).toEqual([]);
  expect(vaultWritesSince(null, 0)).toBe(ALL_KEYS);
});

test('intercepteur axios posé une seule fois : écritures de toute l\'interface notées, lectures groupées exclues', () => {
  ensureVaultWriteObserver();
  ensureVaultWriteObserver();
  const { handlers } = axios.interceptors.request;
  expect(handlers.filter(Boolean)).toHaveLength(1);
  const since = vaultWriteSeq();
  const config = { method: 'post', url: `${V}/v1/users/alice/Mes-Secrets/data/import` };
  expect(handlers[0](config)).toBe(config); // requête inchangée
  handlers[0]({ method: 'post', url: `${V}/v1/users/alice/Mes-Secrets/rdvault-batch-read`, [READ_ONLY_REQUEST_FLAG]: true });
  handlers[0]({ method: 'get', url: `${V}/v1/users/alice/Mes-Secrets/data/lu` });
  expect(handlers[0](null)).toBeNull(); // configuration inattendue : jamais d'exception
  expect(keysOf(vaultWritesSince(kv2, since))).toEqual(['import']);
});

test("écriture en vol pendant une lecture : notée de nouveau à la réponse — la lecture commencée entre-temps relira l'entrée", async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const write = trackVaultWrite('post', `${V}/v1/users/alice/Mes-Secrets/data/k`, () => pending);
  const readStart = vaultWriteSeq(); // lecture commencée pendant l'écriture (ancienne valeur possible)
  expect(keysOf(vaultWritesSince(kv2, readStart))).toEqual([]);
  release('ok');
  await expect(write).resolves.toBe('ok');
  expect(keysOf(vaultWritesSince(kv2, readStart))).toEqual(['k']);

  // Écriture en échec : notée aussi (prudence), l'erreur est propagée telle quelle
  const since = vaultWriteSeq();
  const boom = new Error('refus');
  await expect(trackVaultWrite('delete', `${V}/v1/legacy/x`, () => Promise.reject(boom))).rejects.toBe(boom);
  expect(keysOf(vaultWritesSince(kv1, since))).toEqual(['x']);
});

test("intercepteur de réponse : écriture notée à la réponse comme à l'erreur, réponse et erreur inchangées", async () => {
  ensureVaultWriteObserver();
  const [[onOk, onError]] = axios.interceptors.response.handlers;
  const since = vaultWriteSeq();
  const response = { status: 200, config: { method: 'post', url: `${V}/v1/users/alice/Mes-Secrets/data/r1` } };
  expect(onOk(response)).toBe(response);
  const err = Object.assign(new Error('403'), { config: { method: 'delete', url: `${V}/v1/users/alice/Mes-Secrets/metadata/r2` } });
  await expect(onError(err)).rejects.toBe(err);
  await expect(onError(new Error('sans configuration'))).rejects.toThrow('sans configuration');
  expect(onOk(undefined)).toBeUndefined();
  expect(keysOf(vaultWritesSince(kv2, since))).toEqual(['r1', 'r2']);
});
