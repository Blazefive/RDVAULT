// ========================================
// UTILITAIRE : coffre des passkeys (secret interne « .rdvault-passkeys »)
// ========================================
// Partagé par le hook usePasskeys (requêtes de l'extension) et l'écran « Mes passkeys ».
//
// 1. Coffre personnel (PASSKEYS-16) : coffre dont le nom commence EXACTEMENT par
//    « users/<nom>/ », casse ignorée, sans assainissement du nom (« jean.dupont »,
//    « j.doe@corp.fr », « Élodie », « jean dupont »… sont des noms valides). Jamais de repli
//    vers le coffre d'un autre utilisateur ni vers le premier coffre venu : sans coffre
//    personnel, les passkeys sont indisponibles (création refusée, le navigateur prend le relais).
//    Compte du coffre local créé en 1.5.0 (nom enregistré encodé, ex. « jean.dupont%40exemple.fr ») :
//    coffre cherché aussi sous cette forme, si le serveur la confirme (COMPAT-1, voir personalEngines).
//
// 2. Compatibilité : l'ancien code assainissait le nom (« jean.dupont » → « jeandupont ») et se
//    rabattait sur le premier coffre « users/… » puis sur le premier coffre. Des passkeys ont pu
//    être écrites ailleurs que dans le coffre personnel. En LECTURE, si le coffre personnel n'a
//    pas encore de blob, l'emplacement que l'ancien algorithme aurait choisi est lu, uniquement
//    s'il appartient à l'utilisateur courant (jamais le coffre d'autrui). En ÉCRITURE, seul le
//    coffre personnel est écrit (le contenu hérité y est fusionné) ; l'ancien blob n'est jamais
//    supprimé. Format, nom de clé et chiffrement inchangés.
//
// 3. Concurrence (PASSKEYS-17) : toutes les lectures-modifications-écritures passent par une
//    file d'attente unique (module) ; en KV v2, l'écriture est conditionnelle (cas = version lue,
//    0 si le blob n'existe pas encore) et rejouée sur une relecture en cas de conflit (autre poste
//    connecté au même Vault). Le coffre local ignore l'option cas : la file suffit.
import axios from 'axios';
import { encodeEnginePath } from './security';

// Clé du secret interne qui agrège toutes les passkeys : masquée de l'affichage (useSecrets,
// isInternalSecretKey ci-dessous) et de la synchronisation d'autofill (readAllSecrets).
export const PASSKEY_SECRET_KEY = '.rdvault-passkeys';

// Témoin de clé caché du coffre local (electron/localVault/secretsService.js, KEYCHECK_SECRET_KEY)
export const KEYCHECK_SECRET_KEY = '.rdvault-keycheck';

/**
 * COMPAT-2 : secrets internes RÉSERVÉS, par nom EXACT à la racine du coffre (casse comprise, comme les
 * clés du coffre). Les autres noms commençant par « .rdvault » (« .rdvault », « .rdvault-notes »…)
 * sont des entrées utilisateur ordinaires : la 1.5.0 n'en réservait aucun, elles restent affichées.
 */
export const INTERNAL_SECRET_KEYS = Object.freeze([PASSKEY_SECRET_KEY, KEYCHECK_SECRET_KEY]);
export const isInternalSecretKey = (key) => INTERNAL_SECRET_KEYS.includes(String(key));

// Nombre maximal d'essais d'une écriture conditionnelle (KV v2) en conflit
const MAX_CAS_ATTEMPTS = 5;

// Minuscules ASCII uniquement : même règle que la colonne « username COLLATE NOCASE » du coffre local
const lowerAscii = (s) => String(s).replace(/[A-Z]/g, (c) => c.toLowerCase());

const engineList = (secretEngines) => (Array.isArray(secretEngines) ? secretEngines : [])
  .filter((e) => e && typeof e.name === 'string');

// Nom du compte tel que le SERVEUR l'a enregistré (lookup-self → entity_name), mémorisé par useAuth
// après la connexion ; même source que Sidebar, useContextMenus et EditEngineModal.
const CANONICAL_USER_STORAGE_KEY = 'vault-client.username';
function storedCanonicalUser() {
  try {
    return typeof localStorage === 'undefined' ? '' : (localStorage.getItem(CANONICAL_USER_STORAGE_KEY) || '');
  } catch {
    return '';
  }
}

// encodeURIComponent lève sur une moitié de paire UTF-16 isolée : aucun nom encodé dans ce cas
function encodedUserName(user) {
  try { return encodeURIComponent(user); } catch { return null; }
}

/**
 * Coffres appartenant à l'utilisateur : nom commençant par « users/<nom>/ ».
 * Casse ASCII ignorée (règle du coffre local) ; à défaut, casse Unicode ignorée si tous les
 * coffres trouvés appartiennent au même segment « users/<x>/ » (sinon ambigu → aucun).
 * Un nom vide ou contenant « / » ne désigne aucun coffre (jamais un sous-chemin d'un autre).
 *
 * COMPAT-1 (comptes du coffre local créés en 1.5.0) : l'ancien serveur ne décodait pas le segment
 * d'URL du nom ; « jean.dupont@exemple.fr » a été enregistré « jean.dupont%40exemple.fr » et son
 * coffre personnel créé sous « users/jean.dupont%40exemple.fr/Mes-Secrets ». Le serveur actuel
 * accepte toujours ce compte. Cette forme encodée est donc AUSSI cherchée (après la forme exacte,
 * prioritaire), mais seulement quand le serveur confirme que c'est le nom du compte connecté
 * (canonicalUser, par défaut le nom mémorisé par useAuth) : un compte enregistré sous le nom
 * décodé, un nom canonique absent ou sans rapport (entity_name de Vault, lookup-self en échec)
 * n'ouvrent jamais « users/<forme encodée>/ », qui serait alors le coffre d'un autre compte.
 * @param {Array} secretEngines
 * @param {string} authUser nom tapé à la connexion
 * @param {string} [canonicalUser] nom enregistré renvoyé par le serveur (défaut : localStorage)
 */
export function personalEngines(secretEngines, authUser, canonicalUser = storedCanonicalUser()) {
  const user = typeof authUser === 'string' ? authUser : '';
  if (!user || user.includes('/')) return [];
  const engines = engineList(secretEngines);
  const under = (fold, name) => {
    const prefix = fold('users/' + name + '/');
    return engines.filter((e) => fold(e.name).startsWith(prefix));
  };
  const ascii = under(lowerAscii, user);
  const encoded = encodedUserName(user);
  const confirmed = !!encoded && encoded !== user
    && typeof canonicalUser === 'string' && lowerAscii(canonicalUser) === lowerAscii(encoded);
  // Les deux formes réunies (préfixes distincts : aucun doublon), la forme exacte d'abord
  const mine = confirmed ? [...ascii, ...under(lowerAscii, encoded)] : ascii;
  if (mine.length) return mine;
  const unicode = under((s) => String(s).toLowerCase(), user);
  const owners = new Set(unicode.map((e) => e.name.split('/')[1]));
  return owners.size === 1 ? unicode : [];
}

/** Coffre personnel où vivent les passkeys (« Mes-Secrets » préféré, forme exacte d'abord), ou null */
export function findPersonalEngine(secretEngines, authUser, canonicalUser) {
  const mine = personalEngines(secretEngines, authUser, canonicalUser);
  return mine.find((e) => /mes-secrets/i.test(e.name)) || mine[0] || null;
}

/**
 * Coffre que l'ANCIEN algorithme (avant correction) aurait choisi — reproduit à l'identique,
 * utilisé uniquement pour relire les passkeys qu'il a pu écrire.
 */
export function legacyPasskeyEngine(secretEngines, authUser) {
  const engines = engineList(secretEngines);
  const u = (authUser || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
  const mine = engines.filter((e) => new RegExp('^users/' + u + '/', 'i').test(e.name));
  return mine.find((e) => /mes-secrets/i.test(e.name)) || mine[0]
    || engines.find((e) => /^users\//i.test(e.name)) || engines[0] || null;
}

/** Ancien emplacement à relire : seulement s'il diffère du coffre personnel ET appartient à l'utilisateur */
export function ownedLegacyEngine(secretEngines, authUser, canonicalUser) {
  const personal = findPersonalEngine(secretEngines, authUser, canonicalUser);
  const legacy = legacyPasskeyEngine(secretEngines, authUser);
  if (!personal || !legacy || legacy.name === personal.name) return null;
  return personalEngines(secretEngines, authUser, canonicalUser).some((e) => e.name === legacy.name) ? legacy : null;
}

// ---------- File d'attente unique des lectures-modifications-écritures ----------
let queue = Promise.resolve();
/** Exécute fn après toutes les opérations en cours ; un échec ne bloque pas les suivantes */
export function withPasskeyLock(fn) {
  const run = queue.then(() => fn());
  queue = run.catch(() => {});
  return run;
}

const validBlob = (data) => !!(data && typeof data === 'object' && data.items && typeof data.items === 'object');
const toVersion = (v) => (Number.isInteger(v) && v >= 0 ? v : null);
const isCasConflict = (err) => err?.response?.status === 400
  && /check-and-set/i.test(JSON.stringify(err.response.data?.errors || ''));

/**
 * Accès au blob des passkeys de l'utilisateur.
 * - engine : coffre personnel (null → passkeys indisponibles)
 * - read()  : { blob: { items }, version } (ancien emplacement relu si besoin, lecture seule)
 * - update(mutate) : sous la file d'attente ; mutate(blob) modifie le blob sur place et
 *   renvoie false s'il n'y a rien à écrire. Peut être rejouée (conflit CAS) : sans effet de bord.
 * canonicalUser (facultatif) : nom enregistré par le serveur (voir personalEngines, COMPAT-1) ;
 * absent → nom mémorisé par useAuth, lu à la création du store.
 */
export function createPasskeyStore({ vaultApi, vaultUrl, secretEngines, authUser, canonicalUser }) {
  const canonical = canonicalUser === undefined ? storedCanonicalUser() : canonicalUser;
  const engine = findPersonalEngine(secretEngines, authUser, canonical);
  const legacy = engine ? ownedLegacyEngine(secretEngines, authUser, canonical) : null;

  const blobUrl = (eng) => (eng.version === 2
    ? `${vaultUrl}/v1/${encodeEnginePath(eng.name)}/data/${encodeURIComponent(PASSKEY_SECRET_KEY)}`
    : `${vaultUrl}/v1/${encodeEnginePath(eng.name)}/${encodeURIComponent(PASSKEY_SECRET_KEY)}`);
  const config = () => vaultApi.axiosConfig({ headers: vaultApi.baseHeaders() });

  // { blob | null, version } ; version = version KV v2 courante (0 si absent), null si inconnue / KV v1
  const readFrom = async (eng) => {
    try {
      const res = await axios.get(blobUrl(eng), config());
      const data = eng.version === 2 ? res.data?.data?.data : res.data?.data;
      return { blob: validBlob(data) ? data : null, version: eng.version === 2 ? toVersion(res.data?.data?.metadata?.version) : null };
    } catch (err) {
      if (err.response?.status !== 404) throw err;
      // 404 : jamais écrit (version 0) ou dernière version supprimée (métadonnées jointes)
      const v = toVersion(err.response?.data?.data?.metadata?.version);
      return { blob: null, version: eng.version === 2 ? (v === null ? 0 : v) : null };
    }
  };

  const read = async () => {
    if (!engine) throw new Error('Aucun coffre personnel');
    const own = await readFrom(engine);
    if (own.blob) return { blob: own.blob, version: own.version };
    if (legacy) {
      // Erreur de lecture propagée : écrire sans le contenu hérité le masquerait définitivement
      const old = await readFrom(legacy);
      if (old.blob) return { blob: old.blob, version: own.version, legacy: true };
    }
    return { blob: { items: {} }, version: own.version };
  };

  const write = async (blob, version) => {
    const payload = engine.version === 2
      ? (version === null ? { data: blob } : { data: blob, options: { cas: version } })
      : blob;
    await axios.post(blobUrl(engine), payload, config());
  };

  const update = (mutate) => withPasskeyLock(async () => {
    if (!engine) throw new Error('Aucun coffre personnel');
    for (let attempt = 1; ; attempt++) {
      const cur = await read();
      if (mutate(cur.blob) === false) return;
      try {
        await write(cur.blob, cur.version);
        return;
      } catch (err) {
        if (!isCasConflict(err) || attempt >= MAX_CAS_ATTEMPTS) throw err;
      }
    }
  });

  return { engine, read, update };
}
