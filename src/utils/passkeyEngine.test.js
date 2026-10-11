// ========================================
// TESTS : passkeyEngine — choix du coffre des passkeys et file d'attente des écritures
// ========================================
// PASSKEYS-16 : préfixe exact « users/<nom>/ » (casse ignorée, sans assainissement), aucun repli
// vers le coffre d'autrui ni vers le premier coffre ; ancien emplacement relu seulement s'il
// appartient à l'utilisateur. PASSKEYS-17 : withPasskeyLock exécute les opérations une à une.
import {
  findPersonalEngine, personalEngines, legacyPasskeyEngine, ownedLegacyEngine, withPasskeyLock, PASSKEY_SECRET_KEY,
} from './passkeyEngine';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));

const E = (...names) => names.map((name) => ({ name, version: 2 }));
const pick = (engines, user) => (findPersonalEngine(engines, user) || {}).name || null;

describe('findPersonalEngine (PASSKEYS-16)', () => {
  test('nom de clé du blob inchangé', () => {
    expect(PASSKEY_SECRET_KEY).toBe('.rdvault-passkeys');
  });

  test.each([
    ['jean.dupont'], ['j.doe@corp.fr'], ['Élodie'], ['jean dupont'], ['Иван'], ['o\'brien'], ['a+b'],
  ])('« %s » : son coffre, jamais celui d\'aaron (premier de la liste)', (user) => {
    expect(pick(E('users/aaron/Mes-Secrets', `users/${user}/Archive`, `users/${user}/Mes-Secrets`), user)).toBe(`users/${user}/Mes-Secrets`);
  });

  test('aucun coffre personnel : null (plus de repli vers un autre utilisateur ni vers le premier coffre)', () => {
    expect(pick(E('secret', 'users/alice/Perso'), 'jean.dupont')).toBeNull();
    expect(pick(E('secret'), 'bob')).toBeNull();
    expect(pick([], 'bob')).toBeNull();
    expect(pick(E('users/alice/Perso'), '')).toBeNull();
    expect(pick(E('users/alice/Perso'), undefined)).toBeNull();
  });

  test('préfixe exact : « jean » ne prend pas users/jean.dupont/, « jeandupont » ne prend pas users/jean.dupont/', () => {
    expect(pick(E('users/jean.dupont/Mes-Secrets'), 'jean')).toBeNull();
    expect(pick(E('users/jean.dupont/Mes-Secrets'), 'jeandupont')).toBeNull();
    expect(pick(E('users/jean.dupont/Mes-Secrets', 'users/jeandupont/Mes-Secrets'), 'jean.dupont')).toBe('users/jean.dupont/Mes-Secrets');
  });

  test('caractères spéciaux de regex pris littéralement (« . » ne vaut pas n\'importe quel caractère)', () => {
    expect(pick(E('users/jeanXdupont/Mes-Secrets'), 'jean.dupont')).toBeNull();
    expect(pick(E('users/a/Mes-Secrets'), '.*')).toBeNull();
  });

  test('casse ignorée (ASCII, comme le coffre local) ; « Mes-Secrets » préféré, sinon le premier', () => {
    expect(pick(E('users/alice/Archive', 'users/alice/Mes-Secrets'), 'ALICE')).toBe('users/alice/Mes-Secrets');
    expect(pick(E('users/Alice/Archive', 'users/Alice/Banque'), 'alice')).toBe('users/Alice/Archive');
  });

  test('casse Unicode ignorée seulement si un seul propriétaire correspond', () => {
    expect(pick(E('users/élodie/Mes-Secrets'), 'ÉLODIE')).toBe('users/élodie/Mes-Secrets');
    expect(pick(E('users/élodie/Mes-Secrets', 'users/Élodie/Mes-Secrets'), 'ÉLODIE')).toBe('users/Élodie/Mes-Secrets'); // « É » exact (ASCII ignoré)
    expect(pick(E('users/élodie/A', 'users/ÉLODIE/B'), 'Élodie')).toBe('users/ÉLODIE/B'); // même compte pour le coffre local (NOCASE)
    expect(pick(E('users/éé/A', 'users/ÉÉ/B'), 'éÉ')).toBeNull(); // deux propriétaires possibles : ambigu
  });

  test('nom contenant « / » : aucun coffre (jamais un sous-chemin du coffre d\'un autre)', () => {
    expect(personalEngines(E('users/alice/bob/Perso'), 'alice/bob')).toEqual([]);
  });

  test('noms déjà en [a-z0-9_-] : même choix que l\'ancien algorithme (comptes existants inchangés)', () => {
    const cases = [
      [E('users/alice/Archive', 'users/alice/Mes-Secrets', 'users/bob/Mes-Secrets'), 'alice'],
      [E('users/alice/Archive', 'users/alice/Banque'), 'alice'],
      [E('users/bob_2/Mes-Secrets', 'users/bob/Perso'), 'bob_2'],
      [E('users/x-y/Coffre'), 'X-Y'],
    ];
    for (const [engines, user] of cases) {
      expect(pick(engines, user)).toBe(legacyPasskeyEngine(engines, user).name);
      expect(ownedLegacyEngine(engines, user)).toBeNull();
    }
  });
});

describe('ownedLegacyEngine (compatibilité, lecture seule)', () => {
  test('ancien choix = coffre du même utilisateur (« Archive ») → relu', () => {
    const engines = E('users/jean.dupont/Archive', 'users/jean.dupont/Mes-Secrets');
    expect(legacyPasskeyEngine(engines, 'jean.dupont').name).toBe('users/jean.dupont/Archive');
    expect(ownedLegacyEngine(engines, 'jean.dupont').name).toBe('users/jean.dupont/Archive');
  });

  test('ancien choix = coffre d\'un autre utilisateur ou coffre partagé → jamais relu', () => {
    expect(ownedLegacyEngine(E('users/alice/Perso', 'users/jean.dupont/Mes-Secrets'), 'jean.dupont')).toBeNull();
    expect(ownedLegacyEngine(E('users/jeandupont/Mes-Secrets', 'users/jean.dupont/Mes-Secrets'), 'jean.dupont')).toBeNull();
    expect(ownedLegacyEngine(E('secret', 'users/élodie/Mes-Secrets'), 'élodie')).toBeNull();
  });

  test('pas de coffre personnel → rien (même si l\'ancien algorithme trouvait un coffre)', () => {
    expect(legacyPasskeyEngine(E('secret'), 'bob').name).toBe('secret');
    expect(ownedLegacyEngine(E('secret'), 'bob')).toBeNull();
  });
});

describe('withPasskeyLock (PASSKEYS-17)', () => {
  test('opérations exécutées une à une, dans l\'ordre ; un échec ne bloque pas la suite', async () => {
    const log = [];
    const op = (name, ms, fail) => withPasskeyLock(async () => {
      log.push('début ' + name);
      await new Promise((r) => setTimeout(r, ms));
      log.push('fin ' + name);
      if (fail) throw new Error(name);
      return name;
    });
    const results = await Promise.allSettled([op('a', 15), op('b', 1, true), op('c', 5)]);
    expect(log).toEqual(['début a', 'fin a', 'début b', 'fin b', 'début c', 'fin c']);
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'rejected', 'fulfilled']);
  });
});
