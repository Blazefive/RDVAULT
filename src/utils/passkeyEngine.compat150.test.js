// ========================================
// TESTS : passkeyEngine — compatibilité des comptes du coffre local 1.5.0 (COMPAT-1)
// ========================================
// Le serveur 1.5.0 ne décodait pas le segment d'URL du nom d'utilisateur : un compte tapé
// « jean.dupont@exemple.fr » a été enregistré « jean.dupont%40exemple.fr » et son coffre personnel
// créé sous « users/jean.dupont%40exemple.fr/Mes-Secrets ». Le serveur actuel accepte toujours ce
// compte (repli sur la forme brute), et lookup-self renvoie le nom ENREGISTRÉ, que useAuth mémorise
// dans localStorage « vault-client.username ». Avant : seul « users/<nom tapé>/ » était cherché →
// « Aucun coffre personnel », passkeys indisponibles et écran « Mes passkeys » vide.
// Attendu : coffre personnel trouvé sous ses deux formes (décodée et encodée), la forme encodée
// seulement quand le serveur confirme que c'est le nom du compte — jamais le coffre d'un autre.
import {
  findPersonalEngine, personalEngines, ownedLegacyEngine, createPasskeyStore, PASSKEY_SECRET_KEY,
} from './passkeyEngine';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

const E = (...names) => names.map((name) => ({ name, version: 2 }));
const pick = (engines, user, canonical) => (findPersonalEngine(engines, user, canonical) || {}).name || null;

const AROBASE = 'jean.dupont@exemple.fr';
const AROBASE_STORED = 'jean.dupont%40exemple.fr';
const ACCENT = 'Élodie Martin';
const ACCENT_STORED = '%C3%89lodie%20Martin';

afterEach(() => {
  localStorage.clear();
  jest.clearAllMocks();
});

describe('COMPAT-1 — coffre personnel d\'un compte 1.5.0 enregistré sous forme encodée', () => {
  test.each([
    [AROBASE, AROBASE_STORED],
    [ACCENT, ACCENT_STORED],
    ['a+b c', 'a%2Bb%20c'],
  ])('« %s » (enregistré « %s ») : son coffre encodé est trouvé', (user, stored) => {
    const engines = E('users/aaron/Mes-Secrets', `users/${stored}/Archive`, `users/${stored}/Mes-Secrets`);
    expect(pick(engines, user, stored)).toBe(`users/${stored}/Mes-Secrets`);
  });

  test('nom canonique lu par défaut dans localStorage « vault-client.username » (posé par useAuth)', () => {
    const engines = E(`users/${AROBASE_STORED}/Mes-Secrets`);
    expect(pick(engines, AROBASE)).toBeNull(); // pas encore de nom canonique : aucune supposition
    localStorage.setItem('vault-client.username', AROBASE_STORED);
    expect(pick(engines, AROBASE)).toBe(`users/${AROBASE_STORED}/Mes-Secrets`);
    expect(personalEngines(engines, AROBASE).map((e) => e.name)).toEqual([`users/${AROBASE_STORED}/Mes-Secrets`]);
  });

  test('casse ASCII ignorée (colonne username NOCASE) : nom tapé et nom enregistré de casses différentes', () => {
    const engines = E(`users/${AROBASE_STORED}/Mes-Secrets`);
    expect(pick(engines, 'Jean.Dupont@Exemple.FR', AROBASE_STORED)).toBe(`users/${AROBASE_STORED}/Mes-Secrets`);
    expect(pick(E(`users/${ACCENT_STORED}/Mes-Secrets`), 'Élodie MARTIN', '%C3%89lodie%20martin')).toBe(`users/${ACCENT_STORED}/Mes-Secrets`);
  });

  test('les deux formes réunies : « Mes-Secrets » encodé préféré à un autre coffre décodé', () => {
    const engines = E(`users/${AROBASE}/Perso`, `users/${AROBASE_STORED}/Mes-Secrets`);
    expect(personalEngines(engines, AROBASE, AROBASE_STORED).map((e) => e.name))
      .toEqual([`users/${AROBASE}/Perso`, `users/${AROBASE_STORED}/Mes-Secrets`]);
    expect(pick(engines, AROBASE, AROBASE_STORED)).toBe(`users/${AROBASE_STORED}/Mes-Secrets`);
  });

  test('forme exacte prioritaire quand les deux « Mes-Secrets » existent', () => {
    const engines = E(`users/${AROBASE_STORED}/Mes-Secrets`, `users/${AROBASE}/Mes-Secrets`);
    expect(pick(engines, AROBASE, AROBASE_STORED)).toBe(`users/${AROBASE}/Mes-Secrets`);
  });

  test('jamais le coffre d\'un autre : forme encodée ignorée si le serveur ne la confirme pas', () => {
    const engines = E(`users/${AROBASE_STORED}/Mes-Secrets`, 'users/aaron/Mes-Secrets');
    // Compte enregistré sous le nom décodé (créé par la version actuelle) : « users/jean.dupont%40… » est à autrui
    expect(pick(engines, AROBASE, AROBASE)).toBeNull();
    // Mode Vault : entity_name sans rapport avec le nom tapé
    expect(pick(engines, AROBASE, 'entity_5f1c2a')).toBeNull();
    // lookup-self en échec (useAuth mémorise alors le nom tapé) ou nom absent
    expect(pick(engines, AROBASE, '')).toBeNull();
    expect(pick(engines, AROBASE, null)).toBeNull();
    // Nom canonique d'un autre compte encodé
    expect(pick(E('users/bob%40x.fr/Mes-Secrets'), AROBASE, 'bob%40x.fr')).toBeNull();
    // Double encodage : jamais pris pour le nom simplement encodé
    expect(pick(E('users/jean.dupont%2540exemple.fr/Mes-Secrets'), AROBASE, AROBASE_STORED)).toBeNull();
  });

  test('préfixe exact sur la forme encodée : « jean.dupont%40exemple.fr » ne prend pas « …fr.old/ »', () => {
    expect(pick(E(`users/${AROBASE_STORED}.old/Mes-Secrets`), AROBASE, AROBASE_STORED)).toBeNull();
  });

  test('nom sans caractère encodé (« alice », « jean.dupont ») : comportement inchangé', () => {
    const engines = E('users/alice/Mes-Secrets', 'users/jean.dupont/Mes-Secrets', 'users/bob/Perso');
    expect(pick(engines, 'alice', 'alice')).toBe('users/alice/Mes-Secrets');
    expect(pick(engines, 'jean.dupont', 'jean.dupont')).toBe('users/jean.dupont/Mes-Secrets');
    expect(pick(engines, 'carol', 'carol')).toBeNull();
  });

  test('nom contenant une moitié de paire UTF-16 (encodeURIComponent lèverait) : aucune exception, aucun coffre', () => {
    expect(() => personalEngines(E('users/x/Mes-Secrets'), 'a\uD800b', 'a%ED%A0%80b')).not.toThrow();
    expect(personalEngines(E('users/x/Mes-Secrets'), 'a\uD800b', 'a%ED%A0%80b')).toEqual([]);
  });

  test('ancien emplacement : jamais relu chez un autre utilisateur (aaron, premier coffre « users/ »)', () => {
    const engines = E('users/aaron/Mes-Secrets', `users/${AROBASE_STORED}/Mes-Secrets`);
    expect(ownedLegacyEngine(engines, AROBASE, AROBASE_STORED)).toBeNull();
  });
});

describe('COMPAT-1 — createPasskeyStore sur le coffre encodé', () => {
  const vaultApi = { axiosConfig: (c) => c, baseHeaders: () => ({ 'X-Vault-Token': 'tok' }) };
  const VAULT = 'http://127.0.0.1:1';

  test('lecture et écriture du blob dans users/jean.dupont%40exemple.fr/Mes-Secrets (chemin encodé une fois de plus)', async () => {
    localStorage.setItem('vault-client.username', AROBASE_STORED);
    const engines = E('users/aaron/Mes-Secrets', `users/${AROBASE_STORED}/Mes-Secrets`);
    const blob = { items: { 'site.fr': [{ credentialId: 'Y3JlZA', rpId: 'site.fr', signCount: 0 }] } };
    axios.get.mockResolvedValue({ data: { data: { data: blob, metadata: { version: 3 } } } });
    axios.post.mockResolvedValue({ data: {} });

    const store = createPasskeyStore({ vaultApi, vaultUrl: VAULT, secretEngines: engines, authUser: AROBASE });
    expect(store.engine.name).toBe(`users/${AROBASE_STORED}/Mes-Secrets`);
    const r = await store.read();
    expect(r.blob).toEqual(blob);
    const url = `${VAULT}/v1/users/jean.dupont%2540exemple.fr/Mes-Secrets/data/${encodeURIComponent(PASSKEY_SECRET_KEY)}`;
    expect(axios.get).toHaveBeenCalledWith(url, expect.anything());

    await store.update((b) => { b.items['autre.fr'] = []; });
    expect(axios.post).toHaveBeenCalledWith(url, { data: { items: { ...blob.items, 'autre.fr': [] } }, options: { cas: 3 } }, expect.anything());
    // Jamais le coffre d'aaron
    expect(axios.get.mock.calls.some(([u]) => u.includes('/aaron/'))).toBe(false);
  });

  test('nom canonique passé explicitement (prioritaire sur localStorage)', () => {
    localStorage.setItem('vault-client.username', 'quelqu-un');
    const engines = E(`users/${ACCENT_STORED}/Mes-Secrets`);
    const store = createPasskeyStore({ vaultApi, vaultUrl: VAULT, secretEngines: engines, authUser: ACCENT, canonicalUser: ACCENT_STORED });
    expect(store.engine.name).toBe(`users/${ACCENT_STORED}/Mes-Secrets`);
  });

  test('sans confirmation du serveur : passkeys indisponibles comme avant (aucune requête)', async () => {
    const engines = E(`users/${AROBASE_STORED}/Mes-Secrets`);
    const store = createPasskeyStore({ vaultApi, vaultUrl: VAULT, secretEngines: engines, authUser: AROBASE });
    expect(store.engine).toBeNull();
    await expect(store.read()).rejects.toThrow('Aucun coffre personnel');
    expect(axios.get).not.toHaveBeenCalled();
  });
});
