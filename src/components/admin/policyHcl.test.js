// ========================================
// TESTS : HCL des policies du builder (fonctions pures)
// ========================================

import {
  generatePolicyHcl, parsePolicyHcl, policySignature, analyzePolicyForBuilder,
  totpPrefixCollisions, policyGrantsMount, totpPrefixFor,
} from './policyHcl';

const MOUNTS = [
  { path: 'A', type: 'kv', version: 2 },
  { path: 'B', type: 'kv', version: 2 },
  { path: 'L', type: 'kv', version: 1 },
  { path: 'users/alice/perso', type: 'kv', version: 2 },
  { path: 'users/alice/old', type: 'kv', version: 1 },
];
const LEVELS = ['read-only', 'rbi-only', 'read-write', 'moderator', 'full-admin'];
const rule = (o) => ({ type: 'coffre', coffre: '', secret: '', accessLevel: 'read-only', includeTotp: false, totpLevel: 'read-only', ...o });
const roundTrip = (paths, { allowListMounts = true, policyName = 'p' } = {}) => {
  const hcl = generatePolicyHcl({ paths, allowListMounts, allMounts: MOUNTS, ldapAuthPath: 'auth/ldap', policyName });
  const res = analyzePolicyForBuilder(hcl, { allMounts: MOUNTS, ldapAuthPath: 'auth/ldap', policyName });
  const again = generatePolicyHcl({ paths: res.paths, allowListMounts: res.allowListMounts, allMounts: MOUNTS, ldapAuthPath: 'auth/ldap', policyName });
  return { hcl, res, again };
};

describe('aller-retour génération → relecture → génération (HCL identique)', () => {
  const combos = [];
  for (const coffre of ['A', 'L', 'users/alice/perso', 'users/alice/old']) {
    for (const accessLevel of LEVELS) {
      for (const includeTotp of [false, true]) {
        for (const totpLevel of ['read-only', 'read-write']) {
          combos.push(rule({ coffre, accessLevel, includeTotp, totpLevel }));
          combos.push(rule({ type: 'secret', coffre, secret: 's1', accessLevel, includeTotp, totpLevel }));
        }
      }
    }
  }
  test.each(combos.map(c => [`${c.type} ${c.coffre} ${c.accessLevel} totp=${c.includeTotp}/${c.totpLevel}`, c]))('%s', (_label, c) => {
    for (const allowListMounts of [true, false]) {
      const { hcl, res, again } = roundTrip([c], { allowListMounts });
      expect(res.faithful).toBe(true);
      expect(again).toBe(hcl);
    }
  });

  test('plusieurs règles mêlées (ordre, listing par coffre, TOTP par secret)', () => {
    const paths = [
      rule({ coffre: 'A', accessLevel: 'rbi-only' }),
      rule({ coffre: 'B', accessLevel: 'read-only', includeTotp: true }),
      rule({ type: 'secret', coffre: 'B', secret: 's1', accessLevel: 'read-write', includeTotp: true, totpLevel: 'read-write' }),
      rule({ type: 'secret', coffre: 'B', secret: 's2', accessLevel: 'rbi-only' }),
      rule({ coffre: 'L', accessLevel: 'moderator', includeTotp: true, totpLevel: 'read-write' }),
      rule({ type: 'secret', coffre: 'A', secret: 'x', accessLevel: 'read-only' }),
    ];
    const { hcl, res, again } = roundTrip(paths);
    expect(res.faithful).toBe(true);
    expect(again).toBe(hcl);
    expect(res.paths.map(p => `${p.type}:${p.coffre}/${p.secret}:${p.accessLevel}`)).toEqual([
      'coffre:A/:rbi-only', 'coffre:B/:read-only', 'secret:B/s1:read-write', 'secret:B/s2:rbi-only',
      'coffre:L/:moderator', 'secret:A/x:read-only',
    ]);
  });

  test('« full-admin » sur un secret (même HCL que RW) : relu en RW, HCL identique', () => {
    const { hcl, res, again } = roundTrip([rule({ type: 'secret', coffre: 'A', secret: 's1', accessLevel: 'full-admin' })]);
    expect(res.faithful).toBe(true);
    expect(res.paths[0].accessLevel).toBe('read-write');
    expect(again).toBe(hcl);
  });
});

describe('policies non représentables : faithful = false', () => {
  const analyze = (hcl) => analyzePolicyForBuilder(hcl, { allMounts: MOUNTS, ldapAuthPath: 'auth/ldap', policyName: 'p' });

  test('chemin hors des coffres connus', () => {
    expect(analyze('path "A/data/*" { capabilities = ["read"] }\npath "A/metadata/*" { capabilities = ["list","read"] }\npath "secret/*" { capabilities = ["read"] }').faithful).toBe(false);
  });
  test('format JSON', () => {
    expect(analyze('{"path":{"A/data/*":{"capabilities":["read"]}}}').faithful).toBe(false);
  });
  test('paramètres de règle (allowed_parameters) ou bloc multi-ligne non standard', () => {
    expect(analyze('path "A/data/*" {\n  capabilities = ["read"]\n  allowed_parameters = { "x" = [] }\n}').faithful).toBe(false);
  });
  test('capacités différentes de celles du builder (ex. RO sans list sur metadata)', () => {
    expect(analyze('# KV v2 RO\npath "A/metadata/*" { capabilities = ["read"] }\npath "A/data/*"     { capabilities = ["read"] }').faithful).toBe(false);
  });
  test('bloc modérateur avec écriture système (ancien modèle documenté)', () => {
    const hcl = generatePolicyHcl({ paths: [rule({ coffre: 'A', accessLevel: 'moderator' })], allowListMounts: true, allMounts: MOUNTS })
      .replace('path "sys/policies/acl/*"   { capabilities = ["read","list"] }', 'path "sys/policies/acl/*"   { capabilities = ["read","create","update"] }');
    expect(analyze(hcl).faithful).toBe(false);
  });
  test('TOTP élargi à la main (TOTP/keys/A-* sur un coffre RO à TOTP en lecture)', () => {
    const hcl = generatePolicyHcl({ paths: [rule({ coffre: 'A', includeTotp: true })], allowListMounts: true, allMounts: MOUNTS })
      + 'path "TOTP/keys/A-*" { capabilities = ["read"] }\n';
    // Règle supplémentaire attachée à A → relu en « gestion complète » → droits différents
    expect(analyze(hcl).faithful).toBe(false);
  });
  test('contrôle : policy RO écrite à la main sous la forme du builder → relue fidèlement', () => {
    const hcl = '# KV v2 RO\npath "B/metadata/*" { capabilities = ["list","read"] }\npath "B/data/*"     { capabilities = ["read"] }\n';
    const res = analyze(hcl);
    expect(res.faithful).toBe(true);
    expect(res.paths[0].accessLevel).toBe('read-only');
  });
  test('policy vide', () => {
    expect(analyze('').faithful).toBe(false);
  });
});

describe('policySignature', () => {
  test('ignore commentaires, espaces et ordre ; fusionne les capacités d\'un même chemin', () => {
    const a = '# x\npath "A/data/*" { capabilities = ["read"] }\npath "A/data/*" { capabilities = ["list"] }';
    const b = 'path "A/data/*" {\n  capabilities = ["list", "read"]\n}\n# autre commentaire';
    expect(policySignature(a)).toBe(policySignature(b));
  });
  test('les marqueurs lus par l\'application font partie de la signature', () => {
    const ro = '# KV v2 RO\npath "A/metadata/*" { capabilities = ["list","read"] }';
    const rbi = '# RBI-ONLY\npath "A/metadata/*" { capabilities = ["list","read"] }';
    expect(policySignature(ro)).not.toBe(policySignature(rbi));
  });
  test('contenu non reconnu → null', () => {
    expect(policySignature('path "A/*" { capabilities = ["read"] }\nfoo = "bar"')).toBeNull();
    expect(policySignature('/* bloc */ path "A/*" { capabilities = ["read"] }')).toBeNull();
  });
});

test('parsePolicyHcl : préfixe TOTP exact (TOTP/keys/A-s1 ne fait pas du coffre A un TOTP RW)', () => {
  const hcl = generatePolicyHcl({
    paths: [
      rule({ coffre: 'A', includeTotp: true }),
      rule({ type: 'secret', coffre: 'A', secret: 's1', accessLevel: 'read-write', includeTotp: true, totpLevel: 'read-write' }),
    ],
    allowListMounts: false, allMounts: MOUNTS,
  });
  const { paths } = parsePolicyHcl(hcl, { allMounts: MOUNTS });
  expect(paths[0]).toMatchObject({ type: 'coffre', coffre: 'A', includeTotp: true, totpLevel: 'read-only' });
  expect(paths[1]).toMatchObject({ type: 'secret', coffre: 'A', secret: 's1', includeTotp: true, totpLevel: 'read-write' });
});

test('totpPrefixCollisions : préfixe englobant et coffres personnels homonymes', () => {
  const mounts = [
    { path: 'web', type: 'kv' }, { path: 'web-prod', type: 'kv' }, { path: 'webapp', type: 'kv' },
    { path: 'users/alice/perso', type: 'kv' }, { path: 'users/bob/perso', type: 'kv' }, { path: 'perso-2', type: 'kv' },
  ];
  expect(totpPrefixFor('users/alice/perso')).toBe('PERSO');
  expect(totpPrefixCollisions('web', mounts)).toEqual(['web-prod']);
  expect(totpPrefixCollisions('web-prod', mounts)).toEqual([]);
  expect(totpPrefixCollisions('users/alice/perso', mounts)).toEqual(['users/bob/perso', 'perso-2']);
});

describe('policyGrantsMount', () => {
  test.each([
    ['path "Compta/data/paie" { capabilities = ["read"] }', true],
    ['path "Compta/metadata" { capabilities = ["list"] }', true],
    ['path "Compta" { capabilities = ["list"] }', true],
    ['path "Compta/*" { capabilities = ["read"] }', true],
    ["path 'Compta/data/*' { capabilities = [\"read\"] }", true],
    ['path "*" { capabilities = ["read"] }', true],
    ['path "Comp*" { capabilities = ["read"] }', true],
    ['path "Compta/data/*" { capabilities = ["deny"] }', false],
    ['path "Comptabilite/data/*" { capabilities = ["read"] }', false],
    ['path "TOTP/code/COMPTA-*" { capabilities = ["read"] }', false],
    ['path "sys/*" { capabilities = ["read"] }', false],
  ])('%s → %s', (hcl, expected) => {
    expect(policyGrantsMount(hcl, 'Compta')).toBe(expected);
  });
});
