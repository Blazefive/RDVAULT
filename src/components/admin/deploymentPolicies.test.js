// ========================================
// TESTS : modèles de policies Vault documentés dans DEPLOYMENT.md (étape 7c)
// ========================================
// Les modèles sont copiés tels quels par les administrateurs : ils doivent respecter
// le moindre privilège et rester cohérents avec ce que l'application génère et détecte.
// - Aucune écriture sur les chemins de délégation (policies, auth, groupes, identity,
//   montage de coffres) pour un non-admin : écrire une policy ou un groupe = devenir root.
// - Aucun droit TOTP global (TOTP/keys/*, TOTP/code/*) : chemins délimités par préfixe.
// - Marqueur modérateur au format réellement reconnu (# KV v2 MODERATOR (Coffre)).
// - Modèles par coffre éditables à l'identique dans le builder (aller-retour fidèle).
// - Limite du niveau « RBI uniquement » documentée (restriction d'interface).

import fs from 'fs';
import path from 'path';
import { analyzePolicyForBuilder } from './policyHcl';

const md = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'DEPLOYMENT.md'), 'utf8').replace(/\r\n?/g, '\n');

// Corps HCL des « vault policy write <nom> - <<EOF … EOF » (heredoc quoté ou non)
const templates = Object.fromEntries(
  Array.from(md.matchAll(/vault policy write (\S+) - <<'?EOF'?\n([\s\S]*?)\nEOF/g), m => [m[1], m[2]])
);

const rulesOf = (hcl) => Array.from(
  hcl.matchAll(/path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}/g),
  m => ({ path: m[1], caps: m[2].split(',').map(c => c.trim().replace(/"/g, '')) })
);
const WRITE_CAPS = ['create', 'update', 'delete', 'sudo', 'patch'];

test('les modèles attendus sont présents', () => {
  expect(Object.keys(templates)).toEqual(expect.arrayContaining(['admin', 'self-service-ldap', 'moncoffre-rw', 'moncoffre-ro', 'moderateur', 'nouveaucoffre-rw']));
});

test('aucun modèle non-admin n\'écrit sur les chemins de délégation (escalade vers root)', () => {
  for (const [name, hcl] of Object.entries(templates)) {
    if (name === 'admin') continue;
    for (const { path: p, caps } of rulesOf(hcl)) {
      const writes = caps.some(c => WRITE_CAPS.includes(c));
      if (!writes) continue;
      const delegation = /^(sys\/policies|sys\/auth|identity\/|auth\/)/.test(p);
      // Seule exception : le self-service monte/démonte SES coffres (chemin délimité par son identité)
      const mounts = /^sys\/mounts/.test(p) && !/^sys\/mounts\/users\/\{\{identity\..+?\}\}(\/|$)/.test(p);
      expect([name, p, delegation || mounts]).toEqual([name, p, false]);
    }
  }
});

test('aucun droit TOTP global : chaque chemin TOTP est délimité par un préfixe de coffre', () => {
  for (const [name, hcl] of Object.entries(templates)) {
    if (name === 'admin') continue;
    for (const { path: p } of rulesOf(hcl)) {
      if (!p.startsWith('TOTP/')) continue;
      expect([name, p, /^TOTP\/(keys|code|validate)\/[A-Z0-9_.]+-(\*|[^*]+)$/.test(p)]).toEqual([name, p, true]);
    }
  }
  // Le self-service ne donne plus accès aux clés TOTP de tout le monde
  expect(rulesOf(templates['self-service-ldap']).filter(r => r.path.startsWith('TOTP/'))).toEqual([]);
});

test('modèle modérateur : marqueur reconnu par l\'application et lecture seule système', () => {
  const hcl = templates.moderateur;
  // Même expression que useAuth.js (détection du rôle modérateur)
  const engines = Array.from(hcl.matchAll(/# KV v[12] MODERATOR \(([^)]+)\)/g), m => m[1]);
  expect(engines).toEqual(['MonCoffre']);
  const rules = Object.fromEntries(rulesOf(hcl).map(r => [r.path, r.caps]));
  expect(rules['sys/policies/acl/*']).toEqual(['read', 'list']);
  expect(rules['sys/mounts/*']).toEqual(['read', 'list']);
  expect(rules['auth/ldap/groups/*']).toEqual(['read', 'list']);
});

test('modèles par coffre éditables à l\'identique dans le builder', () => {
  const allMounts = [
    { path: 'MonCoffre', type: 'kv', version: 2 },
    { path: 'NouveauCoffre', type: 'kv', version: 2 },
  ];
  for (const name of ['moncoffre-rw', 'moncoffre-ro', 'moderateur', 'nouveaucoffre-rw']) {
    const res = analyzePolicyForBuilder(templates[name], { allMounts, ldapAuthPath: 'auth/ldap', policyName: name });
    expect([name, res.faithful]).toEqual([name, true]);
  }
});

test('la limite du niveau « RBI uniquement » est documentée', () => {
  expect(md).toMatch(/RBI uniquement[\s\S]{0,300}restriction d'interface/);
  expect(md).toMatch(/mêmes droits Vault que « Lecture seule »/);
});
