// ========================================
// HCL des policies du panneau admin (fonctions pures, testables sans React)
// ========================================
// - generatePolicyHcl : génération du HCL du builder (code déplacé tel quel depuis
//   PolicyBuilderModal : le HCL produit est strictement identique à l'existant).
// - parsePolicyHcl : relecture d'un HCL en règles du builder.
// - policySignature / analyzePolicyForBuilder : garantie d'aller-retour fidèle.
//   « Modifier » puis « Sauvegarder » sans changement ne doit JAMAIS modifier les
//   droits d'une policy. On compare donc la sémantique de la policy d'origine
//   (règles path → capacités + marqueurs lus par l'application) avec celle du HCL
//   régénéré depuis les règles relues ; si elles diffèrent, le builder refuse
//   d'éditer la policy (édition HCL brute uniquement).
// - totpPrefixCollisions : coffres dont les clés TOTP tombent sous le préfixe d'un autre.
// - policyGrantsMount : la policy contient-elle une règle touchant un coffre ?

// SÉCURITÉ: Échappement des métacaractères regex pour éviter le ReDoS
export const escapeRegex = (str) => String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Préfixe des clés TOTP d'un coffre : nom sans « users/<nom>/ », en majuscules.
// Même règle que useTotp.getTotpKeyName et l'extension (format de stockage existant,
// à ne pas modifier : les clés TOTP déjà créées doivent rester lisibles).
export const totpPrefixFor = (coffre) => String(coffre || '')
  .replace(/^users\/[^/]+\//i, '')
  .replace(/\/$/, '')
  .toUpperCase();

/**
 * Génère le HCL d'une policy à partir des règles du builder.
 * @param {Object} o
 * @param {Array} o.paths - règles { type, coffre, secret, accessLevel, includeTotp, totpLevel }
 * @param {boolean} o.allowListMounts - ajouter le listing des coffres (sys/mounts)
 * @param {Array} o.allMounts - coffres connus { path, type, version }
 * @param {string} [o.ldapAuthPath] - chemin de l'auth LDAP (bloc modérateur)
 * @param {string} [o.policyName] - nom de la policy (lecture de sa propre policy si RBI)
 */
export function generatePolicyHcl({ paths = [], allowListMounts = false, allMounts = [], ldapAuthPath = 'auth/ldap', policyName = '' }) {
  let hcl = '# Policy générée par le builder\n\n';
  const addedMetadataList = new Set();

  // Ajouter le listing des coffres si demandé
  if (allowListMounts) {
    hcl += '# Lister tous les coffres\n';
    hcl += 'path "sys/mounts"   { capabilities = ["read","list"] }\n';
    hcl += 'path "sys/mounts/*" { capabilities = ["read","list"] }\n\n';
  }

  paths.forEach(rawPath => {
    if (!rawPath.coffre) return; // Skip si pas de coffre sélectionné

    // SÉCURITÉ: Sanitiser le nom du coffre pour éviter l'injection HCL
    // Rejeter les caractères dangereux (newlines, quotes, backslashes)
    const safeCoffre = rawPath.coffre.replace(/[\r\n"\\*+]/g, '');
    if (safeCoffre !== rawPath.coffre || !safeCoffre) return;
    // Ne pas muter l'état React : travailler sur une copie
    const p = { ...rawPath, coffre: safeCoffre };

    const mount = allMounts.find(m => m.path === p.coffre);
    if (!mount) return;

    const coffreName = totpPrefixFor(p.coffre);

    if (p.type === 'coffre') {
      // Accès au coffre entier
      if (mount.version === 2) {
        // KV v2
        if (p.accessLevel === 'rbi-only') {
          hcl += `# RBI-ONLY\n`;
          hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read"] }\n`;
          hcl += `path "${p.coffre}/data/*"     { capabilities = ["read"] }\n\n`;
        } else if (p.accessLevel === 'read-only') {
          hcl += `# KV v2 RO\n`;
          hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read"] }\n`;
          hcl += `path "${p.coffre}/data/*"     { capabilities = ["read"] }\n\n`;
        } else if (p.accessLevel === 'read-write') {
          hcl += `# KV v2 RW complet\n`;
          hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read","delete"] }\n`;
          hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","update","read","delete","list"] }\n`;
          hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update"] }\n`;
          hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update"] }\n`;
          hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update"] }\n\n`;
        } else if (p.accessLevel === 'moderator') {
          hcl += `# KV v2 MODERATOR (${p.coffre})\n`;
          hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read","delete"] }\n`;
          hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","update","read","delete","list"] }\n`;
          hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update"] }\n`;
          hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update"] }\n`;
          hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update"] }\n\n`;
        } else if (p.accessLevel === 'full-admin') {
          hcl += `# KV v2 Full Admin\n`;
          hcl += `path "${p.coffre}/metadata/*" { capabilities = ["create","read","update","delete","list","sudo"] }\n`;
          hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","read","update","delete","list","sudo"] }\n`;
          hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update","sudo"] }\n`;
          hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update","sudo"] }\n`;
          hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update","sudo"] }\n\n`;
        }
      } else {
        // KV v1
        if (p.accessLevel === 'rbi-only') {
          hcl += `# RBI-ONLY\n`;
          hcl += `path "${p.coffre}/*" { capabilities = ["read","list"] }\n\n`;
        } else if (p.accessLevel === 'read-only') {
          hcl += `# KV v1 RO\n`;
          hcl += `path "${p.coffre}/*" { capabilities = ["read","list"] }\n\n`;
        } else if (p.accessLevel === 'read-write') {
          hcl += `# KV v1 RW\n`;
          hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list"] }\n\n`;
        } else if (p.accessLevel === 'moderator') {
          hcl += `# KV v1 MODERATOR (${p.coffre})\n`;
          hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list"] }\n\n`;
        } else if (p.accessLevel === 'full-admin') {
          hcl += `# KV v1 Full Admin\n`;
          hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list","sudo"] }\n\n`;
        }
      }

      // Ajouter TOTP si demandé OU si RBI-only (nécessaire pour l'injection automatique en session sécurisée)
      if (p.includeTotp || p.accessLevel === 'rbi-only') {
        hcl += `# TOTP (${coffreName}-*)\n`;
        if (p.totpLevel === 'read-only' || p.accessLevel === 'rbi-only') {
          hcl += `path "TOTP/code/${coffreName}-*"     { capabilities = ["read"] }\n`;
          hcl += `path "TOTP/validate/${coffreName}-*" { capabilities = ["update"] }\n\n`;
        } else {
          hcl += `path "TOTP/keys/${coffreName}-*"     { capabilities = ["create","update","read","delete"] }\n`;
          hcl += `path "TOTP/code/${coffreName}-*"     { capabilities = ["read"] }\n`;
          hcl += `path "TOTP/validate/${coffreName}-*" { capabilities = ["update"] }\n\n`;
        }
      }
    } else if (p.type === 'secret' && p.secret) {
      // Accès à un secret spécifique
      let secretName = p.secret.replace(/\/$/, '');
      // SÉCURITÉ: Sanitiser le nom du secret pour éviter l'injection HCL
      secretName = secretName.replace(/[\r\n"\\*+]/g, '');
      if (!secretName) return;
      if (mount.version === 2) {
        // Listing du coffre nécessaire pour que l'app puisse énumérer les secrets
        if (!addedMetadataList.has(p.coffre)) {
          hcl += `# Listing secrets du coffre ${p.coffre}\n`;
          hcl += `path "${p.coffre}/metadata" { capabilities = ["list"] }\n\n`;
          addedMetadataList.add(p.coffre);
        }
        if (p.accessLevel === 'rbi-only') {
          hcl += `# RBI-ONLY\n`;
          hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RBI-ONLY)\n`;
          hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read"] }\n`;
          hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["read"] }\n\n`;
        } else if (p.accessLevel === 'read-only') {
          hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RO)\n`;
          hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read"] }\n`;
          hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["read"] }\n\n`;
        } else {
          hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RW)\n`;
          hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read","delete"] }\n`;
          hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["create","update","read","delete"] }\n\n`;
        }
      } else {
        // KV v1 : listing du coffre
        if (!addedMetadataList.has(p.coffre)) {
          hcl += `# Listing secrets du coffre ${p.coffre}\n`;
          hcl += `path "${p.coffre}" { capabilities = ["list"] }\n\n`;
          addedMetadataList.add(p.coffre);
        }
        if (p.accessLevel === 'rbi-only') {
          hcl += `# RBI-ONLY\n`;
          hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RBI-ONLY)\n`;
          hcl += `path "${p.coffre}/${secretName}" { capabilities = ["read"] }\n\n`;
        } else if (p.accessLevel === 'read-only') {
          hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RO)\n`;
          hcl += `path "${p.coffre}/${secretName}" { capabilities = ["read"] }\n\n`;
        } else {
          hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RW)\n`;
          hcl += `path "${p.coffre}/${secretName}" { capabilities = ["create","read","update","delete"] }\n\n`;
        }
      }

      // Ajouter TOTP pour secret spécifique
      if (p.includeTotp || p.accessLevel === 'rbi-only') {
        const sName = p.secret.replace(/\/$/, '').replace(/[\r\n"\\*+]/g, '');
        if (!sName) return;
        hcl += `# TOTP (${coffreName}-${sName})\n`;
        if (p.totpLevel === 'read-only' || p.accessLevel === 'rbi-only') {
          hcl += `path "TOTP/code/${coffreName}-${sName}"     { capabilities = ["read"] }\n`;
          hcl += `path "TOTP/validate/${coffreName}-${sName}" { capabilities = ["update"] }\n\n`;
        } else {
          hcl += `path "TOTP/keys/${coffreName}-${sName}"     { capabilities = ["create","update","read","delete"] }\n`;
          hcl += `path "TOTP/code/${coffreName}-${sName}"     { capabilities = ["read"] }\n`;
          hcl += `path "TOTP/validate/${coffreName}-${sName}" { capabilities = ["update"] }\n\n`;
        }
      }
    }
  });

  // Si au moins un path a le niveau "moderator", ajouter les permissions de lecture des policies et mounts
  const hasModerator = paths.some(p => p.accessLevel === 'moderator');
  if (hasModerator) {
    // SÉCURITÉ : un modérateur n'a que des droits de LECTURE (read/list) sur les
    // chemins système (policies, mounts, groupes AD). Toute écriture sur ces
    // chemins doit être refusée par Vault lui-même, indépendamment des
    // contrôles côté client (qui ne sont que de l'UX).
    hcl += '# Permissions modérateur : lecture seule des policies, mounts et groupes AD + tags partagés\n';
    hcl += 'path "sys/policies/acl"     { capabilities = ["list"] }\n';
    hcl += 'path "sys/policies/acl/*"   { capabilities = ["read","list"] }\n';
    hcl += 'path "sys/mounts"           { capabilities = ["read","list"] }\n';
    hcl += 'path "sys/mounts/*"         { capabilities = ["read","list"] }\n';
    const safeLdapPath = ldapAuthPath.replace(/[\r\n"\\*+]/g, '');
    hcl += `path "${safeLdapPath}/groups"     { capabilities = ["list"] }\n`;
    hcl += `path "${safeLdapPath}/groups/*"   { capabilities = ["read","list"] }\n`;
    hcl += '# Accès au coffre des tags partagés\n';
    hcl += 'path "tags-shared/metadata/*" { capabilities = ["list","read"] }\n';
    hcl += 'path "tags-shared/data/*"     { capabilities = ["create","update","read","list"] }\n\n';
  }

  // Si la policy contient des restrictions RBI-ONLY, ajouter la permission
  // de lecture de sa propre policy (nécessaire pour la détection RBI côté client)
  const hasRbiOnly = paths.some(p => p.accessLevel === 'rbi-only');
  if (hasRbiOnly && policyName.trim()) {
    const safePolicyName = policyName.trim().replace(/[\r\n"\\*+]/g, '');
    if (safePolicyName) {
      hcl += '# Lecture de la policy (détection RBI côté client)\n';
      hcl += `path "sys/policies/acl/${safePolicyName}" { capabilities = ["read"] }\n\n`;
    }
  }

  return hcl || '# Aucun path configuré';
}

// ----------------------------------------
// Sémantique d'une policy (pour comparer avant / après aller-retour)
// ----------------------------------------

// Bloc « path » réduit à ses capacités (forme du builder, sur une ou plusieurs lignes)
const PATH_BLOCK_RE = /\bpath\s+"([^"]*)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}/g;
// Même chose, sur une seule ligne (parcours ligne à ligne du parseur)
const PATH_LINE_RE = /^path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}$/;

const normalizeNewlines = (s) => String(s || '').replace(/\r\n?/g, '\n');

const parseCaps = (raw) => Array.from(new Set(
  String(raw).split(',').map(c => c.trim().replace(/^"|"$/g, '').toLowerCase()).filter(Boolean)
)).sort();

/**
 * Signature sémantique d'une policy : règles effectives (union des capacités par chemin,
 * comme Vault fusionne les règles d'une même policy) + marqueurs lus par l'application
 * (modérateur : useAuth / AdminPanel ; RBI-ONLY : useAuth). Les autres commentaires sont ignorés.
 * @returns {string|null} null si la policy contient autre chose que des règles « path » simples
 *   (format JSON, paramètres autorisés/requis, commentaires bloc…) : non représentable.
 */
export function policySignature(hcl) {
  const text = normalizeNewlines(hcl);
  // Format JSON, ou commentaire bloc /* … */ hors chaînes (les chemins contiennent « /* »)
  if (/^\s*\{/.test(text) || text.replace(/"[^"\n]*"/g, '""').includes('/*')) return null;
  // Retirer les commentaires de ligne (# ou //) pour l'analyse des règles
  const code = text.split('\n').filter(l => !/^\s*(#|\/\/)/.test(l)).join('\n');
  const rules = {};
  for (const m of code.matchAll(PATH_BLOCK_RE)) {
    const caps = parseCaps(m[2]);
    rules[m[1]] = Array.from(new Set([...(rules[m[1]] || []), ...caps])).sort();
  }
  // Tout ce qui n'est pas une règle « path » simple rend la policy non représentable
  if (code.replace(PATH_BLOCK_RE, '').trim() !== '') return null;

  // Marqueurs exploités par l'application (mêmes expressions que useAuth.js)
  const collect = (re, fmt) => Array.from(new Set(Array.from(text.matchAll(re), fmt))).sort();
  const moderators = collect(/# KV v[12] MODERATOR \(([^)]+)\)/g, m => m[1]);
  const rbiEngines = [
    ...collect(/# RBI-ONLY\npath "([^"]+)\/metadata\/\*"/g, m => m[1]),
    ...collect(/# RBI-ONLY\npath "([^"]+)\/\*"/g, m => m[1]),
  ].sort();
  const rbiSecrets = [
    ...collect(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/metadata\/([^"*\s]+)"/g, m => m[1] + '/' + m[2]),
    ...collect(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/([^"*\s]+)"/g, m => m[1] + '/' + m[2]),
  ].sort();

  const sortedRules = Object.keys(rules).sort().map(k => [k, rules[k]]);
  return JSON.stringify({ rules: sortedRules, moderators, rbiEngines, rbiSecrets });
}

// ----------------------------------------
// Relecture d'un HCL en règles du builder
// ----------------------------------------

/**
 * Relit un HCL en état du builder. Les règles sont reconstruites dans leur ordre
 * d'apparition ; les sections générées automatiquement (listing des secrets, bloc
 * modérateur, lecture de sa propre policy) sont ignorées car régénérées.
 * @returns {{ allowListMounts: boolean, paths: Array, unsupported: boolean }}
 *   unsupported = une règle n'a pas pu être rattachée à une règle du builder.
 */
export function parsePolicyHcl(hcl, { allMounts = [], ldapAuthPath = 'auth/ldap', policyName = '' } = {}) {
  const text = normalizeNewlines(hcl);
  const lines = text.split('\n');
  const kvMounts = allMounts.filter(m => m && m.type === 'kv' && m.path);
  // Coffre le plus spécifique contenant ce chemin (les chemins de coffre peuvent contenir des /)
  const findMount = (p) => kvMounts
    .filter(m => p === m.path || p.startsWith(m.path + '/'))
    .sort((a, b) => b.path.length - a.path.length)[0];

  const safeLdap = String(ldapAuthPath).replace(/[\r\n"\\*+]/g, '');
  const moderatorBlockPaths = new Set([
    'sys/policies/acl', 'sys/policies/acl/*', 'sys/mounts', 'sys/mounts/*',
    `${safeLdap}/groups`, `${safeLdap}/groups/*`, 'tags-shared/metadata/*', 'tags-shared/data/*',
  ]);
  const ownPolicyPath = policyName ? `sys/policies/acl/${String(policyName).trim()}` : null;

  const rules = [];
  let allowListMounts = false;
  let inModeratorBlock = false;
  let sawModeratorBlock = false;
  let unsupported = false;

  const getRule = (type, coffre, secret, rbiMarker) => {
    let rule = rules.find(r => r.type === type && r.coffre === coffre && r.secret === secret);
    if (!rule) {
      rule = { type, coffre, secret, includeTotp: false, totpKeys: false, rbiMarker, dataCaps: [] };
      rules.push(rule);
    }
    return rule;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    if (line.startsWith('#')) {
      if (line.startsWith('# Permissions modérateur')) { inModeratorBlock = true; sawModeratorBlock = true; }
      continue;
    }
    const m = line.match(PATH_LINE_RE);
    if (!m) { unsupported = true; continue; }
    const path = m[1];
    const caps = parseCaps(m[2]);
    const prev = (lines[i - 1] || '').trim();
    const prev2 = (lines[i - 2] || '').trim();

    // Sections régénérées automatiquement
    if (inModeratorBlock && moderatorBlockPaths.has(path)) continue;
    if (path === 'sys/mounts' || path === 'sys/mounts/*') { allowListMounts = true; continue; }
    if (ownPolicyPath && path === ownPolicyPath) continue;

    // TOTP : rattaché à la dernière règle dont la clé (ou le préfixe « -* ») correspond EXACTEMENT
    const totp = path.match(/^TOTP\/(keys|code|validate)\/(.+)$/);
    if (totp) {
      const keyName = totp[2];
      const target = [...rules].reverse().find(r => (r.type === 'coffre'
        ? `${totpPrefixFor(r.coffre)}-*`
        : `${totpPrefixFor(r.coffre)}-${r.secret}`) === keyName);
      if (!target) { unsupported = true; continue; }
      target.includeTotp = true;
      if (totp[1] === 'keys') target.totpKeys = true;
      continue;
    }

    const mount = findMount(path);
    if (!mount) { unsupported = true; continue; }
    const rest = path === mount.path ? '' : path.slice(mount.path.length + 1);
    // Marqueur RBI-ONLY : juste avant la règle (coffre) ou avant le commentaire « # Secret: » (secret)
    const rbiBefore = prev === '# RBI-ONLY' || (prev.startsWith('# Secret:') && prev2 === '# RBI-ONLY');

    if (mount.version === 2) {
      if (rest === 'metadata') continue; // listing des secrets (règles par secret), régénéré
      const sub = rest.match(/^(metadata|data|delete|undelete|destroy)\/(.+)$/);
      if (!sub) { unsupported = true; continue; }
      const [, area, target] = sub;
      if (target === '*') {
        const rule = getRule('coffre', mount.path, '', rbiBefore);
        if (area === 'data') rule.dataCaps = caps;
      } else if ((area === 'metadata' || area === 'data') && !target.includes('*')) {
        const rule = getRule('secret', mount.path, target, rbiBefore);
        if (area === 'data') rule.dataCaps = caps;
      } else {
        unsupported = true;
      }
    } else {
      if (rest === '') continue; // listing KV v1 (règles par secret), régénéré
      if (rest === '*') {
        getRule('coffre', mount.path, '', rbiBefore).dataCaps = caps;
      } else if (!rest.includes('*')) {
        getRule('secret', mount.path, rest, rbiBefore).dataCaps = caps;
      } else {
        unsupported = true;
      }
    }
  }

  const paths = rules.map(r => {
    const mount = findMount(r.coffre);
    let accessLevel = 'read-only';
    const moderatorRe = new RegExp(`# KV v${mount.version} MODERATOR \\(${escapeRegex(r.coffre)}\\)`);
    if (r.type === 'coffre' && moderatorRe.test(text)) {
      accessLevel = 'moderator';
    } else if (r.rbiMarker) {
      accessLevel = 'rbi-only';
    } else if (r.type === 'coffre' && r.dataCaps.includes('sudo')) {
      accessLevel = 'full-admin';
    } else if (r.dataCaps.some(c => c === 'create' || c === 'update' || c === 'delete')) {
      accessLevel = 'read-write';
    }
    // Niveau TOTP : « gestion complète » seulement si la règle TOTP/keys exacte existe ;
    // sans TOTP, valeur par défaut alignée sur le niveau d'accès (comme l'UI)
    const syncedTotp = (accessLevel === 'read-only' || accessLevel === 'rbi-only') ? 'read-only' : 'read-write';
    return {
      type: r.type,
      coffre: r.coffre,
      secret: r.secret,
      accessLevel,
      includeTotp: r.includeTotp,
      totpLevel: r.includeTotp ? (r.totpKeys ? 'read-write' : 'read-only') : syncedTotp,
    };
  });

  // Niveau « modérateur » choisi sur un secret spécifique : le builder génère alors le
  // même HCL qu'en RW, plus le bloc modérateur (sans marqueur). Si ce bloc est présent
  // sans coffre modérateur, il provient d'une telle règle : la première règle par
  // secret en RW la représente (HCL régénéré identique, vérifié par la signature).
  if (sawModeratorBlock && !paths.some(p => p.accessLevel === 'moderator')) {
    const candidate = paths.find(p => p.type === 'secret' && p.accessLevel === 'read-write');
    if (candidate) candidate.accessLevel = 'moderator';
  }

  return { allowListMounts, paths, unsupported };
}

/**
 * Relit une policy pour le builder et vérifie que l'aller-retour est fidèle :
 * HCL régénéré depuis les règles relues ≡ HCL d'origine (même signature sémantique).
 * @returns {{ allowListMounts: boolean, paths: Array, faithful: boolean }}
 */
export function analyzePolicyForBuilder(hcl, { allMounts = [], ldapAuthPath = 'auth/ldap', policyName = '' } = {}) {
  const parsed = parsePolicyHcl(hcl, { allMounts, ldapAuthPath, policyName });
  const original = policySignature(hcl);
  let faithful = false;
  if (!parsed.unsupported && original !== null && parsed.paths.length > 0) {
    const regenerated = generatePolicyHcl({
      paths: parsed.paths, allowListMounts: parsed.allowListMounts, allMounts, ldapAuthPath, policyName,
    });
    faithful = policySignature(regenerated) === original;
  }
  return { allowListMounts: parsed.allowListMounts, paths: parsed.paths, faithful };
}

/**
 * Coffres connus dont les clés TOTP tombent AUSSI sous le préfixe « <PRÉFIXE>-* » du coffre
 * donné (globs Vault = préfixe : TOTP/code/WEB-* couvre WEB-PROD-github du coffre web-prod,
 * et PERSO-* couvre le coffre personnel « perso » de tous les utilisateurs).
 * Le nommage des clés TOTP est un format de stockage existant : on avertit, sans le changer.
 */
export function totpPrefixCollisions(coffre, allMounts = []) {
  const prefix = totpPrefixFor(coffre);
  if (!prefix) return [];
  return allMounts
    .filter(m => m && m.type === 'kv' && m.path && m.path !== coffre)
    .filter(m => {
      const other = totpPrefixFor(m.path);
      return other === prefix || other.startsWith(prefix + '-');
    })
    .map(m => m.path);
}

/**
 * La policy contient-elle une règle (hors « deny ») donnant accès à un chemin du coffre ?
 * Couvre X/*, X/data/*, X/metadata/*, X/data/<secret>, X/metadata (listing), X/<secret> (KV v1)
 * et les globs englobants (« * », « users/* », « Comp* »…).
 */
export function policyGrantsMount(content, mountPath) {
  const text = normalizeNewlines(content);
  const mount = String(mountPath || '').replace(/\/+$/, '');
  if (!mount) return false;
  const declRe = /\bpath\s+["']([^"']*)["']\s*\{([^}]*)\}/g;
  for (const m of text.matchAll(declRe)) {
    const p = m[1];
    const capsMatch = m[2].match(/capabilities\s*=\s*\[([^\]]*)\]/);
    const caps = capsMatch ? parseCaps(capsMatch[1]) : null;
    if (caps && caps.length > 0 && caps.every(c => c === 'deny')) continue; // refus explicite
    if (p.endsWith('*')) {
      const pre = p.slice(0, -1);
      if (pre.startsWith(mount + '/') || (mount + '/').startsWith(pre)) return true;
    } else if (p === mount || p.startsWith(mount + '/')) {
      return true;
    }
  }
  return false;
}
