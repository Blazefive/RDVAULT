// Tests du filtrage réseau RBI : la liste d'hôtes autorisés doit suivre la
// Public Suffix List (domaines privés inclus) — un sous-domaine frère d'un
// hébergeur mutualisé (github.io, herokuapp.com…) ne doit jamais passer —, et la
// logique « locataire » pour les suffixes mutualisés absents de la PSL
// (hostMatch.MULTI_TENANT_SUFFIXES : sharepoint.com, atlassian.net…), sauf force.com.
const test = require('node:test');
const assert = require('node:assert');
const { buildNetworkAllowlist } = require('./secureSession');
const { MULTI_TENANT_SUFFIXES } = require('./hostMatch');

test('hébergeurs mutualisés : sous-domaine frère bloqué', () => {
  const cases = [
    ['https://team.github.io/login', 'team.github.io', 'evil.github.io'],
    ['https://app.contoso.azurewebsites.net/', 'contoso.azurewebsites.net', 'attacker.azurewebsites.net'],
    ['https://myvault.herokuapp.com/', 'myvault.herokuapp.com', 'exfil.herokuapp.com'],
    ['https://bucket.s3.amazonaws.com/', 'bucket.s3.amazonaws.com', 'attacker-bucket.s3.amazonaws.com'],
    ['https://d111.cloudfront.net/', 'd111.cloudfront.net', 'd222.cloudfront.net']
  ];
  for (const [url, ok, evil] of cases) {
    const { isAllowedHost } = buildNetworkAllowlist([url]);
    assert.strictEqual(isAllowedHost(ok), true, `${ok} doit être autorisé`);
    assert.strictEqual(isAllowedHost('cdn.' + ok), true, `sous-domaine de ${ok} autorisé`);
    assert.strictEqual(isAllowedHost(evil), false, `${evil} doit être bloqué (cible ${url})`);
    assert.strictEqual(isAllowedHost(evil.split('.').slice(1).join('.')), false, 'suffixe public nu bloqué');
  }
});

test('domaine classique : domaine enregistrable et ses sous-domaines autorisés', () => {
  const { allowedHosts, isAllowedHost } = buildNetworkAllowlist([
    'https://login.example.co.uk/auth',
    'https://app.site.com/home'
  ]);
  assert.ok(allowedHosts.has('example.co.uk'));
  assert.ok(allowedHosts.has('site.com'));
  assert.strictEqual(isAllowedHost('static.example.co.uk'), true);
  assert.strictEqual(isAllowedHost('cdn.site.com'), true);
  assert.strictEqual(isAllowedHost('other.co.uk'), false);
  assert.strictEqual(isAllowedHost('co.uk'), false);
  assert.strictEqual(isAllowedHost('evilsite.com'), false);
});

test('suffixes mutualisés hors PSL : un locataire n\'ouvre jamais un locataire voisin', () => {
  const cases = [
    // [URL cible, hôte autorisé, locataire voisin, hôte de la même PSL désormais bloqué]
    ['https://contoso.sharepoint.com/sites/rh', 'contoso.sharepoint.com', 'evil.sharepoint.com', 'attacker-my.sharepoint.com'],
    ['https://contoso.onmicrosoft.com/', 'contoso.onmicrosoft.com', 'evil.onmicrosoft.com', 'x.onmicrosoft.com'],
    ['https://moncorp.atlassian.net/jira', 'moncorp.atlassian.net', 'evil.atlassian.net', 'x.atlassian.net'],
    // PSL : « vm.westeurope.cloudapp.azure.com » → « azure.com » : tout Azure passait (autres VM, autres services)
    ['https://vm1.westeurope.cloudapp.azure.com/', 'vm1.westeurope.cloudapp.azure.com', 'vm2.westeurope.cloudapp.azure.com', 'evil.inference.ml.azure.com'],
  ];
  for (const [url, ok, neighbor, other] of cases) {
    const { isAllowedHost } = buildNetworkAllowlist([url]);
    assert.strictEqual(isAllowedHost(ok), true, `${ok} doit être autorisé`);
    assert.strictEqual(isAllowedHost('static.' + ok), true, `sous-domaine de ${ok} autorisé`);
    assert.strictEqual(isAllowedHost(neighbor), false, `${neighbor} (locataire voisin) doit être bloqué (cible ${url})`);
    assert.strictEqual(isAllowedHost(other), false, `${other} doit être bloqué (cible ${url})`);
    assert.strictEqual(isAllowedHost(ok.split('.').slice(1).join('.')), false, 'suffixe mutualisé nu bloqué');
  }
});

test('suffixes mutualisés : tout suffixe de hostMatch.MULTI_TENANT_SUFFIXES suit la logique locataire (sauf force.com)', () => {
  for (const s of MULTI_TENANT_SUFFIXES) {
    if (s === 'force.com' || s.endsWith('.force.com')) continue; // exception documentée (Salesforce), testée ci-dessous
    const { isAllowedHost } = buildNetworkAllowlist(['https://tenant-a.' + s + '/login', 'https://tenant-a.' + s + '/home']);
    assert.strictEqual(isAllowedHost('tenant-a.' + s), true, `tenant-a.${s} autorisé`);
    assert.strictEqual(isAllowedHost('cdn.tenant-a.' + s), true, `sous-domaine de tenant-a.${s} autorisé`);
    assert.strictEqual(isAllowedHost('tenant-b.' + s), false, `tenant-b.${s} (voisin) bloqué`);
    assert.strictEqual(isAllowedHost(s), false, `${s} nu bloqué`);
  }
});

test('suffixe mutualisé nu comme page cible : autorisé à l\'identique, jamais ses locataires', () => {
  const { allowedHosts, exactHosts, isAllowedHost } = buildNetworkAllowlist(['https://sharepoint.com/']);
  assert.strictEqual(allowedHosts.size, 0);
  assert.deepStrictEqual([...exactHosts], ['sharepoint.com']);
  assert.strictEqual(isAllowedHost('sharepoint.com'), true);
  assert.strictEqual(isAllowedHost('evil.sharepoint.com'), false);
});

test('Salesforce (exception force.com) : une session Lightning atteint encore les hôtes de son org', () => {
  // Connexion sur My Domain (salesforce.com), page post-login sur Lightning (force.com)
  const { isAllowedHost } = buildNetworkAllowlist([
    'https://contoso.my.salesforce.com/',
    'https://contoso.lightning.force.com/lightning/page/home',
  ]);
  for (const h of [
    'contoso.lightning.force.com', 'contoso.my.salesforce.com',
    'contoso--c.vf.force.com', 'contoso.file.force.com', // Visualforce, fichiers (même org)
    'static.lightning.force.com', // ressources Lightning partagées par Salesforce
    'contoso--dev.sandbox.lightning.force.com',
  ]) {
    assert.strictEqual(isAllowedHost(h), true, `${h} doit rester atteignable depuis la session Lightning`);
  }
  assert.strictEqual(isAllowedHost('evil-salesforce.com'), false);
  assert.strictEqual(isAllowedHost('force.com.evil.example'), false);
});

test('IP, localhost et URL invalide : hôte exact uniquement', () => {
  const { allowedHosts, isAllowedHost } = buildNetworkAllowlist([
    'http://192.168.1.10:8080/',
    'http://localhost:3000/',
    'pas une url',
    null
  ]);
  assert.deepStrictEqual([...allowedHosts].sort(), ['192.168.1.10', 'localhost']);
  assert.strictEqual(isAllowedHost('192.168.1.10'), true);
  assert.strictEqual(isAllowedHost('1.10'), false);
  assert.strictEqual(isAllowedHost('localhost'), true);
});
