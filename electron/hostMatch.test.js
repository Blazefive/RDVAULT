// Tests du filtrage secret ↔ hôte — exécuter avec : node --test electron/
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { hostnameOf, isValidHostname, baseDomain, hostsMatch, secretMatchesHost, EQUIVALENT_DOMAIN_GROUPS, MULTI_TENANT_SUFFIXES = [] } = require('./hostMatch');

test('hostnameOf accepte URL complète et hôte nu', () => {
  assert.equal(hostnameOf('https://www.Example.com/login?x=1'), 'www.example.com');
  assert.equal(hostnameOf('intranet.local'), 'intranet.local');
  assert.equal(hostnameOf(''), null);
  assert.equal(hostnameOf('http://'), null);
});

test('baseDomain suit la Public Suffix List', () => {
  assert.equal(baseDomain('www.example.com'), 'example.com');
  assert.equal(baseDomain('cfspart-idp.impots.gouv.fr'), 'impots.gouv.fr');
  assert.equal(baseDomain('shop.example.co.uk'), 'example.co.uk');
  assert.equal(baseDomain('victime.github.io'), 'victime.github.io');
  assert.equal(baseDomain('localhost'), null);
  assert.equal(baseDomain('10.0.0.5'), null);
});

test('correspondance exacte et domaine parent', () => {
  assert.equal(secretMatchesHost({ url: 'https://example.com' }, 'example.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://example.com' }, 'login.example.com'), true);
  assert.equal(secretMatchesHost({ website: 'localhost' }, 'localhost'), true);
});

test('même domaine de base : www.site.com proposé sur auth.site.com', () => {
  assert.equal(hostsMatch('www.ovh.com', 'login.ovh.com'), true);
  assert.equal(hostsMatch('www.impots.gouv.fr', 'cfspart-idp.impots.gouv.fr'), true);
  assert.equal(hostsMatch('www.impots.gouv.fr', 'www.ameli.gouv.fr'), false, 'gouv.fr est un suffixe public');
});

test('domaines équivalents connus (connexion hébergée ailleurs)', () => {
  assert.equal(hostsMatch('www.ovh.com', 'auth.eu.ovhcloud.com'), true);
  assert.equal(hostsMatch('fr.wikipedia.org', 'auth.wikimedia.org'), true);
  assert.equal(hostsMatch('www.microsoft.com', 'login.microsoftonline.com'), true);
  assert.equal(hostsMatch('www.ovh.com', 'auth.wikimedia.org'), false);
});

test('pas de correspondance sur un préfixe trompeur ni sur les IP/localhost', () => {
  assert.equal(hostsMatch('example.com', 'evil-example.com'), false);
  assert.equal(hostsMatch('example.com', 'example.com.evil.net'), false);
  assert.equal(hostsMatch('10.0.0.5', '10.0.0.6'), false);
  assert.equal(hostsMatch('localhost', 'localhost.evil.com'), false);
  assert.equal(hostsMatch('intranet', 'intranet.example.com'), false);
});

test('un suffixe public ne matche pas les sous-domaines tiers', () => {
  assert.equal(secretMatchesHost({ url: 'https://github.io' }, 'victime.github.io'), false);
  assert.equal(secretMatchesHost({ url: 'https://moi.github.io' }, 'autre.github.io'), false);
  assert.equal(secretMatchesHost({ url: 'com' }, 'anything.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://moi.github.io' }, 'moi.github.io'), true);
});

// EXTENSION-23 : suffixes d'hébergement MULTI-LOCATAIRES absents de la Public Suffix List
// embarquée (sous-domaines attribués à des tiers). Ils ne doivent jamais être assimilés à la
// marque (table d'équivalence) ni rapprocher deux locataires entre eux.
test('suffixes mutualisés : l\'identifiant de la marque n\'est jamais proposé sur un locataire tiers', () => {
  const leaks = [
    [{ url: 'https://login.microsoftonline.com' }, 'evilcorp.sharepoint.com'],
    [{ url: 'https://microsoft.com' }, 'x.sharepoint.com'],
    [{ url: 'https://live.com' }, 'evilcorp.onmicrosoft.com'],
    [{ url: 'https://portal.azure.com' }, 'evilvm.westeurope.cloudapp.azure.com'],
    [{ url: 'https://login.microsoftonline.com' }, 'evilvm.westeurope.cloudapp.azure.com'],
    [{ url: 'https://microsoft.com' }, 'phish.westeurope.inference.ml.azure.com'],
    [{ url: 'https://login.salesforce.com' }, 'phish-site.force.com'],
    [{ url: 'https://login.salesforce.com' }, 'evil.lightning.force.com'],
    [{ url: 'https://id.atlassian.com' }, 'evilorg.atlassian.net'],
    [{ url: 'https://trello.com' }, 'evilorg.atlassian.net'],
    [{ url: 'https://www.ovh.com' }, 'vps-0badc0de.vps.ovh.net'],
  ];
  for (const [secret, host] of leaks) {
    assert.equal(secretMatchesHost(secret, host), false, `${secret.url} ne doit pas être proposé sur ${host}`);
  }
});

test('suffixes mutualisés : deux locataires distincts ne se correspondent pas', () => {
  assert.equal(secretMatchesHost({ url: 'https://contoso.sharepoint.com' }, 'evil.sharepoint.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://contoso.onmicrosoft.com' }, 'evil.onmicrosoft.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://moncorp.atlassian.net' }, 'evilorg.atlassian.net'), false);
  assert.equal(secretMatchesHost({ url: 'https://moncommu.force.com/s/login' }, 'evil.force.com'), false);
  // Couches Salesforce imbriquées : le locataire est l'hôte complet, pas « lightning.force.com »
  assert.equal(secretMatchesHost({ url: 'https://moncorp.lightning.force.com' }, 'evil.lightning.force.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://vm1.westeurope.cloudapp.azure.com' }, 'vm2.westeurope.cloudapp.azure.com'), false);
  // Le suffixe nu ne couvre aucun locataire (comme « github.io »)
  assert.equal(secretMatchesHost({ url: 'https://sharepoint.com' }, 'contoso.sharepoint.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://atlassian.net' }, 'moncorp.atlassian.net'), false);
  assert.equal(secretMatchesHost({ url: 'https://force.com' }, 'moncommu.force.com'), false);
});

test('suffixes mutualisés : le locataire garde sa correspondance exacte et la connexion de sa marque', () => {
  assert.equal(secretMatchesHost({ url: 'https://contoso.sharepoint.com/sites/rh' }, 'contoso.sharepoint.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://contoso.sharepoint.com' }, 'docs.contoso.sharepoint.com'), true, 'domaine parent');
  assert.equal(secretMatchesHost({ url: 'https://moncorp.atlassian.net/wiki' }, 'moncorp.atlassian.net'), true);
  assert.equal(secretMatchesHost({ url: 'https://moncommu.force.com' }, 'moncommu.force.com'), true);
  // Sens sûr uniquement : l'identifiant d'un locataire reste proposé sur la page de connexion
  // (mono-titulaire) de sa marque, où la redirection l'envoie
  assert.equal(secretMatchesHost({ url: 'https://contoso.sharepoint.com' }, 'login.microsoftonline.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://contoso.onmicrosoft.com' }, 'login.live.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://moncorp.atlassian.net' }, 'id.atlassian.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://moncorp.lightning.force.com' }, 'login.salesforce.com'), true);
  // Une VM Azure n'est pas un compte Microsoft : aucun rattachement à la marque
  assert.equal(secretMatchesHost({ url: 'https://vm1.westeurope.cloudapp.azure.com' }, 'login.microsoftonline.com'), false);
});

test('suffixes mutualisés : les membres mono-titulaires des groupes restent équivalents', () => {
  assert.equal(hostsMatch('www.microsoft.com', 'login.live.com'), true);
  assert.equal(hostsMatch('portal.azure.com', 'login.microsoftonline.com'), true);
  assert.equal(hostsMatch('outlook.com', 'login.microsoftonline.com'), true);
  assert.equal(hostsMatch('id.atlassian.com', 'trello.com'), true);
  assert.equal(hostsMatch('www.ovh.com', 'www.ovh.net'), true);
  assert.equal(hostsMatch('login.salesforce.com', 'moncorp.my.salesforce.com'), true, 'My Domain : page de connexion servie par Salesforce');
});

test('table d\'équivalence : aucun membre n\'est un suffixe mutualisé ou public', () => {
  for (const group of EQUIVALENT_DOMAIN_GROUPS) {
    for (const d of group) {
      assert.ok(!MULTI_TENANT_SUFFIXES.some(s => d === s || d.endsWith('.' + s)), `${d} est un suffixe mutualisé`);
      assert.ok(baseDomain(d), `${d} ne doit pas être un suffixe public (PSL)`);
    }
  }
});

// SaaS multi-locataires absents de la PSL (domaine de base = domaine de la marque) : même règle
// que SharePoint / Atlassian / Salesforce. Avant : la règle 3 (même domaine de base) proposait
// l'identifiant d'une organisation sur n'importe quelle autre organisation du même fournisseur.
const SAAS_TENANT_SUFFIXES = ['okta.com', 'oktapreview.com', 'okta-emea.com', 'auth0.com', 'onelogin.com', 'zendesk.com', 'service-now.com', 'my.site.com', 'my.salesforce-sites.com'];

test('SaaS multi-locataires hors PSL : déclarés comme suffixes mutualisés', () => {
  for (const s of SAAS_TENANT_SUFFIXES) {
    assert.ok(MULTI_TENANT_SUFFIXES.includes(s), `${s} doit être un suffixe mutualisé`);
  }
});

test('SaaS multi-locataires hors PSL : deux locataires distincts ne se correspondent pas', () => {
  for (const s of SAAS_TENANT_SUFFIXES) {
    assert.equal(secretMatchesHost({ url: `https://moncorp.${s}/login` }, `evilcorp.${s}`), false, `moncorp.${s} ne doit pas être proposé sur evilcorp.${s}`);
    // Le suffixe nu (ou la vitrine du fournisseur) ne couvre aucun locataire
    assert.equal(secretMatchesHost({ url: `https://${s}` }, `evilcorp.${s}`), false, `${s} ne doit pas couvrir evilcorp.${s}`);
    assert.equal(secretMatchesHost({ url: `https://www.${s}` }, `evilcorp.${s}`), false, `www.${s} ne doit pas être proposé sur evilcorp.${s}`);
  }
  // Couches régionales imbriquées : le locataire est l'hôte complet
  assert.equal(secretMatchesHost({ url: 'https://moncorp.eu.auth0.com' }, 'evilcorp.eu.auth0.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://moncorp.auth0.com' }, 'evilcorp.us.auth0.com'), false);
});

test('SaaS multi-locataires hors PSL : le locataire garde sa correspondance exacte', () => {
  for (const s of SAAS_TENANT_SUFFIXES) {
    assert.equal(secretMatchesHost({ url: `https://moncorp.${s}/app/login` }, `moncorp.${s}`), true, `moncorp.${s} exact`);
    assert.equal(secretMatchesHost({ website: `moncorp.${s}` }, `moncorp.${s}`), true, `moncorp.${s} (website) exact`);
  }
  assert.equal(secretMatchesHost({ url: 'https://moncorp.eu.auth0.com/u/login' }, 'moncorp.eu.auth0.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://moncorp.zendesk.com' }, 'support.moncorp.zendesk.com'), true, 'domaine parent');
});

test('SaaS multi-locataires hors PSL : sens sûr locataire → page de connexion de la marque uniquement', () => {
  // Sites Salesforce (Experience Cloud / Sites) : comme force.com, rattachés à salesforce.com
  assert.equal(secretMatchesHost({ url: 'https://moncommu.my.site.com/s/login' }, 'login.salesforce.com'), true);
  assert.equal(secretMatchesHost({ url: 'https://monsite.my.salesforce-sites.com' }, 'moncorp.my.salesforce.com'), true);
  // Jamais l'inverse : l'identifiant de la marque n'est pas proposé sur un locataire tiers
  assert.equal(secretMatchesHost({ url: 'https://login.salesforce.com' }, 'evil.my.site.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://login.salesforce.com' }, 'evil.my.salesforce-sites.com'), false);
  // Fournisseurs d'identité / helpdesk : connexion sur le locataire lui-même, aucune marque
  assert.equal(secretMatchesHost({ url: 'https://moncorp.okta.com' }, 'login.okta.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://login.okta.com' }, 'evilcorp.okta.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://manage.auth0.com' }, 'evilcorp.auth0.com'), false);
  // Les autres hôtes de site.com (hors my.site.com) gardent la règle du domaine de base
  assert.equal(secretMatchesHost({ url: 'https://www.site.com' }, 'login.site.com'), true);
});

// CONFIG-1 : la règle « domaine parent » ne doit pas traverser un suffixe mutualisé situé sous le
// domaine de l'entrée (azure.com → *.cloudapp.azure.com, ovh.net → *.vps.ovh.net…) : ces hôtes sont
// des VM / sites de clients dont le contenu est contrôlé par un tiers.
test('domaine parent : jamais à travers un suffixe mutualisé (locataire tiers)', () => {
  const leaks = [
    ['azure.com', 'evil.westeurope.cloudapp.azure.com'],
    ['azure.com', 'x.westeurope.inference.ml.azure.com'],
    ['ovh.net', 'vps-0badc0de.vps.ovh.net'],
    ['site.com', 'evil.my.site.com'],
    ['salesforce-sites.com', 'evil.my.salesforce-sites.com'],
  ];
  for (const [secretHost, requested] of leaks) {
    assert.equal(hostsMatch(secretHost, requested), false, `${secretHost} ne doit pas couvrir ${requested}`);
    assert.equal(secretMatchesHost({ url: `https://${secretHost}` }, requested), false, `${secretHost} (url) ne doit pas couvrir ${requested}`);
  }
  // Inchangé : domaine parent hors suffixe mutualisé, et à l'intérieur d'un même locataire
  assert.equal(hostsMatch('ovh.net', 'mail.ovh.net'), true);
  assert.equal(hostsMatch('azure.com', 'portal.azure.com'), true);
  assert.equal(hostsMatch('site.com', 'login.site.com'), true);
  assert.equal(hostsMatch('contoso.sharepoint.com', 'x.contoso.sharepoint.com'), true);
  assert.equal(hostsMatch('vm1.westeurope.cloudapp.azure.com', 'app.vm1.westeurope.cloudapp.azure.com'), true);
});

// Groupe impots : l'entrée « dgfip.finances.gouv.fr » n'était pas un domaine de base (celui-ci est
// finances.gouv.fr) et ne correspondait donc jamais. Toute entrée doit être un domaine de base.
test('table d\'équivalence : chaque membre est un domaine de base, chaque groupe a au moins 2 membres', () => {
  for (const group of EQUIVALENT_DOMAIN_GROUPS) {
    assert.ok(group.length >= 2, `groupe sans effet : ${JSON.stringify(group)}`);
    for (const d of group) {
      assert.equal(baseDomain(d), d, `${d} n'est pas un domaine de base (entrée morte)`);
    }
  }
});

test('impots.gouv.fr : connexion sous impots.gouv.fr, jamais proposée sur finances.gouv.fr', () => {
  assert.equal(hostsMatch('www.impots.gouv.fr', 'cfspart-idp.impots.gouv.fr'), true);
  assert.equal(hostsMatch('www.impots.gouv.fr', 'cfspro.impots.gouv.fr'), true);
  assert.equal(hostsMatch('www.impots.gouv.fr', 'portail.dgfip.finances.gouv.fr'), false);
  assert.equal(hostsMatch('www.impots.gouv.fr', 'www.finances.gouv.fr'), false);
});

test('hôte demandé invalide refusé', () => {
  assert.equal(isValidHostname('exa mple.com'), false);
  assert.equal(isValidHostname('-bad.com'), false);
  assert.equal(secretMatchesHost({ url: 'https://example.com' }, 'exa mple.com'), false);
});
