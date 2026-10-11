// ========================================
// HOST MATCH — Correspondance secret ↔ hôte (filtrage côté desktop)
// ========================================
// Module pur (sans dépendance Electron) pour être testable.
// L'extension Chrome ne reçoit que les secrets correspondant à l'hôte de l'onglet
// (ou de la frame) courant. Règles, de la plus stricte à la plus large :
//   1. hôte identique ;
//   2. l'hôte du secret est un domaine parent de l'hôte demandé (secret « example.com »
//      proposé sur « login.example.com ») ;
//   3. même domaine de base au sens de la Public Suffix List (secret « www.example.com »
//      proposé sur « auth.example.com », mais « a.github.io » jamais sur « b.github.io ») ;
//   4. domaines équivalents connus (portails de connexion hébergés sur un autre domaine :
//      ovh.com ↔ ovhcloud.com, wikipedia.org ↔ wikimedia.org, etc.).
// Les IP et « localhost » ne correspondent qu'à l'identique.
//
// Suffixes MUTUALISÉS (MULTI_TENANT_SUFFIXES) : hébergements multi-locataires absents de la
// Public Suffix List embarquée (tldts), dont les sous-domaines appartiennent à des tiers
// (tenant SharePoint, site Atlassian Cloud, site Salesforce, VM Azure, organisation Okta / Auth0 /
// OneLogin, instance Zendesk / ServiceNow…). Ils sont traités
// comme des suffixes publics : chaque hôte en dessous est un locataire distinct, qui ne
// correspond qu'à lui-même et à ses sous-domaines (règles 1 et 2), jamais à un autre
// locataire ni, via la règle 4, à la marque. Seul le sens sûr est conservé : l'identifiant
// d'un locataire reste proposé sur les domaines mono-titulaires de sa marque (BRAND), où se
// trouve la page de connexion (contoso.sharepoint.com → login.microsoftonline.com).

'use strict';

const { getDomain } = require('tldts');

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

// Suffixe mutualisé → domaine de la marque dont la connexion sert ses locataires (ou null).
// null : la connexion d'un locataire se fait sur le locataire lui-même (fournisseurs d'identité,
// helpdesk…) ; aucun domaine de la marque ne reçoit alors ses identifiants.
const MULTI_TENANT_SUFFIX_BRAND = new Map([
  ['sharepoint.com', 'microsoft.com'],        // tenants SharePoint / OneDrive (contoso.sharepoint.com)
  ['onmicrosoft.com', 'microsoft.com'],       // tenants Microsoft 365 / Entra ID
  ['cloudapp.azure.com', null],               // VM Azure (vm.region.cloudapp.azure.com) : contenu arbitraire
  ['inference.ml.azure.com', null],           // points de terminaison Azure ML : code du client
  ['atlassian.net', 'atlassian.com'],         // sites Atlassian Cloud (moncorp.atlassian.net)
  ['force.com', 'salesforce.com'],            // sites Salesforce / Experience Cloud, Lightning, Visualforce
  ['my.site.com', 'salesforce.com'],          // sites Experience Cloud (domaines améliorés : moncommu.my.site.com)
  ['my.salesforce-sites.com', 'salesforce.com'], // Salesforce Sites (domaines améliorés : monsite.my.salesforce-sites.com)
  ['vps.ovh.net', null],                      // VPS OVHcloud (vps-xxxx.vps.ovh.net) : contenu arbitraire
  ['okta.com', null],                         // organisations Okta (moncorp.okta.com) : connexion sur l'organisation
  ['oktapreview.com', null],                  // organisations Okta de préproduction (moncorp.oktapreview.com)
  ['okta-emea.com', null],                    // organisations Okta hébergées en Europe (moncorp.okta-emea.com)
  ['auth0.com', null],                        // tenants Auth0 (moncorp.auth0.com, moncorp.eu.auth0.com)
  ['onelogin.com', null],                     // comptes OneLogin (moncorp.onelogin.com)
  ['zendesk.com', null],                      // centres d'assistance Zendesk (moncorp.zendesk.com)
  ['service-now.com', null],                  // instances ServiceNow (moncorp.service-now.com)
]);
const MULTI_TENANT_SUFFIXES = [...MULTI_TENANT_SUFFIX_BRAND.keys()];

/** Suffixe mutualisé dont relève l'hôte (lui-même ou un parent), ou null */
function multiTenantSuffixOf(host) {
  for (const s of MULTI_TENANT_SUFFIXES) {
    if (host === s || host.endsWith('.' + s)) return s;
  }
  return null;
}

// Groupes de domaines de base équivalents (connexion hébergée ailleurs, marques multiples).
// Uniquement des domaines MONO-TITULAIRES : jamais un suffixe mutualisé (voir ci-dessus).
// Chaque membre doit être lui-même un domaine de base (PSL) : la comparaison porte sur les
// domaines de base, un sous-domaine listé ici ne correspondrait jamais (entrée morte).
// impots.gouv.fr n'a pas de groupe : sa connexion (cfspart-idp, cfspro…) est sous impots.gouv.fr
// (règle 3). L'ancienne entrée « dgfip.finances.gouv.fr » était morte (domaine de base
// finances.gouv.fr) et n'a pas été « réparée » : finances.gouv.fr regroupe de nombreuses
// applications ministérielles et l'intranet des agents DGFiP, aux comptes distincts de l'espace
// particulier/professionnel impots.gouv.fr. Les déclarer équivalents y proposerait ces
// identifiants fiscaux.
const EQUIVALENT_DOMAIN_GROUPS = [
  ['ovh.com', 'ovhcloud.com', 'ovh.net'],
  ['wikipedia.org', 'wikimedia.org', 'wiktionary.org', 'wikibooks.org', 'wikiquote.org', 'wikisource.org', 'wikinews.org', 'wikiversity.org', 'wikivoyage.org', 'wikidata.org', 'mediawiki.org'],
  ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'hotmail.com', 'windowsazure.com', 'azure.com', 'msn.com', 'skype.com', 'xbox.com'],
  ['google.com', 'youtube.com', 'gmail.com', 'google.fr', 'google.co.uk', 'google.de', 'google.es', 'google.it', 'google.ca', 'google.be', 'google.ch'],
  ['amazon.com', 'amazon.fr', 'amazon.de', 'amazon.co.uk', 'amazon.es', 'amazon.it', 'amazon.ca', 'amazon.nl', 'amazon.be', 'amazon.com.au', 'amazon.co.jp', 'amazon.in', 'audible.com', 'audible.fr', 'audible.de'],
  ['facebook.com', 'messenger.com', 'instagram.com', 'meta.com'],
  ['apple.com', 'icloud.com'],
  ['atlassian.com', 'bitbucket.org', 'trello.com'],
  ['notion.so', 'notion.com'],
  ['proton.me', 'protonmail.com', 'protonmail.ch', 'pm.me'],
  ['x.com', 'twitter.com'],
  ['yahoo.com', 'yahoo.fr', 'aol.com'],
  ['ebay.com', 'ebay.fr', 'ebay.de', 'ebay.co.uk'],
  ['paypal.com', 'paypal.fr'],
  ['zoom.us', 'zoom.com'],
  ['dropbox.com', 'dropboxapi.com'],
  ['adobe.com', 'adobelogin.com'],
  ['leboncoin.fr', 'leboncoin.com'],
  ['orange.fr', 'orange.com', 'sosh.fr'],
  ['free.fr', 'freebox.fr', 'proxad.net'],
  ['sfr.fr', 'red-by-sfr.fr'],
  ['bouyguestelecom.fr', 'bbox.fr'],
  ['ameli.fr', 'assurance-maladie.fr'],
];
const EQUIVALENT_BY_DOMAIN = new Map();
for (const group of EQUIVALENT_DOMAIN_GROUPS) {
  // Défense en profondeur : un suffixe mutualisé ajouté par erreur à un groupe est ignoré
  const set = new Set(group.filter(d => !multiTenantSuffixOf(d)));
  for (const d of set) EQUIVALENT_BY_DOMAIN.set(d, set);
}

/** Hostname (minuscule) d'une URL ou d'un nom d'hôte nu, ou null */
function hostnameOf(value) {
  const s = typeof value === 'string' ? value.trim() : '';
  if (!s) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'https://' + s);
    return url.hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** true si l'hôte demandé est un nom d'hôte syntaxiquement valide */
function isValidHostname(host) {
  return typeof host === 'string' && host.length > 0 && host.length <= 253 && HOSTNAME_RE.test(host);
}

function isIpOrLocal(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || !host.includes('.');
}

/**
 * Domaine de base (registrable) selon la Public Suffix List, ou null pour une IP,
 * « localhost », ou un suffixe public nu (ex. « github.io »).
 */
function baseDomain(host) {
  if (!host || isIpOrLocal(host)) return null;
  return getDomain(host, { allowPrivateDomains: true }) || null;
}

/**
 * Domaine de base utilisé pour la correspondance secret ↔ hôte : celui de la PSL (baseDomain),
 * sauf sous un suffixe mutualisé, traité comme un suffixe public : l'hôte complet est alors son
 * propre domaine (locataire distinct, y compris dans les couches imbriquées comme
 * « x.lightning.force.com »), et le suffixe nu n'en a aucun.
 * baseDomain reste la PSL pure (utilisée aussi par le filtrage réseau RBI de secureSession).
 */
function matchingBaseDomain(host) {
  if (!host || isIpOrLocal(host)) return null;
  const suffix = multiTenantSuffixOf(host);
  if (suffix) return host === suffix ? null : host;
  return baseDomain(host);
}

/** true si deux domaines de base sont déclarés équivalents */
function areEquivalent(a, b) {
  const set = EQUIVALENT_BY_DOMAIN.get(a);
  return Boolean(set && set.has(b));
}

/** true si l'hôte d'un secret correspond à l'hôte demandé (voir règles en tête de fichier) */
function hostsMatch(secretHost, requestedHost) {
  if (!secretHost || !requestedHost) return false;
  if (secretHost === requestedHost) return true;
  if (isIpOrLocal(secretHost) || isIpOrLocal(requestedHost)) return false;
  const secretBase = matchingBaseDomain(secretHost);
  const requestedBase = matchingBaseDomain(requestedHost);
  if (!secretBase || !requestedBase) return false;
  // Domaine parent : « example.com » couvre « login.example.com » (jamais un suffixe public nu)
  if (requestedHost.endsWith('.' + secretHost) && secretBase === secretHost) return true;
  // Même domaine de base, ou domaines de base équivalents
  if (secretBase === requestedBase || areEquivalent(secretBase, requestedBase)) return true;
  // Secret d'un locataire mutualisé : proposé aussi sur les domaines (mono-titulaires) de sa
  // marque. Jamais l'inverse : un hôte locataire n'est jamais le domaine de base d'une marque.
  const brand = MULTI_TENANT_SUFFIX_BRAND.get(multiTenantSuffixOf(secretHost));
  return Boolean(brand && (requestedBase === brand || areEquivalent(brand, requestedBase)));
}

/** true si le secret (url/website) correspond à l'hôte demandé */
function secretMatchesHost(secret, host) {
  if (!secret || !isValidHostname(host)) return false;
  const h = host.toLowerCase();
  for (const candidate of [secret.url, secret.website]) {
    const sh = hostnameOf(candidate);
    if (sh && hostsMatch(sh, h)) return true;
  }
  return false;
}

module.exports = { hostnameOf, isValidHostname, baseDomain, hostsMatch, secretMatchesHost, EQUIVALENT_DOMAIN_GROUPS, MULTI_TENANT_SUFFIXES };
