// Test de l'extension sur de VRAIS sites : pour chaque page de connexion, un secret factice est créé
// dans le coffre local (URL du site), puis on clique sur l'icône injectée par l'extension, on choisit
// l'entrée, et on vérifie quels champs ont été remplis. Aucune soumission, aucun vrai compte.
// Les iframes hors processus (formulaire embarqué d'un autre domaine) sont aussi inspectées. Un site
// qui sert un mur anti-robot au lieu de sa page de connexion est classé ANTI-ROBOT (hors extension).
// Sécurité (SITES-22) : refus de démarrer si le port 45678 est déjà pris (une autre instance RDVAULT
// servirait SES identifiants à l'extension de test), contrôle que le port est ensuite tenu par l'application
// lancée ici, et seule l'entrée factice du site est cliquée dans le menu.
// Code de sortie : 1 si le harnais n'a rien testé (erreur globale, aucun site, aucun site OK) ou si l'entrée
// factice manque dans un menu ; les murs anti-robot et les écarts propres à un site (pages qui changent) sont
// seulement rapportés dans le résumé. Le dossier temporaire (profil Chrome, coffre de test) est supprimé.
// Lancement : E2E_BROWSER=<chrome-for-testing>\chrome.exe node test/e2e/real-sites.js [filtre]
'use strict'; // eslint-disable-line strict -- script CommonJS lancé par node, pas un module ES
const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const net = require('net');
const { spawn } = require('child_process');
const { appWrapperPath, loginInApp, removeTempDir, waitSyncPortFree, assertSyncPortOwner, SYNC_PORT } = require('./app-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
const EXT = path.join(ROOT, 'chrome-extension/vault-autofill-extension');
const CHROME = process.env.E2E_BROWSER;
if (!CHROME) { console.error('E2E_BROWSER manquant (chrome.exe de Chrome for Testing)'); process.exit(2); }
const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
const electronPath = require(path.join(ROOT, 'node_modules/electron'));
const APP_DEBUG_PORT = 9335;
const USER = 'e2e';
const PASS = 'E2e-password-123';
const ENGINE = `users/${USER}/Mes-Secrets`;
const SHOTS = path.join(os.tmpdir(), 'rdvault-real-sites');

// Sites testés : page de connexion, type attendu
const SITES = [
  // Dev / tech
  { id: 'github', url: 'https://github.com/login', type: 'classique' },
  { id: 'gitlab', url: 'https://gitlab.com/users/sign_in', type: 'classique' },
  { id: 'bitbucket', url: 'https://bitbucket.org/account/signin/', type: 'deux étapes' },
  { id: 'npm', url: 'https://www.npmjs.com/login', type: 'classique' },
  { id: 'heroku', url: 'https://id.heroku.com/login', type: 'classique' },
  { id: 'gitea', url: 'https://gitea.com/user/login', type: 'classique' },
  { id: 'sourceforge', url: 'https://sourceforge.net/auth/', type: 'classique' },
  // Email
  { id: 'google', url: 'https://accounts.google.com/signin/v2/identifier', type: 'deux étapes' },
  { id: 'microsoft', url: 'https://login.microsoftonline.com/', type: 'deux étapes' },
  { id: 'proton', url: 'https://account.proton.me/login', type: 'SPA' },
  { id: 'yahoo', url: 'https://login.yahoo.com/', type: 'deux étapes' },
  { id: 'zoho', url: 'https://accounts.zoho.com/signin', type: 'SPA' },
  { id: 'fastmail', url: 'https://www.fastmail.com/login/', type: 'classique' },
  // Social
  { id: 'facebook', url: 'https://www.facebook.com/login/', type: 'classique' },
  { id: 'linkedin', url: 'https://www.linkedin.com/login', type: 'classique' },
  { id: 'x', url: 'https://x.com/i/flow/login', type: 'SPA modale' },
  { id: 'reddit', url: 'https://www.reddit.com/login/', type: 'shadow DOM' },
  { id: 'instagram', url: 'https://www.instagram.com/accounts/login/', type: 'classique' },
  { id: 'pinterest', url: 'https://www.pinterest.com/login/', type: 'SPA' },
  { id: 'discord', url: 'https://discord.com/login', type: 'SPA' },
  { id: 'mastodon', url: 'https://mastodon.social/auth/sign_in', type: 'classique' },
  // Shopping
  // Amazon exige désormais openid.assoc_handle (sinon page « Vous recherchez quelque chose ? »)
  { id: 'amazon', url: 'https://www.amazon.fr/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.fr%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=frflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0', type: 'deux étapes' },
  { id: 'ebay', url: 'https://signin.ebay.com/', type: 'classique' },
  { id: 'etsy', url: 'https://www.etsy.com/signin', type: 'SPA' },
  // SaaS
  { id: 'dropbox', url: 'https://www.dropbox.com/login', type: 'classique' },
  { id: 'notion', url: 'https://www.notion.so/login', type: 'SPA' },
  { id: 'figma', url: 'https://www.figma.com/login', type: 'classique' },
  { id: 'trello', url: 'https://trello.com/login', type: 'SPA (Atlassian)' },
  { id: 'wordpress', url: 'https://wordpress.com/log-in', type: 'SPA' },
  { id: 'mailchimp', url: 'https://login.mailchimp.com/', type: 'classique' },
  { id: 'bitwarden', url: 'https://vault.bitwarden.com/#/login', type: 'SPA' },
  // Média
  { id: 'spotify', url: 'https://accounts.spotify.com/en/login', type: 'classique' },
  { id: 'netflix', url: 'https://www.netflix.com/login', type: 'classique' },
  // France / gouv
  { id: 'ovh', url: 'https://www.ovh.com/auth/', type: 'SPA' },
  // Orange : input transparent (opacity:0) tant qu'il est vide et sans focus (étiquette flottante)
  { id: 'orange', url: 'https://login.orange.fr/', type: 'deux étapes (étiquette flottante)' },
  // L'ancienne page www.laposte.fr/particulier/outils/authentification affiche « Oops... une erreur » :
  // la connexion passe désormais par moncompte.laposte.fr (Keycloak)
  { id: 'laposte', url: 'https://moncompte.laposte.fr/', type: 'classique (Keycloak)' },
  // Le champ identifiant n'accepte que 13 chiffres (masque JS) : identifiant factice numérique
  { id: 'impots', url: 'https://cfspart.impots.gouv.fr/LoginAccess', type: 'classique (gouv)', username: '0123456789012' },
  // Page de connexion réelle (la page d'accueil du portail n'a qu'un bouton « Connectez-vous ») ;
  // redirige vers ameliconnect.ameli.fr (même domaine enregistrable)
  { id: 'ameli', url: 'https://assure.ameli.fr/PortailAS/appmanager/PortailAS/assure?_nfpb=true&_pageLabel=as_login_page&connexioncompte_2actionEvt=afficher', type: 'classique (gouv, OAuth)', username: '1234567890123' },
  { id: 'leboncoin', url: 'https://auth.leboncoin.fr/login', type: 'SPA' },
  // Forums / savoir
  { id: 'stackoverflow', url: 'https://stackoverflow.com/users/login', type: 'classique' },
  { id: 'wikipedia', url: 'https://fr.wikipedia.org/w/index.php?title=Sp%C3%A9cial:Connexion', type: 'classique' },
  { id: 'archive', url: 'https://archive.org/account/login', type: 'classique' },
  // Ajouts 10/2026 : motifs absents de la liste initiale
  { id: 'twitch', url: 'https://www.twitch.tv/login', type: 'SPA modale' },
  { id: 'steam', url: 'https://store.steampowered.com/login/', type: 'SPA (ids React, champ recherche)' },
  { id: 'apple', url: 'https://account.apple.com/sign-in', type: 'iframe hors processus (idmsa.apple.com)' },
  { id: 'slack', url: 'https://slack.com/signin', type: 'e-mail seul' },
  { id: 'sfr', url: 'https://www.sfr.fr/cas/login', type: 'classique (CAS, champ recherche)' },
  { id: 'free', url: 'https://subscribe.free.fr/login/', type: 'classique (sans autocomplete)' },
  { id: 'deezer', url: 'https://account.deezer.com/fr/login/', type: 'classique' },
  { id: 'booking', url: 'https://account.booking.com/sign-in', type: 'deux étapes' },
  { id: 'tiktok', url: 'https://www.tiktok.com/login/phone-or-email/email', type: 'connexion marquée new-password' },
  { id: 'quora', url: 'https://www.quora.com/', type: 'login sur la page d\'accueil' },
  { id: 'adobe', url: 'https://auth.services.adobe.com/fr_FR/index.html', type: 'e-mail seul' },
];
const filter = process.argv[2];
const sites = filter ? SITES.filter(s => filter.split(',').some(x => s.id.includes(x))) : SITES;

const results = [];
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const log = (...a) => console.log('[REAL]', ...a);

function waitPort(port, timeoutMs = 30000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    (function tryOnce() {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(); });
      s.once('error', () => { s.destroy(); if (Date.now() - start > timeoutMs) reject(new Error('port ' + port)); else setTimeout(tryOnce, 300); });
    })();
  });
}
function vaultReq(port, method, p, token, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Vault-Token': token } : {}), ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let buf = ''; res.on('data', c => buf += c);
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch {} resolve({ status: res.statusCode, json }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}
const enc = (e) => e.split('/').map(encodeURIComponent).join('/');

/** Éléments d'une classe donnée vus par une session CDP, y compris dans les shadow roots fermés (pierce) */
async function nodesFromSession(cdp, className, includeInvisible) {
  const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
  const found = [];
  (function walk(n) {
    if (!n) return;
    const attrs = n.attributes || [];
    for (let i = 0; i < attrs.length; i += 2) if (attrs[i] === 'class' && attrs[i + 1].split(/\s+/).includes(className)) found.push(n);
    (n.children || []).forEach(walk);
    (n.shadowRoots || []).forEach(walk);
    // iframes du même processus (coordonnées déjà exprimées dans la fenêtre de la session)
    if (n.contentDocument) walk(n.contentDocument);
  })(root);
  const out = [];
  for (const n of found) {
    try {
      const { model } = await cdp.send('DOM.getBoxModel', { nodeId: n.nodeId });
      const q = model.content;
      const { outerHTML } = await cdp.send('DOM.getOuterHTML', { nodeId: n.nodeId });
      if (includeInvisible || (model.width > 0 && model.height > 0)) out.push({ x: (q[0] + q[2] + q[4] + q[6]) / 4, y: (q[1] + q[3] + q[5] + q[7]) / 4, w: model.width, h: model.height, html: outerHTML });
    } catch (e) { if (includeInvisible) out.push({ x: 0, y: 0, w: 0, h: 0, html: '(sans boîte) ' + (e.message || '') }); }
  }
  return out;
}

/** Position (px) du coin haut-gauche du CONTENU d'une frame dans la fenêtre de la page principale */
async function frameOffset(frame) {
  let x = 0, y = 0;
  for (let f = frame; f && f.parentFrame(); f = f.parentFrame()) {
    const el = await f.frameElement();
    if (!el) return null;
    const o = await el.evaluate(e => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return { x: r.left + e.clientLeft + parseFloat(cs.paddingLeft || 0), y: r.top + e.clientTop + parseFloat(cs.paddingTop || 0) }; });
    await el.dispose().catch(() => {});
    x += o.x; y += o.y;
  }
  return { x, y };
}

/**
 * Éléments d'une classe donnée dans TOUTES les frames : cible principale (avec ses iframes du même
 * processus) puis iframes hors processus (OOPIF, ex. formulaire idmsa.apple.com dans account.apple.com),
 * dont les coordonnées sont ramenées à la fenêtre de la page principale.
 */
async function shadowNodes(page, className, includeInvisible = false) {
  const cdp = await page.createCDPSession();
  let out;
  try {
    out = await nodesFromSession(cdp, className, includeInvisible);
  } finally {
    await cdp.detach().catch(() => {});
  }
  const seen = new Set([page.mainFrame().client]);
  for (const fr of page.frames()) {
    const client = fr.client;
    if (!client || seen.has(client)) continue; // même processus que la page : déjà couvert
    seen.add(client); // première frame rencontrée = racine de la cible OOPIF
    try {
      const off = await frameOffset(fr);
      if (!off) continue;
      for (const n of await nodesFromSession(client, className, includeInvisible)) out.push({ ...n, x: n.x + off.x, y: n.y + off.y, oopif: fr.url() });
    } catch { /* frame détachée pendant le parcours */ }
  }
  return out;
}
async function waitNodes(page, className, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const nodes = await shadowNodes(page, className).catch(() => []);
    if (nodes.length) return nodes;
    await sleep(400);
  }
  return [];
}

/** Ferme les bannières cookies/consentement les plus courantes (clic réel) */
async function dismissBanners(page) {
  const re = /^(tout accepter|accepter tout|accepter|j'accepte|autoriser tous les cookies|allow all cookies|accept all|accept all cookies|accept|agree|i agree|ok|got it|continuer sans accepter|refuser|reject all|tout refuser)$/i;
  for (let round = 0; round < 2; round++) {
    const clicked = await page.evaluate((src) => {
      const re = new RegExp(src, 'i');
      const all = Array.from(document.querySelectorAll('button, [role="button"], a'));
      const btn = all.find(b => re.test((b.textContent || '').replace(/\s+/g, ' ').trim()) && b.offsetParent !== null);
      if (btn) { const r = btn.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; }
      return null;
    }, re.source).catch(() => null);
    if (!clicked) break;
    await page.mouse.click(clicked.x, clicked.y).catch(() => {});
    await sleep(800);
  }
}

/**
 * Mur anti-robot (DataDome, défi Cloudflare...) servi À LA PLACE de la page de connexion.
 * Retenu seulement s'il n'y a AUCUN champ de saisie visible dans la frame principale :
 * un widget captcha intégré à un vrai formulaire ne doit pas masquer un défaut de détection.
 * @returns {Promise<string|null>} description du mur, ou null
 */
async function detectAntiBot(page) {
  const visibleInputs = await page.evaluate(() => Array.from(document.querySelectorAll('input'))
    .filter(i => ['text', 'email', 'tel', 'password'].includes(i.type))
    .filter(i => { const r = i.getBoundingClientRect(); return r.width > 0 && r.height > 0; }).length).catch(() => 0);
  if (visibleInputs > 0) return null;
  const wall = page.frames().map(f => f.url()).find(u => /captcha-delivery\.com|challenges\.cloudflare\.com|\/cdn-cgi\/challenge-platform/i.test(u));
  if (wall) return 'défi ' + new URL(wall).hostname;
  const title = await page.title().catch(() => '');
  // « Security Measure | eBay » : page de vérification anti-robot d'eBay (hCaptcha)
  if (/^(un instant|just a moment|attention required|access denied|vous avez été bloqué|security measure|pardon our interruption)/i.test(title.trim())) return 'titre « ' + title.trim().slice(0, 40) + ' »';
  return null;
}

/** Valeurs des champs de la page (light DOM + shadow roots ouverts) */
async function collectFieldValues(page) {
  const out = [];
  // Toutes les frames (y compris iframes hors processus : formulaire de connexion embarqué)
  for (const fr of page.frames()) {
    const vals = await fr.evaluate(() => {
      const acc = [];
      const walk = (root) => {
        root.querySelectorAll('input').forEach(i => { if (i.value) acc.push({ type: i.type, name: i.name || i.id || '', value: i.value }); });
        root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) walk(el.shadowRoot); });
      };
      walk(document);
      return acc;
    }).catch(() => []);
    out.push(...vals);
  }
  return out;
}

/** Point de clic (fenêtre principale) du premier champ identifiant visible, toutes frames confondues */
async function firstUsernameFieldPoint(page) {
  for (const fr of page.frames()) {
    const pt = await fr.evaluate(() => {
      const cands = Array.from(document.querySelectorAll('input')).filter(x => ['email', 'text', 'tel'].includes(x.type) && x.getBoundingClientRect().width > 0)
        .filter(x => !/(^|[^a-z])(q|search|term|query|recherche)([^a-z]|$)/i.test((x.name || '') + ' ' + (x.id || '')));
      // Champ explicitement marqué identifiant d'abord, sinon le premier champ texte visible
      const i = cands.find(x => x.type === 'email' || /username|email/i.test(x.getAttribute('autocomplete') || '')) || cands[0];
      if (!i) return null; const r = i.getBoundingClientRect(); return { x: r.x + 12, y: r.y + r.height / 2 };
    }).catch(() => null);
    if (!pt) continue;
    if (fr === page.mainFrame()) return pt;
    const off = await frameOffset(fr).catch(() => null);
    if (off) return { x: pt.x + off.x, y: pt.y + off.y };
  }
  return null;
}

async function testSite(browser, site, expected) {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900 });
  const logs = [];
  page.on('console', m => { const t = m.text(); if (/vault|autofill|error|exception|uncaught/i.test(t)) logs.push(m.type() + ': ' + t.slice(0, 220)); });
  page.on('pageerror', e => logs.push('pageerror: ' + String(e.message || e).slice(0, 160) + ' @ ' + String(e.stack || '').split('\n').slice(1, 3).join(' | ').slice(0, 260)));
  const res = { id: site.id, type: site.type, url: site.url, status: 'FAIL', detail: '' };
  try {
    await page.goto(site.url, { waitUntil: 'domcontentloaded', timeout: 45000 }).catch(e => { throw new Error('navigation: ' + e.message.slice(0, 80)); });
    await sleep(2500);
    await dismissBanners(page);
    await sleep(800);
    const title = (await page.title().catch(() => '')).slice(0, 60);
    const icons = await waitNodes(page, 'vault-autofill-icon', 12000);
    if (icons.length === 0) {
      const wall = await detectAntiBot(page);
      if (wall) {
        // Pas un défaut de l'extension : le site n'a pas servi sa page de connexion au navigateur automatisé
        res.status = 'ANTI-ROBOT';
        res.detail = `titre="${title}" ${wall} : page de connexion non servie (non imputable à l'extension)`;
        await page.screenshot({ path: path.join(SHOTS, site.id + '.png') }).catch(() => {});
        return res;
      }
      const frames = page.frames().length;
      const inputs = await page.evaluate(() => document.querySelectorAll('input:not([type=hidden])').length).catch(() => -1);
      const dump = await page.evaluate(() => Array.from(document.querySelectorAll('input')).filter(i => ['text', 'email', 'tel', 'password'].includes(i.type)).slice(0, 8).map(i => {
        const r = i.getBoundingClientRect(); const cs = getComputedStyle(i);
        let opacity = []; let el = i; for (let k = 0; k < 6 && el; k++) { const o = getComputedStyle(el).opacity; if (o !== '1') opacity.push(el.tagName + ':' + o); el = el.parentElement; }
        const f = i.form; const form = f ? ('form{' + [f.id, f.name, (f.className || '').toString().slice(0, 40), (f.getAttribute('action') || '').slice(0, 60)].join('|') + '}') : 'noform';
        return [i.type, i.name || '', i.id || '', i.getAttribute('autocomplete') || '', 'vis=' + (r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'), 'pos=' + Math.round(r.x) + ',' + Math.round(r.y), 'opacity=' + (opacity.join(';') || 'ok'), form].join('|');
      })).catch(() => []);
      console.log('   inputs ' + site.id + ': ' + JSON.stringify(dump));
      res.status = 'AUCUNE ICÔNE';
      res.detail = `titre="${title}" frames=${frames} inputs=${inputs}` + (frames > 1 ? ' (formulaire peut-être dans une iframe : voir le détail par frame)' : '');
      console.log('   logs ' + site.id + ': ' + JSON.stringify(logs.slice(-8)));
      // Détail par frame : où se trouve le formulaire, et l'extension y tourne-t-elle ?
      const frameInfo = [];
      for (const fr of page.frames()) {
        try {
          const d = await fr.evaluate(() => ({
            host: window.location.hostname,
            pwd: document.querySelectorAll('input[type=password]').length,
            txt: document.querySelectorAll('input[type=text],input[type=email],input[type=tel]').length,
            // Notre content script laisse un hôte d'UI (div all:initial) même si le shadow est fermé
            uiHost: document.querySelectorAll('div[style*="all: initial"]').length,
          }));
          if (d.pwd || d.txt || d.uiHost) frameInfo.push(`${d.host}[pwd=${d.pwd} txt=${d.txt} uiHost=${d.uiHost}]`);
        } catch (e) { frameInfo.push('frame cross-origin: ' + (e.message || '').slice(0, 40)); }
      }
      if (frameInfo.length) res.detail += ' | frames avec champs: ' + JSON.stringify(frameInfo);
      await page.screenshot({ path: path.join(SHOTS, site.id + '.png') }).catch(() => {});
      return res;
    }
    // Ouverture du menu : d'abord un clic dans le champ (parcours utilisateur le plus courant),
    // puis, à défaut, un clic sur l'icône injectée par l'extension.
    let items = [];
    const fieldPt = await firstUsernameFieldPoint(page);
    if (fieldPt) { await page.mouse.click(fieldPt.x, fieldPt.y); items = await waitNodes(page, 'vault-autofill-item', 6000); }
    if (items.length === 0) { await page.mouse.click(icons[0].x, icons[0].y); items = await waitNodes(page, 'vault-autofill-item', 6000); }
    if (items.length === 0) {
      res.status = 'MENU VIDE';
      res.detail = `icônes=${icons.length}, titre="${title}", aucune entrée affichée`;
      await page.screenshot({ path: path.join(SHOTS, site.id + '.png') }).catch(() => {});
      return res;
    }
    // SITES-22 : seule l'entrée FACTICE de ce site est cliquée (jamais une autre entrée, par défaut la
    // première : si le menu venait d'une autre instance RDVAULT, ce serait un vrai mot de passe)
    const item = items.find(i => i.html.includes(expected.username));
    if (!item) {
      // Pas de capture : le menu pourrait afficher les identifiants d'une autre instance
      res.status = 'ENTRÉE DE TEST ABSENTE';
      res.detail = `icônes=${icons.length}, ${items.length} entrée(s) affichée(s) sans l'entrée factice du site : rien n'est cliqué`;
      return res;
    }
    await page.mouse.click(item.x, item.y);
    await sleep(1500);
    const values = await collectFieldValues(page);
    // Comparaison sans espaces : certains sites reformatent la saisie (ameli : NIR « 1 23 45 ... »)
    const norm = (s) => String(s).replace(/\s+/g, '');
    const userFilled = values.find(v => norm(v.value) === norm(expected.username));
    const passFilled = values.find(v => v.value === expected.password);
    await page.screenshot({ path: path.join(SHOTS, site.id + '.png') }).catch(() => {});
    if (userFilled && passFilled) { res.status = 'OK'; res.detail = `identifiant → ${userFilled.type}[${userFilled.name}], mot de passe → ${passFilled.type}[${passFilled.name}]`; }
    else if (userFilled) { res.status = 'OK (étape 1)'; res.detail = `identifiant → ${userFilled.type}[${userFilled.name}] ; pas de champ mot de passe sur cette vue`; }
    else if (passFilled) { res.status = 'PARTIEL'; res.detail = `mot de passe rempli mais identifiant absent (${values.length} champs)`; }
    else { res.status = 'NON REMPLI'; res.detail = `icônes=${icons.length} entrées=${items.length} champs=${JSON.stringify(values.slice(0, 4))}`; }
    return res;
  } catch (err) {
    res.status = 'ERREUR'; res.detail = String(err.message || err).slice(0, 120);
    return res;
  } finally {
    await page.close().catch(() => {});
  }
}

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-real-'));
  const appUserData = path.join(tmp, 'app');
  const portFile = path.join(tmp, 'vault-port.txt');
  const appLog = fs.createWriteStream(path.join(tmp, 'app.log'));
  const configCfg = path.join(ROOT, 'config.cfg');
  const hadConfig = fs.existsSync(configCfg);
  // config.cfg n'est réécrit (avec sauvegarde) que s'il diffère de la config de test : évite
  // tout fichier de sauvegarde et toute course avec d'autres harnais lancés en parallèle.
  const WANTED_CFG = 'APP_MODE=local\nLANG=fr\n';
  let rewroteConfig = false;
  fs.mkdirSync(SHOTS, { recursive: true });
  let appProc, browser, appBrowser;
  let globalError = null;
  try {
    if (!fs.existsSync(path.join(ROOT, 'build/index.html'))) throw new Error('build manquant');
    if (sites.length === 0) throw new Error('aucun site ne correspond au filtre « ' + filter + ' »');
    // SITES-22 : port de synchronisation libre AVANT tout lancement (sinon refus : voir app-helpers.js)
    await waitSyncPortFree({ log });
    if (!hadConfig || fs.readFileSync(configCfg, 'utf8') !== WANTED_CFG) {
      if (hadConfig) fs.copyFileSync(configCfg, configCfg + '.e2e-backup');
      fs.writeFileSync(configCfg, WANTED_CFG);
      rewroteConfig = true;
    }

    browser = await puppeteer.launch({
      executablePath: CHROME, headless: false, userDataDir: path.join(tmp, 'chrome'), defaultViewport: null,
      ignoreDefaultArgs: ['--disable-extensions', '--enable-automation'],
      args: ['--disable-extensions-except=' + EXT, '--load-extension=' + EXT, '--no-first-run', '--no-default-browser-check', '--window-size=1280,960', '--lang=fr-FR'],
    });
    const sw = await browser.waitForTarget(t => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 20000 });
    const extId = new URL(sw.url()).hostname;
    log('extension', extId);

    appProc = spawn(electronPath, [appWrapperPath(), '--remote-debugging-port=' + APP_DEBUG_PORT], {
      env: { ...process.env, E2E_USERDATA: appUserData, E2E_EXT_ID: extId, E2E_PORT_FILE: portFile, RDVAULT_LOG_LEVEL: 'warn' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    appProc.stdout.pipe(appLog); appProc.stderr.pipe(appLog);
    const start = Date.now();
    while (!fs.existsSync(portFile) && Date.now() - start < 40000) await sleep(300);
    if (!fs.existsSync(portFile)) throw new Error('coffre local non démarré');
    const vaultPort = Number(fs.readFileSync(portFile, 'utf8'));
    await waitPort(SYNC_PORT); await waitPort(APP_DEBUG_PORT);
    // SITES-22 : le port de synchronisation doit être tenu par l'application lancée ici, et par elle seule
    assertSyncPortOwner(appProc.pid);

    // Création du premier compte : confirmation du mot de passe exigée (AUTH-14)
    let r = await vaultReq(vaultPort, 'POST', '/v1/auth/ldap/login/' + USER, null, { password: PASS, confirm: PASS });
    if (r.status !== 200 || !r.json || !r.json.auth) throw new Error('création du compte de test refusée (HTTP ' + r.status + ')');
    const vtoken = r.json.auth.client_token;
    const expected = {};
    for (const site of sites) {
      // Identifiant factice : e-mail par défaut, ou valeur propre au site si son JS filtre la saisie
      expected[site.id] = { username: site.username || `rdvault-${site.id}@example.com`, password: `Test-${site.id}-Pw-1234` };
      r = await vaultReq(vaultPort, 'POST', `/v1/${enc(ENGINE)}/data/${encodeURIComponent('site-' + site.id)}`, vtoken, { data: { Username: expected[site.id].username, Password: expected[site.id].password, URL: site.url } });
      if (r.status !== 200) throw new Error('création secret ' + site.id);
    }

    appBrowser = await puppeteer.connect({ browserURL: 'http://127.0.0.1:' + APP_DEBUG_PORT, defaultViewport: null });
    let appPage = null;
    for (let i = 0; i < 40 && !appPage; i++) { const pages = await appBrowser.pages(); appPage = pages.find(p => /index\.html/.test(p.url())) || null; if (!appPage) await sleep(500); }
    if (!appPage) throw new Error('page de l\'app introuvable');
    // Formulaire de connexion habituel (écran de création rechargé s'il était affiché avant le compte, AUTH-14)
    await loginInApp(appPage, USER, PASS);
    await sleep(3000);
    log('app connectée, ' + sites.length + ' secrets synchronisés');

    for (const site of sites) {
      const res = await testSite(browser, site, expected[site.id]);
      results.push(res);
      console.log(`${res.status.padEnd(14)} ${site.id.padEnd(14)} ${site.type.padEnd(18)} ${res.detail}`);
    }
  } catch (err) {
    globalError = err || new Error('erreur inconnue');
    console.log('ERREUR GLOBALE: ' + ((err && err.stack) || err));
  } finally {
    try { if (appBrowser) appBrowser.disconnect(); } catch {}
    try { if (appProc) appProc.kill(); } catch {}
    try { if (browser) await browser.close(); } catch {}
    try { if (rewroteConfig) { if (hadConfig) fs.renameSync(configCfg + '.e2e-backup', configCfg); else fs.unlinkSync(configCfg); } } catch {}
    // SITES-23 : dossier temporaire supprimé (profil Chrome ≈ 200 Mo, coffre de test, journal) ; en cas
    // d'erreur globale, le journal de l'application est d'abord copié à côté des captures
    try { if (appProc) { appProc.stdout.unpipe(appLog); appProc.stderr.unpipe(appLog); } } catch {}
    appLog.on('error', () => {});
    await new Promise((r) => appLog.end(r));
    if (globalError && appProc) {
      try { fs.copyFileSync(path.join(tmp, 'app.log'), path.join(SHOTS, 'app.log')); console.log('app.log: ' + path.join(SHOTS, 'app.log')); } catch {}
    }
    await removeTempDir(tmp, appProc);
    console.log('captures: ' + SHOTS);
    const ok = results.filter(r => r.status.startsWith('OK')).length;
    const walls = results.filter(r => r.status === 'ANTI-ROBOT').map(r => r.id);
    const others = results.filter(r => !r.status.startsWith('OK') && r.status !== 'ANTI-ROBOT').map(r => r.id + ':' + r.status);
    const missingEntry = results.filter(r => r.status === 'ENTRÉE DE TEST ABSENTE').map(r => r.id);
    console.log(`RÉSUMÉ: ${ok}/${results.length} sites OK` + (walls.length ? ` ; anti-robot (hors extension) : ${walls.join(', ')}` : '') + (others.length ? ` ; à analyser : ${others.join(', ')}` : ''));
    // SITES-21 : échec si rien n'a réellement été testé ; les murs anti-robot et les écarts propres à un
    // site ne font pas échouer l'exécution (pages de tiers qui changent)
    const reasons = [];
    if (globalError) reasons.push('erreur globale');
    if (results.length === 0) reasons.push('aucun site testé');
    else if (ok === 0) reasons.push('aucun site OK');
    if (missingEntry.length) reasons.push('entrée factice absente du menu : ' + missingEntry.join(', '));
    if (reasons.length) console.log('ÉCHEC: ' + reasons.join(' ; '));
    process.exit(reasons.length ? 1 : 0);
  }
}
main();
