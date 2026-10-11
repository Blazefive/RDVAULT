// ========================================
// SECURE SESSION (RBI-like) - Session navigateur isolée
// ========================================
// Lance un navigateur Chromium isolé via Puppeteer
// Injecte les credentials automatiquement (l'utilisateur ne voit jamais le mdp)
// Profil éphémère supprimé à la fermeture
//
// Journalisation : via ./logger uniquement. Jamais de texte de page, de username,
// de mot de passe ni d'URL complète (utiliser logger.safeUrl).
//
// Globaux du contexte de PAGE (navigateur), utilisés uniquement dans les fonctions
// injectées via page.evaluate / evaluateOnNewDocument / waitForFunction : API DOM
// Clipboard et framework ExtJS (Proxmox). Ils n'existent pas côté Node ; on les
// déclare pour ESLint sans changer la logique.
/* global Clipboard, Ext */

const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const logger = require('./logger');
const { baseDomain, MULTI_TENANT_SUFFIXES, hostsMatch, hostnameOf } = require('./hostMatch');
// Motifs d'échec renvoyés au renderer (result.error, affiché tel quel) dans la langue de l'interface
const { tm } = require('./mainI18n');

/**
 * Message d'erreur journalisable : les URLs éventuelles sont réduites à origin+pathname
 * (les erreurs Puppeteer embarquent souvent l'URL complète, query string incluse).
 */
function describeError(err) {
  const msg = String((err && err.message) || err || 'erreur inconnue');
  return msg.replace(/https?:\/\/[^\s"')]+/g, (m) => logger.safeUrl(m)).slice(0, 300);
}

// ========================================
// PROFIL ÉPHÉMÈRE : SUPPRESSION FIABLE (RBI-12)
// ========================================
// Sous Windows, l'événement `disconnected` (fermeture du pipe CDP) arrive alors que le processus
// principal Chromium et ses processus enfants tournent encore et verrouillent le profil : une
// suppression immédiate échoue (EPERM). On attend donc la fin du processus principal (attente
// bornée), puis on supprime avec des réessais bornés. Le profil n'est marqué `cleaned` qu'après une
// suppression RÉUSSIE ; en cas d'échec final, son chemin est mémorisé (pendingProfileDirs) pour un
// nouvel essai (lancement suivant, closeAllSessions) et le démarrage suivant supprime tout profil
// orphelin, quel que soit son âge (cleanupStaleProfiles).
const BROWSER_EXIT_TIMEOUT_MS = 10000;  // attente maximale de la fin du processus principal Chromium
const PROFILE_RM_MAX_RETRIES = 8;       // réessais EPERM / EBUSY / ENOTEMPTY (attente linéaire)
const PROFILE_RM_RETRY_DELAY_MS = 150;  // 150, 300 … 1200 ms : environ 5,4 s d'attente au plus
const PROFILE_RM_RETRY_CODES = new Set(['EPERM', 'EBUSY', 'ENOTEMPTY', 'EACCES', 'EMFILE', 'ENFILE']);

// Profils dont la suppression a échoué malgré les réessais (nouvel essai ultérieur)
const pendingProfileDirs = new Set();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Attend (au plus timeoutMs) la fin du processus principal Chromium lancé par Puppeteer */
function waitForBrowserExit(browser, timeoutMs = BROWSER_EXIT_TIMEOUT_MS) {
  let proc = null;
  try {
    proc = browser && typeof browser.process === 'function' ? browser.process() : null;
  } catch (e) {
    proc = null;
  }
  if (!proc || typeof proc.once !== 'function' || proc.exitCode !== null || proc.signalCode != null) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let timer = null;
    const done = () => {
      clearTimeout(timer);
      proc.removeListener('exit', done);
      resolve();
    };
    timer = setTimeout(done, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    proc.once('exit', done);
  });
}

/**
 * Supprime un dossier de profil avec réessais bornés ; true si supprimé (ou déjà absent).
 * Boucle de réessai explicite : l'option maxRetries de fs.rm réessaie à CHAQUE niveau de
 * l'arborescence, ce qui multiplie les attentes (près d'une minute pour un seul fichier verrouillé).
 */
async function removeProfileDir(dir) {
  for (let attempt = 0; ; attempt++) {
    try {
      await fs.promises.rm(dir, { recursive: true, force: true });
      pendingProfileDirs.delete(dir);
      return true;
    } catch (e) {
      if (!PROFILE_RM_RETRY_CODES.has(e.code) || attempt >= PROFILE_RM_MAX_RETRIES) {
        pendingProfileDirs.add(dir);
        logger.warn(`[RBI] Impossible de supprimer le profil ${path.basename(dir)}: ${describeError(e)} (nouvel essai ultérieur)`);
        return false;
      }
      await sleep(PROFILE_RM_RETRY_DELAY_MS * (attempt + 1));
    }
  }
}

/**
 * true si un Chromium vivant utilise encore ce profil (verrou d'instance du profil).
 * - Windows : Chromium garde « lockfile » ouvert sans partage en suppression : sa suppression
 *   échoue tant qu'il tourne. Un lockfile resté d'un crash se supprime normalement.
 * - POSIX : lien symbolique « SingletonLock » → « hôte-pid » ; vivant si ce pid existe.
 */
function isProfileInUse(dir) {
  if (process.platform === 'win32') {
    try {
      fs.unlinkSync(path.join(dir, 'lockfile'));
      return false;
    } catch (e) {
      return e.code !== 'ENOENT';
    }
  }
  let target;
  try {
    target = fs.readlinkSync(path.join(dir, 'SingletonLock'));
  } catch (e) {
    return false;
  }
  const pid = Number((/-(\d+)$/.exec(target) || [])[1]);
  if (!pid) return true; // format inconnu : prudence
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

/** Nouvel essai de suppression des profils dont la suppression avait échoué (profils libérés) */
async function retryPendingProfiles() {
  for (const dir of [...pendingProfileDirs]) {
    if (isProfileInUse(dir)) continue;
    await removeProfileDir(dir);
  }
}

/**
 * Supprime le profil éphémère d'une session, de façon MÉMORISÉE : le handler `disconnected`,
 * closeSession, closeAllSessions et abortSession partagent la même promesse (pas de double
 * suppression concurrente). `cleaned` ne passe à true qu'après une suppression réussie ; après un
 * échec, l'appel suivant retente. Annule aussi le timer TTL éventuel.
 * @returns {Promise<boolean>} true si le profil est supprimé
 */
function removeSessionProfile(session, sessionId) {
  if (!session) return Promise.resolve(false);
  session.closing = true;
  if (session.ttlTimer) {
    clearTimeout(session.ttlTimer);
    session.ttlTimer = null;
  }
  if (session.cleaned) return Promise.resolve(true);
  if (!session.cleanupPromise) {
    session.cleanupPromise = (async () => {
      if (session.profileDir) {
        await waitForBrowserExit(session.browser);
        if (!(await removeProfileDir(session.profileDir))) {
          session.cleanupPromise = null; // l'appel suivant retentera
          return false;
        }
        logger.debug(`[RBI] Profil éphémère supprimé: ${sessionId}`);
      }
      session.cleaned = true;
      return true;
    })();
  }
  return session.cleanupPromise;
}

// ========================================
// HELPERS EXÉCUTÉS DANS LA PAGE
// ========================================
// Ces fonctions sont sérialisées (fn.toString()) et embarquées dans le corps des
// fonctions passées à page.evaluate() / frame.evaluate() via withPageHelpers().
// Elles doivent être autonomes : aucune référence au module, aucune API Node.
//
// NOTE : on n'utilise volontairement PAS `new Function(src)` CÔTÉ PAGE. La CSP des
// sites de login (GitHub, Google, Microsoft…) interdit généralement eval/new Function
// et ferait échouer l'injection. La fonction est assemblée côté Node puis compilée par
// Runtime.callFunctionOn (CDP), qui n'est pas soumis à la CSP de la page.

/** querySelectorAll récursif incluant les Shadow DOM ouverts */
function deepQueryAll(root, selector) {
  const results = Array.from(root.querySelectorAll(selector));
  root.querySelectorAll('*').forEach((el) => {
    if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
  });
  return results;
}

/** Élément rendu et visible (display/visibility/opacity + dimensions non nulles) */
function isVisible(el) {
  if (!el) return false;
  const style = window.getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
  return el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0;
}

/** Remplit un champ en déclenchant les événements attendus par les frameworks (React/Angular/Vue) */
function fillField(el, value) {
  el.focus();
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
  const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
  if (nativeSetter) {
    nativeSetter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

const PAGE_HELPERS_SRC = [deepQueryAll, isVisible, fillField].map((fn) => fn.toString()).join('\n');

/**
 * Enveloppe `fn` (destinée à page.evaluate / frame.evaluate) dans une fonction dont le
 * corps déclare deepQueryAll / isVisible / fillField. Puppeteer sérialise la fonction
 * retournée (« function anonymous(...) ») et Chromium la compile via CDP ; les arguments
 * de evaluate() sont transmis tels quels à `fn`.
 */
function withPageHelpers(fn) {
  // eslint-disable-next-line no-new-func
  return new Function(`${PAGE_HELPERS_SRC}\nreturn (${fn.toString()}).apply(this, arguments);`);
}

// ========================================
// OVERLAY : PASSAGE DES ACTIONS D'AUTOMATISATION
// ========================================
// L'overlay de chargement bloque la souris (pointer-events:auto) et le clavier (garde
// keydown capturante, installée via evaluateOnNewDocument). Les événements synthétiques
// de Puppeteer (CDP) sont indiscernables de ceux de l'utilisateur : on ouvre donc une
// « fenêtre de passage » le temps d'une action d'automatisation, puis on la referme
// (fail-closed : un overlay ré-injecté après navigation est fermé par défaut).
const OVERLAY_ID = '__rbi_loading_overlay__';

async function withOverlayPassthrough(page, fn) {
  const toggle = async (open) => {
    try {
      await page.evaluate((id, flag) => {
        const ov = document.getElementById(id);
        if (!ov) return;
        ov.dataset.rbiPassthrough = flag ? '1' : '0';
        ov.style.pointerEvents = flag ? 'none' : 'auto';
      }, OVERLAY_ID, open);
    } catch (e) { /* page fermée ou en cours de navigation */ }
  };
  await toggle(true);
  try {
    return await fn();
  } finally {
    await toggle(false);
  }
}

/** Clic Puppeteer (par coordonnées) à travers l'overlay */
function clickThroughOverlay(page, handle, options) {
  return withOverlayPassthrough(page, () => handle.click(options));
}

/**
 * Appui clavier à travers l'overlay.
 * `target` peut être une Page (popup) ou un Frame (qui n'a pas de clavier propre → celui de la page).
 */
function pressThroughOverlay(page, target, key) {
  const keyboard = target && target.keyboard ? target.keyboard : page.keyboard;
  return withOverlayPassthrough(page, () => keyboard.press(key));
}

/** Hostname d'une URL (chaîne vide si invalide) */
function safeHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return '';
  }
}

// ========================================
// SAISIE LIÉE À L'HÔTE DE L'ENTRÉE (RBI-11)
// ========================================
// Un identifiant, un mot de passe ou un code TOTP n'est saisi que dans un document (page, iframe,
// popup) dont l'hôte correspond à celui de l'URL de l'entrée (URL de lancement de la session),
// selon la MÊME règle que l'extension : hostMatch.hostsMatch (hôte identique, domaine parent, même
// domaine de base PSL, domaines équivalents ; suffixes mutualisés traités par locataire ; IP et
// localhost à l'identique). Sinon rien n'est saisi, le refus est journalisé (sans secret) et la
// session de connexion est abandonnée (identifiant / mot de passe) ou le code TOTP n'est pas saisi.
// Le contrôle est fait côté Node (URL de la frame) PUIS dans le document qui exécute la saisie
// (location.hostname) : une navigation survenue entre les deux est détectée.
const FOREIGN_ORIGIN_REASON = 'Page de connexion hors du domaine de l\'entrée';
const JS_NOT_DISABLED_REASON = 'Saisie refusée : JavaScript de la frame de connexion non désactivable';
// Codes stables renvoyés au renderer (traduction : error.rbiForeignOrigin…)
const REFUSAL_CODES = {
  [FOREIGN_ORIGIN_REASON]: 'RBI_FOREIGN_ORIGIN',
  [JS_NOT_DISABLED_REASON]: 'RBI_INJECTION_REFUSED'
};

/** Refus de saisie d'un secret (motif renvoyé à l'utilisateur, jamais de secret) */
class InjectionRefusedError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'InjectionRefusedError';
    this.rbiRefusal = reason;
  }
}

/**
 * true si un secret de l'entrée (URL `entryUrls`, chaîne ou liste : url, website…) peut être saisi
 * dans un document d'URL `targetUrl`. Fonction pure. La cible doit être en http(s) :
 * about:blank, data:, blob:, chrome-error://… sont refusés.
 */
function isInjectionTargetAllowed(entryUrls, targetUrl) {
  let target;
  try {
    target = new URL(String(targetUrl));
  } catch (e) {
    return false;
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') return false;
  const targetHost = target.hostname.toLowerCase();
  if (!targetHost) return false;
  const entries = Array.isArray(entryUrls) ? entryUrls : [entryUrls];
  return entries.some((entry) => {
    const entryHost = typeof entry === 'string' ? hostnameOf(entry) : null;
    return Boolean(entryHost) && hostsMatch(entryHost, targetHost);
  });
}

/** URL courante d'une Page / d'un Frame Puppeteer (chaîne vide si indisponible) */
function targetUrlOf(target) {
  try {
    return String((target && target.url()) || '');
  } catch (e) {
    return '';
  }
}

/** Forme journalisable d'une URL cible (http(s) : origin+pathname ; sinon le seul schéma) ; liste : chaque URL */
function describeTarget(url) {
  if (Array.isArray(url)) return url.map(describeTarget).join(' | ');
  try {
    const u = new URL(url);
    return (u.protocol === 'http:' || u.protocol === 'https:') ? logger.safeUrl(url) : u.protocol;
  } catch (e) {
    return '(sans URL)';
  }
}

/** Journalise un refus de saisie (sans secret) et lève InjectionRefusedError */
function refuseInjection(ctx, targetUrl, what) {
  logger.warn(`[RBI] Saisie ${what} refusée : ${describeTarget(targetUrl)} hors du domaine de l'entrée ${describeTarget(ctx.entryUrl)}`);
  throw new InjectionRefusedError(FOREIGN_ORIGIN_REASON);
}

/**
 * Vérifie (côté Node) que `target` (Page ou Frame) peut recevoir un secret de l'entrée.
 * @returns {string} l'hôte validé, à revérifier dans le document au moment de la saisie
 */
function assertInjectionTarget(ctx, target, what) {
  const targetUrl = targetUrlOf(target);
  if (!isInjectionTargetAllowed(ctx.entryUrl, targetUrl)) refuseInjection(ctx, targetUrl, what);
  return safeHostname(targetUrl);
}

/** true si une frame / popup candidate peut recevoir un secret (sinon journalisé une fois) */
function isCandidateAllowed(ctx, target, what) {
  const targetUrl = targetUrlOf(target);
  if (isInjectionTargetAllowed(ctx.entryUrl, targetUrl)) return true;
  const key = `${what}|${describeTarget(targetUrl)}`;
  if (!ctx.skipped.has(key)) {
    ctx.skipped.add(key);
    logger.warn(`[RBI] ${what} ignoré(e) : ${describeTarget(targetUrl)} hors du domaine de l'entrée ${describeTarget(ctx.entryUrl)}`);
  }
  return false;
}

/**
 * Session CDP propre à la cible (frame hors processus, popup), distincte de celle de la page
 * principale, ou null (même session : cdpClient suffit). `frame.client` est l'accesseur
 * Puppeteer de la session de la frame.
 */
function ownCdpSession(ctx, target) {
  try {
    const frame = typeof target.mainFrame === 'function' ? target.mainFrame() : target;
    const client = frame && frame.client;
    const mainClient = ctx.page.mainFrame().client;
    if (!client || client === mainClient || typeof client.send !== 'function') return null;
    return client;
  } catch (e) {
    return null;
  }
}

/**
 * Exécute fn avec le JavaScript désactivé dans la page principale ET, si la cible a sa propre
 * session CDP (iframe hors processus, popup), dans la cible : Emulation.setScriptExecutionDisabled
 * n'agit que sur la session qui l'envoie. Impossible de désactiver le JS de la cible → refus.
 */
async function withJsDisabledFor(ctx, target, fn) {
  const own = ownCdpSession(ctx, target);
  if (!own) return withJsDisabled(ctx.cdpClient, fn);
  try {
    await own.send('Emulation.setScriptExecutionDisabled', { value: true });
  } catch (e) {
    logger.warn(`[RBI] JavaScript de la frame cible non désactivable (${describeError(e)}) : saisie refusée`);
    throw new InjectionRefusedError(JS_NOT_DISABLED_REASON);
  }
  try {
    return await withJsDisabled(ctx.cdpClient, fn);
  } finally {
    try {
      await own.send('Emulation.setScriptExecutionDisabled', { value: false });
    } catch (e) { /* frame détachée */ }
  }
}

/**
 * Saisie d'une valeur sensible au clavier dans l'élément `handle` :
 * contrôle d'origine du document de l'élément, JavaScript désactivé (page + frame cible),
 * passage overlay, puis frappe caractère par caractère : avant chaque caractère, l'élément est
 * refocalisé et l'hôte de SON document revérifié (une navigation entre deux frappes interrompt
 * la saisie : contexte détruit ou hôte différent).
 */
async function typeSecret(ctx, handle, value, delay = 30, what = 'champ') {
  const frame = handle.frame;
  const expectedHost = assertInjectionTarget(ctx, frame, what);
  const keyboard = frame.page().keyboard;
  return withJsDisabledFor(ctx, frame, () => withOverlayPassthrough(ctx.page, async () => {
    for (const ch of String(value)) {
      const sameHost = await handle.evaluate((el, host) => {
        if (window.location.hostname !== host) return false;
        el.focus();
        return true;
      }, expectedHost);
      if (!sameHost) refuseInjection(ctx, targetUrlOf(frame), what);
      await keyboard.type(ch, { delay });
    }
  }));
}

/**
 * Exécute dans `target` (Page ou Frame) une fonction de remplissage de secrets `fn` (helpers de
 * page disponibles : deepQueryAll, isVisible, fillField), après contrôle d'origine côté Node puis
 * dans le document lui-même, JavaScript de la page et de la cible désactivé.
 */
async function evaluateSecretFill(ctx, target, what, fn, ...args) {
  const expectedHost = assertInjectionTarget(ctx, target, what);
  // eslint-disable-next-line no-new-func
  const guarded = new Function(
    `${PAGE_HELPERS_SRC}\n` +
    'if (window.location.hostname !== arguments[0]) return { __rbiForeignOrigin: true };\n' +
    `return (${fn.toString()}).apply(this, Array.prototype.slice.call(arguments, 1));`
  );
  const result = await withJsDisabledFor(ctx, target, () => target.evaluate(guarded, expectedHost, ...args));
  if (result && result.__rbiForeignOrigin) refuseInjection(ctx, targetUrlOf(target), what);
  return result;
}

/**
 * Trouve le chemin vers Chrome embarqué dans les resources de l'app.
 * Priorité : 1) Chrome dans resources/chrome-rbi  2) Cache Puppeteer par défaut
 */
function getEmbeddedChromePath() {
  // En production : resources/chrome-rbi/chrome.exe
  // En dev : on laisse Puppeteer utiliser son cache par défaut
  const possiblePaths = [];

  // 1) Production : process.resourcesPath pointe vers app.asar/../resources
  if (process.resourcesPath) {
    possiblePaths.push(path.join(process.resourcesPath, 'chrome-rbi', 'chrome.exe'));
  }

  // 2) Dev fallback : à côté du dossier electron/
  possiblePaths.push(path.join(__dirname, '..', 'chrome-rbi', 'chrome.exe'));

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      logger.debug(`[RBI] Chrome embarqué trouvé: ${p}`);
      return p;
    }
  }

  logger.debug('[RBI] Pas de Chrome embarqué, utilisation du cache Puppeteer par défaut');
  return null;
}

// Sessions actives (pour cleanup)
const activeSessions = new Map();

// SÉCURITÉ: Nettoyer les profils éphémères orphelins (crash, fermeture de l'application avant la
// fin du nettoyage, suppression impossible) : TOUS les rbi-* non utilisés, quel que soit leur âge
// (un profil récent contient lui aussi les cookies de session du site). Un profil encore utilisé
// par un Chromium vivant est conservé : isProfileInUse.
// Appelé au démarrage par main.js, UNIQUEMENT par l'instance qui détient le verrou d'instance unique
// (STARTUP-23) : plus au chargement du module, sans quoi une seconde instance (lien rdvault://…)
// pouvait supprimer le profil d'une session que la première instance venait de créer, avant même
// que Chromium ne le verrouille.
// Nom exact des profils créés par launchSecureSession ; tout autre « rbi-* » (ancien format ou
// dossier d'un autre logiciel) garde l'ancienne règle prudente : supprimé seulement après 2 h.
const RBI_PROFILE_NAME_RE = /^rbi-[0-9a-f]{16}$/;
const LEGACY_STALE_AGE_MS = 2 * 60 * 60 * 1000;
function cleanupStaleProfiles() {
  let removed = 0;
  try {
    const tmpDir = os.tmpdir();
    const ownDirs = new Set([...activeSessions.values()].map((s) => s.profileDir).filter(Boolean));
    const entries = fs.readdirSync(tmpDir).filter((e) => e.startsWith('rbi-'));
    for (const entry of entries) {
      const fullPath = path.join(tmpDir, entry);
      if (ownDirs.has(fullPath)) continue;
      try {
        // SÉCURITÉ: Vérifier que ce n'est pas un symlink/junction avant de supprimer
        const lstat = fs.lstatSync(fullPath);
        if (lstat.isSymbolicLink()) {
          logger.warn(`[RBI] Symlink ignoré dans le cleanup: ${entry}`);
          continue;
        }
        if (!lstat.isDirectory()) continue;
        if (!RBI_PROFILE_NAME_RE.test(entry) && Date.now() - lstat.mtimeMs <= LEGACY_STALE_AGE_MS) continue;
        if (isProfileInUse(fullPath)) continue;
        // Une seule passe, sans réessai (appel synchrone au démarrage) : un reste verrouillé
        // sera supprimé au démarrage suivant
        fs.rmSync(fullPath, { recursive: true, force: true });
        pendingProfileDirs.delete(fullPath);
        removed++;
        logger.debug(`[RBI] Profil orphelin supprimé: ${entry}`);
      } catch (e) {
        logger.warn(`[RBI] Profil orphelin non supprimé (${entry}): ${describeError(e)}`);
      }
    }
  } catch (e) { /* ignore */ }
  return removed;
}

// Sélecteurs par défaut pour sites courants
const KNOWN_SELECTORS = {
  // Microsoft / Office 365 / Azure
  'login.microsoftonline.com': {
    username: 'input[name="loginfmt"]',
    password: 'input[name="passwd"]',
    submitUsername: 'input[type="submit"]',
    submitPassword: 'input[type="submit"]',
    twoStep: true
  },
  'login.live.com': {
    username: 'input[name="loginfmt"]',
    password: 'input[name="passwd"]',
    submitUsername: 'input[type="submit"]',
    submitPassword: 'input[type="submit"]',
    twoStep: true
  },
  // Amazon (site marchand)
  'amazon.com': {
    username: 'input[name="email"], input#ap_email',
    password: 'input[name="password"], input#ap_password',
    submitUsername: 'input#continue, span#continue input, input[type="submit"]',
    submitPassword: 'input#signInSubmit, input[type="submit"]',
    twoStep: true
  },
  'amazon.fr': {
    username: 'input[name="email"], input#ap_email',
    password: 'input[name="password"], input#ap_password',
    submitUsername: 'input#continue, span#continue input, input[type="submit"]',
    submitPassword: 'input#signInSubmit, input[type="submit"]',
    twoStep: true
  },
  // AWS
  'signin.aws.amazon.com': {
    username: '#account',
    password: '#password',
    submit: '#signin_button'
  },
  'console.aws.amazon.com': {
    username: '#resolving_input',
    password: '#password',
    submit: '#signin_button'
  },
  // Google
  'accounts.google.com': {
    username: 'input[type="email"]',
    password: 'input[type="password"]',
    submitUsername: '#identifierNext button',
    submitPassword: '#passwordNext button',
    twoStep: true
  },
  // GitHub
  'github.com': {
    username: '#login_field',
    password: '#password',
    submit: 'input[type="submit"]'
  },
  // GitLab
  'gitlab.com': {
    username: '#user_login',
    password: '#user_password',
    submit: 'button[type="submit"]'
  },
  // Proxmox VE (ExtJS based)
  'proxmox': {
    username: 'input[name="username"]',
    password: 'input[name="password"]',
    submit: 'button.x-btn-text, span.x-btn-text',
    special: 'proxmox'
  },
  // VMware vSphere / ESXi (toutes versions)
  'vsphere': {
    username: '#username, input[name="username"], input[id*="username"], input[name="j_username"]',
    password: '#password, input[name="password"], input[id*="password"], input[name="j_password"]',
    submit: '#submit, button[type="submit"], input[type="submit"], #loginButton',
    special: 'esxi'
  },
  // OVH
  'ovh.com': {
    username: 'input[name="account"], input#account',
    password: 'input[name="password"], input#password',
    submit: 'button[type="submit"]'
  },
  // Synology DSM
  'synology': {
    username: 'input[name="username"], input#login_username',
    password: 'input[name="password"], input#login_passwd',
    submit: 'button[type="submit"], #login-btn'
  },
  // Salesforce
  'salesforce.com': {
    username: '#username',
    password: '#password',
    submit: '#Login',
    special: 'salesforce'
  },
  'force.com': {
    username: '#username',
    password: '#password',
    submit: '#Login',
    special: 'salesforce'
  },
  // Default fallback - détection automatique
  'default': {
    username: 'input[type="email"], input[type="text"]:not([type="password"]), input[name*="user" i], input[name*="login" i], input[name*="email" i], input[id*="user" i], input[id*="login" i], input[id*="email" i], input[autocomplete="username"]',
    password: 'input[type="password"]',
    submit: 'button[type="submit"], input[type="submit"], button[name*="login" i], button[id*="login" i], button[class*="login" i]'
  }
};

// Domaines de KNOWN_SELECTORS reconnus par l'hôte (hors profils détectés autrement), du plus
// spécifique au plus général : « signin.aws.amazon.com » passe avant « amazon.com ».
const KNOWN_SELECTOR_DOMAINS = Object.keys(KNOWN_SELECTORS)
  .filter((d) => !['default', 'proxmox', 'vsphere', 'synology'].includes(d))
  .sort((a, b) => b.length - a.length);

/**
 * true si `domain` figure dans `hostname` sur des frontières de libellés : « amazon.com »
 * reconnaît « www.amazon.com » et « amazon.com.au », jamais « notamazon.com ».
 */
function hostHasDomainLabels(hostname, domain) {
  return `.${hostname}.`.includes(`.${domain}.`);
}

/**
 * Sélecteurs connus pour une URL (sans les sélecteurs custom).
 * Retourne toujours une COPIE : les entrées de KNOWN_SELECTORS ne sont jamais mutées.
 */
function detectKnownSelectors(url) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return { ...KNOWN_SELECTORS.default };
  }
  const hostname = parsedUrl.hostname.toLowerCase();
  const port = parsedUrl.port;

  // Détection Proxmox par port (8006 est le port par défaut de Proxmox VE)
  if (port === '8006') {
    return { ...KNOWN_SELECTORS['proxmox'] };
  }

  // Détection ESXi/vSphere par URL patterns
  const fullUrl = url.toLowerCase();
  if (hostname.includes('esxi') || hostname.includes('vsphere') || hostname.includes('vcenter') ||
      (fullUrl.includes('/ui/') && (fullUrl.includes('vsphere') || fullUrl.includes('vcenter'))) ||
      fullUrl.includes('/websdk/') || fullUrl.includes('/host-client/')) {
    return { ...KNOWN_SELECTORS['vsphere'] };
  }

  for (const domain of KNOWN_SELECTOR_DOMAINS) {
    if (hostHasDomainLabels(hostname, domain)) {
      return { ...KNOWN_SELECTORS[domain] };
    }
  }

  return { ...KNOWN_SELECTORS.default };
}

// Clés acceptées depuis le renderer (voir main.js, allowedKeys) → clés internes
const CUSTOM_SELECTOR_KEYS = {
  usernameSelector: 'username',
  passwordSelector: 'password',
  submitSelector: 'submit',
  formSelector: 'form',
  totpSelector: 'totp'
};

/**
 * Trouve les sélecteurs appropriés pour une URL.
 * Retourne toujours une COPIE (jamais une référence vers KNOWN_SELECTORS).
 *
 * @param {string} url
 * @param {Object} [customSelectors] - clés `usernameSelector`, `passwordSelector`,
 *   `submitSelector`, `formSelector`, `totpSelector`
 */
function getSelectorsForUrl(url, customSelectors) {
  const detected = detectKnownSelectors(url);
  if (!customSelectors || typeof customSelectors !== 'object') return detected;

  const custom = {};
  for (const [inputKey, key] of Object.entries(CUSTOM_SELECTOR_KEYS)) {
    const value = customSelectors[inputKey];
    if (typeof value === 'string' && value.trim()) custom[key] = value.trim();
  }
  if (Object.keys(custom).length === 0) return detected;

  // Username ET password fournis → formulaire entièrement décrit par l'utilisateur :
  // login classique, sans les modes twoStep/special (qui ignorent ces sélecteurs).
  if (custom.username && custom.password) {
    return { ...KNOWN_SELECTORS.default, ...custom };
  }
  return { ...detected, ...custom };
}

// Suffixes mutualisés (hostMatch.MULTI_TENANT_SUFFIXES) pour lesquels le filtrage réseau RBI garde la
// Public Suffix List pure (domaine de base « force.com » : tout *.force.com autorisé), faute de pouvoir
// garantir sans org Salesforce réelle la liste des hôtes dont une session Lightning a besoin : outre les
// hôtes de l'org (« monorg.lightning.force.com », « monorg--c.vf.force.com », « monorg.file.force.com »,
// variantes « monorg--sandbox.sandbox.* »), Salesforce sert des ressources PARTAGÉES sous force.com
// (ex. « static.lightning.force.com »). Restreindre à l'hôte de l'org casserait ces sessions.
const RBI_PSL_ONLY_SUFFIXES = new Set(['force.com']);
/** true si le suffixe mutualisé relève d'une exception PSL pure (lui-même ou un sous-suffixe, ex. « lightning.force.com ») */
function isRbiPslOnlySuffix(suffix) {
  for (const s of RBI_PSL_ONLY_SUFFIXES) if (suffix === s || suffix.endsWith('.' + s)) return true;
  return false;
}

/** Suffixe mutualisé (le plus long) dont relève l'hôte — lui-même ou un parent — ou null */
function rbiMultiTenantSuffixOf(host) {
  let found = null;
  for (const s of MULTI_TENANT_SUFFIXES || []) {
    if ((host === s || host.endsWith('.' + s)) && (!found || s.length > found.length)) found = s;
  }
  return found;
}

/**
 * Liste d'hôtes autorisés du filtrage réseau post-login, à partir des URL cible
 * (initiale et post-login) : l'hôte exact + son domaine enregistrable selon la
 * Public Suffix List, domaines privés inclus (tldts via hostMatch.baseDomain).
 * Ainsi « team.github.io » n'ouvre jamais « evil.github.io » (idem herokuapp.com,
 * azurewebsites.net, cloudfront.net…). IP, localhost ou suffixe public nu :
 * baseDomain renvoie null → seul l'hôte exact (et ses sous-domaines) est autorisé.
 *
 * Suffixes MUTUALISÉS absents de la PSL (hostMatch.MULTI_TENANT_SUFFIXES : sharepoint.com,
 * onmicrosoft.com, atlassian.net, cloudapp.azure.com…) : logique « locataire », comme
 * hostMatch.matchingBaseDomain — l'hôte complet est son propre domaine de base, donc
 * « contoso.sharepoint.com » n'ouvre jamais « evil.sharepoint.com » (la PSL donnait
 * « sharepoint.com », voire « azure.com » pour une VM Azure). Le suffixe nu lui-même
 * (« sharepoint.com ») n'est autorisé qu'à l'identique (exactHosts), jamais ses sous-domaines.
 * Exception : RBI_PSL_ONLY_SUFFIXES (force.com, voir ci-dessus) garde la PSL pure.
 */
function buildNetworkAllowlist(urls) {
  const allowedHosts = new Set(); // hôte autorisé ET ses sous-domaines
  const exactHosts = new Set();   // hôte autorisé à l'identique uniquement (suffixe mutualisé nu)
  for (const candidate of urls) {
    const host = safeHostname(candidate);
    if (!host) continue;
    const suffix = rbiMultiTenantSuffixOf(host);
    if (suffix && !isRbiPslOnlySuffix(suffix)) {
      // Locataire : lui-même et ses sous-domaines ; suffixe nu : lui-même seulement
      if (host === suffix) exactHosts.add(host); else allowedHosts.add(host);
      continue;
    }
    allowedHosts.add(host);
    const base = baseDomain(host);
    if (base) allowedHosts.add(base);
  }
  const isAllowedHost = (hostname) => {
    if (exactHosts.has(hostname)) return true;
    for (const allowed of allowedHosts) {
      if (hostname === allowed || hostname.endsWith('.' + allowed)) return true;
    }
    return false;
  };
  return { allowedHosts, exactHosts, isAllowedHost };
}

/**
 * Lance une session sécurisée
 *
 * @param {Object} options
 * @param {string} options.url - URL du site
 * @param {string} options.username - Nom d'utilisateur
 * @param {string} options.password - Mot de passe (jamais affiché à l'utilisateur)
 * @param {string} options.totp - Code TOTP/2FA à injecter après le login (optionnel)
 * @param {Object} options.selectors - Sélecteurs CSS personnalisés (optionnel)
 * @param {Object} options.policies - Politiques de session (optionnel)
 * @returns {Promise<Object>} Session info
 */
const MAX_ACTIVE_SESSIONS = 5;
// Timeout global du processus de login (navigation + injection + vérification)
const GLOBAL_LOGIN_TIMEOUT = 90000;

// Motifs d'abandon : texte interne (français, journalisé, clé de REFUSAL_CODES) → texte renvoyé au renderer
// (result.error, affiché tel quel dans un toast) dans la langue de l'interface (mainI18n). Le français est
// strictement identique au motif interne.
const DOWNLOAD_POLICY_REASON = 'Impossible d\'appliquer la politique de téléchargement (CDP indisponible)';
const FORM_NOT_FOUND_REASON = 'Formulaire de connexion introuvable';
const FIELDS_NOT_FOUND_REASON = 'Champs de connexion introuvables sur la page';
const LOGIN_NOT_CONFIRMED_REASON = 'Connexion non confirmée (délai dépassé)';
const LOGIN_FAILED_REASON = 'Connexion échouée sur la page';
const GLOBAL_TIMEOUT_REASON = `Délai dépassé (${GLOBAL_LOGIN_TIMEOUT / 1000}s) - la page ne répond pas`;
const LOGIN_ERROR_REASON = 'Erreur pendant la connexion';
const NETWORK_RESTRICTION_REASON = 'Impossible d\'activer la restriction réseau';
const LAUNCH_ERROR_REASON = 'Erreur lancement session RBI';
const REASON_MESSAGES = new Map([
  [DOWNLOAD_POLICY_REASON, ['rbi.downloadPolicy']],
  [FOREIGN_ORIGIN_REASON, ['rbi.foreignOrigin']],
  [JS_NOT_DISABLED_REASON, ['rbi.jsNotDisabled']],
  [FORM_NOT_FOUND_REASON, ['rbi.formNotFound']],
  [FIELDS_NOT_FOUND_REASON, ['rbi.fieldsNotFound']],
  [LOGIN_NOT_CONFIRMED_REASON, ['rbi.loginNotConfirmed']],
  [LOGIN_FAILED_REASON, ['rbi.loginFailed']],
  [GLOBAL_TIMEOUT_REASON, ['rbi.globalTimeout', { seconds: GLOBAL_LOGIN_TIMEOUT / 1000 }]],
  [LOGIN_ERROR_REASON, ['rbi.loginError']],
  [NETWORK_RESTRICTION_REASON, ['rbi.networkRestriction']],
  [LAUNCH_ERROR_REASON, ['rbi.launchError']],
]);

/** Texte d'un motif d'abandon dans la langue de l'interface (motif inconnu : renvoyé tel quel) */
function reasonMessage(reason) {
  const entry = REASON_MESSAGES.get(reason);
  return entry ? tm(entry[0], entry[1]) : reason;
}

async function launchSecureSession(options) {
  // SÉCURITÉ: Limiter le nombre de sessions concurrentes (prévient l'épuisement des ressources)
  if (activeSessions.size >= MAX_ACTIVE_SESSIONS) {
    return { success: false, error: tm('rbi.maxSessions', { max: MAX_ACTIVE_SESSIONS }) };
  }

  const { url, username, password, totp, selectors: customSelectors, policies = {} } = options;
  // Adresses de l'entrée (url, et website s'il est renseigné) : référence de toute saisie (RBI-11), même
  // règle que l'extension (secretMatchesHost : url OU website). L'URL de lancement reste `url`.
  const entryUrls = [url, ...(typeof options.website === 'string' && options.website ? [options.website] : [])];

  // SÉCURITÉ: ID de session sans Date.now() pour éviter la prédictibilité temporelle
  const sessionId = `session_${crypto.randomBytes(12).toString('hex')}`;

  logger.info(`[RBI] Lancement session sécurisée: ${sessionId}`);

  // Profils d'anciennes sessions dont la suppression avait échoué : nouvel essai (sans bloquer)
  if (pendingProfileDirs.size > 0) retryPendingProfiles().catch(() => {});

  // ------------------------------------------------------------------
  // État de la session — déclaré AVANT tout lancement pour être visible
  // depuis abortSession() et le catch global (aucune TDZ possible).
  // ------------------------------------------------------------------
  let profileDir = null;
  let browser = null;
  let page = null;
  let cdpClient = null;
  let session = null;          // enregistrement placé dans activeSessions juste après le launch
  let overlayDismissed = false;
  let onFrameNavigated = null;
  let globalTimer = null;

  /**
   * Fermeture propre et idempotente en cas d'échec : browser, profil, entrée activeSessions.
   * Déclarée en `function` (hoistée) et AVANT puppeteer.launch : utilisable à tout moment,
   * y compris si le launch lui-même échoue (aucun Chromium zombie).
   */
  async function abortSession(reason, code) {
    logger.warn(`[RBI] Abandon session ${sessionId} : ${reason}`);
    overlayDismissed = true;
    if (globalTimer) {
      clearTimeout(globalTimer);
      globalTimer = null;
    }
    if (page && onFrameNavigated) {
      try { page.off('framenavigated', onFrameNavigated); } catch (e) { /* ignore */ }
    }
    if (browser) {
      try {
        await browser.close();
      } catch (e) {
        logger.warn(`[RBI] Fermeture browser ${sessionId}: ${describeError(e)}`);
      }
    }
    // Suppression du profil APRÈS la fin de Chromium (réessais bornés, voir removeSessionProfile)
    if (session) {
      await removeSessionProfile(session, sessionId);
    } else if (profileDir) {
      await waitForBrowserExit(browser);
      await removeProfileDir(profileDir);
    }
    activeSessions.delete(sessionId);
    // code : identifiant stable du motif ; error : motif dans la langue de l'interface (journal en français)
    const error = reasonMessage(reason);
    return code ? { success: false, error, code } : { success: false, error };
  }

  try {
    const embeddedChrome = getEmbeddedChromePath();

    // SÉCURITÉ RBI: profil Puppeteer éphémère et isolé, supprimé à la fermeture.
    // Le sandbox Chromium reste ACTIF : sous Windows il repose sur les job objects,
    // les integrity levels et les tokens restreints, et fonctionne sans privilège
    // particulier — pas de --no-sandbox, même avec un Chrome embarqué.
    // Les certificats TLS sont vérifiés normalement : un certificat invalide sur un site
    // cible est une erreur de sécurité, pas un cas à contourner dans un navigateur isolé.
    profileDir = path.join(os.tmpdir(), `rbi-${crypto.randomBytes(8).toString('hex')}`);
    // SÉCURITÉ: Vérifier qu'aucun symlink/junction n'existe déjà à ce chemin
    if (fs.existsSync(profileDir)) {
      throw new Error('Le répertoire de profil existe déjà (attaque symlink potentielle)');
    }
    fs.mkdirSync(profileDir);

    const launchOptions = {
      headless: false,
      defaultViewport: null,
      userDataDir: profileDir,
      pipe: true, // SÉCURITÉ: Communication via pipe au lieu d'un port TCP debugging (élimine le vecteur d'attaque réseau local)
      ...(embeddedChrome ? { executablePath: embeddedChrome } : {}),
      args: [
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--disable-extensions',
        '--disable-plugins',
        '--disable-sync',
        '--disable-translate',
        '--disable-background-networking',
        '--safebrowsing-disable-auto-update',
        '--disable-default-apps',
        '--disable-hang-monitor',
        '--disable-prompt-on-repost',
        '--disable-domain-reliability',
        '--disable-client-side-phishing-detection',
        '--no-first-run',
        '--no-default-browser-check',
        '--window-size=1280,800',
      ]
    };

    browser = await puppeteer.launch(launchOptions);

    // Enregistrement IMMÉDIAT : toute sortie (abort, catch global, TTL, closeAllSessions)
    // retrouve le browser à fermer. SÉCURITÉ: ne PAS stocker username/password ici.
    session = {
      browser,
      page: null,
      url,
      startTime: Date.now(),
      policies,
      profileDir,
      cdpClient: null,
      ttlTimer: null,
      closing: false,         // fermeture engagée (disconnected, close, abort, TTL)
      cleaned: false,         // profil effectivement supprimé
      cleanupPromise: null    // suppression en cours, partagée par tous les chemins de fermeture
    };
    activeSessions.set(sessionId, session);

    // Fermeture (utilisateur, crash, abort, TTL) : nettoyage mémorisé + audit. Le pipe CDP se ferme
    // avant la fin de Chromium : removeSessionProfile attend la fin du processus avant de supprimer.
    browser.on('disconnected', () => {
      const duration = Date.now() - session.startTime;
      logger.info(`[RBI] Session ${sessionId} terminée`);
      removeSessionProfile(session, sessionId).catch(() => {});
      activeSessions.delete(sessionId);
      logger.info(`[RBI] Audit: Session ${sessionId}, durée: ${Math.round(duration / 1000)}s`);
    });

    const pages = await browser.pages();
    page = pages[0] || await browser.newPage();
    session.page = page;

    // SÉCURITÉ: Session CDP persistante — utilisée pour désactiver JS pendant l'injection
    // et pour bloquer les téléchargements si policy active
    try {
      cdpClient = await page.createCDPSession();
      session.cdpClient = cdpClient;
      if (policies.disableDownloads) {
        await cdpClient.send('Browser.setDownloadBehavior', { behavior: 'deny' });
      }
    } catch (e) {
      logger.warn(`[RBI] Impossible de créer la session CDP: ${describeError(e)}`);
      // SÉCURITÉ: Fail-closed — si CDP échoue et que le download blocking est demandé, avorter
      if (policies.disableDownloads) {
        return await abortSession(DOWNLOAD_POLICY_REASON);
      }
    }

    // Configurer la page
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // SÉCURITÉ RBI: Bloquer l'accès aux DevTools (F12, Ctrl+Shift+I/J, Ctrl+U)
    // Couche 1 : Interception clavier (empêche l'ouverture via raccourcis)
    await page.evaluateOnNewDocument(() => {
      document.addEventListener('keydown', (e) => {
        if (e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) ||
            (e.ctrlKey && (e.key === 'u' || e.key === 'U')) ||
            // SÉCURITÉ: Bloquer print (Ctrl+P) et save (Ctrl+S) pour éviter exfiltration
            (e.ctrlKey && (e.key === 'p' || e.key === 'P' || e.key === 's' || e.key === 'S'))) {
          e.preventDefault();
          e.stopPropagation();
          return false;
        }
      }, true);
      // SÉCURITÉ: Bloquer window.print()
      window.print = () => {};
    });

    // Couche 2 : Détection au niveau navigateur (indépendante du JS de la page).
    // Le front-end DevTools est un target de type 'other' (URL devtools://…) : target.page()
    // renvoie null, on le ferme donc via CDP (Target.closeTarget), avec repli sur page().close().
    //
    // LIMITE : cette couche est réactive (best-effort) — DevTools peut être visible quelques
    // dizaines de ms avant fermeture, et certaines ouvertures (menu Chromium, DevTools ancrés
    // dans un target existant) ne créent pas toujours de target dédié. Le blocage réellement
    // fiable se fait hors de ce fichier, par la policy Chromium `DeveloperToolsAvailability=2`
    // (registre HKLM/HKCU\Software\Policies\Chromium) appliquée au Chrome embarqué.
    let browserCdp = null;
    const closeTargetViaCdp = async (target) => {
      const targetId = target._targetId || target._getTargetInfo?.()?.targetId;
      if (!targetId) throw new Error('targetId indisponible');
      try {
        if (cdpClient) {
          await cdpClient.send('Target.closeTarget', { targetId });
          return;
        }
      } catch (e) { /* session page : Target.closeTarget refusé → session browser */ }
      if (!browserCdp) browserCdp = await browser.target().createCDPSession();
      await browserCdp.send('Target.closeTarget', { targetId });
    };
    browser.on('targetcreated', async (target) => {
      let targetUrl = '';
      try { targetUrl = target.url() || ''; } catch (e) { return; }
      if (!targetUrl.startsWith('devtools://')) return;
      logger.warn(`[RBI] Ouverture DevTools détectée (session ${sessionId}) — fermeture`);
      try {
        await closeTargetViaCdp(target);
      } catch (e) {
        try {
          const devtoolsPage = await target.page();
          if (devtoolsPage) await devtoolsPage.close();
          else logger.warn(`[RBI] DevTools : fermeture impossible (${describeError(e)})`);
        } catch (e2) {
          logger.warn(`[RBI] DevTools : fermeture impossible (${describeError(e2)})`);
        }
      }
    });

    // SÉCURITÉ: Bloquer le clipboard (empêche l'exfiltration de credentials via copier-coller).
    // Toujours actif sauf policies.disableClipboard === false explicite (main.js force true).
    // Les patchs portent sur les PROTOTYPES (non configurables) : une page ne peut ni
    // restaurer les méthodes d'origine ni obtenir une autre instance de Clipboard.
    if (policies.disableClipboard !== false) {
      await page.evaluateOnNewDocument(() => {
        const deny = () => Promise.reject(new DOMException('Clipboard disabled', 'NotAllowedError'));
        const lock = (obj, prop, descriptor) => {
          try {
            Object.defineProperty(obj, prop, { ...descriptor, configurable: false });
          } catch (e) { /* déjà verrouillé */ }
        };
        // 1) Clipboard.prototype : writeText/write (exfiltration) + readText/read (injection)
        if (typeof Clipboard !== 'undefined' && Clipboard.prototype) {
          for (const method of ['writeText', 'write', 'readText', 'read']) {
            lock(Clipboard.prototype, method, { value: deny, writable: false, enumerable: true });
          }
        }
        // 2) navigator.clipboard : getter non configurable sur Navigator.prototype → stub figé
        const clipboardStub = Object.freeze({ writeText: deny, write: deny, readText: deny, read: deny });
        lock(Navigator.prototype, 'clipboard', { get: () => clipboardStub, enumerable: true });
        // 3) Document.prototype.execCommand : copy / cut / paste refusés
        const originalExecCommand = Document.prototype.execCommand;
        lock(Document.prototype, 'execCommand', {
          value: function execCommand(command, ...rest) {
            const cmd = String(command).toLowerCase();
            if (cmd === 'copy' || cmd === 'cut' || cmd === 'paste') return false;
            return originalExecCommand.call(this, command, ...rest);
          },
          writable: false,
          enumerable: true
        });
        // 4) Bloquer les événements copy/cut/paste/drag natifs
        for (const evt of ['copy', 'cut', 'paste', 'dragstart', 'drop']) {
          document.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
          }, true);
        }
        // 5) Bloquer le menu contextuel (empêche "Copier" natif de Chromium)
        document.addEventListener('contextmenu', (e) => {
          e.preventDefault();
        }, true);
      });
    }

    // Bloquer ouverture nouveaux onglets si policy
    if (policies.disableNewTabs) {
      await page.evaluateOnNewDocument(() => {
        window.open = () => null;
        // Intercepter les liens target=_blank
        document.addEventListener('click', (e) => {
          const a = e.target.closest('a');
          if (a && (a.target === '_blank' || a.target === '_new')) {
            a.target = '_self';
          }
        }, true);
      });
      // Bloquer la création de nouveaux onglets au niveau Puppeteer
      browser.on('targetcreated', async (target) => {
        if (target.type() === 'page') {
          try {
            const newPage = await target.page();
            if (newPage && newPage !== page) {
              logger.info('[RBI] Nouvel onglet bloqué par policy disableNewTabs');
              await newPage.close();
            }
          } catch (e) { /* ignore */ }
        }
      });
    }

    // ========================================
    // OVERLAY DE CHARGEMENT
    // Masque le contenu pendant l'injection des credentials.
    // pointer-events:auto → la souris de l'utilisateur ne traverse pas l'overlay ;
    // la garde clavier ci-dessous bloque les touches tant que l'overlay est présent.
    // Les actions Puppeteer passent par withOverlayPassthrough().
    // L'overlay est ré-injecté à chaque navigation (redirections login)
    // puis supprimé définitivement une fois le login confirmé.
    // ========================================
    const RBI_OVERLAY_HTML = `
      <div id="${OVERLAY_ID}" tabindex="-1" style="
        position:fixed;top:0;left:0;width:100vw;height:100vh;
        background:#ffffff;z-index:2147483647;pointer-events:auto;cursor:default;user-select:none;
        display:flex;flex-direction:column;align-items:center;justify-content:center;
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      ">
        <div style="width:48px;height:48px;border:4px solid #e0e0e0;border-top-color:#2563eb;border-radius:50%;animation:__rbi_spin__ 0.8s linear infinite"></div>
        <div style="margin-top:24px;font-size:15px;color:#64748b;letter-spacing:0.3px">Connexion en cours...</div>
        <style>@keyframes __rbi_spin__{to{transform:rotate(360deg)}}</style>
      </div>`;

    // Garde clavier (phase de capture, installée avant tout script de page, dans chaque frame) :
    // tant que l'overlay est présent et hors fenêtre de passage, aucune touche n'atteint la page.
    // Dans une frame cross-origin le document top est inaccessible → pas de blocage (limite connue).
    await page.evaluateOnNewDocument((overlayId) => {
      const overlayActive = () => {
        let doc;
        try { doc = window.top.document; } catch (e) { return false; }
        const ov = doc.getElementById(overlayId);
        return Boolean(ov) && ov.dataset.rbiPassthrough !== '1';
      };
      const guard = (e) => {
        if (overlayActive()) {
          e.preventDefault();
          e.stopImmediatePropagation();
        }
      };
      for (const type of ['keydown', 'keypress', 'keyup']) {
        window.addEventListener(type, guard, true);
      }
    }, OVERLAY_ID);

    // Injecter l'overlay à chaque chargement de page (pendant le login)
    const injectOverlayInPage = async () => {
      if (overlayDismissed) return;
      try {
        await page.evaluate((html, id) => {
          if (document.getElementById(id)) return;
          const container = document.body || document.documentElement;
          container.insertAdjacentHTML('beforeend', html);
        }, RBI_OVERLAY_HTML, OVERLAY_ID);
      } catch (e) { /* page fermée ou en cours de navigation */ }
    };

    // Écouter les navigations pour ré-injecter l'overlay pendant le login
    onFrameNavigated = async (frame) => {
      if (overlayDismissed) return;
      if (frame === page.mainFrame()) {
        // Attendre que le DOM soit prêt
        try {
          await frame.waitForSelector('body', { timeout: 5000 });
          await injectOverlayInPage();
        } catch (e) { /* ignore */ }
      }
    };
    page.on('framenavigated', onFrameNavigated);

    // ========================================
    // TIMEOUT GLOBAL : 90s max pour tout le processus login
    // Protège contre les blocages infinis (page crashée, evaluate qui hang, etc.)
    // ========================================
    const globalTimeoutPromise = new Promise((_, reject) => {
      globalTimer = setTimeout(() => reject(new Error('__RBI_GLOBAL_TIMEOUT__')), GLOBAL_LOGIN_TIMEOUT);
    });

    // Sélecteurs effectifs (copie — jamais une référence vers KNOWN_SELECTORS)
    const selectors = getSelectorsForUrl(url, customSelectors);

    try {
      await Promise.race([globalTimeoutPromise, (async () => {
        // Naviguer vers l'URL
        // SÉCURITÉ: Ne pas loguer les query strings (peuvent contenir des tokens/credentials)
        logger.debug(`[RBI] Navigation vers ${logger.safeUrl(url)}`);
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

        // SÉCURITÉ (RBI-11): page d'arrivée (après redirections) hors du domaine de l'entrée →
        // abandon, rien n'est saisi (mêmes règles que l'extension, voir isInjectionTargetAllowed)
        if (!isInjectionTargetAllowed(entryUrls, page.url())) {
          logger.warn(`[RBI] Page d'arrivée ${describeTarget(page.url())} hors du domaine de l'entrée ${describeTarget(entryUrls)}`);
          throw new Error(`__RBI_INJECT_FAIL__${FOREIGN_ORIGIN_REASON}`);
        }

        // S'assurer que l'overlay est bien présent après le chargement initial
        await injectOverlayInPage();

        logger.debug(`[RBI] Profil de sélecteurs: ${selectors.special || (selectors.twoStep ? 'twoStep' : 'classique')}`);

        // Injecter les credentials (l'utilisateur ne voit que l'overlay) — uniquement sur l'hôte de l'entrée
        const injectResult = await injectCredentials(page, username, password, selectors, cdpClient, entryUrls);

        // Saisie refusée (document hors du domaine de l'entrée, JS non désactivable) → abandon
        if (injectResult && injectResult.refused) {
          throw new Error(`__RBI_INJECT_FAIL__${injectResult.refused}`);
        }

        // Si le formulaire n'a pas été trouvé ou les champs pas remplis → échec immédiat
        if (!injectResult || !injectResult.credentialsFilled) {
          const reason = !injectResult?.formFound
            ? FORM_NOT_FOUND_REASON
            : FIELDS_NOT_FOUND_REASON;
          logger.debug(`[RBI] ${reason} - fermeture immédiate`);
          throw new Error(`__RBI_INJECT_FAIL__${reason}`);
        }

        // Injecter le code TOTP si fourni (après soumission du formulaire de login)
        if (totp) {
          await injectTotpCode(page, totp, cdpClient, selectors, entryUrls);
        }

        // Attendre que le login soit confirmé avant de retirer l'overlay
        let loginResult = { success: false, reason: 'unknown' };
        try {
          loginResult = await waitForLoginSuccess(page, url, selectors);
        } catch (e) {
          logger.debug(`[RBI] Erreur waitForLoginSuccess: ${describeError(e)}`);
          loginResult = { success: false, reason: 'exception' };
        }
        logger.info(`[RBI] Login success: ${loginResult.success} (${loginResult.reason})`);

        if (!loginResult.success) {
          const detail = loginResult.reason === 'timeout'
            ? LOGIN_NOT_CONFIRMED_REASON
            : LOGIN_FAILED_REASON;
          throw new Error(`__RBI_INJECT_FAIL__${detail}`);
        }
      })()]);
    } catch (rbiError) {
      const message = String(rbiError?.message || '');
      // Erreurs attendues (formulaire pas trouvé, login échoué, timeout global)
      if (message.startsWith('__RBI_INJECT_FAIL__')) {
        const reason = message.replace('__RBI_INJECT_FAIL__', '');
        return await abortSession(reason, REFUSAL_CODES[reason]);
      }
      if (message === '__RBI_GLOBAL_TIMEOUT__') {
        return await abortSession(GLOBAL_TIMEOUT_REASON);
      }
      // Erreur inattendue (navigation échouée, etc.)
      logger.error(`[RBI] Erreur pendant le login ${sessionId}: ${describeError(rbiError)}`);
      return await abortSession(LOGIN_ERROR_REASON);
    }

    clearTimeout(globalTimer);
    globalTimer = null;

    // Retirer l'overlay de chargement - révéler la page
    if (!overlayDismissed) {
      overlayDismissed = true;
      try { page.off('framenavigated', onFrameNavigated); } catch (e) { /* ignore */ }

      // SÉCURITÉ: Nettoyer les credentials et TOTP du DOM AVANT de retirer l'overlay,
      // dans TOUTES les frames (formulaires de login dans des iframes), Shadow DOM inclus.
      const wipeSecretFields = withPageHelpers(() => {
        const secretSelectors = [
          'input[type="password"]',
          'input[autocomplete="one-time-code"]',
          'input[name*="totp" i]', 'input[name*="otp" i]', 'input[name*="mfa" i]',
          'input[name*="code" i]', 'input[name*="token" i]', 'input[name*="passcode" i]',
          'input[inputmode="numeric"][maxlength="6"]', 'input[type="tel"][maxlength="6"]'
        ];
        deepQueryAll(document, secretSelectors.join(', ')).forEach((el) => {
          el.value = '';
          el.setAttribute('value', '');
        });
      });
      for (const frame of page.frames()) {
        try {
          await frame.evaluate(wipeSecretFields);
        } catch (e) { /* frame détachée, cross-origin ou en navigation */ }
      }

      // SÉCURITÉ: Forcer le garbage collection pour effacer les credentials de la mémoire du process Chrome
      if (cdpClient) {
        try {
          await cdpClient.send('HeapProfiler.collectGarbage');
          logger.debug('[RBI] Garbage collection forcé (nettoyage mémoire credentials)');
        } catch (e) { /* ignore */ }
      }

      try {
        await page.evaluate((id) => {
          const overlay = document.getElementById(id);
          if (overlay) {
            overlay.style.transition = 'opacity 0.3s ease-out';
            overlay.style.opacity = '0';
            setTimeout(() => overlay.remove(), 350);
          }
        }, OVERLAY_ID);
        logger.debug('[RBI] Overlay de chargement retiré');
      } catch (e) {
        logger.debug('[RBI] Impossible de retirer l\'overlay (page peut avoir navigué)');
      }
    }

    // ========================================
    // SÉCURITÉ: Filtrage réseau post-login (fail-closed)
    // TOUTES les requêtes (documents, XHR, scripts, images, fonts, websockets…) sont
    // limitées à l'origine cible : hostname initial, hostname post-login, leurs
    // sous-domaines et le domaine enregistrable associé (Public Suffix List, cf. buildNetworkAllowlist ; jamais un
    // locataire voisin d'un hébergement mutualisé comme sharepoint.com). data:/blob: autorisés (locaux).
    // Toute URL non parsable ou d'un autre schéma est bloquée.
    // L'hôte post-login n'est ajouté que s'il correspond à l'entrée (RBI-11, même règle que la saisie).
    // ========================================
    try {
      const postLoginUrl = page.url();
      const allowlistUrls = [url];
      if (isInjectionTargetAllowed(entryUrls, postLoginUrl)) {
        allowlistUrls.push(postLoginUrl);
      } else {
        logger.warn(`[RBI] Hôte post-login ${describeTarget(postLoginUrl)} hors du domaine de l'entrée : non ajouté au filtrage réseau`);
      }
      const { allowedHosts, exactHosts, isAllowedHost } = buildNetworkAllowlist(allowlistUrls);

      await page.setRequestInterception(true);
      page.on('request', (request) => {
        let parsed;
        try {
          parsed = new URL(request.url());
        } catch (e) {
          // URL invalide → fail-closed
          request.abort('blockedbyclient').catch(() => {});
          return;
        }

        if (parsed.protocol === 'data:' || parsed.protocol === 'blob:') {
          request.continue().catch(() => {});
          return;
        }

        const networkScheme = parsed.protocol === 'https:' || parsed.protocol === 'http:' ||
                              parsed.protocol === 'wss:' || parsed.protocol === 'ws:';
        const hostname = parsed.hostname.toLowerCase();

        if (networkScheme && hostname && isAllowedHost(hostname)) {
          request.continue().catch(() => {});
        } else {
          logger.debug(`[RBI] Requête bloquée (${request.resourceType()}): ${logger.safeUrl(request.url())}`);
          request.abort('blockedbyclient').catch(() => {});
        }
      });

      logger.info(`[RBI] Restriction réseau activée: hôtes autorisés = ${[...allowedHosts, ...[...exactHosts].map((h) => h + ' (exact)')].join(', ')}`);
    } catch (e) {
      logger.error(`[RBI] Impossible d'activer la restriction réseau: ${describeError(e)}`);
      // SÉCURITÉ: Fail-closed — sans filtrage réseau, la session n'est pas isolée
      return await abortSession(NETWORK_RESTRICTION_REASON);
    }

    // TTL si configuré
    if (policies.ttlMinutes && policies.ttlMinutes > 0 && !session.closing && !session.cleaned) {
      session.ttlTimer = setTimeout(() => {
        session.ttlTimer = null;
        logger.info(`[RBI] TTL atteint pour session ${sessionId}`);
        closeSession(sessionId).catch((e) => {
          logger.warn(`[RBI] Erreur fermeture TTL ${sessionId}: ${describeError(e)}`);
        });
      }, policies.ttlMinutes * 60 * 1000);
    }

    return {
      success: true,
      sessionId,
      message: 'Session sécurisée lancée'
    };

  } catch (error) {
    // Catch global : launch échoué, CDP indisponible, exception inattendue…
    // abortSession ferme le browser (s'il existe), supprime le profil et libère la Map.
    logger.error(`[RBI] Erreur lancement session ${sessionId}: ${describeError(error)}`);
    await abortSession(LAUNCH_ERROR_REASON);
    return {
      success: false,
      error: reasonMessage(LAUNCH_ERROR_REASON)
    };
  }
}

/**
 * SÉCURITÉ: Désactive le JavaScript de la page pendant l'exécution de fn.
 * Empêche les event listeners de la page de capturer les credentials injectés.
 * page.evaluate() et page.type() passent par CDP et fonctionnent même avec JS désactivé.
 */
async function withJsDisabled(cdpClient, fn) {
  if (!cdpClient) return await fn();
  try {
    await cdpClient.send('Emulation.setScriptExecutionDisabled', { value: true });
  } catch (e) {
    logger.warn(`[RBI] Impossible de désactiver JS: ${describeError(e)}`);
    return await fn();
  }
  try {
    return await fn();
  } finally {
    try {
      await cdpClient.send('Emulation.setScriptExecutionDisabled', { value: false });
    } catch (e) {
      logger.warn(`[RBI] Impossible de réactiver JS: ${describeError(e)}`);
    }
  }
}

/**
 * Injecte les credentials dans la page
 * Attend jusqu'à 30 secondes que le formulaire apparaisse
 * Gère les dialogs et popups automatiquement
 *
 * SÉCURITÉ (RBI-11) : `entryUrl` (URL de l'entrée = URL de lancement) est la référence de toute
 * saisie : frames et popups d'un autre domaine sont ignorés, et chaque saisie revérifie l'hôte.
 * @returns {Promise<{formFound: boolean, credentialsFilled: boolean, refused?: string}>}
 *   `refused` : motif de refus (document hors du domaine de l'entrée…) → session abandonnée
 */
async function injectCredentials(page, username, password, initialSelectors, cdpClient, entryUrl) {
  // Copie locale : les sélecteurs peuvent être remplacés après une redirection
  let selectors = { ...initialSelectors };
  const startHostname = safeHostname(page.url());
  // Contexte de saisie : page principale, session CDP, URL de référence, refus déjà journalisés
  const ctx = { page, cdpClient, entryUrl, skipped: new Set() };
  try {
    // Gérer les dialogs (alertes, confirms, prompts)
    page.on('dialog', async dialog => {
      // SÉCURITÉ: Dismiss au lieu d'accept pour éviter que la page exploite l'auto-confirmation
      logger.debug(`[RBI] Dialog détecté: ${dialog.type()}`);
      await dialog.dismiss();
    });

    // ========================================
    // ÉTAPE 0 : Chercher un bouton "Login" / "Sign in" qui affiche le formulaire
    // ========================================
    // Beaucoup de sites affichent d'abord une landing page avec un lien/bouton
    // qu'il faut cliquer avant que le formulaire de login n'apparaisse
    // Recherche profonde incluant Shadow DOM
    const hasLoginForm = await page.evaluate(withPageHelpers(() =>
      deepQueryAll(document, 'input[type="password"]').some(isVisible)
    ));

    if (!hasLoginForm) {
      logger.debug('[RBI] Pas de formulaire visible, recherche d\'un bouton Login/Sign in...');

      const clicked = await page.evaluate(withPageHelpers(() => {
        const keywords = [
          'sign in', 'signin', 'log in', 'login', 'connexion',
          'se connecter', 'connecter', 'mon compte', 'my account',
          'espace client', 'client area', 'member login', 'user login',
          'accéder', 'access', 'enter', 'entrer', 'identifier',
          's\'identifier', 'authentification', 'authenticate'
        ];

        // Chercher dans les liens, boutons, et éléments cliquables
        const elements = document.querySelectorAll('a, button, [role="button"], [role="link"], span[onclick], div[onclick], li a, nav a, header a');
        for (const el of elements) {
          const text = (el.innerText || el.textContent || el.value || '').toLowerCase().trim();
          const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
          const title = (el.getAttribute('title') || '').toLowerCase();
          const href = (el.getAttribute('href') || '').toLowerCase();

          if (!isVisible(el)) continue;

          const matchText = keywords.some(kw => text === kw || text.includes(kw));
          const matchAria = keywords.some(kw => ariaLabel.includes(kw));
          const matchTitle = keywords.some(kw => title.includes(kw));
          const matchHref = href.includes('login') || href.includes('signin') || href.includes('auth') || href.includes('connexion');

          if (matchText || matchAria || matchTitle || matchHref) {
            el.click();
            return true;
          }
        }
        return false;
      }));

      if (clicked) {
        logger.debug('[RBI] Bouton Login/Sign in cliqué');
        // Attendre la navigation ou le chargement du formulaire
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
        await new Promise(r => setTimeout(r, 1500));

        // SÉCURITÉ (RBI-11): le lien cliqué mène hors du domaine de l'entrée → abandon, rien saisi
        const newUrl = page.url();
        if (!isInjectionTargetAllowed(entryUrl, newUrl)) {
          refuseInjection(ctx, newUrl, 'après le clic « Sign in »');
        }

        // Mettre à jour les sélecteurs si l'URL a changé (ex: redirection vers login.salesforce.com)
        if (safeHostname(newUrl) !== startHostname) {
          logger.debug(`[RBI] URL changée: ${logger.safeUrl(newUrl)}, mise à jour sélecteurs`);
          selectors = getSelectorsForUrl(newUrl);
        }
      } else {
        logger.debug('[RBI] Aucun bouton Login/Sign in trouvé');
      }
    } else {
      logger.debug('[RBI] Formulaire de login déjà visible');
    }

    // Gestion spéciale Proxmox (ExtJS) - AVANT la détection générique
    // Car ExtJS rend les inputs de manière non-standard
    if (selectors.special === 'proxmox') {
      logger.debug('[RBI] Mode spécial Proxmox (ExtJS)');

      try {
        // Attendre que ExtJS soit chargé et le formulaire prêt
        await page.waitForFunction(() => {
          return typeof Ext !== 'undefined' && Ext.ComponentQuery && Ext.ComponentQuery.query('field[name=username]').length > 0;
        }, { timeout: 20000 });

        logger.debug('[RBI] Proxmox: ExtJS chargé, formulaire détecté');
        await new Promise(r => setTimeout(r, 1000)); // Laisser ExtJS finir le rendu

        // Utiliser l'API ExtJS pour remplir les champs (JS page désactivé pendant injection,
        // hôte de la page vérifié : RBI-11)
        const fillResult = await evaluateSecretFill(ctx, page, 'Proxmox', (user, pass) => {
          const result = { username: false, password: false };

          const usernameField = Ext.ComponentQuery.query('field[name=username]')[0];
          const passwordField = Ext.ComponentQuery.query('field[name=password]')[0];

          if (usernameField) {
            usernameField.setValue(user);
            usernameField.fireEvent('change', usernameField, user);
            result.username = true;
          }
          if (passwordField) {
            passwordField.setValue(pass);
            passwordField.fireEvent('change', passwordField, pass);
            result.password = true;
          }

          return result;
        }, username, password);

        logger.debug(`[RBI] Proxmox: fill user:${fillResult.username ? 'ok' : 'fail'}, pass:${fillResult.password ? 'ok' : 'fail'}`);

        await new Promise(r => setTimeout(r, 500));

        // Soumettre le formulaire via ExtJS
        const clicked = await page.evaluate(() => {
          // Méthode 1: bouton par reference
          const loginBtns = Ext.ComponentQuery.query('button[reference=loginButton]');
          if (loginBtns.length > 0) {
            const btn = loginBtns[0];
            if (btn.el && btn.el.dom) btn.el.dom.click();
            return 'reference';
          }

          // Méthode 2: chercher la fenêtre de login et soumettre
          const loginWindows = Ext.ComponentQuery.query('window[title]');
          for (const win of loginWindows) {
            const title = (win.getTitle?.() || '').toLowerCase();
            if (title.includes('login') || title.includes('connexion') || title.includes('auth')) {
              const buttons = win.query('button');
              for (const btn of buttons) {
                const text = (btn.getText?.() || '').toLowerCase();
                if (text.includes('login') || text.includes('connexion') || text.includes('sign') || text.includes('connect')) {
                  if (btn.el && btn.el.dom) btn.el.dom.click();
                  return 'window-button';
                }
              }
            }
          }

          // Méthode 3: tous les boutons ExtJS
          const allButtons = Ext.ComponentQuery.query('button');
          for (const btn of allButtons) {
            const text = (btn.getText?.() || '').toLowerCase();
            if (text.includes('login') || text.includes('connexion') || text.includes('se connecter') || text.includes('sign in')) {
              if (btn.el && btn.el.dom) btn.el.dom.click();
              return 'text-search';
            }
          }

          return null;
        });

        if (clicked) {
          logger.debug(`[RBI] Proxmox: Login soumis (via ${clicked})`);
        } else {
          // Fallback DOM : chercher et cliquer le bouton dans le HTML
          logger.debug('[RBI] Proxmox: fallback clic DOM');
          const allElements = await page.$$('a, button, span, div');
          for (const el of allElements) {
            const text = await page.evaluate(e => (e.innerText || '').trim().toLowerCase(), el);
            if (text === 'login' || text === 'se connecter' || text === 'connexion') {
              await clickThroughOverlay(page, el);
              logger.debug('[RBI] Proxmox: bouton login cliqué via DOM');
              break;
            }
          }
        }

        logger.debug('[RBI] Proxmox: injection terminée');
        return { formFound: true, credentialsFilled: fillResult.username || fillResult.password };
      } catch (proxmoxError) {
        if (proxmoxError instanceof InjectionRefusedError) throw proxmoxError;
        logger.debug(`[RBI] Proxmox ExtJS erreur: ${describeError(proxmoxError)}`);
        logger.debug('[RBI] Tentative avec méthode standard...');
      }
    }

    // Gestion spéciale ESXi / vSphere (toutes versions)
    if (selectors.special === 'esxi') {
      logger.debug('[RBI] Mode spécial ESXi/vSphere');

      try {
        // ESXi 6.7 utilise un client web qui peut charger le formulaire
        // dans un iframe, un Shadow DOM, ou après un délai JS important.
        // On utilise une approche multi-stratégie.

        let filled = false;

        for (let attempt = 0; attempt < 15 && !filled; attempt++) {
          logger.debug(`[RBI] ESXi: tentative ${attempt + 1}/15`);

          // Stratégie 1: Chercher dans la page principale (ESXi 7/8, vCenter)
          // Chercher tous les inputs y compris dans le Shadow DOM (helpers deepQueryAll/isVisible/fillField)
          // Hôte de la page vérifié avant et pendant la saisie (RBI-11)
          filled = await evaluateSecretFill(ctx, page, 'ESXi', (user, pass) => {
            // Chercher les champs avec plusieurs stratégies
            const userSelectors = [
              '#username', 'input[name="username"]', 'input[name="j_username"]',
              'input[id*="username" i]', 'input[placeholder*="user" i]',
              'input[type="text"]:not([style*="display: none"])',
              'input[type="email"]', 'input[autocomplete="username"]'
            ];
            const passSelectors = [
              '#password', 'input[name="password"]', 'input[name="j_password"]',
              'input[id*="password" i]', 'input[type="password"]'
            ];

            let userField = null;
            let passField = null;

            for (const sel of userSelectors) {
              const fields = deepQueryAll(document, sel);
              userField = fields.find(isVisible);
              if (userField) break;
            }
            for (const sel of passSelectors) {
              const fields = deepQueryAll(document, sel);
              passField = fields.find(isVisible);
              if (passField) break;
            }

            if (userField && passField) {
              fillField(userField, user);
              fillField(passField, pass);
              return true;
            }
            return false;
          }, username, password);

          if (filled) {
            logger.debug('[RBI] ESXi: champs remplis dans la page principale');
            break;
          }

          // Stratégie 2: Chercher dans les iframes (ESXi 6.7 embedded host client)
          // SÉCURITÉ (RBI-11): uniquement les iframes de l'hôte de l'entrée
          const frames = page.frames();
          for (const frame of frames) {
            if (frame === page.mainFrame()) continue;
            if (!isCandidateAllowed(ctx, frame, 'iframe')) continue;
            try {
              filled = await evaluateSecretFill(ctx, frame, 'ESXi (iframe)', (user, pass) => {
                const userField = document.querySelector('#username, input[name="username"], input[type="text"]');
                const passField = document.querySelector('#password, input[name="password"], input[type="password"]');

                if (userField && isVisible(userField) && passField && isVisible(passField)) {
                  fillField(userField, user);
                  fillField(passField, pass);
                  return true;
                }
                return false;
              }, username, password);

              if (filled) {
                logger.debug(`[RBI] ESXi: champs remplis dans iframe: ${logger.safeUrl(frame.url())}`);
                break;
              }
            } catch (e) { /* iframe cross-origin */ }
          }

          if (!filled) {
            await new Promise(r => setTimeout(r, 2000));
          }
        }

        if (filled) {
          await new Promise(r => setTimeout(r, 500));

          // Soumettre - chercher le bouton submit partout (page + iframes + shadow DOM)
          let submitted = false;

          submitted = await page.evaluate(withPageHelpers(() => {
            // Chercher le bouton submit
            const submitSelectors = [
              '#submit', '#loginButton', 'button[type="submit"]', 'input[type="submit"]',
              'button[id*="login" i]', 'button[id*="submit" i]'
            ];
            for (const sel of submitSelectors) {
              const btns = deepQueryAll(document, sel);
              const btn = btns.find(isVisible);
              if (btn) { btn.click(); return true; }
            }

            // Chercher par texte
            const keywords = ['log in', 'login', 'sign in', 'submit', 'se connecter', 'connexion'];
            const allBtns = deepQueryAll(document, 'button, input[type="submit"], a[role="button"]');
            for (const btn of allBtns) {
              if (!isVisible(btn)) continue;
              const text = (btn.innerText || btn.value || '').toLowerCase().trim();
              if (keywords.some(kw => text.includes(kw))) {
                btn.click();
                return true;
              }
            }
            return false;
          }));

          if (!submitted) {
            // Essayer dans les iframes
            for (const frame of page.frames()) {
              if (frame === page.mainFrame()) continue;
              try {
                submitted = await frame.evaluate(() => {
                  const btn = document.querySelector('#submit, button[type="submit"], input[type="submit"], #loginButton');
                  if (btn) { btn.click(); return true; }
                  return false;
                });
                if (submitted) break;
              } catch (e) { /* ignore */ }
            }
          }

          if (!submitted) {
            await pressThroughOverlay(page, page, 'Enter');
            submitted = true;
          }

          logger.debug(`[RBI] ESXi: soumis=${submitted}`);
        } else {
          logger.debug('[RBI] ESXi: champs non trouvés');
        }

        logger.debug('[RBI] ESXi: injection terminée');
        return { formFound: true, credentialsFilled: filled };
      } catch (esxiError) {
        if (esxiError instanceof InjectionRefusedError) throw esxiError;
        logger.debug(`[RBI] ESXi erreur: ${describeError(esxiError)}`);
        logger.debug('[RBI] Tentative avec méthode standard...');
      }
    }

    // Gestion spéciale Salesforce
    if (selectors.special === 'salesforce') {
      logger.debug('[RBI] Mode spécial Salesforce');

      try {
        // Salesforce rend le formulaire via JS - attendre qu'il soit prêt
        // Chercher dans la page ET dans les iframes
        let sf = page;

        // Attendre le formulaire dans la page principale
        let found = false;
        for (let i = 0; i < 10; i++) {
          try {
            await page.waitForSelector('#username, input[name="username"]', { visible: true, timeout: 2000 });
            found = true;
            sf = page;
            logger.debug('[RBI] Salesforce: formulaire trouvé dans la page principale');
            break;
          } catch (e) {
            // Chercher dans les iframes (SÉCURITÉ RBI-11 : hôte de l'entrée uniquement)
            for (const frame of page.frames()) {
              if (frame === page.mainFrame()) continue;
              if (!isCandidateAllowed(ctx, frame, 'iframe')) continue;
              try {
                const el = await frame.$('#username, input[name="username"]');
                if (el) {
                  found = true;
                  sf = frame;
                  logger.debug(`[RBI] Salesforce: formulaire trouvé dans iframe: ${logger.safeUrl(frame.url())}`);
                  break;
                }
              } catch (fe) { /* ignore */ }
            }
            if (found) break;
            logger.debug(`[RBI] Salesforce: attente formulaire... (${i + 1}/10)`);
            await new Promise(r => setTimeout(r, 1000));
          }
        }

        if (!found) {
          logger.debug('[RBI] Salesforce: formulaire non trouvé, tentative méthode standard');
        } else {
          // Attendre un peu que tout soit stable
          await new Promise(r => setTimeout(r, 500));

          // Remplir via JavaScript (plus fiable que type() pour Salesforce)
          // SÉCURITÉ: Fill wrappé (JS désactivé, hôte vérifié : RBI-11), submit séparé (JS nécessaire pour le clic)
          const fillResult = await evaluateSecretFill(ctx, sf, 'Salesforce', (user, pass) => {
            const result = { username: false, password: false };

            // Chercher le champ username par plusieurs sélecteurs
            const userEl = document.querySelector('#username') ||
                          document.querySelector('input[name="username"]') ||
                          document.querySelector('input[type="text"]');
            if (userEl) {
              fillField(userEl, user);
              result.username = true;
            }

            // Chercher le champ password
            const passEl = document.querySelector('#password') ||
                          document.querySelector('input[name="pw"]') ||
                          document.querySelector('input[type="password"]');
            if (passEl) {
              fillField(passEl, pass);
              result.password = true;
            }

            return result;
          }, username, password);

          // Soumettre (JS réactivé — le clic a besoin des handlers de la page)
          const submitted = await sf.evaluate(() => {
            const loginBtn = document.querySelector('#Login') ||
                            document.querySelector('input[type="submit"]') ||
                            document.querySelector('button[type="submit"]');
            if (loginBtn) {
              loginBtn.click();
              return true;
            }
            return false;
          });

          logger.debug(`[RBI] Salesforce: fill user:${fillResult.username ? 'ok' : 'fail'}, pass:${fillResult.password ? 'ok' : 'fail'}, submit:${submitted}`);

          if (!submitted) {
            // Fallback: Enter
            await pressThroughOverlay(page, page, 'Enter');
            logger.debug('[RBI] Salesforce: soumis via Enter');
          }

          logger.debug('[RBI] Salesforce: injection terminée');
          return { formFound: true, credentialsFilled: fillResult.username || fillResult.password };
        }
      } catch (sfError) {
        if (sfError instanceof InjectionRefusedError) throw sfError;
        logger.debug(`[RBI] Salesforce erreur: ${describeError(sfError)}`);
        logger.debug('[RBI] Tentative avec méthode standard...');
      }
    }

    // Attendre que le formulaire soit chargé (jusqu'à 30 secondes)
    // Cherche dans la page principale ET dans les iframes
    logger.debug('[RBI] Recherche du formulaire de login...');

    let formFound = false;
    let targetFrame = page; // Par défaut, on travaille sur la page principale
    let attempts = 0;
    const maxAttempts = 6; // 6 x 5s = 30s max
    // Sélecteur custom (formSelector) en tête : prioritaire sur l'auto-détection
    const formSelector = (selectors.form ? `${selectors.form}, ` : '') +
      'input[type="password"], input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="email"]';

    while (!formFound && attempts < maxAttempts) {
      // 1. Chercher dans la page principale (incluant Shadow DOM)
      try {
        // D'abord essayer le waitForSelector standard
        await page.waitForSelector(formSelector, { timeout: 2000, visible: true });
        formFound = true;
        targetFrame = page;
        logger.debug('[RBI] Formulaire détecté dans la page principale');
      } catch (e) {
        // Chercher dans le Shadow DOM
        const inShadow = await page.evaluate(withPageHelpers(() =>
          deepQueryAll(document, 'input[type="password"], input[type="text"], input[type="email"]').some(isVisible)
        ));

        if (inShadow) {
          formFound = true;
          targetFrame = page;
          logger.debug('[RBI] Formulaire détecté dans Shadow DOM');
        } else {
          // 2. Chercher dans les iframes (récursivement)
          // SÉCURITÉ (RBI-11): seulement les iframes de l'hôte de l'entrée (jamais un widget tiers)
          try {
            const frames = page.frames();
            logger.debug(`[RBI] ${frames.length} frames trouvés, recherche dans les iframes...`);

            for (const frame of frames) {
              if (frame === page.mainFrame()) continue;
              if (!isCandidateAllowed(ctx, frame, 'iframe')) continue;
              try {
                const input = await frame.$(formSelector);
                if (input) {
                  formFound = true;
                  targetFrame = frame;
                  logger.debug(`[RBI] Formulaire détecté dans iframe: ${logger.safeUrl(frame.url())}`);
                  break;
                }
              } catch (frameErr) {
                // iframe inaccessible (cross-origin), on ignore
              }
            }
          } catch (framesErr) {
            // Ignore
          }
        }
      }

      // 3. Chercher les popups/nouvelles pages ouvertes par le navigateur (hôte de l'entrée uniquement)
      if (!formFound) {
        try {
          const allPages = await page.browser().pages();
          for (const p of allPages) {
            if (p === page) continue;
            if (!isCandidateAllowed(ctx, p, 'popup')) continue;
            try {
              const hasForm = await p.$(formSelector);
              if (hasForm) {
                formFound = true;
                targetFrame = p;
                logger.debug(`[RBI] Formulaire détecté dans popup: ${logger.safeUrl(p.url())}`);
                break;
              }
            } catch (e) { /* ignore */ }
          }
        } catch (e) { /* ignore */ }
      }

      if (!formFound) {
        attempts++;
        logger.debug(`[RBI] Formulaire non trouvé, tentative ${attempts}/${maxAttempts}...`);

        // Cliquer sur des boutons courants qui pourraient révéler le formulaire
        try {
          const loginButtons = await page.$$('button, a, [role="button"]');
          for (const btn of loginButtons.slice(0, 5)) {
            const text = await page.evaluate(el => el.innerText?.toLowerCase() || '', btn);
            if (text.includes('login') || text.includes('connexion') || text.includes('sign in') || text.includes('se connecter')) {
              logger.debug('[RBI] Clic sur un bouton de type login');
              await clickThroughOverlay(page, btn).catch(() => {});
              await new Promise(r => setTimeout(r, 2000));
              break;
            }
          }
        } catch (clickErr) {
          // Ignore
        }

        // Attendre un peu pour les chargements dynamiques
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    if (!formFound) {
      logger.debug('[RBI] Aucun formulaire trouvé après 30s');
      return { formFound: false, credentialsFilled: false };
    }

    // À partir d'ici, on utilise targetFrame au lieu de page pour interagir avec le formulaire
    // Utiliser targetFrame pour toutes les interactions avec le formulaire
    const f = targetFrame;

    let credentialsFilled = false;

    if (selectors.twoStep) {
      // Login en deux étapes (Microsoft, Google, etc.)
      logger.debug('[RBI] Login deux étapes détecté');

      const clickSelector = async (selector) => {
        const btn = await f.$(selector);
        if (!btn) throw new Error('Bouton de soumission introuvable');
        await clickThroughOverlay(page, btn);
      };

      // Étape 1: Username
      const usernameEl = await f.waitForSelector(selectors.username, { visible: true, timeout: 10000 });
      await typeSecret(ctx, usernameEl, username, 50, 'identifiant');

      if (selectors.submitUsername) {
        await clickSelector(selectors.submitUsername);
        if (f === page) {
          await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {});
        }
        await new Promise(r => setTimeout(r, 1000));
      }

      // Étape 2: Password
      const passwordEl = await f.waitForSelector(selectors.password, { visible: true, timeout: 10000 });
      await typeSecret(ctx, passwordEl, password, 50, 'mot de passe');
      credentialsFilled = true;

      if (selectors.submitPassword) {
        await clickSelector(selectors.submitPassword);
      }

    } else {
      // Login classique (une seule page)
      logger.debug('[RBI] Login classique');

      let usernameFilledOk = false;
      let passwordFilledOk = false;

      // 1. D'abord essayer les sélecteurs connus (plus fiable pour les sites connus)
      if (selectors.username) {
        try {
          await f.waitForSelector(selectors.username, { visible: true, timeout: 3000 });
          const el = await f.$(selectors.username);
          if (el) {
            await clickThroughOverlay(page, el, { clickCount: 3 });
            await typeSecret(ctx, el, username, 30, 'identifiant');
            usernameFilledOk = true;
            logger.debug('[RBI] Username rempli via sélecteur connu');
          }
        } catch (e) {
          if (e instanceof InjectionRefusedError) throw e;
          logger.debug('[RBI] Sélecteur username non trouvé, fallback auto-détection');
        }
      }

      if (selectors.password) {
        try {
          await f.waitForSelector(selectors.password, { visible: true, timeout: 3000 });
          const el = await f.$(selectors.password);
          if (el) {
            await clickThroughOverlay(page, el, { clickCount: 3 });
            await typeSecret(ctx, el, password, 30, 'mot de passe');
            passwordFilledOk = true;
            logger.debug('[RBI] Password rempli via sélecteur connu');
          }
        } catch (e) {
          if (e instanceof InjectionRefusedError) throw e;
          logger.debug('[RBI] Sélecteur password non trouvé, fallback auto-détection');
        }
      }

      // 2. Fallback : auto-détection des champs si sélecteurs n'ont pas marché
      //    Cherche dans le DOM normal, le Shadow DOM, et les popups/modals
      if (!usernameFilledOk || !passwordFilledOk) {
        // D'abord essayer la méthode Puppeteer classique
        const inputs = await f.$$('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
        logger.debug(`[RBI] Auto-détection: ${inputs.length} champs input trouvés (DOM normal)`);

        for (const input of inputs) {
          const info = await f.evaluate(withPageHelpers((el) => ({ type: el.type, visible: isVisible(el) })), input);

          if (!info.visible) continue;

          if (!passwordFilledOk && info.type === 'password') {
            await clickThroughOverlay(page, input, { clickCount: 3 });
            await typeSecret(ctx, input, password, 30, 'mot de passe');
            passwordFilledOk = true;
            logger.debug('[RBI] Password rempli via auto-détection');
          } else if (!usernameFilledOk && (info.type === 'text' || info.type === 'email')) {
            await clickThroughOverlay(page, input, { clickCount: 3 });
            await typeSecret(ctx, input, username, 30, 'identifiant');
            usernameFilledOk = true;
            logger.debug('[RBI] Username rempli via auto-détection');
          }
        }

        // Si toujours pas trouvé, chercher dans le Shadow DOM et les popups/modals
        if (!usernameFilledOk || !passwordFilledOk) {
          logger.debug('[RBI] Auto-détection étendue : Shadow DOM, popups, modals...');
          const deepResult = await evaluateSecretFill(ctx, f, 'recherche étendue', (user, pass, needUser, needPass) => {
            const result = { username: false, password: false };

            // Chercher les champs password dans Shadow DOM
            if (needPass) {
              const passFields = deepQueryAll(document, 'input[type="password"]');
              const passField = passFields.find(isVisible);
              if (passField) {
                fillField(passField, pass);
                result.password = true;
              }
            }

            // Chercher les champs username dans Shadow DOM
            if (needUser) {
              const userSelectors = [
                'input[type="text"]', 'input[type="email"]',
                'input[name*="user" i]', 'input[name*="login" i]',
                'input[id*="user" i]', 'input[autocomplete="username"]',
                'input[placeholder*="user" i]', 'input[placeholder*="login" i]',
                'input[placeholder*="email" i]', 'input[placeholder*="identifiant" i]'
              ];
              for (const sel of userSelectors) {
                const fields = deepQueryAll(document, sel);
                const field = fields.find(el => isVisible(el) && el.type !== 'password');
                if (field) {
                  fillField(field, user);
                  result.username = true;
                  break;
                }
              }
            }

            return result;
          }, username, password, !usernameFilledOk, !passwordFilledOk);

          if (deepResult.username) {
            usernameFilledOk = true;
            logger.debug('[RBI] Username rempli via Shadow DOM/deep search');
          }
          if (deepResult.password) {
            passwordFilledOk = true;
            logger.debug('[RBI] Password rempli via Shadow DOM/deep search');
          }
        }
      }

      // ========================================
      // DÉTECTION LOGIN 2 ÉTAPES NON RECONNU
      // Si username rempli mais pas de champ password visible,
      // c'est probablement un login 2 étapes : cliquer Next puis attendre le password.
      // ========================================
      if (usernameFilledOk && !passwordFilledOk) {
        logger.debug('[RBI] Username rempli mais pas de password visible - tentative login 2 étapes auto');

        // Chercher et cliquer un bouton Next/Suivant/Continue
        const clickedNext = await f.evaluate(withPageHelpers(() => {
          const nextKeywords = [
            'next', 'suivant', 'continue', 'continuer', 'submit',
            'valider', 'log in', 'login', 'sign in', 'se connecter',
            'connexion', 'proceed', 'go', 'ok', 'enter'
          ];

          // Chercher bouton submit / next
          const submitBtn = document.querySelector('button[type="submit"], input[type="submit"]');
          if (submitBtn && isVisible(submitBtn)) {
            submitBtn.click();
            return true;
          }

          // Chercher par texte
          const clickables = deepQueryAll(document, 'button, input[type="submit"], input[type="button"], a[role="button"], [role="button"]');
          for (const el of clickables) {
            const text = (el.innerText || el.value || '').toLowerCase().trim();
            if (isVisible(el) && nextKeywords.some(kw => text === kw || text.includes(kw))) {
              el.click();
              return true;
            }
          }
          return false;
        }));

        if (clickedNext) {
          logger.debug('[RBI] Bouton Next/Submit cliqué');
        } else {
          // Fallback: Enter pour soumettre l'étape email (f peut être un Frame : clavier de la page)
          await pressThroughOverlay(page, f, 'Enter');
          logger.debug('[RBI] Enter pressé pour passer à l\'étape suivante');
        }

        // Attendre que le champ password apparaisse (navigation ou rendu JS)
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
        await new Promise(r => setTimeout(r, 1500));

        // Chercher le champ password maintenant visible
        for (let attempt = 0; attempt < 8 && !passwordFilledOk; attempt++) {
          // Méthode Puppeteer
          try {
            const passInput = await f.$('input[type="password"]');
            if (passInput) {
              const isVis = await f.evaluate(withPageHelpers((el) => isVisible(el)), passInput);
              if (isVis) {
                await clickThroughOverlay(page, passInput, { clickCount: 3 });
                await typeSecret(ctx, passInput, password, 30, 'mot de passe');
                passwordFilledOk = true;
                logger.debug('[RBI] Password rempli après étape 2 (auto-détecté)');
                break;
              }
            }
          } catch (e) {
            if (e instanceof InjectionRefusedError) throw e;
          }

          // Deep search (Shadow DOM)
          const deepPass = await evaluateSecretFill(ctx, f, 'mot de passe (étape 2)', (pass) => {
            const field = deepQueryAll(document, 'input[type="password"]').find(isVisible);
            if (field) {
              fillField(field, pass);
              return true;
            }
            return false;
          }, password);

          if (deepPass) {
            passwordFilledOk = true;
            logger.debug('[RBI] Password rempli après étape 2 (deep search)');
            break;
          }

          logger.debug(`[RBI] Attente champ password... (${attempt + 1}/8)`);
          await new Promise(r => setTimeout(r, 1500));
        }

        if (!passwordFilledOk) {
          logger.debug('[RBI] Password toujours introuvable après étape 2');
        }
      }

      if (!usernameFilledOk) logger.debug('[RBI] ATTENTION: Username non rempli');
      if (!passwordFilledOk) logger.debug('[RBI] ATTENTION: Password non rempli');
      credentialsFilled = usernameFilledOk || passwordFilledOk;

      // Soumettre le formulaire
      await new Promise(r => setTimeout(r, 500));
      let submitted = false;

      // 1. Essayer avec le sélecteur submit connu
      if (selectors.submit) {
        const submitButton = await f.$(selectors.submit);
        if (submitButton) {
          await clickThroughOverlay(page, submitButton);
          submitted = true;
          logger.debug('[RBI] Formulaire soumis via sélecteur');
        }
      }

      // 2. Chercher un bouton par son texte (Se connecter, Login, Sign in, etc.)
      //    Inclut Shadow DOM, popups/modals, et tous types d'éléments cliquables
      if (!submitted) {
        submitted = await f.evaluate(withPageHelpers(() => {
          const keywords = [
            'se connecter', 'connexion', 'login', 'log in', 'sign in',
            'signin', 'submit', 'enter', 'valider', 'envoyer', 'continuer',
            'continue', 'next', 'suivant', 'ok', 'go', 'authenticate',
            's\'identifier', 'identifier', 'accéder', 'access', 'entrer',
            'connect', 'proceed', 'confirm', 'confirmer'
          ];

          // Élargir la recherche : boutons classiques + liens + divs/spans cliquables
          const clickables = deepQueryAll(document,
            'button, input[type="submit"], input[type="button"], ' +
            'a[role="button"], a.btn, a.button, [role="button"], ' +
            'a[href="#"], a[href="javascript"], ' +
            'div[onclick], span[onclick], div.btn, span.btn, ' +
            'div.button, span.button, label[onclick]'
          );

          function matchesKeywords(el) {
            const text = (el.innerText || el.textContent || el.value || '').toLowerCase().trim();
            const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
            const title = (el.getAttribute('title') || '').toLowerCase();
            return keywords.some(kw =>
              text === kw || text.includes(kw) ||
              ariaLabel.includes(kw) || title.includes(kw)
            );
          }

          // Passe 1 : éléments explicitement cliquables
          for (const el of clickables) {
            if (isVisible(el) && matchesKeywords(el)) {
              el.click();
              return true;
            }
          }

          // Passe 2 : tout élément visible avec un texte correspondant
          //           (certains sites utilisent des <a>, <div>, <span> sans attributs spéciaux)
          const allElements = deepQueryAll(document, 'a, div, span, li, label, p');
          for (const el of allElements) {
            if (!isVisible(el)) continue;
            // Ne matcher que les éléments "feuilles" (texte court = probablement un bouton)
            const text = (el.innerText || el.textContent || '').toLowerCase().trim();
            if (text.length > 30) continue; // Trop long pour être un bouton
            if (keywords.some(kw => text === kw || text.includes(kw))) {
              // Vérifier que l'élément semble cliquable (cursor, onclick, rôle)
              const style = window.getComputedStyle(el);
              const looksClickable = style.cursor === 'pointer' ||
                                     el.onclick !== null ||
                                     el.getAttribute('tabindex') !== null ||
                                     el.closest('a, button, [role="button"]');
              if (looksClickable) {
                el.click();
                return true;
              }
            }
          }
          return false;
        }));

        if (submitted) {
          logger.debug('[RBI] Formulaire soumis via détection texte bouton');
        }
      }

      // 3. Fallback : focus sur le champ password puis Enter
      if (!submitted) {
        // S'assurer que le focus est sur le bon champ avant Enter
        await f.evaluate(() => {
          const passField = document.querySelector('input[type="password"]');
          if (passField) passField.focus();
        });
        await pressThroughOverlay(page, f, 'Enter');
        submitted = true;
        logger.debug('[RBI] Formulaire soumis via Enter (focus password)');
      }
    }

    logger.debug('[RBI] Injection credentials terminée');
    return { formFound: true, credentialsFilled };

  } catch (error) {
    if (error instanceof InjectionRefusedError) {
      // Refus journalisé (sans secret) par refuseInjection / withJsDisabledFor
      return { formFound: true, credentialsFilled: false, refused: error.rbiRefusal };
    }
    logger.error(`[RBI] Erreur injection credentials: ${describeError(error)}`);
    return { formFound: false, credentialsFilled: false };
  }
}

/**
 * Injecte un code TOTP/2FA après la soumission du formulaire de login
 * Attend qu'un champ OTP/TOTP apparaisse, le remplit et soumet
 *
 * SÉCURITÉ (RBI-11) : le code n'est saisi que dans un document de l'hôte de l'entrée
 * (`entryUrl`) ; une page ou iframe étrangère est ignorée (l'utilisateur peut saisir le code).
 *
 * @param {Object} page - Page Puppeteer
 * @param {string} code - Code TOTP à injecter
 * @param {Object} cdpClient - Session CDP (désactivation JS pendant la saisie)
 * @param {Object} [selectors] - Sélecteurs effectifs (clé `totp` = sélecteur custom)
 * @param {string} entryUrl - URL de l'entrée (référence d'origine)
 */
async function injectTotpCode(page, code, cdpClient, selectors, entryUrl) {
  const ctx = { page, cdpClient, entryUrl, skipped: new Set() };
  try {
    logger.debug('[RBI] Injection code TOTP...');

    // Attendre que la navigation post-login se termine
    // (injectCredentials soumet le formulaire mais n'attend pas la navigation)
    logger.debug('[RBI] Attente navigation post-login...');
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {
      logger.debug('[RBI] Pas de navigation détectée (SPA ou timeout)');
    });

    // Attendre que le formulaire de login disparaisse (confirmation que la page MFA est chargée)
    await new Promise(r => setTimeout(r, 1500));

    // Sélecteurs courants pour les champs TOTP/OTP/MFA
    // Ordonnés du plus spécifique au plus générique pour éviter les faux positifs
    const totpSelectors = [
      // Sélecteurs très spécifiques (nom/attribut explicite)
      'input[autocomplete="one-time-code"]',
      'input[name="totp"]', 'input[name="otp"]', 'input[name="otc"]',
      'input[name="mfaCode"]', 'input[name="verificationCode"]',
      'input[name="totpPin"]', 'input[name="mfa_token"]',
      'input[name="passcode"]', 'input[name="twoFactorCode"]',
      // Sélecteurs par ID spécifique
      'input[id*="totp" i]', 'input[id*="otp" i]', 'input[id*="mfa" i]',
      'input[id*="2fa" i]', 'input[id*="passcode" i]',
      // Sélecteurs par placeholder spécifique
      'input[placeholder*="totp" i]', 'input[placeholder*="otp" i]',
      'input[placeholder*="vérification" i]', 'input[placeholder*="verification" i]',
      // Champ numérique seul visible (typique des pages MFA)
      'input[inputmode="numeric"]',
      'input[type="tel"][maxlength="6"]', 'input[type="number"][maxlength="6"]',
      // Sélecteurs plus génériques (en dernier pour éviter faux positifs)
      'input[name="code"]', 'input[name="token"]',
      'input[id*="verification" i]', 'input[id*="code" i]', 'input[id*="token" i]',
      'input[placeholder*="code" i]', 'input[placeholder*="token" i]'
    ];

    // Sélecteur custom (totpSelector) en tête de liste : prioritaire sur l'auto-détection
    if (selectors && typeof selectors.totp === 'string' && selectors.totp.trim()) {
      totpSelectors.unshift(selectors.totp.trim());
    }

    const combinedSelector = totpSelectors.join(', ');

    // Chercher le champ TOTP avec plusieurs tentatives (max 25 secondes)
    let totpField = null;
    let targetFrame = page;

    for (let attempt = 0; attempt < 10 && !totpField; attempt++) {
      // Vérifier d'abord que le champ password a disparu
      // (pour ne pas confondre la page de login avec la page MFA)
      const passwordStillVisible = await page.evaluate(withPageHelpers(() =>
        deepQueryAll(document, 'input[type="password"]').some(isVisible)
      )).catch(() => false);

      if (passwordStillVisible && attempt < 4) {
        logger.debug(`[RBI] TOTP: formulaire login encore visible, attente... (${attempt + 1}/10)`);
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      // SÉCURITÉ (RBI-11): page principale et Shadow DOM seulement sur l'hôte de l'entrée
      const mainAllowed = isCandidateAllowed(ctx, page, 'page TOTP');

      // Chercher dans la page principale
      try {
        // Vérifier que le champ trouvé n'est PAS un champ password
        const el = mainAllowed ? await page.$(combinedSelector) : null;
        if (el) {
          const isPassword = await page.evaluate(e => e.type === 'password', el);
          if (!isPassword) {
            totpField = el;
            targetFrame = page;
            logger.debug('[RBI] Champ TOTP trouvé dans la page principale');
            break;
          }
        }
      } catch (e) { /* ignore */ }

      // Chercher dans le Shadow DOM
      try {
        const inShadow = mainAllowed && await page.evaluate(withPageHelpers((sels) =>
          sels.some(sel => deepQueryAll(document, sel).some(el => el.type !== 'password' && isVisible(el)))
        ), totpSelectors);

        if (inShadow) {
          logger.debug('[RBI] Champ TOTP trouvé dans Shadow DOM');
          totpField = 'shadow';
          break;
        }
      } catch (e) { /* ignore */ }

      // Chercher dans les iframes (hôte de l'entrée uniquement)
      for (const frame of page.frames()) {
        if (frame === page.mainFrame()) continue;
        if (!isCandidateAllowed(ctx, frame, 'iframe TOTP')) continue;
        try {
          const el = await frame.$(combinedSelector);
          if (el) {
            totpField = el;
            targetFrame = frame;
            logger.debug(`[RBI] Champ TOTP trouvé dans iframe: ${logger.safeUrl(frame.url())}`);
            break;
          }
        } catch (e) { /* iframe cross-origin */ }
      }

      if (!totpField) {
        logger.debug(`[RBI] Champ TOTP non trouvé, tentative ${attempt + 1}/10...`);
        await new Promise(r => setTimeout(r, 2500));
      }
    }

    if (!totpField) {
      logger.debug('[RBI] Aucun champ TOTP trouvé après 25s - le site n\'en demande peut-être pas');
      return;
    }

    // Injecter le code TOTP (JS page désactivé pendant injection)
    if (totpField === 'shadow') {
      // Injection via Shadow DOM (hôte vérifié avant et pendant la saisie)
      await evaluateSecretFill(ctx, page, 'TOTP', (sels, totpCode) => {
        for (const sel of sels) {
          const field = deepQueryAll(document, sel).find(f => isVisible(f) && f.type !== 'password');
          if (field) {
            fillField(field, totpCode);
            break;
          }
        }
      }, totpSelectors, code);
    } else {
      // Injection classique via Puppeteer
      await clickThroughOverlay(page, totpField, { clickCount: 3 });
      await typeSecret(ctx, totpField, code, 30, 'TOTP');
    }

    logger.debug('[RBI] Code TOTP injecté avec succès');

    // Soumettre le formulaire TOTP
    await new Promise(r => setTimeout(r, 500));

    let submitted = false;

    // 1. Chercher un bouton de soumission
    const submitSelectors = [
      'button[type="submit"]', 'input[type="submit"]',
      'button[id*="verify" i]', 'button[id*="submit" i]', 'button[id*="next" i]',
      'button[id*="confirm" i]'
    ];

    for (const sel of submitSelectors) {
      try {
        const btn = await targetFrame.$(sel);
        if (btn) {
          const btnVisible = await targetFrame.evaluate(withPageHelpers((el) => isVisible(el)), btn);
          if (btnVisible) {
            await clickThroughOverlay(page, btn);
            submitted = true;
            logger.debug(`[RBI] TOTP soumis via sélecteur: ${sel}`);
            break;
          }
        }
      } catch (e) { /* ignore */ }
    }

    // 2. Chercher par texte du bouton
    if (!submitted) {
      try {
        submitted = await targetFrame.evaluate(withPageHelpers(() => {
          const keywords = [
            'verify', 'vérifier', 'valider', 'validate', 'confirm', 'confirmer',
            'submit', 'envoyer', 'continue', 'continuer', 'next', 'suivant',
            'se connecter', 'sign in', 'log in', 'login'
          ];
          const buttons = document.querySelectorAll('button, input[type="submit"], a[role="button"]');
          for (const btn of buttons) {
            const text = (btn.innerText || btn.value || '').toLowerCase().trim();
            if (isVisible(btn) && keywords.some(kw => text.includes(kw))) {
              btn.click();
              return true;
            }
          }
          return false;
        }));
        if (submitted) logger.debug('[RBI] TOTP soumis via détection texte bouton');
      } catch (e) { /* ignore */ }
    }

    // 3. Fallback : Enter
    if (!submitted) {
      await pressThroughOverlay(page, targetFrame, 'Enter');
      logger.debug('[RBI] TOTP soumis via Enter');
    }

    logger.debug('[RBI] Injection TOTP terminée');

  } catch (error) {
    if (error instanceof InjectionRefusedError) {
      // Refus déjà journalisé (sans secret) : le code n'a pas été saisi
      logger.warn('[RBI] Code TOTP non saisi (document hors du domaine de l\'entrée)');
    } else {
      logger.error(`[RBI] Erreur injection TOTP: ${describeError(error)}`);
    }
    // On continue, l'utilisateur peut entrer le code manuellement
  }
}

/**
 * Attend et vérifie si le login a réussi
 * Détecte les changements d'URL, disparition du formulaire, ou messages d'erreur
 *
 * @param {Object} page - Page Puppeteer
 * @param {string} originalUrl - URL de départ
 * @param {Object} selectors - Sélecteurs utilisés (réservé)
 * @returns {Promise<{success: boolean, reason: string}>}
 *   reason ∈ 'url-changed' | 'form-gone' | 'error-detected' | 'timeout'
 *   SÉCURITÉ: un timeout n'est JAMAIS interprété comme un succès.
 */
async function waitForLoginSuccess(page, originalUrl, selectors) { // eslint-disable-line no-unused-vars
  logger.debug('[RBI] Vérification du succès du login...');

  const startTime = Date.now();
  const maxWaitTime = 15000; // 15 secondes max
  const checkInterval = 1000; // Vérifier chaque seconde

  const originalHostname = safeHostname(originalUrl);

  // Aucun champ password visible (page principale, Shadow DOM inclus)
  const isLoginFormGone = withPageHelpers(() => !deepQueryAll(document, 'input[type="password"]').some(isVisible));

  // Indicateurs d'erreur de login visibles
  const hasVisibleLoginError = withPageHelpers(() => {
    const errorSelectors = [
      '.error', '.alert-error', '.alert-danger', '[role="alert"]',
      '.error-message', '.login-error', '.auth-error',
      '[class*="error"]', '[class*="invalid"]', '[class*="failed"]'
    ];
    const errorWords = ['incorrect', 'invalid', 'wrong', 'failed', 'error', 'échec', 'invalide', 'erreur'];
    for (const selector of errorSelectors) {
      for (const el of document.querySelectorAll(selector)) {
        if (!isVisible(el)) continue;
        const text = (el.innerText || '').toLowerCase();
        if (errorWords.some((w) => text.includes(w))) return true;
      }
    }
    return false;
  });

  // Message d'échec explicite dans le corps de page (après stabilisation)
  const hasBodyLoginError = () => {
    const body = document.body?.innerText?.toLowerCase() || '';
    return body.includes('invalid credentials') ||
           body.includes('authentication failed') ||
           body.includes('login failed') ||
           body.includes('incorrect password') ||
           body.includes('access denied');
  };

  while (Date.now() - startTime < maxWaitTime) {
    try {
      const currentUrl = page.url();
      const currentHostname = safeHostname(currentUrl);

      // Vérifier si on a été redirigé vers une page différente
      const urlChanged = currentUrl !== originalUrl;
      const hostChanged = currentHostname !== originalHostname;

      const loginFormGone = await page.evaluate(isLoginFormGone);
      const hasLoginError = await page.evaluate(hasVisibleLoginError);

      // Si erreur détectée, login échoué
      if (hasLoginError) {
        logger.debug('[RBI] Erreur de login détectée');
        return { success: false, reason: 'error-detected' };
      }

      // Si le formulaire a disparu et l'URL a changé, login probablement réussi
      if (loginFormGone && (urlChanged || hostChanged)) {
        logger.debug(`[RBI] Login réussi - URL changée: ${urlChanged}, Host changé: ${hostChanged}`);
        return { success: true, reason: 'url-changed' };
      }

      // Si le formulaire a disparu (même sans changement d'URL), vérifier qu'on n'est pas sur une page d'erreur
      if (loginFormGone) {
        // Attendre un peu plus pour être sûr que la page est stable
        await new Promise(r => setTimeout(r, 1500));

        // Re-vérifier les erreurs après stabilisation
        const stillHasError = await page.evaluate(hasBodyLoginError);
        if (!stillHasError) {
          logger.debug('[RBI] Login réussi - Formulaire disparu, pas d\'erreur');
          return { success: true, reason: 'form-gone' };
        }
      }

      // Attendre avant la prochaine vérification
      await new Promise(r => setTimeout(r, checkInterval));

    } catch (error) {
      logger.debug(`[RBI] Erreur pendant vérification: ${describeError(error)}`);
      // Continuer à vérifier malgré l'erreur (navigation en cours, contexte détruit…)
      await new Promise(r => setTimeout(r, checkInterval));
    }
  }

  // SÉCURITÉ: Timeout = échec. On ne déduit pas un succès de l'absence de formulaire
  // (page blanche, redirection intermédiaire, formulaire rendu tardivement…).
  logger.debug('[RBI] Timeout - impossible de confirmer le succès du login');
  return { success: false, reason: 'timeout' };
}

/**
 * Ferme une session active
 */
async function closeSession(sessionId) {
  const session = activeSessions.get(sessionId);
  if (!session) return;
  session.closing = true;
  // SÉCURITÉ: Nettoyer le timer TTL pour éviter les fuites mémoire
  if (session.ttlTimer) {
    clearTimeout(session.ttlTimer);
    session.ttlTimer = null;
  }
  try {
    await session.browser.close();
  } catch (e) {
    logger.error(`[RBI] Erreur fermeture session ${sessionId}: ${describeError(e)}`);
  }
  // SÉCURITÉ: Supprimer le profil éphémère une fois Chromium terminé (même promesse que le
  // handler disconnected : attendue ici, la fermeture ne rend la main qu'après la suppression)
  await removeSessionProfile(session, sessionId);
  activeSessions.delete(sessionId);
}

/**
 * Ferme toutes les sessions actives (en parallèle) et attend la suppression de leurs profils
 */
async function closeAllSessions() {
  const entries = [...activeSessions];
  logger.info(`[RBI] Fermeture de ${entries.length} sessions actives`);
  await Promise.all(entries.map(async ([sessionId, session]) => {
    session.closing = true;
    if (session.ttlTimer) {
      clearTimeout(session.ttlTimer);
      session.ttlTimer = null;
    }
    try {
      await session.browser.close();
    } catch (e) {
      // Ignore
    }
    // SÉCURITÉ: Supprimer le profil éphémère (mémorisé, après la fin de Chromium)
    await removeSessionProfile(session, sessionId);
  }));
  for (const [sessionId] of entries) activeSessions.delete(sessionId);
  // Profils restés verrouillés lors d'une fermeture précédente : nouvel essai
  await retryPendingProfiles();
}

/**
 * Retourne les sessions actives
 */
function getActiveSessions() {
  const sessions = [];
  for (const [sessionId, session] of activeSessions) {
    sessions.push({
      sessionId,
      url: session.url,
      startTime: session.startTime,
      duration: Date.now() - session.startTime
    });
  }
  return sessions;
}

/**
 * Vérifie si Puppeteer/Chromium est disponible.
 * - Résultat mis en cache 5 minutes (l'UI peut interroger fréquemment)
 * - Vérification par fs.existsSync du binaire ; le lancement réel d'un Chromium
 *   headless n'est effectué qu'UNE fois par processus (coûteux : ~1-2s + process)
 */
const AVAILABILITY_CACHE_TTL = 5 * 60 * 1000;
let availabilityCache = null; // { result, checkedAt }
let launchVerified = false;

/** Résultat (éventuellement en cache) avec le motif d'indisponibilité dans la langue COURANTE de l'interface */
function withAvailabilityMessage(result) {
  return result.available ? result : { ...result, error: tm('rbi.chromiumUnavailable') };
}

async function checkAvailability() {
  const now = Date.now();
  if (availabilityCache && now - availabilityCache.checkedAt < AVAILABILITY_CACHE_TTL) {
    return withAvailabilityMessage(availabilityCache.result);
  }

  let result;
  try {
    let chromePath = getEmbeddedChromePath();
    if (!chromePath) {
      // Pas de Chrome embarqué : cache Puppeteer par défaut (peut lever si absent)
      chromePath = puppeteer.executablePath();
    }
    if (!chromePath || !fs.existsSync(chromePath)) {
      throw new Error('Binaire Chromium introuvable');
    }

    if (!launchVerified) {
      const browser = await puppeteer.launch({
        headless: true,
        pipe: true, // SÉCURITÉ: Pas de port TCP debug
        executablePath: chromePath
      });
      await browser.close();
      launchVerified = true;
    }
    result = { available: true };
  } catch (error) {
    logger.warn(`[RBI] Chromium non disponible: ${describeError(error)}`);
    result = { available: false };
  }

  availabilityCache = { result, checkedAt: now };
  return withAvailabilityMessage(result);
}

module.exports = {
  launchSecureSession,
  closeSession,
  closeAllSessions,
  getActiveSessions,
  checkAvailability,
  buildNetworkAllowlist,
  // Exportés pour les tests et pour un nettoyage explicite au démarrage (après le verrou d'instance)
  isInjectionTargetAllowed,
  detectKnownSelectors,
  cleanupStaleProfiles,
  removeSessionProfile,
  KNOWN_SELECTORS
};
