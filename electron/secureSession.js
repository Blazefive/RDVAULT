// ========================================
// SECURE SESSION (RBI-like) - Session navigateur isolée
// ========================================
// Lance un navigateur Chromium isolé via Puppeteer
// Injecte les credentials automatiquement (l'utilisateur ne voit jamais le mdp)
// Profil éphémère supprimé à la fermeture

const puppeteer = require('puppeteer-core');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

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
      console.log(`[RBI] Chrome embarqué trouvé: ${p}`);
      return p;
    }
  }

  console.log('[RBI] Pas de Chrome embarqué, utilisation du cache Puppeteer par défaut');
  return null;
}

// Sessions actives (pour cleanup)
const activeSessions = new Map();

// SÉCURITÉ: Nettoyer les profils éphémères orphelins (crash précédent)
function cleanupStaleProfiles() {
  try {
    const tmpDir = os.tmpdir();
    const entries = fs.readdirSync(tmpDir).filter(e => e.startsWith('rbi-'));
    for (const entry of entries) {
      const fullPath = path.join(tmpDir, entry);
      try {
        // SÉCURITÉ: Vérifier que ce n'est pas un symlink/junction avant de supprimer
        const lstat = fs.lstatSync(fullPath);
        if (lstat.isSymbolicLink()) {
          console.warn(`[RBI] Symlink ignoré dans le cleanup: ${entry}`);
          continue;
        }
        if (Date.now() - lstat.mtimeMs > 2 * 60 * 60 * 1000) {
          fs.rmSync(fullPath, { recursive: true, force: true });
          console.log(`[RBI] Profil orphelin supprimé: ${entry}`);
        }
      } catch (e) { /* ignore */ }
    }
  } catch (e) { /* ignore */ }
}
cleanupStaleProfiles();

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

/**
 * Trouve les sélecteurs appropriés pour une URL
 */
function getSelectorsForUrl(url, customSelectors) {
  // Si sélecteurs custom fournis, les utiliser
  if (customSelectors && customSelectors.username && customSelectors.password) {
    return customSelectors;
  }

  // Chercher dans les sélecteurs connus
  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname.toLowerCase();
  const port = parsedUrl.port;

  // Détection Proxmox par port (8006 est le port par défaut de Proxmox VE)
  if (port === '8006') {
    return KNOWN_SELECTORS['proxmox'];
  }

  // Détection ESXi/vSphere par URL patterns
  const fullUrl = url.toLowerCase();
  if (hostname.includes('esxi') || hostname.includes('vsphere') || hostname.includes('vcenter') ||
      fullUrl.includes('/ui/') && (fullUrl.includes('vsphere') || fullUrl.includes('vcenter')) ||
      fullUrl.includes('/websdk/') || fullUrl.includes('/host-client/')) {
    return KNOWN_SELECTORS['vsphere'];
  }

  for (const [domain, selectors] of Object.entries(KNOWN_SELECTORS)) {
    if (domain !== 'default' && domain !== 'proxmox' && domain !== 'vsphere' && domain !== 'synology' && hostname.includes(domain)) {
      return selectors;
    }
  }

  return KNOWN_SELECTORS.default;
}

/**
 * Extrait le domaine de base d'un hostname (gère les TLD à 2 niveaux)
 * Ex: "app.example.co.uk" → "example.co.uk", "login.site.com" → "site.com"
 */
function getBaseDomain(hostname) {
  const twoLevelTlds = [
    'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in',
    'com.au', 'com.br', 'com.cn', 'com.mx', 'com.tw', 'com.hk',
    'org.uk', 'net.au', 'ac.uk', 'gov.uk', 'gov.au',
    'ne.jp', 'or.jp', 'ac.jp', 'go.jp'
  ];

  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;

  const lastTwo = parts.slice(-2).join('.');
  if (twoLevelTlds.includes(lastTwo)) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
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

async function launchSecureSession(options) {
  // SÉCURITÉ: Limiter le nombre de sessions concurrentes (prévient l'épuisement des ressources)
  if (activeSessions.size >= MAX_ACTIVE_SESSIONS) {
    return { success: false, error: 'Nombre maximum de sessions RBI atteint (5)' };
  }

  const { url, username, password, totp, selectors: customSelectors, policies = {}, skipOverlay = false } = options;

  const crypto = require('crypto');
  // SÉCURITÉ: ID de session sans Date.now() pour éviter la prédictibilité temporelle
  const sessionId = `session_${crypto.randomBytes(12).toString('hex')}`;

  console.log(`[RBI] Lancement session sécurisée: ${sessionId}`);

  try {
    // Options Puppeteer
    const embeddedChrome = getEmbeddedChromePath();
    // SÉCURITÉ RBI: Le profil Puppeteer est éphémère et isolé.
    // --no-sandbox est nécessaire sous Windows avec un Chrome embarqué.
    // Les erreurs de certificat sont ignorées (ignoreHTTPSErrors + --ignore-certificate-errors)
    // car le navigateur accède aux sites cibles internes qui peuvent avoir des certificats
    // auto-signés ou expirés. Les deux mécanismes sont nécessaires pour couvrir tous les cas.
    // Le profil est supprimé à la fermeture de la session.
    // SÉCURITÉ: Profil éphémère explicite — supprimé à la fermeture
    const profileDir = path.join(os.tmpdir(), `rbi-${crypto.randomBytes(8).toString('hex')}`);
    // SÉCURITÉ: Vérifier qu'aucun symlink/junction n'existe déjà à ce chemin
    if (fs.existsSync(profileDir)) {
      throw new Error('Le répertoire de profil existe déjà (attaque symlink potentielle)');
    }
    fs.mkdirSync(profileDir);

    const launchOptions = {
      headless: false,
      defaultViewport: null,
      ignoreHTTPSErrors: true,
      userDataDir: profileDir,
      pipe: true, // SÉCURITÉ: Communication via pipe au lieu d'un port TCP debugging (élimine le vecteur d'attaque réseau local)
      ...(embeddedChrome ? { executablePath: embeddedChrome } : {}),
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--ignore-certificate-errors',
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
        '--disable-component-update',
        '--no-first-run',
        '--no-default-browser-check',
        '--window-size=1280,800',
      ]
    };

    const browser = await puppeteer.launch(launchOptions);
    const pages = await browser.pages();
    const page = pages[0] || await browser.newPage();

    // SÉCURITÉ: Session CDP persistante — utilisée pour désactiver JS pendant l'injection
    // et pour bloquer les téléchargements si policy active
    let cdpClient = null;
    try {
      cdpClient = await page.createCDPSession();
      if (policies.disableDownloads) {
        await cdpClient.send('Browser.setDownloadBehavior', { behavior: 'deny' });
      }
    } catch (e) {
      console.warn('[RBI] Impossible de créer la session CDP:', e.message);
      // SÉCURITÉ: Fail-closed — si CDP échoue et que le download blocking est demandé, avorter
      if (policies.disableDownloads) {
        return await abortSession('Impossible d\'appliquer la politique de téléchargement (CDP indisponible)');
      }
    }

    // Stocker la session (SÉCURITÉ: ne PAS stocker le username/password dans la Map)
    activeSessions.set(sessionId, {
      browser,
      page,
      url,
      startTime: Date.now(),
      policies,
      profileDir,
      cdpClient
    });

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

    // Couche 2 : Détection au niveau navigateur (indépendant du JS de la page)
    // Si DevTools s'ouvre malgré tout (menu contextuel, autre méthode), on ferme immédiatement
    browser.on('targetcreated', async (target) => {
      if (target.url().startsWith('devtools://')) {
        console.log('[RBI] Ouverture DevTools détectée et bloquée');
        try {
          const devtoolsPage = await target.page();
          if (devtoolsPage) await devtoolsPage.close();
        } catch (e) { /* ignore */ }
      }
    });

    // SÉCURITÉ: Bloquer clipboard par défaut pour les sessions non-admin
    // Empêche l'exfiltration de credentials via copier-coller
    // Désactivable explicitement avec policies.disableClipboard = false
    if (!skipOverlay && policies.disableClipboard !== false) {
      await page.evaluateOnNewDocument(() => {
        // Bloquer TOUTES les API clipboard
        navigator.clipboard.writeText = () => Promise.reject('Clipboard disabled');
        navigator.clipboard.readText = () => Promise.reject('Clipboard disabled');
        navigator.clipboard.write = () => Promise.reject('Clipboard disabled');
        navigator.clipboard.read = () => Promise.reject('Clipboard disabled');
        // SÉCURITÉ: Sauvegarder la référence originale pour éviter la récursion infinie
        const originalExecCommand = document.execCommand.bind(document);
        document.execCommand = (cmd, ...args) => {
          if (cmd === 'copy' || cmd === 'cut' || cmd === 'paste') {
            return false;
          }
          return originalExecCommand(cmd, ...args);
        };
        // Bloquer les événements copy/cut/paste/drag natifs
        for (const evt of ['copy', 'cut', 'paste', 'dragstart', 'drop']) {
          document.addEventListener(evt, (e) => {
            e.preventDefault();
            e.stopPropagation();
          }, true);
        }
        // Bloquer le menu contextuel (empêche "Copier" natif de Chromium)
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
              console.log('[RBI] Nouvel onglet bloqué par policy disableNewTabs');
              await newPage.close();
            }
          } catch (e) { /* ignore */ }
        }
      });
    }

    // ========================================
    // OVERLAY DE CHARGEMENT
    // Masque le contenu pendant l'injection des credentials.
    // L'overlay est ré-injecté à chaque navigation (redirections login)
    // puis supprimé définitivement une fois le login confirmé.
    // Désactivé pour les admins (skipOverlay = true).
    // ========================================
    const RBI_OVERLAY_HTML = `
      <div id="__rbi_loading_overlay__" style="
        position:fixed;top:0;left:0;width:100vw;height:100vh;
        background:#ffffff;z-index:2147483647;pointer-events:none;
        display:flex;flex-direction:column;align-items:center;justify-content:center;
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      ">
        <div style="width:48px;height:48px;border:4px solid #e0e0e0;border-top-color:#2563eb;border-radius:50%;animation:__rbi_spin__ 0.8s linear infinite"></div>
        <div style="margin-top:24px;font-size:15px;color:#64748b;letter-spacing:0.3px">Connexion en cours...</div>
        <style>@keyframes __rbi_spin__{to{transform:rotate(360deg)}}</style>
      </div>`;

    // Flag : une fois true, on ne ré-injecte plus l'overlay
    // Si skipOverlay (admin), l'overlay n'est jamais injecté
    let overlayDismissed = skipOverlay;

    if (skipOverlay) {
      console.log('[RBI] Mode admin : overlay désactivé');
    }

    // Injecter l'overlay à chaque chargement de page (pendant le login)
    const injectOverlayInPage = async () => {
      if (overlayDismissed) return;
      try {
        await page.evaluate((html) => {
          if (document.getElementById('__rbi_loading_overlay__')) return;
          const container = document.body || document.documentElement;
          container.insertAdjacentHTML('beforeend', html);
        }, RBI_OVERLAY_HTML);
      } catch (e) { /* page fermée ou en cours de navigation */ }
    };

    // Écouter les navigations pour ré-injecter l'overlay pendant le login
    const onFrameNavigated = async (frame) => {
      if (overlayDismissed) return;
      if (frame === page.mainFrame()) {
        // Attendre que le DOM soit prêt
        try {
          await frame.waitForSelector('body', { timeout: 5000 });
          await injectOverlayInPage();
        } catch (e) { /* ignore */ }
      }
    };
    if (!skipOverlay) {
      page.on('framenavigated', onFrameNavigated);
    }

    // ========================================
    // HELPER : fermer proprement en cas d'échec
    // ========================================
    const abortSession = async (reason) => {
      console.log(`[RBI] Abandon session ${sessionId} : ${reason}`);
      overlayDismissed = true;
      try { page.off('framenavigated', onFrameNavigated); } catch (e) { /* ignore */ }
      try { await browser.close(); } catch (e) { /* ignore */ }
      // SÉCURITÉ: Supprimer le profil explicitement (le handler disconnected risque de ne pas trouver la session)
      try { fs.rmSync(profileDir, { recursive: true, force: true }); } catch (e) { /* ignore */ }
      activeSessions.delete(sessionId);
      return { success: false, error: reason };
    };

    // ========================================
    // TIMEOUT GLOBAL : 90s max pour tout le processus login
    // Protège contre les blocages infinis (page crashée, evaluate qui hang, etc.)
    // ========================================
    const GLOBAL_TIMEOUT = 90000;
    let globalTimer;
    const globalTimeoutPromise = new Promise((_, reject) => {
      globalTimer = setTimeout(() => reject(new Error('__RBI_GLOBAL_TIMEOUT__')), GLOBAL_TIMEOUT);
    });

    try {
      await Promise.race([globalTimeoutPromise, (async () => {
        // Naviguer vers l'URL
        // SÉCURITÉ: Ne pas loguer les query strings (peuvent contenir des tokens/credentials)
        const safeLogUrl = (() => { try { const u = new URL(url); return `${u.protocol}//${u.hostname}${u.port ? ':' + u.port : ''}${u.pathname}`; } catch { return '[URL invalide]'; } })();
        console.log(`[RBI] Navigation vers ${safeLogUrl}`);
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

        // S'assurer que l'overlay est bien présent après le chargement initial
        await injectOverlayInPage();

        // Obtenir les sélecteurs
        const selectors = getSelectorsForUrl(url, customSelectors);
        console.log(`[RBI] Sélecteurs utilisés:`, selectors);

        // Injecter les credentials (l'utilisateur ne voit que l'overlay)
        const injectResult = await injectCredentials(page, username, password, selectors, cdpClient);

        // Si le formulaire n'a pas été trouvé ou les champs pas remplis → échec immédiat
        // En mode admin (skipOverlay), on ne ferme pas : l'admin voit la page et peut agir
        if (!skipOverlay && (!injectResult || !injectResult.credentialsFilled)) {
          const reason = !injectResult?.formFound
            ? 'Formulaire de connexion introuvable'
            : 'Champs de connexion introuvables sur la page';
          console.log(`[RBI] ${reason} - fermeture immédiate`);
          throw new Error(`__RBI_INJECT_FAIL__${reason}`);
        }

        // Injecter le code TOTP si fourni (après soumission du formulaire de login)
        if (totp) {
          await injectTotpCode(page, totp, cdpClient);
        }

        // Attendre que le login soit confirmé avant de retirer l'overlay
        // En mode admin, pas de vérification : le browser reste ouvert quoi qu'il arrive
        if (!skipOverlay) {
          const originalUrl = url;
          let loginSuccess = false;
          try {
            loginSuccess = await waitForLoginSuccess(page, originalUrl, selectors);
          } catch (e) {
            console.log('[RBI] Erreur waitForLoginSuccess:', e.message);
          }
          console.log(`[RBI] Login success: ${loginSuccess}`);

          if (!loginSuccess) {
            throw new Error('__RBI_INJECT_FAIL__Connexion échouée sur la page');
          }
        } else {
          console.log('[RBI] Mode admin : pas de vérification login, session ouverte directement');
        }
      })()]);
    } catch (rbiError) {
      clearTimeout(globalTimer);

      // Erreurs attendues (formulaire pas trouvé, login échoué, timeout global)
      if (rbiError.message.startsWith('__RBI_INJECT_FAIL__')) {
        const reason = rbiError.message.replace('__RBI_INJECT_FAIL__', '');
        return await abortSession(reason);
      }
      if (rbiError.message === '__RBI_GLOBAL_TIMEOUT__') {
        return await abortSession('Délai dépassé (90s) - la page ne répond pas');
      }
      // Erreur inattendue (navigation échouée, etc.)
      return await abortSession(rbiError.message || 'Erreur inattendue');
    }

    clearTimeout(globalTimer);

    // Retirer l'overlay de chargement - révéler la page (sauf si déjà désactivé pour admin)
    if (!overlayDismissed) {
      overlayDismissed = true;
      try { page.off('framenavigated', onFrameNavigated); } catch (e) { /* ignore */ }

      // SÉCURITÉ: Nettoyer les credentials et TOTP du DOM AVANT de retirer l'overlay
      try {
        await page.evaluate(() => {
          document.querySelectorAll('input[type="password"]').forEach(el => {
            el.value = '';
            el.setAttribute('value', '');
          });
          // SÉCURITÉ: Nettoyer aussi les champs TOTP/OTP
          const totpSelectors = [
            'input[autocomplete="one-time-code"]',
            'input[name*="totp" i]', 'input[name*="otp" i]', 'input[name*="mfa" i]',
            'input[name*="code" i]', 'input[name*="token" i]', 'input[name*="passcode" i]',
            'input[inputmode="numeric"][maxlength="6"]', 'input[type="tel"][maxlength="6"]'
          ];
          document.querySelectorAll(totpSelectors.join(', ')).forEach(el => {
            el.value = '';
            el.setAttribute('value', '');
          });
        });
      } catch (e) { /* page peut avoir navigué */ }

      // SÉCURITÉ: Forcer le garbage collection pour effacer les credentials de la mémoire du process Chrome
      if (cdpClient) {
        try {
          await cdpClient.send('HeapProfiler.collectGarbage');
          console.log('[RBI] Garbage collection forcé (nettoyage mémoire credentials)');
        } catch (e) { /* ignore */ }
      }

      try {
        await page.evaluate(() => {
          const overlay = document.getElementById('__rbi_loading_overlay__');
          if (overlay) {
            overlay.style.transition = 'opacity 0.3s ease-out';
            overlay.style.opacity = '0';
            setTimeout(() => overlay.remove(), 350);
          }
        });
        console.log('[RBI] Overlay de chargement retiré');
      } catch (e) {
        console.log('[RBI] Impossible de retirer l\'overlay (page peut avoir navigué)');
      }
    }

    // SÉCURITÉ: Restriction de navigation post-login
    // Empêche l'utilisateur de naviguer vers des domaines non autorisés (phishing, leak)
    // Seules les sessions non-admin sont restreintes
    if (!skipOverlay) {
      try {
        const initialHostname = new URL(url).hostname;
        const postLoginHostname = new URL(page.url()).hostname;
        const allowedDomains = new Set([
          getBaseDomain(initialHostname),
          getBaseDomain(postLoginHostname)
        ]);

        await page.setRequestInterception(true);
        page.on('request', (request) => {
          // Sous-ressources (CSS, JS, images, XHR) → toujours autorisées
          if (request.resourceType() !== 'document') {
            request.continue();
            return;
          }

          try {
            const reqHostname = new URL(request.url()).hostname;
            const reqBaseDomain = getBaseDomain(reqHostname);

            // Autoriser : même domaine de base, sous-domaines, ou domaine parent
            const allowed = allowedDomains.has(reqBaseDomain) ||
              [...allowedDomains].some(d => reqHostname.endsWith('.' + d));

            if (allowed) {
              request.continue();
            } else {
              console.log(`[RBI] Navigation bloquée: ${request.url()} (domaine ${reqBaseDomain} non autorisé)`);
              request.abort('blockedbyclient');
            }
          } catch (e) {
            // URL invalide ou erreur → laisser passer
            request.continue();
          }
        });

        console.log(`[RBI] Restriction navigation activée: domaines autorisés = ${[...allowedDomains].join(', ')}`);
      } catch (e) {
        console.warn('[RBI] Impossible d\'activer la restriction de navigation:', e.message);
      }
    }

    // Gérer la fermeture
    browser.on('disconnected', () => {
      console.log(`[RBI] Session ${sessionId} terminée`);
      // SÉCURITÉ: Lire la session AVANT de la supprimer (sinon startTime est perdu)
      const session = activeSessions.get(sessionId);
      const duration = session ? Date.now() - session.startTime : 0;

      // SÉCURITÉ: Supprimer le profil éphémère (cookies, cache, localStorage Chromium)
      if (session?.profileDir) {
        try {
          fs.rmSync(session.profileDir, { recursive: true, force: true });
          console.log(`[RBI] Profil éphémère supprimé: ${sessionId}`);
        } catch (e) {
          console.warn(`[RBI] Impossible de supprimer le profil: ${e.message}`);
        }
      }

      activeSessions.delete(sessionId);

      // Log audit
      console.log(`[RBI] Audit: Session ${sessionId}, durée: ${Math.round(duration / 1000)}s`);
    });

    // TTL si configuré
    if (policies.ttlMinutes && policies.ttlMinutes > 0) {
      const ttlTimer = setTimeout(() => {
        console.log(`[RBI] TTL atteint pour session ${sessionId}`);
        closeSession(sessionId);
      }, policies.ttlMinutes * 60 * 1000);
      // Stocker le timer pour pouvoir le nettoyer à la déconnexion
      const sess = activeSessions.get(sessionId);
      if (sess) {
        sess.ttlTimer = ttlTimer;
      } else {
        // Session déjà fermée, annuler le timer orphelin
        clearTimeout(ttlTimer);
      }
    }

    return {
      success: true,
      sessionId,
      message: 'Session sécurisée lancée'
    };

  } catch (error) {
    console.error(`[RBI] Erreur lancement session:`, error);
    // SÉCURITÉ: Lire la session AVANT de la supprimer pour pouvoir fermer le browser
    const session = activeSessions.get(sessionId);
    try {
      if (session?.browser) await session.browser.close();
    } catch (e) { /* ignore */ }
    // SÉCURITÉ: Supprimer le profil explicitement (le handler disconnected risque de ne pas trouver la session)
    try {
      if (profileDir) fs.rmSync(profileDir, { recursive: true, force: true });
    } catch (e) { /* ignore */ }
    activeSessions.delete(sessionId);
    return {
      success: false,
      error: 'Erreur lancement session RBI'
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
    console.warn('[RBI] Impossible de désactiver JS:', e.message);
    return await fn();
  }
  try {
    return await fn();
  } finally {
    try {
      await cdpClient.send('Emulation.setScriptExecutionDisabled', { value: false });
    } catch (e) {
      console.warn('[RBI] Impossible de réactiver JS:', e.message);
    }
  }
}

/**
 * Injecte les credentials dans la page
 * Attend jusqu'à 30 secondes que le formulaire apparaisse
 * Gère les dialogs et popups automatiquement
 */
async function injectCredentials(page, username, password, selectors, cdpClient) {
  try {
    // Gérer les dialogs (alertes, confirms, prompts)
    page.on('dialog', async dialog => {
      // SÉCURITÉ: Dismiss au lieu d'accept pour éviter que la page exploite l'auto-confirmation
      console.log(`[RBI] Dialog détecté: ${dialog.type()}`);
      await dialog.dismiss();
    });

    // ========================================
    // ÉTAPE 0 : Chercher un bouton "Login" / "Sign in" qui affiche le formulaire
    // ========================================
    // Beaucoup de sites affichent d'abord une landing page avec un lien/bouton
    // qu'il faut cliquer avant que le formulaire de login n'apparaisse
    const hasLoginForm = await page.evaluate(() => {
      // Recherche profonde incluant Shadow DOM
      function deepQueryAll(root, selector) {
        const results = Array.from(root.querySelectorAll(selector));
        root.querySelectorAll('*').forEach(el => {
          if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
        });
        return results;
      }
      const inputs = deepQueryAll(document, 'input[type="password"]');
      return inputs.some(el => {
        const style = window.getComputedStyle(el);
        return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
      });
    });

    if (!hasLoginForm) {
      console.log('[RBI] Pas de formulaire visible, recherche d\'un bouton Login/Sign in...');

      const clicked = await page.evaluate(() => {
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

          const style = window.getComputedStyle(el);
          const isVisible = style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;

          if (!isVisible) continue;

          const matchText = keywords.some(kw => text === kw || text.includes(kw));
          const matchAria = keywords.some(kw => ariaLabel.includes(kw));
          const matchTitle = keywords.some(kw => title.includes(kw));
          const matchHref = href.includes('login') || href.includes('signin') || href.includes('auth') || href.includes('connexion');

          if (matchText || matchAria || matchTitle || matchHref) {
            el.click();
            return (el.innerText || el.textContent || '').trim().substring(0, 50);
          }
        }
        return null;
      });

      if (clicked) {
        console.log(`[RBI] Bouton cliqué: "${clicked}"`);
        // Attendre la navigation ou le chargement du formulaire
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
        await new Promise(r => setTimeout(r, 1500));

        // Mettre à jour les sélecteurs si l'URL a changé (ex: redirection vers login.salesforce.com)
        const newUrl = page.url();
        const newSelectors = getSelectorsForUrl(newUrl);
        if (newSelectors !== selectors) {
          console.log(`[RBI] URL changée: ${newUrl}, mise à jour sélecteurs`);
          Object.assign(selectors, newSelectors);
        }
      } else {
        console.log('[RBI] Aucun bouton Login/Sign in trouvé');
      }
    } else {
      console.log('[RBI] Formulaire de login déjà visible');
    }

    // Gestion spéciale Proxmox (ExtJS) - AVANT la détection générique
    // Car ExtJS rend les inputs de manière non-standard
    if (selectors.special === 'proxmox') {
      console.log('[RBI] Mode spécial Proxmox (ExtJS)');

      try {
        // Attendre que ExtJS soit chargé et le formulaire prêt
        await page.waitForFunction(() => {
          return typeof Ext !== 'undefined' && Ext.ComponentQuery && Ext.ComponentQuery.query('field[name=username]').length > 0;
        }, { timeout: 20000 });

        console.log('[RBI] Proxmox: ExtJS chargé, formulaire détecté');
        await new Promise(r => setTimeout(r, 1000)); // Laisser ExtJS finir le rendu

        // Utiliser l'API ExtJS pour remplir les champs (JS page désactivé pendant injection)
        const fillResult = await withJsDisabled(cdpClient, () => page.evaluate((user, pass) => {
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
        }, username, password));

        console.log(`[RBI] Proxmox: fill user:${fillResult.username ? 'ok' : 'fail'}, pass:${fillResult.password ? 'ok' : 'fail'}`);

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
          console.log(`[RBI] Proxmox: Login soumis (via ${clicked})`);
        } else {
          // Fallback DOM : chercher et cliquer le bouton dans le HTML
          console.log('[RBI] Proxmox: fallback clic DOM');
          const allElements = await page.$$('a, button, span, div');
          for (const el of allElements) {
            const text = await page.evaluate(e => (e.innerText || '').trim().toLowerCase(), el);
            if (text === 'login' || text === 'se connecter' || text === 'connexion') {
              await el.click();
              console.log(`[RBI] Proxmox: cliqué sur "${text}" via DOM`);
              break;
            }
          }
        }

        console.log('[RBI] Proxmox: injection terminée');
        return { formFound: true, credentialsFilled: fillResult.username || fillResult.password };
      } catch (proxmoxError) {
        console.log('[RBI] Proxmox ExtJS erreur:', proxmoxError.message);
        console.log('[RBI] Tentative avec méthode standard...');
      }
    }

    // Gestion spéciale ESXi / vSphere (toutes versions)
    if (selectors.special === 'esxi') {
      console.log('[RBI] Mode spécial ESXi/vSphere');

      try {
        // ESXi 6.7 utilise un client web qui peut charger le formulaire
        // dans un iframe, un Shadow DOM, ou après un délai JS important.
        // On utilise une approche multi-stratégie.

        let filled = false;

        for (let attempt = 0; attempt < 15 && !filled; attempt++) {
          console.log(`[RBI] ESXi: tentative ${attempt + 1}/15`);

          // Stratégie 1: Chercher dans la page principale (ESXi 7/8, vCenter)
          filled = await withJsDisabled(cdpClient, () => page.evaluate((user, pass) => {
            // Chercher tous les inputs y compris dans le Shadow DOM
            function deepQueryAll(root, selector) {
              const results = Array.from(root.querySelectorAll(selector));
              // Chercher dans les Shadow DOM
              root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) {
                  results.push(...deepQueryAll(el.shadowRoot, selector));
                }
              });
              return results;
            }

            function isVisible(el) {
              if (!el) return false;
              const style = window.getComputedStyle(el);
              return style.display !== 'none' && style.visibility !== 'hidden' &&
                     style.opacity !== '0' && el.offsetWidth > 0;
            }

            function fillField(el, value) {
              el.focus();
              el.value = value;
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
              el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
              // Pour les frameworks (Angular, React, Vue)
              const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
              )?.set;
              if (nativeInputValueSetter) {
                nativeInputValueSetter.call(el, value);
                el.dispatchEvent(new Event('input', { bubbles: true }));
              }
            }

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
          }, username, password));

          if (filled) {
            console.log('[RBI] ESXi: champs remplis dans la page principale');
            break;
          }

          // Stratégie 2: Chercher dans les iframes (ESXi 6.7 embedded host client)
          const frames = page.frames();
          for (const frame of frames) {
            if (frame === page.mainFrame()) continue;
            try {
              filled = await withJsDisabled(cdpClient, () => frame.evaluate((user, pass) => {
                function isVisible(el) {
                  if (!el) return false;
                  const style = window.getComputedStyle(el);
                  return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetWidth > 0;
                }
                function fillField(el, value) {
                  el.focus();
                  el.value = value;
                  el.dispatchEvent(new Event('input', { bubbles: true }));
                  el.dispatchEvent(new Event('change', { bubbles: true }));
                  const nativeSet = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value'
                  )?.set;
                  if (nativeSet) {
                    nativeSet.call(el, value);
                    el.dispatchEvent(new Event('input', { bubbles: true }));
                  }
                }

                const userField = document.querySelector('#username, input[name="username"], input[type="text"]');
                const passField = document.querySelector('#password, input[name="password"], input[type="password"]');

                if (userField && isVisible(userField) && passField && isVisible(passField)) {
                  fillField(userField, user);
                  fillField(passField, pass);
                  return true;
                }
                return false;
              }, username, password));

              if (filled) {
                console.log(`[RBI] ESXi: champs remplis dans iframe: ${frame.url()}`);
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

          submitted = await page.evaluate(() => {
            function deepQueryAll(root, selector) {
              const results = Array.from(root.querySelectorAll(selector));
              root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
              });
              return results;
            }
            function isVisible(el) {
              if (!el) return false;
              const style = window.getComputedStyle(el);
              return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetWidth > 0;
            }

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
          });

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
            await page.keyboard.press('Enter');
            submitted = true;
          }

          console.log(`[RBI] ESXi: soumis=${submitted}`);
        } else {
          console.log('[RBI] ESXi: champs non trouvés');
        }

        console.log('[RBI] ESXi: injection terminée');
        return { formFound: true, credentialsFilled: filled };
      } catch (esxiError) {
        console.log('[RBI] ESXi erreur:', esxiError.message);
        console.log('[RBI] Tentative avec méthode standard...');
      }
    }

    // Gestion spéciale Salesforce
    if (selectors.special === 'salesforce') {
      console.log('[RBI] Mode spécial Salesforce');

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
            console.log('[RBI] Salesforce: formulaire trouvé dans la page principale');
            break;
          } catch (e) {
            // Chercher dans les iframes
            for (const frame of page.frames()) {
              if (frame === page.mainFrame()) continue;
              try {
                const el = await frame.$('#username, input[name="username"]');
                if (el) {
                  found = true;
                  sf = frame;
                  console.log(`[RBI] Salesforce: formulaire trouvé dans iframe: ${frame.url()}`);
                  break;
                }
              } catch (fe) { /* ignore */ }
            }
            if (found) break;
            console.log(`[RBI] Salesforce: attente formulaire... (${i + 1}/10)`);
            await new Promise(r => setTimeout(r, 1000));
          }
        }

        if (!found) {
          console.log('[RBI] Salesforce: formulaire non trouvé, tentative méthode standard');
        } else {
          // Attendre un peu que tout soit stable
          await new Promise(r => setTimeout(r, 500));

          // Remplir via JavaScript (plus fiable que type() pour Salesforce)
          // SÉCURITÉ: Fill wrappé (JS désactivé), submit séparé (JS nécessaire pour le clic)
          const fillResult = await withJsDisabled(cdpClient, () => sf.evaluate((user, pass) => {
            const result = { username: false, password: false };

            // Chercher le champ username par plusieurs sélecteurs
            const userEl = document.querySelector('#username') ||
                          document.querySelector('input[name="username"]') ||
                          document.querySelector('input[type="text"]');
            if (userEl) {
              userEl.focus();
              userEl.value = user;
              userEl.dispatchEvent(new Event('input', { bubbles: true }));
              userEl.dispatchEvent(new Event('change', { bubbles: true }));
              result.username = true;
            }

            // Chercher le champ password
            const passEl = document.querySelector('#password') ||
                          document.querySelector('input[name="pw"]') ||
                          document.querySelector('input[type="password"]');
            if (passEl) {
              passEl.focus();
              passEl.value = pass;
              passEl.dispatchEvent(new Event('input', { bubbles: true }));
              passEl.dispatchEvent(new Event('change', { bubbles: true }));
              result.password = true;
            }

            return result;
          }, username, password));

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

          console.log(`[RBI] Salesforce: fill user:${fillResult.username ? 'ok' : 'fail'}, pass:${fillResult.password ? 'ok' : 'fail'}, submit:${submitted}`);

          if (!submitted) {
            // Fallback: Enter
            await page.keyboard.press('Enter');
            console.log('[RBI] Salesforce: soumis via Enter');
          }

          console.log('[RBI] Salesforce: injection terminée');
          return { formFound: true, credentialsFilled: fillResult.username || fillResult.password };
        }
      } catch (sfError) {
        console.log('[RBI] Salesforce erreur:', sfError.message);
        console.log('[RBI] Tentative avec méthode standard...');
      }
    }

    // Attendre que le formulaire soit chargé (jusqu'à 30 secondes)
    // Cherche dans la page principale ET dans les iframes
    console.log('[RBI] Recherche du formulaire de login...');

    let formFound = false;
    let targetFrame = page; // Par défaut, on travaille sur la page principale
    let attempts = 0;
    const maxAttempts = 6; // 6 x 5s = 30s max
    const formSelector = 'input[type="password"], input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="email"]';

    while (!formFound && attempts < maxAttempts) {
      // 1. Chercher dans la page principale (incluant Shadow DOM)
      try {
        // D'abord essayer le waitForSelector standard
        await page.waitForSelector(formSelector, { timeout: 2000, visible: true });
        formFound = true;
        targetFrame = page;
        console.log('[RBI] Formulaire détecté dans la page principale');
      } catch (e) {
        // Chercher dans le Shadow DOM
        const inShadow = await page.evaluate(() => {
          function deepQueryAll(root, selector) {
            const results = Array.from(root.querySelectorAll(selector));
            root.querySelectorAll('*').forEach(el => {
              if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
            });
            return results;
          }
          const inputs = deepQueryAll(document, 'input[type="password"], input[type="text"], input[type="email"]');
          return inputs.some(el => {
            const style = window.getComputedStyle(el);
            return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetWidth > 0;
          });
        });

        if (inShadow) {
          formFound = true;
          targetFrame = page;
          console.log('[RBI] Formulaire détecté dans Shadow DOM');
        } else {
          // 2. Chercher dans les iframes (récursivement)
          try {
            const frames = page.frames();
            console.log(`[RBI] ${frames.length} frames trouvés, recherche dans les iframes...`);

            for (const frame of frames) {
              if (frame === page.mainFrame()) continue;
              try {
                const input = await frame.$(formSelector);
                if (input) {
                  formFound = true;
                  targetFrame = frame;
                  console.log(`[RBI] Formulaire détecté dans iframe: ${frame.url()}`);
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

      // 3. Chercher les popups/nouvelles pages ouvertes par le navigateur
      if (!formFound) {
        try {
          const allPages = await page.browser().pages();
          for (const p of allPages) {
            if (p === page) continue;
            try {
              const hasForm = await p.$(formSelector);
              if (hasForm) {
                formFound = true;
                targetFrame = p;
                console.log(`[RBI] Formulaire détecté dans popup: ${p.url()}`);
                break;
              }
            } catch (e) { /* ignore */ }
          }
        } catch (e) { /* ignore */ }
      }

      if (!formFound) {
        attempts++;
        console.log(`[RBI] Formulaire non trouvé, tentative ${attempts}/${maxAttempts}...`);

        // Cliquer sur des boutons courants qui pourraient révéler le formulaire
        try {
          const loginButtons = await page.$$('button, a, [role="button"]');
          for (const btn of loginButtons.slice(0, 5)) {
            const text = await page.evaluate(el => el.innerText?.toLowerCase() || '', btn);
            if (text.includes('login') || text.includes('connexion') || text.includes('sign in') || text.includes('se connecter')) {
              console.log(`[RBI] Clic sur bouton: "${text}"`);
              await btn.click().catch(() => {});
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
      console.log('[RBI] Aucun formulaire trouvé après 30s');
      return { formFound: false, credentialsFilled: false };
    }

    // À partir d'ici, on utilise targetFrame au lieu de page pour interagir avec le formulaire
    // Utiliser targetFrame pour toutes les interactions avec le formulaire
    const f = targetFrame;

    let credentialsFilled = false;

    if (selectors.twoStep) {
      // Login en deux étapes (Microsoft, Google, etc.)
      console.log('[RBI] Login deux étapes détecté');

      // Étape 1: Username
      await f.waitForSelector(selectors.username, { visible: true, timeout: 10000 });
      await withJsDisabled(cdpClient, () => f.type(selectors.username, username, { delay: 50 }));

      if (selectors.submitUsername) {
        await f.click(selectors.submitUsername);
        if (f === page) {
          await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {});
        }
        await new Promise(r => setTimeout(r, 1000));
      }

      // Étape 2: Password
      await f.waitForSelector(selectors.password, { visible: true, timeout: 10000 });
      await withJsDisabled(cdpClient, () => f.type(selectors.password, password, { delay: 50 }));
      credentialsFilled = true;

      if (selectors.submitPassword) {
        await f.click(selectors.submitPassword);
      }

    } else {
      // Login classique (une seule page)
      console.log('[RBI] Login classique');

      let usernameFilledOk = false;
      let passwordFilledOk = false;

      // 1. D'abord essayer les sélecteurs connus (plus fiable pour les sites connus)
      if (selectors.username) {
        try {
          await f.waitForSelector(selectors.username, { visible: true, timeout: 3000 });
          const el = await f.$(selectors.username);
          if (el) {
            await el.click({ clickCount: 3 });
            await withJsDisabled(cdpClient, () => el.type(username, { delay: 30 }));
            usernameFilledOk = true;
            console.log('[RBI] Username rempli via sélecteur connu');
          }
        } catch (e) {
          console.log('[RBI] Sélecteur username non trouvé, fallback auto-détection');
        }
      }

      if (selectors.password) {
        try {
          await f.waitForSelector(selectors.password, { visible: true, timeout: 3000 });
          const el = await f.$(selectors.password);
          if (el) {
            await el.click({ clickCount: 3 });
            await withJsDisabled(cdpClient, () => el.type(password, { delay: 30 }));
            passwordFilledOk = true;
            console.log('[RBI] Password rempli via sélecteur connu');
          }
        } catch (e) {
          console.log('[RBI] Sélecteur password non trouvé, fallback auto-détection');
        }
      }

      // 2. Fallback : auto-détection des champs si sélecteurs n'ont pas marché
      //    Cherche dans le DOM normal, le Shadow DOM, et les popups/modals
      if (!usernameFilledOk || !passwordFilledOk) {
        // D'abord essayer la méthode Puppeteer classique
        const inputs = await f.$$('input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
        console.log(`[RBI] Auto-détection: ${inputs.length} champs input trouvés (DOM normal)`);

        for (const input of inputs) {
          const info = await f.evaluate(el => {
            const style = window.getComputedStyle(el);
            return {
              type: el.type,
              visible: style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null
            };
          }, input);

          if (!info.visible) continue;

          if (!passwordFilledOk && info.type === 'password') {
            await input.click({ clickCount: 3 });
            await withJsDisabled(cdpClient, () => input.type(password, { delay: 30 }));
            passwordFilledOk = true;
            console.log('[RBI] Password rempli via auto-détection');
          } else if (!usernameFilledOk && (info.type === 'text' || info.type === 'email')) {
            await input.click({ clickCount: 3 });
            await withJsDisabled(cdpClient, () => input.type(username, { delay: 30 }));
            usernameFilledOk = true;
            console.log('[RBI] Username rempli via auto-détection');
          }
        }

        // Si toujours pas trouvé, chercher dans le Shadow DOM et les popups/modals
        if (!usernameFilledOk || !passwordFilledOk) {
          console.log('[RBI] Auto-détection étendue : Shadow DOM, popups, modals...');
          const deepResult = await withJsDisabled(cdpClient, () => f.evaluate((user, pass, needUser, needPass) => {
            function deepQueryAll(root, selector) {
              const results = Array.from(root.querySelectorAll(selector));
              root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
              });
              return results;
            }
            function isVisible(el) {
              if (!el) return false;
              const style = window.getComputedStyle(el);
              return style.display !== 'none' && style.visibility !== 'hidden' &&
                     style.opacity !== '0' && el.offsetWidth > 0;
            }
            function fillField(el, value) {
              el.focus();
              el.value = value;
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
              el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
              const nativeSet = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
              )?.set;
              if (nativeSet) {
                nativeSet.call(el, value);
                el.dispatchEvent(new Event('input', { bubbles: true }));
              }
            }

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
          }, username, password, !usernameFilledOk, !passwordFilledOk));

          if (deepResult.username) {
            usernameFilledOk = true;
            console.log('[RBI] Username rempli via Shadow DOM/deep search');
          }
          if (deepResult.password) {
            passwordFilledOk = true;
            console.log('[RBI] Password rempli via Shadow DOM/deep search');
          }
        }
      }

      // ========================================
      // DÉTECTION LOGIN 2 ÉTAPES NON RECONNU
      // Si username rempli mais pas de champ password visible,
      // c'est probablement un login 2 étapes : cliquer Next puis attendre le password.
      // ========================================
      if (usernameFilledOk && !passwordFilledOk) {
        console.log('[RBI] Username rempli mais pas de password visible - tentative login 2 étapes auto');

        // Chercher et cliquer un bouton Next/Suivant/Continue
        const clickedNext = await f.evaluate(() => {
          function deepQueryAll(root, selector) {
            const results = Array.from(root.querySelectorAll(selector));
            root.querySelectorAll('*').forEach(el => {
              if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
            });
            return results;
          }

          const nextKeywords = [
            'next', 'suivant', 'continue', 'continuer', 'submit',
            'valider', 'log in', 'login', 'sign in', 'se connecter',
            'connexion', 'proceed', 'go', 'ok', 'enter'
          ];

          // Chercher bouton submit / next
          const submitBtn = document.querySelector('button[type="submit"], input[type="submit"]');
          if (submitBtn) {
            const style = window.getComputedStyle(submitBtn);
            if (style.display !== 'none' && style.visibility !== 'hidden' && submitBtn.offsetWidth > 0) {
              submitBtn.click();
              return (submitBtn.innerText || submitBtn.value || 'submit').trim().substring(0, 50);
            }
          }

          // Chercher par texte
          const clickables = deepQueryAll(document, 'button, input[type="submit"], input[type="button"], a[role="button"], [role="button"]');
          for (const el of clickables) {
            const text = (el.innerText || el.value || '').toLowerCase().trim();
            const style = window.getComputedStyle(el);
            const isVisible = style.display !== 'none' && style.visibility !== 'hidden' && el.offsetWidth > 0;
            if (isVisible && nextKeywords.some(kw => text === kw || text.includes(kw))) {
              el.click();
              return text.substring(0, 50);
            }
          }
          return null;
        });

        if (clickedNext) {
          console.log(`[RBI] Bouton Next/Submit cliqué: "${clickedNext}"`);
        } else {
          // Fallback: Enter pour soumettre l'étape email
          await f.keyboard.press('Enter');
          console.log('[RBI] Enter pressé pour passer à l\'étape suivante');
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
              const isVis = await f.evaluate(el => {
                const s = window.getComputedStyle(el);
                return s.display !== 'none' && s.visibility !== 'hidden' && el.offsetParent !== null;
              }, passInput);
              if (isVis) {
                await passInput.click({ clickCount: 3 });
                await withJsDisabled(cdpClient, () => passInput.type(password, { delay: 30 }));
                passwordFilledOk = true;
                console.log('[RBI] Password rempli après étape 2 (auto-détecté)');
                break;
              }
            }
          } catch (e) { /* ignore */ }

          // Deep search (Shadow DOM)
          const deepPass = await withJsDisabled(cdpClient, () => f.evaluate((pass) => {
            function deepQueryAll(root, selector) {
              const results = Array.from(root.querySelectorAll(selector));
              root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
              });
              return results;
            }
            const fields = deepQueryAll(document, 'input[type="password"]');
            const field = fields.find(el => {
              const s = window.getComputedStyle(el);
              return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0' && el.offsetWidth > 0;
            });
            if (field) {
              field.focus();
              field.value = pass;
              field.dispatchEvent(new Event('input', { bubbles: true }));
              field.dispatchEvent(new Event('change', { bubbles: true }));
              const nativeSet = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
              if (nativeSet) { nativeSet.call(field, pass); field.dispatchEvent(new Event('input', { bubbles: true })); }
              return true;
            }
            return false;
          }, password));

          if (deepPass) {
            passwordFilledOk = true;
            console.log('[RBI] Password rempli après étape 2 (deep search)');
            break;
          }

          console.log(`[RBI] Attente champ password... (${attempt + 1}/8)`);
          await new Promise(r => setTimeout(r, 1500));
        }

        if (!passwordFilledOk) {
          console.log('[RBI] Password toujours introuvable après étape 2');
        }
      }

      if (!usernameFilledOk) console.log('[RBI] ATTENTION: Username non rempli');
      if (!passwordFilledOk) console.log('[RBI] ATTENTION: Password non rempli');
      credentialsFilled = usernameFilledOk || passwordFilledOk;

      // Soumettre le formulaire
      await new Promise(r => setTimeout(r, 500));
      let submitted = false;

      // 1. Essayer avec le sélecteur submit connu
      if (selectors.submit) {
        const submitButton = await f.$(selectors.submit);
        if (submitButton) {
          await submitButton.click();
          submitted = true;
          console.log('[RBI] Formulaire soumis via sélecteur');
        }
      }

      // 2. Chercher un bouton par son texte (Se connecter, Login, Sign in, etc.)
      //    Inclut Shadow DOM, popups/modals, et tous types d'éléments cliquables
      if (!submitted) {
        submitted = await f.evaluate(() => {
          function deepQueryAll(root, selector) {
            const results = Array.from(root.querySelectorAll(selector));
            root.querySelectorAll('*').forEach(el => {
              if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
            });
            return results;
          }

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

          function isVisible(el) {
            const style = window.getComputedStyle(el);
            return style.display !== 'none' && style.visibility !== 'hidden' &&
                   style.opacity !== '0' && el.offsetWidth > 0;
          }

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
        });

        if (submitted) {
          console.log('[RBI] Formulaire soumis via détection texte bouton');
        }
      }

      // 3. Fallback : focus sur le champ password puis Enter
      if (!submitted) {
        // S'assurer que le focus est sur le bon champ avant Enter
        await f.evaluate(() => {
          const passField = document.querySelector('input[type="password"]');
          if (passField) passField.focus();
        });
        await page.keyboard.press('Enter');
        submitted = true;
        console.log('[RBI] Formulaire soumis via Enter (focus password)');
      }
    }

    console.log('[RBI] Injection credentials terminée');
    return { formFound: true, credentialsFilled };

  } catch (error) {
    console.error('[RBI] Erreur injection credentials:', error.message);
    return { formFound: false, credentialsFilled: false };
  }
}

/**
 * Injecte un code TOTP/2FA après la soumission du formulaire de login
 * Attend qu'un champ OTP/TOTP apparaisse, le remplit et soumet
 *
 * @param {Object} page - Page Puppeteer
 * @param {string} code - Code TOTP à injecter
 */
async function injectTotpCode(page, code, cdpClient) {
  try {
    console.log('[RBI] Injection code TOTP...');

    // Attendre que la navigation post-login se termine
    // (injectCredentials soumet le formulaire mais n'attend pas la navigation)
    console.log('[RBI] Attente navigation post-login...');
    await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {
      console.log('[RBI] Pas de navigation détectée (SPA ou timeout)');
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

    const combinedSelector = totpSelectors.join(', ');

    // Chercher le champ TOTP avec plusieurs tentatives (max 25 secondes)
    let totpField = null;
    let targetFrame = page;

    for (let attempt = 0; attempt < 10 && !totpField; attempt++) {
      // Vérifier d'abord que le champ password a disparu
      // (pour ne pas confondre la page de login avec la page MFA)
      const passwordStillVisible = await page.evaluate(() => {
        const pwdFields = document.querySelectorAll('input[type="password"]');
        return Array.from(pwdFields).some(el => {
          const style = window.getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
        });
      }).catch(() => false);

      if (passwordStillVisible && attempt < 4) {
        console.log(`[RBI] TOTP: formulaire login encore visible, attente... (${attempt + 1}/10)`);
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }

      // Chercher dans la page principale
      try {
        // Vérifier que le champ trouvé n'est PAS un champ password
        const el = await page.$(combinedSelector);
        if (el) {
          const isPassword = await page.evaluate(e => e.type === 'password', el);
          if (!isPassword) {
            totpField = el;
            targetFrame = page;
            console.log('[RBI] Champ TOTP trouvé dans la page principale');
            break;
          }
        }
      } catch (e) { /* ignore */ }

      // Chercher dans le Shadow DOM
      try {
        const inShadow = await page.evaluate((sels) => {
          function deepQuery(root, selector) {
            const el = root.querySelector(selector);
            if (el && el.type !== 'password') return true;
            for (const child of root.querySelectorAll('*')) {
              if (child.shadowRoot && deepQuery(child.shadowRoot, selector)) return true;
            }
            return false;
          }
          return sels.some(sel => deepQuery(document, sel));
        }, totpSelectors);

        if (inShadow) {
          console.log('[RBI] Champ TOTP trouvé dans Shadow DOM');
          totpField = 'shadow';
          break;
        }
      } catch (e) { /* ignore */ }

      // Chercher dans les iframes
      for (const frame of page.frames()) {
        if (frame === page.mainFrame()) continue;
        try {
          const el = await frame.$(combinedSelector);
          if (el) {
            totpField = el;
            targetFrame = frame;
            console.log(`[RBI] Champ TOTP trouvé dans iframe: ${frame.url()}`);
            break;
          }
        } catch (e) { /* iframe cross-origin */ }
      }

      if (!totpField) {
        console.log(`[RBI] Champ TOTP non trouvé, tentative ${attempt + 1}/10...`);
        await new Promise(r => setTimeout(r, 2500));
      }
    }

    if (!totpField) {
      console.log('[RBI] Aucun champ TOTP trouvé après 25s - le site n\'en demande peut-être pas');
      return;
    }

    // Injecter le code TOTP (JS page désactivé pendant injection)
    if (totpField === 'shadow') {
      // Injection via Shadow DOM
      await withJsDisabled(cdpClient, () => page.evaluate((sels, totpCode) => {
        function deepQueryAll(root, selector) {
          const results = Array.from(root.querySelectorAll(selector));
          root.querySelectorAll('*').forEach(el => {
            if (el.shadowRoot) results.push(...deepQueryAll(el.shadowRoot, selector));
          });
          return results;
        }
        function isVisible(el) {
          if (!el) return false;
          const style = window.getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetWidth > 0;
        }

        for (const sel of sels) {
          const fields = deepQueryAll(document, sel);
          const field = fields.find(f => isVisible(f) && f.type !== 'password');
          if (field) {
            field.focus();
            field.value = totpCode;
            field.dispatchEvent(new Event('input', { bubbles: true }));
            field.dispatchEvent(new Event('change', { bubbles: true }));
            field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
            const nativeSet = Object.getOwnPropertyDescriptor(
              window.HTMLInputElement.prototype, 'value'
            )?.set;
            if (nativeSet) {
              nativeSet.call(field, totpCode);
              field.dispatchEvent(new Event('input', { bubbles: true }));
            }
            break;
          }
        }
      }, totpSelectors, code));
    } else {
      // Injection classique via Puppeteer
      await totpField.click({ clickCount: 3 });
      await withJsDisabled(cdpClient, () => totpField.type(code, { delay: 30 }));
    }

    console.log('[RBI] Code TOTP injecté avec succès');

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
          const isVisible = await targetFrame.evaluate(el => {
            const style = window.getComputedStyle(el);
            return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetWidth > 0;
          }, btn);
          if (isVisible) {
            await btn.click();
            submitted = true;
            console.log(`[RBI] TOTP soumis via sélecteur: ${sel}`);
            break;
          }
        }
      } catch (e) { /* ignore */ }
    }

    // 2. Chercher par texte du bouton
    if (!submitted) {
      try {
        submitted = await targetFrame.evaluate(() => {
          const keywords = [
            'verify', 'vérifier', 'valider', 'validate', 'confirm', 'confirmer',
            'submit', 'envoyer', 'continue', 'continuer', 'next', 'suivant',
            'se connecter', 'sign in', 'log in', 'login'
          ];
          const buttons = document.querySelectorAll('button, input[type="submit"], a[role="button"]');
          for (const btn of buttons) {
            const text = (btn.innerText || btn.value || '').toLowerCase().trim();
            const style = window.getComputedStyle(btn);
            const isVisible = style.display !== 'none' && style.visibility !== 'hidden' && btn.offsetWidth > 0;
            if (isVisible && keywords.some(kw => text.includes(kw))) {
              btn.click();
              return true;
            }
          }
          return false;
        });
        if (submitted) console.log('[RBI] TOTP soumis via détection texte bouton');
      } catch (e) { /* ignore */ }
    }

    // 3. Fallback : Enter
    if (!submitted) {
      await page.keyboard.press('Enter');
      console.log('[RBI] TOTP soumis via Enter');
    }

    console.log('[RBI] Injection TOTP terminée');

  } catch (error) {
    console.error('[RBI] Erreur injection TOTP:', error.message);
    // On continue, l'utilisateur peut entrer le code manuellement
  }
}

/**
 * Attend et vérifie si le login a réussi
 * Détecte les changements d'URL, disparition du formulaire, ou messages d'erreur
 *
 * @param {Object} page - Page Puppeteer
 * @param {string} originalUrl - URL de départ
 * @param {Object} selectors - Sélecteurs utilisés
 * @returns {Promise<boolean>} true si login réussi
 */
async function waitForLoginSuccess(page, originalUrl, selectors) {
  console.log('[RBI] Vérification du succès du login...');

  const startTime = Date.now();
  const maxWaitTime = 15000; // 15 secondes max
  const checkInterval = 1000; // Vérifier chaque seconde

  const originalHostname = new URL(originalUrl).hostname;

  while (Date.now() - startTime < maxWaitTime) {
    try {
      const currentUrl = page.url();
      const currentHostname = new URL(currentUrl).hostname;

      // Vérifier si on a été redirigé vers une page différente
      const urlChanged = currentUrl !== originalUrl;
      const hostChanged = currentHostname !== originalHostname;

      // Vérifier si le formulaire de login a disparu
      const loginFormGone = await page.evaluate(() => {
        const passwordFields = document.querySelectorAll('input[type="password"]');
        const visiblePasswordFields = Array.from(passwordFields).filter(el => {
          const style = window.getComputedStyle(el);
          return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
        });
        return visiblePasswordFields.length === 0;
      });

      // Vérifier les indicateurs d'erreur de login
      const hasLoginError = await page.evaluate(() => {
        const errorSelectors = [
          '.error', '.alert-error', '.alert-danger', '[role="alert"]',
          '.error-message', '.login-error', '.auth-error',
          '[class*="error"]', '[class*="invalid"]', '[class*="failed"]'
        ];

        for (const selector of errorSelectors) {
          const elements = document.querySelectorAll(selector);
          for (const el of elements) {
            const text = el.innerText?.toLowerCase() || '';
            const style = window.getComputedStyle(el);
            const isVisible = style.display !== 'none' && style.visibility !== 'hidden';

            if (isVisible && (
              text.includes('incorrect') ||
              text.includes('invalid') ||
              text.includes('wrong') ||
              text.includes('failed') ||
              text.includes('error') ||
              text.includes('échec') ||
              text.includes('invalide') ||
              text.includes('erreur') ||
              text.includes('incorrect')
            )) {
              return true;
            }
          }
        }
        return false;
      });

      // Si erreur détectée, login échoué
      if (hasLoginError) {
        console.log('[RBI] Erreur de login détectée');
        return false;
      }

      // Si le formulaire a disparu et l'URL a changé, login probablement réussi
      if (loginFormGone && (urlChanged || hostChanged)) {
        console.log(`[RBI] Login réussi - URL changée: ${urlChanged}, Host changé: ${hostChanged}, Formulaire disparu: ${loginFormGone}`);
        return true;
      }

      // Si le formulaire a disparu (même sans changement d'URL), vérifier qu'on n'est pas sur une page d'erreur
      if (loginFormGone) {
        // Attendre un peu plus pour être sûr que la page est stable
        await new Promise(r => setTimeout(r, 1500));

        // Re-vérifier les erreurs après stabilisation
        const stillHasError = await page.evaluate(() => {
          const body = document.body?.innerText?.toLowerCase() || '';
          return body.includes('invalid credentials') ||
                 body.includes('authentication failed') ||
                 body.includes('login failed') ||
                 body.includes('incorrect password') ||
                 body.includes('access denied');
        });

        if (!stillHasError) {
          console.log('[RBI] Login réussi - Formulaire disparu, pas d\'erreur');
          return true;
        }
      }

      // Attendre avant la prochaine vérification
      await new Promise(r => setTimeout(r, checkInterval));

    } catch (error) {
      console.log('[RBI] Erreur pendant vérification:', error.message);
      // Continuer à vérifier malgré l'erreur
    }
  }

  console.log('[RBI] Timeout - impossible de confirmer le succès du login');

  // En cas de timeout, on vérifie une dernière fois si le formulaire est toujours là
  try {
    const formStillVisible = await page.evaluate(() => {
      const passwordFields = document.querySelectorAll('input[type="password"]');
      return Array.from(passwordFields).some(el => {
        const style = window.getComputedStyle(el);
        return style.display !== 'none' && style.visibility !== 'hidden' && el.offsetParent !== null;
      });
    });

    // Si le formulaire n'est plus visible, considérer comme succès
    if (!formStillVisible) {
      console.log('[RBI] Formulaire non visible après timeout - considéré comme succès');
      return true;
    }
  } catch (e) {
    // Ignore
  }

  return false;
}

/**
 * Ferme une session active
 */
async function closeSession(sessionId) {
  const session = activeSessions.get(sessionId);
  if (session) {
    // SÉCURITÉ: Nettoyer le timer TTL pour éviter les fuites mémoire
    if (session.ttlTimer) clearTimeout(session.ttlTimer);
    try {
      await session.browser.close();
    } catch (e) {
      console.error(`[RBI] Erreur fermeture session ${sessionId}:`, e.message);
    }
    // SÉCURITÉ: Supprimer le profil éphémère
    if (session.profileDir) {
      try {
        fs.rmSync(session.profileDir, { recursive: true, force: true });
      } catch (e) { /* disconnect handler peut avoir déjà nettoyé */ }
    }
    activeSessions.delete(sessionId);
  }
}

/**
 * Ferme toutes les sessions actives
 */
async function closeAllSessions() {
  console.log(`[RBI] Fermeture de ${activeSessions.size} sessions actives`);
  for (const [sessionId, session] of activeSessions) {
    if (session.ttlTimer) clearTimeout(session.ttlTimer);
    try {
      await session.browser.close();
    } catch (e) {
      // Ignore
    }
    // SÉCURITÉ: Supprimer le profil éphémère
    if (session.profileDir) {
      try {
        fs.rmSync(session.profileDir, { recursive: true, force: true });
      } catch (e) { /* best effort */ }
    }
  }
  activeSessions.clear();
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
 * Vérifie si Puppeteer/Chromium est disponible
 */
async function checkAvailability() {
  try {
    const embeddedChrome = getEmbeddedChromePath();
    const browser = await puppeteer.launch({
      headless: true,
      pipe: true, // SÉCURITÉ: Pas de port TCP debug
      ...(embeddedChrome ? { executablePath: embeddedChrome } : {})
    });
    await browser.close();
    return { available: true };
  } catch (error) {
    return { available: false, error: 'Chromium non disponible' };
  }
}

module.exports = {
  launchSecureSession,
  closeSession,
  closeAllSessions,
  getActiveSessions,
  checkAvailability,
  KNOWN_SELECTORS
};
