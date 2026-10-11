// ========================================
// HOOK: useAuth — Authentification LDAP Vault
// ========================================
import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import axios from 'axios';
import * as validation from '../validation';
import bruteForceProtection from '../bruteForceProtection';
import secureLogger from '../secureLogger';

// I18N-27 : motif d'échec de connexion traduit. Mêmes messages génériques que sanitizeError
// (utils/security.js) : aucune information sensible exposée.
const HTTP_ERROR_KEYS = {
  400: 'error.httpBadRequest',
  401: 'error.httpUnauthorized',
  403: 'error.httpForbidden',
  404: 'error.httpNotFound',
  429: 'error.httpTooManyRequests',
  500: 'error.httpServerError',
  502: 'error.httpUnavailable',
  503: 'error.httpUnavailable',
};

/** Motif générique et traduit d'une erreur HTTP (« Invalid request », « Accès refusé »…) */
export function translatedHttpReason(err, t) {
  return t(HTTP_ERROR_KEYS[err?.response?.status] || 'error.unexpected');
}

/**
 * AUTH-5 / AUTH-15 : vrai si le statut HTTP signale un serveur indisponible (Vault scellé 503,
 * répartiteur 502/504, erreur interne 500, quota 429) et non un refus d'identifiants.
 * Ces réponses ne sont PAS décomptées par la protection anti-force brute.
 */
export function isServerUnavailableStatus(status) {
  return status === 429 || (typeof status === 'number' && status >= 500 && status <= 599);
}

/**
 * AUTH-14 : refus du coffre local VIDE d'une connexion envoyée sans confirmation du mot de passe
 * (400 « password confirmation required ») : le compte administrateur reste à créer. Cas d'une détection
 * GET /v1/sys/init en échec (délai, serveur pas encore prêt) : le formulaire était resté en mode
 * connexion. Aucun mot de passe n'a été vérifié (jamais décompté par l'anti-force brute).
 */
export function isFirstAccountSetupRequired(err) {
  const errors = err?.response?.data?.errors;
  return err?.response?.status === 400 && Array.isArray(errors)
    && errors.some(e => /password confirmation required/i.test(String(e)));
}

// AUTH-14 : règles de création du compte administrateur du coffre local, identiques à
// electron/localVault/authService.createUser (vérifiées ici AVANT l'envoi : une erreur de saisie
// n'est jamais décomptée comme tentative échouée et la règle est affichée en clair).
export const SETUP_MIN_PASSWORD_LENGTH = 8;
export const SETUP_USERNAME_MIN_LENGTH = 2;
export const SETUP_USERNAME_MAX_LENGTH = 64;

// ========================================
// CYCLE DE VIE DU JETON VAULT (AUTH-2)
// ========================================
// Le jeton obtenu à la connexion a une durée de vie (lease_duration). Il est renouvelé
// (POST auth/token/renew-self, autorisé par la policy « default » de Vault) aux 2/3 de sa durée ;
// s'il n'est pas renouvelable, il est vérifié à l'échéance (GET auth/token/lookup-self). Dès que
// Vault le déclare invalide (401, ou 403 « invalid token »), la session se termine proprement (même
// nettoyage que l'expiration par inactivité : état de l'extension vidé, écran de connexion, message
// dédié). Échéance dépassée sans confirmation possible (Vault injoignable, lookup-self interdit) :
// le jeton est forcément expiré, la session se termine aussi.
const RENEW_FRACTION = 2 / 3;
const MIN_RENEW_DELAY_MS = 5000;           // en deçà, plus de renouvellement : vérification à l'échéance
const MAX_TIMER_DELAY_MS = 60 * 60 * 1000; // au plus 1 h entre deux contrôles (et jamais au-delà de la borne de setTimeout)
const RETRY_DELAY_MS = 30000;              // nouvel essai après une erreur réseau ou serveur
const EXPIRY_GRACE_MS = 1000;
const TOKEN_CHECK_THROTTLE_MS = 15000;     // vérifications déclenchées par des 403 : au plus une toutes les 15 s
const REVOKE_TIMEOUT_MS = 5000;            // AUTH-13 : révocation en arrière-plan, délai court

/** Vrai pour les routes du jeton lui-même (pas de vérification en boucle sur leurs 403) */
const TOKEN_ROUTE_RE = /\/v1\/auth\/token\/(lookup-self|renew-self|revoke-self)(\?|$)/;

/** Serveur du coffre local (http://127.0.0.1:port) : sa route lookup-self ne refuse (403) qu'un jeton invalide */
const LOCAL_VAULT_RE = /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/i;

/**
 * Vrai si le refus vient d'un jeton expiré ou révoqué : Vault répond alors 403 avec
 * « permission denied » ET « invalid token ». Un jeton VALIDE privé de la policy « default »
 * (token_no_default_policy) reçoit 403 « permission denied » seul sur lookup-self : ce n'est
 * pas une fin de session.
 */
function isInvalidTokenResponse(err) {
  const errors = err?.response?.data?.errors;
  const text = Array.isArray(errors) ? errors.join(' ') : '';
  return /invalid token|token (is )?expired|bad token/i.test(text);
}

/**
 * Programme le renouvellement et la vérification du jeton de la session en cours.
 * N'utilise que des références : les minuteries ne gardent aucune valeur périmée.
 */
function createTokenLifecycle({ vaultUrlRef, vaultApiRefRef, sessionTokenRef, onExpiredRef }) {
  const fresh = () => ({
    token: '', timer: null, expiresAt: 0, renewable: false,
    renewDisabled: false,   // renouvellement refusé ou absent : vérification seule
    lookupForbidden: false, // lookup-self refusé à un jeton valide : seule l'échéance connue fait foi
    checking: false, lastCheck: 0,
  });
  let life = fresh();

  // Le jeton suivi est toujours celui de la session en cours (sinon : session terminée ou remplacée)
  const isCurrent = (tok) => !!tok && life.token === tok && sessionTokenRef.current === tok;

  const requestConfig = (tok) => {
    const api = vaultApiRefRef.current?.current;
    const headers = api?.baseHeaders ? api.baseHeaders(tok) : { 'X-Vault-Request': 'true', 'X-Vault-Token': tok };
    return api?.axiosConfig ? api.axiosConfig({ headers }) : { timeout: 30000, headers };
  };

  const clearTimer = () => {
    if (life.timer) clearTimeout(life.timer);
    life.timer = null;
  };

  const setTimer = (fn, ms) => {
    clearTimer();
    life.timer = setTimeout(fn, Math.max(0, Math.min(ms, MAX_TIMER_DELAY_MS)));
  };

  const stop = () => {
    clearTimer();
    life = fresh();
  };

  const expire = (tok) => {
    if (!isCurrent(tok)) return;
    stop();
    secureLogger.warn('[Session] Jeton Vault expiré ou révoqué : fin de session');
    if (onExpiredRef.current) onExpiredRef.current('token');
  };

  // Erreur transitoire (réseau, 5xx, 429) : nouvel essai avant l'échéance connue. Échéance
  // dépassée sans confirmation possible : le jeton est forcément mort côté Vault → fin de session.
  const retryOrExpire = (tok, fn) => {
    const remaining = life.expiresAt ? life.expiresAt - Date.now() : Infinity;
    if (remaining <= 0) { expire(tok); return; }
    setTimer(() => fn(tok), Math.min(RETRY_DELAY_MS, remaining + EXPIRY_GRACE_MS));
  };

  let renew;
  let check;

  const schedule = (tok, ttlSeconds, renewable) => {
    if (!isCurrent(tok)) return;
    const ttl = Number(ttlSeconds);
    if (!Number.isFinite(ttl) || ttl <= 0) {
      // Jeton sans échéance (jeton racine…) ou durée inconnue : rien à programmer
      life.expiresAt = 0;
      clearTimer();
      return;
    }
    const ttlMs = ttl * 1000;
    life.expiresAt = Date.now() + ttlMs;
    life.renewable = !!renewable;
    const renewIn = ttlMs * RENEW_FRACTION;
    if (renewable && !life.renewDisabled && renewIn >= MIN_RENEW_DELAY_MS) setTimer(() => renew(tok), renewIn);
    else setTimer(() => check(tok), ttlMs + EXPIRY_GRACE_MS);
  };

  renew = async (tok) => {
    if (!isCurrent(tok)) return;
    life.timer = null;
    try {
      const res = await axios.post(`${vaultUrlRef.current}/v1/auth/token/renew-self`, {}, requestConfig(tok));
      if (!isCurrent(tok)) return;
      const auth = res?.data?.auth;
      if (!auth || typeof auth.lease_duration !== 'number') {
        // Réponse sans durée (serveur qui ne gère pas le renouvellement) : vérification seule désormais
        life.renewDisabled = true;
        await check(tok);
        return;
      }
      schedule(tok, auth.lease_duration, auth.renewable);
    } catch (err) {
      if (!isCurrent(tok)) return;
      const status = err?.response?.status;
      if (status === undefined || status === null || isServerUnavailableStatus(status)) {
        retryOrExpire(tok, renew);
        return;
      }
      if (status === 401 || (status === 403 && isInvalidTokenResponse(err))) { expire(tok); return; }
      // Renouvellement refusé à un jeton valide (403 : policy sans renew-self) ou route absente (404,
      // coffre local) : plus de renouvellement, l'état réel du jeton est demandé à Vault
      life.renewDisabled = true;
      await check(tok);
    }
  };

  // lookup-self refusé à un jeton valide : reprogrammation d'après la seule échéance connue
  // (renouvellement encore tenté s'il est possible) ; échéance dépassée → fin de session
  const followExpiryOnly = (tok) => {
    if (!life.expiresAt) { clearTimer(); return; }
    const remaining = life.expiresAt - Date.now();
    if (remaining <= 0) { expire(tok); return; }
    schedule(tok, remaining / 1000, life.renewable);
  };

  check = async (tok) => {
    if (!isCurrent(tok) || life.checking) return;
    if (life.lookupForbidden) { followExpiryOnly(tok); return; }
    life.checking = true;
    life.lastCheck = Date.now();
    clearTimer();
    try {
      const res = await axios.get(`${vaultUrlRef.current}/v1/auth/token/lookup-self`, requestConfig(tok));
      life.checking = false;
      if (!isCurrent(tok)) return;
      const data = res?.data?.data || {};
      schedule(tok, data.ttl, data.renewable);
    } catch (err) {
      life.checking = false;
      if (!isCurrent(tok)) return;
      const status = err?.response?.status;
      const localServer = LOCAL_VAULT_RE.test(String(vaultUrlRef.current || ''));
      if (status === 401 || (status === 403 && (isInvalidTokenResponse(err) || localServer))) { expire(tok); return; }
      if (status === 403) {
        life.lookupForbidden = true;
        secureLogger.warn('[Session] lookup-self refusé (policy « default » absente) : suivi du jeton par sa seule échéance');
        followExpiryOnly(tok);
        return;
      }
      retryOrExpire(tok, check);
    }
  };

  return {
    /** Démarre le suivi du jeton de la session qui vient de s'ouvrir */
    start(tok, leaseDuration, renewable) {
      stop();
      if (!tok) return;
      life.token = tok;
      schedule(tok, leaseDuration, renewable);
    },
    stop,
    /** Un appel Vault a reçu 403 : le jeton est-il encore valide ? (au plus une vérification / 15 s) */
    requestCheck() {
      const tok = life.token;
      if (!isCurrent(tok) || life.checking || life.lookupForbidden) return;
      if (Date.now() - life.lastCheck < TOKEN_CHECK_THROTTLE_MS) return;
      check(tok);
    },
    /** Vrai pour une requête de la session vers Vault (hors routes du jeton lui-même) */
    isSessionRequest(url) {
      const base = vaultUrlRef.current;
      return typeof url === 'string' && !!base && url.startsWith(`${base}/v1/`) && !TOKEN_ROUTE_RE.test(url);
    },
  };
}

/**
 * Hook d'authentification LDAP Vault.
 *
 * @param {object} options - dépendances stables ou recréées chaque rendu
 *   vaultUrl, ldapAuthPath, showToast, t,
 *   vaultApiRef  — { current: vaultApi } (ref pour éviter la dépendance circulaire)
 *   setters pour l'état global que le hook doit vider au logout
 */
export function useAuth(options) {
  const {
    vaultUrl, ldapAuthPath,
    showToast, t,
    vaultApiRef,
    // Refs vers des callbacks définies après le hook
    fetchEnginesLikeUiRef,
    // Setters passés depuis App pour le cleanup au logout
    setSecretEngines, setSelectedEngine, setSecrets,
    setCurrentView, setVisiblePasswords,
    setAllVaultSecrets, setDiscoveredTags, setMultiVaultSearch,
    setSelectedSecrets,
    setSearchState, // { setSearch, setSearchInput }
  } = options;

  const [authUser, setAuthUser] = useState(() => {
    return localStorage.getItem('rdvault-saved-username') || '';
  });
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [isModerator, setIsModerator] = useState(false);
  const [moderatorEngines, setModeratorEngines] = useState([]);
  const [rememberMe, setRememberMe] = useState(() => {
    return !!localStorage.getItem('rdvault-saved-username');
  });
  const [rbiOnlyEngines, setRbiOnlyEngines] = useState(new Set());
  const [rbiOnlySecrets, setRbiOnlySecrets] = useState(new Set());
  // AUTH-14 : demandes de nouvelle détection du premier démarrage (LoginForm), incrémentées quand le
  // coffre local refuse une connexion faute de confirmation (isFirstAccountSetupRequired)
  const [firstRunRecheck, setFirstRunRecheck] = useState(0);

  // SÉCURITÉ : jeton de la session en cours, mis à jour de façon SYNCHRONE dès la
  // connexion / déconnexion / expiration (l'état React ne l'est qu'au rendu suivant).
  // Permet aux opérations asynchrones en cours (synchro extension, CLI) de détecter
  // que la session a pris fin avant d'écrire leur résultat.
  const sessionTokenRef = useRef('');

  // AUTH-2 : renouvellement / vérification du jeton (minuteries, références uniquement)
  // Dernières valeurs lues par les minuteries (le suivi est créé une seule fois pour toute la vie
  // du composant : aucune minuterie n'est perdue si l'appelant recrée ses objets à chaque rendu)
  const vaultUrlRef = useRef(vaultUrl);
  vaultUrlRef.current = vaultUrl;
  const vaultApiRefRef = useRef(vaultApiRef);
  vaultApiRefRef.current = vaultApiRef;
  const handleSessionExpiredRef = useRef(null);
  const tokenLifecycle = useMemo(() => createTokenLifecycle({
    vaultUrlRef, vaultApiRefRef, sessionTokenRef, onExpiredRef: handleSessionExpiredRef,
  }), []);

  // Minuteries arrêtées au démontage
  useEffect(() => () => tokenLifecycle.stop(), [tokenLifecycle]);

  // AUTH-2 : un 403 reçu par un appel Vault de la session (liste, lecture, écriture…) peut venir
  // d'un jeton expiré ou révoqué : l'état du jeton est alors vérifié (lookup-self). Un vrai refus
  // de droits laisse la session intacte. L'erreur est toujours transmise telle quelle à l'appelant.
  useEffect(() => {
    const responseInterceptors = axios.interceptors?.response;
    if (!token || !responseInterceptors?.use) return undefined;
    const id = responseInterceptors.use(
      (response) => response,
      (error) => {
        if (error?.response?.status === 403 && tokenLifecycle.isSessionRequest(error?.config?.url)) {
          tokenLifecycle.requestCheck();
        }
        return Promise.reject(error);
      }
    );
    return () => { if (responseInterceptors.eject) responseInterceptors.eject(id); };
  }, [token, tokenLifecycle]);

  // Vérifier si le coffre sélectionné est entièrement RBI-Only
  const isCurrentEngineRbiOnly = (selectedEngine) => {
    return selectedEngine && rbiOnlyEngines.has(selectedEngine.name);
  };

  // Vérifier si un secret spécifique est RBI-Only (coffre passé en paramètre).
  // Mémoïsé : utilisé comme dépendance de calculs mémoïsés dans App.jsx.
  const isSecretRbiOnly = useCallback((secretName, selectedEngine) => {
    if (!selectedEngine) return false;
    if (rbiOnlyEngines.has(selectedEngine.name)) return true;
    return rbiOnlySecrets.has(selectedEngine.name + '/' + secretName);
  }, [rbiOnlyEngines, rbiOnlySecrets]);

  // SÉCURITÉ: Nettoyage des données sensibles dans localStorage lors de la déconnexion
  const cleanupOnLogout = useCallback(() => {
    localStorage.removeItem('vault-client.username');
    localStorage.removeItem('vault-client.isAdmin');
    if (window.electronCLI?.revokeSession) {
      window.electronCLI.revokeSession().catch(() => {});
    }
    // SÉCURITÉ: Nettoyer toutes les données sensibles du localStorage
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('vault-audit-ssh-')) localStorage.removeItem(key);
    });
    localStorage.removeItem('rdvault-cli-session');
    localStorage.removeItem('rdvault-cli-auto-approve');
    localStorage.removeItem('rdvault-cli-list-approve');
    localStorage.removeItem('rdvault-user-tags');
    // Nettoyer le sessionStorage (brute force state)
    try { sessionStorage.removeItem('rdvault-bf-state'); } catch { /* ignore */ }
    setVisiblePasswords({});
    setAllVaultSecrets([]);
    setSelectedSecrets(new Set());
    setDiscoveredTags([]);
    setIsModerator(false);
    setModeratorEngines([]);
    setMultiVaultSearch(false);
    // SÉCURITÉ: Vider le fichier de sync extension Chrome
    try {
      if (window.electronSync?.writeState) {
        Promise.resolve(window.electronSync.writeState({
          vaultUrl: '', username: '', connected: false, secrets: []
        })).catch(() => {});
      }
    } catch (err) { /* ignore */ }
  }, [setVisiblePasswords, setAllVaultSecrets, setSelectedSecrets, setDiscoveredTags, setMultiVaultSearch]);

  // SÉCURITÉ: Révoquer le token Vault côté serveur (best effort, délai court).
  // tokenToRevoke : jeton explicite (déconnexion : l'ancien jeton, l'état étant déjà vidé).
  const revokeToken = useCallback(async (tokenToRevoke) => {
    const tok = typeof tokenToRevoke === 'string' ? tokenToRevoke : token;
    const api = vaultApiRef.current;
    if (!tok || !api) return;
    try {
      await axios.post(`${vaultUrl}/v1/auth/token/revoke-self`, null,
        api.axiosConfig({ headers: api.baseHeaders(tok), timeout: REVOKE_TIMEOUT_MS }));
    } catch { /* best-effort */ }
  }, [token, vaultUrl, vaultApiRef]);

  /**
   * Connexion. options (facultatif, fourni par LoginForm) :
   *   { setup: true, confirmPassword } — création du compte administrateur au premier démarrage
   *   du coffre local (AUTH-14). Tout autre argument (évènement de clic…) est ignoré.
   */
  const handleLogin = async (loginOptions) => {
    const api = vaultApiRef.current;
    if (!api) return;
    const { baseHeaders, axiosConfig } = api;
    const setup = !!(loginOptions && typeof loginOptions === 'object' && loginOptions.setup === true);
    // Vrai dès que Vault a délivré un jeton : une erreur ultérieure (policies, coffres) n'est pas
    // un échec d'authentification et n'est jamais décomptée
    let loginAccepted = false;
    try {
      // SÉCURITÉ: Validation des entrées
      if (!authUser || !password) {
        showToast(t('login.fieldsRequired'), 'error');
        return;
      }

      // Messages de validation.js dans la langue de l'interface (I18N-28)
      const usernameValidation = validation.validateUsername(authUser);
      if (!usernameValidation.valid) {
        showToast(validation.translateValidationError(usernameValidation, t), 'error');
        return;
      }

      const passwordValidation = validation.validatePassword(password);
      if (!passwordValidation.valid) {
        showToast(validation.translateValidationError(passwordValidation, t), 'error');
        return;
      }

      // AUTH-14 : création du compte administrateur — règles du serveur vérifiées et confirmation
      // exigée AVANT l'envoi (une faute de frappe deviendrait sinon le mot de passe maître)
      if (setup) {
        if (authUser.length < SETUP_USERNAME_MIN_LENGTH || authUser.length > SETUP_USERNAME_MAX_LENGTH) {
          showToast(t('login.setupUsernameLength', { min: SETUP_USERNAME_MIN_LENGTH, max: SETUP_USERNAME_MAX_LENGTH }), 'error', 5000);
          return;
        }
        if (password.length < SETUP_MIN_PASSWORD_LENGTH) {
          showToast(t('login.setupTooShort', { min: SETUP_MIN_PASSWORD_LENGTH }), 'error', 5000);
          return;
        }
        if (loginOptions.confirmPassword !== password) {
          showToast(t('login.setupMismatch'), 'error', 5000);
          return;
        }
      }

      // SÉCURITÉ: Vérifier le brute force protection
      if (bruteForceProtection.isBlocked(authUser)) {
        const stats = bruteForceProtection.getStats(authUser);
        const remainingSeconds = Math.ceil((stats.blockedUntil - Date.now()) / 1000);
        showToast(t('login.bruteForceLocked', { seconds: remainingSeconds }), 'error', 4000);
        return;
      }

      // SÉCURITÉ: Capturer et effacer le mot de passe du state AVANT la requête réseau
      let currentPassword = password;
      setPassword('');
      try {
      // Création du compte : la confirmation accompagne la requête (contrôle côté serveur possible)
      const body = setup ? { password: currentPassword, confirm: loginOptions.confirmPassword } : { password: currentPassword };
      const res = await axios.post(`${vaultUrl}/v1/${ldapAuthPath}/login/${encodeURIComponent(authUser)}`, body, axiosConfig({ headers: baseHeaders() }));
      const auth = res?.data?.auth;
      const userToken = auth && typeof auth.client_token === 'string' ? auth.client_token : '';
      if (!userToken) {
        // AUTH-6 : « login MFA » de Vault (identity/mfa/login-enforcement) → 200 avec client_token vide
        // et mfa_requirement : aucune session n'est ouverte. Ni « connexion réussie », ni mode principal,
        // ni remise à zéro du compteur anti-force brute.
        if (auth && auth.mfa_requirement) {
          showToast(t('login.mfaRequired'), 'error', 7000);
          secureLogger.warn('Connexion : second facteur Vault (MFA) exigé, non pris en charge');
        } else {
          // Réponse 200 sans jeton : adresse qui n'est pas un serveur Vault, méthode d'authentification erronée…
          showToast(t('login.unexpectedResponse'), 'error', 6000);
          secureLogger.warn('Connexion : réponse sans jeton');
        }
        return;
      }
      loginAccepted = true;
      // Compte créé ou existant : plus de nouvelle détection du premier démarrage à l'écran de
      // connexion suivant (sinon le formulaire de création réapparaîtrait après la déconnexion)
      setFirstRunRecheck(0);
      // SÉCURITÉ : aucun droit hérité d'une session précédente (admin, modérateur,
      // vue admin) avant la lecture des policies de CE compte (lookup-self)
      setIsAdmin(false);
      setIsModerator(false);
      setModeratorEngines([]);
      setCurrentView('vault');
      sessionTokenRef.current = userToken;
      setToken(userToken);
      // AUTH-2 : renouvellement avant l'échéance (ou vérification à l'échéance si non renouvelable)
      tokenLifecycle.start(userToken, auth.lease_duration, auth.renewable);

      // SÉCURITÉ: Connexion réussie - Reset brute force protection
      bruteForceProtection.registerSuccessfulAttempt(authUser);

      // Sauvegarder ou supprimer le nom d'utilisateur selon la case à cocher
      if (rememberMe) {
        localStorage.setItem('rdvault-saved-username', authUser);
      } else {
        localStorage.removeItem('rdvault-saved-username');
      }

      try {
        const tokenInfo = await axios.get(`${vaultUrl}/v1/auth/token/lookup-self`, axiosConfig({ headers: baseHeaders(userToken) }));
        const entityName = tokenInfo.data?.data?.entity_name || authUser;
        const policies = tokenInfo.data?.data?.policies || [];

        // Détecter si l'utilisateur est admin
        const hasAdminPolicy = policies.some(p => p.toLowerCase() === 'admin' || p.toLowerCase() === 'root');
        setIsAdmin(hasAdminPolicy);

        // Détecter les coffres avec niveau "moderator" dans les policies
        const moderatorEnginesList = [];
        secureLogger.debug('[MODERATOR] Vérification des policies');

        for (const policyName of policies) {
          try {
            const policyRes = await axios.get(
              `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`,
              axiosConfig({ headers: baseHeaders(userToken) })
            );
            const policyHcl = policyRes.data?.data?.policy || policyRes.data?.policy || '';

            const moderatorMatches = [
              ...policyHcl.matchAll(/# KV v2 MODERATOR \(([^)]+)\)/g),
              ...policyHcl.matchAll(/# KV v1 MODERATOR \(([^)]+)\)/g)
            ];

            if (moderatorMatches.length > 0) {
              secureLogger.debug('[MODERATOR] Policy contient des droits moderateur');
            }

            for (const match of moderatorMatches) {
              const engineName = match[1];
              if (!moderatorEnginesList.includes(engineName)) {
                moderatorEnginesList.push(engineName);
              }
            }
          } catch (err) {
            secureLogger.warn('[Policy] Impossible de lire une policy');
          }
        }

        secureLogger.debug('[MODERATOR] Coffres modérateur détectés:', moderatorEnginesList.length);
        setIsModerator(moderatorEnginesList.length > 0);
        setModeratorEngines(moderatorEnginesList);

        // Détecter les coffres et secrets RBI-ONLY dans les policies
        const rbiEnginesSet = new Set();
        const rbiSecretsSet = new Set();
        for (const policyName of policies) {
          try {
            const policyRes = await axios.get(
              `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(policyName)}`,
              axiosConfig({ headers: baseHeaders(userToken) })
            );
            const policyHcl = policyRes.data?.data?.policy || policyRes.data?.policy || '';
            if (policyHcl.includes('# RBI-ONLY')) {
              for (const m of policyHcl.matchAll(/# RBI-ONLY\npath "([^"]+)\/metadata\/\*"/g)) {
                rbiEnginesSet.add(m[1]);
              }
              for (const m of policyHcl.matchAll(/# RBI-ONLY\npath "([^"]+)\/\*"/g)) {
                rbiEnginesSet.add(m[1]);
              }
              for (const m of policyHcl.matchAll(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/metadata\/([^"*\s]+)"/g)) {
                rbiSecretsSet.add(m[1] + '/' + m[2]);
              }
              for (const m of policyHcl.matchAll(/# RBI-ONLY\n# Secret:[^\n]+\npath "([^"]+)\/([^"*\s]+)"/g)) {
                rbiSecretsSet.add(m[1] + '/' + m[2]);
              }
              secureLogger.debug('[RBI-ONLY] Policy contient des restrictions');
            }
          } catch (err) {
            secureLogger.warn('[RBI-ONLY] Impossible de lire une policy');
          }
        }
        setRbiOnlyEngines(rbiEnginesSet);
        setRbiOnlySecrets(rbiSecretsSet);
        secureLogger.debug('[RBI-ONLY] Engines:', rbiEnginesSet.size, 'Secrets:', rbiSecretsSet.size);

        // Afficher le panel admin par défaut pour les admins
        if (hasAdminPolicy) {
          setCurrentView('admin');
        }

        localStorage.setItem('vault-client.username', entityName);
      } catch {
        localStorage.setItem('vault-client.username', authUser);
        setIsAdmin(false);
        setIsModerator(false);
      }

      await fetchEnginesLikeUiRef.current(userToken);

      showToast(t('login.success'), 'success');

      // Passer la fenêtre en mode principal (1280x800)
      if (window.electronWindow?.setMainMode) await window.electronWindow.setMainMode();
      } finally {
        // SÉCURITÉ: Effacer la copie locale du mot de passe
        currentPassword = undefined;
      }
    } catch (err) {
      if (loginAccepted) {
        // Échec d'une étape postérieure à l'authentification : la session est ouverte, rien à décompter
        secureLogger.warn('Connexion : étape postérieure à l\'authentification en échec');
        try { if (window.electronWindow?.setMainMode) await window.electronWindow.setMainMode(); } catch { /* ignore */ }
        return;
      }
      const status = err?.response?.status;
      // SÉCURITÉ: Différencier erreur réseau vs erreur d'authentification
      const isNetworkError = !err?.response && (
        err?.code === 'ECONNREFUSED' || err?.code === 'ECONNABORTED' ||
        err?.code === 'ETIMEDOUT' || err?.code === 'ERR_NETWORK' ||
        err?.message?.includes('Network Error')
      );

      if (isNetworkError) {
        showToast(t('login.networkError'), 'error', 5000);
        secureLogger.warn('Échec connexion : erreur réseau (non décompté)');
      } else if (isServerUnavailableStatus(status)) {
        // AUTH-5 / AUTH-15 : Vault scellé (503), répartiteur (502/504), erreur interne, quota (429) :
        // aucun mot de passe n'a été vérifié → ni tentative décomptée, ni blocage local
        showToast(t(status === 429 ? 'login.serverBusy' : 'login.serverUnavailable'), 'error', 5000);
        secureLogger.warn(`Échec connexion : serveur indisponible (HTTP ${status}, non décompté)`);
      } else if (!setup && isFirstAccountSetupRequired(err)) {
        // Coffre local sans compte, détection du premier démarrage en échec : formulaire de création
        // (LoginForm relance la détection), aucune tentative décomptée
        setFirstRunRecheck(n => n + 1);
        showToast(t('login.setupRequired'), 'warning', 7000);
        secureLogger.warn('Connexion : coffre local sans compte, création du compte administrateur requise');
      } else if (authUser) {
        const bruteForceResult = bruteForceProtection.registerFailedAttempt(authUser);

        // I18N-27 : le toast est composé à partir des seuls champs numériques, avec des clés traduites
        // (séparateur « : » propre à chaque langue, inclus dans la traduction).
        if (bruteForceResult.blocked) {
          const seconds = Math.max(1, Math.ceil((bruteForceResult.retryAfterMs || 0) / 1000));
          showToast(seconds >= 60
            ? t('login.tooManyAttempts', { minutes: Math.ceil(seconds / 60) })
            : t('login.bruteForceLocked', { seconds }), 'error', 4000);
          secureLogger.warn('Tentative de connexion bloquée');
        } else {
          showToast(t('login.failedWithRemaining', {
            reason: translatedHttpReason(err, t),
            count: bruteForceResult.remainingAttempts,
          }), 'error', 4000);
          secureLogger.warn(`Échec authentification (${bruteForceResult.remainingAttempts} tentatives restantes)`);
        }
      } else {
        showToast(t('login.failedWithReason', { reason: translatedHttpReason(err, t) }), 'error');
      }
    }
  };

  const handleLogout = async () => {
    // SÉCURITÉ : la session prend fin dès maintenant pour les opérations en cours
    const previousToken = sessionTokenRef.current || token;
    sessionTokenRef.current = '';
    tokenLifecycle.stop();

    // AUTH-13 : tout est effacé AVANT la moindre attente réseau (cleanupOnLogout vide aussi l'état
    // servi à l'extension) : un serveur Vault muet ne laisse plus le coffre affiché après le clic.
    cleanupOnLogout();
    setToken('');
    setSecretEngines([]);
    setSelectedEngine(null);
    setSecrets([]);
    if (setSearchState) {
      setSearchState.setSearch('');
      setSearchState.setSearchInput('');
    }
    setPassword('');
    setCurrentView('vault');
    setIsAdmin(false);
    setRbiOnlyEngines(new Set());
    setRbiOnlySecrets(new Set());
    showToast(t('login.logoutSuccess'), 'success');

    // Révocation côté serveur en arrière-plan, avec l'ancien jeton et un délai court (best effort)
    revokeToken(previousToken);

    if (window.electronWindow?.setLoginMode) await window.electronWindow.setLoginMode();
  };

  // Setters de recherche (stables : setters useState d'App) extraits de l'objet
  // setSearchState, recréé à chaque rendu et donc inutilisable comme dépendance
  const setSearch = setSearchState?.setSearch;
  const setSearchInput = setSearchState?.setSearchInput;

  // Mémoïsé : passé à useSessionTimeout (dépendance d'effet) — une nouvelle
  // référence à chaque rendu réinitialiserait les timers d'inactivité.
  // reason : 'idle' (inactivité) ou 'locked' (PC verrouillé trop longtemps), fourni par useSessionTimeout ;
  // 'token' (jeton Vault expiré ou révoqué), fourni par le suivi du jeton (AUTH-2)
  const handleSessionExpired = useCallback((reason) => {
    if (token) {
      secureLogger.warn('Session expirée (inactivité, PC verrouillé ou jeton Vault expiré)');
      sessionTokenRef.current = '';
      tokenLifecycle.stop();
      // Un jeton déjà expiré n'a pas à être révoqué
      if (reason !== 'token') revokeToken(token);
      cleanupOnLogout();
      setToken('');
      setAuthUser('');
      setPassword('');
      setSecretEngines([]);
      setSelectedEngine(null);
      setSecrets([]);
      // Même remise à zéro que handleLogout : l'utilisateur suivant n'hérite ni
      // des droits admin ni de la vue admin ni de la recherche en cours
      if (setSearch) setSearch('');
      if (setSearchInput) setSearchInput('');
      setCurrentView('vault');
      setIsAdmin(false);
      setRbiOnlyEngines(new Set());
      setRbiOnlySecrets(new Set());
      // Message adapté à la cause
      const messageKey = reason === 'token' ? 'login.sessionExpiredVault'
        : reason === 'idle' ? 'login.sessionExpiredActive' : 'login.sessionExpired';
      showToast(t(messageKey), 'warning', reason === 'token' ? 6000 : 4000);
      if (window.electronWindow?.setLoginMode) window.electronWindow.setLoginMode();
    }
  }, [token, tokenLifecycle, revokeToken, cleanupOnLogout, setSecretEngines, setSelectedEngine, setSecrets, setSearch, setSearchInput, setCurrentView, showToast, t]);
  handleSessionExpiredRef.current = handleSessionExpired;

  return {
    authUser, setAuthUser,
    password, setPassword,
    token, setToken,
    isAdmin, setIsAdmin,
    isModerator, setIsModerator,
    moderatorEngines, setModeratorEngines,
    rememberMe, setRememberMe,
    rbiOnlyEngines, setRbiOnlyEngines,
    rbiOnlySecrets, setRbiOnlySecrets,
    firstRunRecheck,
    isCurrentEngineRbiOnly,
    isSecretRbiOnly,
    sessionTokenRef,
    handleLogin,
    handleLogout,
    handleSessionExpired,
    revokeToken,
    cleanupOnLogout,
  };
}
