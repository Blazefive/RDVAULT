// ========================================
// TESTS : useAuth — session Vault distante (vague E, cluster E3)
// ========================================
// AUTH-2  : jeton renouvelé (renew-self) avant l'échéance ; jeton expiré détecté → fin de session propre
// AUTH-5/15 : Vault scellé (503), 5xx et 429 ne sont pas comptés comme mot de passe faux
// AUTH-6  : connexion soumise à la MFA Vault (client_token vide + mfa_requirement) → message clair
// AUTH-13 : déconnexion hors ligne → écran fermé tout de suite, révocation en arrière-plan
// AUTH-14 : création du compte administrateur (premier démarrage local) → confirmation exigée

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { useAuth } from './useAuth';
import bruteForceProtection from '../bruteForceProtection';

jest.mock('axios', () => ({
  __esModule: true,
  default: {
    get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn(),
    interceptors: { response: { use: jest.fn(() => 7), eject: jest.fn() } },
  },
}));
global.IS_REACT_ACT_ENVIRONMENT = true;

const VAULT = 'https://vault.test';
const noop = () => {};
let root = null;
let seq = 0;

afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
  localStorage.clear();
  sessionStorage.clear();
  jest.useRealTimers();
  axios.post.mockReset();
  axios.get.mockReset();
  axios.interceptors.response.use.mockClear();
  axios.interceptors.response.eject.mockClear();
  delete window.electronSync;
  delete window.electronWindow;
});

/** Laisse s'écouler les promesses en attente (et les minuteries simulées à 0 ms) */
async function flush(times = 6) {
  for (let i = 0; i < times; i++) {
    // eslint-disable-next-line no-await-in-loop -- volontaire : vidage successif des microtâches
    await act(async () => { await Promise.resolve(); });
  }
}

/** Avance l'horloge simulée de `ms` (minuteries ET Date.now) puis vide les promesses */
async function advance(ms) {
  await act(async () => { jest.advanceTimersByTime(ms); });
  await flush();
}

function mountAuth({ vaultUrl = VAULT } = {}) {
  const api = { current: null };
  const toasts = [];
  const writeStates = [];
  window.electronSync = { writeState: jest.fn(async (s) => { writeStates.push(s); return { success: true }; }) };
  window.electronWindow = { setMainMode: jest.fn(async () => {}), setLoginMode: jest.fn(async () => {}) };
  function Harness() {
    api.current = useAuth({
      vaultUrl, ldapAuthPath: 'auth/ldap', showToast: (m, kind) => toasts.push([m, kind]), t: (k) => k,
      vaultApiRef: {
        current: {
          baseHeaders: (tok) => ({ 'X-Vault-Token': tok || 'stale-api-token' }),
          axiosConfig: (c = {}) => ({ timeout: 30000, ...c }),
        },
      },
      fetchEnginesLikeUiRef: { current: async () => {} }, setSecretEngines: noop, setSelectedEngine: noop, setSecrets: noop,
      setCurrentView: noop, setVisiblePasswords: noop, setAllVaultSecrets: noop, setDiscoveredTags: noop,
      setMultiVaultSearch: noop, setSelectedSecrets: noop, setSearchState: { setSearch: noop, setSearchInput: noop },
    });
    return null;
  }
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const mountInRoot = (reactRoot, element) => reactRoot.render(element); // hors Testing Library
  act(() => { mountInRoot(root, <Harness />); });
  return { api, toasts, writeStates };
}

async function login(api, user, pass, opts) {
  await act(async () => { api.current.setAuthUser(user); api.current.setPassword(pass); });
  await act(async () => { await api.current.handleLogin(opts); });
}

const uniqueUser = (p) => `${p}-${++seq}`;
const urlsOf = (mock) => mock.mock.calls.map(c => c[0]);
const toastKeys = (toasts) => toasts.map(([m]) => m);

// Réponse de connexion Vault (jeton renouvelable de 60 s, comme token_ttl=60s)
const loginResponse = (tok, lease = 60, renewable = true) => ({ data: { auth: { client_token: tok, lease_duration: lease, renewable } } });
const lookupOk = (ttl = 60, renewable = true) => ({ data: { data: { entity_name: 'x', policies: ['default'], ttl, renewable } } });
const forbidden = () => Object.assign(new Error('Request failed with status code 403'), { response: { status: 403, data: { errors: ['permission denied', 'invalid token'] } } });

describe('AUTH-2 : jeton Vault renouvelé, expiration détectée', () => {
  test('jeton renouvelable (TTL 60 s) : renew-self appelé avant l\'échéance, puis reprogrammé', async () => {
    jest.useFakeTimers();
    const { api } = mountAuth();
    axios.post.mockImplementation(async (url) => {
      if (url.includes('/login/')) return loginResponse('tok-renew');
      if (url.endsWith('/v1/auth/token/renew-self')) return loginResponse('tok-renew');
      throw new Error('inattendu ' + url);
    });
    axios.get.mockImplementation(async (url) => (url.endsWith('/lookup-self') ? lookupOk() : { data: { data: { policy: '' } } }));
    await login(api, uniqueUser('ttl'), 'Passw0rd-Ttl');
    expect(api.current.token).toBe('tok-renew');
    expect(urlsOf(axios.post).filter(u => u.endsWith('/renew-self'))).toHaveLength(0);

    await advance(41000); // 2/3 de 60 s = 40 s
    const renewCalls = axios.post.mock.calls.filter(c => c[0] === `${VAULT}/v1/auth/token/renew-self`);
    expect(renewCalls).toHaveLength(1);
    expect(renewCalls[0][2].headers['X-Vault-Token']).toBe('tok-renew');

    await advance(41000); // nouveau TTL de 60 s → nouveau renouvellement
    expect(urlsOf(axios.post).filter(u => u.endsWith('/renew-self'))).toHaveLength(2);
    expect(api.current.token).toBe('tok-renew');
  });

  test('renouvellement refusé puis lookup-self 403 (jeton invalide) → déconnexion propre, extension vidée', async () => {
    jest.useFakeTimers();
    const { api, toasts, writeStates } = mountAuth();
    axios.post.mockImplementation(async (url) => {
      if (url.includes('/login/')) return loginResponse('tok-dead');
      if (url.endsWith('/renew-self')) throw forbidden();
      return { data: {} };
    });
    let tokenValid = true;
    axios.get.mockImplementation(async (url) => {
      if (url.endsWith('/lookup-self')) { if (tokenValid) return lookupOk(); throw forbidden(); }
      return { data: { data: { policy: '' } } };
    });
    await login(api, uniqueUser('dead'), 'Passw0rd-Dead');
    tokenValid = false;
    await advance(41000);
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toContain('login.sessionExpiredVault');
    expect(writeStates[writeStates.length - 1]).toMatchObject({ connected: false, secrets: [] });
    expect(window.electronWindow.setLoginMode).toHaveBeenCalled();
  });

  test('jeton non renouvelable : vérifié à l\'échéance, fin de session si Vault le refuse', async () => {
    jest.useFakeTimers();
    const { api, toasts } = mountAuth();
    axios.post.mockImplementation(async (url) => (url.includes('/login/') ? loginResponse('tok-fixed', 30, false) : { data: {} }));
    let expired = false;
    axios.get.mockImplementation(async (url) => {
      if (url.endsWith('/lookup-self')) { if (!expired) return lookupOk(30, false); throw forbidden(); }
      return { data: { data: { policy: '' } } };
    });
    await login(api, uniqueUser('fixed'), 'Passw0rd-Fixed');
    await advance(25000);
    expect(api.current.token).toBe('tok-fixed');
    expect(urlsOf(axios.post).filter(u => u.endsWith('/renew-self'))).toHaveLength(0);
    expired = true;
    await advance(7000);
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toContain('login.sessionExpiredVault');
  });

  test('serveur injoignable après l\'échéance du jeton : la session prend fin quand même', async () => {
    jest.useFakeTimers();
    const { api, toasts } = mountAuth();
    axios.post.mockImplementation(async (url) => (url.includes('/login/') ? loginResponse('tok-off', 30, false) : { data: {} }));
    let offline = false;
    axios.get.mockImplementation(async (url) => {
      if (offline) throw Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' });
      return url.endsWith('/lookup-self') ? lookupOk(30, false) : { data: { data: { policy: '' } } };
    });
    await login(api, uniqueUser('off'), 'Passw0rd-Off');
    offline = true;
    await advance(32000);
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toContain('login.sessionExpiredVault');
  });

  test('un 403 sur un appel Vault déclenche la vérification du jeton (lookup-self)', async () => {
    const { api, toasts } = mountAuth();
    axios.post.mockImplementation(async (url) => (url.includes('/login/') ? loginResponse('tok-403', 3600, true) : { data: {} }));
    let valid = true;
    axios.get.mockImplementation(async (url) => {
      if (url.endsWith('/lookup-self')) { if (valid) return lookupOk(3600, true); throw forbidden(); }
      return { data: { data: { policy: '' } } };
    });
    await login(api, uniqueUser('ic'), 'Passw0rd-Ic');
    const calls = axios.interceptors.response.use.mock.calls;
    expect(calls.length).toBeGreaterThan(0);
    const onRejected = calls[calls.length - 1][1];
    valid = false;
    const err = Object.assign(forbidden(), { config: { url: `${VAULT}/v1/MonEquipe/metadata?list=true` } });
    await act(async () => { await expect(onRejected(err)).rejects.toBe(err); });
    await flush();
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toContain('login.sessionExpiredVault');
  });

  test('un 403 sur une autre origine (HIBP…) ne déclenche aucune vérification', async () => {
    const { api } = mountAuth();
    axios.post.mockImplementation(async (url) => (url.includes('/login/') ? loginResponse('tok-other', 3600, true) : { data: {} }));
    axios.get.mockImplementation(async (url) => (url.endsWith('/lookup-self') ? lookupOk(3600, true) : { data: { data: { policy: '' } } }));
    await login(api, uniqueUser('other'), 'Passw0rd-Other');
    const lookups = () => urlsOf(axios.get).filter(u => u.endsWith('/lookup-self')).length;
    const before = lookups();
    const calls = axios.interceptors.response.use.mock.calls;
    const onRejected = calls[calls.length - 1][1];
    const err = Object.assign(forbidden(), { config: { url: 'https://api.pwnedpasswords.com/range/ABCDE' } });
    await act(async () => { await expect(onRejected(err)).rejects.toBe(err); });
    await flush();
    expect(lookups()).toBe(before);
    expect(api.current.token).toBe('tok-other');
  });

  test('jeton VALIDE sans droit sur lookup-self (403 « permission denied » seul) : pas de déconnexion, fin à l\'échéance connue', async () => {
    jest.useFakeTimers();
    const { api, toasts } = mountAuth();
    const denied = () => Object.assign(new Error('403'), { response: { status: 403, data: { errors: ['1 error occurred:\n\t* permission denied\n\n'] } } });
    axios.post.mockImplementation(async (url) => {
      if (url.includes('/login/')) return loginResponse('tok-nodefault', 60, true);
      if (url.endsWith('/renew-self')) throw denied(); // policy « default » absente
      return { data: {} };
    });
    axios.get.mockImplementation(async (url) => {
      if (url.endsWith('/lookup-self')) throw denied();
      throw denied(); // policies illisibles, etc.
    });
    await login(api, uniqueUser('nodef'), 'Passw0rd-NoDef');
    // Les 403 de la connexion (lookup-self, policies) ne ferment pas la session
    expect(api.current.token).toBe('tok-nodefault');
    await advance(41000); // renouvellement refusé, vérification impossible : la session continue
    expect(api.current.token).toBe('tok-nodefault');
    const calls = axios.interceptors.response.use.mock.calls;
    const onRejected = calls[calls.length - 1][1];
    const err = Object.assign(denied(), { config: { url: `${VAULT}/v1/MonEquipe/metadata?list=true` } });
    await act(async () => { await expect(onRejected(err)).rejects.toBe(err); });
    await flush();
    expect(api.current.token).toBe('tok-nodefault');
    expect(toastKeys(toasts)).not.toContain('login.sessionExpiredVault');
    await advance(21000); // échéance du TTL de 60 s : le jeton est forcément expiré
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toContain('login.sessionExpiredVault');
  });

  test('coffre local (http://127.0.0.1) : 403 sur lookup-self = jeton invalide', async () => {
    const { api, toasts } = mountAuth({ vaultUrl: 'http://127.0.0.1:51234' });
    axios.post.mockImplementation(async (url) => (url.includes('/login/') ? loginResponse('tok-local', 2764800, true) : { data: {} }));
    let valid = true;
    axios.get.mockImplementation(async (url) => {
      if (url.endsWith('/lookup-self') && !valid) throw Object.assign(new Error('403'), { response: { status: 403, data: { errors: ['permission denied'] } } });
      return url.endsWith('/lookup-self') ? { data: { data: { entity_name: 'x', policies: ['default'], ttl: 2764800 } } } : { data: { data: { policy: '' } } };
    });
    await login(api, uniqueUser('local'), 'Passw0rd-Local');
    valid = false;
    const calls = axios.interceptors.response.use.mock.calls;
    const onRejected = calls[calls.length - 1][1];
    const err = Object.assign(new Error('403'), { response: { status: 403 }, config: { url: 'http://127.0.0.1:51234/v1/users%2Fx/metadata?list=true' } });
    await act(async () => { await expect(onRejected(err)).rejects.toBe(err); });
    await flush();
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toContain('login.sessionExpiredVault');
  });

  test('déconnexion : le minuteur de renouvellement est annulé', async () => {
    jest.useFakeTimers();
    const { api } = mountAuth();
    axios.post.mockImplementation(async (url) => (url.includes('/login/') ? loginResponse('tok-bye') : { data: {} }));
    axios.get.mockImplementation(async (url) => (url.endsWith('/lookup-self') ? lookupOk() : { data: { data: { policy: '' } } }));
    await login(api, uniqueUser('bye'), 'Passw0rd-Bye');
    await act(async () => { await api.current.handleLogout(); });
    await advance(120000);
    expect(urlsOf(axios.post).filter(u => u.endsWith('/renew-self'))).toHaveLength(0);
  });
});

describe('AUTH-5 / AUTH-15 : serveur indisponible ≠ mot de passe faux', () => {
  test('5 réponses 503 (Vault scellé) : aucune tentative décomptée, message « serveur indisponible »', async () => {
    const { api, toasts } = mountAuth();
    const user = uniqueUser('sealed');
    for (let i = 0; i < 5; i++) {
      axios.post.mockRejectedValueOnce({ response: { status: 503, data: { errors: ['Vault is sealed'] } } });
      // eslint-disable-next-line no-await-in-loop -- tentatives successives
      await login(api, user, 'Bon-Mot-De-Passe-1');
    }
    expect(bruteForceProtection.isBlocked(user)).toBe(false);
    expect(bruteForceProtection.getStats(user).attempts).toBe(0);
    expect(toastKeys(toasts)).toEqual(Array(5).fill('login.serverUnavailable'));
    // Vault descellé : le bon mot de passe est envoyé et la connexion aboutit
    axios.post.mockResolvedValueOnce(loginResponse('tok-unsealed', 3600));
    axios.get.mockResolvedValue(lookupOk(3600));
    await login(api, user, 'Bon-Mot-De-Passe-1');
    expect(api.current.token).toBe('tok-unsealed');
  });

  test('500, 502, 504 et 429 ne sont pas décomptés non plus', async () => {
    const { api, toasts } = mountAuth();
    const user = uniqueUser('5xx');
    for (const status of [500, 502, 504, 429]) {
      axios.post.mockRejectedValueOnce({ response: { status } });
      // eslint-disable-next-line no-await-in-loop -- tentatives successives
      await login(api, user, 'Bon-Mot-De-Passe-2');
    }
    expect(bruteForceProtection.getStats(user).attempts).toBe(0);
    expect(toastKeys(toasts)).toEqual(['login.serverUnavailable', 'login.serverUnavailable', 'login.serverUnavailable', 'login.serverBusy']);
  });

  test('un refus d\'identifiants (400) reste décompté', async () => {
    const { api, toasts } = mountAuth();
    const user = uniqueUser('bad');
    axios.post.mockRejectedValueOnce({ response: { status: 400 } });
    await login(api, user, 'Mauvais-Mot-De-Passe');
    expect(bruteForceProtection.getStats(user).attempts).toBe(1);
    expect(toastKeys(toasts)).toEqual(['login.failedWithRemaining']);
    bruteForceProtection.registerSuccessfulAttempt(user);
  });
});

describe('AUTH-6 : MFA Vault (client_token vide + mfa_requirement)', () => {
  test('pas de « connexion réussie », pas de mode principal, compteur anti-force brute intact', async () => {
    const { api, toasts } = mountAuth();
    const user = uniqueUser('mfa');
    bruteForceProtection.registerFailedAttempt(user); // un échec antérieur
    jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 5000); // délai exponentiel écoulé
    axios.post.mockResolvedValueOnce({
      data: { auth: { client_token: '', mfa_requirement: { mfa_request_id: 'req-1', mfa_constraints: { totp: { any: [{ type: 'totp', id: 'm-1', uses_passcode: true }] } } } } },
    });
    await login(api, user, 'Passw0rd-Mfa');
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toEqual(['login.mfaRequired']);
    expect(window.electronWindow.setMainMode).not.toHaveBeenCalled();
    expect(urlsOf(axios.get)).toHaveLength(0); // ni lookup-self ni découverte des coffres sans jeton
    expect(bruteForceProtection.getStats(user).attempts).toBe(1);
    jest.restoreAllMocks();
    bruteForceProtection.registerSuccessfulAttempt(user);
  });

  test('réponse 200 sans jeton ni MFA (URL qui n\'est pas un Vault) : message d\'erreur, pas de session', async () => {
    const { api, toasts } = mountAuth();
    axios.post.mockResolvedValueOnce({ data: '<html>portail</html>' });
    await login(api, uniqueUser('html'), 'Passw0rd-Html');
    expect(api.current.token).toBe('');
    expect(toastKeys(toasts)).toEqual(['login.unexpectedResponse']);
    expect(window.electronWindow.setMainMode).not.toHaveBeenCalled();
  });
});

describe('AUTH-13 : déconnexion sans attendre la révocation du jeton', () => {
  test('revoke-self qui ne répond jamais : état effacé et écran de connexion dès le clic', async () => {
    const { api, writeStates } = mountAuth();
    axios.post.mockImplementation((url) => {
      if (url.includes('/login/')) return Promise.resolve(loginResponse('tok-offline', 3600));
      if (url.endsWith('/revoke-self')) return new Promise(() => {}); // serveur muet
      return Promise.resolve({ data: {} });
    });
    axios.get.mockResolvedValue(lookupOk(3600));
    await login(api, uniqueUser('offline'), 'Passw0rd-Offline');
    expect(api.current.token).toBe('tok-offline');

    let logoutDone = false;
    await act(async () => { api.current.handleLogout().then(() => { logoutDone = true; }); });
    await flush();
    expect(api.current.token).toBe('');
    expect(logoutDone).toBe(true);
    expect(window.electronWindow.setLoginMode).toHaveBeenCalled();
    expect(writeStates.some(s => s.connected === false)).toBe(true);
    // La révocation part quand même, avec l'ANCIEN jeton et un délai court
    const revoke = axios.post.mock.calls.find(c => c[0] === `${VAULT}/v1/auth/token/revoke-self`);
    expect(revoke).toBeTruthy();
    expect(revoke[2].headers['X-Vault-Token']).toBe('tok-offline');
    expect(revoke[2].timeout).toBeLessThanOrEqual(5000);
  });
});

describe('AUTH-14 : création du compte administrateur (premier démarrage du coffre local)', () => {
  test('confirmation différente : aucune requête, aucune tentative décomptée', async () => {
    const { api, toasts } = mountAuth();
    const user = uniqueUser('admin');
    await login(api, user, 'Tournesol-Bleu-2025', { setup: true, confirmPassword: 'Tournesol-Bleu-2026' });
    expect(axios.post).not.toHaveBeenCalled();
    expect(toastKeys(toasts)).toEqual(['login.setupMismatch']);
    expect(bruteForceProtection.getStats(user).attempts).toBe(0);
    // Le mot de passe saisi est conservé pour corriger la confirmation
    expect(api.current.password).toBe('Tournesol-Bleu-2025');
  });

  test('moins de 8 caractères : règle affichée, aucune requête', async () => {
    const { api, toasts } = mountAuth();
    await login(api, uniqueUser('short'), 'court', { setup: true, confirmPassword: 'court' });
    expect(axios.post).not.toHaveBeenCalled();
    expect(toastKeys(toasts)).toEqual(['login.setupTooShort']);
  });

  test('identifiant hors 2-64 caractères : refusé avant l\'envoi', async () => {
    const { api, toasts } = mountAuth();
    await login(api, 'a', 'Tournesol-Bleu-2026', { setup: true, confirmPassword: 'Tournesol-Bleu-2026' });
    expect(axios.post).not.toHaveBeenCalled();
    expect(toastKeys(toasts)).toEqual(['login.setupUsernameLength']);
  });

  test('confirmation identique : le compte est créé (confirmation transmise au serveur)', async () => {
    const { api } = mountAuth();
    axios.post.mockResolvedValueOnce(loginResponse('tok-admin', 2764800));
    axios.get.mockResolvedValue(lookupOk(2764800));
    await login(api, uniqueUser('ok'), 'Tournesol-Bleu-2026', { setup: true, confirmPassword: 'Tournesol-Bleu-2026' });
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(axios.post.mock.calls[0][1]).toEqual({ password: 'Tournesol-Bleu-2026', confirm: 'Tournesol-Bleu-2026' });
    expect(api.current.token).toBe('tok-admin');
  });

  test('connexion habituelle (évènement de clic en argument) : corps inchangé, sans confirmation', async () => {
    const { api } = mountAuth();
    axios.post.mockResolvedValueOnce(loginResponse('tok-usual', 3600));
    axios.get.mockResolvedValue(lookupOk(3600));
    await login(api, uniqueUser('usual'), 'x', { type: 'click', target: {} });
    expect(axios.post.mock.calls[0][1]).toEqual({ password: 'x' });
    expect(api.current.token).toBe('tok-usual');
  });
});
