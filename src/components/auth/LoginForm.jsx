import React, { useEffect, useId, useState } from 'react';
import axios from 'axios';
import { analyzePassword, STRENGTH_LABEL_KEYS } from '../../utils/passwordStrength';
import { SETUP_MIN_PASSWORD_LENGTH } from '../../hooks/useAuth';

// Délai de la détection du premier démarrage (serveur local, réponse immédiate attendue)
const INIT_PROBE_TIMEOUT_MS = 5000;

/**
 * AUTH-14 : premier démarrage du coffre local (aucun compte) ?
 * Le premier « Se connecter » sur un coffre local vide crée le compte administrateur avec le mot
 * de passe saisi : le formulaire passe alors en mode création. Détection par GET /v1/sys/init
 * (même route et même réponse que Vault : { initialized }), en mode local uniquement. Route absente
 * (403/404), serveur injoignable ou mode entreprise : formulaire de connexion habituel.
 *
 * Nouvelle détection (`recheck` incrémenté par useAuth) : le coffre local a refusé une connexion faute de
 * confirmation (400 « password confirmation required », il n'a donc aucun compte) alors que la première
 * détection avait échoué (délai, serveur pas encore prêt). Le formulaire passe aussitôt en mode création ;
 * la détection relancée ne le remet en mode connexion que si le serveur répond qu'un compte existe
 * désormais (créé entre-temps).
 *
 * @param {boolean} [forced] - mode imposé par l'appelant (aucune détection)
 * @param {number} [recheck] - compteur de demandes de nouvelle détection (0 : aucune)
 * @returns {boolean} vrai si le compte administrateur reste à créer
 */
function useFirstRunSetup(forced, recheck = 0) {
  const [detected, setDetected] = useState(false);
  const isForced = typeof forced === 'boolean';

  useEffect(() => {
    if (isForced) return undefined;
    let cancelled = false;
    const serverRequiresSetup = recheck > 0;
    if (serverRequiresSetup) setDetected(true);
    (async () => {
      try {
        const getConfig = window.electronConfig?.getConfig;
        if (typeof getConfig !== 'function') return;
        const result = await getConfig();
        const config = result?.success ? result.config : null;
        if (!config || config.APP_MODE !== 'local' || typeof config.VAULT_URL !== 'string' || !config.VAULT_URL) return;
        const res = await axios.get(`${config.VAULT_URL}/v1/sys/init`, { timeout: INIT_PROBE_TIMEOUT_MS });
        if (cancelled) return;
        if (res?.data?.initialized === false) setDetected(true);
        else if (serverRequiresSetup && res?.data?.initialized === true) setDetected(false);
      } catch { /* route absente ou serveur injoignable : mode inchangé */ }
    })();
    return () => { cancelled = true; };
  }, [isForced, recheck]);

  return isForced ? forced : detected;
}

/**
 * Formulaire de connexion LDAP.
 * Affiche le formulaire d'authentification avec nom d'utilisateur, mot de passe et "se souvenir de moi".
 * Premier démarrage du coffre local : formulaire de création du compte administrateur (AUTH-14),
 * avec confirmation du mot de passe maître, règle de longueur et indicateur de force ; onLogin
 * reçoit alors { setup: true, confirmPassword } (vérifiés par useAuth.handleLogin avant l'envoi).
 * setupRecheck : compteur (useAuth.firstRunRecheck) ; chaque incrément relance la détection et passe en
 * mode création (le serveur a exigé la confirmation du premier compte).
 */
export default function LoginForm({
  authUser, setAuthUser,
  password, setPassword,
  rememberMe, setRememberMe,
  onLogin,
  t,
  setupMode,
  setupRecheck = 0,
}) {
  const setup = useFirstRunSetup(setupMode, setupRecheck);
  const [confirmPassword, setConfirmPassword] = useState('');
  const fieldId = useId();
  // UI-36 : libellés reliés (htmlFor/id) : nom accessible = libellé visible, le texte
  // indicatif reste un simple exemple
  const usernameId = `${fieldId}-username`;
  const passwordId = `${fieldId}-password`;
  const confirmId = `${fieldId}-confirm`;
  const ruleId = `${fieldId}-rule`;
  const mismatchId = `${fieldId}-mismatch`;

  // Une seule voie d'envoi (bouton, Entrée dans chaque champ) : jamais l'évènement en argument
  const submit = () => {
    if (setup) onLogin({ setup: true, confirmPassword });
    else onLogin();
  };
  const onEnter = (e) => { if (e.key === 'Enter') submit(); };

  const strength = setup && password ? analyzePassword(password) : null;
  const mismatch = setup && confirmPassword !== '' && confirmPassword !== password;

  return (
    <div className="main-header">
      <div className="login-container">
        <div className="login-card">
          <div className="login-header" style={{ WebkitAppRegion: 'drag' }}>
            <button
              className="login-close-btn"
              onClick={() => window.electronWindow?.close()}
              title={t('common.close')}
              type="button"
              style={{ WebkitAppRegion: 'no-drag' }}
            >
              <svg width="10" height="10" viewBox="0 0 10 10"><path stroke="currentColor" strokeWidth="1.2" d="M1,1 L9,9 M9,1 L1,9" /></svg>
            </button>
            {/* Mode création : logo réduit pour que les champs supplémentaires tiennent dans la fenêtre de connexion */}
            <img src={process.env.PUBLIC_URL + '/logo.png'} alt="RDVAULT" style={{ height: setup ? '64px' : '176px', width: 'auto', marginBottom: '-4px' }} />
            <h2>{t(setup ? 'login.setupTitle' : 'login.title')}</h2>
            <p>{t(setup ? 'login.setupHint' : 'login.fieldsRequired')}</p>
          </div>

          <div className="login-form">
            <div className="form-group-vertical">
              <label className="form-label-vertical" htmlFor={usernameId}>{t('login.username')}</label>
              <input
                id={usernameId}
                autoComplete="username"
                value={authUser}
                onChange={e => setAuthUser(e.target.value)}
                placeholder={t('login.placeholderUser')}
                className="form-input-vertical"
                onKeyDown={onEnter}
              />
            </div>

            <div className="form-group-vertical">
              <label className="form-label-vertical" htmlFor={passwordId}>{t('login.password')}</label>
              <input
                id={passwordId}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder={t('login.placeholderPass')}
                type="password"
                className="form-input-vertical"
                autoComplete={setup ? 'new-password' : 'current-password'}
                aria-describedby={setup ? ruleId : undefined}
                onKeyDown={onEnter}
              />
              {setup && (
                <div id={ruleId} style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginTop: 'var(--sp-2)' }}>
                  {/* Règle et force sur une même ligne : le formulaire tient dans la fenêtre de connexion */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                    <span>{t('login.setupRule', { min: SETUP_MIN_PASSWORD_LENGTH })}</span>
                    {strength && (
                      <span>{t('passwordGenerator.strength')} <strong style={{ color: strength.color }}>{t(STRENGTH_LABEL_KEYS[strength.level])}</strong></span>
                    )}
                  </div>
                  {strength && (
                    <div data-testid="setup-strength" className="clipboard-progress" style={{ marginTop: 'var(--sp-1)' }}>
                      <div
                        className="clipboard-progress-bar"
                        style={{ width: `${strength.percentage}%`, background: strength.color, transition: 'width 0.3s, background 0.3s' }}
                      />
                    </div>
                  )}
                </div>
              )}
            </div>

            {setup && (
              <div className="form-group-vertical">
                <label className="form-label-vertical" htmlFor={confirmId}>{t('login.confirmPassword')}</label>
                <input
                  id={confirmId}
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  placeholder={t('login.placeholderConfirm')}
                  type="password"
                  className="form-input-vertical"
                  autoComplete="new-password"
                  aria-invalid={mismatch || undefined}
                  aria-describedby={mismatch ? mismatchId : undefined}
                  onKeyDown={onEnter}
                />
                {mismatch && (
                  <div id={mismatchId} role="alert" style={{ fontSize: 'var(--text-xs)', color: 'var(--error)', marginTop: 'var(--sp-2)' }}>
                    {t('login.setupMismatchHint')}
                  </div>
                )}
              </div>
            )}

            <div className="form-group-vertical" style={{ marginBottom: 'var(--sp-4)' }}>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                />
                <span>{t('login.rememberUser')}</span>
              </label>
            </div>

            <button onClick={submit} className="btn btn-primary btn-login" type="button">
              <svg viewBox="0 0 24 24" fill="none" width="20" height="20">
                <path d="M15 3H19C19.5304 3 20.0391 3.21071 20.4142 3.58579C20.7893 3.96086 21 4.46957 21 5V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M10 17L15 12L10 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M15 12H3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              {t(setup ? 'login.setupSubmit' : 'login.submit')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
