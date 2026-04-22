import React from 'react';

/**
 * Formulaire de connexion LDAP.
 * Affiche le formulaire d'authentification avec nom d'utilisateur, mot de passe et "se souvenir de moi".
 */
export default function LoginForm({
  authUser, setAuthUser,
  password, setPassword,
  rememberMe, setRememberMe,
  onLogin,
  configLoaded,
  appMode,
  t
}) {
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
            <img src={process.env.PUBLIC_URL + '/logo.png'} alt="RDVAULT" style={{ height: '176px', width: 'auto', marginBottom: '-4px' }} />
            <h2>{t('login.title')}</h2>
            <p>{t('login.fieldsRequired')}</p>
          </div>

          <div className="login-form">
            <div className="form-group-vertical">
              <label className="form-label-vertical">{t('login.username')}</label>
              <input
                value={authUser}
                onChange={e => setAuthUser(e.target.value)}
                placeholder={t('login.placeholderUser')}
                className="form-input-vertical"
                onKeyDown={(e) => e.key === 'Enter' && onLogin()}
              />
            </div>

            <div className="form-group-vertical">
              <label className="form-label-vertical">{t('login.password')}</label>
              <input
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder={t('login.placeholderPass')}
                type="password"
                className="form-input-vertical"
                onKeyDown={(e) => e.key === 'Enter' && onLogin()}
              />
            </div>

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

            <button onClick={onLogin} className="btn btn-primary btn-login" type="button">
              <svg viewBox="0 0 24 24" fill="none" width="20" height="20">
                <path d="M15 3H19C19.5304 3 20.0391 3.21071 20.4142 3.58579C20.7893 3.96086 21 4.46957 21 5V19C21 19.5304 20.7893 20.0391 20.4142 20.4142C20.0391 20.7893 19.5304 21 19 21H15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M10 17L15 12L10 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M15 12H3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              {t('login.submit')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
