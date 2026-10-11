// ========================================
// TESTS : handleUrlAction (src/utils/urlHandler.js)
// ========================================
// RBI-15 : une URL sans schéma dont l'hôte commence par « http » (httpd.corp.local) s'ouvre
//          (navigateur ou session RBI) au lieu d'afficher « URL invalide ».
// RBI-11 : refus d'une session RBI (page de connexion hors du domaine de l'entrée) → motif traduit ;
//          champ « website » de l'entrée transmis à la session (seconde adresse de référence).
// RBI-29 : erreurs assainies traduites avec le t de l'appelant.

import { handleUrlAction, rbiLaunchErrorMessage, rbiWebsiteOption } from './urlHandler';

const t = (key) => `[${key}]`;

function options(extra = {}) {
  return {
    isSecretRbiOnly: () => false,
    getTotpKeyName: (name) => `WEB-${name}`,
    getTotpCode: jest.fn().mockResolvedValue(null),
    startClipboardTimer: jest.fn(),
    showToast: jest.fn(),
    t,
    ...extra,
  };
}

afterEach(() => {
  delete window.electronRBI;
  delete window.electronBrowser;
});

describe('RBI-15 : hôte commençant par « http » sans schéma', () => {
  test('mode RBI uniquement : session lancée sur https://httpd.corp.local', async () => {
    const launchSession = jest.fn().mockResolvedValue({ success: true });
    window.electronRBI = { launchSession };
    const opts = options({ isSecretRbiOnly: () => true });
    await handleUrlAction('httpd.corp.local', { name: 'httpd', username: 'u', password: 'p' }, opts);
    expect(launchSession).toHaveBeenCalledTimes(1);
    expect(launchSession.mock.calls[0][0].url).toBe('https://httpd.corp.local');
    expect(opts.showToast).not.toHaveBeenCalledWith('[error.invalidUrl]', 'error');
  });

  test('navigateur par défaut : https://httpd.corp.local ouvert', async () => {
    const openUrl = jest.fn().mockResolvedValue({ success: true });
    window.electronBrowser = { openUrl };
    const opts = options();
    await handleUrlAction('httpd.corp.local', { name: 'httpd' }, opts);
    expect(openUrl).toHaveBeenCalledWith('https://httpd.corp.local', 'default');
    expect(opts.showToast).not.toHaveBeenCalled();
  });
});

describe('RBI-11 : refus de session traduit', () => {
  test('code RBI_FOREIGN_ORIGIN → t(error.rbiForeignOrigin), jamais le texte français brut', async () => {
    window.electronRBI = {
      launchSession: jest.fn().mockResolvedValue({ success: false, error: 'Page de connexion hors du domaine de l\'entrée', code: 'RBI_FOREIGN_ORIGIN' }),
    };
    const opts = options({ isSecretRbiOnly: () => true });
    await handleUrlAction('https://app.example.com', { name: 'app', username: 'u', password: 'p' }, opts);
    expect(opts.showToast).toHaveBeenLastCalledWith('[error.rbiForeignOrigin]', 'error');
  });

  test('rbiLaunchErrorMessage : autre échec → texte renvoyé, sinon message générique', () => {
    expect(rbiLaunchErrorMessage({ success: false, error: 'Délai dépassé' }, t)).toBe('Délai dépassé');
    expect(rbiLaunchErrorMessage({ success: false }, t)).toBe('[error.rbiLaunch]');
    expect(rbiLaunchErrorMessage(undefined, t)).toBe('[error.rbiLaunch]');
  });
});

describe('I18N-32 : libellé du minuteur de presse-papiers traduit (SSH / RDP)', () => {
  test('SSH : « [table.password] (SSH) », plus « Password (SSH) » codé en dur', async () => {
    window.electronBrowser = { openSshConnection: jest.fn().mockResolvedValue({ success: true }) };
    const opts = options();
    await handleUrlAction('ssh://srv.example.com', { name: 'srv', username: 'root', password: 'pw-ssh' }, opts);
    expect(opts.startClipboardTimer).toHaveBeenCalledWith('[table.password] (SSH)', 'pw-ssh');
  });

  test('RDP : « [table.password] (RDP) »', async () => {
    window.electronBrowser = { openRdpConnection: jest.fn().mockResolvedValue({ success: true }) };
    const opts = options();
    await handleUrlAction('rdp://poste.example.com', { name: 'poste', username: 'admin', password: 'pw-rdp' }, opts);
    expect(opts.startClipboardTimer).toHaveBeenCalledWith('[table.password] (RDP)', 'pw-rdp');
  });
});

describe('RBI-29 : erreurs assainies traduites avec le t de l\'appelant', () => {
  test('SSH : 403 → [error.sshOpen] [error.sanitized.forbidden] (cause sans texte d\'origine)', async () => {
    window.electronBrowser = { openSshConnection: jest.fn().mockRejectedValue({ response: { status: 403 }, message: 'hvs.SECRET' }) };
    const opts = options();
    await handleUrlAction('ssh://srv.example.com', { name: 'srv', username: 'root' }, opts);
    expect(opts.showToast).toHaveBeenCalledWith('[error.sshOpen] [error.sanitized.forbidden]', 'error');
  });
});

describe('RBI-11 : champ « website » de l\'entrée transmis à la session RBI', () => {
  test('rbiWebsiteOption : chaîne non vide (rognée) → { website }, sinon aucune option', () => {
    expect(rbiWebsiteOption({ website: ' https://sso.example.com ' })).toEqual({ website: 'https://sso.example.com' });
    expect(rbiWebsiteOption({ website: '' })).toEqual({});
    expect(rbiWebsiteOption({ website: '   ' })).toEqual({});
    expect(rbiWebsiteOption({ website: 42 })).toEqual({});
    expect(rbiWebsiteOption({})).toEqual({});
    expect(rbiWebsiteOption(null)).toEqual({});
  });

  test('mode RBI uniquement : launchSession reçoit url ET website (avant : url seule)', async () => {
    const launchSession = jest.fn().mockResolvedValue({ success: true });
    window.electronRBI = { launchSession };
    const opts = options({ isSecretRbiOnly: () => true });
    await handleUrlAction('https://app.example.com', { name: 'app', username: 'u', password: 'p', website: 'https://sso.example.com' }, opts);
    expect(launchSession.mock.calls[0][0]).toEqual(expect.objectContaining({ url: 'https://app.example.com', website: 'https://sso.example.com' }));
  });

  test('entrée sans website : aucune option website', async () => {
    const launchSession = jest.fn().mockResolvedValue({ success: true });
    window.electronRBI = { launchSession };
    await handleUrlAction('https://app.example.com', { name: 'app', username: 'u', password: 'p' }, options({ isSecretRbiOnly: () => true }));
    expect('website' in launchSession.mock.calls[0][0]).toBe(false);
  });
});
