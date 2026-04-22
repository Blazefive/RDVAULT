import { buildSafeUrl, sanitizeErrorMessage, safeWindowOpen } from './security';
import secureLogger from '../secureLogger';

/**
 * handleUrlAction — route URL clicks to the appropriate handler
 * (SSH, RDP, SFTP, UNC/local paths, FTP/Telnet/VNC, HTTP/HTTPS, RBI-only)
 *
 * @param {string} url - The URL from the secret
 * @param {Object} secret - The full secret object (name, username, password, Port, etc.)
 * @param {Object} options - Callbacks and flags
 */
export async function handleUrlAction(url, secret, {
  isSecretRbiOnly,
  getTotpKeyName,
  getTotpCode,
  startClipboardTimer,
  showToast,
  t
}) {
  const urlLower = url.toLowerCase();
  const isSsh = urlLower.startsWith('ssh://') || urlLower.includes(':22');
  const isUncPath = url.startsWith('\\\\') || url.startsWith('//');
  const isLocalPath = /^[a-zA-Z]:\\/.test(url);
  const isWindowsPath = isUncPath || isLocalPath;

  // ── Windows paths (UNC or local drive) ──
  if (isWindowsPath) {
    if (!/^(\\\\[^\\]+\\|\/\/[^/]+\/|[a-zA-Z]:\\)/.test(url)) {
      showToast(t('error.invalidPath'), 'error');
      return;
    }
    try {
      if (window.electronBrowser?.openExternalLink) {
        const result = await window.electronBrowser.openExternalLink(url);
        if (result.success) {
          showToast(t('toast.explorerOpened'), 'success', 1500);
        } else {
          showToast(result.error || t('error.explorerOpen'), 'error');
        }
      } else {
        showToast(t('error.explorerUnavailable'), 'error');
      }
    } catch (err) {
      showToast(`${t('error.explorerOpen')} ${sanitizeErrorMessage(err)}`, 'error');
    }
    return;
  }

  // ── SSH ──
  if (isSsh) {
    try {
      let host = url.replace(/^ssh:\/\//i, '');
      let port = '22';

      if (secret.Port || secret.port) {
        port = String(secret.Port || secret.port);
        secureLogger.debug('[SSH] Port depuis champ personnalisé');
      } else {
        const portMatch = host.match(/:(\d+)$/);
        if (portMatch) {
          port = portMatch[1];
          host = host.replace(`:${port}`, '');
          secureLogger.debug('[SSH] Port depuis URL');
        } else {
          secureLogger.debug('[SSH] Port par défaut: 22');
        }
      }

      host = host.replace(/^[^@]+@/, '');

      if (!host || host.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(host)) {
        showToast(t('error.invalidSshHost'), 'error');
        return;
      }
      const portNum = parseInt(port, 10);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        showToast(t('error.invalidSshPort'), 'error');
        return;
      }

      secureLogger.debug('[SSH] Connexion lancée');

      if (window.electronBrowser?.openSshConnection) {
        const result = await window.electronBrowser.openSshConnection({
          host,
          username: secret.username,
          port
        });

        if (result.success) {
          if (secret.password) {
            await startClipboardTimer('Password (SSH)', secret.password);
          }
        } else {
          showToast(result.error || t('error.sshOpen'), 'error');
        }
      } else {
        showToast(t('error.sshUnavailable'), 'error');
      }
    } catch (err) {
      showToast(`${t('error.sshOpen')} ${sanitizeErrorMessage(err)}`, 'error');
    }
    return;
  }

  // ── RDP ──
  if (urlLower.startsWith('rdp:')) {
    if (window.electronBrowser?.openRdpConnection) {
      try {
        const rdpUrl = url.replace(/^rdp:\/\//i, '');
        const [hostPort] = rdpUrl.split('/');
        const [host, port] = hostPort.split(':');

        if (!host || host.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(host)) {
          showToast(t('error.invalidRdpHost'), 'error'); return;
        }
        const rdpPort = port || '3389';
        const rdpPortNum = parseInt(rdpPort, 10);
        if (isNaN(rdpPortNum) || rdpPortNum < 1 || rdpPortNum > 65535) {
          showToast(t('error.invalidRdpPort'), 'error'); return;
        }

        const result = await window.electronBrowser.openRdpConnection({
          host,
          username: secret.username,
          password: secret.password,
          port: rdpPort
        });

        if (result.success) {
          if (secret.password) {
            await startClipboardTimer('Password (RDP)', secret.password);
          }
        } else {
          showToast(result.error || t('error.rdpOpen'), 'error');
        }
      } catch (err) {
        showToast(`${t('error.rdpOpen')} ${sanitizeErrorMessage(err)}`, 'error');
      }
    } else {
      showToast(t('error.rdpUnavailable'), 'error');
    }
    return;
  }

  // ── SFTP ──
  if (urlLower.startsWith('sftp:')) {
    if (window.electronBrowser?.openSftpConnection) {
      try {
        const sftpUrl = url.replace(/^sftp:\/\//i, '');
        const [hostPort] = sftpUrl.split('/');
        const [host, port] = hostPort.split(':');

        if (!host || host.length > 253 || !/^[a-zA-Z0-9._-]+$/.test(host)) {
          showToast(t('error.invalidSftpHost'), 'error'); return;
        }
        const sftpPort = port || '22';
        const sftpPortNum = parseInt(sftpPort, 10);
        if (isNaN(sftpPortNum) || sftpPortNum < 1 || sftpPortNum > 65535) {
          showToast(t('error.invalidSftpPort'), 'error'); return;
        }

        const result = await window.electronBrowser.openSftpConnection({
          host,
          username: secret.username,
          password: secret.password,
          port: sftpPort
        });

        if (result.success) {
          showToast(result.client === 'filezilla' ? t('toast.sftpFilezilla') : t('toast.sftpWinscp'), 'success', 3000);
        } else {
          showToast(result.error || t('error.sftpOpen'), 'error');
        }
      } catch (err) {
        showToast(`${t('error.sftpOpen')} ${sanitizeErrorMessage(err)}`, 'error');
      }
    } else {
      showToast(t('error.sftpOpen'), 'error');
    }
    return;
  }

  // ── Other special protocols (ftp, telnet, vnc) ──
  const otherProtocols = ['ftp:', 'telnet:', 'vnc:'];
  const isOtherProtocol = otherProtocols.some(proto => urlLower.startsWith(proto));

  if (isOtherProtocol) {
    try {
      const parsedProto = new URL(url);
      if (!['ftp:', 'telnet:', 'vnc:'].includes(parsedProto.protocol)) {
        showToast(t('error.protocolBlocked'), 'error'); return;
      }
    } catch { showToast(t('error.invalidUrl'), 'error'); return; }

    if (window.electronBrowser?.openExternalLink) {
      await window.electronBrowser.openExternalLink(url);
    } else {
      safeWindowOpen(url);
    }
    return;
  }

  // ── HTTP/HTTPS (default) ──
  const safeUrl = buildSafeUrl(url);
  if (!safeUrl) { showToast(t('error.invalidUrl'), 'error'); return; }

  if (isSecretRbiOnly(secret.name) && window.electronRBI?.launchSession) {
    // Mode RBI-Only : toujours ouvrir en session sécurisée
    let totpCode = null;
    try {
      const totpKey = getTotpKeyName(secret.name);
      totpCode = await getTotpCode(totpKey);
      if (totpCode) {
        showToast(t('toast.totpRetrieved'), 'info', 2000);
      } else {
        showToast(t('toast.launchingRbiNoTotp'), 'info', 2000);
      }
    } catch (e) {
      showToast(t('toast.launchingRbi'), 'info', 3000);
    }
    const result = await window.electronRBI.launchSession({
      url: safeUrl,
      username: secret.username,
      password: secret.password,
      totp: totpCode,
      skipOverlay: false,
      policies: {
        disableClipboard: true,
        disableNewTabs: true,
        disableDownloads: false
      }
    });
    if (result.success) {
      showToast(t('toast.rbiOpened'), 'success', 3000);
    } else {
      showToast(result.error || t('error.rbiLaunch'), 'error');
    }
  } else if (window.electronBrowser?.openUrl) {
    await window.electronBrowser.openUrl(safeUrl, 'default');
  } else {
    safeWindowOpen(safeUrl);
  }
}
