// ========================================
// MISE À JOUR AUTOMATIQUE (electron-updater)
// ========================================
// Indispensable pour un produit public : permet de diffuser un correctif de
// sécurité à tous les utilisateurs en quelques heures.
//
// Ce module est ENTIÈREMENT PROTÉGÉ : si la dépendance « electron-updater » n'est
// pas installée (ou en développement), il ne fait rien et n'empêche ni le build ni
// l'exécution. Pour l'activer :
//   1) npm i electron-updater
//   2) renseigner le bloc "publish" dans electron-builder.json (voir ce fichier)
//   3) signer les binaires Windows (sinon SmartScreen avertit à chaque mise à jour)
//
// Flux : au démarrage (app empaquetée), vérifie la présence d'une mise à jour, la
// télécharge, puis informe le renderer. L'installation n'a lieu qu'au prochain
// redémarrage (ou via l'action « installer maintenant » déclenchée par l'IHM).

'use strict';

const log = require('./logger');

let initialized = false;

/**
 * @param {() => (import('electron').BrowserWindow|null)} getWindow - accès paresseux à la fenêtre principale
 * @param {{ app: import('electron').App, ipcMain: import('electron').IpcMain, enabled?: boolean }} deps
 */
function initAutoUpdater(getWindow, { app, ipcMain, enabled = true } = {}) {
  if (initialized) return;
  initialized = true;

  // Désactivé explicitement, ou hors application empaquetée : ne rien faire.
  if (!enabled) { log.info('[Update] désactivé par configuration'); return; }
  if (!app || !app.isPackaged) { log.info('[Update] ignoré (développement)'); return; }

  let autoUpdater;
  try {
    ({ autoUpdater } = require('electron-updater'));
  } catch (err) {
    log.warn('[Update] electron-updater non installé — mises à jour automatiques indisponibles');
    return;
  }

  const send = (channel, payload) => {
    try {
      const win = getWindow && getWindow();
      if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
    } catch { /* fenêtre indisponible */ }
  };

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  // Journalisation minimale (pas d'electron-log requis)
  autoUpdater.logger = { info: (m) => log.info('[Update] ' + m), warn: (m) => log.warn('[Update] ' + m), error: (m) => log.error('[Update] ' + m), debug: () => {} };

  autoUpdater.on('checking-for-update', () => send('update-status', { state: 'checking' }));
  autoUpdater.on('update-available', (info) => send('update-status', { state: 'available', version: info?.version }));
  autoUpdater.on('update-not-available', () => send('update-status', { state: 'none' }));
  autoUpdater.on('download-progress', (p) => send('update-status', { state: 'downloading', percent: Math.round(p?.percent || 0) }));
  autoUpdater.on('update-downloaded', (info) => send('update-status', { state: 'downloaded', version: info?.version }));
  autoUpdater.on('error', (err) => {
    log.error('[Update] erreur: ' + (err?.message || err));
    send('update-status', { state: 'error' });
  });

  // IPC déclenché par le renderer
  ipcMain.handle('update:check', async () => {
    try { await autoUpdater.checkForUpdates(); return { success: true }; }
    catch (err) { return { success: false, error: String(err?.message || err) }; }
  });
  ipcMain.handle('update:install', () => {
    // Redémarre et installe la version téléchargée
    try { autoUpdater.quitAndInstall(false, true); return { success: true }; }
    catch (err) { return { success: false, error: String(err?.message || err) }; }
  });

  // Vérification au démarrage (différée pour ne pas ralentir l'ouverture), puis toutes les 6 h
  setTimeout(() => { autoUpdater.checkForUpdates().catch(() => {}); }, 10000);
  setInterval(() => { autoUpdater.checkForUpdates().catch(() => {}); }, 6 * 60 * 60 * 1000);

  log.info('[Update] initialisé');
}

module.exports = { initAutoUpdater };
