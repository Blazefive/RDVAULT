// ========================================
// MODULE: Secure Clipboard - Gestion sécurisée du presse-papier
// ========================================
// Fonctions de copie de mots de passe avec auto-effacement.
//
// Sécurité:
// - Effacement automatique après délai configurable
// - Nettoyage de l'historique Windows (Win+V) après toute copie de mot de passe,
//   même si l'utilisateur a copié autre chose entre-temps (le mot de passe est
//   déjà entré dans l'historique au moment de la copie)
// - Comparaison avant effacement du presse-papiers courant pour ne pas supprimer d'autres données
// - Commande PowerShell constante encodée Base64, exécutée sans shell (pas d'injection possible)
//
// Limite connue : l'API Electron ne permet pas d'écrire les formats
// "ExcludeClipboardContentFromMonitorProcessing" / "CanIncludeInClipboardHistory"
// en même temps que le texte ; le mot de passe transite donc brièvement par
// l'historique Win+V (et le presse-papiers cloud s'il est activé) avant nettoyage.

const { clipboard } = require('electron');
const { execFile } = require('child_process');
const path = require('path');
const log = require('./logger');

// Commande constante : vider l'historique du presse-papiers Windows (Win+V)
const PS_CLEAR_HISTORY = `
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $null = [Windows.ApplicationModel.DataTransfer.Clipboard,Windows.ApplicationModel.DataTransfer,ContentType=WindowsRuntime]
  [Windows.ApplicationModel.DataTransfer.Clipboard]::ClearHistory()
`;
const PS_ENCODED = Buffer.from(PS_CLEAR_HISTORY, 'utf16le').toString('base64');

/**
 * Vide l'historique du presse-papiers Windows (Win+V). Sans effet sur les autres OS.
 * @returns {Promise<boolean>} true si la commande a réussi
 */
function clearClipboardHistory() {
  if (process.platform !== 'win32') return Promise.resolve(false);
  return new Promise((resolve) => {
    // SÉCURITÉ: chemin absolu (pas de PATH hijacking), execFile (pas de shell), -NoProfile
    const psPath = path.join(process.env.SYSTEMROOT || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    execFile(psPath, ['-NoProfile', '-NonInteractive', '-EncodedCommand', PS_ENCODED], { timeout: 15000, windowsHide: true }, (err) => {
      if (err) {
        log.warn('[Clipboard] Échec du nettoyage de l\'historique Win+V:', err.code || err.message);
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}

/**
 * Copie un mot de passe avec auto-effacement après un délai
 *
 * @param {string} password - Le mot de passe à copier
 * @param {Object} options - Options de configuration
 * @param {number} options.timeoutMs - Délai avant effacement (défaut: 12000ms = 12s)
 * @returns {Object} Objet avec méthodes cancel(), remaining() et clearNow()
 */
function copyPasswordWithAutoClear(password, options = {}) {
  if (typeof password !== 'string') return { cancel: () => {}, remaining: () => 0, clearNow: () => {} };
  const timeoutMs = options.timeoutMs ?? 12000;

  clipboard.writeText(password);

  const deadline = Date.now() + timeoutMs;
  let timerId = null;
  let cleared = false;

  const clear = () => {
    if (cleared) return;
    cleared = true;
    timerId = null;
    try {
      // N'effacer le presse-papiers courant que s'il contient encore le mot de passe
      if (clipboard.readText() === password) clipboard.clear();
    } catch (err) {
      log.warn('[Clipboard] Effacement du presse-papiers impossible');
    }
    // L'historique contient le mot de passe dans tous les cas : le vider systématiquement
    clearClipboardHistory();
  };

  timerId = setTimeout(clear, timeoutMs);

  return {
    cancel: () => {
      if (timerId) {
        clearTimeout(timerId);
        timerId = null;
      }
    },
    remaining: () => Math.max(0, deadline - Date.now()),
    clearNow: () => {
      if (timerId) {
        clearTimeout(timerId);
        timerId = null;
      }
      clear();
    }
  };
}

module.exports = {
  copyPasswordWithAutoClear,
  clearClipboardHistory,
};
