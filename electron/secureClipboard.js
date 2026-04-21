// ========================================
// MODULE: Secure Clipboard - Gestion sécurisée du presse-papier
// ========================================
// Fonctions de copie de mots de passe avec auto-effacement.
//
// Sécurité:
// - Effacement automatique après délai configurable
// - Nettoyage de l'historique Windows (Win+V)
// - Comparaison avant effacement pour éviter de supprimer d'autres données
// - Commande PowerShell sécurisée via encodage Base64 (protection injection)

const { clipboard } = require('electron');
const { execFile } = require('child_process');
const path = require('path');

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

  // Copie du mot de passe
  clipboard.writeText(password);

  const deadline = Date.now() + timeoutMs;
  let timerId = null;

  // Fonction d'effacement complet du presse-papiers
  const clear = () => {
    const current = clipboard.readText();
    // N'effacer que si le contenu n'a pas changé entre-temps
    if (current === password) {
      // Effacer le presse-papier actuel
      clipboard.clear();

      // SÉCURITÉ: Effacer l'historique Windows (Win+V) via l'API Windows Runtime
      // Utilisation de l'encodage Base64 pour éviter les injections de commandes
      // (la commande PowerShell est encodée, pas exécutée en tant que chaîne)
      const psCommand = `
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $null = [Windows.ApplicationModel.DataTransfer.Clipboard,Windows.ApplicationModel.DataTransfer,ContentType=WindowsRuntime]
        [Windows.ApplicationModel.DataTransfer.Clipboard]::ClearHistory()
      `;

      // Encoder la commande en Base64 pour éviter les problèmes d'échappement
      // et protéger contre les injections de commandes
      const encodedCommand = Buffer.from(psCommand, 'utf16le').toString('base64');

      // SÉCURITÉ: execFile évite l'injection de commandes (pas de shell intermédiaire)
      // -NoProfile empêche l'exécution de scripts de profil utilisateur
      // SÉCURITÉ: Utiliser le chemin absolu pour éviter le PATH hijacking
      const psPath = path.join(process.env.SYSTEMROOT || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
      execFile(psPath, ['-NoProfile', '-NonInteractive', '-EncodedCommand', encodedCommand], () => {});
    }
    timerId = null;
  };

  // Planifier l'effacement
  timerId = setTimeout(clear, timeoutMs);

  // Retourner un objet de contrôle
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
};
