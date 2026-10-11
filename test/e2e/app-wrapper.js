// Lance l'application RDVAULT réelle (main.js) avec un userData temporaire et une extension pré-appairée.
// Variables : E2E_USERDATA (dossier), E2E_EXT_ID (id extension), E2E_PORT_FILE (fichier où écrire le port du coffre local)
const { app } = require('electron');
const path = require('path');
const fs = require('fs');

const ROOT = path.resolve(__dirname, '..', '..');
const userData = process.env.E2E_USERDATA;
if (!userData) { console.error('E2E_USERDATA manquant'); process.exit(2); }
fs.mkdirSync(userData, { recursive: true });
app.setPath('userData', userData);
process.env.RDVAULT_LOG_LEVEL = process.env.RDVAULT_LOG_LEVEL || 'info';

// Aucun effet de bord sur le registre Windows
app.setAsDefaultProtocolClient = () => true;

// Boîtes de dialogue natives remplacées par des chemins fixes (test export/import via l'UI)
if (process.env.E2E_EXPORT_PATH || process.env.E2E_IMPORT_PATH) {
  const { dialog } = require('electron');
  dialog.showSaveDialog = async () => ({ canceled: false, filePath: process.env.E2E_EXPORT_PATH });
  dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [process.env.E2E_IMPORT_PATH] });
}

if (process.env.E2E_EXT_ID) {
  fs.writeFileSync(path.join(userData, 'paired-extensions.json'), JSON.stringify([process.env.E2E_EXT_ID]));
}

require(path.join(ROOT, 'electron/main.js'));

app.whenReady().then(() => {
  const portFile = process.env.E2E_PORT_FILE;
  if (!portFile) return;
  const localVault = require(path.join(ROOT, 'electron/localVault/localVaultServer.js'));
  const timer = setInterval(() => {
    const port = localVault.getPort();
    if (port) {
      clearInterval(timer);
      fs.writeFileSync(portFile, String(port));
      console.log('[E2E] local vault port ' + port);
    }
  }, 200);
});
