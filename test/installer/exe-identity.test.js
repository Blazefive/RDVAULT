// INSTALLER-26 — identité de RDVAULT.exe (ressources de version), SANS signature de code.
// Avec "signAndEditExecutable": false, electron-builder sautait signAndEditResources : RDVAULT.exe
// gardait les métadonnées d'Electron (FileDescription « Electron », CompanyName « GitHub, Inc. »,
// electron.exe 38.x) et legalTrademarks était ignoré. À true, electron-builder lance rcedit (via
// app-builder et l'outil winCodeSign de son cache) ; sans certificat (ni CSC_LINK ni signtoolOptions /
// azureSignOptions), la signature est simplement sautée (« no signing info identified »).
//  1. configuration : édition des ressources activée, aucune signature configurée ;
//  2. chaîne d'outils : la commande exacte qu'exécute electron-builder (app-builder rcedit, mêmes
//     arguments que WinPackager.signAndEditResources) appliquée à une COPIE d'un petit exécutable ;
//     ignoré si l'outil winCodeSign n'est pas dans le cache (aucun téléchargement n'est déclenché).
// Lancement : node --test test/installer/exe-identity.test.js
// RDV_EB_CONFIG=<fichier> teste une autre configuration electron-builder (ex. l'ancienne).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PROJECT_DIR = path.resolve(__dirname, '..', '..');
const configFile = path.resolve(process.env.RDV_EB_CONFIG || path.join(PROJECT_DIR, 'electron-builder.json'));
const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(PROJECT_DIR, 'package.json'), 'utf8'));

test('electron-builder : ressources de version éditées, aucune signature configurée', () => {
  const win = config.win || {};
  assert.notEqual(win.signAndEditExecutable, false, 'signAndEditExecutable: false laisse RDVAULT.exe identifié comme electron.exe');
  assert.equal(win.legalTrademarks, 'Blazefive');
  assert.equal(win.signtoolOptions, undefined, 'aucun certificat ne doit être exigé');
  assert.equal(win.azureSignOptions, undefined, 'aucun service de signature ne doit être exigé');
  assert.notEqual(win.forceCodeSigning, true, 'le build doit réussir sans certificat');
  assert.ok(config.productName && pkg.author && pkg.version, 'productName, author (CompanyName) et version renseignés');
});

function winCodeSignRcedit() {
  const cache = process.env.ELECTRON_BUILDER_CACHE
    || path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'electron-builder', 'Cache');
  return path.join(cache, 'winCodeSign', 'winCodeSign-2.6.0', 'rcedit-x64.exe');
}

function toolchainSkipReason() {
  if (process.platform !== 'win32') return 'Windows requis';
  if (!fs.existsSync(winCodeSignRcedit())) return `winCodeSign absent du cache d'electron-builder (${winCodeSignRcedit()}) : le build le téléchargera`;
  try {
    require.resolve('app-builder-bin', { paths: [PROJECT_DIR] });
    require.resolve('7zip-bin', { paths: [PROJECT_DIR] });
  } catch {
    return 'app-builder-bin / 7zip-bin absents';
  }
  return false;
}

test('chaîne d\'outils : app-builder rcedit pose l\'identité RDVAULT sur une copie d\'exécutable', { skip: toolchainSkipReason() }, () => {
  const appBuilder = require(require.resolve('app-builder-bin', { paths: [PROJECT_DIR] })).appBuilderPath;
  const path7za = require(require.resolve('7zip-bin', { paths: [PROJECT_DIR] })).path7za;
  const base = process.env.RDV_INSTALLER_TEST_TMP || os.tmpdir();
  fs.mkdirSync(base, { recursive: true });
  const dir = fs.mkdtempSync(path.join(base, 'rdv-rcedit-'));
  try {
    const exe = path.join(dir, `${config.productName}.exe`);
    fs.copyFileSync(path7za, exe);
    const version = pkg.version;
    // Mêmes arguments que WinPackager.signAndEditResources (app-builder-lib/out/winPackager.js)
    const args = [
      exe,
      '--set-version-string', 'FileDescription', config.productName,
      '--set-version-string', 'ProductName', config.productName,
      '--set-version-string', 'LegalCopyright', `Copyright (c) ${new Date().getFullYear()} ${pkg.author}`,
      '--set-file-version', version,
      '--set-product-version', `${version}.0`,
      '--set-version-string', 'InternalName', config.productName,
      '--set-version-string', 'OriginalFilename', '',
      '--set-version-string', 'CompanyName', pkg.author,
      '--set-version-string', 'LegalTrademarks', config.win.legalTrademarks,
      '--set-icon', path.join(PROJECT_DIR, config.win.icon || config.icon),
    ];
    const r = spawnSync(appBuilder, ['rcedit', '--args', JSON.stringify(args)], {
      encoding: 'utf8', env: { ...process.env, SZA_PATH: path7za }, timeout: 120000,
    });
    assert.equal(r.status, 0, `app-builder rcedit : ${r.stdout}${r.stderr}${r.error ? r.error.message : ''}`);
    const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      `(Get-Item -LiteralPath '${exe.replace(/'/g, "''")}').VersionInfo | Select-Object FileDescription,ProductName,CompanyName,LegalTrademarks,FileVersion,ProductVersion | ConvertTo-Json`],
    { encoding: 'utf8', timeout: 60000 });
    assert.equal(ps.status, 0, ps.stderr);
    const info = JSON.parse(ps.stdout);
    assert.equal(info.FileDescription, config.productName);
    assert.equal(info.ProductName, config.productName);
    assert.equal(info.CompanyName, pkg.author);
    assert.equal(info.LegalTrademarks, 'Blazefive');
    assert.equal(info.FileVersion, version);
    assert.equal(info.ProductVersion, `${version}.0`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
