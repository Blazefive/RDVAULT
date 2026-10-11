// ========================================
// Banc d'essai NSIS de l'installeur RDVAULT
// ========================================
// Compile les macros RÉELLES d'un script d'installeur (assets/installer.nsh par défaut) — preInit,
// customInit, customInstall, customUnInstall — dans un installeur et un désinstalleur minimaux qui
// reproduisent l'ordre d'electron-builder 26 (node_modules/app-builder-lib/templates/nsis) :
//   .onInit (installer.nsi)        : SetOutPath $INSTDIR, preInit, initMultiUser (perMachine :
//                                    installMode=all, SetShellVarContext all, $INSTDIR = /D=), customInit
//   section (installSection.nsh)   : InitPluginsDir, uninstallOldVersion (installUtil.nsh : copie de
//                                    l'ancien désinstalleur dans $PLUGINSDIR puis
//                                    « /S /KEEP_APP_DATA /allusers --updated _?=$INSTDIR »),
//                                    installApplicationFiles (nouveau désinstalleur), customInstall
//   un.install (uninstaller.nsh)   : customUnInstall puis RMDir /r $INSTDIR
// Le désinstalleur est produit comme le fait electron-builder : compilation avec BUILD_UNINSTALLER puis
// exécution du générateur (WriteUninstaller dans .onInit, après preInit). Les tests ${isUpdated}… sont
// générés par le NsisScriptGenerator d'app-builder-lib et s'appuient sur le plugin StdUtils
// d'electron-builder ; makensis est celui d'electron-builder (cache nsis-3.0.4.1).
//
// SÉCURITÉ : dans la copie compilée du script, toutes les constantes de dossiers système ($APPDATA,
// $DESKTOP, $SMPROGRAMS, $TEMP…) sont redirigées vers un bac à sable temporaire (vérifié après coup) ;
// TEMP/TMP des processus lancés pointent aussi dans le bac à sable ; le banc s'arrête (code 97) si
// $INSTDIR sort du bac à sable ; un script qui écrirait dans le registre ou lancerait un programme est
// refusé. Le vrai %APPDATA%\RDVAULT, Program Files, le registre et les raccourcis réels ne sont jamais
// touchés, et aucun installeur RDVAULT réel n'est exécuté.
//
// Variables d'environnement facultatives : ELECTRON_BUILDER_CACHE, ELECTRON_BUILDER_NSIS_DIR,
// RDV_NSIS_RESOURCES_DIR (emplacements du makensis et des plugins d'electron-builder).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PROJECT_DIR = path.resolve(__dirname, '..', '..');
const UNINSTALL_FILENAME = 'Uninstall RDVAULT.exe';

// Constantes NSIS désignant des dossiers réels du poste : redirigées vers le bac à sable
const REDIRECTED_CONSTANTS = [
  'APPDATA', 'LOCALAPPDATA', 'DESKTOP', 'SMPROGRAMS', 'STARTMENU', 'SMSTARTUP', 'QUICKLAUNCH',
  'DOCUMENTS', 'PROFILE', 'TEMP', 'TEMPLATES', 'SENDTO', 'RECENT', 'FAVORITES', 'MUSIC', 'PICTURES',
  'VIDEOS', 'NETHOOD', 'PRINTHOOD', 'FONTS', 'INTERNET_CACHE', 'COOKIES', 'HISTORY', 'ADMINTOOLS',
  'CDBURN_AREA', 'COMMONFILES', 'COMMONFILES32', 'COMMONFILES64', 'PROGRAMFILES', 'PROGRAMFILES32',
  'PROGRAMFILES64', 'WINDIR', 'SYSDIR', 'RESOURCES', 'RESOURCES_LOCALIZED',
];
const CONSTANT_RE = new RegExp(`\\$(${REDIRECTED_CONSTANTS.join('|')})(?![A-Za-z0-9_])`, 'gi');
// Instructions qui sortiraient du bac à sable (registre, exécution de programmes, appels système)
const FORBIDDEN_RE = /^\s*(WriteReg\w*|DeleteReg\w*|Exec|ExecWait|ExecShell\w*|ExecDos\w*|nsExec::\w+|System::\w+|UAC::\w+|WinShell::\w+|RegDLL|UnRegDLL)\b/im;

function electronBuilderCacheDir() {
  if (process.env.ELECTRON_BUILDER_CACHE) return process.env.ELECTRON_BUILDER_CACHE;
  const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  return path.join(localAppData, 'electron-builder', 'Cache');
}

/**
 * Localise makensis, les plugins et les modèles d'electron-builder.
 * @returns {{reason:string}|{nsisDir:string,makensis:string,pluginDir:string,templatesDir:string,NsisScriptGenerator:Function}}
 */
function findToolchain() {
  if (process.platform !== 'win32') return { reason: 'Windows requis (installeur NSIS)' };
  const cache = electronBuilderCacheDir();
  const nsisDir = process.env.ELECTRON_BUILDER_NSIS_DIR || path.join(cache, 'nsis', 'nsis-3.0.4.1');
  const makensis = path.join(nsisDir, 'Bin', 'makensis.exe');
  const resourcesDir = process.env.RDV_NSIS_RESOURCES_DIR || path.join(cache, 'nsis', 'nsis-resources-3.4.1');
  const pluginDir = path.join(resourcesDir, 'plugins', 'x86-unicode');
  const appBuilderLib = path.join(PROJECT_DIR, 'node_modules', 'app-builder-lib');
  const templatesDir = path.join(appBuilderLib, 'templates', 'nsis');
  const required = [
    [makensis, 'makensis d\'electron-builder'],
    [path.join(pluginDir, 'StdUtils.dll'), 'plugin StdUtils d\'electron-builder'],
    [path.join(templatesDir, 'include', 'StdUtils.nsh'), 'modèles NSIS d\'app-builder-lib'],
  ];
  for (const [file, what] of required) {
    if (!fs.existsSync(file)) return { reason: `${what} introuvable (${file})` };
  }
  let NsisScriptGenerator;
  try {
    ({ NsisScriptGenerator } = require(path.join(appBuilderLib, 'out', 'targets', 'nsis', 'nsisScriptGenerator.js')));
  } catch (err) {
    return { reason: `NsisScriptGenerator d'app-builder-lib indisponible (${err.message})` };
  }
  return { nsisDir, makensis, pluginDir, templatesDir, NsisScriptGenerator };
}

/** Crée le bac à sable (dossiers système redirigés compris) */
function createSandbox(baseDir = process.env.RDV_INSTALLER_TEST_TMP || os.tmpdir()) {
  fs.mkdirSync(baseDir, { recursive: true });
  const root = fs.mkdtempSync(path.join(baseDir, 'rdv-nsis-'));
  for (const name of ['APPDATA', 'DESKTOP', 'SMPROGRAMS', 'TEMP']) {
    fs.mkdirSync(path.join(root, 'sys', name), { recursive: true });
  }
  fs.mkdirSync(path.join(root, 'envtemp'), { recursive: true });
  fs.mkdirSync(path.join(root, 'bin'), { recursive: true });
  return {
    root,
    appData: path.join(root, 'sys', 'APPDATA'),
    sysTemp: path.join(root, 'sys', 'TEMP'),
    envTemp: path.join(root, 'envtemp'),
    bin: path.join(root, 'bin'),
  };
}

/**
 * Copie du script testé où les dossiers système pointent dans le bac à sable.
 * Refuse un script qui sortirait du bac à sable.
 */
function prepareScriptUnderTest(sourceFile, targetFile) {
  const original = fs.readFileSync(sourceFile, 'utf8');
  const forbidden = original.match(FORBIDDEN_RE);
  if (forbidden) throw new Error(`banc refusé : instruction hors bac à sable dans ${sourceFile} (« ${forbidden[0].trim()} »)`);
  let count = 0;
  const redirected = original.replace(CONSTANT_RE, (m, name) => {
    count++;
    return `\${RDV_SANDBOX}\\sys\\${name.toUpperCase()}`;
  });
  CONSTANT_RE.lastIndex = 0;
  if (CONSTANT_RE.test(redirected)) throw new Error('banc refusé : constante de dossier système non redirigée');
  CONSTANT_RE.lastIndex = 0;
  if (count === 0) throw new Error(`aucune constante redirigée dans ${sourceFile} : script inattendu`);
  fs.writeFileSync(targetFile, redirected);
  return count;
}

function benchSource({ toolchain, sandbox, underTest, outFile, uninstallerFile, uninstallerOut, withPagesApi }) {
  const gen = new toolchain.NsisScriptGenerator();
  // Même en-tête qu'electron-builder (computeCommonInstallerScriptHeader) : StdUtils, drapeaux, plugins, include
  gen.include(path.join(toolchain.templatesDir, 'include', 'StdUtils.nsh'));
  gen.addIncludeDir(path.join(toolchain.templatesDir, 'include'));
  gen.flags(['updated', 'force-run', 'keep-shortcuts', 'no-desktop-shortcut', 'delete-app-data', 'allusers', 'currentuser']);
  gen.addPluginDir('x86-unicode', toolchain.pluginDir);
  gen.include(underTest);
  const header = gen.build();
  const guard = `
; Garde-fou : $INSTDIR doit rester dans le bac a sable
!macro RdvBenchGuard
  StrLen $9 "\${RDV_SANDBOX}\\"
  StrCpy $8 "$INSTDIR" $9
  \${If} $8 != "\${RDV_SANDBOX}\\"
    SetErrorLevel 97
    Quit
  \${EndIf}
!macroend
`;
  // BUILD_UNINSTALLER est défini avant tout le reste, comme le fait electron-builder (-DBUILD_UNINSTALLER)
  const common = `Unicode true
${uninstallerOut ? '!define BUILD_UNINSTALLER' : ''}
!define RDV_SANDBOX "${sandbox.root}"
!define RDV_UNINSTALL_FILENAME "${UNINSTALL_FILENAME}"
Var installMode
${header}
Name "RDVAULT banc NSIS"
OutFile "${outFile}"
RequestExecutionLevel user
InstallDir "\${RDV_SANDBOX}\\instdir-defaut"
ShowInstDetails nevershow
${guard}`;
  if (uninstallerOut) {
    return `${common}
ShowUninstDetails nevershow

; Section d'installation vide, comme installer.nsi d'electron-builder quand BUILD_UNINSTALLER est defini
Section "install"
SectionEnd

Function .onInit
  !insertmacro preInit
  WriteUninstaller "${uninstallerOut}"
  SetErrorLevel 0
  Quit
FunctionEnd

Function un.onInit
  !insertmacro RdvBenchGuard
  ; initMultiUser (perMachine) : setInstallModePerAllUsers
  StrCpy $installMode "all"
  SetShellVarContext all
FunctionEnd

Section "un.install"
  !insertmacro customUnInstall
  ; Contexte laisse par customUnInstall (lecture de chemins uniquement) : electron-builder enchaine
  ; avec DeleteRegKey SHELL_CONTEXT, qui doit viser HKLM pour une installation par machine
  StrCpy $5 "$SMSTARTUP"
  SetShellVarContext all
  StrCpy $6 "$SMSTARTUP"
  StrCpy $7 "current"
  \${If} $5 == $6
    StrCpy $7 "all"
  \${EndIf}
  FileOpen $9 "\${RDV_SANDBOX}\\trace-uninstall.txt" w
  FileWrite $9 "CONTEXT=$7$\\r$\\n"
  \${If} \${isUpdated}
    FileWrite $9 "UPDATED=1$\\r$\\n"
  \${Else}
    FileWrite $9 "UPDATED=0$\\r$\\n"
  \${EndIf}
  FileClose $9
  RMDir /r $INSTDIR
SectionEnd
`;
  }
  // Emulation des pages de l'assistant : appelle les fonctions qu'appellent les pages a leur validation
  const pages = withPagesApi ? `
  ClearErrors
  \${GetParameters} $R0
  \${GetOptions} $R0 "/BENCHPAGES=" $R1
  \${IfNot} \${Errors}
    \${If} $R1 == "local"
    \${OrIf} $R1 == "enterprise"
      Push $R1
    \${Else}
      Push $APP_MODE
    \${EndIf}
    Call RdvModeChosen
    \${If} $APP_MODE != "local"
      Call RdvEnterpriseValidated
    \${EndIf}
  \${EndIf}` : '';
  return `${common}
Function .onInit
  !insertmacro RdvBenchGuard
  SetOutPath $INSTDIR
  !insertmacro preInit
  ; initMultiUser (perMachine) : setInstallModePerAllUsers ($INSTDIR = /D=)
  StrCpy $installMode "all"
  SetShellVarContext all
  !insertmacro RdvBenchGuard
  !insertmacro customInit
${pages}
  ; Etat apres customInit : valeurs preselectionnees dans les pages de l'assistant
  FileOpen $9 "\${RDV_SANDBOX}\\trace-init.txt" w
  FileWrite $9 "APP_MODE=$APP_MODE$\\r$\\n"
  FileWrite $9 "VAULT_URL=$VAULT_URL$\\r$\\n"
  FileWrite $9 "LDAP_AUTH_PATH=$LDAP_AUTH_PATH$\\r$\\n"
  FileWrite $9 "TRUSTED_DOMAINS=$TRUSTED_DOMAINS$\\r$\\n"
  FileWrite $9 "RBI_PROXY_URL=$RBI_PROXY_URL$\\r$\\n"
  FileClose $9
FunctionEnd

Section "install"
  !insertmacro RdvBenchGuard
  InitPluginsDir
  ; uninstallOldVersion : ancien desinstalleur copie dans $PLUGINSDIR et lance en mise a jour
  \${If} \${FileExists} "$INSTDIR\\\${RDV_UNINSTALL_FILENAME}"
    CopyFiles /SILENT "$INSTDIR\\\${RDV_UNINSTALL_FILENAME}" "$PLUGINSDIR\\old-uninstaller.exe"
    ClearErrors
    ExecWait '"$PLUGINSDIR\\old-uninstaller.exe" /S /KEEP_APP_DATA /allusers --updated _?=$INSTDIR' $R0
    \${If} \${Errors}
    \${OrIf} $R0 != 0
      SetErrorLevel 98
      Quit
    \${EndIf}
  \${EndIf}
  ; installApplicationFiles : fichiers de l'application, dont le nouveau desinstalleur
  SetOutPath $INSTDIR
  File "/oname=$INSTDIR\\\${RDV_UNINSTALL_FILENAME}" "${uninstallerFile}"
  !insertmacro customInstall
SectionEnd
`;
}

function makensis(toolchain, scriptFile, cwd) {
  const r = spawnSync(toolchain.makensis, ['-V2', '-INPUTCHARSET', 'UTF8', scriptFile], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NSISDIR: toolchain.nsisDir },
    timeout: 120000,
  });
  if (r.status !== 0) {
    throw new Error(`makensis a échoué (${scriptFile}, code ${r.status}) :\n${r.stdout || ''}${r.stderr || ''}${r.error ? r.error.message : ''}`);
  }
  return `${r.stdout || ''}${r.stderr || ''}`;
}

/** Environnement des installeurs du banc : TEMP/TMP dans le bac à sable */
function benchEnv(sandbox) {
  return { ...process.env, TEMP: sandbox.envTemp, TMP: sandbox.envTemp };
}

/**
 * Compile un banc (désinstalleur puis installeur) pour un script donné.
 * @returns {{installer:string, uninstaller:string, warnings:string}}
 */
function buildBench(toolchain, sandbox, scriptFile, name) {
  const dir = path.join(sandbox.root, 'build', name);
  fs.mkdirSync(dir, { recursive: true });
  const underTest = path.join(dir, 'installer-under-test.nsh');
  prepareScriptUnderTest(scriptFile, underTest);
  const withPagesApi = /^\s*Function\s+RdvModeChosen\b/m.test(fs.readFileSync(scriptFile, 'utf8'));
  const uninstallerOut = path.join(sandbox.bin, `${name}-${UNINSTALL_FILENAME}`);
  const generator = path.join(dir, 'uninstaller-generator.exe');
  const uninstSrc = path.join(dir, 'bench-uninstaller.nsi');
  fs.writeFileSync(uninstSrc, benchSource({ toolchain, sandbox, underTest, outFile: generator, uninstallerOut }));
  let warnings = makensis(toolchain, uninstSrc, dir);
  const gen = spawnSync(generator, [], { env: benchEnv(sandbox), timeout: 60000 });
  if (gen.status !== 0 || !fs.existsSync(uninstallerOut)) {
    throw new Error(`génération du désinstalleur impossible (code ${gen.status})`);
  }
  const installer = path.join(sandbox.bin, `${name}-setup.exe`);
  const instSrc = path.join(dir, 'bench-installer.nsi');
  fs.writeFileSync(instSrc, benchSource({ toolchain, sandbox, underTest, outFile: installer, uninstallerFile: uninstallerOut, withPagesApi }));
  warnings += makensis(toolchain, instSrc, dir);
  return { installer, uninstaller: uninstallerOut, warnings, withPagesApi };
}

/**
 * Lance un exécutable du banc. Les arguments sont passés tels quels (comme une ligne de commande
 * Windows) : /D= doit rester le dernier et n'est jamais entre guillemets.
 */
function runExe(sandbox, exe, args, { cwd } = {}) {
  const r = spawnSync(exe, args, {
    argv0: `"${exe}"`,
    windowsVerbatimArguments: true,
    env: benchEnv(sandbox),
    cwd: cwd || sandbox.root,
    timeout: 120000,
  });
  if (r.error) throw r.error;
  return r.status;
}

/** Installation (première installation ou mise à jour) dans instDir */
function install(sandbox, bench, instDir, args = [], opts = {}) {
  return runExe(sandbox, bench.installer, ['/S', ...args, `/D=${instDir}`], opts);
}

/**
 * Désinstallation par le désinstalleur présent dans instDir, copié hors du dossier comme le fait NSIS.
 * Sans argument : vraie désinstallation (Applications installées) ; ['--updated'] : étape de
 * désinstallation d'une mise à jour, telle que la lance installUtil.nsh.
 */
function uninstall(sandbox, instDir, extraArgs = []) {
  const copy = path.join(sandbox.envTemp, `uninstall-${Date.now()}.exe`);
  fs.copyFileSync(path.join(instDir, UNINSTALL_FILENAME), copy);
  try {
    return runExe(sandbox, copy, ['/S', ...extraArgs, `_?=${instDir}`]);
  } finally {
    fs.rmSync(copy, { force: true });
  }
}

/** Lit un fichier de trace « CLE=valeur » du banc */
function readTrace(sandbox, name) {
  const file = path.join(sandbox.root, name);
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
  }
  return out;
}

module.exports = {
  PROJECT_DIR,
  UNINSTALL_FILENAME,
  findToolchain,
  createSandbox,
  prepareScriptUnderTest,
  buildBench,
  install,
  uninstall,
  runExe,
  readTrace,
};
