// Installeur NSIS (assets/installer.nsh) — banc d'essai sur les macros RÉELLES, ordre d'electron-builder 26
// (voir test/installer/nsis-bench.js). Couvre :
//  - INSTALLER-21 : « /S /CONFIG=fichier » lit vraiment le fichier (le drapeau d'erreur laissé par
//    GetOptions /MODE= absent faisait sauter la lecture), sans écraser le mode par défaut ;
//  - INSTALLER-24 : avec /CONFIG=, le fichier est copié tel quel (TRUSTED_CERT_FINGERPRINTS, LANG,
//    commentaires…) ; /MODE= ne remplace que la ligne APP_MODE ;
//  - INSTALLER-22 : une mise à jour (ancien désinstalleur lancé avec --updated, qui vide $INSTDIR avant
//    customInstall) conserve config.cfg à l'octet près et l'appairage des extensions
//    (paired-extensions.json), y compris depuis le désinstalleur livré en 1.7.0
//    (fixtures/installer-1.7.0.nsh) ; la page de mode est présélectionnée d'après l'APP_MODE existant ;
//  - vraie désinstallation : données de session supprimées, contexte SetShellVarContext rétabli (sinon
//    electron-builder efface les clés de registre HKCU au lieu de HKLM) ;
//  - première installation : fichier généré inchangé par rapport à la 1.7.0.
// Ignoré proprement si makensis / les plugins d'electron-builder sont absents (hors Windows notamment).
// Tout se passe dans un bac à sable temporaire : ni le vrai %APPDATA%\RDVAULT, ni Program Files, ni le
// registre ne sont touchés.
// Lancement : node --test test/installer/installer-nsis.test.js
// Script testé : assets/installer.nsh, ou RDV_INSTALLER_NSH=<fichier> (ex. la version 1.7.0 pour
// constater les défauts corrigés). RDV_INSTALLER_TEST_KEEP=1 conserve le bac à sable.
// suite = describe de node:test (accepte les options { skip } en deuxième argument)
const { suite, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const bench = require('./nsis-bench');
const { parseCfgFile, DEFAULT_CONFIG } = require('../../electron/configLoader');

const SCRIPT = path.resolve(process.env.RDV_INSTALLER_NSH || path.join(bench.PROJECT_DIR, 'assets', 'installer.nsh'));
const SCRIPT_170 = path.join(__dirname, 'fixtures', 'installer-1.7.0.nsh');
const toolchain = bench.findToolchain();
const skip = toolchain.reason ? `banc NSIS indisponible : ${toolchain.reason}` : false;

const CRLF = '\r\n';
// Fichier de déploiement d'entreprise conforme à config.example.cfg (CRLF, commentaires accentués en UTF-8)
const DEPLOY_CFG = [
  '# RDVAULT - déploiement du parc',
  'APP_MODE=enterprise',
  'VAULT_URL=https://vault.corp.example:8200',
  'LDAP_AUTH_PATH=auth/ldap-corp',
  'TRUSTED_DOMAINS=vault.corp.example,10.0.0.50',
  'TRUSTED_CERT_FINGERPRINTS=sha256/q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=',
  'RBI_PROXY_URL=https://rbi.corp.example:3001',
  'LANG=de',
  ''].join(CRLF);
const LOCAL_CFG = ['APP_MODE=local', 'LANG=es', ''].join(CRLF);
// Configuration réelle d'un poste en mode local (fins de ligne LF, écrite à la main)
const USER_LOCAL_CFG = 'APP_MODE=local\nLANG=fr\n';
// Poste d'entreprise configuré à la main après installation (empreintes, langue, commentaires, BOM)
const USER_ENTERPRISE_CFG = '﻿# Poste comptabilité\r\nAPP_MODE=enterprise\r\nVAULT_URL=https://vault.compta.example:8200\r\n'
  + 'LDAP_AUTH_PATH=auth/ldap\r\nTRUSTED_DOMAINS=vault.compta.example,localhost,127.0.0.1\r\n'
  + 'TRUSTED_CERT_FINGERPRINTS=' + 'ab'.repeat(32) + '\r\nRBI_PROXY_URL=\r\nLANG=it\r\n# fin';
const PAIRED = '["abcdefghijklmnopabcdefghijklmnop"]';

suite('installeur NSIS : macros réelles de assets/installer.nsh', { skip }, () => {
  let sb;
  let current;
  let v170;
  let caseNo = 0;

  before(() => {
    sb = bench.createSandbox();
    current = bench.buildBench(toolchain, sb, SCRIPT, 'courant');
    v170 = bench.buildBench(toolchain, sb, SCRIPT_170, 'v170');
    fs.writeFileSync(path.join(sb.root, 'deploy.cfg'), DEPLOY_CFG);
    fs.writeFileSync(path.join(sb.root, 'local.cfg'), LOCAL_CFG);
    fs.mkdirSync(path.join(sb.root, 'dossier avec espaces'));
    fs.writeFileSync(path.join(sb.root, 'dossier avec espaces', 'deploy.cfg'), DEPLOY_CFG);
    // Chemin relatif : résolu par rapport au dossier de l'installeur
    fs.writeFileSync(path.join(sb.bin, 'local.cfg'), LOCAL_CFG);
  });

  after(() => {
    if (sb && process.env.RDV_INSTALLER_TEST_KEEP !== '1') fs.rmSync(sb.root, { recursive: true, force: true });
  });

  const userDir = () => path.join(sb.appData, 'RDVAULT');
  const machineDir = () => path.join(sb.programData, 'RDVAULT');
  beforeEach(() => {
    // Profil utilisateur simulé : coffre local, appairage, session CLI
    fs.rmSync(userDir(), { recursive: true, force: true });
    fs.mkdirSync(path.join(userDir(), 'cli'), { recursive: true });
    fs.writeFileSync(path.join(userDir(), 'local-vault.db'), 'coffre');
    fs.writeFileSync(path.join(userDir(), 'paired-extensions.json'), PAIRED);
    fs.writeFileSync(path.join(userDir(), 'cli', 'session.json'), '{}');
    for (const trace of ['trace-init.txt', 'trace-uninstall.txt', 'trace-icacls.txt']) fs.rmSync(path.join(sb.root, trace), { force: true });
    // %PROGRAMDATA%\RDVAULT simulé (CONFIG-8) : absent au départ (lien éventuel retiré sans suivre sa cible)
    const machine = machineDir();
    try { if (fs.lstatSync(machine).isSymbolicLink()) fs.unlinkSync(machine); } catch { /* absent */ }
    fs.rmSync(machine, { recursive: true, force: true });
  });

  // Dossier d'installation propre à chaque cas (avec espace, comme « Program Files »)
  const newInstDir = () => path.join(sb.root, 'cas', String(++caseNo), 'Program Files', 'RDVAULT');
  const cfgPath = (dir) => path.join(dir, 'config.cfg');
  const readCfg = (dir) => fs.readFileSync(cfgPath(dir));
  const cfgArg = (file) => `/CONFIG=${path.join(sb.root, file)}`;
  const effective = (dir) => parseCfgFile(readCfg(dir).toString('utf8'));

  /** Poste déjà installé avec `setup`, dont config.cfg a ensuite été modifié à la main */
  function installedWith(setup, userCfg) {
    const dir = newInstDir();
    assert.equal(bench.install(sb, setup, dir, ['/MODE=local']), 0, 'installation initiale');
    fs.writeFileSync(cfgPath(dir), userCfg);
    return dir;
  }

  // ── INSTALLER-21 / INSTALLER-24 : /CONFIG= ──

  it('C1 « /S /CONFIG=deploy.cfg » (commande documentée) : fichier copié tel quel', () => {
    const dir = newInstDir();
    assert.equal(bench.install(sb, current, dir, [cfgArg('deploy.cfg')]), 0);
    assert.equal(readCfg(dir).toString('utf8'), DEPLOY_CFG, 'config.cfg = deploy.cfg à l\'octet près');
    const cfg = effective(dir);
    assert.equal(cfg.VAULT_URL, 'https://vault.corp.example:8200');
    assert.equal(cfg.APP_MODE, 'enterprise');
  });

  it('C1b config.example.cfg du projet comme fichier de déploiement : copié tel quel', () => {
    const dir = newInstDir();
    const example = path.join(bench.PROJECT_DIR, 'config.example.cfg');
    assert.equal(bench.install(sb, current, dir, [`/CONFIG=${example}`]), 0);
    assert.deepEqual(readCfg(dir), fs.readFileSync(example));
    assert.deepEqual(effective(dir), parseCfgFile(fs.readFileSync(example, 'utf8')));
  });

  it('C2 « /S /MODE=enterprise /CONFIG=deploy.cfg » : TRUSTED_CERT_FINGERPRINTS et LANG conservés', () => {
    const dir = newInstDir();
    assert.equal(bench.install(sb, current, dir, ['/MODE=enterprise', cfgArg('deploy.cfg')]), 0);
    const cfg = effective(dir);
    assert.equal(cfg.TRUSTED_CERT_FINGERPRINTS, 'sha256/q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=');
    assert.equal(cfg.LANG, 'de');
    assert.equal(readCfg(dir).toString('utf8'), DEPLOY_CFG, 'valeur APP_MODE identique : fichier inchangé');
  });

  it('C3 « /S /CONFIG=local.cfg » : mode local', () => {
    const dir = newInstDir();
    assert.equal(bench.install(sb, current, dir, [cfgArg('local.cfg')]), 0);
    assert.equal(readCfg(dir).toString('utf8'), LOCAL_CFG);
    assert.equal(effective(dir).APP_MODE, 'local');
  });

  it('C3b /CONFIG= relatif (dossier de l\'installeur) et chemin entre guillemets avec espaces', () => {
    const rel = newInstDir();
    assert.equal(bench.install(sb, current, rel, ['/CONFIG=local.cfg'], { cwd: sb.root }), 0);
    assert.equal(readCfg(rel).toString('utf8'), LOCAL_CFG);
    const quoted = newInstDir();
    const spaced = path.join(sb.root, 'dossier avec espaces', 'deploy.cfg');
    assert.equal(bench.install(sb, current, quoted, [`/CONFIG="${spaced}"`]), 0);
    assert.equal(readCfg(quoted).toString('utf8'), DEPLOY_CFG);
  });

  it('C2b « /MODE=local /CONFIG=deploy.cfg » : seule la ligne APP_MODE change', () => {
    const dir = newInstDir();
    assert.equal(bench.install(sb, current, dir, ['/MODE=local', cfgArg('deploy.cfg')]), 0);
    assert.equal(readCfg(dir).toString('utf8'), DEPLOY_CFG.replace('APP_MODE=enterprise\r\n', 'APP_MODE=local\r\n'));
  });

  it('C6 silencieux : /CONFIG= introuvable ou /MODE= invalide → arrêt (code 2), installation existante intacte', () => {
    const dir = installedWith(current, USER_LOCAL_CFG);
    assert.equal(bench.install(sb, current, dir, [cfgArg('absent.cfg')]), 2);
    assert.equal(bench.install(sb, current, dir, ['/MODE=locale']), 2);
    assert.equal(readCfg(dir).toString('utf8'), USER_LOCAL_CFG);
    assert.ok(fs.existsSync(path.join(dir, bench.UNINSTALL_FILENAME)), 'ancienne version non désinstallée');
    const fresh = newInstDir();
    assert.equal(bench.install(sb, current, fresh, [cfgArg('absent.cfg')]), 2);
    assert.equal(fs.existsSync(cfgPath(fresh)), false, 'aucune configuration d\'exemple écrite');
    // Casse indifférente et orthographe française de l'assistant acceptées (scripts de déploiement existants)
    const french = newInstDir();
    assert.equal(bench.install(sb, current, french, ['/MODE=Entreprise']), 0);
    assert.equal(effective(french).APP_MODE, 'enterprise');
  });

  // ── INSTALLER-22 : mise à jour ──

  it('C4 mise à jour « /S » : config.cfg local conservé à l\'octet près, appairage conservé', () => {
    const dir = installedWith(current, USER_LOCAL_CFG);
    const json = '{"LANG":"fr"}';
    fs.writeFileSync(path.join(dir, 'config.json'), json);
    assert.equal(bench.install(sb, current, dir), 0);
    assert.equal(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'), json, 'config.json conservé aussi');
    const un = bench.readTrace(sb, 'trace-uninstall.txt');
    assert.equal(un.UPDATED, '1', 'l\'ancien désinstalleur a bien tourné en mode mise à jour');
    assert.equal(readCfg(dir).toString('utf8'), USER_LOCAL_CFG);
    assert.equal(effective(dir).APP_MODE, 'local');
    assert.equal(bench.readTrace(sb, 'trace-init.txt').APP_MODE, 'local', 'page de mode présélectionnée');
    assert.equal(fs.readFileSync(path.join(userDir(), 'paired-extensions.json'), 'utf8'), PAIRED);
    assert.equal(fs.readFileSync(path.join(userDir(), 'local-vault.db'), 'utf8'), 'coffre');
    assert.ok(fs.existsSync(path.join(userDir(), 'cli', 'session.json')), 'customUnInstall n\'a rien supprimé (--updated)');
    assert.equal(un.CONTEXT, 'all', 'contexte de l\'installation par machine rétabli');
  });

  it('C4a désinstalleur lancé avec --updated (étape de mise à jour) : profil utilisateur intact', () => {
    const dir = installedWith(current, USER_LOCAL_CFG);
    assert.equal(bench.uninstall(sb, dir, ['/KEEP_APP_DATA', '/allusers', '--updated']), 0);
    assert.equal(bench.readTrace(sb, 'trace-uninstall.txt').UPDATED, '1');
    assert.equal(fs.readFileSync(path.join(userDir(), 'paired-extensions.json'), 'utf8'), PAIRED);
    assert.ok(fs.existsSync(path.join(userDir(), 'cli', 'session.json')));
  });

  it('C4b mise à jour depuis la 1.7.0 (son désinstalleur supprime config.cfg et l\'appairage)', () => {
    const dir = installedWith(v170, USER_LOCAL_CFG);
    assert.equal(bench.install(sb, current, dir), 0);
    assert.equal(bench.readTrace(sb, 'trace-uninstall.txt').UPDATED, '1');
    assert.equal(readCfg(dir).toString('utf8'), USER_LOCAL_CFG);
    assert.equal(fs.readFileSync(path.join(userDir(), 'paired-extensions.json'), 'utf8'), PAIRED,
      'paired-extensions.json restauré après le désinstalleur 1.7.0');
  });

  it('C4c mise à jour d\'un poste d\'entreprise (BOM, empreintes, LANG, commentaires) : fichier identique', () => {
    const dir = installedWith(current, USER_ENTERPRISE_CFG);
    assert.equal(bench.install(sb, current, dir), 0);
    assert.equal(readCfg(dir).toString('utf8'), USER_ENTERPRISE_CFG);
    const init = bench.readTrace(sb, 'trace-init.txt');
    assert.equal(init.APP_MODE, 'enterprise');
    assert.equal(init.VAULT_URL, 'https://vault.compta.example:8200', 'page entreprise pré-remplie');
  });

  it('C4d mise à jour « /S /MODE=enterprise » : seule la ligne APP_MODE est remplacée', () => {
    const dir = installedWith(current, USER_LOCAL_CFG);
    assert.equal(bench.install(sb, current, dir, ['/MODE=enterprise']), 0);
    assert.equal(readCfg(dir).toString('utf8'), 'APP_MODE=enterprise\r\nLANG=fr\n');
  });

  it('C4e assistant (pages validées sans modification) : fichier identique', () => {
    assert.ok(current.withPagesApi, 'RdvModeChosen / RdvEnterpriseValidated absents du script');
    const local = installedWith(current, USER_LOCAL_CFG);
    assert.equal(bench.install(sb, current, local, ['/BENCHPAGES=keep']), 0);
    assert.equal(readCfg(local).toString('utf8'), USER_LOCAL_CFG);
    const ent = installedWith(current, USER_ENTERPRISE_CFG);
    assert.equal(bench.install(sb, current, ent, ['/BENCHPAGES=keep']), 0);
    assert.equal(readCfg(ent).toString('utf8'), USER_ENTERPRISE_CFG);
  });

  it('C4f assistant : changement de mode → seule APP_MODE change ; clé absente ajoutée en fin de fichier', () => {
    assert.ok(current.withPagesApi, 'RdvModeChosen / RdvEnterpriseValidated absents du script');
    const ent = installedWith(current, USER_ENTERPRISE_CFG);
    assert.equal(bench.install(sb, current, ent, ['/BENCHPAGES=local']), 0);
    assert.equal(readCfg(ent).toString('utf8'), USER_ENTERPRISE_CFG.replace('APP_MODE=enterprise', 'APP_MODE=local'));
    const noMode = installedWith(current, 'LANG=fr');
    assert.equal(bench.install(sb, current, noMode, ['/BENCHPAGES=local']), 0);
    assert.equal(readCfg(noMode).toString('utf8'), 'LANG=fr\r\nAPP_MODE=local\r\n');
    // Ligne plus longue que NSIS_MAX_STRLEN (8192) : lue en plusieurs morceaux, recopiée à l'octet près
    const longCfg = `TRUSTED_CERT_FINGERPRINTS=${Array.from({ length: 200 }, (_, i) => i.toString(16).padStart(64, 'a')).join(',')}\r\nAPP_MODE=enterprise\r\nLANG=fr\r\n`;
    const long = installedWith(current, longCfg);
    assert.equal(bench.install(sb, current, long, ['/BENCHPAGES=local']), 0);
    assert.equal(readCfg(long).toString('utf8'), longCfg.replace('APP_MODE=enterprise', 'APP_MODE=local'));
    // Mode entreprise choisi sur un poste sans clé entreprise : valeurs par défaut de l'application, rien d'ajouté
    const local = installedWith(current, USER_LOCAL_CFG);
    assert.equal(bench.install(sb, current, local, ['/BENCHPAGES=enterprise']), 0);
    assert.equal(readCfg(local).toString('utf8'), 'APP_MODE=enterprise\r\nLANG=fr\n');
  });

  // ── Désinstallation ──

  it('C5 vraie désinstallation : configuration et données de session supprimées, coffre conservé', () => {
    const dir = installedWith(current, USER_LOCAL_CFG);
    assert.equal(bench.uninstall(sb, dir), 0);
    const un = bench.readTrace(sb, 'trace-uninstall.txt');
    assert.equal(un.UPDATED, '0');
    assert.equal(un.CONTEXT, 'all', 'DeleteRegKey SHELL_CONTEXT doit viser HKLM');
    assert.equal(fs.existsSync(cfgPath(dir)), false);
    assert.equal(fs.existsSync(path.join(userDir(), 'paired-extensions.json')), false);
    assert.equal(fs.existsSync(path.join(userDir(), 'cli', 'session.json')), false);
    assert.equal(fs.readFileSync(path.join(userDir(), 'local-vault.db'), 'utf8'), 'coffre');
  });

  // ── Première installation : comportement 1.7.0 conservé ──

  it('C7 première installation : même fichier qu\'en 1.7.0, APP_MODE par défaut « enterprise » écrit', () => {
    const fresh = (setup, args) => {
      const dir = newInstDir();
      assert.equal(bench.install(sb, setup, dir, args), 0);
      return readCfg(dir).toString('utf8');
    };
    const localNow = fresh(current, ['/MODE=local']);
    assert.equal(localNow, fresh(v170, ['/MODE=local']), '« /S /MODE=local »');
    assert.equal(parseCfgFile(localNow).APP_MODE, 'local');
    // « /S » seul : la 1.7.0 écrivait « APP_MODE= » (défaut écrasé par GetOptions /MODE= absent)
    const defaultNow = fresh(current, []);
    assert.equal(defaultNow, fresh(v170, []).replace('APP_MODE=\r\n', 'APP_MODE=enterprise\r\n'), '« /S »');
    assert.equal(parseCfgFile(defaultNow).APP_MODE, 'enterprise');
  });

  // ── CONFIG-8 : %PROGRAMDATA%\RDVAULT réservé aux administrateurs ──
  // Avant : jamais créé ni protégé ; tout utilisateur pouvait le créer (ACL de C:\ProgramData) et y imposer
  // config.cfg, lu en priorité par tous les utilisateurs du poste. icacls est SIMULÉ par le banc : seule la
  // ligne de commande est vérifiée, aucun droit réel n'est modifié.
  const icaclsTrace = () => {
    const file = path.join(sb.root, 'trace-icacls.txt');
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean) : [];
  };
  const expectedIcacls = (dir) => [
    `icacls.exe "${dir}" /setowner *S-1-5-32-544 /C /Q`,
    `icacls.exe "${dir}" /reset /C /Q`,
    `icacls.exe "${dir}" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /C /Q`,
  ];

  it('C8 installation par machine : %PROGRAMDATA%\\RDVAULT créé, propriétaire Administrateurs, ACL posée par SID', () => {
    const dir = newInstDir();
    assert.equal(bench.install(sb, current, dir, ['/MODE=local']), 0);
    assert.ok(fs.statSync(machineDir()).isDirectory(), 'dossier créé');
    assert.deepEqual(icaclsTrace(), expectedIcacls(machineDir()), 'propriétaire, ACE explicites retirées, héritage coupé, SID (indépendants de la langue)');
    // Mise à jour : ACL réappliquée (un dossier altéré entre-temps est corrigé)
    assert.equal(bench.install(sb, current, dir), 0);
    assert.deepEqual(icaclsTrace(), [...expectedIcacls(machineDir()), ...expectedIcacls(machineDir())]);
  });

  it('C8b dossier déjà présent avec la configuration de l\'administrateur : conservée à l\'octet près, même après désinstallation', () => {
    fs.mkdirSync(machineDir(), { recursive: true });
    fs.writeFileSync(path.join(machineDir(), 'config.cfg'), DEPLOY_CFG);
    const dir = newInstDir();
    assert.equal(bench.install(sb, current, dir), 0);
    assert.equal(fs.readFileSync(path.join(machineDir(), 'config.cfg'), 'utf8'), DEPLOY_CFG);
    assert.deepEqual(icaclsTrace(), expectedIcacls(machineDir()));
    assert.equal(bench.uninstall(sb, dir), 0);
    assert.equal(fs.readFileSync(path.join(machineDir(), 'config.cfg'), 'utf8'), DEPLOY_CFG, 'configuration de déploiement non supprimée');
  });

  it('C8c jonction posée par un utilisateur à la place du dossier : supprimée sans toucher à sa cible, vrai dossier créé', () => {
    const target = path.join(sb.root, 'cas', `jonction-${++caseNo}`);
    fs.mkdirSync(target, { recursive: true });
    fs.writeFileSync(path.join(target, 'config.cfg'), 'VAULT_URL=https://vault-corp.attaquant.example\n');
    fs.symlinkSync(target, machineDir(), 'junction');
    assert.ok(fs.lstatSync(machineDir()).isSymbolicLink());
    assert.equal(bench.install(sb, current, newInstDir()), 0);
    assert.equal(fs.lstatSync(machineDir()).isSymbolicLink(), false, 'jonction retirée');
    assert.ok(fs.statSync(machineDir()).isDirectory());
    assert.deepEqual(fs.readdirSync(machineDir()), [], 'la configuration de la cible n\'est plus lue');
    assert.ok(fs.existsSync(path.join(target, 'config.cfg')), 'cible de la jonction intacte');
    assert.deepEqual(icaclsTrace(), expectedIcacls(machineDir()), 'ACL posée sur le vrai dossier');
  });

  it('C8d fichier « RDVAULT » à la place du dossier : remplacé par le dossier protégé', () => {
    fs.writeFileSync(machineDir(), 'bloque le dossier');
    assert.equal(bench.install(sb, current, newInstDir()), 0);
    assert.ok(fs.statSync(machineDir()).isDirectory());
    assert.deepEqual(icaclsTrace(), expectedIcacls(machineDir()));
  });

  it('C8e banc : seul le bloc icacls attendu est simulé ; tout autre appel de programme est refusé', () => {
    const text = fs.readFileSync(SCRIPT, 'utf8');
    const tmp = path.join(sb.root, 'build', 'refus');
    fs.mkdirSync(tmp, { recursive: true });
    const tryScript = (name, content) => {
      const src = path.join(tmp, `${name}.nsh`);
      fs.writeFileSync(src, content);
      return () => bench.prepareScriptUnderTest(src, path.join(tmp, `${name}.out.nsh`));
    };
    // Script réel : accepté, sans nsExec ni icacls réel dans la copie compilée
    tryScript('reel', text)();
    const compiled = fs.readFileSync(path.join(tmp, 'reel.out.nsh'), 'utf8');
    assert.doesNotMatch(compiled, /nsExec::|\$SYSDIR/);
    assert.match(compiled, /trace-icacls\.txt/);
    assert.match(compiled, /sys\\PROGRAMDATA\\RDVAULT/);
    // Bloc modifié (autre programme) ou appel hors bloc : refus
    assert.throws(tryScript('autre-prog', text.replace('$SYSDIR\\icacls.exe', '$SYSDIR\\cmd.exe')), /bloc RDV-BENCH-EXEC inattendu/);
    assert.throws(tryScript('hors-bloc', `${text}\r\nFunction X\r\n  nsExec::Exec 'whoami'\r\nFunctionEnd\r\n`), /hors bac à sable/);
    assert.throws(tryScript('double', `${text}\r\n${text.match(/; >>> RDV-BENCH-EXEC-BEGIN[\s\S]*?; <<< RDV-BENCH-EXEC-END/)[0]}\r\n`), /plusieurs blocs/);
  });

  it('valeurs « par défaut de l\'application » du script = DEFAULT_CONFIG de configLoader', () => {
    const text = fs.readFileSync(SCRIPT, 'utf8');
    const define = (name) => (text.match(new RegExp(`^!define ${name} "([^"]*)"`, 'm')) || [])[1];
    assert.equal(define('APP_DEFAULT_VAULT_URL'), DEFAULT_CONFIG.VAULT_URL);
    assert.equal(define('APP_DEFAULT_LDAP_PATH'), DEFAULT_CONFIG.LDAP_AUTH_PATH);
    assert.equal(define('APP_DEFAULT_TRUSTED_DOMAINS'), DEFAULT_CONFIG.TRUSTED_DOMAINS);
  });
});
