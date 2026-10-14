// Tests du broker WinRM (electron/winrmBroker.js).
// - Pureté du script PowerShell (aucun secret, lecture stdin).
// - Mécanisme réel de transmission du mot de passe par STDIN (PowerShell, Windows).
// - Échec propre (hôte bidon) SANS fuite du mot de passe.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
// RDV_WINRM_BROKER_MODULE : permet de rejouer ces tests sur une autre version du broker (preuve avant/après)
const { execWinRM, runPowerShell, WINRM_SCRIPT } = require(process.env.RDV_WINRM_BROKER_MODULE || './winrmBroker');

const WIN = process.platform === 'win32';

test('le script PowerShell est statique : lit le mot de passe sur stdin, rien d\'interpolé', () => {
  assert.match(WINRM_SCRIPT, /OpenStandardInput\(\)/);
  assert.match(WINRM_SCRIPT, /\$env:RDV_WINRM_CMD/);
  assert.match(WINRM_SCRIPT, /\$env:RDV_WINRM_HOST/);
  assert.match(WINRM_SCRIPT, /PSCredential/);
  // Aucun gabarit interpolé (pas de ${...} JS laissé dans le texte)
  assert.equal(/\$\{/.test(WINRM_SCRIPT), false);
});

test('paramètres manquants → rejet clair', async () => {
  await assert.rejects(() => execWinRM({ host: 'h', username: 'u', command: 'c' }), /requis/);
});

test('mot de passe transmis par STDIN (PowerShell réel)', { skip: !WIN }, async () => {
  const r = await runPowerShell(
    "if([Console]::In.ReadLine() -eq $env:EXPECT){'MATCH'}else{'NO'}",
    { EXPECT: 'pw-via-stdin-123' },
    'pw-via-stdin-123',
    { timeoutMs: 20000 }
  );
  assert.equal(r.code, 0);
  assert.match(r.stdout, /MATCH/);
});

// Double de New-PSSession : vérifie le mot de passe reçu (PSCredential) puis échoue comme un hôte injoignable.
// Exécuté par le VRAI powershell.exe (5.1) : le script du broker y est analysé et lancé tel quel.
const STUB_PW_CHECK = [
  'function New-PSSession { [CmdletBinding()] param($ComputerName,$Credential,$Port,[switch]$UseSSL,$Authentication)',
  "  [Console]::Out.WriteLine('PWMATCH=' + ($Credential.GetNetworkCredential().Password -ceq $env:RDV_TEST_EXPECT))",
  "  throw 'Connexion impossible (double de test) é' }",
].join('\n');

test('mot de passe accentué transmis intact par STDIN (UTF-8) ; message d\'erreur accentué non corrompu', { skip: !WIN }, async () => {
  // Avant : stdin lu dans la page de code de la console (850/1252) → « pw-é€漢 » arrivait corrompu
  // à PSCredential (authentification refusée), et « é » devenait « � » dans les messages.
  const pw = 'pw-é€漢-Ünïcode';
  const r = await runPowerShell(STUB_PW_CHECK + '\n' + WINRM_SCRIPT,
    { RDV_WINRM_HOST: 'srv', RDV_WINRM_USER: 'admin', RDV_WINRM_CMD: 'hostname', RDV_TEST_EXPECT: pw }, pw, { timeoutMs: 30000 });
  assert.match(r.stdout, /PWMATCH=True/);
  assert.equal(r.code, 1, 'échec de connexion → 1');
  assert.match(r.stderr, /Connexion impossible \(double de test\) é/);
});

// Code de sortie de la commande distante, à travers une VRAIE session PowerShell Remoting : PowerShell 7
// (pwsh) ouvre une PSSession hors processus vers Windows PowerShell (-UseWindowsPowerShell), même protocole
// et mêmes Invoke-Command / $LASTEXITCODE / erreurs distantes qu'une session WinRM, sans réseau ni droits
// d'administrateur. Seul New-PSSession est remplacé (l'hôte de test n'a pas de listener WinRM accessible).
const PWSH = WIN && spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { timeout: 20000 }).status === 0;
const STUB_OUT_OF_PROC = [
  'function New-PSSession { [CmdletBinding()] param($ComputerName,$Credential,$Port,[switch]$UseSSL,$Authentication)',
  '  & (Get-Command New-PSSession -CommandType Cmdlet) -UseWindowsPowerShell }',
].join('\n');

test('mvault winrm : le code de sortie est celui de la commande distante ($LASTEXITCODE, erreurs, exit)', { skip: !PWSH && 'pwsh absent' }, async () => {
  // Avant : « exit 0 » inconditionnel après Invoke-Command → 0 pour « cmd /c exit 7 » et pour « exit 5 ».
  const cases = [
    { cmd: 'cmd /c exit 7', code: 7 },
    { cmd: 'cmd /c exit 3; Write-Output apres', code: 3, stdout: /apres/ },
    { cmd: 'Write-Output ok', code: 0, stdout: /^ok\s*$/ },
    { cmd: "Write-Output 'sortie é漢'", code: 0, stdout: /sortie é漢/ },
    // Erreur distante non bloquante : la commande continue (comme dans une console distante), code 1
    { cmd: "Write-Error 'erreur-distante'; Write-Output suite", code: 1, stdout: /suite/, stderr: /erreur-distante/ },
    { cmd: "throw 'boum-distant'", code: 1, stderr: /boum-distant/ },
    // « exit N » ferme la session distante : N n'est pas transmis → 1 (jamais 0 par défaut) + explication
    { cmd: 'exit 5', code: 1, stderr: /session distante a été fermée/ },
    { cmd: 'exit 0', code: 1, stderr: /session distante a été fermée/ },
  ];
  const results = await Promise.all(cases.map((c) => runPowerShell(STUB_OUT_OF_PROC + '\n' + WINRM_SCRIPT,
    { RDV_WINRM_HOST: 'srv', RDV_WINRM_USER: 'admin', RDV_WINRM_CMD: c.cmd }, 'mot-de-passe', { timeoutMs: 90000, psBin: 'pwsh' })));
  results.forEach((r, i) => {
    const c = cases[i];
    assert.equal(r.code, c.code, `« ${c.cmd} » → code ${c.code} (reçu ${r.code}, stderr : ${r.stderr.slice(0, 200)})`);
    if (c.stdout) assert.match(r.stdout, c.stdout, `stdout de « ${c.cmd} »`);
    if (c.stderr) assert.match(r.stderr, c.stderr, `stderr de « ${c.cmd} »`);
  });
});

test('execWinRM : hôte inexistant → échec propre, mot de passe absent de la sortie', { skip: !WIN }, async () => {
  const secret = 'Winrm-S3cret!pw';
  const r = await execWinRM({
    host: 'rdvault-hote-bidon.invalid', username: 'administrateur', password: secret,
    command: 'hostname', timeoutMs: 25000,
  }).catch((e) => ({ code: -1, stdout: '', stderr: String(e.message || e) }));
  assert.notEqual(r.code, 0, 'code non nul (connexion impossible)');
  const combined = (r.stdout || '') + (r.stderr || '');
  assert.equal(combined.includes(secret), false, 'le mot de passe n\'apparaît jamais dans la sortie');
});
