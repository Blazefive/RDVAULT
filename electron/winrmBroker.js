// ========================================
// BROKER WINRM — « utiliser un identifiant Windows sans le voir »
// ========================================
// Pour l'exécution distante Windows (WinRM / PowerShell Remoting), RDVAULT exécute
// lui-même la commande avec l'identifiant du coffre et ne renvoie que la SORTIE.
// L'appelant (Claude Code) ne voit jamais le mot de passe.
//
// Isolation du secret : le mot de passe est transmis à PowerShell par STDIN (jamais en
// argument de ligne de commande, jamais en variable d'environnement). Tous les autres
// paramètres (hôte, utilisateur, commande, port, auth) passent par l'environnement du
// process enfant — le script PowerShell est STATIQUE (aucune interpolation = aucune
// injection). PowerShell construit un PSCredential et lance Invoke-Command.
//
// Windows uniquement (nécessite powershell.exe et un listener WinRM côté serveur).

'use strict';

const { spawn } = require('child_process');

// Script PowerShell STATIQUE : lit le mot de passe sur stdin, le reste via $env:RDV_WINRM_*.
// Aucune donnée n'est interpolée dans le texte → pas d'injection via l'hôte/l'utilisateur/la commande.
//
// Encodage : stdin est lu en UTF-8 (Node écrit le mot de passe en UTF-8 ; la page de code de la console,
// 850/1252, corrompait un mot de passe accentué) et la sortie est écrite en UTF-8 (décodée en UTF-8 par
// runPowerShell : sinon « é » devenait « � » dans la sortie et les messages d'erreur).
//
// Code de sortie (celui que `mvault winrm` renvoie) : la commande s'exécute dans une PSSession, puis
// $LASTEXITCODE est relu DANS cette session (Invoke-Command -ComputerName ne le transmet pas) :
//   - $LASTEXITCODE distant non nul (dernier exécutable lancé, ex. « cmd /c exit 7 ») → ce code ;
//   - sinon, erreur PowerShell distante (non bloquante ou throw) → 1 ;
//   - sinon → 0.
// Erreur locale (connexion, authentification, session) → 1. Un « exit N » distant ferme la session
// PowerShell Remoting : N n'est pas transmis → 1 avec un message explicite (jamais 0 par défaut).
// Les erreurs distantes ne sont plus bloquantes (-ErrorAction Continue) : la commande se poursuit comme
// dans une console distante et ses erreurs sont affichées sur stderr.
const WINRM_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  '$u8=New-Object System.Text.UTF8Encoding $false',
  'try { [Console]::OutputEncoding=$u8 } catch { }',
  '$code=1',
  '$s=$null',
  'try {',
  '  $pw=(New-Object System.IO.StreamReader([Console]::OpenStandardInput(),$u8)).ReadLine()',
  '  $sec=ConvertTo-SecureString $pw -AsPlainText -Force',
  '  $cred=New-Object System.Management.Automation.PSCredential($env:RDV_WINRM_USER,$sec)',
  '  $p=@{ComputerName=$env:RDV_WINRM_HOST;Credential=$cred}',
  "  if($env:RDV_WINRM_PORT){$p['Port']=[int]$env:RDV_WINRM_PORT}",
  "  if($env:RDV_WINRM_SSL -eq '1'){$p['UseSSL']=$true}",
  "  if($env:RDV_WINRM_AUTH){$p['Authentication']=$env:RDV_WINRM_AUTH}",
  '  $s=New-PSSession @p',
  '  $rdvErr=$null',
  '  Invoke-Command -Session $s -ScriptBlock ([ScriptBlock]::Create($env:RDV_WINRM_CMD)) -ErrorAction Continue -ErrorVariable rdvErr',
  "  if($s.State -ne 'Opened'){",
  "    [Console]::Error.WriteLine('RDVAULT : la session distante a été fermée par la commande (exit ?) : son code de sortie n''est pas transmis par PowerShell Remoting.')",
  '    $code=1',
  '  } else {',
  '    $lec=Invoke-Command -Session $s -ScriptBlock { $global:LASTEXITCODE }',
  '    if(($null -ne $lec) -and ([int]$lec -ne 0)){ $code=[int]$lec }',
  '    elseif($rdvErr.Count -gt 0){ $code=1 }',
  '    else { $code=0 }',
  '  }',
  '} catch { [Console]::Error.WriteLine($_.Exception.Message); $code=1 }',
  'finally { if($s){ try { Remove-PSSession $s -ErrorAction SilentlyContinue } catch { } } }',
  'exit $code',
].join('\n');

/**
 * Exécute un script PowerShell en lui fournissant une donnée sur STDIN.
 * Exporté pour tester le mécanisme de transmission par stdin (sans WinRM).
 */
function runPowerShell(script, extraEnv, stdinData, { timeoutMs = 30000, maxOutputBytes = 1024 * 1024, psBin } = {}) {
  return new Promise((resolve, reject) => {
    const bin = psBin || (process.platform === 'win32' ? 'powershell.exe' : 'pwsh');
    const child = spawn(bin, ['-NoProfile', '-NonInteractive', '-Command', script], { env: { ...process.env, ...extraEnv } });
    let out = Buffer.alloc(0), errb = Buffer.alloc(0), settled = false;
    const cap = (b, c) => (b.length >= maxOutputBytes ? b : Buffer.concat([b, c]).slice(0, maxOutputBytes));
    const finish = (fn, arg) => { if (settled) return; settled = true; clearTimeout(timer); fn(arg); };
    const timer = setTimeout(() => { try { child.kill(); } catch { /* ignore */ } finish(reject, new Error('Délai PowerShell dépassé')); }, timeoutMs);
    child.stdout.on('data', (c) => { out = cap(out, c); });
    child.stderr.on('data', (c) => { errb = cap(errb, c); });
    child.on('error', (e) => finish(reject, e));
    child.on('close', (code) => finish(resolve, { code, stdout: out.toString('utf8'), stderr: errb.toString('utf8') }));
    try { child.stdin.write(String(stdinData) + '\n'); child.stdin.end(); } catch { /* le process a pu échouer à démarrer */ }
  });
}

/**
 * Exécute une commande sur un hôte Windows via WinRM (PowerShell Remoting).
 * @param {object} opts
 * @param {string} opts.host
 * @param {string} opts.username
 * @param {string} opts.password          - lu du coffre, transmis par stdin, jamais journalisé
 * @param {string} opts.command           - commande PowerShell distante
 * @param {number} [opts.port]            - 5985 (http) / 5986 (https) par défaut selon useSSL
 * @param {boolean} [opts.useSSL=false]
 * @param {string} [opts.authMethod]      - Default|Negotiate|Kerberos|Basic|CredSSP
 * @param {number} [opts.timeoutMs=30000]
 * @returns {Promise<{ code, stdout, stderr }>}
 */
function execWinRM(opts) {
  const { host, username, password, command, port, useSSL = false, authMethod, timeoutMs, maxOutputBytes, psBin } = opts || {};
  if (!host || !username || !password || !command) {
    return Promise.reject(new Error('host, username, password et command sont requis'));
  }
  const env = { RDV_WINRM_HOST: host, RDV_WINRM_USER: username, RDV_WINRM_CMD: command };
  if (port) env.RDV_WINRM_PORT = String(port);
  if (useSSL) env.RDV_WINRM_SSL = '1';
  if (authMethod) env.RDV_WINRM_AUTH = authMethod;
  return runPowerShell(WINRM_SCRIPT, env, password, { timeoutMs, maxOutputBytes, psBin });
}

module.exports = { execWinRM, runPowerShell, WINRM_SCRIPT };
