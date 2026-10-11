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
const WINRM_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  'try {',
  '  $pw=[Console]::In.ReadLine()',
  '  $sec=ConvertTo-SecureString $pw -AsPlainText -Force',
  '  $cred=New-Object System.Management.Automation.PSCredential($env:RDV_WINRM_USER,$sec)',
  '  $p=@{ComputerName=$env:RDV_WINRM_HOST;Credential=$cred;ScriptBlock=[ScriptBlock]::Create($env:RDV_WINRM_CMD)}',
  "  if($env:RDV_WINRM_PORT){$p['Port']=[int]$env:RDV_WINRM_PORT}",
  "  if($env:RDV_WINRM_SSL -eq '1'){$p['UseSSL']=$true}",
  "  if($env:RDV_WINRM_AUTH){$p['Authentication']=$env:RDV_WINRM_AUTH}",
  '  Invoke-Command @p',
  '  exit 0',
  '} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }',
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
