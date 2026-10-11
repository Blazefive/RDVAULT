// Tests du broker WinRM (electron/winrmBroker.js).
// - Pureté du script PowerShell (aucun secret, lecture stdin).
// - Mécanisme réel de transmission du mot de passe par STDIN (PowerShell, Windows).
// - Échec propre (hôte bidon) SANS fuite du mot de passe.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execWinRM, runPowerShell, WINRM_SCRIPT } = require('./winrmBroker');

const WIN = process.platform === 'win32';

test('le script PowerShell est statique : lit le mot de passe sur stdin, rien d\'interpolé', () => {
  assert.match(WINRM_SCRIPT, /\[Console\]::In\.ReadLine\(\)/);
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
