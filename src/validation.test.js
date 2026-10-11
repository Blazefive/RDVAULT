// ========================================
// TESTS : validation et sanitization (src/validation.js)
// ========================================

import {
  isValidUrl,
  validateSecretName,
  validateUsername,
  validatePassword,
  isValidEmail,
  validateTotpSecret,
  isValidHostname,
  isValidPort,
  sanitizeForDisplay,
  validateFilePath,
  validateSshConfig,
  truncate,
  validateSecret,
} from './validation';

describe('isValidUrl', () => {
  it('accepte les protocoles autorisés', () => {
    expect(isValidUrl('https://example.com')).toBe(true);
    expect(isValidUrl('ssh://host:22')).toBe(true);
    expect(isValidUrl('rdp://server')).toBe(true);
  });

  it('accepte les hôtes sans protocole', () => {
    expect(isValidUrl('monserveur.local')).toBe(true);
    expect(isValidUrl('192.168.1.1')).toBe(true);
  });

  it('rejette les schémas non autorisés et les valeurs vides', () => {
    // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir refusée
    expect(isValidUrl('javascript:alert(1)')).toBe(false);
    expect(isValidUrl('data:text/html,x')).toBe(false);
    expect(isValidUrl('')).toBe(false);
    expect(isValidUrl(null)).toBe(false);
  });
});

describe('validateSecretName', () => {
  it('accepte un nom simple ou avec dossiers', () => {
    expect(validateSecretName('github-deploy')).toEqual({ valid: true });
    expect(validateSecretName('prod/db/password')).toEqual({ valid: true });
  });

  it('rejette un nom vide ou non textuel', () => {
    expect(validateSecretName('').valid).toBe(false);
    expect(validateSecretName(null).valid).toBe(false);
    expect(validateSecretName(42).valid).toBe(false);
  });

  it('rejette un nom trop long', () => {
    expect(validateSecretName('a'.repeat(513)).valid).toBe(false);
    expect(validateSecretName('a'.repeat(512)).valid).toBe(true);
  });

  it('rejette le path traversal, y compris encodé', () => {
    expect(validateSecretName('../etc').valid).toBe(false);
    expect(validateSecretName('a\\b').valid).toBe(false);
    expect(validateSecretName('%2e%2e/etc').valid).toBe(false);
    expect(validateSecretName('a%5cb').valid).toBe(false);
  });

  it('rejette les caractères de contrôle', () => {
    expect(validateSecretName('a\x00b').valid).toBe(false);
    expect(validateSecretName('a\nb').valid).toBe(false);
  });
});

describe('validateUsername', () => {
  it('accepte un username classique', () => {
    expect(validateUsername('john.doe')).toEqual({ valid: true });
  });

  it('accepte les apostrophes/guillemets (identifiants légitimes : O\'Brien, etc.)', () => {
    expect(validateUsername("o'neil").valid).toBe(true);
    expect(validateUsername('a"b').valid).toBe(true);
  });

  it('rejette vide, trop long et caractères de contrôle', () => {
    expect(validateUsername('').valid).toBe(false);
    expect(validateUsername('a'.repeat(257)).valid).toBe(false);
    expect(validateUsername('a\tb').valid).toBe(false);
    expect(validateUsername('a\u0000b').valid).toBe(false);
  });
});

describe('validatePassword', () => {
  it('accepte tous les symboles', () => {
    expect(validatePassword('P@ss w0rd!"\'`{}')).toEqual({ valid: true });
  });

  it('rejette vide, trop long et caractères de contrôle', () => {
    expect(validatePassword('').valid).toBe(false);
    expect(validatePassword('a'.repeat(1025)).valid).toBe(false);
    expect(validatePassword('a\x1Fb').valid).toBe(false);
  });
});

describe('isValidEmail', () => {
  it('valide des emails simples', () => {
    expect(isValidEmail('user@example.com')).toBe(true);
    expect(isValidEmail('not-an-email')).toBe(false);
    expect(isValidEmail('')).toBe(false);
  });
});

describe('validateTotpSecret', () => {
  it('accepte une clé base32', () => {
    expect(validateTotpSecret('JBSWY3DPEHPK3PXP')).toEqual({ valid: true });
    expect(validateTotpSecret('JBSWY3DPEHPK3PXP====')).toEqual({ valid: true });
  });

  it('rejette les clés invalides', () => {
    expect(validateTotpSecret('').valid).toBe(false);
    expect(validateTotpSecret('abc123!').valid).toBe(false);
    expect(validateTotpSecret('A'.repeat(257)).valid).toBe(false);
  });
});

describe('isValidHostname / isValidPort', () => {
  it('valide IPv4, IPv6 et noms DNS', () => {
    expect(isValidHostname('192.168.1.10')).toBe(true);
    expect(isValidHostname('256.1.1.1')).toBe(false);
    expect(isValidHostname('fe80:0:0:0:0:0:0:1')).toBe(true);
    expect(isValidHostname('serveur.exemple.fr')).toBe(true);
    expect(isValidHostname('bad host')).toBe(false);
    expect(isValidHostname('')).toBe(false);
  });

  it('valide les ports 1-65535', () => {
    expect(isValidPort(22)).toBe(true);
    expect(isValidPort('3389')).toBe(true);
    expect(isValidPort(0)).toBe(false);
    expect(isValidPort(65536)).toBe(false);
    expect(isValidPort('abc')).toBe(false);
  });
});

describe('sanitizeForDisplay', () => {
  it('échappe les caractères HTML dangereux', () => {
    expect(sanitizeForDisplay('<script>alert("x")</script>'))
      .toBe('&lt;script&gt;alert(&quot;x&quot;)&lt;&#x2F;script&gt;');
    expect(sanitizeForDisplay("a & b 'c'")).toBe('a &amp; b &#x27;c&#x27;');
  });

  it('retourne une chaîne vide pour les valeurs non textuelles', () => {
    expect(sanitizeForDisplay('')).toBe('');
    expect(sanitizeForDisplay(null)).toBe('');
    expect(sanitizeForDisplay(123)).toBe('');
  });
});

describe('validateFilePath', () => {
  it('n\'autorise que /var/log/vault/*', () => {
    expect(validateFilePath('/var/log/vault/audit.log').valid).toBe(true);
    expect(validateFilePath('/etc/passwd').valid).toBe(false);
    expect(validateFilePath('/var/log/vault/../../etc/passwd').valid).toBe(false);
    expect(validateFilePath('/var/log/vault/%2e%2e/x').valid).toBe(false);
    expect(validateFilePath('/var/log/vault/~root').valid).toBe(false);
    expect(validateFilePath('/var/log/vault/a\x00').valid).toBe(false);
    expect(validateFilePath('').valid).toBe(false);
  });
});

describe('validateSshConfig', () => {
  it('valide une configuration correcte', () => {
    expect(validateSshConfig({ host: 'srv01', username: 'root', port: 22 })).toEqual({ valid: true, errors: {} });
  });

  it('remonte les erreurs par champ', () => {
    const res = validateSshConfig({ host: 'bad host', username: 'a;b', port: 70000 });
    expect(res.valid).toBe(false);
    expect(res.errors.host).toBeDefined();
    expect(res.errors.username).toBeDefined();
    expect(res.errors.port).toBeDefined();
  });
});

describe('truncate', () => {
  it('tronque au-delà de la longueur maximale', () => {
    expect(truncate('abcdef', 3)).toBe('abc');
    expect(truncate('abc', 10)).toBe('abc');
    expect(truncate(null)).toBe('');
  });
});

describe('validateSecret', () => {
  it('valide un secret complet', () => {
    const res = validateSecret({ name: 'ok', username: 'u', password: 'p', url: 'https://x.io', totpSecret: 'JBSWY3DP' });
    expect(res).toEqual({ valid: true, errors: {} });
  });

  it('agrège les erreurs de chaque champ', () => {
    const res = validateSecret({
      name: '../x',
      username: 'a\x00b',
      password: 'a\x00',
      // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir refusée
      url: 'javascript:alert(1)',
      totpSecret: '!!!',
      notes: 'n'.repeat(10001),
    });
    expect(res.valid).toBe(false);
    expect(Object.keys(res.errors).sort()).toEqual(['name', 'notes', 'password', 'totpSecret', 'url', 'username']);
  });
});
