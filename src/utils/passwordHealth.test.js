// ========================================
// TESTS : audit de santé des mots de passe (src/utils/passwordHealth.js)
// ========================================
// Logique pure (faibles / réutilisés / score) + vérification HIBP en k-anonymity
// avec fetch et Web Crypto injectés (déterministes, hors ligne).

import crypto from 'crypto';
import { TextEncoder } from 'util';
import { extractPassword, analyzeVault, computeScore, checkBreach, checkBreaches } from './passwordHealth';

// jsdom ne fournit pas toujours TextEncoder (présent dans le renderer Electron réel).
// passwordHealth ne l'utilise qu'à l'appel (pas au chargement) : le polyfill peut suivre les imports.
if (typeof global.TextEncoder === 'undefined') global.TextEncoder = TextEncoder;

// Shim SubtleCrypto minimal (SHA-1) basé sur le crypto natif de Node.
const subtle = {
  digest: async (_algo, data) => {
    const h = crypto.createHash('sha1').update(Buffer.from(data)).digest();
    return h.buffer.slice(h.byteOffset, h.byteOffset + h.byteLength);
  },
};
const sha1Upper = (s) => crypto.createHash('sha1').update(s).digest('hex').toUpperCase();

describe('extractPassword', () => {
  it('lit le champ principal', () => {
    expect(extractPassword({ password: 'abc' })).toBe('abc');
  });
  it('se rabat sur un champ personnalisé de type mot de passe', () => {
    expect(extractPassword({ password: '', customFields: [{ key: 'Mot de passe RDP', value: 'xyz' }] })).toBe('xyz');
  });
  it('renvoie une chaîne vide sans mot de passe', () => {
    expect(extractPassword({ username: 'u' })).toBe('');
    expect(extractPassword(null)).toBe('');
  });
});

describe('analyzeVault', () => {
  const secrets = [
    { name: 'a', password: 'azerty', engineName: 'E' },              // faible + réutilisé
    { name: 'b', password: 'azerty', engineName: 'E' },              // faible + réutilisé
    { name: 'c', password: 'Gh7$kLm2!pQ9xZr4&vB1', engineName: 'E' },// fort, unique
    { name: 'd', entryType: 'placeholder', password: '' },           // ignoré
    { name: 'e', username: 'u', engineName: 'E' },                   // sans mot de passe → ignoré
  ];

  it('compte les entrées analysables (hors placeholder / sans mot de passe)', () => {
    expect(analyzeVault(secrets).total).toBe(3);
  });

  it('détecte les mots de passe faibles', () => {
    const r = analyzeVault(secrets);
    expect(r.weak.map(i => i.name).sort()).toEqual(['a', 'b']);
  });

  it('détecte les réutilisations et les regroupe', () => {
    const r = analyzeVault(secrets);
    expect(r.reused.map(i => i.name).sort()).toEqual(['a', 'b']);
    expect(r.reusedGroups).toHaveLength(1);
    expect(r.reusedGroups[0]).toHaveLength(2);
  });

  it('ne divulgue pas le mot de passe dans les groupes de réutilisation', () => {
    const r = analyzeVault(secrets);
    expect(r.reusedGroups[0][0]).not.toHaveProperty('password');
  });

  it('score : 100 pour un coffre vide, < 100 s\'il y a des problèmes', () => {
    expect(analyzeVault([]).score).toBe(100);
    expect(analyzeVault(secrets).score).toBeLessThan(100);
  });
});

describe('computeScore', () => {
  it('100 sans problème, 0 pour un coffre entièrement faible+réutilisé', () => {
    expect(computeScore(0, 0, 0)).toBe(100);
    expect(computeScore(5, 0, 0)).toBe(100);
    expect(computeScore(5, 5, 5)).toBe(0);
  });
});

describe('checkBreach (k-anonymity)', () => {
  it('n\'envoie que le préfixe de 5 caractères et trouve le compte', async () => {
    const pwd = 'password';
    const full = sha1Upper(pwd);
    const prefix = full.slice(0, 5);
    const suffix = full.slice(5);
    let requestedUrl = null;
    const fetchImpl = async (url, opts) => {
      requestedUrl = url;
      expect(opts.headers['Add-Padding']).toBe('true');
      return { ok: true, text: async () => `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n${suffix}:12345\n` };
    };
    const count = await checkBreach(pwd, { fetchImpl, subtle });
    expect(count).toBe(12345);
    expect(requestedUrl).toBe(`https://api.pwnedpasswords.com/range/${prefix}`);
    // Le condensat complet ne doit jamais apparaître dans l'URL
    expect(requestedUrl).not.toContain(suffix);
  });

  it('renvoie 0 si le suffixe est absent', async () => {
    const fetchImpl = async () => ({ ok: true, text: async () => 'FFFF:1\n' });
    expect(await checkBreach('unique', { fetchImpl, subtle })).toBe(0);
  });

  it('lève en cas d\'erreur HTTP', async () => {
    const fetchImpl = async () => ({ ok: false, status: 503, text: async () => '' });
    await expect(checkBreach('x', { fetchImpl, subtle })).rejects.toThrow(/HIBP 503/);
  });
});

describe('checkBreaches', () => {
  it('déduplique les mots de passe identiques et renseigne breachCount', async () => {
    const items = [
      { password: 'password', breachCount: null },
      { password: 'password', breachCount: null },
      { password: 'unique-xyz', breachCount: null },
    ];
    let calls = 0;
    const fetchImpl = async (url) => {
      calls++;
      const pwdHashSuffix = sha1Upper('password').slice(5);
      return { ok: true, text: async () => `${pwdHashSuffix}:7\n` };
    };
    const res = await checkBreaches(items, { fetchImpl, subtle, delayMs: 0 });
    expect(calls).toBe(2); // 'password' interrogé une seule fois
    expect(items[0].breachCount).toBe(7);
    expect(items[1].breachCount).toBe(7);
    expect(res.breached).toBe(2);
  });
});
