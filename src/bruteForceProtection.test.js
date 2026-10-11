// ========================================
// TESTS : bruteForceProtection — messages dans la langue de l'interface
// ========================================
// Le champ `message` des résultats de registerFailedAttempt était toujours en français
// (« Tentative échouée… », « Trop de tentatives échouées… »). Il suit désormais la langue de
// l'interface (attribut lang du document, tenu à jour par I18nProvider), avec repli anglais,
// et la clé i18n est exposée (messageKey / messageParams) pour un appelant muni de t().
import { BruteForceProtection } from './bruteForceProtection';

let bf;
beforeEach(() => {
  sessionStorage.clear();
  bf = new BruteForceProtection({ maxAttempts: 3, blockDurationMs: 300000, attemptWindowMs: 900000 });
});
afterEach(() => {
  bf.destroy();
  document.documentElement.lang = '';
  jest.restoreAllMocks();
});

test('anglais : échec puis blocage, sans aucun texte français', () => {
  document.documentElement.lang = 'en';
  const now = Date.now();
  const clock = jest.spyOn(Date, 'now');
  clock.mockReturnValue(now);
  const first = bf.registerFailedAttempt('Alice');
  expect(first.message).toBe('Attempt failed. 2 attempt(s) left before lockout.');
  expect(first.messageKey).toBe('login.attemptFailedRemaining');
  expect(first.messageParams).toEqual({ count: 2 });

  clock.mockReturnValue(now + 61000);
  bf.registerFailedAttempt('alice');
  clock.mockReturnValue(now + 122000);
  const blocked = bf.registerFailedAttempt('alice');
  expect(blocked.blocked).toBe(true);
  expect(blocked.message).toBe('Too many failed attempts. Account locked for 5 minutes.');

  clock.mockReturnValue(now + 123000);
  const again = bf.registerFailedAttempt('alice');
  expect(again.message).toBe('Account temporarily locked. Try again in 299 seconds.');
  for (const r of [first, blocked, again]) expect(r.message).not.toMatch(/Tentative|Compte|bloqué/);
});

test('allemand et japonais', () => {
  document.documentElement.lang = 'de';
  expect(bf.registerFailedAttempt('bob').message).toBe('Versuch fehlgeschlagen. Noch 2 Versuch(e) bis zur Sperrung.');
  document.documentElement.lang = 'ja';
  jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 61000);
  expect(bf.registerFailedAttempt('bob').message).toBe('試行に失敗しました。ロックまでの残り試行回数：1回。');
});

test('français conservé quand l\'interface est en français', () => {
  document.documentElement.lang = 'fr';
  expect(bf.registerFailedAttempt('claire').message).toBe('Tentative échouée. 2 tentative(s) restante(s) avant blocage.');
});
