// ========================================
// TESTS : concurrence bornée et relances (src/utils/mapLimit.js) — PERF-5
// ========================================
import { createLimiter, mapLimit, withRetry, isTransientError } from './mapLimit';

const deferred = () => {
  let resolve; let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
};
const tick = () => new Promise(r => setTimeout(r, 0));
const networkError = () => Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }); // sans `response`
const httpError = (status) => Object.assign(new Error(String(status)), { response: { status } });

describe('createLimiter', () => {
  test('au plus `limit` tâches en vol, toutes exécutées, résultats dans l\'ordre', async () => {
    const limiter = createLimiter(4);
    let inFlight = 0; let peak = 0;
    const jobs = Array.from({ length: 50 }, (_, i) => limiter.run(async () => {
      inFlight++; peak = Math.max(peak, inFlight);
      await tick();
      inFlight--;
      return i * 2;
    }));
    const out = await Promise.all(jobs);
    expect(peak).toBe(4);
    expect(limiter.stats().peak).toBe(4);
    expect(out).toEqual(Array.from({ length: 50 }, (_, i) => i * 2));
    expect(limiter.stats()).toMatchObject({ active: 0, pending: 0 });
  });

  test('une file partagée borne PLUSIEURS lecteurs simultanés (file globale)', async () => {
    const limiter = createLimiter(3);
    let inFlight = 0; let peak = 0;
    const work = () => limiter.run(async () => { inFlight++; peak = Math.max(peak, inFlight); await tick(); inFlight--; });
    await Promise.all([
      Promise.all(Array.from({ length: 20 }, work)),
      Promise.all(Array.from({ length: 20 }, work)),
    ]);
    expect(peak).toBe(3);
  });

  test('priorité haute servie avant la basse ; une erreur libère la place', async () => {
    const limiter = createLimiter(1);
    const gate = deferred();
    const order = [];
    const first = limiter.run(() => gate.promise);
    const low = limiter.run(async () => { order.push('low'); }, { priority: 'low' });
    const failing = limiter.run(async () => { order.push('high-err'); throw new Error('x'); });
    const high = limiter.run(async () => { order.push('high'); });
    gate.resolve();
    await first;
    await expect(failing).rejects.toThrow('x');
    await Promise.all([low, high]);
    expect(order).toEqual(['high-err', 'high', 'low']);
  });
});

describe('mapLimit', () => {
  test('ordre conservé et concurrence locale bornée', async () => {
    let inFlight = 0; let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6, 7], 3, async (x) => {
      inFlight++; peak = Math.max(peak, inFlight);
      await tick();
      inFlight--;
      return x * 10;
    });
    expect(out).toEqual([10, 20, 30, 40, 50, 60, 70]);
    expect(peak).toBe(3);
  });

  test('annulation : plus aucun appel lancé après abort', async () => {
    const ac = new AbortController();
    const seen = [];
    await mapLimit([1, 2, 3, 4, 5], 1, async (x) => { seen.push(x); if (x === 2) ac.abort(); }, { signal: ac.signal });
    expect(seen).toEqual([1, 2]);
  });
});

describe('withRetry / isTransientError', () => {
  test('erreur sans réponse (requête refusée par le navigateur) relancée puis réussie', async () => {
    let calls = 0;
    const out = await withRetry(async () => { calls++; if (calls < 3) throw networkError(); return 'ok'; }, { delayMs: 1 });
    expect(out).toBe('ok');
    expect(calls).toBe(3);
  });

  test('403 / 404 non relancées ; relances limitées', async () => {
    let calls = 0;
    await expect(withRetry(async () => { calls++; throw httpError(404); }, { delayMs: 1 })).rejects.toThrow('404');
    expect(calls).toBe(1);
    calls = 0;
    await expect(withRetry(async () => { calls++; throw httpError(503); }, { retries: 2, delayMs: 1 })).rejects.toThrow('503');
    expect(calls).toBe(3);
  });

  test('classification', () => {
    expect(isTransientError(networkError())).toBe(true);
    expect(isTransientError(Object.assign(new Error('timeout'), { code: 'ECONNABORTED' }))).toBe(true);
    expect(isTransientError(httpError(502))).toBe(true);
    expect(isTransientError(httpError(429))).toBe(true);
    expect(isTransientError(httpError(500))).toBe(false);
    expect(isTransientError(httpError(403))).toBe(false);
    expect(isTransientError(Object.assign(new Error('x'), { name: 'AbortError' }))).toBe(false);
    expect(isTransientError(null)).toBe(false);
  });

  // Vague F : erreurs applicatives déterministes (sans réponse HTTP) — avant, relancées 2 fois
  test('VALIDATION, LIST_TOO_LARGE et LIST_TOO_DEEP ne sont pas transitoires (aucune relance)', async () => {
    for (const code of ['VALIDATION', 'LIST_TOO_LARGE', 'LIST_TOO_DEEP']) {
      const appError = () => Object.assign(new Error(code), { code });
      expect(isTransientError(appError())).toBe(false);
      let calls = 0;
      // eslint-disable-next-line no-await-in-loop -- un code après l'autre
      await expect(withRetry(async () => { calls++; throw appError(); }, { delayMs: 1 })).rejects.toMatchObject({ code });
      expect(calls).toBe(1);
    }
    // Témoin : une coupure réseau reste relancée
    expect(isTransientError(Object.assign(new Error('Network Error'), { code: 'ERR_NETWORK' }))).toBe(true);
  });
});
