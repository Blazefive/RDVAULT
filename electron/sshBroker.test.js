// Tests du broker SSH par mot de passe (electron/sshBroker.js) — serveur ssh2 EN MÉMOIRE,
// aucun serveur SSH réel requis. Vérifie exécution, échec d'auth, vérification de clé d'hôte
// (épinglage, known_hosts, rappel, opt-in, compare-and-swap, re-KEX, clé changée en cours de
// session), délais connexion/exécution (codes, destruction de la socket, valeurs invalides),
// abandon par signal (AbortSignal), bornage de sortie, fin de session shell, et que le mot de
// passe n'est jamais renvoyé ni envoyé à un hôte refusé.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { getEventListeners } = require('node:events');
const { Server, utils: { parseKey } } = require('ssh2');
const net = require('node:net');
const { execWithPassword, createShellSession, hostKeyFingerprint, normalizeFp, createHostVerifier } = require('./sshBroker');
const { createKnownHosts } = require('./knownHosts');
// Messages HOST_KEY_* traduits (mainI18n) : français imposé, les assertions ci-dessous portent sur le texte d'origine
require('./mainI18n').setDefaultLanguageProvider(() => 'fr');

const USER = 'deploy';
const PASS = 'S3cr3t!pw';
const HOST_KEY = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
// Empreinte attendue calculée INDÉPENDAMMENT du broker (clé publique au format SSH, SHA256 base64 sans padding)
const HOST_FP = 'SHA256:' + crypto.createHash('sha256').update(parseKey(HOST_KEY).getPublicSSH()).digest('base64').replace(/=+$/, '');
const OTHER_FP = 'SHA256:' + Buffer.alloc(32, 0x42).toString('base64').replace(/=+$/, '');
// Seconde VRAIE clé d'hôte (même type RSA) présentée par le serveur lors d'un re-KEX « piégé »
const SWAP_HOST_KEY = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
const SWAP_FP = 'SHA256:' + crypto.createHash('sha256').update(parseKey(SWAP_HOST_KEY).getPublicSSH()).digest('base64').replace(/=+$/, '');

// Dossiers temporaires des fichiers known_hosts de test (%TEMP%\rdvault-kh-*) : tous supprimés en fin de
// fichier (auparavant jamais nettoyés : des centaines de dossiers s'accumulaient au fil des exécutions)
const khTmpDirs = [];
function khTmpDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-kh-'));
  khTmpDirs.push(dir);
  return dir;
}
test.after(() => {
  for (const dir of khTmpDirs) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ }
  }
});

function tmpKnownHosts() {
  return createKnownHosts(path.join(khTmpDir(), 'known_hosts.json'));
}

// Serveur SSH jouet : accepte (USER, PASS), répond à exec. 'bigout' → 2 Mo ; 'fail' → code 3 ;
// 'hang' → flux jamais fermé ; 'slow' → se termine après 3 s ; 'rekey' → re-KEX serveur à 100 ms
// puis fin à 1,2 s ; 'swapkey' → re-KEX à 100 ms en présentant une AUTRE clé d'hôte (SWAP_HOST_KEY).
// Options : shellNoReply (la requête 'shell' n'obtient jamais de réponse), shellRekeyAfterMs (re-KEX
// serveur après l'ouverture du shell), shellSwapKeyAfterMs (idem avec une autre clé d'hôte),
// authDelayMs (réponse à l'authentification par mot de passe différée). Compte les connexions SSH,
// les appels 'authentication' (preuve que le mot de passe n'a jamais été envoyé quand la clé d'hôte
// est refusée), les mots de passe reçus, 'ready', les commandes exec et shells reçus, les re-KEX
// terminés et les fermetures de connexion vues par le serveur.
function startServer(opts = {}) {
  return new Promise((resolve) => {
    const stats = { conns: 0, authCalls: 0, pwAttempts: 0, ready: 0, execs: 0, shells: 0, rekeys: 0, closed: 0 };
    const rekey = (client) => client.rekey((err) => { if (!err) stats.rekeys++; });
    // ssh2 n'offre pas d'API pour changer de clé d'hôte en cours de session : le test remplace la table
    // interne des clés de CETTE connexion (copie : la table partagée par les autres connexions reste intacte).
    const rekeyWithOtherKey = (client) => {
      const other = parseKey(SWAP_HOST_KEY);
      const swapped = Object.create(null);
      for (const algo of Object.keys(client._protocol._hostKeys)) swapped[algo] = other;
      client._protocol._hostKeys = swapped;
      rekey(client);
    };
    const srv = new Server({ hostKeys: [HOST_KEY] }, (client) => {
      let gone = false;
      stats.conns++;
      client.on('close', () => { gone = true; stats.closed++; });
      client.on('authentication', (ctx) => {
        stats.authCalls++;
        if (ctx.method === 'none') return ctx.reject(['password']);
        if (ctx.method === 'password') stats.pwAttempts++;
        const ok = ctx.method === 'password' && ctx.username === USER && ctx.password === PASS;
        // Client parti pendant l'attente : ne pas répondre (ssh2 émettrait 'ready' APRÈS 'close' et son
        // keepalive serveur, jamais arrêté, retiendrait le processus de test une minute).
        const answer = () => { if (gone) return; try { if (ok) ctx.accept(); else ctx.reject(); } catch { /* client parti */ } };
        if (opts.authDelayMs) setTimeout(answer, opts.authDelayMs); else answer();
      });
      client.on('ready', () => {
        stats.ready++;
        client.on('session', (accept) => {
          const session = accept();
          session.on('exec', (acc, rej, info) => {
            stats.execs++;
            const ch = acc();
            const cmd = info.command;
            if (cmd.includes('hang')) { ch.write('hanging\n'); return; } // ne se ferme jamais
            const finish = () => {
              try {
                if (cmd.includes('bigout')) ch.write(Buffer.alloc(2 * 1024 * 1024, 0x41));
                else ch.write('stdout:' + cmd + '\n');
                ch.stderr.write('stderr:' + cmd + '\n');
                ch.exit(cmd.includes('fail') ? 3 : 0);
                ch.end();
              } catch { /* connexion déjà fermée par le client */ }
            };
            if (cmd.includes('swapkey')) { setTimeout(() => rekeyWithOtherKey(client), 100); setTimeout(finish, 1200); return; }
            if (cmd.includes('rekey')) { setTimeout(() => rekey(client), 100); setTimeout(finish, 1200); return; }
            if (cmd.includes('slow')) setTimeout(finish, 3000); else finish();
          });
          let shellCh = null;
          session.on('pty', (acc) => { if (acc) acc(); });
          session.on('shell', (acc) => {
            stats.shells++;
            if (opts.shellNoReply) return; // ni accept ni reject : le client attend indéfiniment
            if (opts.shellRekeyAfterMs) setTimeout(() => rekey(client), opts.shellRekeyAfterMs);
            if (opts.shellSwapKeyAfterMs) setTimeout(() => rekeyWithOtherKey(client), opts.shellSwapKeyAfterMs);
            shellCh = acc();
            shellCh.write('READY\r\n');
            shellCh.on('data', (d) => {
              if (String(d).includes('exit')) { shellCh.exit(0); shellCh.end(); shellCh.close(); return; } // fermeture DISTANTE
              shellCh.write('ECHO:' + d);
            });
          });
          session.on('window-change', (acc, rej, info) => { if (acc) acc(); if (shellCh) shellCh.write('WIN:' + info.rows + 'x' + info.cols + '\r\n'); });
        });
      });
      client.on('error', () => {});
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port, stats }));
  });
}

const base = (port, extra) => ({ host: '127.0.0.1', port, username: USER, password: PASS, ...extra });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Échoue (au lieu de bloquer la suite) si la promesse n'est pas réglée en `ms` millisecondes. */
function within(ms, promise, label) {
  let t;
  return Promise.race([
    promise,
    new Promise((resolve, reject) => { t = setTimeout(() => reject(new Error(`${label} : toujours en attente après ${ms} ms`)), ms); }),
  ]).finally(() => clearTimeout(t));
}

// Serveur TCP « muet » : accepte la connexion mais ne lit ni n'écrit jamais (sshd figé, tarpit…),
// donc ne renvoie jamais de FIN. Les sockets côté serveur sont suivies pour être décomptées.
function startMuteServer() {
  return new Promise((resolve) => {
    const sockets = new Set();
    const srv = net.createServer((s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => {}); s.pause(); });
    srv.listen(0, '127.0.0.1', () => resolve({
      port: srv.address().port, sockets,
      close: () => { for (const s of sockets) s.destroy(); srv.close(); },
    }));
  });
}
/** Nombre de handles TCP (sockets) actifs dans ce processus. */
const tcpHandles = () => process.getActiveResourcesInfo().filter((r) => r === 'TCPSocketWrap').length;

test('exécute une commande et renvoie stdout/stderr/code (mot de passe du coffre, opt-in trustNewHostKeys)', async () => {
  const { srv, port } = await startServer();
  try {
    const r = await execWithPassword(base(port, { command: 'hostname', trustNewHostKeys: true }));
    assert.equal(r.code, 0);
    assert.match(r.stdout, /stdout:hostname/);
    assert.match(r.stderr, /stderr:hostname/);
    assert.equal(r.hostFingerprint, HOST_FP, 'empreinte observée = empreinte réelle de la clé du serveur');
    assert.equal(r.hostKeyStatus, 'new');
  } finally { srv.close(); }
});

test('le résultat ne contient PAS le mot de passe', async () => {
  const { srv, port } = await startServer();
  try {
    const r = await execWithPassword(base(port, { command: 'echo hi', trustNewHostKeys: true }));
    assert.equal(JSON.stringify(r).includes(PASS), false, 'mot de passe absent du résultat');
  } finally { srv.close(); }
});

test('code de sortie non nul propagé', async () => {
  const { srv, port } = await startServer();
  try {
    const r = await execWithPassword(base(port, { command: 'do-fail', trustNewHostKeys: true }));
    assert.equal(r.code, 3);
  } finally { srv.close(); }
});

test('mauvais mot de passe → échec de connexion (rejet, sans code HOST_KEY_*)', async () => {
  const { srv, port, stats } = await startServer();
  try {
    await assert.rejects(
      () => execWithPassword(base(port, { password: 'mauvais', command: 'x', timeoutMs: 8000, trustNewHostKeys: true })),
      (e) => !/^HOST_KEY_/.test(e.code || ''),
    );
    assert.ok(stats.authCalls > 0, 'la clé d\'hôte acceptée, l\'authentification a bien été tentée');
  } finally { srv.close(); }
});

test('SEC-1 : clé inconnue sans opt-in → HOST_KEY_UNKNOWN et le mot de passe n\'est JAMAIS envoyé', async () => {
  const { srv, port, stats } = await startServer();
  try {
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', timeoutMs: 8000 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_UNKNOWN');
      assert.equal(e.observed, HOST_FP);
      assert.match(e.message, /inconnue/);
      assert.equal(e.message.includes(PASS), false);
      return true;
    });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(stats.authCalls, 0, 'handler authentication du serveur jamais appelé');
    assert.equal(stats.ready, 0);
  } finally { srv.close(); }
});

test('épinglage : hostFingerprint correct → statut pinned et mémorisé ; incorrect → HOST_KEY_MISMATCH sans auth', async () => {
  const { srv, port, stats } = await startServer();
  const kh = tmpKnownHosts();
  try {
    const ok = await execWithPassword(base(port, { command: 'id', hostFingerprint: 'sha256:' + HOST_FP.slice(7) + '=', knownHosts: kh }));
    assert.equal(ok.code, 0);
    assert.equal(ok.hostKeyStatus, 'pinned');
    assert.equal(kh.lookup('127.0.0.1', port), HOST_FP, 'empreinte épinglée mémorisée dans known_hosts');
    const before = stats.authCalls;
    kh.forget('127.0.0.1', port);
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', hostFingerprint: OTHER_FP, knownHosts: kh, timeoutMs: 8000 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_MISMATCH');
      assert.equal(e.expected, OTHER_FP);
      assert.equal(e.observed, HOST_FP);
      assert.match(e.message, /attendue .* observée/);
      return true;
    });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(stats.authCalls, before, 'aucune tentative d\'authentification après refus');
    assert.equal(kh.lookup('127.0.0.1', port), null, 'rien mémorisé après refus');
  } finally { srv.close(); }
});

test('known_hosts + onNewHostKey : rappel une fois (host, port, fingerprint), mémorisé, puis statut known sans rappel', async () => {
  const { srv, port } = await startServer();
  const kh = tmpKnownHosts();
  const calls = [];
  const onNewHostKey = async (info) => { calls.push(info); await new Promise((r) => setTimeout(r, 50)); return true; };
  try {
    const first = await execWithPassword(base(port, { command: 'id', knownHosts: kh, onNewHostKey }));
    assert.equal(first.hostKeyStatus, 'new');
    assert.deepEqual(calls, [{ host: '127.0.0.1', port, fingerprint: HOST_FP }]);
    assert.equal(kh.lookup('127.0.0.1', port), HOST_FP);
    const second = await execWithPassword(base(port, { command: 'id', knownHosts: kh, onNewHostKey }));
    assert.equal(second.hostKeyStatus, 'known');
    assert.equal(second.hostFingerprint, HOST_FP);
    assert.equal(calls.length, 1, 'pas de nouveau rappel pour une clé connue');
  } finally { srv.close(); }
});

test('known_hosts altéré → HOST_KEY_CHANGED avec err.expected / err.observed, sans auth ni réécriture', async () => {
  const { srv, port, stats } = await startServer();
  const kh = tmpKnownHosts();
  kh.remember('127.0.0.1', port, OTHER_FP); // clé « précédemment vue » différente
  let called = 0;
  try {
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', knownHosts: kh, onNewHostKey: async () => { called++; return true; }, trustNewHostKeys: true, timeoutMs: 8000 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_CHANGED');
      assert.equal(e.expected, OTHER_FP);
      assert.equal(e.observed, HOST_FP);
      assert.match(e.message, new RegExp('attendue ' + OTHER_FP.replace(/[+/]/g, '\\$&') + '.*observée'));
      return true;
    });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(stats.authCalls, 0);
    assert.equal(called, 0, 'un changement de clé n\'est pas une « nouvelle clé » : pas de rappel, même avec trustNewHostKeys');
    assert.equal(kh.lookup('127.0.0.1', port), OTHER_FP, 'known_hosts inchangé');
  } finally { srv.close(); }
});

test('onNewHostKey → false (ou exception) → HOST_KEY_REJECTED, rien mémorisé, pas d\'auth', async () => {
  const { srv, port, stats } = await startServer();
  const kh = tmpKnownHosts();
  try {
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', knownHosts: kh, onNewHostKey: async () => false, timeoutMs: 8000 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_REJECTED');
      assert.equal(e.observed, HOST_FP);
      return true;
    });
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', knownHosts: kh, onNewHostKey: async () => { throw new Error('boum'); }, timeoutMs: 8000 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_REJECTED');
      assert.match(e.message, /boum/);
      return true;
    });
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(stats.authCalls, 0);
    assert.equal(kh.lookup('127.0.0.1', port), null);
  } finally { srv.close(); }
});

test('BUG-3 : execTimeoutMs court sur un flux jamais fermé → EXEC_TIMEOUT alors que la connexion a réussi', async () => {
  const { srv, port, stats } = await startServer();
  try {
    const t0 = Date.now();
    await assert.rejects(() => execWithPassword(base(port, { command: 'hang', trustNewHostKeys: true, execTimeoutMs: 500 })), (e) => {
      assert.equal(e.code, 'EXEC_TIMEOUT');
      assert.match(e.message, /Délai d'exécution SSH dépassé/);
      return true;
    });
    assert.ok(Date.now() - t0 < 10000, 'rejet rapide');
    assert.equal(stats.ready, 1, 'connexion et authentification réussies avant le délai d\'exécution');
  } finally { srv.close(); }
});

test('BUG-3 : le délai de connexion est annulé sur ready — une commande plus longue que timeoutMs aboutit (execTimeoutMs=0 illimité)', async () => {
  const { srv, port } = await startServer();
  try {
    const r = await execWithPassword(base(port, { command: 'slow', trustNewHostKeys: true, timeoutMs: 2000, execTimeoutMs: 0 }));
    assert.equal(r.code, 0);
    assert.match(r.stdout, /stdout:slow/);
  } finally { srv.close(); }
});

test('sortie bornée par maxOutputBytes', async () => {
  const { srv, port } = await startServer();
  try {
    const r = await execWithPassword(base(port, { command: 'bigout', maxOutputBytes: 4096, trustNewHostKeys: true }));
    assert.ok(r.stdout.length <= 4096, 'stdout borné à 4096 (len=' + r.stdout.length + ')');
  } finally { srv.close(); }
});

test('paramètres manquants → rejet clair', async () => {
  await assert.rejects(() => execWithPassword({ host: 'h', username: 'u', command: 'c' }), /requis/);
});

test('shell interactif proxifié sur socket : échange bidirectionnel, mot de passe absent, statut de clé', async () => {
  const { srv, port } = await startServer();
  let sess = null;
  try {
    sess = await createShellSession(base(port, { rows: 24, cols: 80, trustNewHostKeys: true }));
    assert.ok(sess.sock, 'socket de session fournie');
    assert.equal(sess.hostFingerprint, HOST_FP);
    assert.equal(sess.hostKeyStatus, 'new');
    const got = await new Promise((resolve, reject) => {
      const c = net.connect(sess.sock);
      let buf = '';
      c.on('data', (d) => { buf += d; if (buf.includes('ECHO:ping')) { resolve(buf); try { c.end(); } catch {} } });
      c.on('connect', () => setTimeout(() => c.write('ping\n'), 200));
      c.on('error', reject);
      setTimeout(() => reject(new Error('timeout shell')), 8000);
    });
    const clean = got.replace(/\r/g, '');
    assert.match(clean, /READY/, 'bannière du shell reçue');
    assert.match(clean, /ECHO:ping/, 'entrée relayée et écho reçu');
    assert.equal(clean.includes(PASS), false, 'le mot de passe ne transite jamais par la socket');
  } finally {
    if (sess) sess.close();
    srv.close();
  }
});

test('shell : clé inconnue sans opt-in → HOST_KEY_UNKNOWN, aucune auth', async () => {
  const { srv, port, stats } = await startServer();
  try {
    await assert.rejects(() => createShellSession(base(port, { timeoutMs: 8000 })), (e) => e.code === 'HOST_KEY_UNKNOWN');
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(stats.authCalls, 0);
  } finally { srv.close(); }
});

test('redimensionnement du terminal propagé au PTY distant (window-change)', async () => {
  const { srv, port } = await startServer();
  let sess = null;
  try {
    sess = await createShellSession(base(port, { rows: 24, cols: 80, trustNewHostKeys: true }));
    const got = await new Promise((resolve, reject) => {
      const c = net.connect(sess.sock);
      let buf = '';
      c.on('data', (d) => { buf += d; if (buf.includes('WIN:40x120')) { resolve(buf); try { c.end(); } catch {} } });
      c.on('connect', () => setTimeout(() => sess.resize(40, 120), 250));
      c.on('error', reject);
      setTimeout(() => reject(new Error('timeout resize')), 8000);
    });
    assert.match(got.replace(/\r/g, ''), /WIN:40x120/, 'le PTY distant a reçu la nouvelle taille');
  } finally {
    if (sess) sess.close();
    srv.close();
  }
});

test('BUG-8 : onClose appelé exactement une fois quand le serveur ferme le canal (puis close() local sans rappel)', async () => {
  const { srv, port } = await startServer();
  let sess = null, closes = 0;
  try {
    sess = await createShellSession(base(port, { trustNewHostKeys: true, onClose: () => { closes++; } }));
    assert.equal(closes, 0);
    await new Promise((resolve, reject) => {
      const c = net.connect(sess.sock);
      c.on('data', () => {}); // flux consommé (sinon 'end' n'est jamais émis côté client)
      c.on('connect', () => setTimeout(() => c.write('exit\n'), 200));
      c.on('close', resolve); // la socket locale se ferme quand le canal distant est fermé
      c.on('error', () => {});
      setTimeout(() => reject(new Error('timeout fermeture')), 8000);
    });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(closes, 1, 'onClose appelé une fois à la fermeture distante');
    sess.close();
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(closes, 1, 'close() local après coup : pas de second appel');
  } finally {
    if (sess) sess.close();
    srv.close();
  }
});

test('BUG-8 : onClose appelé une fois sur close() local', async () => {
  const { srv, port } = await startServer();
  let closes = 0;
  try {
    const sess = await createShellSession(base(port, { trustNewHostKeys: true, onClose: () => { closes++; } }));
    sess.close(); sess.close();
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(closes, 1);
  } finally { srv.close(); }
});

test('createHostVerifier utilisable seul (forme asynchrone ssh2 : retour undefined, puis verify)', async () => {
  const keyBuf = parseKey(HOST_KEY).getPublicSSH();
  const run = (o) => new Promise((resolve) => {
    const hv = createHostVerifier({ host: 'Srv', port: 22, ...o });
    const ret = hv.verifier(keyBuf, (ok) => resolve({ ok, hv }));
    assert.equal(ret, undefined, 'forme asynchrone : rien n\'est renvoyé, ssh2 attend verify()');
  });
  // aucune politique → refus
  let r = await run({});
  assert.equal(r.ok, false);
  assert.equal(r.hv.error.code, 'HOST_KEY_UNKNOWN');
  assert.equal(r.hv.fingerprint, HOST_FP);
  assert.equal(r.hv.status, null);
  // opt-in explicite
  r = await run({ trustNewHostKeys: true });
  assert.equal(r.ok, true); assert.equal(r.hv.status, 'new'); assert.equal(r.hv.error, null);
  // épinglage
  r = await run({ hostFingerprint: HOST_FP });
  assert.equal(r.ok, true); assert.equal(r.hv.status, 'pinned');
  r = await run({ hostFingerprint: OTHER_FP });
  assert.equal(r.ok, false); assert.equal(r.hv.error.code, 'HOST_KEY_MISMATCH');
  // mémoire + rappel
  const kh = tmpKnownHosts();
  r = await run({ knownHosts: kh, onNewHostKey: async (i) => i.fingerprint === HOST_FP });
  assert.equal(r.ok, true); assert.equal(r.hv.status, 'new'); assert.equal(kh.lookup('srv', 22), HOST_FP);
  r = await run({ knownHosts: kh });
  assert.equal(r.ok, true); assert.equal(r.hv.status, 'known');
  kh.remember('srv', 22, OTHER_FP);
  r = await run({ knownHosts: kh, trustNewHostKeys: true });
  assert.equal(r.ok, false); assert.equal(r.hv.error.code, 'HOST_KEY_CHANGED');
  assert.equal(r.hv.error.expected, OTHER_FP); assert.equal(r.hv.error.observed, HOST_FP);
  // SSHCORE-64 : un épinglage correct ne remplace JAMAIS en silence une autre clé mémorisée
  r = await run({ knownHosts: kh, hostFingerprint: HOST_FP });
  assert.equal(r.ok, false, 'épinglage ≠ mémoire → refus'); assert.equal(r.hv.error.code, 'HOST_KEY_CHANGED');
  assert.equal(r.hv.error.expected, OTHER_FP); assert.equal(r.hv.error.observed, HOST_FP);
  assert.equal(kh.lookup('srv', 22), OTHER_FP, 'mémoire inchangée');
  kh.forget('srv', 22);
  r = await run({ knownHosts: kh, hostFingerprint: HOST_FP });
  assert.equal(r.ok, true, 'épinglage sans entrée mémorisée'); assert.equal(r.hv.status, 'pinned');
  assert.equal(kh.lookup('srv', 22), HOST_FP, 'et mémorise l\'empreinte épinglée');
  r = await run({ knownHosts: kh, hostFingerprint: HOST_FP });
  assert.equal(r.ok, true, 'épinglage = mémoire'); assert.equal(r.hv.status, 'pinned');
  // mémorisation impossible → refus explicite
  const blocker = path.join(khTmpDir(), 'f');
  fs.writeFileSync(blocker, 'x');
  r = await run({ knownHosts: createKnownHosts(path.join(blocker, 'known_hosts.json')), trustNewHostKeys: true });
  assert.equal(r.ok, false); assert.equal(r.hv.error.code, 'KNOWN_HOSTS_WRITE');
  // SSHCORE-52 : mémoire illisible → refus explicite KNOWN_HOSTS_READ (jamais traitée comme vide)
  const corrupt = path.join(khTmpDir(), 'known_hosts.json');
  fs.writeFileSync(corrupt, '{ pas du json');
  for (const o of [{ trustNewHostKeys: true }, { hostFingerprint: HOST_FP }, { onNewHostKey: async () => true }]) {
    r = await run({ knownHosts: createKnownHosts(corrupt), ...o });
    assert.equal(r.ok, false); assert.equal(r.hv.error.code, 'KNOWN_HOSTS_READ'); assert.equal(r.hv.status, null);
    assert.match(r.hv.error.message, /lire/);
  }
  assert.equal(fs.readFileSync(corrupt, 'utf8'), '{ pas du json', 'fichier illisible jamais réécrit');
});

test('SSHCORE-52 : known_hosts illisible → KNOWN_HOSTS_READ, le mot de passe n\'est jamais envoyé', async () => {
  const { srv, port, stats } = await startServer();
  const file = path.join(khTmpDir(), 'known_hosts.json');
  fs.writeFileSync(file, '{ pas du json');
  try {
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', knownHosts: createKnownHosts(file), trustNewHostKeys: true, timeoutMs: 8000 })),
      (e) => e.code === 'KNOWN_HOSTS_READ');
    await sleep(200);
    assert.equal(stats.authCalls, 0);
  } finally { srv.close(); }
});

test('SSHCORE-64 : épinglage correct mais known_hosts mémorise une AUTRE clé → HOST_KEY_CHANGED, sans auth ni réécriture', async () => {
  const { srv, port, stats } = await startServer();
  const kh = tmpKnownHosts();
  kh.remember('127.0.0.1', port, OTHER_FP); // clé validée précédemment (TOFU)
  try {
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', hostFingerprint: HOST_FP, knownHosts: kh, timeoutMs: 8000 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_CHANGED');
      assert.equal(e.expected, OTHER_FP, 'attendue = clé mémorisée');
      assert.equal(e.observed, HOST_FP);
      return true;
    });
    await sleep(200);
    assert.equal(stats.authCalls, 0, 'mot de passe jamais envoyé');
    assert.equal(kh.lookup('127.0.0.1', port), OTHER_FP, 'known_hosts non empoisonné');
    // une connexion suivante NON épinglée voit toujours la clé mémorisée d'origine
    await assert.rejects(() => execWithPassword(base(port, { command: 'id', knownHosts: kh, trustNewHostKeys: true, timeoutMs: 8000 })),
      (e) => e.code === 'HOST_KEY_CHANGED');
  } finally { srv.close(); }
});

test('SSHCORE-65 : acceptation d\'une clé inconnue re-vérifiée APRÈS la réponse de l\'utilisateur (compare-and-swap)', async () => {
  const keyA = parseKey(HOST_KEY).getPublicSSH();
  const keyB = Buffer.from('autre-cle-d-hote');
  const FP_B = hostKeyFingerprint(keyB);
  // (1) deux premières connexions concurrentes vers srv:22 observant des clés différentes, popups en attente
  const kh = tmpKnownHosts();
  const answers = [];
  const onNewHostKey = () => new Promise((resolve) => answers.push(resolve));
  const hvA = createHostVerifier({ host: 'srv', port: 22, knownHosts: kh, onNewHostKey });
  const hvB = createHostVerifier({ host: 'srv', port: 22, knownHosts: kh, onNewHostKey });
  const pA = new Promise((resolve) => hvA.verifier(keyA, resolve));
  const pB = new Promise((resolve) => hvB.verifier(keyB, resolve));
  await sleep(20);
  assert.equal(answers.length, 2, 'les deux clés sont « nouvelles » au moment de la vérification');
  answers[0](true);
  assert.equal(await pA, true);
  assert.equal(kh.lookup('srv', 22), HOST_FP);
  answers[1](true);
  assert.equal(await pB, false, 'la seconde acceptation constate qu\'une autre clé a été mémorisée entre-temps');
  assert.equal(hvB.error.code, 'HOST_KEY_CHANGED');
  assert.equal(hvB.error.expected, HOST_FP); assert.equal(hvB.error.observed, FP_B);
  assert.equal(kh.lookup('srv', 22), HOST_FP, 'la clé mémorisée n\'est pas écrasée');
  // (2) une autre voie mémorise une clé différente pendant la popup
  const kh2 = tmpKnownHosts();
  const hvC = createHostVerifier({ host: 'srv', port: 22, knownHosts: kh2, onNewHostKey: async () => { kh2.remember('srv', 22, FP_B); return true; } });
  assert.equal(await new Promise((resolve) => hvC.verifier(keyA, resolve)), false);
  assert.equal(hvC.error.code, 'HOST_KEY_CHANGED'); assert.equal(hvC.error.expected, FP_B);
  assert.equal(kh2.lookup('srv', 22), FP_B);
  // (3) même clé mémorisée pendant la popup → acceptée (statut « new »)
  const kh3 = tmpKnownHosts();
  const hvD = createHostVerifier({ host: 'srv', port: 22, knownHosts: kh3, onNewHostKey: async () => { kh3.remember('srv', 22, HOST_FP); return true; } });
  assert.equal(await new Promise((resolve) => hvD.verifier(keyA, resolve)), true);
  assert.equal(hvD.status, 'new');
});

test('SSHCORE-55/67 : vérificateur rappelé au re-KEX — même clé acceptée sans rappel, statut figé ; clé différente refusée', async () => {
  const keyA = parseKey(HOST_KEY).getPublicSSH();
  const keyB = Buffer.from('autre-cle-d-hote');
  let calls = 0;
  const hv = createHostVerifier({ host: 'srv', port: 22, onNewHostKey: async () => { calls++; return true; } });
  const verifyOnce = (k) => new Promise((resolve) => hv.verifier(k, resolve));
  assert.equal(await verifyOnce(keyA), true);
  assert.equal(await verifyOnce(keyA), true, 're-KEX, même clé');
  assert.equal(calls, 1, 'pas de nouveau rappel pour la clé déjà acceptée sur cette connexion');
  assert.equal(hv.status, 'new');
  assert.equal(await verifyOnce(keyB), false, 'clé d\'hôte différente en cours de session');
  assert.equal(hv.error.code, 'HOST_KEY_CHANGED_REKEY', 'code distinct d\'un changement constaté à la connexion');
  assert.equal(hv.error.expected, HOST_FP); assert.equal(hv.error.observed, hostKeyFingerprint(keyB));
  assert.match(hv.error.message, /EN COURS de session/);
  assert.match(hv.error.message, /known_hosts n'a pas été modifié/);
  assert.doesNotMatch(hv.error.message, /supprime/i, 'aucune invitation à supprimer l\'entrée mémorisée');
  assert.equal(hv.fingerprint, HOST_FP, 'empreinte rapportée = celle acceptée pour la connexion');
  assert.equal(calls, 1);
  // avec known_hosts : le statut « new » n'est pas réécrit en « known » au re-KEX, rien n'est re-mémorisé
  const kh = tmpKnownHosts();
  const hv2 = createHostVerifier({ host: 'srv', port: 22, knownHosts: kh, onNewHostKey: async () => true });
  assert.equal(await new Promise((resolve) => hv2.verifier(keyA, resolve)), true);
  kh.forget('srv', 22); // entrée oubliée en cours de session
  assert.equal(await new Promise((resolve) => hv2.verifier(keyA, resolve)), true);
  assert.equal(hv2.status, 'new');
  assert.equal(kh.lookup('srv', 22), null, 'le re-KEX ne re-mémorise pas');
  // clé mémorisée puis clé DIFFÉRENTE au re-KEX : HOST_KEY_CHANGED_REKEY, known_hosts jamais réécrit
  const kh3 = tmpKnownHosts();
  kh3.remember('srv', 22, HOST_FP);
  const khBefore = fs.readFileSync(kh3.path, 'utf8');
  const hv3 = createHostVerifier({ host: 'srv', port: 22, knownHosts: kh3, trustNewHostKeys: true });
  assert.equal(await new Promise((resolve) => hv3.verifier(keyA, resolve)), true);
  assert.equal(hv3.status, 'known');
  assert.equal(await new Promise((resolve) => hv3.verifier(keyB, resolve)), false);
  assert.equal(hv3.error.code, 'HOST_KEY_CHANGED_REKEY');
  assert.equal(hv3.status, 'known', 'statut de la connexion inchangé');
  assert.equal(fs.readFileSync(kh3.path, 'utf8'), khBefore, 'known_hosts.json inchangé (ni mémorisation, ni suppression)');
});

test('SSHCORE-66/55/67 : re-KEX serveur pendant une commande — un seul rappel, délai de connexion non réarmé, statut « new »', async () => {
  const { srv, port, stats } = await startServer();
  try {
    // onNewHostKey SANS knownHosts (forme documentée) ; la commande dure 1,2 s > timeoutMs (400 ms)
    let calls = 0;
    const r = await within(8000, execWithPassword(base(port, { command: 'rekey', timeoutMs: 400, execTimeoutMs: 0, onNewHostKey: async () => { calls++; return true; } })), 'exec+rekey');
    assert.equal(stats.rekeys, 1, 'le re-KEX a bien eu lieu');
    assert.equal(r.code, 0);
    assert.match(r.stdout, /stdout:rekey/);
    assert.equal(calls, 1);
    assert.equal(r.hostKeyStatus, 'new');
    // knownHosts vide + onNewHostKey : statut rapporté « new » malgré le re-KEX
    const kh = tmpKnownHosts();
    calls = 0;
    const r2 = await within(8000, execWithPassword(base(port, { command: 'rekey', timeoutMs: 400, execTimeoutMs: 0, knownHosts: kh, onNewHostKey: async () => { calls++; return true; } })), 'exec+rekey+kh');
    assert.equal(stats.rekeys, 2);
    assert.equal(r2.hostKeyStatus, 'new');
    assert.equal(calls, 1);
    assert.equal(kh.lookup('127.0.0.1', port), HOST_FP);
  } finally { srv.close(); }
});

test('SSHCORE-66/55 : shell — re-KEX après ouverture : session vivante au-delà de timeoutMs, un seul rappel', async () => {
  const { srv, port, stats } = await startServer({ shellRekeyAfterMs: 100 });
  let sess = null, calls = 0, closes = 0, c = null;
  try {
    sess = await within(8000, createShellSession(base(port, { timeoutMs: 400, onNewHostKey: async () => { calls++; return true; }, onClose: () => { closes++; } })), 'shell');
    c = net.connect(sess.sock);
    let buf = '';
    c.on('data', (d) => { buf += d; });
    c.on('error', () => {});
    await sleep(1000); // > 100 + 400 ms : un délai réarmé au re-KEX aurait expiré
    c.write('ping\n');
    for (let i = 0; i < 50 && !buf.includes('ECHO:ping'); i++) await sleep(100);
    assert.equal(stats.rekeys, 1, 'le re-KEX a bien eu lieu');
    assert.match(buf, /ECHO:ping/, 'session toujours vivante');
    assert.equal(closes, 0);
    assert.equal(calls, 1, 'pas de nouveau rappel au re-KEX');
    assert.equal(sess.hostKeyStatus, 'new');
  } finally {
    if (c) c.destroy();
    if (sess) sess.close();
    srv.close();
  }
});

test('SSHCORE-51 : shell — le délai de connexion couvre l\'ouverture du shell (requête « shell » sans réponse)', async () => {
  const { srv, port, stats } = await startServer({ shellNoReply: true });
  try {
    const t0 = Date.now();
    await within(5000, assert.rejects(() => createShellSession(base(port, { trustNewHostKeys: true, timeoutMs: 1000 })), (e) => {
      assert.equal(e.code, 'CONNECT_TIMEOUT');
      assert.match(e.message, /Délai de connexion SSH dépassé/);
      return true;
    }), 'createShellSession');
    assert.ok(Date.now() - t0 < 4000, 'rejet au délai');
    assert.equal(stats.ready, 1, 'authentification réussie avant le blocage');
    for (let i = 0; i < 30 && stats.closed === 0; i++) await sleep(100);
    assert.equal(stats.closed, 1, 'la connexion authentifiée est fermée (pas de fuite côté serveur)');
  } finally { srv.close(); }
});

test('SSHCORE-53/54 : serveur TCP muet → CONNECT_TIMEOUT et socket client DÉTRUITE (exec et shell)', async () => {
  const mute = await startMuteServer();
  try {
    await sleep(300); // laisse se fermer les sockets des tests précédents
    const before = tcpHandles();
    for (let i = 0; i < 2; i++) {
      const t0 = Date.now();
      await within(5000, assert.rejects(() => execWithPassword(base(mute.port, { command: 'x', trustNewHostKeys: true, timeoutMs: 300 })), (e) => {
        assert.equal(e.code, 'CONNECT_TIMEOUT');
        assert.match(e.message, /Délai de connexion SSH dépassé/);
        return true;
      }), 'exec');
      assert.ok(Date.now() - t0 < 3000);
      await within(5000, assert.rejects(() => createShellSession(base(mute.port, { trustNewHostKeys: true, timeoutMs: 300 })), (e) => e.code === 'CONNECT_TIMEOUT'), 'shell');
    }
    await sleep(300);
    const clientHandles = tcpHandles() - mute.sockets.size;
    assert.ok(clientHandles <= before, `aucun handle TCP client résiduel (avant ${before}, après ${clientHandles})`);
  } finally { mute.close(); }
});

test('SSHCORE-57 : timeoutMs invalide (null, NaN, texte, négatif) → délai par défaut de 20 s, jamais d\'attente infinie', async (t) => {
  const mute = await startMuteServer();
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const flush = () => new Promise((r) => setImmediate(r));
  try {
    const cases = [['exec', null], ['exec', NaN], ['exec', 'abc'], ['exec', -5], ['shell', null], ['shell', 'abc']];
    for (const [kind, timeoutMs] of cases) {
      const o = base(mute.port, { command: 'x', trustNewHostKeys: true, timeoutMs });
      let outcome = null;
      (kind === 'exec' ? execWithPassword(o) : createShellSession(o)).then(() => { outcome = 'résolu'; }, (e) => { outcome = e; });
      await flush();
      t.mock.timers.tick(19999);
      await flush();
      assert.equal(outcome, null, `${kind} timeoutMs=${String(timeoutMs)} : pas de rejet avant le délai par défaut`);
      t.mock.timers.tick(1);
      await flush(); await flush();
      assert.ok(outcome && outcome.code === 'CONNECT_TIMEOUT', `${kind} timeoutMs=${String(timeoutMs)} : rejet CONNECT_TIMEOUT au délai par défaut (obtenu ${outcome && (outcome.code || outcome.message || outcome)})`);
    }
  } finally {
    t.mock.timers.reset();
    mute.close();
  }
});

// ─── REKEY : clé d'hôte changée lors d'un re-KEX en cours de session (bout en bout) ───

test('REKEY : exec — re-KEX serveur avec une AUTRE clé d\'hôte → HOST_KEY_CHANGED_REKEY, known_hosts intact', async () => {
  const { srv, port, stats } = await startServer();
  const kh = tmpKnownHosts();
  kh.remember('127.0.0.1', port, HOST_FP);
  const khBefore = fs.readFileSync(kh.path, 'utf8');
  try {
    await within(8000, assert.rejects(() => execWithPassword(base(port, { command: 'swapkey', knownHosts: kh, execTimeoutMs: 0 })), (e) => {
      assert.equal(e.code, 'HOST_KEY_CHANGED_REKEY');
      assert.equal(e.expected, HOST_FP, 'attendue = clé vérifiée à la connexion');
      assert.equal(e.observed, SWAP_FP, 'observée = clé présentée au re-KEX');
      assert.match(e.message, /EN COURS de session/);
      assert.doesNotMatch(e.message, /supprime/i);
      assert.equal(e.message.includes(PASS), false);
      return true;
    }), 'exec+swapkey');
    assert.equal(stats.execs, 1, 'commande lancée (clé initiale valide) puis connexion interrompue au re-KEX');
    assert.equal(stats.rekeys, 0, 'le re-KEX piégé n\'aboutit pas');
    assert.equal(fs.readFileSync(kh.path, 'utf8'), khBefore, 'known_hosts.json non modifié');
    assert.equal(kh.lookup('127.0.0.1', port), HOST_FP);
  } finally { srv.close(); }
});

test('REKEY : shell — re-KEX avec une autre clé → session fermée, onClose(err) une fois avec HOST_KEY_CHANGED_REKEY', async () => {
  const { srv, port } = await startServer({ shellSwapKeyAfterMs: 300 });
  const kh = tmpKnownHosts();
  kh.remember('127.0.0.1', port, HOST_FP);
  const khBefore = fs.readFileSync(kh.path, 'utf8');
  const reasons = [];
  let sess = null, c = null;
  try {
    sess = await within(8000, createShellSession(base(port, { knownHosts: kh, onClose: (err) => { reasons.push(err); } })), 'shell');
    assert.equal(sess.hostKeyStatus, 'known');
    c = net.connect(sess.sock);
    c.on('data', () => {}); c.on('error', () => {});
    await within(8000, new Promise((resolve) => c.on('close', resolve)), 'fermeture de la socket locale');
    await sleep(200);
    assert.equal(reasons.length, 1, 'onClose appelé une seule fois');
    assert.ok(reasons[0] && reasons[0].code === 'HOST_KEY_CHANGED_REKEY', 'onClose reçoit l\'erreur de clé d\'hôte (obtenu ' + (reasons[0] && reasons[0].code) + ')');
    assert.equal(reasons[0].expected, HOST_FP); assert.equal(reasons[0].observed, SWAP_FP);
    assert.equal(fs.readFileSync(kh.path, 'utf8'), khBefore, 'known_hosts.json non modifié');
  } finally {
    if (c) c.destroy();
    if (sess) sess.close();
    srv.close();
  }
});

test('shell : onClose(null) pour une fermeture ordinaire (aucune erreur de clé d\'hôte)', async () => {
  const { srv, port } = await startServer();
  const reasons = [];
  try {
    const sess = await createShellSession(base(port, { trustNewHostKeys: true, onClose: (err) => { reasons.push(err); } }));
    sess.close();
    await sleep(100);
    assert.deepEqual(reasons, [null]);
  } finally { srv.close(); }
});

// ─── PERTE DE CONNEXION en cours de session : onClose reçoit une Error (et non null) ───

// Relais TCP entre le client et le serveur SSH jouet : permet de couper la connexion côté client
// (RST ou FIN) sans fermeture SSH propre, comme une coupure réseau ou un sshd tué.
function startRelay(targetPort) {
  return new Promise((resolve) => {
    const pairs = new Set();
    const srv = net.createServer((client) => {
      const upstream = net.connect(targetPort, '127.0.0.1');
      const pair = { client, upstream };
      pairs.add(pair);
      client.on('error', () => {}); upstream.on('error', () => {});
      client.pipe(upstream); upstream.pipe(client);
      const drop = () => { pairs.delete(pair); client.destroy(); upstream.destroy(); };
      client.on('close', drop); upstream.on('close', drop);
    });
    srv.listen(0, '127.0.0.1', () => resolve({
      port: srv.address().port,
      // reset : RST (ECONNRESET côté client) ; sinon FIN sans SSH_MSG_DISCONNECT ni fermeture de canal.
      cut: (reset) => { for (const { client, upstream } of pairs) { upstream.unpipe(client); if (reset) client.resetAndDestroy(); else client.destroy(); } },
      close: () => { for (const { client, upstream } of pairs) { client.destroy(); upstream.destroy(); } srv.close(); },
    }));
  });
}

for (const reset of [true, false]) {
  test(`shell : connexion coupée après ouverture (${reset ? 'RST' : 'FIN'}) → onClose reçoit une Error, une seule fois`, async () => {
    const { srv, port } = await startServer();
    const relay = await startRelay(port);
    const reasons = [];
    let sess = null;
    try {
      sess = await within(8000, createShellSession(base(relay.port, { trustNewHostKeys: true, onClose: (err) => { reasons.push(err); } })), 'shell');
      await sleep(100);
      relay.cut(reset);
      const t0 = Date.now();
      while (reasons.length === 0 && Date.now() - t0 < 5000) await sleep(20);
      await sleep(200);
      assert.equal(reasons.length, 1, 'onClose appelé une seule fois');
      assert.ok(reasons[0] instanceof Error, 'perte de connexion rapportée comme erreur, pas comme fermeture ordinaire');
      assert.ok(reasons[0].code, 'erreur dotée d\'un code');
      if (!reset) assert.equal(reasons[0].code, 'SSH_CONNECTION_LOST');
      assert.notEqual(reasons[0].code, 'HOST_KEY_CHANGED_REKEY');
      assert.ok(!String(reasons[0].message).includes(PASS), 'le mot de passe n\'apparaît pas dans l\'erreur');
      sess.close();
      await sleep(50);
      assert.equal(reasons.length, 1, 'close() local après coup : pas de second appel');
    } finally {
      if (sess) sess.close();
      relay.close();
      srv.close();
    }
  });
}

test('shell : fermeture DISTANTE normale du canal (exit) → onClose(null), même si la TCP se ferme ensuite', async () => {
  const { srv, port } = await startServer();
  const relay = await startRelay(port);
  const reasons = [];
  let sess = null;
  try {
    sess = await within(8000, createShellSession(base(relay.port, { trustNewHostKeys: true, onClose: (err) => { reasons.push(err); } })), 'shell');
    await new Promise((resolve, reject) => {
      const c = net.connect(sess.sock);
      c.on('data', () => {});
      c.on('connect', () => setTimeout(() => c.write('exit\n'), 200));
      c.on('close', resolve);
      c.on('error', () => {});
      setTimeout(() => reject(new Error('timeout fermeture')), 8000);
    });
    relay.cut(false); // TCP coupée APRÈS la fermeture normale du canal : sans effet sur la raison
    await sleep(300);
    assert.deepEqual(reasons, [null]);
  } finally {
    if (sess) sess.close();
    relay.close();
    srv.close();
  }
});

// ─── ABORT : abandon par AbortSignal (client HTTP parti, Ctrl+C…) ───

test('ABORT : signal déjà déclenché → ABORTED immédiat, aucune connexion ouverte (exec et shell)', async () => {
  const { srv, port, stats } = await startServer();
  try {
    const ac = new AbortController();
    ac.abort();
    for (const run of [
      () => execWithPassword(base(port, { command: 'id', trustNewHostKeys: true, signal: ac.signal })),
      () => createShellSession(base(port, { trustNewHostKeys: true, signal: ac.signal })),
    ]) {
      await within(2000, assert.rejects(run, (e) => { assert.equal(e.code, 'ABORTED'); return true; }), 'abort');
    }
    await sleep(300);
    assert.equal(stats.conns, 0, 'aucune connexion SSH ouverte');
    assert.equal(stats.pwAttempts, 0, 'mot de passe jamais envoyé');
    assert.equal(stats.execs + stats.shells, 0);
  } finally { srv.close(); }
});

test('ABORT : abandon pendant l\'authentification → ABORTED, connexion détruite, commande / shell JAMAIS lancés', async () => {
  const { srv, port, stats } = await startServer({ authDelayMs: 700 });
  try {
    for (const kind of ['exec', 'shell']) {
      const ac = new AbortController();
      const o = base(port, { command: 'id', trustNewHostKeys: true, signal: ac.signal, execTimeoutMs: 0 });
      const attempts = stats.pwAttempts;
      const t0 = Date.now();
      const p = kind === 'exec' ? execWithPassword(o) : createShellSession(o);
      p.catch(() => {}); // rejet attendu, vérifié plus bas
      for (let i = 0; i < 200 && stats.pwAttempts === attempts; i++) await sleep(10);
      assert.equal(stats.pwAttempts, attempts + 1, `${kind} : mot de passe reçu, réponse du serveur en attente`);
      ac.abort();
      await within(2000, assert.rejects(p, (e) => { assert.equal(e.code, 'ABORTED'); assert.match(e.message, /abandonn/); return true; }), kind);
      assert.ok(Date.now() - t0 < 700, `${kind} : rejet sans attendre la fin de l'authentification`);
      assert.equal(getEventListeners(ac.signal, 'abort').length, 0, `${kind} : écouteur d'abandon retiré`);
    }
    await sleep(1200); // > authDelayMs : l'acceptation différée du serveur est passée
    assert.equal(stats.execs, 0, 'la commande n\'a JAMAIS été lancée côté serveur');
    assert.equal(stats.shells, 0, 'aucun shell ouvert côté serveur');
    assert.equal(stats.closed, 2, 'les deux connexions ont été fermées');
  } finally { srv.close(); }
});

test('ABORT : abandon pendant la décision sur une clé inconnue → ABORTED, rien mémorisé, mot de passe jamais envoyé', async () => {
  const { srv, port, stats } = await startServer();
  try {
    for (const kind of ['exec', 'shell']) {
      const kh = tmpKnownHosts();
      const ac = new AbortController();
      // L'utilisateur accepte la clé APRÈS l'abandon (popup restée ouverte) : la clé ne doit pas être mémorisée.
      const onNewHostKey = async () => { ac.abort(); await sleep(100); return true; };
      const o = base(port, { command: 'id', knownHosts: kh, onNewHostKey, signal: ac.signal });
      await within(3000, assert.rejects(() => (kind === 'exec' ? execWithPassword(o) : createShellSession(o)), (e) => e.code === 'ABORTED'), kind);
      await sleep(300);
      assert.equal(kh.lookup('127.0.0.1', port), null, `${kind} : clé non mémorisée`);
    }
    assert.equal(stats.pwAttempts, 0);
    assert.equal(stats.execs + stats.shells, 0);
  } finally { srv.close(); }
});

test('ABORT : abandon pendant l\'exécution → ABORTED et connexion détruite ; sans abandon, écouteur retiré à la fin', async () => {
  const { srv, port, stats } = await startServer();
  try {
    const ac = new AbortController();
    const p = execWithPassword(base(port, { command: 'hang', trustNewHostKeys: true, execTimeoutMs: 0, signal: ac.signal }));
    p.catch(() => {});
    for (let i = 0; i < 200 && stats.execs === 0; i++) await sleep(10);
    assert.equal(stats.execs, 1, 'commande en cours côté serveur');
    ac.abort();
    await within(2000, assert.rejects(p, (e) => e.code === 'ABORTED'), 'exec');
    for (let i = 0; i < 40 && stats.closed === 0; i++) await sleep(50);
    assert.equal(stats.closed, 1, 'connexion fermée côté serveur');
    // Signal jamais déclenché : résultat normal, écouteur retiré (pas de fuite sur un signal à longue durée de vie)
    const ac2 = new AbortController();
    const r = await execWithPassword(base(port, { command: 'id', trustNewHostKeys: true, signal: ac2.signal }));
    assert.equal(r.code, 0);
    assert.equal(getEventListeners(ac2.signal, 'abort').length, 0);
  } finally { srv.close(); }
});

test('ABORT : shell — le signal ne vise que l\'ouverture ; une session établie survit à un abandon ultérieur', async () => {
  const { srv, port } = await startServer();
  let sess = null, c = null, closes = 0;
  try {
    const ac = new AbortController();
    sess = await createShellSession(base(port, { trustNewHostKeys: true, signal: ac.signal, onClose: () => { closes++; } }));
    assert.equal(getEventListeners(ac.signal, 'abort').length, 0, 'écouteur retiré à l\'établissement');
    ac.abort();
    c = net.connect(sess.sock);
    let buf = '';
    c.on('data', (d) => { buf += d; });
    c.on('error', () => {});
    c.on('connect', () => setTimeout(() => c.write('ping\n'), 150));
    for (let i = 0; i < 50 && !buf.includes('ECHO:ping'); i++) await sleep(100);
    assert.match(buf, /ECHO:ping/, 'session toujours vivante');
    assert.equal(closes, 0);
  } finally {
    if (c) c.destroy();
    if (sess) sess.close();
    srv.close();
  }
});

test('hostKeyFingerprint / normalizeFp exportés et cohérents', () => {
  assert.equal(hostKeyFingerprint(parseKey(HOST_KEY).getPublicSSH()), HOST_FP);
  assert.equal(normalizeFp('sha256:' + HOST_FP.slice(7) + '='), HOST_FP);
});
