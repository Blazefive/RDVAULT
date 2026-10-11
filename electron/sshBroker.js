// ========================================
// BROKER SSH PAR MOT DE PASSE — « utiliser un mot de passe sans le voir »
// ========================================
// Pour l'authentification par MOT DE PASSE (pas de clé), on ne peut pas cacher le
// secret au client SSH (il doit l'envoyer au serveur). Mais on le cache à l'APPELANT
// (Claude Code, un script) : RDVAULT ouvre lui-même la connexion avec `ssh2` en
// utilisant le mot de passe issu du coffre, exécute la commande demandée et ne renvoie
// que la SORTIE. Le mot de passe ne quitte jamais le processus RDVAULT (ni argument,
// ni sortie, ni variable d'environnement de l'appelant).
//
// Vérification de la clé d'hôte (createHostVerifier) : épinglage explicite (hostFingerprint),
// mémoire persistante known_hosts (knownHosts), rappel pour une clé inconnue (onNewHostKey)
// ou opt-in explicite (trustNewHostKeys). Aucune clé n'est acceptée « par défaut ». Le
// verifier s'exécute pendant l'échange de clés, AVANT l'authentification : une clé refusée
// implique que le mot de passe n'est jamais envoyé.
//
// Abandon (option `signal`, AbortSignal) : la connexion est détruite et la promesse rejetée avec
// le code ABORTED ; un abandon survenu avant 'ready' garantit que la commande (ou le shell) n'est
// jamais lancée.
//
// Module PUR (ssh2 + crypto). Testable avec un serveur ssh2 en mémoire (voir le test).

'use strict';

const crypto = require('crypto');
const net = require('net');
const os = require('os');
const path = require('path');
const { Client } = require('ssh2');
const { normalizeFp } = require('./knownHosts');
// Messages des erreurs de clé d'hôte (HOST_KEY_* / KNOWN_HOSTS_*) dans la langue de l'interface : affichés tels
// quels dans un toast (AdminPanel) et en « Détail » par mvault. Les codes (err.code) restent la référence.
const { tm } = require('./mainI18n');

/** Empreinte « SHA256:… » (base64 sans padding) d'une clé d'hôte, format OpenSSH. */
function hostKeyFingerprint(keyBuf) {
  return 'SHA256:' + crypto.createHash('sha256').update(keyBuf).digest('base64').replace(/=+$/, '');
}

/**
 * Fabrique le vérificateur de clé d'hôte ssh2 (forme ASYNCHRONE à 2 paramètres :
 * `(keyBuf, verify) => undefined`, ssh2 attend alors `verify(true|false)`).
 * UN vérificateur PAR CONNEXION : ssh2 le rappelle à chaque échange de clés, re-KEX compris ;
 * une fois une clé acceptée, la même clé est ré-acceptée sans rappel ni écriture (statut et
 * empreinte rapportés restent ceux de la connexion) et une clé différente est refusée.
 * Ordre de décision : hostFingerprint (épinglage) > knownHosts (mémoire) > onNewHostKey > trustNewHostKeys.
 * Mémorisation : jamais d'écrasement d'une AUTRE empreinte déjà mémorisée pour hôte:port — ni par
 * un épinglage, ni par une acceptation (état relu juste avant l'écriture, après onNewHostKey).
 * Codes d'erreur (err.code) : HOST_KEY_MISMATCH (épinglage), HOST_KEY_CHANGED (clé différente de la
 * mémoire, avec err.expected / err.observed), HOST_KEY_CHANGED_REKEY (clé différente présentée lors d'un
 * re-KEX EN COURS de session : connexion interrompue, known_hosts ni relu ni modifié ; err.expected = clé
 * vérifiée à la connexion, err.observed), HOST_KEY_REJECTED (rappel → false), HOST_KEY_UNKNOWN (aucune
 * politique n'autorise la clé), KNOWN_HOSTS_READ (mémoire illisible ou corrompue), KNOWN_HOSTS_WRITE
 * (mémorisation impossible).
 * @param {object} o
 * @param {string} o.host
 * @param {number} [o.port=22]
 * @param {string|null} [o.hostFingerprint]   - empreinte épinglée (doit correspondre)
 * @param {object|null} [o.knownHosts]        - mémoire persistante (createKnownHosts)
 * @param {Function|null} [o.onNewHostKey]    - async ({ host, port, fingerprint }) => boolean
 * @param {boolean} [o.trustNewHostKeys=false] - accepter une clé inconnue sans rappel (opt-in explicite)
 * @returns {{ verifier: Function, fingerprint: string|null, status: 'pinned'|'known'|'new'|null, error: Error|null }}
 */
function createHostVerifier(o) {
  const { host, port = 22, hostFingerprint = null, knownHosts = null, onNewHostKey = null, trustNewHostKeys = false } = o || {};
  let fingerprint = null, status = null, error = null, accepted = null;
  const where = `${host}:${port}`;
  const fail = (code, message, extra) => { error = Object.assign(new Error(message), { code }, extra || {}); return false; };
  // pinned : empreinte épinglée qui contredit la mémoire (message précisant que l'épinglage ne la remplace pas)
  const changed = (expected, observed, pinned = false) => fail('HOST_KEY_CHANGED',
    tm(pinned ? 'sshHostKey.changedPinned' : 'sshHostKey.changed', { where, expected, observed }), { expected, observed });

  // Mémorise l'empreinte SAUF si une AUTRE empreinte est déjà mémorisée pour hôte:port (alors
  // HOST_KEY_CHANGED). Relecture et écriture synchrones : rien ne peut s'intercaler dans ce processus.
  function rememberUnlessChanged(observed, pinned) {
    if (!knownHosts) return true;
    const r = knownHosts.check(host, port, observed);
    if (r.status === 'mismatch') return changed(r.expected, observed, pinned);
    knownHosts.remember(host, port, observed);
    return true;
  }

  async function decide(observed) {
    if (hostFingerprint) {
      const expected = normalizeFp(hostFingerprint);
      if (expected !== observed) {
        return fail('HOST_KEY_MISMATCH', tm('sshHostKey.mismatch', { where, expected, observed }), { expected, observed });
      }
      // L'épinglage ne remplace jamais en silence une clé mémorisée différente (known_hosts partagé).
      if (!rememberUnlessChanged(observed, true)) return false;
      status = 'pinned';
      return true;
    }
    if (knownHosts) {
      const r = knownHosts.check(host, port, observed);
      if (r.status === 'known') { status = 'known'; return true; }
      if (r.status === 'mismatch') return changed(r.expected, observed);
    }
    // Clé inconnue : rappel de l'appelant, sinon opt-in explicite, sinon refus.
    if (typeof onNewHostKey === 'function') {
      let ok = false;
      try { ok = await onNewHostKey({ host, port, fingerprint: observed }); }
      catch (e) { return fail('HOST_KEY_REJECTED', tm('sshHostKey.rejected', { where, reason: (e && e.message) || e }), { observed }); }
      if (ok !== true) return fail('HOST_KEY_REJECTED', tm('sshHostKey.rejectedByUser', { where, observed }), { observed });
      // Compare-and-swap : pendant l'invite, une autre connexion a pu mémoriser une autre clé.
      if (!rememberUnlessChanged(observed)) return false;
      status = 'new';
      return true;
    }
    if (trustNewHostKeys === true) {
      if (!rememberUnlessChanged(observed)) return false;
      status = 'new';
      return true;
    }
    return fail('HOST_KEY_UNKNOWN', tm('sshHostKey.unknown', { where, observed }), { observed });
  }

  const verifier = (keyBuf, verify) => {
    const observed = hostKeyFingerprint(Buffer.isBuffer(keyBuf) ? keyBuf : Buffer.from(keyBuf));
    let decision;
    if (accepted) {
      // Re-KEX : la clé de cette connexion est déjà vérifiée (ni rappel, ni écriture, statut inchangé) ;
      // elle ne doit pas changer en cours de session. Code DISTINCT d'un changement constaté à la
      // connexion : la mémoire n'est pas en cause (ni relue ni modifiée), seule la session est interrompue.
      decision = Promise.resolve(observed === accepted || fail('HOST_KEY_CHANGED_REKEY',
        tm('sshHostKey.changedRekey', { where, expected: accepted, observed }), { expected: accepted, observed }));
    } else {
      fingerprint = observed;
      decision = decide(observed)
        .catch((e) => { // erreur inattendue (lecture ou écriture de known_hosts) → refus explicite
          status = null;
          if (e && e.code === 'KNOWN_HOSTS_READ') {
            fail('KNOWN_HOSTS_READ', tm('sshHostKey.readError', { where, reason: e.message }), { observed, cause: e });
          } else {
            fail('KNOWN_HOSTS_WRITE', tm('sshHostKey.writeError', { where, reason: (e && e.message) || e }), { observed, cause: e });
          }
          return false;
        })
        .then((ok) => { if (ok === true) accepted = observed; return ok; });
    }
    decision.then((ok) => { try { verify(ok === true); } catch { /* connexion déjà fermée */ } });
    // Retour undefined → ssh2 attend l'appel différé de verify().
  };

  return {
    verifier,
    get fingerprint() { return fingerprint; },
    get status() { return status; },
    get error() { return error; },
  };
}

/**
 * Délai en ms : nombre (ou texte numérique) fini >= 0, 0 = illimité, borné à la limite de
 * setTimeout ; toute autre valeur (null, NaN, texte, négatif…) → défaut (jamais d'attente infinie).
 */
function delayMs(v, def) {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) && n >= 0 ? Math.min(n, 2147483647) : def;
}

/** Erreur de délai dépassé avec son code (CONNECT_TIMEOUT / EXEC_TIMEOUT). */
const timeoutError = (message, code) => Object.assign(new Error(message), { code });

/** Erreur d'abandon demandé par l'appelant (signal déclenché) : code ABORTED. */
const abortedError = () => Object.assign(new Error('Connexion SSH abandonnée à la demande de l\'appelant'), { code: 'ABORTED' });

/** Abonne `onAbort` au signal (s'il existe) ; renvoie la fonction de désabonnement (toujours appelable). */
function watchAbort(signal, onAbort) {
  if (!signal || typeof signal.addEventListener !== 'function') return () => {};
  signal.addEventListener('abort', onAbort, { once: true });
  return () => signal.removeEventListener('abort', onAbort);
}

/** Délai (ré)armable ; sans effet si ms <= 0. Le timer ne retient pas le processus (unref). */
function makeTimer(ms, onExpire) {
  let t = null;
  const clear = () => { if (t) { clearTimeout(t); t = null; } };
  const arm = () => { clear(); if (ms > 0) { t = setTimeout(onExpire, ms); if (t.unref) t.unref(); } };
  return { arm, clear };
}

/**
 * Suspend le délai de connexion pendant la décision de l'appelant sur une clé inconnue (invite
 * utilisateur), puis le réarme SEULEMENT si la connexion est encore en cours d'établissement.
 * Une acceptation arrivée APRÈS l'abandon (signal) est ignorée : personne n'attend plus cette
 * connexion, la clé n'est donc pas mémorisée.
 */
function pauseDuring(onNewHostKey, timer, connecting, signal) {
  if (typeof onNewHostKey !== 'function') return null;
  return async (info) => {
    timer.clear();
    let ok;
    try { ok = await onNewHostKey(info); } finally { if (connecting()) timer.arm(); }
    return signal && signal.aborted ? false : ok;
  };
}

/**
 * Exécute une commande sur un hôte distant via SSH en s'authentifiant par mot de passe.
 * @param {object} opts
 * @param {string} opts.host
 * @param {number} [opts.port=22]
 * @param {string} opts.username
 * @param {string} opts.password          - lu du coffre, jamais journalisé
 * @param {string} opts.command           - commande distante
 * @param {string} [opts.hostFingerprint] - « SHA256:… » épinglée ; sinon knownHosts / onNewHostKey / trustNewHostKeys
 * @param {object} [opts.knownHosts]      - mémoire persistante (createKnownHosts)
 * @param {Function} [opts.onNewHostKey]  - async ({ host, port, fingerprint }) => boolean pour une clé inconnue
 * @param {boolean} [opts.trustNewHostKeys=false]
 * @param {number} [opts.timeoutMs=20000]      - délai de CONNEXION (jusqu'à 'ready', suspendu pendant onNewHostKey) → code CONNECT_TIMEOUT
 * @param {number} [opts.execTimeoutMs=600000] - délai d'EXÉCUTION de la commande → code EXEC_TIMEOUT
 *   (délais : 0 = illimité ; valeur non numérique ou négative → défaut ; sur délai, la connexion est détruite)
 * @param {number} [opts.maxOutputBytes=1048576]
 * @param {AbortSignal} [opts.signal]          - abandon (avant ou pendant connexion, authentification ou
 *   exécution) → connexion détruite, rejet code ABORTED ; avant 'ready', la commande n'est jamais lancée
 * @returns {Promise<{ code, signal, stdout, stderr, hostFingerprint, hostKeyStatus }>}
 */
function execWithPassword(opts) {
  const {
    host, port = 22, username, password, command,
    hostFingerprint = null, knownHosts = null, onNewHostKey = null, trustNewHostKeys = false,
    timeoutMs = 20000, execTimeoutMs = 600000, maxOutputBytes = 1024 * 1024, signal = null,
  } = opts || {};

  return new Promise((resolve, reject) => {
    if (!host || !username || !password || !command) {
      reject(new Error('host, username, password et command sont requis'));
      return;
    }
    // Déjà abandonné : aucune connexion n'est ouverte (le mot de passe n'est pas envoyé).
    if (signal && signal.aborted) { reject(abortedError()); return; }
    const conn = new Client();
    let settled = false, ready = false;
    // Deux délais distincts : connexion (annulé sur 'ready') puis exécution de la commande.
    const connTimer = makeTimer(delayMs(timeoutMs, 20000), () => done(reject, timeoutError('Délai de connexion SSH dépassé', 'CONNECT_TIMEOUT'), true));
    const execTimer = makeTimer(delayMs(execTimeoutMs, 600000), () => done(reject, timeoutError('Délai d\'exécution SSH dépassé', 'EXEC_TIMEOUT'), true));
    const unwatch = watchAbort(signal, () => done(reject, abortedError(), true));
    // hard (abandon sur délai ou signal) : destroy() et non end(), qui attendrait indéfiniment le FIN d'un pair muet.
    function done(fn, arg, hard) {
      if (settled) return; settled = true; connTimer.clear(); execTimer.clear(); unwatch();
      try { if (hard) conn.destroy(); else conn.end(); } catch { /* ignore */ }
      fn(arg);
    }
    const hv = createHostVerifier({ host, port, hostFingerprint, knownHosts, trustNewHostKeys, onNewHostKey: pauseDuring(onNewHostKey, connTimer, () => !settled && !ready, signal) });
    connTimer.arm();

    conn.on('ready', () => {
      if (settled) return; // abandon ou délai survenu entre-temps : la commande n'est JAMAIS lancée
      ready = true;
      connTimer.clear();
      execTimer.arm();
      conn.exec(command, (err, stream) => {
        if (err) return done(reject, err);
        let out = Buffer.alloc(0), errb = Buffer.alloc(0);
        const cap = (buf, chunk) => (buf.length >= maxOutputBytes ? buf : Buffer.concat([buf, chunk]).slice(0, maxOutputBytes));
        stream.on('data', (c) => { out = cap(out, c); });
        stream.stderr.on('data', (c) => { errb = cap(errb, c); });
        stream.on('close', (code, exitSignal) => {
          // Re-KEX refusé (clé d'hôte changée en cours de session) : erreur explicite, jamais un résultat tronqué.
          if (hv.error) return done(reject, hv.error, true);
          done(resolve, {
            code: typeof code === 'number' ? code : null,
            signal: exitSignal || null,
            stdout: out.toString('utf8'),
            stderr: errb.toString('utf8'),
            hostFingerprint: hv.fingerprint,
            hostKeyStatus: hv.status,
          });
        });
      });
    });
    // Clé d'hôte refusée : notre erreur (code HOST_KEY_*) remplace l'erreur générique ssh2.
    conn.on('error', (err) => done(reject, hv.error || err));
    conn.on('close', () => done(reject, hv.error || new Error('Connexion SSH fermée prématurément')));

    conn.connect({
      host, port, username, password,
      readyTimeout: 0, // délai de connexion géré ici (suspendu pendant onNewHostKey)
      hostVerifier: hv.verifier,
    });
  });
}

/**
 * Ouvre une session SHELL interactive (PTY) par mot de passe et la relaie sur une socket
 * locale. RDVAULT détient le mot de passe et la connexion ; l'appelant branche son terminal
 * sur la socket (stdin/stdout) sans jamais voir le mot de passe. Une seule session par socket.
 * @param {object} opts  host, port, username, password, hostFingerprint?, knownHosts?, onNewHostKey?,
 *                       trustNewHostKeys?, term?, rows?, cols?, timeoutMs? (défaut 20000 : délai jusqu'à
 *                       l'ouverture EFFECTIVE du shell et de la socket locale, suspendu pendant
 *                       onNewHostKey → code CONNECT_TIMEOUT ; 0 = illimité ; valeur invalide → défaut),
 *                       onClose? (appelé une seule fois à la fin d'une session établie : fermeture
 *                       distante, erreur ou close() local ; reçoit l'erreur HOST_KEY_CHANGED_REKEY si la
 *                       session a été interrompue par un changement de clé d'hôte, l'erreur réseau / SSH
 *                       (ex. ECONNRESET) ou une erreur code SSH_CONNECTION_LOST si la connexion a été
 *                       perdue alors que le canal du shell était encore ouvert, sinon null),
 *                       signal? (AbortSignal : abandon de l'OUVERTURE → connexion détruite, rejet code
 *                       ABORTED, shell jamais ouvert si l'abandon précède 'ready' ; sans effet sur une
 *                       session déjà établie, que l'appelant ferme avec close())
 * @returns {Promise<{ sock: string, hostFingerprint: string|null, hostKeyStatus: string|null, close: () => void, resize: (rows, cols) => void }>}
 */
function createShellSession(opts) {
  const {
    host, port = 22, username, password,
    hostFingerprint = null, knownHosts = null, onNewHostKey = null, trustNewHostKeys = false,
    term = 'xterm-256color', rows = 24, cols = 80, timeoutMs = 20000, onClose = null, signal = null,
  } = opts || {};

  return new Promise((resolve, reject) => {
    if (!host || !username || !password) { reject(new Error('host, username et password sont requis')); return; }
    // Déjà abandonné : aucune connexion n'est ouverte (le mot de passe n'est pas envoyé).
    if (signal && signal.aborted) { reject(abortedError()); return; }

    const conn = new Client();
    let settled = false, closed = false, established = false, server = null, shellStream = null;
    // Délai de connexion : couvre tout le chemin jusqu'à la résolution (shell ouvert, socket locale prête).
    const connTimer = makeTimer(delayMs(timeoutMs, 20000), () => rejectOnce(timeoutError('Délai de connexion SSH dépassé', 'CONNECT_TIMEOUT'), true));
    const unwatch = watchAbort(signal, () => rejectOnce(abortedError(), true));
    const hv = createHostVerifier({ host, port, hostFingerprint, knownHosts, trustNewHostKeys, onNewHostKey: pauseDuring(onNewHostKey, connTimer, () => !settled, signal) });
    connTimer.arm();

    // hard (abandon sur délai ou signal) : destroy() et non end(), qui attendrait indéfiniment le FIN d'un pair muet.
    // err : cause d'une fin anormale d'une session établie (perte de connexion), transmise à onClose.
    function closeAll(hard, err) {
      if (closed) return; closed = true;
      try { if (shellStream) shellStream.end(); } catch { /* ignore */ }
      try { if (hard) conn.destroy(); else conn.end(); } catch { /* ignore */ }
      try { if (server) server.close(); } catch { /* ignore */ }
      // Informe l'appelant UNE SEULE FOIS de la fin d'une session établie (après 'ready', hv.error ne
      // peut venir que d'un re-KEX refusé : HOST_KEY_CHANGED_REKEY ; sinon err = perte de connexion).
      if (established && typeof onClose === 'function') { try { onClose(hv.error || err || null); } catch { /* ignore */ } }
    }
    // Canal du shell encore ouvert côté distant ? (ssh2 passe incoming.state à 'closed' dès réception
    // de CHANNEL_CLOSE, donc AVANT la fermeture TCP d'une fin normale.) Une fin de connexion survenant
    // canal ouvert est une perte de session, pas une fermeture ordinaire.
    const channelOpen = () => !!(shellStream && shellStream.incoming && shellStream.incoming.state !== 'closed');
    function lostError(cause) {
      if (cause) return cause;
      const e = new Error('Connexion SSH perdue pendant la session');
      e.code = 'SSH_CONNECTION_LOST';
      return e;
    }
    // Fin de la phase d'ouverture (résolue ou rejetée) : délai annulé, le signal ne concerne plus la session.
    function settle() { settled = true; connTimer.clear(); unwatch(); }
    function rejectOnce(e, hard) { if (settled) return; settle(); closeAll(hard); reject(e); }

    conn.on('ready', () => {
      if (settled) return; // abandon ou délai survenu entre-temps : le shell n'est JAMAIS demandé
      conn.shell({ term, rows, cols }, (err, stream) => {
        if (err) return rejectOnce(err);
        if (settled) return; // abandon pendant l'ouverture du shell : connexion déjà détruite
        shellStream = stream;
        stream.on('close', () => closeAll());
        stream.on('error', () => {});

        const sock = process.platform === 'win32'
          ? '\\\\.\\pipe\\rdvault-sshsh-' + crypto.randomBytes(8).toString('hex')
          : path.join(os.tmpdir(), 'rdvault-sshsh-' + crypto.randomBytes(8).toString('hex') + '.sock');

        let connected = false;
        server = net.createServer((socket) => {
          if (connected) { socket.destroy(); return; } // une seule session par socket
          connected = true;
          socket.pipe(stream);
          stream.pipe(socket);
          socket.on('close', () => closeAll());
          socket.on('error', () => {});
        });
        server.on('error', (e) => rejectOnce(e));
        server.listen(sock, () => {
          if (settled) return; settle(); established = true;
          const resize = (rows, cols) => {
            const r = parseInt(rows, 10), c = parseInt(cols, 10);
            if (!Number.isInteger(r) || !Number.isInteger(c) || r < 1 || c < 1) return;
            try { if (shellStream && shellStream.setWindow) shellStream.setWindow(r, c, 0, 0); } catch { /* ignore */ }
          };
          resolve({ sock, hostFingerprint: hv.fingerprint, hostKeyStatus: hv.status, close: () => closeAll(), resize });
        });
      });
    });
    // Après établissement : une erreur (TCP reset, déconnexion SSH…) ou une fermeture TCP survenant canal
    // ouvert est transmise à onClose, pour que l'appelant ne la confonde pas avec une fin normale.
    conn.on('error', (e) => { if (!settled) rejectOnce(hv.error || e); else closeAll(false, channelOpen() ? lostError(e) : null); });
    conn.on('close', () => { if (!settled) rejectOnce(hv.error || new Error('Connexion SSH fermée prématurément')); else closeAll(false, channelOpen() ? lostError() : null); });

    conn.connect({
      host, port, username, password,
      readyTimeout: 0, // délai de connexion géré ici (suspendu pendant onNewHostKey)
      hostVerifier: hv.verifier,
    });
  });
}

module.exports = { execWithPassword, createShellSession, hostKeyFingerprint, normalizeFp, createHostVerifier };
