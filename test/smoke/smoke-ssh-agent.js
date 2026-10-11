// Test d'intégration de l'agent SSH via le serveur CLI (electron, userData temporaire).
// Vérifie toute la chaîne : POST /ssh (approbation + audit) -> clé lue du « coffre » ->
// agent éphémère sur une socket -> un client obtient les identités et (si dispo) ssh-add -l
// liste la clé. La clé privée n'est JAMAIS renvoyée par l'endpoint. JAMAIS le vrai coffre.
// Mode mot de passe (serveur ssh2 en mémoire) : clé d'hôte inconnue refusée sans fenêtre (le
// mot de passe n'est jamais envoyé), épinglage, mémoire known_hosts.json, clé changée, délai
// d'exécution, shell ; /secret refuse les clés héritées ; corps JSON multi-octets en morceaux.
// Phase 2 (fenêtre factice, popups simulées) : VRAI cli/mvault.js (sortie multi-octets, codes de
// sortie, messages par code d'erreur), épinglage contredisant la mémoire, mémoire illisible, délai
// de connexion, audit assaini, débit de /ssh/resize, client parti avant la connexion.
// Phase 3 : client parti PENDANT la connexion (commande / shell jamais lancés), empreintes de
// commande HMAC de l'audit (clé par installation, « #? » si illisible), clé d'hôte changée lors
// d'un re-KEX en cours de session (HOST_KEY_CHANGED_REKEY, exec et shell, message de mvault).
// Fin d'un shell interactif (POST /ssh/status) : VRAI mvault — fin normale → 0 sans message, clé changée
// en cours de session → message + code 1, garde-fou de durée → message + code ≠ 0 ; état ouvert/fermé,
// session inconnue ou d'un autre jeton → 404 identique, pas de limitation de débit authentifiée.
// Fin d'un shell sur ERREUR : code toujours en CHAÎNE (/ssh/status, audit, réponses d'erreur de /ssh), y compris
// la raison NUMÉRIQUE d'un SSH_MSG_DISCONNECT distant (ssh2 : err.code = 2), ECONNRESET et SSH_CONNECTION_LOST.
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par Electron (pas un module ES) : mode strict voulu
const { app } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const net = require('net');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-sshagent-'));
app.setPath('userData', tmp); // AVANT de requérir cliServer (calcule ses chemins au chargement)
process.env.RDVAULT_LOG_LEVEL = 'error';

let failures = 0;
const check = (c, l) => { console.log((c ? 'PASS ' : 'FAIL ') + l); if (!c) failures++; };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function req(port, token, urlPath, body, method = 'POST') {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ host: '127.0.0.1', port, path: urlPath, method, headers: {
      ...(token ? { 'Authorization': 'Bearer ' + token } : {}), 'Content-Type': 'application/json',
      ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {})
    } }, (res) => { let b = ''; res.on('data', c => b += c); res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch {} resolve({ status: res.statusCode, json: j }); }); });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

// Requête abandonnée par le client après `abortMs` (comme mvault à l'expiration de son délai HTTP)
function reqAbort(port, token, urlPath, body, abortMs) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const r = http.request({ host: '127.0.0.1', port, path: urlPath, method: 'POST', headers: {
      'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data),
    } }, (res) => { res.resume(); res.on('end', () => resolve('réponse ' + res.statusCode)); });
    r.on('error', () => resolve('abandonnée'));
    r.write(data); r.end();
    setTimeout(() => r.destroy(), abortMs);
  });
}

// VRAI client cli/mvault.js (Electron en mode Node) ; session et known_hosts.json du userData TEMPORAIRE
function runMvault(args, sessionFile, extraEnv = {}, nodeArgs = []) {
  return new Promise((resolve) => {
    const ch = spawn(process.execPath, [...nodeArgs, path.join(ROOT, 'cli', 'mvault.js'), ...args], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', MVAULT_SESSION_FILE: sessionFile, ...extraEnv },
    });
    const so = [], se = [];
    ch.stdout.on('data', d => so.push(d)); ch.stderr.on('data', d => se.push(d));
    ch.on('close', (code) => resolve({ code, stdout: Buffer.concat(so).toString('utf8'), stderr: Buffer.concat(se).toString('utf8') }));
  });
}

// VRAI mvault en SHELL interactif (stdin/stdout en tubes, sans TTY) : `onReady(child)` est appelé dès que
// l'invite « SHELL_READY » du serveur de test est relayée. Processus tué après `killMs` (jamais de blocage).
function runMvaultShell(args, sessionFile, onReady = null, killMs = 12000) {
  return new Promise((resolve) => {
    const ch = spawn(process.execPath, [path.join(ROOT, 'cli', 'mvault.js'), ...args], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', MVAULT_SESSION_FILE: sessionFile },
    });
    const so = [], se = [];
    let ready = false;
    ch.stdin.on('error', () => {});
    ch.stdout.on('data', (d) => {
      so.push(d);
      if (!ready && Buffer.concat(so).toString('utf8').includes('SHELL_READY')) { ready = true; if (onReady) onReady(ch); }
    });
    ch.stderr.on('data', d => se.push(d));
    const killer = setTimeout(() => { try { ch.kill(); } catch {} }, killMs);
    ch.on('close', (code) => { clearTimeout(killer); resolve({ code, ready, stdout: Buffer.concat(so).toString('utf8'), stderr: Buffer.concat(se).toString('utf8') }); });
  });
}

// Envoie un corps BRUT (Buffer) en morceaux de `chunkSize` octets, espacés de quelques ms,
// pour forcer plusieurs événements 'data' côté serveur (coupures au milieu de caractères UTF-8).
function reqChunked(port, token, urlPath, buf, chunkSize) {
  return new Promise((resolve) => {
    const r = http.request({ host: '127.0.0.1', port, path: urlPath, method: 'POST', headers: {
      'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Content-Length': buf.length,
    } }, (res) => { let b = ''; res.on('data', c => b += c); res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch {} resolve({ status: res.statusCode, json: j }); }); });
    r.on('error', (e) => resolve({ status: -1, error: e.code || e.message }));
    (async () => {
      for (let off = 0; off < buf.length; off += chunkSize) {
        if (r.destroyed) break;
        r.write(buf.subarray(off, Math.min(off + chunkSize, buf.length)));
        await sleep(2);
      }
      r.end();
    })();
  });
}

// Client minimal : demande les identités à l'agent sur `sock` et renvoie le nombre de clés
function agentIdentityCount(sock) {
  return new Promise((resolve) => {
    const c = net.connect(sock);
    let buf = Buffer.alloc(0);
    const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
    c.on('connect', () => { const m = Buffer.from([11]); c.write(Buffer.concat([u32(m.length), m])); });
    c.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
        const payload = buf.slice(4, 4 + buf.readUInt32BE(0));
        c.end();
        resolve(payload[0] === 12 ? payload.readUInt32BE(1) : -1); // 12 = IDENTITIES_ANSWER
      }
    });
    c.on('error', () => resolve(-2));
    setTimeout(() => { try { c.destroy(); } catch {} resolve(-3); }, 4000);
  });
}

app.whenReady().then(async () => {
  try {
    const cli = require(path.join(ROOT, 'electron/cliServer.js'));

    // Clé privée « stockée dans le coffre » (RSA pkcs1, lisible par ssh2) + un leurre
    const rsaPem = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    const storedData = { username: 'deploy', privateKey: rsaPem, note: 'clé de prod' };

    // readSecretFn simulé ; auto-approbation sur test/* (pas de popup, pas de fenêtre requise)
    const readSecretFn = async (engine, p) => (engine === 'test' && p === 'serveur')
      ? { success: true, data: storedData }
      : { success: false, error: 'introuvable' };
    const { port, token } = await cli.startCLIServer(null, readSecretFn, null, null, ['test/*']);
    check(typeof port === 'number' && port > 0, 'serveur CLI démarré');

    // 1. /ssh charge la clé dans un agent et renvoie un SSH_AUTH_SOCK — SANS la clé
    let r = await req(port, token, '/ssh', { engine: 'test', path: 'serveur' });
    check(r.status === 200 && r.json?.success && typeof r.json.authSock === 'string', '/ssh renvoie un authSock');
    const bodyStr = JSON.stringify(r.json);
    check(!bodyStr.includes('BEGIN') && !bodyStr.includes('PRIVATE'), '/ssh ne renvoie JAMAIS la clé privée');
    const authSock = r.json.authSock;

    // 2. L'agent sert bien l'identité (1 clé)
    await sleep(200);
    const nIds = await agentIdentityCount(authSock);
    check(nIds === 1, 'agent sert 1 identité sur la socket (n=' + nIds + ')');

    // 3. Bonus : un vrai client (ssh-add natif) liste la clé
    const sshAdd = process.platform === 'win32' ? 'C:\\Windows\\System32\\OpenSSH\\ssh-add.exe' : 'ssh-add';
    if (process.platform !== 'win32' || fs.existsSync(sshAdd)) {
      const out = await new Promise((resolve) => {
        const ch = spawn(sshAdd, ['-l'], { env: { ...process.env, SSH_AUTH_SOCK: authSock } });
        let s = ''; ch.stdout.on('data', d => s += d); ch.stderr.on('data', () => {});
        ch.on('error', () => resolve('__noexec__'));
        ch.on('close', () => resolve(s.trim()));
        setTimeout(() => { try { ch.kill(); } catch {} resolve(s.trim()); }, 8000);
      });
      if (out === '__noexec__') check(true, 'ssh-add non exécutable — étape ignorée');
      else check(/SHA256:|RSA|\(RSA\)|2048/.test(out), 'ssh-add -l (client réel) liste la clé: ' + out.slice(0, 80));
    } else {
      check(true, 'ssh-add natif absent — étape ignorée');
    }

    // 4. Clé inconnue / secret absent -> 404
    r = await req(port, token, '/ssh', { engine: 'test', path: 'inconnu' });
    check(r.status === 404, 'secret introuvable -> 404');

    // 5. Secret sans clé NI mot de passe -> 404
    const readNoCred = async () => ({ success: true, data: { username: 'x', note: 'rien d\'utilisable' } });
    cli.setVaultReadFunction(readNoCred);
    r = await req(port, token, '/ssh', { engine: 'test', path: 'serveur' });
    check(r.status === 404, 'secret sans clé ni mot de passe -> 404');
    cli.setVaultReadFunction(readSecretFn);

    // 6. /ssh/close détruit l'agent de l'étape 1 (la socket ne répond plus)
    // NB : budget de 15 accès auto-approuvés par minute (détection de rafale → popup → 403 sans
    // fenêtre) : chaque /ssh, /secret ou /winrm validé compte ; ne pas en ajouter sans retirer ailleurs.
    await req(port, token, '/ssh/close', { authSock });
    await sleep(200);
    const nAfter = await agentIdentityCount(authSock);
    check(nAfter < 0, 'agent détruit après /ssh/close (socket fermée, n=' + nAfter + ')');

    // 7. Sans token -> 401
    const noTok = await new Promise((resolve) => {
      const r2 = http.request({ host: '127.0.0.1', port, path: '/ssh', method: 'POST', headers: { 'Content-Type': 'application/json' } }, (res) => { res.resume(); resolve(res.statusCode); });
      r2.on('error', () => resolve(-1)); r2.end(JSON.stringify({ engine: 'test', path: 'serveur' }));
    });
    check(noTok === 401, 'sans token -> 401');

    // 8. /secret : seules les propriétés PROPRES du secret sont servies (constructor/toString/__proto__ -> 404)
    r = await req(port, token, '/secret', { engine: 'test', path: 'serveur', key: 'constructor' });
    check(r.status === 404, '/secret key=constructor -> 404 (status=' + r.status + ')');
    r = await req(port, token, '/secret', { engine: 'test', path: 'serveur', key: 'username' });
    check(r.status === 200 && r.json?.value === 'deploy', '/secret key=username -> 200 (propriété propre)');

    // ─── Mode MOT DE PASSE (broker) : serveur ssh2 en mémoire ───
    const { Server, utils: { parseKey } } = require('ssh2');
    const BUSER = 'deploy', BPASS = 'Brok3r!pw';
    const hostKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    // Empreinte réelle de la clé d'hôte, calculée indépendamment du broker (format OpenSSH)
    const HOST_FP = 'SHA256:' + crypto.createHash('sha256').update(parseKey(hostKey).getPublicSSH()).digest('base64').replace(/=+$/, '');
    const OTHER_FP = 'SHA256:' + Buffer.alloc(32, 0x42).toString('base64').replace(/=+$/, '');
    const sshStats = { authCalls: 0, shells: 0, execs: 0 }; // preuve que le mot de passe n'est jamais envoyé à un hôte refusé
    const sshCfg = { authDelayMs: 0, shellSwapKeyMs: 0 }; // phase 3 : authentification lente, re-KEX piégé du shell
    const BIG = '漢'.repeat(200000) + '\n'; // 600 001 octets UTF-8 (< plafond 1 Mo du broker)
    // Seconde vraie clé d'hôte (RSA) présentée lors d'un re-KEX « piégé » en cours de session. ssh2 n'offre pas
    // d'API pour cela : la table interne des clés de CETTE connexion est remplacée par une copie (test uniquement).
    const swapHostKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
    const SWAP_FP = 'SHA256:' + crypto.createHash('sha256').update(parseKey(swapHostKey).getPublicSSH()).digest('base64').replace(/=+$/, '');
    const rekeyWithOtherKey = (c) => {
      const other = parseKey(swapHostKey);
      const swapped = Object.create(null);
      for (const algo of Object.keys(c._protocol._hostKeys)) swapped[algo] = other;
      c._protocol._hostKeys = swapped;
      c.rekey(() => {});
    };
    const sshSrv = await new Promise((resolve) => {
      const s = new Server({ hostKeys: [hostKey] }, (c) => {
        let gone = false;
        c.on('close', () => { gone = true; });
        c.on('authentication', (ctx) => {
          sshStats.authCalls++;
          if (ctx.method === 'none') return ctx.reject(['password']);
          const ok = ctx.method === 'password' && ctx.username === BUSER && ctx.password === BPASS;
          // Client parti pendant une réponse différée : ne plus répondre (connexion déjà fermée)
          const answer = () => { if (gone) return; try { if (ok) ctx.accept(); else ctx.reject(); } catch { /* client parti */ } };
          if (ctx.method === 'password' && sshCfg.authDelayMs) setTimeout(answer, sshCfg.authDelayMs); else answer();
        });
        c.on('ready', () => c.on('session', (accept) => {
          const sess = accept();
          sess.on('exec', (acc, rej, info) => {
            sshStats.execs++;
            const ch = acc();
            if (info.command === 'hang') { ch.write('hanging\n'); return; } // flux jamais fermé (délai d'exécution)
            if (info.command === 'swapkey') { // re-KEX avec une autre clé d'hôte pendant la commande
              ch.write('avant-rekey\n');
              setTimeout(() => rekeyWithOtherKey(c), 100);
              setTimeout(() => { try { ch.exit(0); ch.end(); } catch { /* connexion fermée */ } }, 1500);
              return;
            }
            if (info.command === 'bigout') { ch.write(BIG); ch.exit(0); ch.end(); return; }
            if (info.command === 'killme') { ch.write('tué\n'); ch.exit('KILL'); ch.end(); return; } // exit-signal, pas de statut
            if (info.command === 'nostatus') { ch.end(); return; } // flux fermé sans exit-status
            ch.write('REMOTE_OK:' + info.command + '\n'); ch.exit(0); ch.end();
          });
          sess.on('pty', (acc) => { if (acc) acc(); });
          sess.on('shell', (acc) => {
            sshStats.shells++;
            const ch = acc(); ch.write('SHELL_READY\r\n');
            ch.on('data', (d) => {
              const s = String(d).trim();
              if (s === 'exit') { ch.exit(0); ch.end(); return; } // fin normale du shell distant
              if (s === 'rekey') { rekeyWithOtherKey(c); return; } // re-KEX piégé à la demande du client
              // Coupures canal ouvert (test uniquement, objets internes ssh2) : SSH_MSG_DISCONNECT de raison 2
              // (PROTOCOL_ERROR, code NUMÉRIQUE côté client), fermeture TCP (FIN) ou coupure brutale (RST)
              if (s === 'drop-disconnect') { c._protocol.disconnect(2); setTimeout(() => { try { c._sock.end(); } catch { /* fermé */ } }, 50); return; }
              if (s === 'drop-fin') { c._sock.end(); return; }
              if (s === 'drop-rst') { c._sock.resetAndDestroy(); return; }
              ch.write('ECHO:' + d);
            });
            if (sshCfg.shellSwapKeyMs) setTimeout(() => rekeyWithOtherKey(c), sshCfg.shellSwapKeyMs);
          });
        }));
        c.on('error', () => {});
      });
      s.listen(0, '127.0.0.1', () => resolve(s));
    });
    const sshPort = sshSrv.address().port;
    const KH_FILE = path.join(tmp, 'known_hosts.json'); // userData temporaire, jamais %APPDATA%\RDVAULT
    const khKey = '127.0.0.1:' + sshPort;
    const sshBody = (extra) => ({ engine: 'test', path: 'serveur', host: '127.0.0.1', port: sshPort, ...extra });

    // vaultReadFn renvoie désormais un secret À MOT DE PASSE (pas de clé)
    cli.setVaultReadFunction(async () => ({ success: true, data: { username: BUSER, password: BPASS } }));

    // (1) clé d'hôte inconnue, pas d'empreinte, pas de fenêtre pour la popup -> 403 HOST_KEY_REJECTED,
    //     et le serveur SSH n'a reçu AUCUNE tentative d'authentification (mot de passe jamais envoyé)
    r = await req(port, token, '/ssh', sshBody({ command: 'hostname' }));
    check(r.status === 403 && r.json?.error === 'HOST_KEY_REJECTED' && r.json.observed === HOST_FP, 'clé inconnue sans fenêtre -> 403 HOST_KEY_REJECTED (status=' + r.status + ' error=' + r.json?.error + ')');
    await sleep(200);
    check(sshStats.authCalls === 0, 'clé refusée : le serveur n\'a reçu AUCUNE authentification (authCalls=' + sshStats.authCalls + ')');
    check(!fs.existsSync(KH_FILE), 'clé refusée : rien mémorisé dans known_hosts.json');

    // (2) empreinte épinglée correcte -> 200, hostKeyStatus pinned, known_hosts.json créé avec l'entrée
    r = await req(port, token, '/ssh', sshBody({ command: 'hostname', hostFingerprint: HOST_FP }));
    check(r.status === 200 && r.json?.mode === 'exec' && /REMOTE_OK:hostname/.test(r.json.stdout || ''), 'mode mot de passe : commande exécutée via le broker (sortie relayée)');
    check(r.json?.hostKeyStatus === 'pinned' && r.json.hostFingerprint === HOST_FP, 'épinglage correct -> hostKeyStatus pinned (' + r.json?.hostKeyStatus + ')');
    check(!JSON.stringify(r.json).includes(BPASS), 'mode mot de passe : le mot de passe n\'est JAMAIS renvoyé');
    let kh = null; try { kh = JSON.parse(fs.readFileSync(KH_FILE, 'utf8')); } catch {}
    check(kh?.version === 1 && kh.hosts?.[khKey]?.fingerprint === HOST_FP, 'known_hosts.json créé dans le userData temporaire avec l\'entrée ' + khKey);

    // (2b) empreinte épinglée incorrecte -> 502 HOST_KEY_MISMATCH (expected/observed), pas d'auth
    let authBefore = sshStats.authCalls;
    r = await req(port, token, '/ssh', sshBody({ command: 'hostname', hostFingerprint: OTHER_FP }));
    check(r.status === 502 && r.json?.error === 'HOST_KEY_MISMATCH' && r.json.expected === OTHER_FP && r.json.observed === HOST_FP, 'épinglage incorrect -> 502 HOST_KEY_MISMATCH avec expected/observed');
    await sleep(200);
    check(sshStats.authCalls === authBefore, 'épinglage incorrect : aucune authentification tentée');

    // (3) nouvelle requête SANS empreinte -> la mémoire fait foi : 200 hostKeyStatus known
    //     (commande « VAR=secret cmd » : le secret ne doit pas finir dans audit.log, voir plus bas)
    r = await req(port, token, '/ssh', sshBody({ command: 'PGPASSWORD=hunter2-s3cret uptime' }));
    check(r.status === 200 && r.json?.hostKeyStatus === 'known' && /REMOTE_OK:PGPASSWORD=hunter2-s3cret uptime/.test(r.json.stdout || ''), 'clé mémorisée -> 200 hostKeyStatus known (' + r.json?.hostKeyStatus + ')');

    // (4) empreinte altérée dans known_hosts.json -> 502 HOST_KEY_CHANGED, pas d'auth, fichier non réécrit
    kh.hosts[khKey].fingerprint = OTHER_FP;
    fs.writeFileSync(KH_FILE, JSON.stringify(kh));
    authBefore = sshStats.authCalls;
    r = await req(port, token, '/ssh', sshBody({ command: 'hostname' }));
    check(r.status === 502 && r.json?.error === 'HOST_KEY_CHANGED' && r.json.expected === OTHER_FP && r.json.observed === HOST_FP, 'clé changée -> 502 HOST_KEY_CHANGED avec expected/observed (status=' + r.status + ' error=' + r.json?.error + ')');
    await sleep(200);
    check(sshStats.authCalls === authBefore, 'clé changée : aucune authentification tentée');
    check(JSON.parse(fs.readFileSync(KH_FILE, 'utf8')).hosts[khKey].fingerprint === OTHER_FP, 'clé changée : known_hosts.json non réécrit');
    kh.hosts[khKey].fingerprint = HOST_FP; // restauration pour la suite
    fs.writeFileSync(KH_FILE, JSON.stringify(kh));

    // (4b) délai d'exécution : paramètre invalide -> 400 ; commande qui ne se termine jamais -> 504 EXEC_TIMEOUT
    r = await req(port, token, '/ssh', sshBody({ command: 'hostname', execTimeoutMs: -1 }));
    check(r.status === 400, 'execTimeoutMs invalide -> 400');
    r = await req(port, token, '/ssh', sshBody({ command: 'hang', execTimeoutMs: 500 }));
    check(r.status === 504 && r.json?.error === 'EXEC_TIMEOUT' && r.json.code === 'EXEC_TIMEOUT', 'execTimeoutMs court sur une commande bloquée -> 504 EXEC_TIMEOUT (status=' + r.status + ' error=' + r.json?.error + ')');

    // (5) sans commande -> SHELL interactif proxifié sur une socket locale (clé épinglée)
    r = await req(port, token, '/ssh', sshBody({ hostFingerprint: HOST_FP }));
    check(r.status === 200 && r.json?.mode === 'shell' && typeof r.json.sock === 'string', 'mode mot de passe sans commande -> session shell');
    check(r.json?.hostKeyStatus === 'pinned' && r.json.hostFingerprint === HOST_FP, 'shell : hostKeyStatus pinned');
    check(!JSON.stringify(r.json).includes(BPASS), 'shell : le mot de passe n\'est JAMAIS renvoyé');
    const shellSock = r.json.sock;
    const echoed = await new Promise((resolve) => {
      const nc = net.connect(shellSock); let b = '';
      nc.on('data', (d) => { b += d; if (b.includes('ECHO:ping')) { resolve(b); try { nc.end(); } catch {} } });
      nc.on('connect', () => setTimeout(() => nc.write('ping\n'), 250));
      nc.on('error', () => resolve(''));
      setTimeout(() => resolve(b), 7000);
    });
    check(/SHELL_READY/.test(echoed) && /ECHO:ping/.test(echoed), 'shell : écho bidirectionnel via la socket (saisie relayée)');
    await req(port, token, '/ssh/close', { authSock: shellSock });

    // (7) corps JSON volumineux et multi-octets (é, €, CJK, emoji) envoyé en morceaux coupant des
    //     caractères UTF-8 -> relu sans U+FFFD (la commande revient intacte dans l'écho du serveur)
    const multi = 'echo ' + 'aé€漢😀'.repeat(1300); // 7805 unités UTF-16 (< 8192), ~16,5 Ko en UTF-8
    const bigBuf = Buffer.from(JSON.stringify(sshBody({ command: multi, pad: '漢'.repeat(10000) })), 'utf8'); // ~47 Ko
    r = await reqChunked(port, token, '/ssh', bigBuf, 1001);
    check(r.status === 200 && r.json?.stdout === 'REMOTE_OK:' + multi + '\n', 'corps ' + bigBuf.length + ' octets en morceaux : commande multi-octets relue intacte (status=' + r.status + ')');
    check(!(r.json?.stdout || '').includes('�'), 'corps en morceaux : aucun U+FFFD');
    const hugeBuf = Buffer.from(JSON.stringify(sshBody({ command: 'hostname', pad: '漢'.repeat(25000) })), 'utf8'); // > 64 Ko
    r = await reqChunked(port, token, '/ssh', hugeBuf, 4096);
    check(r.status !== 200, 'corps > 64 Ko refusé (status=' + r.status + ')');

    // Audit : commandes journalisées par exécutable + hash (jamais les arguments), décisions de clé d'hôte
    const audit = fs.readFileSync(path.join(tmp, 'cli', 'audit.log'), 'utf8');
    check(/SSH-EXEC \| [^\n]* \| APPROVED \| cmd:hostname#[0-9a-f]{12}\n/.test(audit), 'audit SSH-EXEC : cmd:<exécutable>#<hash12>');
    check(/cmd:echo#[0-9a-f]{12}/.test(audit) && !audit.includes('aé€漢😀'), 'audit : les arguments de la commande ne sont pas journalisés');
    check(!audit.includes('hunter2') && /cmd:PGPASSWORD=\*\*\*#[0-9a-f]{12}/.test(audit), 'audit : affectation « VAR=valeur » en tête de commande masquée (CLI-19)');
    check(/SSH-HOSTKEY \| 127\.0\.0\.1:\d+ \| DENIED \| rejected/.test(audit), 'audit SSH-HOSTKEY rejected');
    check(/SSH-HOSTKEY \| 127\.0\.0\.1:\d+ \| DENIED \| changed/.test(audit), 'audit SSH-HOSTKEY changed');
    const fpRe = HOST_FP.replace(/[+/]/g, '\\$&'), khRe = khKey.replace(/\./g, '\\.');
    check(new RegExp('SSH-HOSTKEY \\| ' + khRe + ' \\| APPROVED \\| pinned-new:' + fpRe).test(audit), 'audit SSH-HOSTKEY : épinglage qui mémorise une clé inconnue journalisé (pinned-new)');
    check(new RegExp('SSH-HOSTKEY \\| ' + khRe + ' \\| APPROVED \\| pinned:' + fpRe).test(audit), 'audit SSH-HOSTKEY : épinglage d\'une clé déjà mémorisée journalisé (pinned)');

    // ─── WinRM (plumbing) : sous Windows, hôte bidon → échec propre SANS fuite du mdp ───
    if (process.platform === 'win32') {
      const WPASS = 'Winrm-S3cret!pw';
      cli.setVaultReadFunction(async () => ({ success: true, data: { username: 'administrateur', password: WPASS } }));
      r = await req(port, token, '/winrm', { engine: 'test', path: 'serveur', host: 'rdvault-bogus.invalid', command: 'hostname' });
      // Hôte injoignable : Invoke-Command échoue → remonté proprement (code != 0 + stderr), pas de crash
      const winOk = (r.status === 200 && r.json?.mode === 'exec' && r.json.code !== 0 && (r.json.stderr || '').length > 0) || r.status === 502;
      check(winOk, 'WinRM hôte bidon : échec propre (code!=0 + stderr, ou 502), status=' + r.status + ' code=' + r.json?.code);
      check(!JSON.stringify(r.json).includes(WPASS), 'WinRM : le mot de passe n\'est JAMAIS renvoyé');
      r = await req(port, token, '/winrm', { engine: 'test', path: 'serveur', host: 'srv' });
      check(r.status === 400, 'WinRM sans commande -> 400');
    } else {
      check(true, 'WinRM : non-Windows, plumbing ignoré');
    }

    // ═══ Phase 2 : fenêtre factice + popups simulées, AUCUNE règle d'auto-approbation ═══
    // Chaque accès passe par la popup (réponse « Autoriser » simulée) : hors du budget de rafale de la
    // phase 1. Nouveau serveur = nouveau limiteur de débit (30 req/min) : ~27 requêtes comptées ici.
    const { dialog } = require('electron');
    const popupCfg = { accessDelayMs: 0, hostKeyDelayMs: 0, hostKeyAnswer: 0 };
    dialog.showMessageBox = async (win, opts) => {
      // Popup de clé d'hôte reconnue quelle que soit la langue de l'interface (titres traduits, « SSH » dans
      // le seul titre de clé d'hôte) ; popup d'accès à un secret sinon
      const isHostKey = /SSH/.test((opts && opts.title) || '');
      const d = isHostKey ? popupCfg.hostKeyDelayMs : popupCfg.accessDelayMs;
      if (d) await sleep(d);
      return { response: isHostKey ? popupCfg.hostKeyAnswer : 0 };
    };
    const fakeWin = { isDestroyed: () => false, show: () => {}, webContents: { send: () => {} } };
    const readFn2 = async (engine, p) => {
      if (engine !== 'test') return { success: false, error: 'introuvable' };
      if (p === 'cle') return { success: true, data: storedData }; // clé privée -> mode agent
      return { success: true, data: { username: BUSER, password: BPASS } };
    };
    cli.stopCLIServer();
    const s2 = await cli.startCLIServer(fakeWin, readFn2, async () => [{ name: 'test', version: 2, type: 'kv' }], null, []);
    const port2 = s2.port, token2 = s2.token;
    const SESSION_FILE = path.join(tmp, 'cli', 'session.json');
    check(fs.existsSync(SESSION_FILE), 'phase 2 : serveur CLI redémarré (session.json du userData temporaire)');
    const AUDIT_FILE = path.join(tmp, 'cli', 'audit.log');
    const auditLen = () => fs.readFileSync(AUDIT_FILE, 'utf8').length;
    const auditSince = (n) => fs.readFileSync(AUDIT_FILE, 'utf8').slice(n);
    const sshArgs = (p, ...rest) => ['ssh', BUSER + '@127.0.0.1', '-s', 'test/serveur', '-p', String(p), ...rest];
    let m, a0, delta;

    // (CONNECT_TIMEOUT) serveur TCP muet : délai de connexion du broker (20 s) -> lancé en tâche de fond
    const muteSockets = [];
    const mute = net.createServer((s) => { muteSockets.push(s); s.on('error', () => {}); });
    await new Promise((resolve) => mute.listen(0, '127.0.0.1', resolve));
    const mutePort = mute.address().port;
    const pTimeoutReq = req(port2, token2, '/ssh', { engine: 'test', path: 'serveur', host: '127.0.0.1', port: mutePort, command: 'hostname' });
    const pTimeoutCli = runMvault(sshArgs(mutePort, '--', 'hostname'), SESSION_FILE);

    // (CLI-42) sortie volumineuse multi-octets : relue intacte par le VRAI mvault (aucun U+FFFD)
    m = await runMvault(sshArgs(sshPort, '--', 'bigout'), SESSION_FILE);
    const nFffd = (m.stdout.match(/�/g) || []).length;
    check(m.code === 0 && m.stdout === BIG && nFffd === 0, `mvault : sortie de ${Buffer.byteLength(BIG)} octets multi-octets intacte (exit=${m.code}, reçu ${m.stdout.length}/${BIG.length} car., U+FFFD=${nFffd})`);

    // (CLI-34) commande tuée par un signal -> 128 + 9 ; flux fermé sans statut -> 1 (jamais 0)
    m = await runMvault(sshArgs(sshPort, '--', 'killme'), SESSION_FILE);
    check(m.code === 137, 'mvault : commande distante tuée par KILL -> code de sortie 137 (eu ' + m.code + ')');
    m = await runMvault(sshArgs(sshPort, '--', 'nostatus'), SESSION_FILE);
    check(m.code === 1, 'mvault : flux fermé sans statut de sortie -> code 1, pas 0 (eu ' + m.code + ')');

    // (CLI-18) épinglage CONTREDISANT la mémoire : la clé mémorisée n'est jamais remplacée, pas d'auth
    kh.hosts[khKey].fingerprint = OTHER_FP;
    fs.writeFileSync(KH_FILE, JSON.stringify(kh));
    const khPinBefore = fs.readFileSync(KH_FILE, 'utf8');
    authBefore = sshStats.authCalls;
    r = await req(port2, token2, '/ssh', sshBody({ command: 'hostname', hostFingerprint: HOST_FP }));
    check(r.status === 502 && r.json?.error === 'HOST_KEY_CHANGED' && r.json.expected === OTHER_FP && r.json.observed === HOST_FP, 'épinglage contredisant la mémoire -> 502 HOST_KEY_CHANGED (status=' + r.status + ' error=' + r.json?.error + ')');
    m = await runMvault(sshArgs(sshPort, '--hostkey', HOST_FP, '--', 'hostname'), SESSION_FILE);
    check(m.code === 1 && /--hostkey[^\n]*ne remplace pas/.test(m.stderr) && /PAS été envoyé/.test(m.stderr), 'mvault : épinglage contredisant la mémoire -> message explicite (exit=' + m.code + ')');
    await sleep(200);
    check(sshStats.authCalls === authBefore && fs.readFileSync(KH_FILE, 'utf8') === khPinBefore, 'épinglage contredisant la mémoire : aucune authentification, known_hosts.json inchangé');
    kh.hosts[khKey].fingerprint = HOST_FP;
    fs.writeFileSync(KH_FILE, JSON.stringify(kh));

    // (KNOWN_HOSTS_READ) mémoire corrompue -> 500 explicite, pas d'auth, fichier jamais réécrit
    fs.writeFileSync(KH_FILE, '{ corrompu');
    authBefore = sshStats.authCalls;
    r = await req(port2, token2, '/ssh', sshBody({ command: 'hostname' }));
    check(r.status === 500 && r.json?.error === 'KNOWN_HOSTS_READ', 'known_hosts.json corrompu -> 500 KNOWN_HOSTS_READ (status=' + r.status + ' error=' + r.json?.error + ')');
    m = await runMvault(sshArgs(sshPort, '--', 'hostname'), SESSION_FILE);
    check(m.code === 1 && /illisible ou corrompue/.test(m.stderr) && m.stderr.includes('known_hosts.json') && /PAS été envoyé/.test(m.stderr), 'mvault : mémoire des clés d\'hôte illisible -> message explicite (exit=' + m.code + ')');
    await sleep(200);
    check(sshStats.authCalls === authBefore && fs.readFileSync(KH_FILE, 'utf8') === '{ corrompu', 'mémoire illisible : aucune authentification, fichier non réécrit');
    fs.writeFileSync(KH_FILE, JSON.stringify(kh));

    // (CLI-33 a) description de SSH_MSG_DISCONNECT (en clair, choisie par le pair) avec \n et ESC :
    //            ni ligne d'audit forgée, ni séquence de contrôle dans audit.log ou sur le terminal
    const FORGED = 'x\x1b[2J\n2026-01-01T00:00:00.000Z | GET | prod/db | APPROVED | forged';
    const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
    const discSrv = net.createServer((sock) => {
      sock.on('error', () => {});
      sock.write('SSH-2.0-FakeSrv\r\n');
      sock.once('data', () => {
        const desc = Buffer.from(FORGED, 'utf8');
        const payload = Buffer.concat([Buffer.from([1]), u32(2), u32(desc.length), desc, u32(0)]);
        let padLen = 8 - ((payload.length + 5) % 8); if (padLen < 4) padLen += 8;
        sock.write(Buffer.concat([u32(payload.length + padLen + 1), Buffer.from([padLen]), payload, Buffer.alloc(padLen)]));
        setTimeout(() => sock.end(), 50);
      });
    });
    await new Promise((resolve) => discSrv.listen(0, '127.0.0.1', resolve));
    const discPort = discSrv.address().port;
    a0 = auditLen();
    r = await req(port2, token2, '/ssh', { engine: 'test', path: 'serveur', host: '127.0.0.1', port: discPort, command: 'hostname' });
    delta = auditSince(a0);
    check(r.status === 502 && /echec:x\?\[2J\?2026-01-01/.test(delta) && !delta.includes('\n2026-01-01T00:00:00.000Z') && !delta.includes('\x1b'), 'audit : message DISCONNECT distant neutralisé (ni ligne forgée, ni ESC) (status=' + r.status + ')');
    check(r.json?.code === '2', 'erreur /ssh : raison de déconnexion ssh2 numérique (2) renvoyée en chaîne (code=' + JSON.stringify(r.json?.code) + ')');
    m = await runMvault(sshArgs(discPort, '--', 'hostname'), SESSION_FILE);
    check(m.code === 1 && /Erreur/.test(m.stderr) && !m.stderr.includes('\x1b') && !m.stderr.includes('\n2026-01-01T00'), 'mvault : message d\'erreur distant affiché sans caractères de contrôle');

    // (CLI-33 b) séquences ANSI / BEL dans le premier mot de la commande -> neutralisées dans l'audit
    a0 = auditLen();
    r = await req(port2, token2, '/ssh', sshBody({ command: '\x1b]0;pwned\x07hostname && uptime' }));
    delta = auditSince(a0);
    // eslint-disable-next-line no-control-regex -- volontaire : aucun caractère de contrôle (hors \n) ne doit subsister dans l'audit
    check(r.status === 200 && /cmd:\?\]0;pwned\?hostname#[0-9a-f]{12}/.test(delta) && !/[\x00-\x09\x0b-\x1f\x7f]/.test(delta), 'audit : séquences de contrôle de la commande neutralisées');

    // (CLI-43) rafale de /ssh/resize authentifiés : ne consomme pas le limiteur de débit des autres appels
    let n429 = 0;
    for (let i = 0; i < 40; i++) { const x = await req(port2, token2, '/ssh/resize', { authSock: 'inconnu', rows: 24, cols: 80 }); if (x.status === 429) n429++; }
    const closeR = await req(port2, token2, '/ssh/close', { authSock: 'inconnu' });
    const engR = await req(port2, token2, '/engines', null, 'GET');
    check(n429 === 0 && closeR.status === 200 && engR.status === 200, `40 /ssh/resize authentifiés : ni 429, ni blocage de /ssh/close et /engines (429=${n429}, close=${closeR.status}, engines=${engR.status})`);

    // (CLI-44) client parti pendant la popup d'accès : ni connexion, ni mot de passe envoyé, ni shell orphelin
    authBefore = sshStats.authCalls;
    const shellsBefore = sshStats.shells;
    popupCfg.accessDelayMs = 800;
    a0 = auditLen();
    const ab1 = await reqAbort(port2, token2, '/ssh', sshBody({}), 300);
    await sleep(1500);
    popupCfg.accessDelayMs = 0;
    delta = auditSince(a0);
    check(ab1 === 'abandonnée' && sshStats.authCalls === authBefore && sshStats.shells === shellsBefore && /\| client-parti/.test(delta) && !/shell-ouvert/.test(delta), `client parti pendant la popup d'accès : aucune connexion (auth=${sshStats.authCalls - authBefore}, shells=${sshStats.shells - shellsBefore})`);
    //          ... puis pendant la popup de clé d'hôte (acceptée trop tard) : refus, rien mémorisé, pas d'auth
    const khSaved = fs.readFileSync(KH_FILE, 'utf8');
    fs.unlinkSync(KH_FILE);
    popupCfg.hostKeyDelayMs = 800;
    a0 = auditLen();
    const ab2 = await reqAbort(port2, token2, '/ssh', sshBody({}), 300);
    await sleep(1500);
    popupCfg.hostKeyDelayMs = 0;
    delta = auditSince(a0);
    check(ab2 === 'abandonnée' && sshStats.authCalls === authBefore && sshStats.shells === shellsBefore && /SSH-HOSTKEY \| [^\n]* \| DENIED \| client-parti/.test(delta) && !fs.existsSync(KH_FILE), `client parti pendant la popup de clé d'hôte : refus, rien mémorisé (auth=${sshStats.authCalls - authBefore}, shells=${sshStats.shells - shellsBefore})`);
    fs.writeFileSync(KH_FILE, khSaved);

    // (CLI-20 + CLI-45) mode clé (agent) : --hostkey / --exec-timeout signalés comme non appliqués ; Ctrl+C
    // pendant ssh -> /ssh/close envoyé AVANT de quitter (agent détruit). Un « ssh » factice qui lit stdin
    // (findstr / grep) dure jusqu'au signal. Préchargement (instrumentation de test) : note SSH_AUTH_SOCK
    // passé à ssh et, 1,5 s après le lancement, émule le Ctrl+C selon la sémantique de Node (sans
    // écouteur 'SIGINT' : sortie immédiate, code 130 ; sinon les écouteurs sont appelés).
    const PRELOAD = path.join(tmp, 'sigint-preload.js');
    fs.writeFileSync(PRELOAD, [
      "const cp = require('child_process'); const orig = cp.spawn;",
      "cp.spawn = function (cmd, args, opts) { process.stderr.write('AUTH_SOCK=' + ((opts && opts.env && opts.env.SSH_AUTH_SOCK) || '') + '\\n'); return orig.apply(this, arguments); };",
      "setTimeout(() => { if (process.listenerCount('SIGINT') === 0) process.exit(130); process.emit('SIGINT', 'SIGINT'); }, 1500).unref();",
    ].join('\n'));
    const fakeSsh = process.platform === 'win32' ? 'C:\\Windows\\System32\\findstr.exe' : 'grep';
    m = await runMvault(['ssh', BUSER + '@127.0.0.1', '-s', 'test/cle', '--hostkey', HOST_FP, '--exec-timeout', '5'], SESSION_FILE, { MVAULT_SSH_BIN: fakeSsh }, ['-r', PRELOAD]);
    check(/--hostkey[^\n]*n'est pas appliqué/.test(m.stderr) && /--exec-timeout[^\n]*n'est pas appliqué/.test(m.stderr), 'mvault mode clé (agent) : --hostkey / --exec-timeout signalés comme non appliqués');
    const sigSock = (m.stderr.match(/AUTH_SOCK=(\S+)/) || [])[1];
    await sleep(300);
    const nSig = sigSock ? await agentIdentityCount(sigSock) : 0;
    check(m.code === 130 && sigSock && nSig < 0, `mvault mode clé : Ctrl+C -> /ssh/close avant de quitter, agent détruit (exit=${m.code}, n=${nSig})`);

    // (CONNECT_TIMEOUT) résultat des requêtes lancées en tâche de fond
    const [tReq, tCli] = await Promise.all([pTimeoutReq, pTimeoutCli]);
    check(tReq.status === 504 && tReq.json?.error === 'CONNECT_TIMEOUT', 'serveur SSH muet -> 504 CONNECT_TIMEOUT (status=' + tReq.status + ' error=' + tReq.json?.error + ')');
    check(tCli.code === 1 && /délai de connexion SSH dépassé pour 127\.0\.0\.1:\d+/.test(tCli.stderr) && /injoignable/.test(tCli.stderr), 'mvault : délai de connexion -> message explicite (exit=' + tCli.code + ')');

    // Le limiteur de débit reste actif pour /ssh/resize NON authentifié (protection du token) — en dernier
    let unauth429 = 0;
    for (let i = 0; i < 35; i++) { const x = await req(port2, null, '/ssh/resize', { authSock: 'x' }); if (x.status === 429) unauth429++; }
    check(unauth429 > 0, '/ssh/resize sans token : toujours soumis au limiteur de débit (429=' + unauth429 + ')');

    // (MAIN-10) serveur neuf : une rafale de GET /health NON authentifiés (processus local sans jeton) épuise
    // son propre compteur, jamais celui des commandes authentifiées de l'utilisateur
    cli.stopCLIServer();
    const s10 = await cli.startCLIServer(fakeWin, readFn2, async () => [{ name: 'test', version: 2, type: 'kv' }], null, []);
    let health429 = 0;
    for (let i = 0; i < 35; i++) { const x = await req(s10.port, null, '/health', null, 'GET'); if (x.status === 429) health429++; }
    const eng10 = await req(s10.port, s10.token, '/engines', null, 'GET');
    check(health429 > 0 && eng10.status === 200, `35 GET /health non authentifiés : limités entre eux (429=${health429}) sans bloquer /engines authentifié (${eng10.status})`);

    // ═══ Phase 3 : nouveau serveur CLI (nouveau limiteur de débit), popups simulées, aucune auto-approbation ═══
    cli.stopCLIServer();
    const s3 = await cli.startCLIServer(fakeWin, readFn2, async () => [{ name: 'test', version: 2, type: 'kv' }], null, []);
    const port3 = s3.port, token3 = s3.token;
    kh.hosts[khKey].fingerprint = HOST_FP; // clé d'hôte mémorisée : connexion sans popup
    fs.writeFileSync(KH_FILE, JSON.stringify(kh));

    // (ABORT) client parti PENDANT la connexion (authentification retardée par le serveur) : la connexion SSH
    //         est abandonnée, la commande / le shell ne sont JAMAIS lancés côté serveur
    sshCfg.authDelayMs = 800;
    const execs0 = sshStats.execs, shells0 = sshStats.shells;
    a0 = auditLen();
    const ab3 = await reqAbort(port3, token3, '/ssh', sshBody({ command: 'hostname' }), 300);
    const ab4 = await reqAbort(port3, token3, '/ssh', sshBody({}), 300);
    await sleep(1500); // > authDelayMs : sans abandon, la commande et le shell auraient été lancés
    sshCfg.authDelayMs = 0;
    delta = auditSince(a0);
    check(ab3 === 'abandonnée' && sshStats.execs === execs0 && /SSH-EXEC \| [^\n]* \| DENIED \| client-parti/.test(delta) && !/SSH-EXEC \| [^\n]* \| APPROVED/.test(delta), `client parti pendant la connexion : commande JAMAIS lancée (execs=${sshStats.execs - execs0})`);
    check(ab4 === 'abandonnée' && sshStats.shells === shells0 && /SSH-SHELL \| [^\n]* \| DENIED \| client-parti/.test(delta) && !/shell-ouvert/.test(delta), `client parti pendant la connexion : shell JAMAIS ouvert (shells=${sshStats.shells - shells0})`);

    // (HMAC) empreinte de commande = HMAC-SHA256 tronqué, clé de 32 octets propre à l'installation (cli/audit-key)
    const AUDIT_KEY_FILE = path.join(tmp, 'cli', 'audit-key');
    const sha12 = crypto.createHash('sha256').update('hostname').digest('hex').slice(0, 12); // ancienne empreinte non salée
    a0 = auditLen();
    r = await req(port3, token3, '/ssh', sshBody({ command: 'hostname' }));
    const rBis = await req(port3, token3, '/ssh', sshBody({ command: 'hostname' }));
    delta = auditSince(a0);
    const refs = [...delta.matchAll(/SSH-EXEC \| [^\n]* \| APPROVED \| cmd:hostname#([^\n]*)\n/g)].map((x) => x[1]);
    check(r.status === 200 && rBis.status === 200 && refs.length === 2 && /^[0-9a-f]{12}$/.test(refs[0]) && refs[0] === refs[1], 'audit : deux commandes identiques -> même empreinte (' + refs.join(', ') + ')');
    let auditKey = null; try { auditKey = fs.readFileSync(AUDIT_KEY_FILE); } catch {}
    check(!!auditKey && auditKey.length === 32, 'audit : clé HMAC de 32 octets créée dans cli/audit-key (' + (auditKey ? auditKey.length : 'absente') + ')');
    const hmac12 = auditKey ? crypto.createHmac('sha256', auditKey).update('hostname').digest('hex').slice(0, 12) : null;
    check(refs[0] === hmac12 && refs[0] !== sha12, 'audit : empreinte = HMAC-SHA256(clé, commande) tronqué, différente du SHA-256 brut');
    const auditAll = fs.readFileSync(AUDIT_FILE, 'utf8');
    const allRefs = [...auditAll.matchAll(/cmd:hostname#([0-9a-f]{12})/g)].map((x) => x[1]);
    check(allRefs.length >= 3 && allRefs.every((x) => x === hmac12), 'audit : empreinte stable pour l\'installation (phase 1 et phase 3, redémarrage du serveur CLI) (n=' + allRefs.length + ')');
    check(!auditAll.includes(sha12) && !!auditKey && !auditAll.includes(auditKey.toString('hex')) && !auditAll.includes(auditKey.toString('base64')), 'audit : ni SHA-256 non salé, ni clé HMAC dans audit.log');
    if (process.platform !== 'win32') check((fs.statSync(AUDIT_KEY_FILE).mode & 0o777) === 0o600, 'audit : cli/audit-key en mode 0600');
    //        clé illisible (remplacée par un dossier) -> « #? », jamais de hash non salé, fichier non écrasé
    const hadKey = fs.existsSync(AUDIT_KEY_FILE);
    if (hadKey) fs.renameSync(AUDIT_KEY_FILE, AUDIT_KEY_FILE + '.bak');
    fs.mkdirSync(AUDIT_KEY_FILE);
    a0 = auditLen();
    r = await req(port3, token3, '/ssh', sshBody({ command: 'hostname' }));
    delta = auditSince(a0);
    const keyIsDir = fs.statSync(AUDIT_KEY_FILE).isDirectory();
    fs.rmdirSync(AUDIT_KEY_FILE);
    if (hadKey) fs.renameSync(AUDIT_KEY_FILE + '.bak', AUDIT_KEY_FILE);
    check(r.status === 200 && /SSH-EXEC \| [^\n]* \| APPROVED \| cmd:hostname#\?\n/.test(delta) && !delta.includes(sha12) && keyIsDir, 'audit : clé illisible -> « cmd:hostname#? » (jamais de hash non salé)');

    // (REKEY) clé d'hôte changée lors d'un re-KEX EN COURS de session : code distinct, known_hosts.json intact
    const khBefore3 = fs.readFileSync(KH_FILE, 'utf8');
    a0 = auditLen();
    r = await req(port3, token3, '/ssh', sshBody({ command: 'swapkey' }));
    delta = auditSince(a0);
    check(r.status === 502 && r.json?.error === 'HOST_KEY_CHANGED_REKEY' && r.json.expected === HOST_FP && r.json.observed === SWAP_FP, 'clé changée en cours de session -> 502 HOST_KEY_CHANGED_REKEY avec expected/observed (status=' + r.status + ' error=' + r.json?.error + ')');
    check(/SSH-HOSTKEY \| 127\.0\.0\.1:\d+ \| DENIED \| changed-rekey/.test(delta) && fs.readFileSync(KH_FILE, 'utf8') === khBefore3, 'clé changée en cours de session : audit « changed-rekey », known_hosts.json non modifié');
    m = await runMvault(sshArgs(sshPort, '--', 'swapkey'), SESSION_FILE);
    check(m.code === 1 && m.stderr.includes('la clé d\'hôte a changé EN COURS de session : connexion interrompue ; known_hosts n\'a pas été modifié')
      && !/supprime/i.test(m.stderr) && !m.stderr.includes(KH_FILE) && !m.stdout.includes('avant-rekey'),
    'mvault : clé changée en cours de session -> message spécifique, sans inviter à supprimer l\'entrée (exit=' + m.code + ')');
    //        shell : session interrompue par le re-KEX piégé -> audit « changed-rekey »
    sshCfg.shellSwapKeyMs = 300;
    a0 = auditLen();
    r = await req(port3, token3, '/ssh', sshBody({}));
    let shellClosed = false;
    if (r.status === 200 && r.json?.sock) {
      shellClosed = await new Promise((resolve) => {
        const nc = net.connect(r.json.sock);
        nc.on('data', () => {}); nc.on('error', () => {});
        nc.on('close', () => resolve(true));
        setTimeout(() => { try { nc.destroy(); } catch {} resolve(false); }, 5000);
      });
    }
    sshCfg.shellSwapKeyMs = 0;
    await sleep(200);
    delta = auditSince(a0);
    check(r.status === 200 && shellClosed && /SSH-HOSTKEY \| 127\.0\.0\.1:\d+ \| DENIED \| changed-rekey/.test(delta) && fs.readFileSync(KH_FILE, 'utf8') === khBefore3, 'shell : clé changée en cours de session -> session fermée, audit « changed-rekey », known_hosts.json intact');

    // (SHELL-FIN) shell interactif via le VRAI mvault : à la fermeture de sa socket, mvault demande la raison
    //             de la fin à RDVAULT (POST /ssh/status) ; seule une coupure côté RDVAULT donne un message et un code ≠ 0
    const otherLines = (s) => s.split('\n').filter((l) => l.trim() && !l.startsWith('Clé d\'hôte ')); // hors rappel de la clé vérifiée
    //   fin normale (le shell distant se termine) -> code 0, aucun message
    a0 = auditLen();
    m = await runMvaultShell(sshArgs(sshPort), SESSION_FILE, (ch) => ch.stdin.write('exit\n'));
    delta = auditSince(a0);
    check(m.ready && m.code === 0 && otherLines(m.stderr).length === 0, `mvault shell : fin normale du shell distant -> code 0 sans message (exit=${m.code}, ready=${m.ready}, stderr=${JSON.stringify(otherLines(m.stderr))})`);
    check(/SSH-SHELL \| [^\n]* \| APPROVED \| shell-ferme:closed\n/.test(delta), 'audit : fin normale du shell journalisée (shell-ferme:closed)');
    //   clé d'hôte changée lors d'un re-KEX en cours de session -> avertissement dédié + code 1
    a0 = auditLen();
    m = await runMvaultShell(sshArgs(sshPort), SESSION_FILE, (ch) => ch.stdin.write('rekey\n'));
    delta = auditSince(a0);
    check(m.ready && m.code === 1 && m.stderr.includes('la clé d\'hôte a changé EN COURS de session : connexion interrompue ; known_hosts n\'a pas été modifié')
      && m.stderr.includes(HOST_FP) && m.stderr.includes(SWAP_FP) && /session shell a été coupée/.test(m.stderr) && !/supprime/i.test(m.stderr) && !m.stderr.includes(KH_FILE),
    `mvault shell : clé changée en cours de session -> message spécifique + code 1 (exit=${m.code}, stderr=${JSON.stringify(otherLines(m.stderr).slice(0, 2))})`);
    check(/SSH-SHELL \| [^\n]* \| APPROVED \| shell-ferme:host-key-changed-rekey/.test(delta) && fs.readFileSync(KH_FILE, 'utf8') === khBefore3, 'audit : fin du shell par re-KEX journalisée, known_hosts.json intact');
    //   garde-fou de durée (4 h, réduit ici à 1,5 s) -> message + code ≠ 0
    const cfg = cli.CLI_CONFIG;
    check(!!cfg && cfg.SSH_SHELL_MAX_MS === 4 * 60 * 60 * 1000, 'garde-fou des shells : 4 h par défaut (CLI_CONFIG.SSH_SHELL_MAX_MS=' + (cfg && cfg.SSH_SHELL_MAX_MS) + ')');
    if (cfg) cfg.SSH_SHELL_MAX_MS = 1500;
    a0 = auditLen();
    m = await runMvaultShell(sshArgs(sshPort), SESSION_FILE);
    delta = auditSince(a0);
    if (cfg) cfg.SSH_SHELL_MAX_MS = 4 * 60 * 60 * 1000;
    check(m.ready && m.code !== 0 && m.code !== null && /durée maximale d'une session shell atteinte \(1,5 s\)/.test(m.stderr), `mvault shell : garde-fou de durée -> message + code ≠ 0 (exit=${m.code}, stderr=${JSON.stringify(otherLines(m.stderr))})`);
    check(/SSH-SHELL \| [^\n]* \| APPROVED \| shell-ferme:max-duration/.test(delta), 'audit : fin du shell par le garde-fou journalisée (shell-ferme:max-duration)');

    // (STATUS) POST /ssh/status : ouverte, fermée (raison conservée), inconnue / invalide / autre jeton -> 404 identique
    r = await req(port3, token3, '/ssh', sshBody({}));
    const stSock = r.json?.sock;
    let st = await req(port3, token3, '/ssh/status', { sock: stSock });
    check(r.status === 200 && st.status === 200 && st.json?.open === true && st.json.closedReason === null && st.json.code === null, '/ssh/status : session ouverte -> open:true (status=' + st.status + ')');
    await req(port3, token3, '/ssh/close', { authSock: stSock });
    st = await req(port3, token3, '/ssh/status', { sock: stSock });
    check(st.status === 200 && st.json?.open === false && st.json.closedReason === 'closed-by-request' && st.json.code === 'CLOSED_BY_REQUEST', '/ssh/status : session fermée par /ssh/close -> raison conservée (' + st.json?.closedReason + ')');
    const stUnknown = await req(port3, token3, '/ssh/status', { sock: '\\\\.\\pipe\\rdvault-sshsh-0000000000000000' });
    const stBad = await req(port3, token3, '/ssh/status', { sock: 42 });
    check(stUnknown.status === 404 && stBad.status === 404 && JSON.stringify(stUnknown.json) === JSON.stringify(stBad.json) && !/sshsh|pipe/.test(JSON.stringify(stUnknown.json)), '/ssh/status : session inconnue ou sock invalide -> 404 neutre (' + JSON.stringify(stUnknown.json) + ')');
    st = await req(port3, null, '/ssh/status', { sock: stSock });
    check(st.status === 401, '/ssh/status sans jeton -> 401');
    let st429 = 0;
    for (let i = 0; i < 35; i++) { const x = await req(port3, token3, '/ssh/status', { sock: stSock }); if (x.status === 429) st429++; }
    check(st429 === 0, '35 /ssh/status authentifiés : jamais limités en débit (429=' + st429 + ')');
    //        serveur CLI redémarré (nouveau jeton) : la session de l'ancien jeton est inconnue
    cli.stopCLIServer();
    const s4 = await cli.startCLIServer(fakeWin, readFn2, async () => [{ name: 'test', version: 2, type: 'kv' }], null, []);
    st = await req(s4.port, s4.token, '/ssh/status', { sock: stSock });
    check(st.status === 404 && JSON.stringify(st.json) === JSON.stringify(stUnknown.json), '/ssh/status : session d\'un autre jeton (serveur redémarré) -> 404 identique à une session inconnue');
    //        nouveau jeton SANS arrêt du serveur (session toujours ouverte) : 404 aussi (session rattachée à son jeton).
    //        L'ancien serveur HTTP reste à l'écoute jusqu'à la fin du test (aucune référence pour le fermer).
    r = await req(s4.port, s4.token, '/ssh', sshBody({}));
    const s5 = await cli.startCLIServer(fakeWin, readFn2, async () => [{ name: 'test', version: 2, type: 'kv' }], null, []);
    st = await req(s5.port, s5.token, '/ssh/status', { sock: r.json?.sock });
    const stOwn = await req(s4.port, s4.token, '/ssh/status', { sock: r.json?.sock });
    check(r.status === 200 && st.status === 404 && JSON.stringify(st.json) === JSON.stringify(stUnknown.json) && stOwn.status === 401, '/ssh/status : session ouverte avec un autre jeton -> 404 identique (ancien jeton -> 401)');
    //        serveur CLI arrêté pendant le shell (déconnexion, fermeture de RDVAULT) : raison injoignable -> message + code 1
    m = await runMvaultShell(sshArgs(sshPort), SESSION_FILE, () => cli.stopCLIServer());
    check(m.ready && m.code === 1 && /RDVAULT ne répond plus/.test(m.stderr), `mvault shell : RDVAULT arrêté pendant la session -> message + code 1 (exit=${m.code}, stderr=${JSON.stringify(otherLines(m.stderr))})`);

    // (CODE) fin d'un shell sur ERREUR, canal encore ouvert : le code est TOUJOURS une chaîne pour /ssh/status et
    //        l'audit — raison NUMÉRIQUE d'un SSH_MSG_DISCONNECT distant (ssh2 : err.code = 2), coupure TCP brutale
    //        (ECONNRESET), fermeture TCP sans DISCONNECT (SSH_CONNECTION_LOST). Nouveau serveur CLI (débit neuf).
    const s6 = await cli.startCLIServer(fakeWin, readFn2, async () => [{ name: 'test', version: 2, type: 'kv' }], null, []);
    const shellDrop = async (cmd) => {
      const a = auditLen();
      const o = await req(s6.port, s6.token, '/ssh', sshBody({}));
      let closed = false;
      if (o.status === 200 && o.json?.sock) {
        closed = await new Promise((resolve) => {
          const nc = net.connect(o.json.sock); let b = ''; let sent = false;
          nc.on('data', (d) => { b += d; if (!sent && b.includes('SHELL_READY')) { sent = true; nc.write(cmd + '\n'); } });
          nc.on('error', () => {});
          nc.on('close', () => resolve(true));
          setTimeout(() => { try { nc.destroy(); } catch {} resolve(false); }, 5000);
        });
      }
      let stat = null; // fermeture enregistrée de façon asynchrone : quelques relances tant que open:true
      for (let i = 0; i < 20; i++) {
        stat = await req(s6.port, s6.token, '/ssh/status', { sock: o.json?.sock });
        if (stat.status !== 200 || stat.json?.open !== true) break;
        await sleep(100);
      }
      return { status: o.status, closed, st: stat, delta: auditSince(a) };
    };
    const DROPS = [
      ['drop-disconnect', '2', 'SSH_MSG_DISCONNECT distant (raison numérique 2)'],
      ['drop-rst', 'ECONNRESET', 'coupure TCP brutale (RST)'],
      ['drop-fin', 'SSH_CONNECTION_LOST', 'fermeture TCP canal ouvert (FIN)'],
    ];
    for (const [cmd, want, what] of DROPS) {
      const d = await shellDrop(cmd);
      const code = d.st?.json?.code;
      check(d.status === 200 && d.closed && d.st?.status === 200 && d.st.json.open === false && d.st.json.closedReason === 'error' && typeof code === 'string' && code === want,
        `/ssh/status : ${what} -> code chaîne « ${want} » (eu ${JSON.stringify(code)}, closedReason=${d.st?.json?.closedReason})`);
      check(new RegExp('SSH-SHELL \\| [^\\n]* \\| APPROVED \\| shell-ferme:error:' + want + '\\n').test(d.delta), `audit : ${what} journalisé « shell-ferme:error:${want} »`);
    }
    //        VRAI mvault : raison numérique affichée en clair, code de sortie 1 (coupure, pas une fin normale)
    m = await runMvaultShell(sshArgs(sshPort), SESSION_FILE, (ch) => ch.stdin.write('drop-disconnect\n'));
    check(m.ready && m.code === 1 && /interrompue par RDVAULT \(2\)/.test(m.stderr), `mvault shell : DISCONNECT distant (raison 2) -> message + code 1 (exit=${m.code}, stderr=${JSON.stringify(otherLines(m.stderr))})`);
    cli.stopCLIServer();

    for (const s of muteSockets) { try { s.destroy(); } catch {} }
    try { mute.close(); } catch {}
    try { discSrv.close(); } catch {}
    try { sshSrv.close(); } catch {}
    cli.stopCLIServer();
  } catch (err) {
    console.log('FAIL exception: ' + ((err && err.stack) || err));
    failures++;
  }
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  console.log(failures === 0 ? 'SSH-AGENT OK' : `SSH-AGENT FAILURES: ${failures}`);
  app.exit(failures === 0 ? 0 : 1);
});
