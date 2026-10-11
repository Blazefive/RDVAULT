// ========================================
// AGENT SSH — « utiliser une clé sans la voir »
// ========================================
// Implémente le protocole ssh-agent (OpenSSH PROTOCOL.agent) sur une socket locale
// (named pipe Windows « \\.\pipe\… » ou socket Unix). RDVAULT charge une clé privée
// issue du coffre DANS l'agent et SIGNE les défis à la demande ; la clé privée ne
// quitte JAMAIS le processus. Un client `ssh` lancé avec SSH_AUTH_SOCK pointant vers
// cet agent s'authentifie sans jamais recevoir la clé (ni dans ses arguments, ni dans
// sa sortie) — c'est le modèle utilisé par Pageant, 1Password, les clés matérielles.
//
// Module PUR (ne dépend pas d'Electron) : `net` + `ssh2` uniquement, donc testable
// hors application (voir sshAgent.test.js, signatures vérifiées cryptographiquement).

'use strict';

const net = require('net');
const { utils: { parseKey } } = require('ssh2');

// Codes de messages (OpenSSH PROTOCOL.agent)
const MSG = {
  FAILURE: 5,
  SUCCESS: 6,
  REQUEST_IDENTITIES: 11,
  IDENTITIES_ANSWER: 12,
  SIGN_REQUEST: 13,
  SIGN_RESPONSE: 14,
  REMOVE_ALL_IDENTITIES: 19,
};
// Drapeaux de SIGN_REQUEST (sélection de l'algorithme pour les clés RSA)
const FLAG_RSA_SHA2_256 = 2;
const FLAG_RSA_SHA2_512 = 4;

/** Encode une « string » SSH : uint32(longueur) || octets */
function sshString(value) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

/** Lit une « string » SSH à l'offset donné, renvoie { data, next } */
function readSshString(buf, offset) {
  if (offset + 4 > buf.length) throw new Error('troncature');
  const n = buf.readUInt32BE(offset);
  const start = offset + 4;
  if (start + n > buf.length) throw new Error('troncature');
  return { data: buf.slice(start, start + n), next: start + n };
}

function createAgent() {
  const keys = []; // { parsedKey, pub: Buffer, comment: string }

  /** Charge une clé privée (PEM/OpenSSH) ; renvoie le blob public SSH. Lève si illisible. */
  function addKey(privatePem, comment = 'rdvault') {
    const parsedKey = parseKey(privatePem);
    if (parsedKey instanceof Error) throw new Error('Clé SSH illisible: ' + parsedKey.message);
    if (typeof parsedKey.getPublicSSH !== 'function') throw new Error('Clé sans partie publique');
    const pub = Buffer.from(parsedKey.getPublicSSH());
    if (!keys.some(k => k.pub.equals(pub))) keys.push({ parsedKey, pub, comment: String(comment || '') });
    return pub;
  }

  function removeAll() { keys.length = 0; }
  function count() { return keys.length; }

  const failure = () => Buffer.from([MSG.FAILURE]);

  /**
   * Traite un message d'agent (sans le préfixe de longueur) et renvoie la réponse (idem).
   * Fonction pure : aucune E/S, pour un test déterministe.
   */
  function handleMessage(payload) {
    if (!Buffer.isBuffer(payload) || payload.length < 1) return failure();
    const type = payload[0];

    if (type === MSG.REQUEST_IDENTITIES) {
      const parts = [Buffer.from([MSG.IDENTITIES_ANSWER])];
      const n = Buffer.alloc(4); n.writeUInt32BE(keys.length, 0); parts.push(n);
      for (const k of keys) { parts.push(sshString(k.pub)); parts.push(sshString(k.comment)); }
      return Buffer.concat(parts);
    }

    if (type === MSG.SIGN_REQUEST) {
      try {
        let off = 1;
        const keyBlob = readSshString(payload, off); off = keyBlob.next;
        const data = readSshString(payload, off); off = data.next;
        const flags = (off + 4 <= payload.length) ? payload.readUInt32BE(off) : 0;

        const entry = keys.find(k => k.pub.equals(keyBlob.data));
        if (!entry) return failure();

        let algoName, hashAlgo;
        if (entry.parsedKey.type === 'ssh-rsa') {
          if (flags & FLAG_RSA_SHA2_512) { algoName = 'rsa-sha2-512'; hashAlgo = 'sha512'; }
          else if (flags & FLAG_RSA_SHA2_256) { algoName = 'rsa-sha2-256'; hashAlgo = 'sha256'; }
          else { algoName = 'ssh-rsa'; hashAlgo = undefined; }
        } else {
          algoName = entry.parsedKey.type; // ssh-ed25519, ecdsa-sha2-nistp256, …
          hashAlgo = undefined;
        }

        const raw = hashAlgo ? entry.parsedKey.sign(data.data, hashAlgo) : entry.parsedKey.sign(data.data);
        if (!Buffer.isBuffer(raw) || raw.length === 0) return failure();

        // Blob de signature SSH : string(nom d'algo) || string(signature brute)
        const sigBlob = Buffer.concat([sshString(algoName), sshString(raw)]);
        return Buffer.concat([Buffer.from([MSG.SIGN_RESPONSE]), sshString(sigBlob)]);
      } catch { return failure(); }
    }

    if (type === MSG.REMOVE_ALL_IDENTITIES) { removeAll(); return Buffer.from([MSG.SUCCESS]); }

    return failure();
  }

  let server = null;

  /** Démarre l'agent sur une socket/named pipe. Renvoie le chemin d'écoute. */
  function listen(socketPath) {
    return new Promise((resolve, reject) => {
      server = net.createServer((socket) => {
        let buf = Buffer.alloc(0);
        socket.on('data', (chunk) => {
          buf = Buffer.concat([buf, chunk]);
          // Démultiplexage des trames : uint32(longueur) || payload
          while (buf.length >= 4) {
            const len = buf.readUInt32BE(0);
            if (len > 256 * 1024) { socket.destroy(); return; } // garde-fou
            if (buf.length < 4 + len) break;
            const payload = buf.slice(4, 4 + len);
            buf = buf.slice(4 + len);
            let resp;
            try { resp = handleMessage(payload); } catch { resp = failure(); }
            const frameLen = Buffer.alloc(4); frameLen.writeUInt32BE(resp.length, 0);
            socket.write(Buffer.concat([frameLen, resp]));
          }
        });
        socket.on('error', () => { try { socket.destroy(); } catch {} });
      });
      server.on('error', reject);
      server.listen(socketPath, () => resolve(socketPath));
    });
  }

  function close() {
    try { if (server) server.close(); } catch { /* ignore */ }
    server = null;
    removeAll();
  }

  return { addKey, removeAll, count, handleMessage, listen, close };
}

module.exports = { createAgent, sshString, readSshString, MSG, FLAG_RSA_SHA2_256, FLAG_RSA_SHA2_512 };
