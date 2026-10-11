// Tests de l'agent SSH (electron/sshAgent.js) — node --test, sans Electron ni serveur SSH.
// Les signatures produites par l'agent sont VÉRIFIÉES cryptographiquement (pile ssh2 +,
// pour RSA, Node crypto indépendamment) et un aller-retour réel sur named pipe est testé.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { utils: { parseKey } } = require('ssh2');
const { createAgent, sshString, readSshString, MSG, FLAG_RSA_SHA2_256, FLAG_RSA_SHA2_512 } = require('./sshAgent');

// Clés générées par Node (formats acceptés par ssh2 : RSA pkcs1, EC sec1)
const RSA_PEM = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
const EC_PEM = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'sec1', format: 'pem' });

const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
function signRequest(pubBlob, data, flags = 0) {
  return Buffer.concat([Buffer.from([MSG.SIGN_REQUEST]), sshString(pubBlob), sshString(data), u32(flags)]);
}
function parseSignResponse(resp) {
  assert.equal(resp[0], MSG.SIGN_RESPONSE, 'type SIGN_RESPONSE');
  const blob = readSshString(resp, 1).data;
  const algo = readSshString(blob, 0);
  const sig = readSshString(blob, algo.next);
  return { algo: algo.data.toString(), sig: sig.data };
}
function parseIdentities(resp) {
  assert.equal(resp[0], MSG.IDENTITIES_ANSWER, 'type IDENTITIES_ANSWER');
  const nkeys = resp.readUInt32BE(1);
  const list = []; let off = 5;
  for (let i = 0; i < nkeys; i++) {
    const blob = readSshString(resp, off); off = blob.next;
    const comment = readSshString(resp, off); off = comment.next;
    list.push({ pub: blob.data, comment: comment.data.toString() });
  }
  return list;
}

test('REQUEST_IDENTITIES liste les clés chargées avec leur blob public', () => {
  const agent = createAgent();
  const rsaPub = agent.addKey(RSA_PEM, 'rsa@rdvault');
  const ecPub = agent.addKey(EC_PEM, 'ec@rdvault');
  const ids = parseIdentities(agent.handleMessage(Buffer.from([MSG.REQUEST_IDENTITIES])));
  assert.equal(ids.length, 2);
  assert.ok(ids.some(i => i.pub.equals(rsaPub) && i.comment === 'rsa@rdvault'));
  assert.ok(ids.some(i => i.pub.equals(ecPub) && i.comment === 'ec@rdvault'));
});

test('addKey est idempotent (pas de doublon pour la même clé)', () => {
  const agent = createAgent();
  agent.addKey(RSA_PEM); agent.addKey(RSA_PEM);
  assert.equal(agent.count(), 1);
});

test('SIGN_REQUEST RSA (ssh-rsa, sha1) : signature valide', () => {
  const agent = createAgent();
  const pub = agent.addKey(RSA_PEM);
  const verifier = parseKey(RSA_PEM);
  const data = nodeCrypto.randomBytes(40);
  const { algo, sig } = parseSignResponse(agent.handleMessage(signRequest(pub, data, 0)));
  assert.equal(algo, 'ssh-rsa');
  assert.equal(verifier.verify(data, sig), true, 'vérifiée par la pile SSH');
});

test('SIGN_REQUEST RSA sha2-256 / sha2-512 : algo et signature corrects (+ Node crypto)', () => {
  const agent = createAgent();
  const pub = agent.addKey(RSA_PEM);
  const verifier = parseKey(RSA_PEM);
  const pubKeyObj = nodeCrypto.createPublicKey(verifier.getPublicPEM());
  const data = nodeCrypto.randomBytes(64);

  const r256 = parseSignResponse(agent.handleMessage(signRequest(pub, data, FLAG_RSA_SHA2_256)));
  assert.equal(r256.algo, 'rsa-sha2-256');
  assert.equal(verifier.verify(data, r256.sig, 'sha256'), true);
  assert.equal(nodeCrypto.verify('sha256', data, pubKeyObj, r256.sig), true, 'RSA-SHA256 validée par Node crypto');

  const r512 = parseSignResponse(agent.handleMessage(signRequest(pub, data, FLAG_RSA_SHA2_512)));
  assert.equal(r512.algo, 'rsa-sha2-512');
  assert.equal(nodeCrypto.verify('sha512', data, pubKeyObj, r512.sig), true, 'RSA-SHA512 validée par Node crypto');
});

test('SIGN_REQUEST ECDSA (nistp256) : signature valide', () => {
  const agent = createAgent();
  const pub = agent.addKey(EC_PEM);
  const verifier = parseKey(EC_PEM);
  const data = nodeCrypto.randomBytes(32);
  const { algo, sig } = parseSignResponse(agent.handleMessage(signRequest(pub, data, 0)));
  assert.equal(algo, 'ecdsa-sha2-nistp256');
  assert.equal(verifier.verify(data, sig), true);
});

test('SIGN_REQUEST pour une clé inconnue → FAILURE', () => {
  const agent = createAgent();
  agent.addKey(RSA_PEM);
  const unknownPub = parseKey(EC_PEM).getPublicSSH();
  const resp = agent.handleMessage(signRequest(unknownPub, Buffer.from('x'), 0));
  assert.equal(resp[0], MSG.FAILURE);
});

test('message inconnu / vide → FAILURE', () => {
  const agent = createAgent();
  assert.equal(agent.handleMessage(Buffer.from([99]))[0], MSG.FAILURE);
  assert.equal(agent.handleMessage(Buffer.alloc(0))[0], MSG.FAILURE);
});

test('REMOVE_ALL_IDENTITIES vide l\'agent', () => {
  const agent = createAgent();
  agent.addKey(RSA_PEM);
  assert.equal(agent.handleMessage(Buffer.from([MSG.REMOVE_ALL_IDENTITIES]))[0], MSG.SUCCESS);
  assert.equal(agent.count(), 0);
});

test('addKey rejette une clé illisible', () => {
  const agent = createAgent();
  assert.throws(() => agent.addKey('pas une clé'));
});

test('aller-retour réel sur named pipe (framing uint32) : un client obtient les identités', async () => {
  const agent = createAgent();
  const pub = agent.addKey(RSA_PEM, 'pipe@rdvault');
  const pipePath = process.platform === 'win32'
    ? '\\\\.\\pipe\\rdvault-agent-test-' + nodeCrypto.randomBytes(6).toString('hex')
    : path.join(os.tmpdir(), 'rdvault-agent-' + nodeCrypto.randomBytes(6).toString('hex') + '.sock');
  await agent.listen(pipePath);
  try {
    const resp = await new Promise((resolve, reject) => {
      const c = net.connect(pipePath);
      let buf = Buffer.alloc(0);
      c.on('connect', () => {
        const msg = Buffer.from([MSG.REQUEST_IDENTITIES]);
        c.write(Buffer.concat([u32(msg.length), msg]));
      });
      c.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
          const len = buf.readUInt32BE(0);
          c.end(); resolve(buf.slice(4, 4 + len));
        }
      });
      c.on('error', reject);
    });
    const ids = parseIdentities(resp);
    assert.equal(ids.length, 1);
    assert.ok(ids[0].pub.equals(pub));
  } finally {
    agent.close();
  }
});
