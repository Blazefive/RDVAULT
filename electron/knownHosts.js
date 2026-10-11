// ========================================
// MÉMOIRE DES CLÉS D'HÔTE SSH — équivalent de ~/.ssh/known_hosts
// ========================================
// Conserve, par « hôte:port », l'empreinte SHA256 de la clé d'hôte vue lors de la première
// connexion (TOFU) afin de détecter tout CHANGEMENT de clé ultérieur (attaque de l'homme du
// milieu, réinstallation du serveur…). Le fichier est relu à CHAQUE consultation (pas de cache)
// pour rester cohérent entre les processus (serveur CLI, audit SSH).
//
// Format JSON : { "version": 1, "hosts": { "<host:port>": { "fingerprint": "SHA256:…",
//                 "firstSeen": "<ISO>", "lastSeen": "<ISO>" } } }
//
// Module PUR Node (fs/path uniquement, aucun require('electron')). Testable sans Electron.

'use strict';

const fs = require('fs');
const path = require('path');

const FILE_VERSION = 1;

/** Clé d'index « hôte:port » : hôte en minuscules sans espaces, port 22 par défaut. */
function hostKey(host, port) {
  return `${String(host == null ? '' : host).trim().toLowerCase()}:${Number(port) || 22}`;
}

/** Normalise une empreinte (« SHA256:xxx », « sha256:xxx », « xxx », avec/sans padding) au format comparable. */
function normalizeFp(fp) {
  let s = String(fp == null ? '' : fp).trim();
  if (/^sha256:/i.test(s)) s = s.slice(7);
  return 'SHA256:' + s.replace(/=+$/, '');
}

/** Découpe une clé « hôte:port » (le port est après le DERNIER « : », compatible IPv6). */
function splitKey(key) {
  const i = key.lastIndexOf(':');
  if (i < 0) return { host: key, port: 22 };
  return { host: key.slice(0, i), port: Number(key.slice(i + 1)) || 22 };
}

/**
 * Crée une mémoire de clés d'hôte adossée au fichier JSON `filePath` (créé paresseusement
 * à la première mémorisation). Fichier ABSENT = mémoire vide. Fichier illisible (verrou,
 * droits, EISDIR…) ou corrompu (JSON invalide, forme inattendue) = échec FERMÉ : toute
 * opération lève une erreur de code KNOWN_HOSTS_READ et le fichier n'est jamais réécrit
 * (un changement de clé ne doit pas devenir une « nouvelle clé », ni les entrées être effacées).
 * Les erreurs d'ÉCRITURE sont propagées à l'appelant.
 */
function createKnownHosts(filePath) {
  if (!filePath || typeof filePath !== 'string') throw new Error('createKnownHosts : chemin de fichier requis');

  const readError = (message, cause) => Object.assign(new Error(message), { code: 'KNOWN_HOSTS_READ', cause });

  // Lecture : seul un fichier absent (ENOENT, ou ENOTDIR : un parent n'est pas un dossier) vaut
  // mémoire vide ; toute autre anomalie lève KNOWN_HOSTS_READ. Entrée individuelle invalide → ignorée.
  function read() {
    let raw;
    try { raw = fs.readFileSync(filePath, 'utf8'); } catch (e) {
      if (e && (e.code === 'ENOENT' || e.code === 'ENOTDIR')) return { version: FILE_VERSION, hosts: {} };
      throw readError(`Mémoire des clés d'hôte SSH illisible (${filePath}) : ${(e && e.message) || e}`, e);
    }
    let data = null;
    try { data = JSON.parse(raw); } catch (e) {
      throw readError(`Mémoire des clés d'hôte SSH corrompue (${filePath}) : JSON invalide — corrigez ou supprimez ce fichier`, e);
    }
    if (!data || typeof data !== 'object' || !data.hosts || typeof data.hosts !== 'object' || Array.isArray(data.hosts)) {
      throw readError(`Mémoire des clés d'hôte SSH corrompue (${filePath}) : forme inattendue — corrigez ou supprimez ce fichier`);
    }
    const hosts = {};
    for (const [k, v] of Object.entries(data.hosts)) {
      if (!v || typeof v !== 'object' || typeof v.fingerprint !== 'string') continue; // entrée invalide ignorée
      const fp = normalizeFp(v.fingerprint);
      if (fp === 'SHA256:') continue; // empreinte vide après normalisation (« sha256: », « = »…) : ignorée
      hosts[k] = {
        fingerprint: fp,
        firstSeen: typeof v.firstSeen === 'string' ? v.firstSeen : null,
        lastSeen: typeof v.lastSeen === 'string' ? v.lastSeen : null,
      };
    }
    return { version: FILE_VERSION, hosts };
  }

  // Écriture ATOMIQUE : fichier temporaire puis rename (jamais de fichier à moitié écrit),
  // dossier créé au besoin, permissions 0600 en meilleur effort (sans effet sous Windows).
  function write(data) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify({ version: FILE_VERSION, hosts: data.hosts }, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
      try { fs.chmodSync(tmp, 0o600); } catch { /* meilleur effort */ }
      fs.renameSync(tmp, filePath);
    } catch (e) {
      try { fs.unlinkSync(tmp); } catch { /* déjà absent */ }
      throw e;
    }
    try { fs.chmodSync(filePath, 0o600); } catch { /* meilleur effort */ }
  }

  return {
    get path() { return filePath; },

    /** Empreinte mémorisée pour hôte:port, ou null. */
    lookup(host, port) {
      const entry = read().hosts[hostKey(host, port)];
      return entry ? entry.fingerprint : null;
    },

    /** Mémorise l'empreinte : met à jour lastSeen, conserve firstSeen (réinitialisé si la clé change). */
    remember(host, port, fingerprint) {
      const k = hostKey(host, port);
      if (k.startsWith(':')) throw new Error('knownHosts.remember : hôte requis');
      const fp = normalizeFp(fingerprint);
      if (fp === 'SHA256:') throw new Error('knownHosts.remember : empreinte requise');
      const data = read();
      const now = new Date().toISOString();
      const prev = data.hosts[k];
      data.hosts[k] = {
        fingerprint: fp,
        firstSeen: prev && prev.firstSeen && prev.fingerprint === fp ? prev.firstSeen : now,
        lastSeen: now,
      };
      write(data);
    },

    /** Oublie hôte:port ; renvoie true si une entrée existait. */
    forget(host, port) {
      const k = hostKey(host, port);
      const data = read();
      if (!Object.prototype.hasOwnProperty.call(data.hosts, k)) return false;
      delete data.hosts[k];
      write(data);
      return true;
    },

    /** Compare l'empreinte observée à la mémoire : 'known' | 'new' | 'mismatch' (+ empreinte attendue). */
    check(host, port, observedFp) {
      const expected = this.lookup(host, port);
      if (!expected) return { status: 'new', expected: null };
      return { status: normalizeFp(observedFp) === expected ? 'known' : 'mismatch', expected };
    },

    /** Liste des entrées mémorisées. */
    entries() {
      return Object.entries(read().hosts).map(([k, v]) => {
        const { host, port } = splitKey(k);
        return { host, port, fingerprint: v.fingerprint, firstSeen: v.firstSeen, lastSeen: v.lastSeen };
      });
    },
  };
}

module.exports = { createKnownHosts, hostKey, normalizeFp };
