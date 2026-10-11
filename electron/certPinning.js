// ========================================
// CERT PINNING — logique pure (testable, sans dépendance Electron)
// ========================================
// Calcul de l'empreinte SHA-256 d'un certificat et comparaison à la liste épinglée
// (TRUSTED_CERT_FINGERPRINTS). Utilisé par le handler `certificate-error` de main.js.

'use strict';

const crypto = require('crypto');

/**
 * Empreinte SHA-256 (hex minuscule) d'un certificat Electron.
 * Accepte un objet { data: <PEM> } ou { fingerprint: 'sha256/<base64>' }. Renvoie null si illisible.
 * @param {{ data?: string, fingerprint?: string }} certificate
 * @returns {string|null}
 */
function certificateFingerprintHex(certificate) {
  try {
    if (certificate && typeof certificate.data === 'string') {
      const der = Buffer.from(certificate.data.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
      if (der.length > 0) return crypto.createHash('sha256').update(der).digest('hex');
    }
    if (certificate && typeof certificate.fingerprint === 'string' && certificate.fingerprint.startsWith('sha256/')) {
      return Buffer.from(certificate.fingerprint.slice(7), 'base64').toString('hex');
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * true si l'empreinte du certificat figure dans la liste épinglée (membership exact).
 * Une liste vide signifie « pas de pinning » : renvoie false (le décideur gère ce cas à part).
 * @param {object} certificate
 * @param {string[]} pinnedList - empreintes hex minuscules (sortie de getTrustedCertFingerprints)
 * @returns {boolean}
 */
function fingerprintMatches(certificate, pinnedList) {
  if (!Array.isArray(pinnedList) || pinnedList.length === 0) return false;
  const actual = certificateFingerprintHex(certificate);
  return !!actual && pinnedList.includes(actual);
}

module.exports = { certificateFingerprintHex, fingerprintMatches };
