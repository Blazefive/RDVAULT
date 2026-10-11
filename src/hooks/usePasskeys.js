import { useEffect } from 'react';
import secureLogger from '../secureLogger';
import { createPasskeyStore, PASSKEY_SECRET_KEY } from '../utils/passkeyEngine';

/**
 * Hook usePasskeys — stocke les passkeys WebAuthn de l'extension DANS le coffre chiffré.
 *
 * Le serveur sync (main process) relaie trois requêtes que l'on traite ici en lisant /
 * écrivant un secret dédié (`.rdvault-passkeys`) dans le coffre personnel de l'utilisateur
 * (préfixe exact « users/<nom>/ », voir utils/passkeyEngine) :
 *  - passkey-list        : renvoie les passkeys d'un rpId (clé privée incluse, pour signer)
 *  - passkey-store       : ajoute / remplace une passkey
 *  - passkey-update-count: RÉSERVE une valeur du compteur de signatures. Le compteur ne recule
 *    jamais : la valeur demandée n'est enregistrée que si elle dépasse la valeur stockée
 *    (réponse { reserved: true }) ; sinon { reserved: false, signCount: <valeur stockée> } et
 *    l'extension redemande la valeur suivante avant de signer.
 *
 * Les écritures sont sérialisées (file d'attente unique, partagée avec l'écran « Mes passkeys »)
 * et conditionnelles en KV v2 (CAS) : deux opérations simultanées ne s'écrasent plus.
 *
 * Les passkeys bénéficient ainsi du chiffrement du coffre (AES-256-GCM en mode local)
 * et de la sauvegarde, au lieu de vivre dans le stockage du navigateur.
 */

// Ré-export (compatibilité des imports existants)
export { PASSKEY_SECRET_KEY };

export function usePasskeys({ vaultApi, token, vaultUrl, secretEngines, authUser }) {
  useEffect(() => {
    if (!window.electronPasskey?.onRequest || !token || !vaultApi) return;
    const store = createPasskeyStore({ vaultApi, vaultUrl, secretEngines, authUser });

    const handle = async (channel, req) => {
      const requestId = req.requestId;
      const respond = (result) => { try { window.electronPasskey.sendResponse(channel, result, requestId); } catch { /* ignore */ } };
      try {
        // Aucun coffre personnel : jamais de repli vers un autre coffre (création refusée)
        if (!store.engine) return respond({ success: false, error: 'Aucun coffre personnel' });

        if (channel === 'passkey-list') {
          const { blob } = await store.read();
          return respond({ success: true, passkeys: Array.isArray(blob.items[req.rpId]) ? blob.items[req.rpId] : [] });
        }
        if (channel === 'passkey-store') {
          const pk = req.passkey;
          if (!pk || !pk.rpId || !pk.credentialId) return respond({ success: false, error: 'passkey invalide' });
          await store.update((blob) => {
            const list = (Array.isArray(blob.items[pk.rpId]) ? blob.items[pk.rpId] : []).filter(e => e.credentialId !== pk.credentialId);
            list.push(pk);
            blob.items[pk.rpId] = list;
          });
          secureLogger.debug('[Passkey] Passkey enregistrée dans le coffre');
          return respond({ success: true });
        }
        if (channel === 'passkey-update-count') {
          const wanted = Number(req.signCount) || 0;
          let result = { success: true };
          await store.update((blob) => {
            const list = Array.isArray(blob.items[req.rpId]) ? blob.items[req.rpId] : [];
            const entry = list.find(x => x.credentialId === req.credentialId);
            if (!entry) { result = { success: true }; return false; }
            const stored = Number(entry.signCount) || 0;
            // Compteur monotone : jamais de recul (deux onglets, réponse tardive)
            if (wanted <= stored) { result = { success: true, signCount: stored, reserved: false }; return false; }
            entry.signCount = wanted;
            result = { success: true, signCount: wanted, reserved: true };
            return true;
          });
          return respond(result);
        }
        respond({ success: false, error: 'op inconnue' });
      } catch (err) {
        secureLogger.error('[Passkey] Erreur stockage coffre');
        respond({ success: false, error: 'Erreur coffre' });
      }
    };

    const remove = window.electronPasskey.onRequest(handle);
    return remove;
  }, [token, vaultUrl, secretEngines, authUser]); // eslint-disable-line react-hooks/exhaustive-deps
}
