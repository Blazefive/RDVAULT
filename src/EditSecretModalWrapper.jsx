// src/EditSecretModalWrapper.jsx
// Wrapper pour EditSecretModal qui gère la vérification TOTP
// Extrait de App.jsx pour éviter les re-renders causés par les changements d'état parent
import React, { useState, useEffect, useRef } from 'react';
import EditSecretModal from './EditSecretModal.jsx';

export default function EditSecretModalWrapper({
  editSecret,
  selectedEngine,
  onClose,
  onSave,
  checkTotpExists,
  getTotpKeyName,
  existingTags = [],
  showToast
}) {
  // Clé TOTP à vérifier : entrée nommée uniquement (le TOTP éventuel verrouille son nom)
  const totpKeyName = editSecret && editSecret.name ? getTotpKeyName(editSecret.name) : null;

  // PERF : la fiche s'affiche dès le clic, la vérification TOTP (requête au coffre) se fait en
  // parallèle. Avant : rien n'était rendu avant la réponse (« Modifier » : ≈ 65 ms mesurés avec le
  // coffre local, un aller-retour réseau de plus avec un Vault distant ; « Nouvelle entrée » : une
  // image de retard). Pendant la vérification, le nom d'une entrée existante reste en lecture
  // seule ; l'enregistrement revérifie de toute façon le TOTP avant un renommage (useSecrets).
  const [totpState, setTotpState] = useState(() => ({ key: totpKeyName, exists: false, pending: totpKeyName !== null }));

  // Fonction de vérification la plus récente, sans relancer la vérification à chaque rendu
  const checkRef = useRef(checkTotpExists);
  useEffect(() => { checkRef.current = checkTotpExists; });

  useEffect(() => {
    if (totpKeyName === null) {
      setTotpState((prev) => (prev.pending || prev.exists ? { key: null, exists: false, pending: false } : prev));
      return undefined;
    }
    let active = true;
    // Nouvelle clé (autre entrée ou autre coffre) : nom en lecture seule jusqu'à la réponse
    setTotpState((prev) => (prev.key === totpKeyName && prev.pending ? prev : { key: totpKeyName, exists: false, pending: true }));
    (async () => {
      let exists = false;
      try { exists = await checkRef.current(totpKeyName); } catch { exists = false; }
      // Réponse d'une fiche fermée ou d'une clé remplacée entre-temps : ignorée
      if (active) setTotpState({ key: totpKeyName, exists: !!exists, pending: false });
    })();
    return () => { active = false; };
  }, [totpKeyName]);

  return (
    <EditSecretModal
      initial={editSecret}
      totpExists={totpState.exists}
      totpPending={totpState.pending}
      onClose={onClose}
      onSave={onSave}
      existingTags={existingTags}
      showToast={showToast}
    />
  );
}
