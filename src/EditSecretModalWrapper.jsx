// src/EditSecretModalWrapper.jsx
// Wrapper pour EditSecretModal qui gère la vérification TOTP
// Extrait de App.jsx pour éviter les re-renders causés par les changements d'état parent
import React, { useState, useEffect } from 'react';
import EditSecretModal from './EditSecretModal.jsx';

export default function EditSecretModalWrapper({
  editSecret,
  selectedEngine,
  onClose,
  onSave,
  checkTotpExists,
  getTotpKeyName,
  existingTags = []
}) {
  const [totpExists, setTotpExistsState] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkTotp = async () => {
      if (editSecret && editSecret.name) {
        const totpKeyName = getTotpKeyName(editSecret.name);
        const exists = await checkTotpExists(totpKeyName);
        setTotpExistsState(exists);
      }
      setLoading(false);
    };
    checkTotp();
  }, [editSecret, checkTotpExists, getTotpKeyName]);

  if (loading) return null;

  return (
    <EditSecretModal
      initial={editSecret}
      totpExists={totpExists}
      onClose={onClose}
      onSave={onSave}
      existingTags={existingTags}
    />
  );
}
