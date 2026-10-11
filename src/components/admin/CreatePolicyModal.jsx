// ========================================
// MODALE : Création d'une nouvelle policy (panneau admin)
// ========================================
// Extrait d'AdminPanel.jsx. Crée une policy de base puis passe par savePolicy
// (qui applique les validations modérateur) — plus d'appel axios direct.
//
// Props :
// - savePolicy(name, hcl) : Promise<boolean> (true si sauvegardée)
// - onCreated(name, hcl) : callback après création réussie
// - showToast, onClose
//
// Squelette commun Modal (hook useDialogA11y) : role="dialog" nommé par le titre, focus initial
// sur le champ, piège de focus, Échap (modale du dessus seulement), retour du focus au bouton
// déclencheur, fermeture sur le fond par mousedown + mouseup ; couleurs du thème (clair / sombre).

import React, { useId } from 'react';
import Modal from '../common/Modal';
import { useTranslation } from '../../i18n';
import { ltrWhenFilled } from './i18nHelpers';

export default function CreatePolicyModal({ savePolicy, onCreated, showToast, onClose }) {
  const { t } = useTranslation();
  const [policyName, setPolicyName] = React.useState('');
  const formId = useId();
  const inputId = useId();

  const handleCreate = async () => {
    if (!policyName.trim()) return;

    // SÉCURITÉ: Sanitiser le nom de policy pour éviter l'injection HCL
    const name = policyName.trim().replace(/[\r\n"\\*+]/g, '');
    if (!name || name.length > 256) {
      showToast(t('admin.toast.policyNameInvalid'), 'error');
      return;
    }

    // Créer une policy de base avec configuration minimale
    const basePolicy = `# Policy créée automatiquement - ${name}
# Modifiez cette policy selon vos besoins

# Lecture de la liste des secrets engines
path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/internal/ui/mounts" {
  capabilities = ["read"]
}

# Accès en lecture au coffre personnel
path "secret/data/users/{{identity.entity.name}}/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/users/{{identity.entity.name}}/*" {
  capabilities = ["read", "list"]
}

# Lookup token (pour entity_name)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}`;

    // SÉCURITÉ: Passer par savePolicy (validations modérateur, toast, rechargement
    // de la liste) plutôt qu'un axios.put direct.
    const saved = await savePolicy(name, basePolicy);
    if (!saved) return;

    // Mettre à jour l'interface
    onCreated && onCreated(name, basePolicy);
    onClose();
  };

  return (
    <Modal
      title={t('admin.newPolicy')}
      onClose={onClose}
      maxWidth="460px"
      footer={(
        <>
          <button type="button" className="btn btn-secondary" onClick={() => onClose()}>
            {t('common.cancel')}
          </button>
          <button
            type="submit"
            form={formId}
            className="btn btn-success"
            disabled={!policyName.trim()}
          >
            {t('admin.common.create')}
          </button>
        </>
      )}
    >
      {/* Formulaire : Entrée dans le champ crée la policy (remplace l'écoute globale du clavier) */}
      <form id={formId} onSubmit={(e) => { e.preventDefault(); handleCreate(); }}>
        <div className="form-group-vertical" style={{ marginBottom: 0 }}>
          <label className="modal-label" htmlFor={inputId}>{t('admin.policyName')}*</label>
          {/* Nom de policy : identifiant technique saisi de gauche à droite (ADMIN-11) ; texte
              indicatif traduit dans le sens de la langue tant que le champ est vide */}
          <input
            id={inputId}
            type="text"
            dir={ltrWhenFilled(policyName)}
            className="modal-input"
            style={{ marginBottom: 0 }}
            autoComplete="off"
            placeholder={t('admin.common.example', { value: 'app-read-only' })}
            value={policyName}
            onChange={(e) => setPolicyName(e.target.value)}
          />
        </div>
      </form>
    </Modal>
  );
}
