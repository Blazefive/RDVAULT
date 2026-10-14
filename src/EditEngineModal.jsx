// ========================================
// MODAL DE CRÉATION D'ENGINE (COFFRE)
// ========================================
// Permet de créer un nouveau secret engine KV v2 dans Vault
//
// Props :
// - onClose : Callback pour fermer la modal
// - onCreate : Callback appelée avec les données de l'engine à créer {name, version, description}
// - isAdmin : Si true, l'utilisateur peut créer des coffres partagés, sinon coffres sous users/{username}/
//
// Fonctionnalités :
// - Création d'engines KV v2 uniquement
// - Préfixe automatique "users/{username}/" pour les utilisateurs non-admin (self-service)
// - Validation du nom (pas de slashes au début/fin)
// - Description optionnelle
// - État de chargement pendant la requête réseau
//
// Comportement (squelette commun Modal) :
// - Escape pour fermer (sauf pendant le chargement)
// - Clic hors modal pour fermer (sauf pendant le chargement)
// - Focus automatique sur le champ "Chemin" à l'ouverture

import React, { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from './i18n';
import Modal from './components/common/Modal';

/**
 * Modal de création d'un nouveau secret engine (coffre)
 */
export default function EditEngineModal({ onClose, onCreate, isAdmin }) {
  const { t } = useTranslation();
  const pathRef = useRef(null);
  const version = 2; // KV v2 uniquement
  const descRef = useRef(null);
  const [loading, setLoading] = useState(false);
  // UI-36 : libellés « Chemin* » et « Description » reliés à leur champ (htmlFor / id)
  const idBase = useId();
  const pathId = `${idBase}-path`;
  const descId = `${idBase}-desc`;

  // Détecte le username pour suggérer le préfixe self-service (sauf pour les admins)
  const username = localStorage.getItem('vault-client.username') || '';
  const userPrefix = username && !isAdmin ? `users/${username}/` : '';

  useEffect(() => { pathRef.current?.focus(); }, []);

  const handleCreate = async () => {
    if (loading) return;
    const nameRaw = pathRef.current?.value || '';
    const description = descRef.current?.value || '';
    const cleanName = nameRaw.replace(/^\/+|\/+$/g, '');
    if (!cleanName.trim()) { pathRef.current?.focus(); return; }

    // Ajouter automatiquement le préfixe users/ pour les non-admins
    const finalName = userPrefix ? `${userPrefix}${cleanName}` : cleanName;

    try {
      setLoading(true);
      // On laisse la modale OUVERTE pendant la requête réseau…
      await onCreate({ name: finalName, version: Number(version), description });
      // … puis on ferme proprement
      onClose();
    } catch (e) {
      // onCreate gère l'affichage d'erreur côté App via toast
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal
      title={t('engine.newEngine')}
      onClose={onClose}
      disableClose={loading}
      footer={(
        <>
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="btn btn-secondary"
          >
            {t('engine.cancel')}
          </button>
          <button
            type="button"
            onClick={handleCreate}
            disabled={loading}
            className="btn btn-success"
          >
            {loading ? t('engine.creating') : t('engine.create')}
          </button>
        </>
      )}
    >
      <div className="form-group-vertical">
        <label className="modal-label" htmlFor={pathId}>{t('engine.path')}</label>
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <input
            ref={pathRef}
            id={pathId}
            aria-required="true"
            className="modal-input"
            style={{
              marginBottom: 0
            }}
            placeholder={isAdmin ? t('engine.placeholderAdmin') : t('engine.placeholderUser')}
            defaultValue=""
            autoComplete="off"
            disabled={loading}
          />
        </div>
        {isAdmin && (
          <div className="info-box">
            <div className="info-box-title">{t('engine.adminMode')}</div>
            <div className="info-box-content">
              🛡️ {t('engine.adminModeDesc')}
            </div>
          </div>
        )}
      </div>

      <div className="form-group-vertical">
        <label className="modal-label" htmlFor={descId}>{t('engine.description')}</label>
        <textarea
          ref={descRef}
          id={descId}
          className="modal-textarea"
          placeholder={t('engine.placeholderDesc')}
          disabled={loading}
        />
      </div>
    </Modal>
  );
}
