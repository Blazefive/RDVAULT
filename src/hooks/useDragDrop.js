import { useState } from 'react';
import secureLogger from '../secureLogger';

/**
 * Hook useDragDrop — gère le drag & drop de secrets entre engines et dossiers
 */
export function useDragDrop({
  selectedSecrets,
  setSelectedSecrets,
  isSecretSelected,
  migrateSecretsToEngine,
  moveSecretsToFolder,
  selectedEngine,
  secretEngines,
  showToast,
  t
}) {
  const [isDragging, setIsDragging] = useState(false);
  const [dragOverTarget, setDragOverTarget] = useState(null);

  /**
   * Gestionnaire de début de drag
   */
  const handleDragStart = (e, secret) => {
    // Si le secret n'est pas dans la sélection, le sélectionner seul
    if (!selectedSecrets.has(secret.name)) {
      setSelectedSecrets(new Set([secret.name]));
    }

    // Stocker les données de drag
    const dragData = {
      type: 'secrets',
      secrets: selectedSecrets.has(secret.name)
        ? Array.from(selectedSecrets)
        : [secret.name],
      sourceEngine: selectedEngine?.name,
      sourceVersion: selectedEngine?.version
    };

    e.dataTransfer.setData('application/json', JSON.stringify(dragData));
    e.dataTransfer.effectAllowed = 'move';

    setIsDragging(true);

    // Créer un élément de drag visuel personnalisé
    const dragCount = dragData.secrets.length;
    const dragGhost = document.createElement('div');
    dragGhost.className = 'drag-ghost';
    dragGhost.textContent = `\u{1F4E6} ${dragCount} entr\u00E9e${dragCount > 1 ? 's' : ''}`;
    dragGhost.style.cssText = `
      position: absolute;
      top: -1000px;
      left: -1000px;
      padding: 8px 16px;
      background: var(--accent, #3b82f6);
      color: white;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      pointer-events: none;
      z-index: 9999;
    `;
    document.body.appendChild(dragGhost);
    e.dataTransfer.setDragImage(dragGhost, 50, 20);

    // Nettoyer le ghost après un court délai
    setTimeout(() => {
      if (dragGhost.parentNode) {
        dragGhost.parentNode.removeChild(dragGhost);
      }
    }, 0);
  };

  /**
   * Gestionnaire de fin de drag
   */
  const handleDragEnd = () => {
    setIsDragging(false);
    setDragOverTarget(null);
  };

  /**
   * Gestionnaire de survol pour les drop zones
   */
  const handleDragOver = (e, targetId) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOverTarget(targetId);
  };

  /**
   * Gestionnaire de sortie de zone de drop
   */
  const handleDragLeave = () => {
    setDragOverTarget(null);
  };

  /**
   * Gestionnaire de drop sur un engine (migration inter-coffre ou déplacement à la racine)
   */
  const handleDropOnEngine = async (e, targetEngine) => {
    e.preventDefault();
    setDragOverTarget(null);
    setIsDragging(false);

    try {
      const dragData = JSON.parse(e.dataTransfer.getData('application/json'));

      if (dragData.type !== 'secrets' || !Array.isArray(dragData.secrets) || !dragData.secrets.length) {
        return;
      }
      // SÉCURITÉ: Valider les données du drag-and-drop
      if (dragData.secrets.length > 500) { showToast(t('error.tooManyEntries'), 'error'); return; }
      if (typeof dragData.sourceEngine !== 'string' || !secretEngines.some(eng => eng.name === dragData.sourceEngine)) return;
      if (dragData.secrets.some(n => typeof n !== 'string' || n.includes('..') || /[\x00-\x1F]/.test(n) || n.length > 512)) return;

      // Vérifier les droits d'écriture sur l'engine cible
      if (!targetEngine.canWrite) {
        showToast(t('error.noReadAccess'), 'error');
        return;
      }

      // Si drop sur le même engine → déplacer à la racine
      if (dragData.sourceEngine === targetEngine.name) {
        // Vérifier si les entrées sont déjà à la racine
        const secretsInFolders = dragData.secrets.filter(name => name.includes('/'));
        if (secretsInFolders.length === 0) {
          showToast(t('migrate.root'), 'info');
          return;
        }
        // Déplacer à la racine (chemin vide)
        await moveSecretsToFolder(dragData.secrets, '');
        return;
      }

      // Sinon → migration inter-coffre
      await migrateSecretsToEngine(dragData.secrets, dragData.sourceEngine, dragData.sourceVersion, targetEngine);

    } catch (err) {
      secureLogger.error('[Drop] Erreur');
      showToast(t('error.retrieveSecret'), 'error');
    }
  };

  /**
   * Gestionnaire de drop sur un dossier (déplacement intra-coffre)
   */
  const handleDropOnFolder = async (e, targetFolder) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverTarget(null);
    setIsDragging(false);

    try {
      const dragData = JSON.parse(e.dataTransfer.getData('application/json'));

      if (dragData.type !== 'secrets' || !Array.isArray(dragData.secrets) || !dragData.secrets.length) {
        return;
      }
      // SÉCURITÉ: Valider les données du drag-and-drop
      if (dragData.secrets.length > 500) return;
      if (dragData.secrets.some(n => typeof n !== 'string' || n.includes('..') || /[\x00-\x1F]/.test(n) || n.length > 512)) return;

      // Vérifier qu'on est dans le même engine
      if (dragData.sourceEngine !== selectedEngine?.name) {
        showToast(t('migrate.noWritableEngines'), 'warning');
        return;
      }

      // Lancer le déplacement vers le dossier
      await moveSecretsToFolder(dragData.secrets, targetFolder);

    } catch (err) {
      secureLogger.error('[Drop] Erreur dossier');
      showToast(t('error.retrieveSecret'), 'error');
    }
  };

  return {
    isDragging,
    dragOverTarget,
    handleDragStart,
    handleDragEnd,
    handleDragOver,
    handleDragLeave,
    handleDropOnEngine,
    handleDropOnFolder
  };
}
