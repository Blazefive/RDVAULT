import { useState } from 'react';
import secureLogger from '../secureLogger';
import { entryKeyEngine } from './useSelection';

/**
 * Hook useDragDrop — gère le drag & drop de secrets entre engines et dossiers
 *
 * @param {Object} options
 * @param {{ current: Array|null }} [options.displayedSecretsRef] - Lignes affichées par le tableau
 *   (useSelection / SecretsTable). Fourni, seules les entrées AFFICHÉES du coffre sélectionné sont
 *   emportées par un glisser (APP-4, défense en profondeur).
 */
export function useDragDrop({
  selectedSecrets,
  setSelectedSecrets,
  isSecretSelected,
  migrateSecretsToEngine,
  moveSecretsToFolder,
  selectedEngine,
  secretEngines,
  displayedSecretsRef,
  showToast,
  t
}) {
  const [isDragging, setIsDragging] = useState(false);
  const [dragOverTarget, setDragOverTarget] = useState(null);

  /**
   * APP-4 (défense en profondeur) : noms réellement déplaçables depuis le coffre sélectionné.
   * La sélection est indexée par nom : une sélection restée d'un autre coffre (homonymes), une entrée
   * sélectionnée puis masquée par la recherche ou par le dossier ouvert, ou la clé « coffre + nom » d'un
   * résultat d'un autre coffre ne doivent jamais partir avec le glisser. Ne sont gardés que les noms
   * d'entrées affichées (ni dossier, ni entrée supprimée) appartenant au coffre sélectionné. Sans liste
   * affichée fournie, seules les clés composées d'autres coffres sont écartées.
   */
  const draggableNames = (names) => {
    const kept = names.filter(n => typeof n === 'string' && n !== '' && !entryKeyEngine(n));
    const shown = displayedSecretsRef && Array.isArray(displayedSecretsRef.current) ? displayedSecretsRef.current : null;
    if (!shown) return kept;
    const engineName = selectedEngine?.name;
    const allowed = new Set();
    for (const row of shown) {
      if (!row || typeof row.name !== 'string' || row.isFolder || row.deleted) continue;
      if (row.engineName && row.engineName !== engineName) continue;
      allowed.add(row.name);
    }
    return kept.filter(n => allowed.has(n));
  };

  /**
   * Gestionnaire de début de drag
   */
  const handleDragStart = (e, secret) => {
    // Entrée glissée absente des lignes affichées du coffre sélectionné (ligne périmée, autre coffre) :
    // aucun glisser, la sélection n'est pas emportée à sa place
    if (!secret || !draggableNames([secret.name]).length) {
      if (e && typeof e.preventDefault === 'function') e.preventDefault();
      return;
    }
    const inSelection = selectedSecrets.has(secret.name);
    const names = inSelection ? draggableNames(Array.from(selectedSecrets)) : [secret.name];

    // Si le secret n'est pas dans la sélection, le sélectionner seul
    if (!inSelection) {
      setSelectedSecrets(new Set([secret.name]));
    }

    // Stocker les données de drag
    const dragData = {
      type: 'secrets',
      secrets: names,
      sourceEngine: selectedEngine?.name,
      sourceVersion: selectedEngine?.version
    };

    e.dataTransfer.setData('application/json', JSON.stringify(dragData));
    e.dataTransfer.effectAllowed = 'move';

    setIsDragging(true);

    // Créer un élément de drag visuel personnalisé
    // Fond « accent-fill » : en thème sombre, --accent est un violet clair destiné au texte
    // (blanc dessus ≈ 2.7:1) ; --accent-fill n'existe qu'en sombre, le thème clair est inchangé.
    // Libell\u00E9 traduit (\u00E9tait \u00AB N entr\u00E9e(s) \u00BB cod\u00E9 en dur en fran\u00E7ais), singulier / pluriel
    const dragCount = dragData.secrets.length;
    const dragGhost = document.createElement('div');
    dragGhost.className = 'drag-ghost';
    const countLabel = t(dragCount === 1 ? 'table.dragCountOne' : 'table.dragCountMany', { count: dragCount });
    dragGhost.textContent = `\u{1F4E6} ${countLabel}`;
    dragGhost.style.cssText = `
      position: absolute;
      top: -1000px;
      left: -1000px;
      padding: 8px 16px;
      background: var(--accent-fill, var(--accent, #3b82f6));
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
      // eslint-disable-next-line no-control-regex -- volontaire : nom d'entrée avec caractère de contrôle refusé
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
      // eslint-disable-next-line no-control-regex -- volontaire : nom d'entrée avec caractère de contrôle refusé
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
