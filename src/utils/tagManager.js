// src/utils/tagManager.js
// Utilitaire pour gérer les tags personnalisés et partagés

/**
 * Tags personnalisés : stockés localement pour chaque utilisateur
 * Tags partagés : stockés dans Vault sous un engine spécial "tags-shared"
 */

const TAGS_STORAGE_KEY = 'rdvault-user-tags';

// ========================================
// TAGS PERSONNALISÉS (localStorage)
// ========================================

/**
 * Récupérer tous les tags personnalisés de l'utilisateur
 * @returns {string[]} Liste des tags
 */
export function getUserTags() {
  try {
    const stored = localStorage.getItem(TAGS_STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch (err) {
    console.error('Erreur lecture tags utilisateur:', err);
    return [];
  }
}

/**
 * Sauvegarder les tags personnalisés de l'utilisateur
 * @param {string[]} tags - Liste des tags
 */
export function saveUserTags(tags) {
  try {
    const uniqueTags = [...new Set(tags)].filter(t => t && t.trim());
    localStorage.setItem(TAGS_STORAGE_KEY, JSON.stringify(uniqueTags));
  } catch (err) {
    console.error('Erreur sauvegarde tags utilisateur:', err);
  }
}

/**
 * Ajouter un nouveau tag personnalisé
 * @param {string} tag - Nouveau tag
 */
export function addUserTag(tag) {
  if (!tag || !tag.trim()) return;
  const tags = getUserTags();
  const normalizedTag = normalizeTag(tag);
  if (!tags.includes(normalizedTag)) {
    tags.push(normalizedTag);
    saveUserTags(tags);
  }
}

/**
 * Supprimer un tag personnalisé
 * @param {string} tag - Tag à supprimer
 */
export function removeUserTag(tag) {
  const tags = getUserTags();
  const filtered = tags.filter(t => t !== tag);
  saveUserTags(filtered);
}

// ========================================
// TAGS PARTAGÉS (Vault)
// ========================================

/**
 * Récupérer tous les tags partagés depuis Vault
 * @param {string} vaultUrl - URL de Vault
 * @param {object} headers - Headers avec token
 * @param {function} axiosConfig - Config axios
 * @returns {Promise<string[]>} Liste des tags partagés
 */
export async function getSharedTags(vaultUrl, headers, axiosConfig, axios) {
  try {
    const res = await axios.get(
      `${vaultUrl}/v1/tags-shared/data/tags`,
      axiosConfig({ headers })
    );
    return res.data?.data?.data?.tags || [];
  } catch (err) {
    // Si le secret n'existe pas ou pas d'accès, retourner une liste vide
    if (err.response?.status === 404 || err.response?.status === 403) {
      return [];
    }
    throw err;
  }
}

/**
 * Sauvegarder les tags partagés dans Vault
 * @param {string} vaultUrl - URL de Vault
 * @param {string[]} tags - Liste des tags
 * @param {object} headers - Headers avec token
 * @param {function} axiosConfig - Config axios
 */
export async function saveSharedTags(vaultUrl, tags, headers, axiosConfig, axios) {
  const uniqueTags = [...new Set(tags)].filter(t => t && t.trim());
  await axios.post(
    `${vaultUrl}/v1/tags-shared/data/tags`,
    {
      data: {
        tags: uniqueTags
      }
    },
    axiosConfig({ headers })
  );
}

/**
 * Ajouter un tag partagé
 * @param {string} vaultUrl - URL de Vault
 * @param {string} tag - Nouveau tag
 * @param {object} headers - Headers avec token
 * @param {function} axiosConfig - Config axios
 */
export async function addSharedTag(vaultUrl, tag, headers, axiosConfig, axios) {
  if (!tag || !tag.trim()) return;
  const tags = await getSharedTags(vaultUrl, headers, axiosConfig, axios);
  const normalizedTag = normalizeTag(tag);
  if (!tags.includes(normalizedTag)) {
    tags.push(normalizedTag);
    await saveSharedTags(vaultUrl, tags, headers, axiosConfig, axios);
  }
}

/**
 * Supprimer un tag partagé
 * @param {string} vaultUrl - URL de Vault
 * @param {string} tag - Tag à supprimer
 * @param {object} headers - Headers avec token
 * @param {function} axiosConfig - Config axios
 */
export async function removeSharedTag(vaultUrl, tag, headers, axiosConfig, axios) {
  const tags = await getSharedTags(vaultUrl, headers, axiosConfig, axios);
  const filtered = tags.filter(t => t !== tag);
  await saveSharedTags(vaultUrl, filtered, headers, axiosConfig, axios);
}

// ========================================
// UTILITAIRES
// ========================================

/**
 * Normaliser un tag (lowercase, trim, préfixe #)
 * @param {string} tag - Tag à normaliser
 * @returns {string} Tag normalisé
 */
export function normalizeTag(tag) {
  if (!tag) return '';
  let normalized = tag.trim().toLowerCase();
  // Ajouter # au début si absent
  if (!normalized.startsWith('#')) {
    normalized = '#' + normalized;
  }
  return normalized;
}

/**
 * Parser les tags d'une chaîne (séparés par espaces, virgules ou points-virgules)
 * @param {string} tagsString - Chaîne contenant les tags
 * @returns {string[]} Liste des tags normalisés
 */
export function parseTags(tagsString) {
  if (!tagsString || typeof tagsString !== 'string') return [];
  return tagsString
    .split(/[\s,;]+/)
    .map(t => normalizeTag(t))
    .filter(t => t && t.length > 1); // Au moins # + 1 caractère
}

/**
 * Formatter les tags pour affichage (array → string)
 * @param {string[]} tags - Liste des tags
 * @returns {string} Tags formatés pour affichage
 */
export function formatTags(tags) {
  if (!tags || !Array.isArray(tags)) return '';
  return tags.join(' ');
}

/**
 * Générer une couleur aléatoire pour un nouveau tag
 * @returns {string} Couleur hexadécimale
 */
export function getRandomColor() {
  const colors = [
    '#3b82f6', // blue
    '#10b981', // green
    '#f59e0b', // amber
    '#ef4444', // red
    '#8b5cf6', // violet
    '#ec4899', // pink
    '#06b6d4', // cyan
    '#f97316', // orange
    '#84cc16', // lime
    '#6366f1', // indigo
  ];
  return colors[Math.floor(Math.random() * colors.length)];
}

// ========================================
// MIGRATION DES TAGS
// ========================================

/**
 * Extraire tous les tags depuis une liste de secrets
 * @param {Array} secrets - Liste des secrets
 * @returns {string[]} Liste des tags uniques trouvés
 */
export function extractTagsFromSecrets(secrets) {
  const allTags = new Set();

  if (!Array.isArray(secrets)) return [];

  secrets.forEach(secret => {
    if (secret?.tags && typeof secret.tags === 'string') {
      const tags = parseTags(secret.tags);
      tags.forEach(tag => allTags.add(tag));
    }
  });

  return Array.from(allTags).sort();
}

/**
 * Migrer les tags des secrets vers les tags partagés
 * Cette fonction copie tous les tags trouvés dans les secrets vers le coffre "tags-shared"
 * sans supprimer les tags des entrées elles-mêmes
 *
 * @param {string} vaultUrl - URL de Vault
 * @param {Array} secrets - Liste de tous les secrets depuis lesquels extraire les tags
 * @param {object} headers - Headers avec token
 * @param {function} axiosConfig - Config axios
 * @param {object} axios - Instance axios
 * @returns {Promise<{total: number, added: number, existing: number}>} Statistiques de la migration
 */
export async function migrateTagsToShared(vaultUrl, secrets, headers, axiosConfig, axios) {
  try {
    // 1. Extraire tous les tags depuis les secrets
    const discoveredTags = extractTagsFromSecrets(secrets);
    console.log('[TAG-MIGRATION] Tags découverts dans les secrets:', discoveredTags);

    // 2. Récupérer les tags partagés existants
    const existingSharedTags = await getSharedTags(vaultUrl, headers, axiosConfig, axios);
    console.log('[TAG-MIGRATION] Tags partagés existants:', existingSharedTags);

    // 3. Fusionner les tags (sans doublons)
    const existingSet = new Set(existingSharedTags);
    const newTags = discoveredTags.filter(tag => !existingSet.has(tag));

    console.log('[TAG-MIGRATION] Nouveaux tags à ajouter:', newTags);

    // 4. Sauvegarder la liste complète dans le coffre partagé
    if (newTags.length > 0) {
      const allTags = [...existingSharedTags, ...newTags].sort();
      await saveSharedTags(vaultUrl, allTags, headers, axiosConfig, axios);
      console.log('[TAG-MIGRATION] Migration terminée avec succès');
    } else {
      console.log('[TAG-MIGRATION] Aucun nouveau tag à migrer');
    }

    // 5. Retourner les statistiques
    return {
      total: discoveredTags.length,
      added: newTags.length,
      existing: existingSharedTags.length
    };
  } catch (err) {
    console.error('[TAG-MIGRATION] Erreur lors de la migration:', err);
    throw err;
  }
}
