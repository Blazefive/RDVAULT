// ========================================
// MODULE: Brute Force Protection
// ========================================
// Protection contre les attaques par force brute sur le login.
//
// Stratégie:
// - Limite le nombre de tentatives par utilisateur
// - Délai exponentiel après échecs répétés (exponential backoff)
// - Blocage temporaire après trop d'échecs
// - Reset automatique après succès
//
// Sécurité:
// - Protection contre credential stuffing
// - Ralentissement des attaques automatisées
// - Logging des tentatives suspectes

/**
 * Classe pour gérer la protection brute force
 */
class BruteForceProtection {
  constructor(options = {}) {
    // Configuration
    this.maxAttempts = options.maxAttempts || 5; // Tentatives max avant blocage
    this.blockDurationMs = options.blockDurationMs || 300000; // 5 minutes de blocage
    this.attemptWindowMs = options.attemptWindowMs || 900000; // Fenêtre de 15 minutes
    this.exponentialBase = options.exponentialBase || 2; // Base pour délai exponentiel

    // État
    this.attempts = new Map(); // username -> [timestamps]
    this.blocked = new Map(); // username -> blockedUntil timestamp
    this.cleanupInterval = null;

    // SÉCURITÉ: Restaurer l'état depuis sessionStorage (survit au rechargement de page)
    this._restoreState();
    // Démarrer le nettoyage périodique
    this._startCleanup();
  }

  /**
   * Restaure l'état depuis sessionStorage
   * @private
   */
  _restoreState() {
    try {
      const saved = sessionStorage.getItem('rdvault-bf-state');
      if (saved) {
        const state = JSON.parse(saved);
        if (state.attempts) {
          for (const [k, v] of Object.entries(state.attempts)) {
            if (Array.isArray(v)) this.attempts.set(k, v);
          }
        }
        if (state.blocked) {
          for (const [k, v] of Object.entries(state.blocked)) {
            if (typeof v === 'number') this.blocked.set(k, v);
          }
        }
      }
    } catch { /* ignore corrupt data */ }
  }

  /**
   * Persiste l'état dans sessionStorage
   * @private
   */
  _persistState() {
    try {
      const state = {
        attempts: Object.fromEntries(this.attempts),
        blocked: Object.fromEntries(this.blocked)
      };
      sessionStorage.setItem('rdvault-bf-state', JSON.stringify(state));
    } catch { /* ignore */ }
  }

  /**
   * Enregistre une tentative de connexion échouée
   *
   * @param {string} username - Username
   * @returns {Object} { blocked: boolean, remainingAttempts: number, retryAfterMs: number }
   */
  registerFailedAttempt(username) {
    if (!username) {
      throw new Error('Username requis');
    }

    const now = Date.now();
    const normalizedUsername = username.toLowerCase();

    // Vérifier si déjà bloqué
    if (this.isBlocked(normalizedUsername)) {
      const blockedUntil = this.blocked.get(normalizedUsername);
      const retryAfterMs = blockedUntil - now;

      // SÉCURITÉ: Ne pas logger le username

      return {
        blocked: true,
        remainingAttempts: 0,
        retryAfterMs: Math.max(0, retryAfterMs),
        message: `Compte temporairement bloqué. Réessayez dans ${Math.ceil(retryAfterMs / 1000)} secondes.`
      };
    }

    // Récupérer les tentatives existantes
    if (!this.attempts.has(normalizedUsername)) {
      this.attempts.set(normalizedUsername, []);
    }

    const userAttempts = this.attempts.get(normalizedUsername);

    // Nettoyer les anciennes tentatives (hors fenêtre)
    const recentAttempts = userAttempts.filter(t => now - t < this.attemptWindowMs);
    recentAttempts.push(now);
    this.attempts.set(normalizedUsername, recentAttempts);

    const attemptCount = recentAttempts.length;
    const remainingAttempts = Math.max(0, this.maxAttempts - attemptCount);

    // Calculer le délai d'attente (exponential backoff)
    const delayMs = this._calculateDelay(attemptCount);

    // Bloquer si trop de tentatives
    if (attemptCount >= this.maxAttempts) {
      this.blocked.set(normalizedUsername, now + this.blockDurationMs);
      this._persistState();

      return {
        blocked: true,
        remainingAttempts: 0,
        retryAfterMs: this.blockDurationMs,
        message: `Trop de tentatives échouées. Compte bloqué pour ${this.blockDurationMs / 60000} minutes.`
      };
    }

    // SÉCURITÉ: Appliquer le délai exponentiel comme un blocage temporaire
    if (delayMs > 0) {
      this.blocked.set(normalizedUsername, now + delayMs);
    }

    this._persistState();
    return {
      blocked: false,
      remainingAttempts,
      retryAfterMs: delayMs,
      message: `Tentative échouée. ${remainingAttempts} tentative(s) restante(s) avant blocage.`
    };
  }

  /**
   * Enregistre une connexion réussie (reset des tentatives)
   *
   * @param {string} username - Username
   */
  registerSuccessfulAttempt(username) {
    if (!username) return;

    const normalizedUsername = username.toLowerCase();

    // Supprimer les tentatives et blocages
    this.attempts.delete(normalizedUsername);
    this.blocked.delete(normalizedUsername);
    this._persistState();
  }

  /**
   * Vérifie si un utilisateur est bloqué
   *
   * @param {string} username - Username
   * @returns {boolean} true si bloqué
   */
  isBlocked(username) {
    if (!username) return false;

    const normalizedUsername = username.toLowerCase();
    const now = Date.now();

    if (!this.blocked.has(normalizedUsername)) {
      return false;
    }

    const blockedUntil = this.blocked.get(normalizedUsername);

    // Débloquer si le temps est écoulé
    if (now >= blockedUntil) {
      this.blocked.delete(normalizedUsername);
      return false;
    }

    return true;
  }

  /**
   * Calcule le délai d'attente (exponential backoff)
   *
   * @param {number} attemptCount - Nombre de tentatives
   * @returns {number} Délai en ms
   * @private
   */
  _calculateDelay(attemptCount) {
    if (attemptCount <= 1) return 0;

    // Délai exponentiel: 2^(n-1) secondes
    // Tentative 2: 2^1 = 2s
    // Tentative 3: 2^2 = 4s
    // Tentative 4: 2^3 = 8s
    // Tentative 5: 2^4 = 16s
    const delaySeconds = Math.pow(this.exponentialBase, attemptCount - 1);
    return Math.min(delaySeconds * 1000, 60000); // Max 60 secondes
  }

  /**
   * Obtient les statistiques pour un utilisateur
   *
   * @param {string} username - Username
   * @returns {Object} { attempts: number, blocked: boolean, blockedUntil: number|null }
   */
  getStats(username) {
    if (!username) return null;

    const normalizedUsername = username.toLowerCase();
    const now = Date.now();

    const attempts = this.attempts.get(normalizedUsername) || [];
    const recentAttempts = attempts.filter(t => now - t < this.attemptWindowMs);

    const blockedUntil = this.blocked.get(normalizedUsername);
    const blocked = blockedUntil && now < blockedUntil;

    return {
      attempts: recentAttempts.length,
      blocked,
      blockedUntil: blocked ? blockedUntil : null,
      remainingAttempts: Math.max(0, this.maxAttempts - recentAttempts.length)
    };
  }

  /**
   * Reset manuel d'un utilisateur (admin)
   *
   * @param {string} username - Username
   */
  reset(username) {
    if (!username) return;

    const normalizedUsername = username.toLowerCase();
    this.attempts.delete(normalizedUsername);
    this.blocked.delete(normalizedUsername);

    // Compteurs réinitialisés manuellement
  }

  /**
   * Nettoyage périodique des données obsolètes
   * @private
   */
  _startCleanup() {
    // Nettoyer toutes les 5 minutes
    this.cleanupInterval = setInterval(() => {
      this._cleanup();
    }, 300000);
  }

  /**
   * Nettoie les données obsolètes
   * @private
   */
  _cleanup() {
    const now = Date.now();

    // Nettoyer les tentatives hors fenêtre
    for (const [username, attempts] of this.attempts.entries()) {
      const recentAttempts = attempts.filter(t => now - t < this.attemptWindowMs);

      if (recentAttempts.length === 0) {
        this.attempts.delete(username);
      } else {
        this.attempts.set(username, recentAttempts);
      }
    }

    // Nettoyer les blocages expirés
    for (const [username, blockedUntil] of this.blocked.entries()) {
      if (now >= blockedUntil) {
        this.blocked.delete(username);
      }
    }

    // Nettoyage périodique effectué
  }

  /**
   * Arrête le nettoyage périodique
   */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// Instance singleton
const bruteForceProtection = new BruteForceProtection({
  maxAttempts: 5, // 5 tentatives avant blocage
  blockDurationMs: 300000, // 5 minutes
  attemptWindowMs: 900000, // Fenêtre de 15 minutes
  exponentialBase: 2
});

export default bruteForceProtection;
export { BruteForceProtection };
