// ========================================
// LOGGER — Journalisation centralisée du processus principal
// ========================================
// Remplace les console.* dispersés. En production (app packagée), seuls
// warn et error sont émis. RDVAULT_LOG_LEVEL=debug|info|warn|error force le niveau.
//
// Règle : ne jamais passer de secret, de token ni d'URL complète (query string)
// à ce logger. Utiliser safeUrl() pour journaliser une URL.

'use strict';

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };

function isPackaged() {
  try {
    return Boolean(require('electron').app?.isPackaged);
  } catch {
    return false;
  }
}

const envLevel = String(process.env.RDVAULT_LOG_LEVEL || '').toLowerCase();
const minLevel = envLevel in LEVELS ? LEVELS[envLevel] : (isPackaged() ? LEVELS.warn : LEVELS.debug);

function make(level, sink) {
  return (...args) => {
    if (LEVELS[level] >= minLevel) sink(...args);
  };
}

/** Réduit une URL à origin + pathname (pas de query string ni de credentials) */
function safeUrl(url) {
  try {
    const u = new URL(String(url));
    return `${u.origin}${u.pathname}`;
  } catch {
    return '[url invalide]';
  }
}

module.exports = {
  debug: make('debug', console.log),
  info: make('info', console.log),
  warn: make('warn', console.warn),
  error: make('error', console.error),
  safeUrl,
};
