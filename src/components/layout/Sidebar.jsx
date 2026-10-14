import React from 'react';

// Séquence d'échappement « %XX » (forme écrite par encodeURIComponent)
const PERCENT_ESCAPE = /%[0-9A-Fa-f]{2}/;
// Caractères qu'un décodage ne doit jamais faire apparaître à l'écran : contrôle (C0, DEL, C1) et marques
// ou isolats de direction (une inversion « U+202E » encodée maquillerait le nom affiché)
// eslint-disable-next-line no-control-regex -- caractères de contrôle volontairement ciblés
const UNSAFE_DECODED = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;

/**
 * Nom de coffre AFFICHÉ (compat 1.5.0) : le serveur local de la 1.5.0 ne décodait pas l'URL et a enregistré
 * certains noms sous leur forme encodée (« Coffre%20%C3%A9quipe », « users/jean.dupont%40exemple.fr/… »).
 * Chaque segment n'est décodé que s'il est EXACTEMENT la forme encodeURIComponent de son décodage (un nom
 * qui contient « % » sans être encodé, ou mal formé, reste tel quel), sans faire apparaître « / » ni
 * caractère de contrôle ou de direction. Affichage seulement : les requêtes, la sélection, le glisser-déposer
 * et les droits utilisent toujours le nom technique renvoyé par le serveur.
 * @param {string} name - Nom technique du coffre
 * @returns {string}
 */
export function engineDisplayName(name) {
  const raw = typeof name === 'string' ? name : String(name ?? '');
  if (!PERCENT_ESCAPE.test(raw)) return raw;
  return raw.split('/').map((segment) => {
    if (!PERCENT_ESCAPE.test(segment)) return segment;
    let decoded;
    try { decoded = decodeURIComponent(segment); } catch { return segment; }
    if (encodeURIComponent(decoded) !== segment) return segment;
    return decoded.includes('/') || UNSAFE_DECODED.test(decoded) ? segment : decoded;
  }).join('/');
}

/**
 * Sidebar — liste des engines avec support drag & drop
 */
export default function Sidebar({
  secretEngines,
  selectedEngine,
  onSelectEngine,
  isDragging,
  dragOverTarget,
  onDragOver,
  onDragLeave,
  onDropOnEngine,
  isAdmin,
  sidebarOpen,
  onEngineRightClick,
  onCreateEngine,
  t
}) {
  return (
    <div className={`sidebar ${sidebarOpen ? "open" : ""}`}>
      <div className="sidebar-header">
        {/* I18N-33 : clé propre au titre (libellé court en russe, « Просмотр хранилища » était
            tronqué) et infobulle : le texte complet reste lisible si l'ellipse s'applique */}
        <h2 title={t('sidebar.title')}>{t('sidebar.title')}</h2>
        <button
          onClick={onCreateEngine}
          className="btn btn-success btn-sm"
          title={t('toolbar.newEngine')}
          type="button"
          style={{ flexShrink: 0, whiteSpace: 'nowrap' }}
        >
          + {t('toolbar.newEngine')}
        </button>
      </div>

      <div className="sidebar-content">
        {secretEngines.map(engine => {
          const active = selectedEngine?.name === engine.name && selectedEngine?.version === engine.version;
          const currentUser = localStorage.getItem('vault-client.username') || '';
          const userPrefix = currentUser ? `users/${currentUser}/` : '';
          const canDelete = !userPrefix || engine.name.startsWith(userPrefix) || engine.name.startsWith(`users/${currentUser}`);

          // Extraire uniquement le nom du coffre pour les coffres personnels (préfixe comparé sur le nom
          // technique), puis décoder un nom 1.5.0 enregistré encodé (affichage seulement)
          const isPersonalVault = engine.name.startsWith(userPrefix);
          const displayName = engineDisplayName(isPersonalVault
            ? engine.name.substring(userPrefix.length)
            : engine.name);

          // Déterminer si ce engine est la cible de drop actuelle
          const isDropTarget = isDragging && dragOverTarget === engine.name;
          // Permettre le drop sur tous les engines avec droits d'écriture
          const canReceiveDrop = engine.canWrite;

          // Clavier : carte focalisable (role="button"), Entrée / Espace sélectionne le coffre ;
          // touche Menu / Maj+F10 déclenche nativement onContextMenu (menu « Supprimer le coffre »).
          return (
            <div
              key={`${engine.name}-${engine.version}-${engine.source || 'auto'}`}
              className={`engine-card ${active ? 'active' : ''} ${isDropTarget ? 'drop-target' : ''}`}
              role="button"
              tabIndex={0}
              aria-current={active ? 'true' : undefined}
              onClick={() => onSelectEngine(engine)}
              onKeyDown={(e) => {
                if (e.target !== e.currentTarget) return;
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelectEngine(engine);
                }
              }}
              onContextMenu={(e) => onEngineRightClick(e, engine)}
              // Gestionnaires Drag & Drop
              onDragOver={(e) => canReceiveDrop && onDragOver(e, engine.name)}
              onDragEnter={(e) => canReceiveDrop && onDragOver(e, engine.name)}
              onDragLeave={onDragLeave}
              onDrop={(e) => canReceiveDrop && onDropOnEngine(e, engine)}
              style={{
                outline: isDropTarget ? '2px dashed var(--accent, #3b82f6)' : undefined,
                background: isDropTarget ? 'var(--bg-selection, rgba(59, 130, 246, 0.15))' : undefined,
                transform: isDropTarget ? 'scale(1.02)' : undefined,
                transition: 'background-color 0.15s ease, transform 0.15s ease'
              }}
            >
              <span className="engine-name">{displayName}</span>
              <div className="engine-card-actions">
                {isAdmin && <span className="badge badge-version">kv{engine.version}</span>}
                {isAdmin && engine.source && <span className="badge badge-source">{engine.source}</span>}
                {!canDelete && isAdmin && (
                  <span className="badge badge-shared">
                    {t('engine.shared')}
                  </span>
                )}
                {/* Indicateur de drop zone pendant le drag (violet de remplissage en sombre : blanc dessus ≥ 4.5:1) */}
                {isDragging && canReceiveDrop && (
                  <span
                    className="badge"
                    aria-hidden="true"
                    style={{ background: 'var(--accent-fill, var(--accent))', color: 'white' }}
                  >
                    {active ? '\u{1F3E0}' : '\u2B07\uFE0F'}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
