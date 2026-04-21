import React, { useState, useEffect } from 'react';

// ========================================
// COMPOSANT WINDOW CONTROLS - Boutons fenêtre frameless (style VS Code)
// ========================================
export default function WindowControls() {
  const [isMaximized, setIsMaximized] = useState(false);

  useEffect(() => {
    // Écouter les changements d'état de la fenêtre
    const handleMaximizeChange = (_event, maximized) => setIsMaximized(maximized);
    if (window.electronWindow?.onMaximizeChange) {
      window.electronWindow.onMaximizeChange(handleMaximizeChange);
    }
    // Vérifier l'état initial
    if (window.electronWindow?.isMaximized) {
      window.electronWindow.isMaximized().then(setIsMaximized).catch(() => {});
    }
    return () => {
      if (window.electronWindow?.removeMaximizeListener) {
        window.electronWindow.removeMaximizeListener(handleMaximizeChange);
      }
    };
  }, []);

  return (
    <div className="window-controls">
      <button onClick={() => window.electronWindow?.minimize()} title="Minimiser" type="button">
        <svg width="10" height="1" viewBox="0 0 10 1"><rect fill="currentColor" width="10" height="1" /></svg>
      </button>
      <button onClick={() => { window.electronWindow?.maximize(); setIsMaximized(m => !m); }} title={isMaximized ? 'Restaurer' : 'Maximiser'} type="button">
        {isMaximized ? (
          /* Icône restaurer : deux carrés superposés */
          <svg width="10" height="10" viewBox="0 0 10 10">
            <rect fill="none" stroke="currentColor" strokeWidth="1" x="2.5" y="0.5" width="7" height="7" />
            <rect fill="var(--bg-app, #fff)" stroke="currentColor" strokeWidth="1" x="0.5" y="2.5" width="7" height="7" />
          </svg>
        ) : (
          /* Icône maximiser : un seul carré */
          <svg width="10" height="10" viewBox="0 0 10 10">
            <rect fill="none" stroke="currentColor" strokeWidth="1" x="0.5" y="0.5" width="9" height="9" />
          </svg>
        )}
      </button>
      <button className="btn-close" onClick={() => window.electronWindow?.close()} title="Fermer" type="button">
        <svg width="10" height="10" viewBox="0 0 10 10"><path stroke="currentColor" strokeWidth="1.2" d="M1,1 L9,9 M9,1 L1,9" /></svg>
      </button>
    </div>
  );
}
