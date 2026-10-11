// src/index.js
import React from 'react';
import ReactDOM from 'react-dom/client';
import { I18nProvider, useOptionalTranslation } from './i18n';
import en from './locales/en.json';
import secureLogger from './secureLogger';
import App from './App';

// Texte anglais si l'écran de secours est rendu hors de I18nProvider (repli, jamais une clé brute)
const fallbackT = (key) => key.split('.').reduce((node, part) => (node ? node[part] : undefined), en) || key;

/**
 * Écran de secours (TREE-10) : traduit, sans aucun détail de l'erreur. Le message ou la pile d'une
 * exception levée pendant le rendu peuvent contenir des données de l'interface (nom d'entrée,
 * identifiant, mot de passe) : rien n'en est affiché ni journalisé. Recharger l'interface vide l'état
 * React (jeton de session compris) : une nouvelle connexion est demandée.
 */
function CrashScreen() {
  const i18n = useOptionalTranslation();
  const t = i18n ? i18n.t : fallbackT;
  return (
    <div className="crash-screen" role="alert">
      <h1>{t('crash.title')}</h1>
      <p>{t('crash.message')}</p>
      <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
        {t('crash.reload')}
      </button>
    </div>
  );
}

/**
 * Error boundary racine. Sans elle, une exception de rendu démontait toute la racine React
 * (React 18) : fenêtre transparente vide, sans barre latérale ni menu, et le même plantage à chaque
 * connexion quand la cause est une donnée du coffre (TREE-10 : dossier « constructor »).
 * Placée DANS I18nProvider : l'écran de secours suit la langue de l'interface.
 */
export class RootErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch() {
    // Volontairement sans l'erreur ni la pile de composants (données possibles de l'interface)
    secureLogger.error('[UI] Rendu interrompu : écran de secours affiché');
  }

  render() {
    if (this.state.failed) return <CrashScreen />;
    return this.props.children;
  }
}

// Montage (absent sous Jest, qui importe ce module pour tester RootErrorBoundary)
const container = typeof document !== 'undefined' ? document.getElementById('root') : null;
if (container) {
  const root = ReactDOM.createRoot(container);
  root.render(
    <I18nProvider defaultLang="en">
      <RootErrorBoundary>
        <App />
      </RootErrorBoundary>
    </I18nProvider>
  );
}
