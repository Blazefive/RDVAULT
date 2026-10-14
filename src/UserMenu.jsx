// src/UserMenu.jsx
// Menu utilisateur (bouton de menu, WAI-ARIA APG « Menu Button ») :
// - déclencheur : aria-haspopup="menu" + aria-expanded, nom accessible « Connecté en tant que … » ;
// - à l'ouverture, focus sur le premier élément ; flèches haut/bas, Début/Fin pour naviguer ;
// - Échap ferme et rend le focus au déclencheur ; le menu se ferme aussi quand le focus le quitte
//   (Tab) ou sur un clic extérieur ;
// - une action rend d'abord le focus au déclencheur : la modale ouverte le lui rendra à sa fermeture.
import React, { useState, useEffect, useId, useRef } from 'react';
import { useTranslation } from './i18n';

export default function UserMenu({ username, onLogout, darkMode, onToggleDarkMode, isAdmin, isModerator, currentView, onToggleAdminView, onOpenSettings, onOpenPasswordHealth, onOpenPasskeys, onOpenPasswordGenerator }) {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef(null);
  const triggerRef = useRef(null);
  const dropdownRef = useRef(null);
  const menuId = useId();

  const menuItems = () => Array.from(dropdownRef.current?.querySelectorAll('[role="menuitem"]') || []);

  // Ouverture : focus sur le premier élément du menu
  useEffect(() => {
    if (isOpen) dropdownRef.current?.querySelector('[role="menuitem"]')?.focus();
  }, [isOpen]);

  const closeAndFocusTrigger = () => {
    setIsOpen(false);
    triggerRef.current?.focus();
  };

  // Action d'un élément : focus rendu au déclencheur AVANT l'action (élément du menu démonté ensuite)
  const runItem = (action) => {
    triggerRef.current?.focus();
    setIsOpen(false);
    action && action();
  };

  const handleMenuKeyDown = (e) => {
    if (!isOpen) return;
    const items = menuItems();
    const index = items.indexOf(document.activeElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      closeAndFocusTrigger();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!items.length) return;
      const delta = e.key === 'ArrowDown' ? 1 : -1;
      const next = index < 0 ? (delta > 0 ? 0 : items.length - 1) : (index + delta + items.length) % items.length;
      items[next].focus();
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      (e.key === 'Home' ? items[0] : items[items.length - 1])?.focus();
    }
  };

  // Ouverture au clavier depuis le déclencheur (flèche bas / haut)
  const handleTriggerKeyDown = (e) => {
    if (!isOpen && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      setIsOpen(true);
    }
  };

  // Fermeture quand le focus quitte le menu (Tab, clic ailleurs)
  const handleBlur = (e) => {
    if (isOpen && menuRef.current && !menuRef.current.contains(e.relatedTarget)) {
      setIsOpen(false);
    }
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const getInitials = (name) => {
    if (!name) return 'U';
    const parts = name.split(/[\s._-]+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
  };

  return (
    <div className="user-menu" ref={menuRef} onKeyDown={handleMenuKeyDown} onBlur={handleBlur}>
      <button
        ref={triggerRef}
        className="user-menu-trigger"
        onClick={() => setIsOpen(!isOpen)}
        onKeyDown={handleTriggerKeyDown}
        type="button"
        title={t('user.connectedAs', { name: username })}
        aria-label={t('user.connectedAs', { name: username })}
        aria-haspopup="menu"
        aria-expanded={isOpen}
        aria-controls={isOpen ? menuId : undefined}
      >
        <div className="user-avatar" aria-hidden="true">
          {getInitials(username)}
        </div>
        <span className="user-menu-name">{username}</span>
        <svg
          className={`user-menu-arrow ${isOpen ? 'open' : ''}`}
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M4 6L8 10L12 6"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>

      {isOpen && (
        // tabIndex -1 : un clic sur une zone non interactive du menu y garde le focus (pas de fermeture)
        <div className="user-menu-dropdown" id={menuId} role="menu" aria-label={username} ref={dropdownRef} tabIndex={-1}>
          <div className="user-menu-header" role="none">
            <div className="user-avatar-large" aria-hidden="true">
              {getInitials(username)}
            </div>
            <div className="user-menu-info">
              <div className="user-menu-username">{username}</div>
              <div className="user-menu-status">{t('user.connected')}</div>
            </div>
          </div>

          <div className="user-menu-separator" role="separator" />

          {(isAdmin || isModerator) && (
            <>
              <button
                className="user-menu-item user-menu-item-admin"
                role="menuitem"
                tabIndex={-1}
                onClick={() => runItem(onToggleAdminView)}
                type="button"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                  <path
                    d="M12 2L2 7L12 12L22 7L12 2Z"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M2 17L12 22L22 17"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M2 12L12 17L22 12"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                {currentView === 'admin' ? t('toolbar.vaultView') : t('toolbar.adminView')}
              </button>
              <div className="user-menu-separator" role="separator" />
            </>
          )}

          <button
            className="user-menu-item"
            role="menuitem"
            tabIndex={-1}
            onClick={() => runItem(onOpenSettings)}
            type="button"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            {t('toolbar.settings')}
          </button>

          {onOpenPasswordGenerator && (
            <button
              className="user-menu-item"
              role="menuitem"
              tabIndex={-1}
              onClick={() => runItem(onOpenPasswordGenerator)}
              type="button"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <rect x="3" y="3" width="18" height="18" rx="3" />
                <circle cx="8.5" cy="8.5" r="1.2" fill="currentColor" />
                <circle cx="15.5" cy="8.5" r="1.2" fill="currentColor" />
                <circle cx="12" cy="12" r="1.2" fill="currentColor" />
                <circle cx="8.5" cy="15.5" r="1.2" fill="currentColor" />
                <circle cx="15.5" cy="15.5" r="1.2" fill="currentColor" />
              </svg>
              {t('passwordGenerator.title')}
            </button>
          )}

          {onOpenPasswordHealth && (
            <button
              className="user-menu-item"
              role="menuitem"
              tabIndex={-1}
              onClick={() => runItem(onOpenPasswordHealth)}
              type="button"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
              {t('user.passwordHealth')}
            </button>
          )}

          {onOpenPasskeys && (
            <button
              className="user-menu-item"
              role="menuitem"
              tabIndex={-1}
              onClick={() => runItem(onOpenPasskeys)}
              type="button"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="8" cy="12" r="4" />
                <path d="M12 12h9" />
                <path d="M18 12v3" />
                <path d="M15 12v2" />
              </svg>
              {t('user.passkeys')}
            </button>
          )}

          <div className="user-menu-separator" role="separator" />

          <button
            className="user-menu-item user-menu-item-logout"
            role="menuitem"
            tabIndex={-1}
            onClick={() => runItem(onLogout)}
            type="button"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path
                d="M9 21H5C4.46957 21 3.96086 20.7893 3.58579 20.4142C3.21071 20.0391 3 19.5304 3 19V5C3 4.46957 3.21071 3.96086 3.58579 3.58579C3.96086 3.21071 4.46957 3 5 3H9"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M16 17L21 12L16 7"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M21 12H9"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            {t('toolbar.logout')}
          </button>
        </div>
      )}
    </div>
  );
}
