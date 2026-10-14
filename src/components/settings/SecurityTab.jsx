// ========================================
// Paramètres › Sécurité : délai de verrouillage automatique
// ========================================
// L'utilisateur choisit au bout de combien de temps sans activité dans RDVAULT la session est
// fermée (il faut alors se reconnecter). Le choix s'applique immédiatement (le minuteur est réarmé)
// et reste mémorisé sur ce poste. Le délai « poste Windows verrouillé » (3 h) est inchangé.

import React, { useId, useState } from 'react';
import { useTranslation } from '../../i18n';
import {
  IDLE_TIMEOUT_CHOICES_MIN,
  DEFAULT_IDLE_TIMEOUT_MIN,
  getIdleTimeoutMinutes,
  setIdleTimeoutMinutes,
} from '../../hooks/useIdleTimeout';

export default function SecurityTab() {
  const { t } = useTranslation();
  const selectId = useId();
  const descId = useId();
  const [minutes, setMinutes] = useState(getIdleTimeoutMinutes);

  // Libellé d'une durée : « 5 minutes », « 1 heure », « 2 heures »…
  const durationLabel = (m) => {
    const text = m < 60
      ? t(m === 1 ? 'settings.autoLockMinute' : 'settings.autoLockMinutes', { count: m })
      : t(m === 60 ? 'settings.autoLockHour' : 'settings.autoLockHours', { count: m / 60 });
    return m === DEFAULT_IDLE_TIMEOUT_MIN ? `${text} (${t('settings.autoLockDefault')})` : text;
  };

  const onChange = (e) => {
    const value = Number(e.target.value);
    if (setIdleTimeoutMinutes(value)) setMinutes(value);
  };

  return (
    <div>
      <h3 style={{
        fontSize: 'var(--text-lg)',
        fontWeight: 'var(--weight-bold)',
        marginBottom: 'var(--sp-2)',
        color: 'var(--text-primary)'
      }}>
        {t('settings.autoLockTitle')}
      </h3>
      <p id={descId} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)' }}>
        {t('settings.autoLockDesc')}
      </p>
      <label htmlFor={selectId} style={{
        display: 'block',
        fontSize: 'var(--text-sm)',
        fontWeight: 'var(--weight-bold)',
        color: 'var(--text-primary)',
        marginBottom: 'var(--sp-2)'
      }}>
        {t('settings.autoLockLabel')}
      </label>
      <select
        id={selectId}
        data-testid="idle-timeout-select"
        aria-describedby={descId}
        value={String(minutes)}
        onChange={onChange}
        style={{
          width: '100%',
          maxWidth: '320px',
          padding: 'var(--sp-2) var(--sp-3)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius)',
          background: 'var(--bg-surface)',
          color: 'var(--text-primary)',
          fontSize: 'var(--text-base)',
          marginBottom: 'var(--sp-4)'
        }}
      >
        {IDLE_TIMEOUT_CHOICES_MIN.map((m) => (
          <option key={m} value={String(m)}>{durationLabel(m)}</option>
        ))}
      </select>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
        {t('settings.autoLockLockedNote')}
      </p>
    </div>
  );
}
