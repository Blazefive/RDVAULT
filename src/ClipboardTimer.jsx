// src/ClipboardTimer.jsx
// Composant isolé pour éviter que les re-renders du countdown n'affectent les modaux
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from './i18n';

export default function ClipboardTimer({
  fieldName,
  duration = 12000,
  startTime, // Timestamp de début passé par le parent pour stabilité
  onClear,
  onExpire
}) {
  const { t } = useTranslation();
  const [remaining, setRemaining] = useState(() => {
    // Calculer le temps restant initial basé sur startTime
    const elapsed = Date.now() - startTime;
    return Math.max(0, duration - elapsed);
  });

  // Animation d'entrée uniquement au montage
  const [isEntering, setIsEntering] = useState(true);

  const intervalRef = useRef(null);
  const onExpireRef = useRef(onExpire);

  // Garder la référence onExpire à jour sans déclencher le useEffect
  useEffect(() => {
    onExpireRef.current = onExpire;
  }, [onExpire]);

  // Retirer la classe d'animation après qu'elle soit jouée
  useEffect(() => {
    const timer = setTimeout(() => setIsEntering(false), 400);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    // Calculer le temps restant basé sur le startTime fixe
    const calculateRemaining = () => {
      const elapsed = Date.now() - startTime;
      return Math.max(0, duration - elapsed);
    };

    // Initialiser avec le temps correct
    setRemaining(calculateRemaining());

    intervalRef.current = setInterval(() => {
      const newRemaining = calculateRemaining();
      setRemaining(newRemaining);

      if (newRemaining === 0) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
        onExpireRef.current?.();
      }
    }, 100);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [startTime, duration]); // Ne dépend que de startTime et duration

  // UI-32 : annonce « copié » aux lecteurs d'écran. La région live est montée VIDE puis le
  // message y est écrit un instant après : une région insérée déjà remplie n'est pas annoncée
  // par la plupart des lecteurs d'écran. Le compte à rebours, lui, n'est pas annoncé.
  const [announce, setAnnounce] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setAnnounce(true), 100);
    return () => clearTimeout(timer);
  }, []);
  const announcement = announce
    ? `${t('toast.copiedField', { field: fieldName })}. ${t('clipboard.autoClear', { seconds: Math.round(duration / 1000) })}`
    : '';

  const handleClear = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    onClear?.();
  }, [onClear]);

  return (
    <div className={`clipboard-timer${isEntering ? ' entering' : ''}`}>
      <div role="status" aria-live="polite" className="sr-only">{announcement}</div>
      <div className="clipboard-timer-header">
        <span>{t('toast.copiedField', { field: fieldName })}</span>
        <span className="clipboard-timer-countdown">
          {Math.ceil(remaining / 1000)}{t('totp.seconds')}
        </span>
      </div>
      <div className="clipboard-progress">
        <div
          className="clipboard-progress-bar"
          style={{ width: `${(remaining / duration) * 100}%` }}
        />
      </div>
      <button
        onClick={handleClear}
        className="btn btn-sm btn-secondary"
        type="button"
      >
        {t('clipboard.clearNow')}
      </button>
    </div>
  );
}
