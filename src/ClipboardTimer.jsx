// src/ClipboardTimer.jsx
// Composant isolé pour éviter que les re-renders du countdown n'affectent les modaux
import React, { useState, useEffect, useRef, useCallback } from 'react';

export default function ClipboardTimer({
  fieldName,
  duration = 12000,
  startTime, // Timestamp de début passé par le parent pour stabilité
  onClear,
  onExpire
}) {
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

  const handleClear = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    onClear?.();
  }, [onClear]);

  return (
    <div className={`clipboard-timer${isEntering ? ' entering' : ''}`}>
      <div className="clipboard-timer-header">
        <span>{fieldName} copié</span>
        <span className="clipboard-timer-countdown">
          {Math.ceil(remaining / 1000)}s
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
        Effacer maintenant
      </button>
    </div>
  );
}
