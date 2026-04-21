// src/LoadingSpinner.jsx
// Composant de chargement avec spinner CSS moderne
import React from 'react';

export default function LoadingSpinner({ message = '', size = 'medium' }) {
  const sizeMap = {
    small: 24,
    medium: 48,
    large: 64
  };

  const spinnerSize = sizeMap[size] || sizeMap.medium;
  const borderWidth = Math.max(3, Math.floor(spinnerSize / 12));

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 'var(--sp-4)',
      gap: 'var(--sp-3)'
    }}>
      {/* Spinner circulaire CSS */}
      <div style={{
        width: `${spinnerSize}px`,
        height: `${spinnerSize}px`,
        border: `${borderWidth}px solid var(--border-subtle, #e5e7eb)`,
        borderTopColor: 'var(--accent-primary, #3b82f6)',
        borderRadius: '50%',
        animation: 'spinner-rotate 0.8s linear infinite',
        boxSizing: 'border-box'
      }} />
      {message && (
        <div style={{
          fontSize: 'var(--text-sm)',
          color: 'var(--text-secondary)'
        }}>
          {message}
        </div>
      )}
      <style>
        {`
          @keyframes spinner-rotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}
      </style>
    </div>
  );
}
