// src/VersionHistoryModal.jsx
import React, { useEffect, useState, useCallback } from 'react';
import { useTranslation } from './i18n';

export default function VersionHistoryModal({
  secretName,
  engine,
  vaultUrl,
  baseHeaders,
  axiosConfig,
  onClose,
  onRestore,
  showToast
}) {
  const [versions, setVersions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedVersion, setSelectedVersion] = useState(null);
  const [versionData, setVersionData] = useState(null);
  const [loadingData, setLoadingData] = useState(false);
  const { t } = useTranslation();

  useEffect(() => {
    fetchVersions();
  }, []);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  const fetchVersions = async () => {
    if (!engine || engine.version !== 2) {
      showToast('Le versioning n\'est disponible que pour KV v2', 'error');
      onClose();
      return;
    }

    try {
      setLoading(true);
      const axios = (await import('axios')).default;
      const metaRes = await axios.get(
        `${vaultUrl}/v1/${engine.name.split('/').map(s => encodeURIComponent(s)).join('/')}/metadata/${encodeURIComponent(secretName)}`,
        axiosConfig({ headers: baseHeaders() })
      );

      const versionsData = metaRes.data?.data?.versions || {};
      const versionsList = Object.entries(versionsData).map(([version, data]) => ({
        version: Number(version),
        createdTime: data.created_time,
        deletionTime: data.deletion_time,
        destroyed: data.destroyed
      })).sort((a, b) => b.version - a.version);

      setVersions(versionsList);
    } catch (err) {
      showToast(t('error.versionsLoad'), 'error');
      onClose();
    } finally {
      setLoading(false);
    }
  };

  const loadVersionData = async (version) => {
    try {
      setLoadingData(true);
      setSelectedVersion(version);
      const axios = (await import('axios')).default;
      const dataRes = await axios.get(
        `${vaultUrl}/v1/${engine.name.split('/').map(s => encodeURIComponent(s)).join('/')}/data/${encodeURIComponent(secretName)}?version=${encodeURIComponent(version)}`,
        axiosConfig({ headers: baseHeaders() })
      );

      const data = dataRes.data?.data?.data || {};
      setVersionData(data);
    } catch (err) {
      showToast(t('error.versionLoad'), 'error');
      setVersionData(null);
    } finally {
      setLoadingData(false);
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('fr-FR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '900px', maxHeight: '80vh', display: 'flex', flexDirection: 'column' }}
      >
        <div className="modal-header">
          <h2>{t('versionHistory.title')}</h2>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', fontWeight: 'normal' }}>
            {secretName}
          </div>
        </div>

        <div className="modal-body" style={{ flex: 1, overflow: 'hidden', display: 'flex', gap: 'var(--sp-4)' }}>
          {/* Liste des versions */}
          <div style={{ flex: '0 0 250px', overflowY: 'auto' }}>
            {loading ? (
              <div style={{ padding: 'var(--sp-4)', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                {t('versionHistory.loading')}
              </div>
            ) : versions.length === 0 ? (
              <div style={{ padding: 'var(--sp-4)', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                {t('versionHistory.noVersions')}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                {versions.map((v) => (
                  <button
                    key={v.version}
                    onClick={() => loadVersionData(v.version)}
                    className={selectedVersion === v.version ? 'version-item selected' : 'version-item'}
                    type="button"
                    disabled={v.destroyed}
                    style={{
                      padding: 'var(--sp-3)',
                      border: selectedVersion === v.version ? '2px solid var(--accent)' : '1px solid var(--border)',
                      background: v.destroyed ? 'var(--bg-surface)' : selectedVersion === v.version ? 'var(--bg-surface-active)' : 'var(--bg-surface)',
                      borderRadius: 'var(--radius-md)',
                      textAlign: 'left',
                      cursor: v.destroyed ? 'not-allowed' : 'pointer',
                      opacity: v.destroyed ? 0.5 : 1
                    }}
                  >
                    <div style={{ fontWeight: 'var(--weight-bold)', color: 'var(--text-primary)' }}>
                      {t('versionHistory.version', { n: v.version })}
                    </div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginTop: 'var(--sp-1)' }}>
                      {formatDate(v.createdTime)}
                    </div>
                    {v.deletionTime && !v.destroyed && (
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--warning)', marginTop: 'var(--sp-1)' }}>
                        {t('versionHistory.deleted')}
                      </div>
                    )}
                    {v.destroyed && (
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--error)', marginTop: 'var(--sp-1)' }}>
                        {t('versionHistory.deleted')}
                      </div>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Détails de la version */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loadingData ? (
              <div style={{ padding: 'var(--sp-4)', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                {t('versionHistory.loading')}
              </div>
            ) : selectedVersion && versionData ? (
              <div>
                <div style={{ marginBottom: 'var(--sp-4)', padding: 'var(--sp-3)', background: 'var(--bg-app)', borderRadius: 'var(--radius-md)' }}>
                  <div style={{ fontWeight: 'var(--weight-bold)', marginBottom: 'var(--sp-2)' }}>
                    {t('versionHistory.version', { n: selectedVersion })}
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
                  {Object.entries(versionData).map(([key, value]) => {
                    // SÉCURITÉ: Masquer les mots de passe par défaut
                    const isSensitive = /password|secret|token|key|totp|private|credential|ssh_key|apikey|api_key/i.test(key);
                    return (
                    <div key={key} style={{ padding: 'var(--sp-3)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-md)' }}>
                      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: 'var(--sp-1)' }}>
                        {key}
                      </div>
                      <div style={{
                        fontFamily: key === 'Password' ? 'var(--font-mono)' : 'inherit',
                        color: 'var(--text-primary)',
                        wordBreak: 'break-all'
                      }}>
                        {isSensitive ? '••••••••' : String(value || '')}
                      </div>
                    </div>
                    );
                  })}
                </div>

                {onRestore && (
                  <div style={{ marginTop: 'var(--sp-4)' }}>
                    <button
                      onClick={() => {
                        onRestore(selectedVersion, versionData);
                        onClose();
                      }}
                      className="btn btn-primary"
                      type="button"
                    >
                      {t('versionHistory.restore')}
                    </button>
                  </div>
                )}
              </div>
            ) : selectedVersion ? (
              <div style={{ padding: 'var(--sp-4)', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                Impossible de charger les données de cette version
              </div>
            ) : (
              <div style={{ padding: 'var(--sp-4)', textAlign: 'center', color: 'var(--text-tertiary)' }}>
                Sélectionnez une version pour voir ses détails
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button onClick={onClose} className="btn btn-secondary" type="button">
            {t('versionHistory.close')}
          </button>
        </div>
      </div>
    </div>
  );
}
