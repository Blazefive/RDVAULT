// ========================================
// COMPOSANT : Mes passkeys — liste et gestion des passkeys stockées dans le coffre
// ========================================
// Lit le secret interne « .rdvault-passkeys » (agrégé par site) et affiche, par site,
// les passkeys enregistrées (compte, date, nombre d'utilisations). Permet d'en supprimer.
// La clé privée n'est JAMAIS affichée : seules les métadonnées publiques le sont.
// Coffre, compatibilité et sérialisation des écritures : mêmes règles que le hook usePasskeys
// (utils/passkeyEngine) — la suppression partage la file d'attente des écritures de l'extension.

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Modal from './common/Modal';
import { createPasskeyStore } from '../utils/passkeyEngine';
import { useTranslation } from '../i18n';

export default function PasskeysModal({ onClose, vaultApi, vaultUrl, secretEngines, authUser, showToast }) {
  const { t, lang } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [groups, setGroups] = useState([]);
  const [confirmId, setConfirmId] = useState(null);

  // Coffre personnel exact de l'utilisateur (users/<nom>/…, « Mes-Secrets » préféré)
  const user = authUser || localStorage.getItem('vault-client.username') || '';
  const store = useMemo(
    () => createPasskeyStore({ vaultApi, vaultUrl, secretEngines, authUser: user }),
    [vaultApi, vaultUrl, secretEngines, user]
  );

  const load = useCallback(async () => {
    setLoading(true); setConfirmId(null);
    if (!store.engine) { setGroups([]); setLoading(false); return; }
    try {
      const { blob } = await store.read();
      const g = Object.entries(blob.items || {})
        .map(([rpId, arr]) => ({
          rpId,
          items: (Array.isArray(arr) ? arr : []).map(p => ({
            credentialId: p.credentialId,
            userName: p.userName || p.userDisplayName || '',
            createdAt: p.createdAt,
            signCount: typeof p.signCount === 'number' ? p.signCount : 0,
          })),
        }))
        .filter(x => x.items.length > 0)
        .sort((a, b) => a.rpId.localeCompare(b.rpId));
      setGroups(g);
    } catch {
      setGroups([]);
      if (showToast) showToast(t('passkeysView.readError'), 'error');
    }
    setLoading(false);
  }, [store, showToast, t]);

  useEffect(() => { load(); }, [load]);

  const deletePasskey = useCallback(async (rpId, credentialId) => {
    if (!store.engine) return;
    try {
      // Relecture + écriture sous la file d'attente (aucune création concurrente perdue) ;
      // contenu hérité de l'ancien emplacement fusionné dans le coffre personnel
      await store.update((blob) => {
        if (!Array.isArray(blob.items[rpId])) return false;
        blob.items[rpId] = blob.items[rpId].filter(p => p.credentialId !== credentialId);
        if (blob.items[rpId].length === 0) delete blob.items[rpId];
        return true;
      });
      if (showToast) showToast(t('passkeysView.deleted'), 'success');
      load();
    } catch {
      if (showToast) showToast(t('passkeysView.deleteError'), 'error');
    }
  }, [store, showToast, t, load]);

  const total = groups.reduce((n, g) => n + g.items.length, 0);

  // Date de création formatée dans la langue de l'application ; vide si absente ou invalide
  const formatCreated = (iso) => {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    try { return d.toLocaleDateString(lang); } catch { return d.toLocaleDateString(); }
  };

  return (
    <Modal
      title={`🔑 ${t('passkeysView.title')}`}
      onClose={onClose}
      maxWidth="640px"
      footer={<button type="button" className="btn btn-secondary" onClick={onClose}>{t('common.close')}</button>}
    >
      {loading && <p style={{ color: 'var(--text-secondary)' }}>{t('passkeysView.loading')}</p>}

      {!loading && (
        <>
          <p style={{ color: 'var(--text-secondary)', marginTop: 0, fontSize: 'var(--text-sm)' }}>
            {t('passkeysView.subtitle', { count: total })}
          </p>

          {total === 0 ? (
            <p style={{ color: 'var(--text-secondary)' }}>{t('passkeysView.empty')}</p>
          ) : (
            groups.map((g) => (
              <div key={g.rpId} style={{ marginBottom: 'var(--sp-3)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md, 8px)', overflow: 'hidden' }}>
                <div style={{ padding: 'var(--sp-2) var(--sp-3)', fontWeight: 700, borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
                  {g.rpId}
                </div>
                {g.items.map((p, i) => {
                  const pending = confirmId === (p.credentialId || g.rpId + i);
                  const cid = p.credentialId || g.rpId + i;
                  const created = p.createdAt ? formatCreated(p.createdAt) : '';
                  return (
                    <div key={cid} style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)', padding: 'var(--sp-2) var(--sp-3)', borderBottom: i < g.items.length - 1 ? '1px solid var(--border)' : 'none' }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {p.userName || t('passkeysView.noAccount')}
                        </div>
                        <div style={{ fontSize: 'var(--text-xs, 12px)', color: 'var(--text-tertiary)' }}>
                          {created ? t('passkeysView.created', { date: created }) : ''}
                          {created ? ' · ' : ''}{t('passkeysView.uses', { count: p.signCount })}
                        </div>
                      </div>
                      {pending ? (
                        <>
                          <button type="button" className="btn btn-sm" style={{ background: 'var(--error)', color: '#fff' }} onClick={() => deletePasskey(g.rpId, p.credentialId)}>
                            {t('passkeysView.confirm')}
                          </button>
                          <button type="button" className="btn btn-secondary btn-sm" onClick={() => setConfirmId(null)}>
                            {t('common.cancel')}
                          </button>
                        </>
                      ) : (
                        <button type="button" className="btn btn-secondary btn-sm" onClick={() => setConfirmId(cid)}>
                          {t('common.delete')}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            ))
          )}

          <p style={{ fontSize: 'var(--text-xs, 12px)', color: 'var(--text-tertiary)', marginBottom: 0 }}>
            {t('passkeysView.note')}
          </p>
        </>
      )}
    </Modal>
  );
}
