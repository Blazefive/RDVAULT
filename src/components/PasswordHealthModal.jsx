// ========================================
// COMPOSANT : Audit de sécurité des mots de passe
// ========================================
// Analyse hors ligne (faibles / réutilisés) de tous les coffres, plus une
// vérification de fuite optionnelle via Have I Been Pwned (k-anonymity : seuls
// 5 caractères du SHA-1 sont transmis ; le mot de passe ne quitte jamais l'appareil).
// La vérification est annulable (bouton « Annuler », fermeture de la modale, déconnexion) :
// aucune requête n'est plus envoyée ensuite et les mots de passe en clair sont effacés du rapport.

import React, { useState, useEffect, useRef, useCallback } from 'react';
import Modal from './common/Modal';
import { readAllSecrets } from '../utils/readAllSecrets';
import { analyzeVault, checkBreaches } from '../utils/passwordHealth';
import { getPasswordStrength, STRENGTH_LABEL_KEYS } from '../utils/passwordStrength';
import { useTranslation } from '../i18n';
import { partialListMessages, unreadableCount } from '../hooks/useTags';

function StatCard({ value, label, color, active, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        flex: 1, minWidth: 90, cursor: 'pointer', textAlign: 'center',
        padding: 'var(--sp-3)', borderRadius: 'var(--radius-md, 8px)',
        border: active ? `2px solid ${color}` : '1px solid var(--border)',
        background: active ? 'var(--bg-tertiary, rgba(127,127,127,0.08))' : 'var(--bg-secondary)',
      }}
    >
      <div style={{ fontSize: '28px', fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>{label}</div>
    </button>
  );
}

export default function PasswordHealthModal({ onClose, vaultApi, secretEngines, showToast }) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState(null);
  const [checking, setChecking] = useState(false);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [breachesDone, setBreachesDone] = useState(false);
  const [filter, setFilter] = useState('all');
  // Entrées ou coffres illisibles (réseau, délai, 5xx après relances) : rapport partiel signalé
  const [unreadable, setUnreadable] = useState(0);
  // Coffres listés partiellement (borne de listage, readAllSecrets.partialEngines) : message précis,
  // distinct d'une erreur réseau (traduit au rendu)
  const [partialEngines, setPartialEngines] = useState([]);
  const mountedRef = useRef(true);
  // Vérification HIBP en cours (annulation) et rapport courant (effacement des mots de passe)
  const breachAbortRef = useRef(null);
  const reportRef = useRef(null);
  reportRef.current = report;

  // Efface de la mémoire les mots de passe en clair conservés pour la vérification HIBP
  const forgetPasswords = (rep, { keepErrors = false } = {}) => {
    for (const item of rep?.items || []) {
      if (!(keepErrors && item.breachCount === -1)) item.password = '';
    }
  };

  useEffect(() => {
    mountedRef.current = true;
    const ac = new AbortController();
    breachAbortRef.current?.abort();
    (async () => {
      setLoading(true);
      try {
        const result = await readAllSecrets(vaultApi, secretEngines, { signal: ac.signal });
        if (mountedRef.current) {
          setUnreadable(unreadableCount(result));
          setPartialEngines(Array.isArray(result.partialEngines) ? result.partialEngines : []);
          setReport(analyzeVault(result.secrets));
        }
      } catch {
        if (mountedRef.current) setReport(analyzeVault([]));
      } finally {
        if (mountedRef.current) setLoading(false);
      }
    })();
    return () => { mountedRef.current = false; ac.abort(); };
  }, [vaultApi, secretEngines]);

  // Fermeture de la modale / déconnexion : vérification annulée (plus aucune requête HIBP)
  // et mots de passe en clair effacés du rapport.
  useEffect(() => () => {
    breachAbortRef.current?.abort();
    forgetPasswords(reportRef.current);
  }, []);

  const runBreachCheck = useCallback(async () => {
    if (!report || checking || report.items.length === 0) return;
    // Reprise possible après une annulation : seuls les items non vérifiés (ou en erreur) sont interrogés
    const pending = report.items.filter(i => (i.breachCount === null || i.breachCount === -1) && i.password);
    if (pending.length === 0) return;
    const ac = new AbortController();
    breachAbortRef.current = ac;
    setChecking(true);
    setProgress({ done: 0, total: pending.length });
    try {
      const res = await checkBreaches(pending, {
        signal: ac.signal,
        onProgress: (done, total) => mountedRef.current && !ac.signal.aborted && setProgress({ done, total }),
      });
      if (!mountedRef.current) return;
      setReport(prev => ({ ...prev })); // refléter les breachCount mis à jour en place
      if (res.aborted) {
        if (showToast) showToast(t('passwordHealth.cancelled', { done: res.checked, total: pending.length }), 'info');
        return;
      }
      setBreachesDone(true);
      // Vérification terminée : mots de passe en clair inutiles (sauf items en erreur, à réessayer)
      forgetPasswords(report, { keepErrors: true });
      if (showToast) {
        const breachedTotal = report.items.filter(i => i.breachCount > 0).length;
        if (breachedTotal > 0) showToast(t('passwordHealth.breachFound', { count: breachedTotal }), 'error');
        else if (res.errors > 0) showToast(t('passwordHealth.breachError'), 'warning');
        else showToast(t('passwordHealth.breachNone'), 'success');
      }
    } finally {
      if (breachAbortRef.current === ac) breachAbortRef.current = null;
      if (mountedRef.current) setChecking(false);
    }
  }, [report, checking, showToast, t]);

  const cancelBreachCheck = useCallback(() => {
    breachAbortRef.current?.abort();
  }, []);

  const breachedCount = report ? report.items.filter(i => i.breachCount > 0).length : 0;
  // Reste-t-il des mots de passe à vérifier (jamais vérifiés, ou en erreur à réessayer) ?
  const hasPendingBreachCheck = !!report && report.items.some(i => (i.breachCount === null || i.breachCount === -1) && i.password);

  const filtered = (() => {
    if (!report) return [];
    switch (filter) {
      case 'weak': return report.weak;
      case 'reused': return report.reused;
      case 'breached': return report.items.filter(i => i.breachCount > 0);
      default: return report.items;
    }
  })();

  const scoreColor = (s) => (s >= 80 ? 'var(--success)' : s >= 50 ? 'var(--warning)' : 'var(--error)');

  const footer = (
    <>
      <button type="button" className="btn btn-secondary" onClick={onClose}>{t('common.close')}</button>
      {checking && (
        <button type="button" className="btn btn-secondary" onClick={cancelBreachCheck}>
          {t('passwordHealth.cancelCheck')}
        </button>
      )}
      <button
        type="button"
        className="btn btn-primary"
        onClick={runBreachCheck}
        disabled={loading || checking || !report || report.items.length === 0 || !hasPendingBreachCheck}
      >
        {checking
          ? t('passwordHealth.checking', { done: progress.done, total: progress.total })
          : t('passwordHealth.checkBreaches')}
      </button>
    </>
  );

  return (
    <Modal
      title={`🛡️ ${t('passwordHealth.title')}`}
      onClose={onClose}
      maxWidth="720px"
      footer={footer}
      disableClose={checking}
    >
      {loading && <p style={{ color: 'var(--text-secondary)' }}>{t('passwordHealth.loading')}</p>}

      {!loading && report && (
        <>
          <p style={{ color: 'var(--text-secondary)', marginTop: 0, fontSize: 'var(--text-sm)' }}>
            {t('passwordHealth.subtitle')}
          </p>

          {(unreadable > 0 || partialEngines.length > 0) && (
            <p role="status" className="password-health-partial" style={{ color: 'var(--warning)', fontSize: 'var(--text-sm)', fontWeight: 600 }}>
              {[
                ...partialListMessages({ partialEngines }, t),
                ...(unreadable > 0 ? [t('passwordHealth.partial', { count: unreadable })] : []),
              ].join(' ')}
            </p>
          )}

          {report.total === 0 ? (
            <p style={{ color: 'var(--text-secondary)' }}>{t('passwordHealth.empty')}</p>
          ) : (
            <>
              {/* Score global */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-4)', margin: 'var(--sp-3) 0' }}>
                <div style={{ fontSize: '42px', fontWeight: 800, color: scoreColor(report.score) }}>
                  {report.score}<span style={{ fontSize: '18px', color: 'var(--text-tertiary)' }}>/100</span>
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
                  {t('passwordHealth.scoreLabel', { total: report.total })}
                </div>
              </div>

              {/* Cartes statistiques cliquables (filtre) */}
              <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap', marginBottom: 'var(--sp-3)' }}>
                <StatCard value={report.total} label={t('passwordHealth.filterAll')} color="var(--accent)"
                  active={filter === 'all'} onClick={() => setFilter('all')} />
                <StatCard value={report.weak.length} label={t('passwordHealth.weak')} color="var(--error)"
                  active={filter === 'weak'} onClick={() => setFilter('weak')} />
                <StatCard value={report.reused.length} label={t('passwordHealth.reused')} color="var(--warning)"
                  active={filter === 'reused'} onClick={() => setFilter('reused')} />
                <StatCard value={breachesDone ? breachedCount : '—'} label={t('passwordHealth.breached')} color="var(--error)"
                  active={filter === 'breached'} onClick={() => setFilter('breached')} />
              </div>

              {/* Liste */}
              <div style={{ maxHeight: '320px', overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius-md, 8px)' }}>
                {filtered.length === 0 ? (
                  <p style={{ padding: 'var(--sp-3)', color: 'var(--text-secondary)', margin: 0 }}>
                    {t('passwordHealth.noneInCategory')}
                  </p>
                ) : filtered.map((item, idx) => {
                  const strength = getPasswordStrength(item.entropy);
                  return (
                    <div key={idx} style={{
                      display: 'flex', alignItems: 'center', gap: 'var(--sp-2)',
                      padding: 'var(--sp-2) var(--sp-3)',
                      borderBottom: idx < filtered.length - 1 ? '1px solid var(--border)' : 'none',
                    }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {item.name}
                        </div>
                        <div style={{ fontSize: 'var(--text-xs, 12px)', color: 'var(--text-tertiary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {[item.engine, item.username, item.url].filter(Boolean).join(' · ')}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '6px', flexShrink: 0, alignItems: 'center' }}>
                        <span style={{ fontSize: 'var(--text-xs, 12px)', color: strength.color }}>{t(STRENGTH_LABEL_KEYS[strength.level])}</span>
                        {item.reused && <Badge color="var(--warning)" text={t('passwordHealth.reusedBadge')} />}
                        {item.weak && <Badge color="var(--error)" text={t('passwordHealth.weakBadge')} />}
                        {item.breachCount > 0 && <Badge color="var(--error)" text={t('passwordHealth.breachedBadge', { count: item.breachCount })} filled />}
                        {item.breachCount === 0 && breachesDone && <Badge color="var(--success)" text={t('passwordHealth.safeBadge')} />}
                      </div>
                    </div>
                  );
                })}
              </div>

              <p style={{ fontSize: 'var(--text-xs, 12px)', color: 'var(--text-tertiary)', marginBottom: 0 }}>
                {t('passwordHealth.privacyNote')}
              </p>
            </>
          )}
        </>
      )}
    </Modal>
  );
}

function Badge({ color, text, filled }) {
  return (
    <span style={{
      fontSize: '11px', fontWeight: 600, padding: '2px 6px', borderRadius: '10px',
      color: filled ? '#fff' : color,
      background: filled ? color : 'transparent',
      border: `1px solid ${color}`,
      whiteSpace: 'nowrap',
    }}>{text}</span>
  );
}
