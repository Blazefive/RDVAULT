// ========================================
// MODAL DE PARTAGE RBI VIA VAULT WRAPPING + PROXY
// ========================================
// Mode "send" :
//   1. Wrap le secret via Vault (one-time wrapping token)
//   2. Envoie le wrapping token au proxy avec maxUses + TTL
//   3. Le proxy unwrap, stocke en mémoire, retourne un shareId
//   4. Le sender partage le shareId au destinataire
//
// Mode "receive" :
//   1. Le destinataire colle le shareId
//   2. Le proxy vérifie uses/expiry, fetch TOTP frais, retourne les données
//   3. La session RBI est lancée avec credentials + TOTP

import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const TTL_OPTIONS = [
  { label: '1 heure', value: '1h' },
  { label: '8 heures', value: '8h' },
  { label: '24 heures', value: '24h' },
  { label: '48 heures', value: '48h' },
];

const USES_OPTIONS = [
  { label: '1x', value: 1 },
  { label: '2x', value: 2 },
  { label: '3x', value: 3 },
  { label: '5x', value: 5 },
  { label: '10x', value: 10 },
  { label: 'Illimite', value: 0 },
];

const DEFAULT_RBI_PROXY_URL = '';

export default function ShareRbiModal({
  mode = 'send',        // 'send' ou 'receive'
  secret,               // secret à partager (mode send uniquement)
  totpKeyName,          // nom de la clé TOTP (mode send uniquement)
  vaultUrl,
  token,
  axiosConfig,
  rbiProxyUrl,          // URL du proxy RBI (depuis la configuration)
  onClose,
  showToast,
}) {
  const RBI_PROXY_URL = rbiProxyUrl || process.env.REACT_APP_RBI_PROXY_URL || DEFAULT_RBI_PROXY_URL;
  const [selectedTtl, setSelectedTtl] = useState('8h');
  const [maxUses, setMaxUses] = useState(1);
  const [shareId, setShareId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [pastedId, setPastedId] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Focus l'input en mode receive
  useEffect(() => {
    if (mode === 'receive' && inputRef.current) {
      inputRef.current.focus();
    }
  }, [mode]);

  // === MODE SEND ===
  const handleGenerateShare = async () => {
    setLoading(true);
    setError('');
    setShareId('');
    setCopied(false);

    try {
      const url = secret.url && secret.url.startsWith('http') ? secret.url : `https://${secret.url}`;

      // 1. Wrap via Vault
      const wrapData = {
        url,
        username: secret.username || '',
        password: secret.password || '',
      };
      if (totpKeyName) {
        wrapData.totpKeyName = totpKeyName;
      }

      const wrapRes = await axios.post(
        `${vaultUrl}/v1/sys/wrapping/wrap`,
        wrapData,
        axiosConfig({
          headers: {
            'X-Vault-Token': token,
            'X-Vault-Wrap-TTL': selectedTtl,
            'Content-Type': 'application/json',
          },
        })
      );

      const wrappingToken = wrapRes.data?.wrap_info?.token;
      if (!wrappingToken) {
        throw new Error('Aucun token de wrapping retourne par Vault');
      }

      // 2. Enregistrer le partage sur le proxy
      const proxyRes = await axios.post(
        `${RBI_PROXY_URL}/create-share`,
        {
          wrappingToken,
          maxUses,
          ttl: selectedTtl,
        },
        { headers: { 'Content-Type': 'application/json' }, timeout: 15000 }
      );

      const id = proxyRes.data?.shareId;
      if (!id) {
        throw new Error('Le proxy n\'a pas retourne de shareId');
      }

      setShareId(id);
    } catch (err) {
      if (err.code === 'ECONNREFUSED' || err.code === 'ERR_NETWORK') {
        setError('Proxy RBI injoignable - contactez l\'administrateur');
      } else {
        setError('Erreur lors de la génération du partage');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopyShareId = async () => {
    try {
      if (window.electronClipboard?.copySecure) {
        await window.electronClipboard.copySecure(shareId, 120000);
      } else {
        await navigator.clipboard.writeText(shareId);
      }
      setCopied(true);
      showToast('ID de partage copie - envoyez-le au destinataire', 'success', 4000);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      showToast('Erreur lors de la copie', 'error');
    }
  };

  // === MODE RECEIVE ===
  const handleReceiveShare = async () => {
    const id = pastedId.trim();
    if (!id) return;
    // SÉCURITÉ: Valider le format du shareId (alphanumeric + hyphens, max 128 chars)
    if (!/^[a-zA-Z0-9\-_]{1,128}$/.test(id)) {
      setError('Format de l\'ID de partage invalide');
      return;
    }

    setLoading(true);
    setError('');

    try {
      showToast('Recuperation du secret partage...', 'info', 2000);

      const res = await axios.post(
        `${RBI_PROXY_URL}/unwrap-rbi`,
        { shareId: id },
        { headers: { 'Content-Type': 'application/json' }, timeout: 15000 }
      );

      const data = res.data;
      if (!data || !data.url) {
        setError('Partage invalide : donnees manquantes');
        setLoading(false);
        return;
      }

      // Lancer la session RBI
      if (window.electronRBI?.launchSession) {
        if (data.totpCode) {
          showToast('TOTP recupere, lancement session securisee...', 'info', 2000);
        } else {
          showToast('Lancement session securisee (sans TOTP)...', 'info', 2000);
        }
        const result = await window.electronRBI.launchSession({
          url: data.url,
          username: data.username || '',
          password: data.password || '',
          totp: data.totpCode || null,
          policies: {
            disableClipboard: true,
            disableNewTabs: true,
            disableDownloads: false,
          },
        });

        if (result.success) {
          showToast('Session securisee partagee ouverte', 'success', 3000);
          onClose();
        } else {
          setError(result.error || 'Erreur lancement session');
        }
      } else {
        setError('Fonction session securisee non disponible');
      }
    } catch (err) {
      const status = err.response?.status;
      if (status === 404) {
        setError('Partage introuvable ou expire');
      } else if (status === 410) {
        setError('Nombre maximum d\'utilisations atteint');
      } else if (status === 400) {
        setError('Partage expire');
      } else if (err.code === 'ECONNREFUSED' || err.code === 'ERR_NETWORK') {
        setError('Proxy RBI injoignable - contactez l\'administrateur');
      } else {
        setError('Erreur lors de la récupération du partage');
      }
    } finally {
      setLoading(false);
    }
  };

  // ========== RENDU ==========
  const usesLabel = maxUses === 0 ? 'illimite' : `${maxUses} utilisation${maxUses > 1 ? 's' : ''}`;

  return (
    <div className="modal-overlay" onClick={onClose} style={{ zIndex: 'var(--z-modal)' }}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '520px' }}>
        <div className="modal-header">
          <h2>{mode === 'send' ? 'Partager en RBI' : 'Recevoir un partage RBI'}</h2>
        </div>
        <div className="modal-body">

          {/* ======= MODE SEND ======= */}
          {mode === 'send' && (
            <>
              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--sp-2)' }}>
                  Secret : <strong style={{ color: 'var(--text-primary)' }}>{secret.name}</strong>
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)' }}>
                  URL : <strong style={{ color: 'var(--text-primary)' }}>{secret.url}</strong>
                </div>
              </div>

              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <label style={{ display: 'block', marginBottom: 'var(--sp-2)', fontWeight: 'var(--weight-semibold)' }}>
                  Expiration
                </label>
                <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                  {TTL_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setSelectedTtl(opt.value)}
                      className={selectedTtl === opt.value ? 'btn btn-primary' : 'btn btn-secondary'}
                      style={{ flex: '1 1 auto', minWidth: '80px' }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <label style={{ display: 'block', marginBottom: 'var(--sp-2)', fontWeight: 'var(--weight-semibold)' }}>
                  Nombre d'utilisations
                </label>
                <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                  {USES_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setMaxUses(opt.value)}
                      className={maxUses === opt.value ? 'btn btn-primary' : 'btn btn-secondary'}
                      style={{ flex: '1 1 auto', minWidth: '60px' }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {shareId && (
                <div style={{
                  padding: 'var(--sp-3)',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                  marginBottom: 'var(--sp-4)'
                }}>
                  <div style={{ fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-semibold)', marginBottom: 'var(--sp-2)' }}>
                    ID de partage :
                  </div>
                  <div style={{
                    padding: 'var(--sp-2)',
                    background: 'var(--bg-input)',
                    borderRadius: 'var(--radius-sm)',
                    marginBottom: 'var(--sp-3)',
                    wordBreak: 'break-all',
                    fontFamily: 'monospace',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--accent)',
                    userSelect: 'all',
                    cursor: 'text',
                    textAlign: 'center',
                    letterSpacing: '1px',
                  }}>
                    {shareId}
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyShareId}
                    className="btn btn-primary"
                    style={{ width: '100%' }}
                  >
                    {copied ? 'Copie !' : 'Copier l\'ID'}
                  </button>
                  <div style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-tertiary)',
                    marginTop: 'var(--sp-3)',
                    lineHeight: 1.5
                  }}>
                    <strong>Instructions :</strong><br/>
                    1. Copiez l'ID ci-dessus<br/>
                    2. Envoyez-le au destinataire par Teams ou email<br/>
                    3. Le destinataire ouvre RDVAULT et clique sur "Recevoir un partage"<br/>
                    4. Il colle l'ID pour ouvrir la session securisee
                  </div>
                  <div style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--warning)',
                    marginTop: 'var(--sp-2)',
                    fontStyle: 'italic'
                  }}>
                    Expire dans {TTL_OPTIONS.find(o => o.value === selectedTtl)?.label || selectedTtl} - {usesLabel}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ======= MODE RECEIVE ======= */}
          {mode === 'receive' && (
            <>
              <div style={{ marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Collez l'ID de partage recu par Teams ou email.<br/>
                Une session securisee RBI sera lancee automatiquement.
              </div>

              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <label style={{ display: 'block', marginBottom: 'var(--sp-2)', fontWeight: 'var(--weight-semibold)' }}>
                  ID de partage
                </label>
                <input
                  ref={inputRef}
                  type="text"
                  value={pastedId}
                  onChange={(e) => setPastedId(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && pastedId.trim()) {
                      handleReceiveShare();
                    }
                  }}
                  placeholder="Collez l'ID ici"
                  className="search-input"
                  style={{
                    width: '100%',
                    fontFamily: 'monospace',
                    fontSize: 'var(--text-sm)',
                    letterSpacing: '1px',
                  }}
                />
              </div>
            </>
          )}

          {error && (
            <div style={{
              padding: 'var(--sp-3)',
              background: 'var(--bg-danger)',
              color: 'var(--danger)',
              borderRadius: 'var(--radius-md)',
              marginBottom: 'var(--sp-4)',
              fontSize: 'var(--text-sm)'
            }}>
              {error}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Fermer
          </button>
          {mode === 'send' && !shareId && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleGenerateShare}
              disabled={loading}
            >
              {loading ? 'Generation...' : 'Generer le partage'}
            </button>
          )}
          {mode === 'receive' && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleReceiveShare}
              disabled={loading || !pastedId.trim()}
            >
              {loading ? 'Ouverture...' : 'Ouvrir la session'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
