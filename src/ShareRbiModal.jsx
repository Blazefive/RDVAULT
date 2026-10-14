// ========================================
// MODAL DE PARTAGE RBI VIA VAULT WRAPPING + PROXY
// ========================================
// Conforme aux exigences « obligatoires » du proxy (DEPLOYMENT.md, étape 8) :
// - chaque appel au proxy porte le jeton Vault du demandeur (X-Vault-Token) : aucun appel anonyme ;
// - le proxy ne voit jamais les identifiants : il stocke et rend le seul wrapping token ;
// - maxUses ≤ 5 (jamais illimité), TTL ≤ 24 h ;
// - le proxy n'a aucun accès TOTP : le destinataire lit le code avec SON jeton, s'il en a le droit.
//
// Mode "send" :
//   1. Wrap le secret via Vault (wrapping token à usage unique, TTL choisi)
//   2. Envoie le wrapping token au proxy (authentifié) avec maxUses + TTL → shareId
//   3. Le sender partage le shareId au destinataire
//   REMOTE-4 : le proxy reçoit le wrapping token dans /create-share, il ne peut donc pas être appelé
//   avant le wrap. Si l'enregistrement échoue (proxy injoignable, CSP, refus, réponse sans shareId),
//   le wrapping token est aussitôt consommé (unwrap par l'émetteur, usage unique) : aucune copie
//   emballée des identifiants ne reste dans Vault pendant le TTL avec un jeton que personne ne reçoit.
//
// Mode "receive" :
//   1. Le destinataire colle le shareId
//   2. Le proxy (authentifié) vérifie uses/expiry et rend le wrapping token
//   3. Le destinataire unwrappe lui-même auprès de Vault (usage unique), l'URL est validée
//   4. Confirmation explicite (URL + identifiant affichés), puis code TOTP lu avec le jeton du
//      destinataire (si l'entrée en a un et qu'il y a droit) et lancement de la session RBI

import React, { useState, useEffect, useId, useRef } from 'react';
import axios from 'axios';
import { useTranslation } from './i18n';
import Modal from './components/common/Modal';
import { buildSafeUrl } from './utils/security';
import { rbiWebsiteOption } from './utils/urlHandler';

// Libellés traduits via t(labelKey) au rendu. Plafond DEPLOYMENT.md : 24 h.
const TTL_OPTIONS = [
  { labelKey: 'share.ttl1h', value: '1h' },
  { labelKey: 'share.ttl8h', value: '8h' },
  { labelKey: 'share.ttl24h', value: '24h' },
];

// Plafond DEPLOYMENT.md : 5 utilisations, jamais illimité
const USES_OPTIONS = [
  { label: '1x', value: 1 },
  { label: '2x', value: 2 },
  { label: '3x', value: 3 },
  { label: '5x', value: 5 },
];

const DEFAULT_RBI_PROXY_URL = '';
// Moteur TOTP de Vault (comme useTotp)
const TOTP_ENGINE = 'TOTP';

/** Jeton (wrapping token, jeton Vault) utilisable comme en-tête HTTP : non vide, borné, sans contrôle */
function isHeaderSafeToken(value) {
  // eslint-disable-next-line no-control-regex -- volontaire : un jeton avec caractère de contrôle ne doit pas atteindre un en-tête HTTP
  return typeof value === 'string' && value.length > 0 && value.length <= 512 && !/[\r\n\x00-\x1F\x7F]/.test(value);
}

/**
 * Champ « website » reçu dans un partage : chaîne non vide, bornée (2 048, comme le processus
 * principal) et sans caractère de contrôle, sinon absent. Le processus principal vérifie ensuite le
 * nom d'hôte ; l'adresse n'est jamais ouverte (l'URL de lancement reste `url`).
 */
function sharedWebsite(value) {
  // eslint-disable-next-line no-control-regex -- volontaire : valeur avec caractère de contrôle écartée
  return typeof value === 'string' && value.length > 0 && value.length <= 2048 && !/[\x00-\x1F\x7F]/.test(value) ? value : undefined;
}

/**
 * Format d'un ID de partage (contrat DEPLOYMENT.md, étape 8) : lettres, chiffres, « - » ou « _ », 128
 * caractères au plus. Même règle à l'ÉMISSION (réponse de /create-share) et à la RÉCEPTION (ID collé).
 */
const SHARE_ID_RE = /^[a-zA-Z0-9\-_]{1,128}$/;

/** true si la valeur est un ID de partage conforme au contrat */
export function isValidShareId(value) {
  return typeof value === 'string' && SHARE_ID_RE.test(value);
}

/** URL de partage reçue : http(s) uniquement (sinon null) */
function sharedHttpUrl(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol) ? value : null;
  } catch {
    return null;
  }
}

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
  const { t } = useTranslation();
  const RBI_PROXY_URL = rbiProxyUrl || process.env.REACT_APP_RBI_PROXY_URL || DEFAULT_RBI_PROXY_URL;
  const [selectedTtl, setSelectedTtl] = useState('8h');
  const [maxUses, setMaxUses] = useState(1);
  const [shareId, setShareId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [pastedId, setPastedId] = useState('');
  // Partage reçu et déchiffré (unwrap), en attente de confirmation explicite
  const [pendingShare, setPendingShare] = useState(null);
  const inputRef = useRef(null);
  // Libellés associés (groupes de boutons d'option et champ ID de partage)
  const ttlLabelId = useId();
  const usesLabelId = useId();
  const shareIdInputId = useId();

  // Échap, clic hors zone, focus initial / piège / retour : squelette commun Modal (ci-dessous)

  // Focus l'input en mode receive
  useEffect(() => {
    if (mode === 'receive' && inputRef.current) {
      inputRef.current.focus();
    }
  }, [mode]);

  // Invalide un wrapping token resté sans partage (REMOTE-4) : un wrapping token est à usage
  // unique, l'unwrap par l'émetteur le consomme (les données rendues sont les siennes et sont
  // ignorées). Au mieux : en cas d'échec, Vault l'expire de toute façon au terme du TTL.
  const discardWrappingToken = async (wrappingToken) => {
    if (!isHeaderSafeToken(wrappingToken)) return;
    try {
      await axios.post(
        `${vaultUrl}/v1/sys/wrapping/unwrap`,
        null,
        axiosConfig({ headers: { 'X-Vault-Token': wrappingToken, 'Content-Type': 'application/json' } })
      );
    } catch {
      /* déjà consommé ou expiré, ou Vault injoignable : rien d'autre à faire */
    }
  };

  // === MODE SEND ===
  const handleGenerateShare = async () => {
    setLoading(true);
    setError('');
    setShareId('');
    setCopied(false);

    // Wrapping token créé et pas encore remis au proxy (consommé si l'enregistrement échoue)
    let pendingWrappingToken = null;
    try {
      // URL normalisée comme à l'ouverture (buildSafeUrl : https:// ajouté sans schéma http(s)
      // explicite, protocoles dangereux refusés)
      const url = buildSafeUrl(secret.url);
      if (!url) {
        setError(t('error.invalidUrl'));
        return;
      }
      // Plafonds DEPLOYMENT.md (défense en profondeur : seules les options proposées passent)
      if (!TTL_OPTIONS.some((o) => o.value === selectedTtl) || !USES_OPTIONS.some((o) => o.value === maxUses)) {
        setError(t('share.errGenerate'));
        return;
      }

      // 1. Wrap via Vault : le contenu n'est lisible que par celui qui unwrappe (jamais le proxy).
      // totpKeyName : nom de la clé TOTP, lue par le destinataire avec SON jeton s'il y a droit.
      const wrapData = {
        url,
        username: secret.username || '',
        password: secret.password || '',
        // Adresse « website » de l'entrée (RBI-11) : le destinataire la transmet à sa session RBI
        ...rbiWebsiteOption(secret),
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
        throw new Error(t('share.errNoWrapToken'));
      }
      pendingWrappingToken = wrappingToken;

      // 2. Enregistrer le partage sur le proxy (appel authentifié par le jeton Vault du demandeur)
      const proxyRes = await axios.post(
        `${RBI_PROXY_URL}/create-share`,
        {
          wrappingToken,
          maxUses,
          ttl: selectedTtl,
        },
        { headers: { 'Content-Type': 'application/json', 'X-Vault-Token': token }, timeout: 15000 }
      );

      const rawId = proxyRes.data?.shareId;
      if (!rawId) {
        throw new Error(t('share.errNoShareId'));
      }
      // DOCS-17 : format contrôlé dès l'ÉMISSION. Avant, tout shareId non vide était affiché tel quel et seul
      // le destinataire le refusait (« ID invalide ») : partage inutilisable découvert trop tard. Même règle
      // qu'à la réception, y compris le retrait des espaces de bord que le destinataire appliquait déjà : tout
      // ID utilisable jusqu'ici reste accepté. Refus → wrapping token consommé (catch), message explicite.
      const id = typeof rawId === 'string' ? rawId.trim() : rawId;
      if (!isValidShareId(id)) {
        throw Object.assign(new Error(t('share.errProxyInvalidShareId')), { code: 'RDV_INVALID_SHARE_ID' });
      }

      // Partage enregistré : le wrapping token appartient désormais au proxy
      pendingWrappingToken = null;
      setShareId(id);
    } catch (err) {
      // Enregistrement impossible : le wrapping token ne doit pas rester utilisable dans Vault
      if (pendingWrappingToken) {
        const orphan = pendingWrappingToken;
        pendingWrappingToken = null;
        await discardWrappingToken(orphan);
      }
      if (err.code === 'RDV_INVALID_SHARE_ID') {
        setError(t('share.errProxyInvalidShareId'));
      } else if (err.code === 'ECONNREFUSED' || err.code === 'ERR_NETWORK') {
        setError(t('share.errProxyUnreachable'));
      } else {
        setError(t('share.errGenerate'));
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopyShareId = async () => {
    try {
      // L'ID de partage n'est pas un secret : durée d'auto-effacement plus longue (2 min)
      if (window.electronClipboard?.copySecure) {
        await window.electronClipboard.copySecure(shareId, 120000);
      } else {
        await navigator.clipboard.writeText(shareId);
      }
      setCopied(true);
      showToast(t('share.idCopied'), 'success', 4000);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      showToast(t('share.copyError'), 'error');
    }
  };

  // === MODE RECEIVE ===
  const handleReceiveShare = async () => {
    const id = pastedId.trim();
    if (!id) return;
    // SÉCURITÉ: Valider le format du shareId (lettres, chiffres, - et _, 128 caractères au plus)
    if (!isValidShareId(id)) {
      setError(t('share.errInvalidId'));
      return;
    }

    if (!window.electronRBI?.launchSession) {
      setError(t('share.errRbiUnavailable'));
      return;
    }
    if (!isHeaderSafeToken(token)) {
      setError(t('share.errUnauthorized'));
      return;
    }

    setLoading(true);
    setError('');

    // 1. Le proxy (appel authentifié) rend le wrapping token — jamais les identifiants
    let wrappingToken;
    try {
      showToast(t('share.fetching'), 'info', 2000);
      const res = await axios.post(
        `${RBI_PROXY_URL}/unwrap-rbi`,
        { shareId: id },
        { headers: { 'Content-Type': 'application/json', 'X-Vault-Token': token }, timeout: 15000 }
      );
      wrappingToken = res.data?.wrappingToken;
    } catch (err) {
      const status = err.response?.status;
      if (status === 404) {
        setError(t('share.errNotFound'));
      } else if (status === 410) {
        setError(t('share.errMaxUses'));
      } else if (status === 400) {
        setError(t('share.errExpired'));
      } else if (status === 401 || status === 403) {
        setError(t('share.errUnauthorized'));
      } else if (err.code === 'ECONNREFUSED' || err.code === 'ERR_NETWORK') {
        setError(t('share.errProxyUnreachable'));
      } else {
        setError(t('share.errReceive'));
      }
      setLoading(false);
      return;
    }
    if (!isHeaderSafeToken(wrappingToken)) {
      setError(t('share.errDataMissing'));
      setLoading(false);
      return;
    }

    // 2. Unwrap par le destinataire lui-même auprès de Vault (wrapping token à usage unique)
    try {
      const unwrapRes = await axios.post(
        `${vaultUrl}/v1/sys/wrapping/unwrap`,
        null,
        axiosConfig({ headers: { 'X-Vault-Token': wrappingToken, 'Content-Type': 'application/json' } })
      );
      const data = unwrapRes.data?.data;
      if (!data || !data.url) {
        setError(t('share.errDataMissing'));
        return;
      }
      // SÉCURITÉ: protocole de l'URL validé avant toute session RBI
      const url = sharedHttpUrl(data.url);
      if (!url) {
        setError(t('error.shareUrlInvalid'));
        return;
      }
      // 3. Confirmation explicite (URL et identifiant affichés) avant le lancement
      setPendingShare({
        url,
        // Adresse « website » de l'entrée partagée (RBI-11), si l'émetteur l'a transmise
        website: sharedWebsite(data.website),
        username: typeof data.username === 'string' ? data.username : '',
        password: typeof data.password === 'string' ? data.password : '',
        // Nom de clé TOTP (encodé dans l'URL à la lecture) : chaîne bornée sans caractère de contrôle
        totpKeyName: isHeaderSafeToken(data.totpKeyName) ? data.totpKeyName : null,
      });
    } catch (err) {
      const status = err.response?.status;
      // Vault : wrapping token déjà utilisé ou expiré → 400
      if (status === 400 || status === 404) {
        setError(t('share.errExpired'));
      } else {
        setError(t('share.errReceive'));
      }
    } finally {
      setLoading(false);
    }
  };

  const cancelPendingShare = () => {
    setPendingShare(null);
  };

  // 4. Lancement après confirmation : code TOTP lu avec le jeton du destinataire (s'il y a droit)
  const confirmPendingShare = async () => {
    const share = pendingShare;
    if (!share) return;
    setLoading(true);
    setError('');
    try {
      let totpCode = null;
      if (share.totpKeyName) {
        try {
          const res = await axios.get(
            `${vaultUrl}/v1/${TOTP_ENGINE}/code/${encodeURIComponent(share.totpKeyName)}`,
            axiosConfig({ headers: { 'X-Vault-Token': token } })
          );
          totpCode = typeof res.data?.data?.code === 'string' ? res.data.data.code : null;
        } catch {
          totpCode = null; // pas de droit TOTP : session sans code
        }
      }
      showToast(totpCode ? t('toast.totpRetrieved') : t('toast.launchingRbiNoTotp'), 'info', 2000);
      const result = await window.electronRBI.launchSession({
        url: share.url,
        ...rbiWebsiteOption(share),
        username: share.username,
        password: share.password,
        totp: totpCode,
        policies: {
          disableClipboard: true,
          disableNewTabs: true,
          disableDownloads: false,
        },
      });
      setPendingShare(null);
      if (result?.success) {
        showToast(t('share.opened'), 'success', 3000);
        onClose();
      } else if (result?.code === 'RBI_FOREIGN_ORIGIN') {
        setError(t('error.rbiForeignOrigin'));
      } else {
        setError(result?.error || t('share.errLaunch'));
      }
    } catch {
      setPendingShare(null);
      setError(t('share.errLaunch'));
    } finally {
      setLoading(false);
    }
  };

  // ========== RENDU ==========
  const usesLabel = t('share.usesCount', { count: maxUses });
  const optionLabel = (opt) => (opt.labelKey ? t(opt.labelKey) : opt.label);

  return (
    <Modal
      title={mode === 'send' ? t('share.titleSend') : t('share.titleReceive')}
      onClose={onClose}
      maxWidth="520px"
      overlayStyle={{ zIndex: 'var(--z-modal)' }}
      footer={(
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t('common.close')}
          </button>
          {mode === 'send' && !shareId && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleGenerateShare}
              disabled={loading}
            >
              {loading ? t('share.generating') : t('share.generate')}
            </button>
          )}
          {mode === 'receive' && !pendingShare && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleReceiveShare}
              disabled={loading || !pastedId.trim()}
            >
              {loading ? t('share.opening') : t('share.open')}
            </button>
          )}
          {mode === 'receive' && pendingShare && (
            <>
              <button type="button" className="btn btn-secondary" onClick={cancelPendingShare} disabled={loading}>
                {t('common.cancel')}
              </button>
              <button type="button" className="btn btn-primary" onClick={confirmPendingShare} disabled={loading}>
                {loading ? t('share.opening') : t('confirm.open')}
              </button>
            </>
          )}
        </>
      )}
    >

          {/* ======= MODE SEND ======= */}
          {mode === 'send' && (
            <>
              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', marginBottom: 'var(--sp-2)' }}>
                  {t('share.secret')} <strong style={{ color: 'var(--text-primary)' }}>{secret.name}</strong>
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)' }}>
                  {t('share.url')} <strong style={{ color: 'var(--text-primary)' }}>{secret.url}</strong>
                </div>
              </div>

              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <div id={ttlLabelId} style={{ display: 'block', marginBottom: 'var(--sp-2)', fontWeight: 'var(--weight-semibold)' }}>
                  {t('share.expiration')}
                </div>
                <div role="group" aria-labelledby={ttlLabelId} style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                  {TTL_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      aria-pressed={selectedTtl === opt.value}
                      onClick={() => setSelectedTtl(opt.value)}
                      className={selectedTtl === opt.value ? 'btn btn-primary' : 'btn btn-secondary'}
                      style={{ flex: '1 1 auto', minWidth: '80px' }}
                    >
                      {optionLabel(opt)}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <div id={usesLabelId} style={{ display: 'block', marginBottom: 'var(--sp-2)', fontWeight: 'var(--weight-semibold)' }}>
                  {t('share.usesLabel')}
                </div>
                <div role="group" aria-labelledby={usesLabelId} style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                  {USES_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      aria-pressed={maxUses === opt.value}
                      onClick={() => setMaxUses(opt.value)}
                      className={maxUses === opt.value ? 'btn btn-primary' : 'btn btn-secondary'}
                      style={{ flex: '1 1 auto', minWidth: '60px' }}
                    >
                      {optionLabel(opt)}
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
                    {t('share.shareId')}
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
                    {copied ? t('share.copiedShort') : t('share.copyId')}
                  </button>
                  <div style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-tertiary)',
                    marginTop: 'var(--sp-3)',
                    lineHeight: 1.5
                  }}>
                    <strong>{t('share.instructions')}</strong><br/>
                    {t('share.step1')}<br/>
                    {t('share.step2')}<br/>
                    {t('share.step3')}<br/>
                    {t('share.step4')}
                  </div>
                  <div style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--warning)',
                    marginTop: 'var(--sp-2)',
                    fontStyle: 'italic'
                  }}>
                    {t('share.expiresIn', {
                      ttl: (() => { const o = TTL_OPTIONS.find(o => o.value === selectedTtl); return o ? optionLabel(o) : selectedTtl; })(),
                      uses: usesLabel
                    })}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ======= MODE RECEIVE ======= */}
          {mode === 'receive' && (
            <>
              <div style={{ marginBottom: 'var(--sp-4)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {t('share.receiveHint')}<br/>
                {t('share.receiveHint2')}
              </div>

              <div style={{ marginBottom: 'var(--sp-4)' }}>
                <label htmlFor={shareIdInputId} style={{ display: 'block', marginBottom: 'var(--sp-2)', fontWeight: 'var(--weight-semibold)' }}>
                  {t('share.shareIdLabel')}
                </label>
                <input
                  id={shareIdInputId}
                  ref={inputRef}
                  type="text"
                  value={pastedId}
                  onChange={(e) => setPastedId(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && pastedId.trim() && !pendingShare && !loading) {
                      handleReceiveShare();
                    }
                  }}
                  readOnly={Boolean(pendingShare)}
                  placeholder={t('share.pasteHere')}
                  className="search-input"
                  style={{
                    width: '100%',
                    fontFamily: 'monospace',
                    fontSize: 'var(--text-sm)',
                    letterSpacing: '1px',
                  }}
                />
              </div>

              {/* Confirmation explicite avant d'ouvrir la session (URL et identifiant reçus) */}
              {pendingShare && (
                <div role="status" style={{
                  padding: 'var(--sp-3)',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                  marginBottom: 'var(--sp-4)',
                  fontSize: 'var(--text-sm)',
                  wordBreak: 'break-all'
                }}>
                  {t('confirm.openShareMsg', { url: pendingShare.url, username: pendingShare.username || '-' })}
                </div>
              )}
            </>
          )}

          {error && (
            <div role="alert" style={{
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
    </Modal>
  );
}
