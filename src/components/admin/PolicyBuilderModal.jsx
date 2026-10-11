// ========================================
// MODALE : Builder de policy (panneau admin)
// ========================================
// Extrait d'AdminPanel.jsx. Construit visuellement une policy HCL Vault.
//
// Props :
// - allMounts, loadAllMounts : liste des coffres (chargée si vide)
// - editPolicyName : nom de la policy à éditer (null = création)
// - vaultUrl, axiosConfig, baseHeaders, ldapAuthPath : accès API Vault
// - savePolicy(name, hcl) : sauvegarde (validations modérateur incluses)
// - showToast, onClose
//
// Squelette commun Modal (hook useDialogA11y) : role="dialog" nommé par le titre, focus initial
// sur le premier champ, piège de focus, Échap (modale du dessus seulement), retour du focus au
// bouton déclencheur, fermeture sur le fond par mousedown + mouseup ; couleurs du thème.

import React, { useId } from 'react';
import axios from 'axios';
import Modal from '../common/Modal';
import secureLogger from '../../secureLogger';
import { encodeEnginePath } from '../../utils/security';
import { useTranslation } from '../../i18n';
import { generatePolicyHcl, analyzePolicyForBuilder, totpPrefixCollisions, totpPrefixFor } from './policyHcl';
import { ltrIsolate, ltrWhenFilled } from './i18nHelpers';

export default function PolicyBuilderModal({
  allMounts = [],
  loadAllMounts,
  editPolicyName,
  vaultUrl,
  axiosConfig,
  baseHeaders,
  ldapAuthPath = 'auth/ldap',
  savePolicy,
  showToast,
  onClose,
}) {
  const { t } = useTranslation();
  const [policyName, setPolicyName] = React.useState('');
  const [allowListMounts, setAllowListMounts] = React.useState(true);
  const [paths, setPaths] = React.useState([
    {
      type: 'coffre', // 'coffre' ou 'secret'
      coffre: '',
      secret: '',
      accessLevel: 'read-only', // 'read-only', 'read-write', 'full-admin'
      includeTotp: true,
      totpLevel: 'read-only' // 'read-only' ou 'read-write'
    }
  ]);
  const [availableSecrets, setAvailableSecrets] = React.useState({});
  const [isEditMode, setIsEditMode] = React.useState(false);
  // Édition d'une policy existante : 'loading' (lecture / analyse en cours), 'ready'
  // (relue fidèlement, modifiable), 'unsupported' (non représentable : jamais réécrite
  // depuis le builder) ou 'error' (lecture impossible). Création : 'ready'.
  const [editStatus, setEditStatus] = React.useState(editPolicyName ? 'loading' : 'ready');
  const [loadedHcl, setLoadedHcl] = React.useState(null);
  const [mountsLoaded, setMountsLoaded] = React.useState(allMounts.length > 0);
  const analyzedRef = React.useRef(false);
  const nameId = useId();

  React.useEffect(() => {
    // Focus initial : assuré par le squelette Modal (premier champ du panneau).
    // Charger les mounts si pas déjà chargés (la relecture d'une policy en a besoin)
    if (allMounts.length === 0) {
      Promise.resolve().then(() => loadAllMounts()).catch(() => {}).finally(() => setMountsLoaded(true));
    }

    // Si mode édition, charger la policy
    if (editPolicyName) {
      loadPolicyForEdit(editPolicyName);
    }
    // Initialisation unique au montage (chargement des coffres, lecture de la policy éditée) :
    // la relancer à chaque changement de props rechargerait la policy et écraserait la saisie en cours.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Charger la policy pour l'éditer
  const loadPolicyForEdit = async (name) => {
    try {
      const res = await axios.get(
        `${vaultUrl}/v1/sys/policies/acl/${encodeURIComponent(name)}`,
        axiosConfig({ headers: baseHeaders() })
      );
      const hcl = res.data?.data?.policy || res.data?.policy || '';

      setPolicyName(name);
      setIsEditMode(true);
      // Relecture différée jusqu'au chargement des coffres (voir l'effet ci-dessous)
      setLoadedHcl(hcl);
    } catch (err) {
      // Si c'est une 404, c'est une nouvelle policy - initialiser vide
      if (err.response?.status === 404) {
        secureLogger.debug('[AdminPanel] Nouvelle policy - initialisation vide');
        setPolicyName(name);
        setIsEditMode(true);
        setAllowListMounts(true);
        setPaths([
          {
            type: 'coffre',
            coffre: '',
            secret: '',
            accessLevel: 'read-only',
            includeTotp: true,
            totpLevel: 'read-only'
          }
        ]);
        setEditStatus('ready');
      } else {
        // Lecture impossible : ne surtout pas permettre d'écraser la policy avec l'état par défaut
        setEditStatus('error');
        showToast(t('admin.builder.loadError'), 'error');
        secureLogger.error('[AdminPanel] Erreur chargement policy');
      }
    }
  };

  // Relire la policy une fois le HCL ET les coffres disponibles. L'aller-retour doit
  // être fidèle (HCL régénéré ≡ HCL d'origine) : sinon la policy n'est pas éditable
  // ici, car « Sauvegarder » sans changement modifierait ses droits.
  React.useEffect(() => {
    if (loadedHcl === null || analyzedRef.current) return;
    if (allMounts.length === 0 && !mountsLoaded) return;
    analyzedRef.current = true;
    const result = analyzePolicyForBuilder(loadedHcl, { allMounts, ldapAuthPath, policyName: editPolicyName || '' });
    if (result.faithful) {
      setAllowListMounts(result.allowListMounts);
      setPaths(result.paths);
      setEditStatus('ready');
      // Charger la liste des secrets des coffres ayant des règles par secret (sélecteurs)
      new Set(result.paths.filter(p => p.type === 'secret').map(p => p.coffre)).forEach(c => loadSecretsForMount(c));
    } else {
      secureLogger.debug('[AdminPanel] Policy non représentable dans le builder');
      setEditStatus('unsupported');
    }
    // Analyse unique (analyzedRef) : ne dépend que du HCL lu et des coffres chargés
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadedHcl, allMounts, mountsLoaded]);

  const closeModal = () => {
    onClose();
  };

  // Charger les secrets d'un coffre
  const loadSecretsForMount = async (mountPath, index) => {
    try {
      const mount = allMounts.find(m => m.path === mountPath);
      if (!mount) {
        secureLogger.error('[AdminPanel] Mount non trouvé');
        return;
      }

      let secretsList = [];
      if (mount.version === 2) {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(mount.path)}/metadata?list=true`,
          axiosConfig({ headers: baseHeaders() })
        );
        const allKeys = res.data?.data?.keys || [];

        // Filtrer les dossiers
        const keys = allKeys.filter(k => !k.endsWith('/'));

        // Pour KV v2, vérifier si les secrets sont supprimés
        const secretsWithStatus = await Promise.all(
          keys.map(async (key) => {
            try {
              const metaRes = await axios.get(
                `${vaultUrl}/v1/${encodeEnginePath(mount.path)}/metadata/${encodeURIComponent(key)}`,
                axiosConfig({ headers: baseHeaders() })
              );
              const currentVersion = metaRes.data?.data?.current_version;
              const versionData = metaRes.data?.data?.versions?.[currentVersion];

              // Retourner null si supprimé
              if (versionData?.deletion_time) {
                return null;
              }
              return key;
            } catch {
              return null; // En cas d'erreur, on ignore ce secret
            }
          })
        );

        // Filtrer les secrets non supprimés
        secretsList = secretsWithStatus.filter(k => k !== null);
      } else {
        const res = await axios.get(
          `${vaultUrl}/v1/${encodeEnginePath(mount.path)}?list=true`,
          axiosConfig({ headers: baseHeaders() })
        );
        secretsList = res.data?.data?.keys || [];
        // Filtrer les dossiers
        secretsList = secretsList.filter(k => !k.endsWith('/'));
      }

      setAvailableSecrets(prev => ({ ...prev, [mountPath]: secretsList }));
    } catch (err) {
      secureLogger.error('[AdminPanel] Erreur chargement secrets');
      setAvailableSecrets(prev => ({ ...prev, [mountPath]: [] }));
    }
  };

  const addPath = () => {
    setPaths([...paths, {
      type: 'coffre',
      coffre: '',
      secret: '',
      accessLevel: 'read-only',
      includeTotp: true,
      totpLevel: 'read-only'
    }]);
  };

  const removePath = (index) => {
    setPaths(paths.filter((_, i) => i !== index));
  };

  const updatePath = (index, field, value) => {
    const newPaths = [...paths];
    newPaths[index][field] = value;

    // Si on change de coffre, réinitialiser le secret et charger les secrets
    if (field === 'coffre' && value) {
      newPaths[index].secret = '';
      loadSecretsForMount(value, index);
    }

    // Si on change le type vers "secret" et qu'un coffre est déjà sélectionné, charger les secrets
    if (field === 'type' && value === 'secret' && newPaths[index].coffre) {
      loadSecretsForMount(newPaths[index].coffre, index);
    }

    // Si on change le niveau d'accès, synchroniser le niveau TOTP
    if (field === 'accessLevel') {
      if (value === 'read-only' || value === 'rbi-only') {
        newPaths[index].totpLevel = 'read-only';
      } else if (value === 'read-write' || value === 'moderator' || value === 'full-admin') {
        newPaths[index].totpLevel = 'read-write';
      }
    }

    setPaths(newPaths);
  };

  // Génération déléguée au module pur policyHcl (HCL identique à l'implémentation précédente)
  const generateHCL = () => generatePolicyHcl({ paths, allowListMounts, allMounts, ldapAuthPath, policyName });

  const handleSave = async () => {
    // SÉCURITÉ : jamais de réécriture d'une policy non relue fidèlement (ou pas encore relue)
    if (editStatus !== 'ready') {
      if (editStatus === 'unsupported') showToast(t('admin.builder.unsupportedTitle'), 'error');
      return;
    }
    if (!policyName.trim()) {
      showToast(t('admin.builder.nameRequired'), 'error');
      return;
    }

    const validPaths = paths.filter(p => p.coffre && (p.type === 'coffre' || (p.type === 'secret' && p.secret)));
    if (validPaths.length === 0) {
      showToast(t('admin.builder.pathRequired'), 'error');
      return;
    }

    const hclContent = generateHCL();
    await savePolicy(policyName.trim(), hclContent);
    closeModal();
  };

  // Couleurs du thème (variables CSS) : l'ancien panneau blanc et ses encadrés pastel codés en
  // dur restaient clairs en thème sombre, sous un texte clair illisible.
  const smallLabelStyle = { fontSize: 11, color: 'var(--text-tertiary)', display: 'block', marginBottom: 4 };
  const hintStyle = { fontSize: 11, color: 'var(--text-tertiary)' };
  const selectStyle = {
    width: '100%',
    padding: 6,
    // --border-control n'existe qu'en thème sombre (≥ 3:1) ; repli = gris clair d'origine
    border: '1px solid var(--border-control, var(--border-hover))',
    borderRadius: 6,
    fontSize: 13,
    background: 'var(--bg-surface)',
    color: 'var(--text-primary)'
  };
  const pathItemStyle = {
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
    background: 'var(--bg-app)'
  };
  const warningNoteStyle = {
    fontSize: 11,
    color: 'var(--warning-text)',
    background: 'var(--warning-bg)',
    border: '1px solid var(--warning-border)',
    borderRadius: 6,
    padding: '6px 8px'
  };
  const infoTextStyle = { fontSize: 11, color: 'var(--info-text)', marginBottom: 6, fontStyle: 'italic' };
  const codeStyle = { background: 'var(--bg-surface)', color: 'var(--text-primary)', padding: '2px 6px', borderRadius: 4, fontWeight: 600 };

  return (
    <Modal
      title={isEditMode ? `✏️ ${t('admin.editPolicy')}` : `🛠️ ${t('admin.builder.title')}`}
      onClose={closeModal}
      maxWidth="700px"
      footer={(
        <>
          <button type="button" className="btn btn-secondary" onClick={closeModal}>
            {t('common.cancel')}
          </button>
          <button
            type="button"
            className="btn btn-success"
            onClick={handleSave}
            disabled={editStatus !== 'ready'}
          >
            💾 {t('admin.builder.savePolicy')}
          </button>
        </>
      )}
    >
        <label className="modal-label" htmlFor={nameId}>{t('admin.policyName')}*</label>
        {/* Nom de policy : identifiant technique saisi de gauche à droite (ADMIN-11) ; texte
            indicatif traduit dans le sens de la langue tant que le champ est vide */}
        <input
          id={nameId}
          type="text"
          dir={ltrWhenFilled(policyName)}
          className="modal-input"
          style={{ marginBottom: 16, ...(isEditMode ? { background: 'var(--bg-surface-active)', color: 'var(--text-secondary)', cursor: 'not-allowed' } : {}) }}
          placeholder={t('admin.common.example', { value: 'app-read-write' })}
          value={policyName}
          onChange={(e) => setPolicyName(e.target.value)}
          disabled={isEditMode}
        />

        {/* Policy non représentable : avertissement, aucune règle éditable ici */}
        {editStatus === 'unsupported' && (
          <div role="alert" style={{ marginBottom: 16, padding: 12, background: 'var(--warning-bg)', border: '1px solid var(--warning)', borderRadius: 8, color: 'var(--warning-text)' }}>
            <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>⚠️ {t('admin.builder.unsupportedTitle')}</div>
            <div style={{ fontSize: 12 }}>{t('admin.builder.unsupportedText')}</div>
          </div>
        )}
        {editStatus === 'loading' && (
          <p style={{ fontSize: 13, color: 'var(--text-tertiary)', marginBottom: 16 }}>{t('common.loading')}</p>
        )}

        {editStatus === 'ready' && (<>
        {/* Option globale pour lister les coffres */}
        <div style={{ marginBottom: 16, padding: 12, background: 'var(--bg-app)', border: '1px solid var(--border)', borderRadius: 8 }}>
          <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={allowListMounts}
              onChange={(e) => setAllowListMounts(e.target.checked)}
              style={{ marginInlineEnd: 8, width: 16, height: 16 }}
            />
            <span style={{ fontSize: 13, fontWeight: 600 }}>📋 {t('admin.builder.listMounts')}</span>
          </label>
          {/* ADMIN-16 : marges logiques (case et retrait de l'aide suivent le sens d'écriture) */}
          <div style={{ ...hintStyle, marginTop: 4, marginInlineStart: 24 }}>
            {t('admin.builder.listMountsHint')}
          </div>
        </div>

        <div className="modal-label">{t('admin.builder.rules')}</div>
        {paths.map((p, idx) => (
          <div key={idx} style={pathItemStyle}>
            {/* En-tête avec type et suppression */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <label style={smallLabelStyle} htmlFor={`${nameId}-type-${idx}`}>{t('admin.builder.accessType')}</label>
                <select
                  id={`${nameId}-type-${idx}`}
                  style={selectStyle}
                  value={p.type}
                  onChange={(e) => updatePath(idx, 'type', e.target.value)}
                >
                  <option value="coffre">{t('admin.builder.typeVault')}</option>
                  <option value="secret">{t('admin.builder.typeSecret')}</option>
                </select>
              </div>
              {paths.length > 1 && (
                <button
                  type="button"
                  style={{ padding: '8px 12px', border: '1px solid var(--error)', borderRadius: 6, background: 'var(--bg-surface)', color: 'var(--error)', cursor: 'pointer', marginTop: 18 }}
                  onClick={() => removePath(idx)}
                >
                  ✕ {t('admin.builder.remove')}
                </button>
              )}
            </div>

            {/* Sélection du coffre */}
            <div style={{ marginBottom: 12 }}>
              <label style={smallLabelStyle} htmlFor={`${nameId}-vault-${idx}`}>
                {p.type === 'coffre' ? t('admin.common.vault') : t('admin.builder.vaultContainingSecret')}
              </label>
              <select
                id={`${nameId}-vault-${idx}`}
                style={selectStyle}
                value={p.coffre}
                onChange={(e) => updatePath(idx, 'coffre', e.target.value)}
              >
                <option value="">{t('admin.builder.selectVault')}</option>
                {allMounts.filter(m => m.type === 'kv').map(mount => (
                  <option key={mount.path} value={mount.path}>
                    {ltrIsolate(`${mount.path}/ (KV v${mount.version})`)}
                  </option>
                ))}
              </select>
            </div>

            {/* Sélection du secret (seulement si type = secret) */}
            {p.type === 'secret' && p.coffre && (
              <div style={{ marginBottom: 12 }}>
                <label style={smallLabelStyle} htmlFor={`${nameId}-secret-${idx}`}>{t('admin.builder.secret')}</label>
                <select
                  id={`${nameId}-secret-${idx}`}
                  style={selectStyle}
                  value={p.secret}
                  onChange={(e) => updatePath(idx, 'secret', e.target.value)}
                >
                  <option value="">{t('admin.builder.selectSecret')}</option>
                  {/* Secret relu depuis la policy mais absent du listing (supprimé, non listable) : conservé */}
                  {p.secret && !(availableSecrets[p.coffre] || []).includes(p.secret) && (
                    <option value={p.secret}>{p.secret}</option>
                  )}
                  {(availableSecrets[p.coffre] || []).map(secretName => (
                    <option key={secretName} value={secretName}>
                      {secretName}
                    </option>
                  ))}
                </select>
                {(!availableSecrets[p.coffre] || availableSecrets[p.coffre].length === 0) && (
                  <div style={{ ...hintStyle, marginTop: 4 }}>
                    {t('admin.builder.noSecrets')}
                  </div>
                )}
              </div>
            )}

            {/* Niveau d'accès */}
            <div style={{ marginBottom: 12 }}>
              <label style={smallLabelStyle} htmlFor={`${nameId}-access-${idx}`}>{t('admin.builder.accessLevel')}</label>
              <select
                id={`${nameId}-access-${idx}`}
                style={selectStyle}
                value={p.accessLevel}
                onChange={(e) => updatePath(idx, 'accessLevel', e.target.value)}
              >
                <option value="read-only">{`🔒 ${t('admin.builder.levelReadOnly')}`}</option>
                <option value="rbi-only">{`🖥️ ${t('admin.builder.levelRbi')}`}</option>
                <option value="read-write">{`✏️ ${t('admin.builder.levelReadWrite')}`}</option>
                <option value="moderator">{`👮 ${t('admin.builder.levelModerator')}`}</option>
                <option value="full-admin">{`👑 ${t('admin.builder.levelFullAdmin')}`}</option>
              </select>
              {/* « RBI uniquement » : mêmes droits Vault que la lecture seule (le client lit
                  le secret avec le jeton de l'utilisateur pour l'injecter) → restriction d'UI */}
              {p.accessLevel === 'rbi-only' && (
                <div style={{ ...warningNoteStyle, marginTop: 6 }}>
                  ⚠️ {t('admin.builder.rbiVaultLimit')}
                </div>
              )}
            </div>

            {/* TOTP */}
            {p.coffre && (p.type === 'coffre' || (p.type === 'secret' && p.secret)) && (
              <div style={{ marginTop: 12, padding: 10, background: 'var(--info-bg)', border: '1px solid var(--info-border)', borderRadius: 6 }}>
                <label style={{ display: 'flex', alignItems: 'center', cursor: p.accessLevel === 'rbi-only' ? 'default' : 'pointer', marginBottom: 8 }}>
                  <input
                    type="checkbox"
                    checked={p.includeTotp || p.accessLevel === 'rbi-only'}
                    onChange={(e) => updatePath(idx, 'includeTotp', e.target.checked)}
                    disabled={p.accessLevel === 'rbi-only'}
                    style={{ marginInlineEnd: 8, width: 16, height: 16 }}
                  />
                  <span style={{ fontSize: 12, fontWeight: 600 }}>{t('admin.builder.includeTotp')}</span>
                  {p.accessLevel === 'rbi-only' && (
                    <span style={{ fontSize: 10, color: 'var(--info-text)', marginInlineStart: 8, fontStyle: 'italic' }}>{t('admin.builder.totpAutoRbi')}</span>
                  )}
                </label>
                {(p.includeTotp || p.accessLevel === 'rbi-only') && (
                  <div style={{ marginInlineStart: 24 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>
                      {p.type === 'secret'
                        ? <>{t('admin.builder.totpKey')} <code style={codeStyle}>{totpPrefixFor(p.coffre)}-{p.secret}</code></>
                        : <>{t('admin.builder.totpPrefix')} <code style={codeStyle}>{totpPrefixFor(p.coffre)}-*</code></>
                      }
                    </div>
                    {/* Les globs Vault sont des préfixes et le nom de clé TOTP n'inclut ni le
                        propriétaire ni de séparateur réservé (format existant, non modifiable) :
                        signaler les coffres dont les clés tombent aussi sous ce préfixe */}
                    {(() => {
                      const collisions = p.type === 'coffre' ? totpPrefixCollisions(p.coffre, allMounts) : [];
                      const personal = /^users\/[^/]+\//i.test(p.coffre);
                      if (collisions.length === 0 && !personal) return null;
                      const prefix = p.type === 'secret' ? `${totpPrefixFor(p.coffre)}-${p.secret}` : `${totpPrefixFor(p.coffre)}-*`;
                      return (
                        <div style={{ ...warningNoteStyle, marginBottom: 6 }}>
                          {collisions.length > 0 && <div>⚠️ {t('admin.builder.totpPrefixShared', { prefix, vaults: collisions.join(', ') })}</div>}
                          {personal && <div>⚠️ {t('admin.builder.totpPrefixPersonal', { prefix })}</div>}
                        </div>
                      );
                    })()}
                    {p.accessLevel === 'rbi-only' ? (
                      <div style={infoTextStyle}>
                        {t('admin.builder.totpRbiReadOnly')}
                      </div>
                    ) : (
                      <>
                        <div style={infoTextStyle}>
                          {t('admin.builder.totpFollows')}
                        </div>
                        <select
                          style={{ ...selectStyle, border: '1px solid var(--info-border)', fontSize: 12 }}
                          value={p.totpLevel}
                          onChange={(e) => updatePath(idx, 'totpLevel', e.target.value)}
                        >
                          <option value="read-only">{t('admin.builder.totpReadOnly')}</option>
                          <option value="read-write">{t('admin.builder.totpReadWrite')}</option>
                        </select>
                      </>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        <button
          type="button"
          className="btn btn-secondary"
          style={{ width: '100%', marginBottom: 16 }}
          onClick={addPath}
        >
          + {t('admin.builder.addRule')}
        </button>
        </>)}

        {(editStatus === 'ready' || editStatus === 'unsupported') && (
          <div style={{ background: 'var(--bg-surface-active)', padding: 12, borderRadius: 8 }}>
            <div style={{ ...hintStyle, marginBottom: 6 }}>
              {editStatus === 'unsupported' ? t('admin.builder.currentHcl') : t('admin.builder.preview')}
            </div>
            {/* Non représentable : la policy réelle, et non un HCL régénéré trompeur */}
            <pre style={{ fontSize: 11, margin: 0, whiteSpace: 'pre-wrap', color: 'var(--text-primary)' }}>
              {editStatus === 'unsupported' ? loadedHcl : generateHCL()}
            </pre>
          </div>
        )}
    </Modal>
  );
}
