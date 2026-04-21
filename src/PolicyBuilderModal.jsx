// src/PolicyBuilderModal.jsx
import React from 'react';
import axios from 'axios';

const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export default function PolicyBuilderModal({
  vaultUrl,
  axiosConfig,
  baseHeaders,
  showToast,
  allMounts,
  loadAllMounts,
  editPolicyName,
  savePolicy,
  onClose
}) {
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
  const inputRef = React.useRef(null);

  React.useEffect(() => {
    inputRef.current?.focus();
    // Charger les mounts si pas déjà chargés
    if (allMounts.length === 0) {
      loadAllMounts();
    }

    // Si mode édition, charger la policy
    if (editPolicyName) {
      loadPolicyForEdit(editPolicyName);
    }
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

      // Parser le HCL pour extraire les configs
      parseHclToState(hcl);
    } catch (err) {
      showToast('Erreur lors du chargement de la policy', 'error');
      // Erreur chargement politique (secureLogger non dispo ici, erreur silencieuse)
    }
  };

  // Parser le HCL et mettre à jour l'état
  const parseHclToState = (hcl) => {
    // Vérifier si sys/mounts est présent
    const hasMountsList = hcl.includes('path "sys/mounts"');
    setAllowListMounts(hasMountsList);

    const parsedPaths = [];

    // Extraire les coffres KV
    const kvDataMatches = hcl.match(/path "([^"]+)\/(?:data|metadata)\/\*"/g) || [];
    const kvV1Matches = hcl.match(/path "([^"]+)\/\*"/g) || [];

    const processedCoffres = new Set();

    // Détecter si la policy contient le marqueur RBI-ONLY
    const hasRbiOnly = hcl.includes('# RBI-ONLY');

    // Parser KV v2
    for (const match of kvDataMatches) {
      const pathMatch = match.match(/path "([^"]+)\/(data|metadata)\/\*"/);
      if (pathMatch) {
        const coffreName = pathMatch[1];

        if (processedCoffres.has(coffreName) || coffreName === 'sys/mounts') continue;
        processedCoffres.add(coffreName);

        // Détecter le niveau d'accès
        let accessLevel = 'read-only';
        const dataPathRegex = new RegExp(`path "${escapeRegex(coffreName)}/data/\\*"[^}]+capabilities = \\[([^\\]]+)\\]`);
        const dataMatch = hcl.match(dataPathRegex);

        if (dataMatch) {
          const caps = dataMatch[1];
          if (caps.includes('sudo')) {
            accessLevel = 'full-admin';
          } else if (caps.includes('create') || caps.includes('update') || caps.includes('delete')) {
            accessLevel = 'read-write';
          } else if (hasRbiOnly) {
            accessLevel = 'rbi-only';
          }
        } else if (hasRbiOnly) {
          accessLevel = 'rbi-only';
        }

        // Vérifier TOTP
        const coffreNameUpper = coffreName.toUpperCase();
        const hasTotpKeys = hcl.includes(`path "TOTP/keys/${coffreNameUpper}-*"`);
        const hasTotpCode = hcl.includes(`path "TOTP/code/${coffreNameUpper}-*"`);
        const hasTotpValidate = hcl.includes(`path "TOTP/validate/${coffreNameUpper}-*"`);

        // Synchroniser le niveau TOTP avec le niveau d'accès
        let totpLevel = 'read-only';
        if (accessLevel === 'read-write' || accessLevel === 'full-admin') {
          totpLevel = 'read-write';
        }

        parsedPaths.push({
          type: 'coffre',
          coffre: coffreName,
          secret: '',
          accessLevel,
          includeTotp: hasTotpCode || hasTotpKeys || hasTotpValidate,
          totpLevel: hasTotpKeys ? 'read-write' : totpLevel
        });
      }
    }

    // Parser KV v1 (seulement si pas déjà traité en v2)
    for (const match of kvV1Matches) {
      const pathMatch = match.match(/path "([^"]+)\/\*"/);
      if (pathMatch) {
        const coffreName = pathMatch[1];

        if (processedCoffres.has(coffreName) || coffreName === 'sys/mounts' || coffreName.includes('/')) continue;
        processedCoffres.add(coffreName);

        // Détecter le niveau d'accès
        let accessLevel = 'read-only';
        const pathRegex = new RegExp(`path "${escapeRegex(coffreName)}/\\*"[^}]+capabilities = \\[([^\\]]+)\\]`);
        const pathMatchCaps = hcl.match(pathRegex);

        if (pathMatchCaps) {
          const caps = pathMatchCaps[1];
          if (caps.includes('sudo')) {
            accessLevel = 'full-admin';
          } else if (caps.includes('create') || caps.includes('update') || caps.includes('delete')) {
            accessLevel = 'read-write';
          } else if (hasRbiOnly) {
            accessLevel = 'rbi-only';
          }
        } else if (hasRbiOnly) {
          accessLevel = 'rbi-only';
        }

        // Vérifier TOTP
        const coffreNameUpper = coffreName.toUpperCase();
        const hasTotpKeys = hcl.includes(`path "TOTP/keys/${coffreNameUpper}-*"`);
        const hasTotpCode = hcl.includes(`path "TOTP/code/${coffreNameUpper}-*"`);
        const hasTotpValidate = hcl.includes(`path "TOTP/validate/${coffreNameUpper}-*"`);

        // Synchroniser le niveau TOTP avec le niveau d'accès
        let totpLevel = 'read-only';
        if (accessLevel === 'read-write' || accessLevel === 'full-admin') {
          totpLevel = 'read-write';
        }

        parsedPaths.push({
          type: 'coffre',
          coffre: coffreName,
          secret: '',
          accessLevel,
          includeTotp: hasTotpCode || hasTotpKeys || hasTotpValidate,
          totpLevel: hasTotpKeys ? 'read-write' : totpLevel
        });
      }
    }

    if (parsedPaths.length > 0) {
      setPaths(parsedPaths);
    }
  };

  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Charger les secrets d'un coffre
  const loadSecretsForMount = async (mountPath) => {
    try {
      const mount = allMounts.find(m => m.path === mountPath);
      if (!mount) {
        // Mount non trouvé (ne pas logger le mountPath)
        return;
      }

      let secretsList = [];
      if (mount.version === 2) {
        const res = await axios.get(
          `${vaultUrl}/v1/${mount.path}/metadata?list=true`,
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
                `${vaultUrl}/v1/${mount.path}/metadata/${encodeURIComponent(key)}`,
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
          `${vaultUrl}/v1/${mount.path}?list=true`,
          axiosConfig({ headers: baseHeaders() })
        );
        secretsList = res.data?.data?.keys || [];
        // Filtrer les dossiers
        secretsList = secretsList.filter(k => !k.endsWith('/'));
      }

      setAvailableSecrets(prev => ({ ...prev, [mountPath]: secretsList }));
    } catch (err) {
      // Erreur chargement secrets
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
      loadSecretsForMount(value);
    }

    // Si on change le type vers "secret" et qu'un coffre est déjà sélectionné, charger les secrets
    if (field === 'type' && value === 'secret' && newPaths[index].coffre) {
      loadSecretsForMount(newPaths[index].coffre);
    }

    // Si on change le niveau d'accès, synchroniser le niveau TOTP
    if (field === 'accessLevel') {
      if (value === 'read-only' || value === 'rbi-only') {
        newPaths[index].totpLevel = 'read-only';
      } else if (value === 'read-write' || value === 'full-admin') {
        newPaths[index].totpLevel = 'read-write';
      }
    }

    setPaths(newPaths);
  };

  const generateHCL = () => {
    let hcl = '# Policy générée par le builder\n\n';
    const addedMetadataList = new Set();

    // Ajouter le listing des coffres si demandé
    if (allowListMounts) {
      hcl += '# Lister tous les coffres\n';
      hcl += 'path "sys/mounts"   { capabilities = ["read","list"] }\n';
      hcl += 'path "sys/mounts/*" { capabilities = ["read","list"] }\n\n';
    }

    paths.forEach(p => {
      if (!p.coffre) return; // Skip si pas de coffre sélectionné

      // SÉCURITÉ: Sanitiser le nom du coffre pour éviter l'injection HCL
      const safeCoffre = p.coffre.replace(/[\r\n"\\]/g, '');
      if (safeCoffre !== p.coffre || !safeCoffre) return;

      const mount = allMounts.find(m => m.path === p.coffre);
      if (!mount) return;

      const coffreName = p.coffre
        .replace(/^users\/[^/]+\//i, '')
        .replace(/\/$/, '')
        .toUpperCase();

      if (p.type === 'coffre') {
        // Accès au coffre entier
        if (mount.version === 2) {
          // KV v2
          if (p.accessLevel === 'rbi-only') {
            hcl += `# RBI-ONLY\n`;
            hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read"] }\n`;
            hcl += `path "${p.coffre}/data/*"     { capabilities = ["read"] }\n\n`;
          } else if (p.accessLevel === 'read-only') {
            hcl += `# KV v2 RO\n`;
            hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read"] }\n`;
            hcl += `path "${p.coffre}/data/*"     { capabilities = ["read"] }\n\n`;
          } else if (p.accessLevel === 'read-write') {
            hcl += `# KV v2 RW complet\n`;
            hcl += `path "${p.coffre}/metadata/*" { capabilities = ["list","read","delete"] }\n`;
            hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","update","read","delete","list"] }\n`;
            hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update"] }\n`;
            hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update"] }\n`;
            hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update"] }\n\n`;
          } else if (p.accessLevel === 'full-admin') {
            hcl += `# KV v2 Full Admin\n`;
            hcl += `path "${p.coffre}/metadata/*" { capabilities = ["create","read","update","delete","list","sudo"] }\n`;
            hcl += `path "${p.coffre}/data/*"     { capabilities = ["create","read","update","delete","list","sudo"] }\n`;
            hcl += `path "${p.coffre}/delete/*"   { capabilities = ["update","sudo"] }\n`;
            hcl += `path "${p.coffre}/undelete/*" { capabilities = ["update","sudo"] }\n`;
            hcl += `path "${p.coffre}/destroy/*"  { capabilities = ["update","sudo"] }\n\n`;
          }
        } else {
          // KV v1
          if (p.accessLevel === 'rbi-only') {
            hcl += `# RBI-ONLY\n`;
            hcl += `path "${p.coffre}/*" { capabilities = ["read","list"] }\n\n`;
          } else if (p.accessLevel === 'read-only') {
            hcl += `# KV v1 RO\n`;
            hcl += `path "${p.coffre}/*" { capabilities = ["read","list"] }\n\n`;
          } else if (p.accessLevel === 'read-write') {
            hcl += `# KV v1 RW\n`;
            hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list"] }\n\n`;
          } else if (p.accessLevel === 'full-admin') {
            hcl += `# KV v1 Full Admin\n`;
            hcl += `path "${p.coffre}/*" { capabilities = ["create","read","update","delete","list","sudo"] }\n\n`;
          }
        }

        // Ajouter TOTP si demandé OU si RBI-only (nécessaire pour l'injection automatique en session sécurisée)
        if (p.includeTotp || p.accessLevel === 'rbi-only') {
          hcl += `# TOTP (${coffreName}-*)\n`;
          if (p.totpLevel === 'read-only' || p.accessLevel === 'rbi-only') {
            hcl += `path "TOTP/code/${coffreName}-*"     { capabilities = ["read"] }\n`;
            hcl += `path "TOTP/validate/${coffreName}-*" { capabilities = ["update"] }\n\n`;
          } else {
            hcl += `path "TOTP/keys/${coffreName}-*"     { capabilities = ["create","update","read","delete"] }\n`;
            hcl += `path "TOTP/code/${coffreName}-*"     { capabilities = ["read"] }\n`;
            hcl += `path "TOTP/validate/${coffreName}-*" { capabilities = ["update"] }\n\n`;
          }
        }
      } else if (p.type === 'secret' && p.secret) {
        // Accès à un secret spécifique
        let secretName = p.secret.replace(/\/$/, '');
        // SÉCURITÉ: Sanitiser le nom du secret pour éviter l'injection HCL
        secretName = secretName.replace(/[\r\n"\\]/g, '');
        if (!secretName) return;
        if (mount.version === 2) {
          // Listing du coffre nécessaire pour que l'app puisse énumérer les secrets
          if (!addedMetadataList.has(p.coffre)) {
            hcl += `# Listing secrets du coffre ${p.coffre}\n`;
            hcl += `path "${p.coffre}/metadata" { capabilities = ["list"] }\n\n`;
            addedMetadataList.add(p.coffre);
          }
          if (p.accessLevel === 'rbi-only') {
            hcl += `# RBI-ONLY\n`;
            hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RBI-ONLY)\n`;
            hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read"] }\n`;
            hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["read"] }\n\n`;
          } else if (p.accessLevel === 'read-only') {
            hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RO)\n`;
            hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read"] }\n`;
            hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["read"] }\n\n`;
          } else {
            hcl += `# Secret: ${p.coffre}/${secretName} (KV v2 RW)\n`;
            hcl += `path "${p.coffre}/metadata/${secretName}" { capabilities = ["read","delete"] }\n`;
            hcl += `path "${p.coffre}/data/${secretName}"     { capabilities = ["create","update","read","delete"] }\n\n`;
          }
        } else {
          // KV v1 : listing du coffre
          if (!addedMetadataList.has(p.coffre)) {
            hcl += `# Listing secrets du coffre ${p.coffre}\n`;
            hcl += `path "${p.coffre}" { capabilities = ["list"] }\n\n`;
            addedMetadataList.add(p.coffre);
          }
          if (p.accessLevel === 'rbi-only') {
            hcl += `# RBI-ONLY\n`;
            hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RBI-ONLY)\n`;
            hcl += `path "${p.coffre}/${secretName}" { capabilities = ["read"] }\n\n`;
          } else if (p.accessLevel === 'read-only') {
            hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RO)\n`;
            hcl += `path "${p.coffre}/${secretName}" { capabilities = ["read"] }\n\n`;
          } else {
            hcl += `# Secret: ${p.coffre}/${secretName} (KV v1 RW)\n`;
            hcl += `path "${p.coffre}/${secretName}" { capabilities = ["create","read","update","delete"] }\n\n`;
          }
        }

        // Ajouter TOTP pour secret spécifique
        if (p.includeTotp || p.accessLevel === 'rbi-only') {
          const sName = p.secret.replace(/\/$/, '').replace(/[\r\n"\\]/g, '');
          if (!sName) return;
          hcl += `# TOTP (${coffreName}-${sName})\n`;
          if (p.totpLevel === 'read-only' || p.accessLevel === 'rbi-only') {
            hcl += `path "TOTP/code/${coffreName}-${sName}"     { capabilities = ["read"] }\n`;
            hcl += `path "TOTP/validate/${coffreName}-${sName}" { capabilities = ["update"] }\n\n`;
          } else {
            hcl += `path "TOTP/keys/${coffreName}-${sName}"     { capabilities = ["create","update","read","delete"] }\n`;
            hcl += `path "TOTP/code/${coffreName}-${sName}"     { capabilities = ["read"] }\n`;
            hcl += `path "TOTP/validate/${coffreName}-${sName}" { capabilities = ["update"] }\n\n`;
          }
        }
      }
    });
    // Si la policy contient des restrictions RBI-ONLY, ajouter la permission
    // de lecture de sa propre policy (nécessaire pour la détection RBI côté client)
    const hasRbiOnly = paths.some(p => p.accessLevel === 'rbi-only');
    if (hasRbiOnly && policyName.trim()) {
      const safePolicyName = policyName.trim().replace(/[\r\n"\\]/g, '');
      if (safePolicyName) {
        hcl += '# Lecture de la policy (détection RBI côté client)\n';
        hcl += `path "sys/policies/acl/${safePolicyName}" { capabilities = ["read"] }\n\n`;
      }
    }

    return hcl || '# Aucun path configuré';
  };

  const handleSave = async () => {
    if (!policyName.trim()) {
      showToast('Veuillez entrer un nom de policy', 'error');
      return;
    }

    const validPaths = paths.filter(p => p.coffre && (p.type === 'coffre' || (p.type === 'secret' && p.secret)));
    if (validPaths.length === 0) {
      showToast('Veuillez configurer au moins un coffre ou secret', 'error');
      return;
    }

    const hclContent = generateHCL();
    await savePolicy(policyName.trim(), hclContent);
    onClose();
  };

  const overlayStyle = {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0,0,0,0.45)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 20000,
  };

  const panelStyle = {
    width: 700,
    maxWidth: '90vw',
    maxHeight: '90vh',
    background: '#fff',
    borderRadius: 12,
    boxShadow: '0 20px 60px rgba(0,0,0,0.35)',
    padding: 20,
    overflow: 'auto'
  };

  const titleStyle = {
    fontSize: 20,
    fontWeight: 700,
    marginBottom: 16
  };

  const labelStyle = {
    fontSize: 13,
    fontWeight: 600,
    color: '#374151',
    marginBottom: 6,
    display: 'block'
  };

  const inputStyle = {
    width: '100%',
    padding: 8,
    border: '1px solid #d1d5db',
    borderRadius: 6,
    fontSize: 14,
    marginBottom: 16
  };

  const pathItemStyle = {
    border: '1px solid #e5e7eb',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
    background: '#f9fafb'
  };

  const buttonRowStyle = {
    display: 'flex',
    justifyContent: 'space-between',
    gap: 8,
    marginTop: 16
  };

  const btnStyle = {
    padding: '8px 12px',
    borderRadius: 8,
    cursor: 'pointer',
    border: '1px solid #d1d5db',
    background: '#fff',
    color: '#111827'
  };

  const btnPrimaryStyle = {
    ...btnStyle,
    background: '#10b981',
    borderColor: '#10b981',
    color: '#fff'
  };

  const btnSecondaryStyle = {
    ...btnStyle,
    background: '#3b82f6',
    borderColor: '#3b82f6',
    color: '#fff'
  };

  return (
    <div style={overlayStyle} onClick={() => onClose()}>
      <div style={panelStyle} onClick={(e) => e.stopPropagation()}>
        <div style={titleStyle}>
          {isEditMode ? '✏️ Modifier la Policy' : '🛠️ Builder de Policy'}
        </div>

        <label style={labelStyle}>Nom de la policy*</label>
        <input
          ref={inputRef}
          type="text"
          style={{ ...inputStyle, ...(isEditMode ? { background: '#f3f4f6', cursor: 'not-allowed' } : {}) }}
          placeholder="ex: app-read-write"
          value={policyName}
          onChange={(e) => setPolicyName(e.target.value)}
          disabled={isEditMode}
        />

        {/* Option globale pour lister les coffres */}
        <div style={{ marginBottom: 16, padding: 12, background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8 }}>
          <label style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={allowListMounts}
              onChange={(e) => setAllowListMounts(e.target.checked)}
              style={{ marginRight: 8, width: 16, height: 16 }}
            />
            <span style={{ fontSize: 13, fontWeight: 600 }}>📋 Permettre le listing de tous les coffres (sys/mounts)</span>
          </label>
          <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4, marginLeft: 24 }}>
            Nécessaire pour que l'utilisateur puisse voir tous les coffres disponibles
          </div>
        </div>

        <label style={labelStyle}>Règles d'accès</label>
        {paths.map((p, idx) => (
          <div key={idx} style={pathItemStyle}>
            {/* En-tête avec type et suppression */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>Type d'accès</label>
                <select
                  style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                  value={p.type}
                  onChange={(e) => updatePath(idx, 'type', e.target.value)}
                >
                  <option value="coffre">Coffre entier</option>
                  <option value="secret">Secret spécifique</option>
                </select>
              </div>
              {paths.length > 1 && (
                <button
                  style={{ padding: '8px 12px', border: '1px solid #ef4444', borderRadius: 6, background: '#fff', color: '#ef4444', cursor: 'pointer', marginTop: 18 }}
                  onClick={() => removePath(idx)}
                  type="button"
                >
                  ✕ Retirer
                </button>
              )}
            </div>

            {/* Sélection du coffre */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>
                {p.type === 'coffre' ? 'Coffre' : 'Coffre contenant le secret'}
              </label>
              <select
                style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                value={p.coffre}
                onChange={(e) => updatePath(idx, 'coffre', e.target.value)}
              >
                <option value="">-- Sélectionnez un coffre --</option>
                {allMounts.filter(m => m.type === 'kv').map(mount => (
                  <option key={mount.path} value={mount.path}>
                    {mount.path}/ (KV v{mount.version})
                  </option>
                ))}
              </select>
            </div>

            {/* Sélection du secret (seulement si type = secret) */}
            {p.type === 'secret' && p.coffre && (
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>Secret</label>
                <select
                  style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                  value={p.secret}
                  onChange={(e) => updatePath(idx, 'secret', e.target.value)}
                >
                  <option value="">-- Sélectionnez un secret --</option>
                  {(availableSecrets[p.coffre] || []).map(secretName => (
                    <option key={secretName} value={secretName}>
                      {secretName}
                    </option>
                  ))}
                </select>
                {(!availableSecrets[p.coffre] || availableSecrets[p.coffre].length === 0) && (
                  <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 4 }}>
                    Aucun secret disponible ou chargement...
                  </div>
                )}
              </div>
            )}

            {/* Niveau d'accès */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 11, color: '#6b7280', display: 'block', marginBottom: 4 }}>Niveau d'accès</label>
              <select
                style={{ width: '100%', padding: 6, border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
                value={p.accessLevel}
                onChange={(e) => updatePath(idx, 'accessLevel', e.target.value)}
              >
                <option value="read-only">🔒 Lecture seule (RO)</option>
                <option value="rbi-only">🖥️ RBI uniquement (session securisee)</option>
                <option value="read-write">✏️ Lecture/Écriture (RW)</option>
                <option value="full-admin">👑 Full Admin (avec delete/undelete/destroy)</option>
              </select>
            </div>

            {/* TOTP */}
            {p.coffre && (p.type === 'coffre' || (p.type === 'secret' && p.secret)) && (
              <div style={{ marginTop: 12, padding: 10, background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 6 }}>
                <label style={{ display: 'flex', alignItems: 'center', cursor: p.accessLevel === 'rbi-only' ? 'default' : 'pointer', marginBottom: 8 }}>
                  <input
                    type="checkbox"
                    checked={p.includeTotp || p.accessLevel === 'rbi-only'}
                    onChange={(e) => updatePath(idx, 'includeTotp', e.target.checked)}
                    disabled={p.accessLevel === 'rbi-only'}
                    style={{ marginRight: 8, width: 16, height: 16 }}
                  />
                  <span style={{ fontSize: 12, fontWeight: 600 }}>Inclure acces TOTP</span>
                  {p.accessLevel === 'rbi-only' && (
                    <span style={{ fontSize: 11, color: '#3b82f6', marginLeft: 8, fontStyle: 'italic' }}>(inclus automatiquement en RBI)</span>
                  )}
                </label>
                {(p.includeTotp || p.accessLevel === 'rbi-only') && (
                  <div style={{ marginLeft: 24 }}>
                    <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 6 }}>
                      {p.type === 'secret'
                        ? <>Cle TOTP : <code style={{ background: '#fff', padding: '2px 6px', borderRadius: 4, fontWeight: 600 }}>{p.coffre.replace(/^users\/[^/]+\//i, '').replace(/\/$/, '').toUpperCase()}-{p.secret}</code></>
                        : <>Prefixe TOTP : <code style={{ background: '#fff', padding: '2px 6px', borderRadius: 4, fontWeight: 600 }}>{p.coffre.replace(/^users\/[^/]+\//i, '').replace(/\/$/, '').toUpperCase()}-*</code></>
                      }
                    </div>
                    <div style={{ fontSize: 11, color: '#3b82f6', marginBottom: 6, fontStyle: 'italic' }}>
                      {p.accessLevel === 'rbi-only'
                        ? 'Lecture seule (injection automatique en session securisee)'
                        : 'Le niveau TOTP suit automatiquement le niveau d\'acces du coffre'
                      }
                    </div>
                    {p.accessLevel !== 'rbi-only' && (
                      <select
                        style={{ width: '100%', padding: 6, border: '1px solid #bfdbfe', borderRadius: 6, fontSize: 12 }}
                        value={p.totpLevel}
                        onChange={(e) => updatePath(idx, 'totpLevel', e.target.value)}
                      >
                        <option value="read-only">Lecture seule (code/validate)</option>
                        <option value="read-write">Gestion complete (keys/code/validate)</option>
                      </select>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        <button
          type="button"
          style={{ ...btnSecondaryStyle, width: '100%', marginBottom: 16 }}
          onClick={addPath}
        >
          + Ajouter une règle
        </button>

        <div style={{ background: '#f3f4f6', padding: 12, borderRadius: 8, marginBottom: 16 }}>
          <div style={{ fontSize: 11, color: '#6b7280', marginBottom: 6 }}>Aperçu HCL :</div>
          <pre style={{ fontSize: 11, margin: 0, whiteSpace: 'pre-wrap', color: '#1f2937' }}>{generateHCL()}</pre>
        </div>

        <div style={buttonRowStyle}>
          <button
            type="button"
            style={btnStyle}
            onClick={onClose}
          >
            Annuler
          </button>
          <button
            type="button"
            style={btnPrimaryStyle}
            onClick={handleSave}
          >
            💾 Sauvegarder la policy
          </button>
        </div>
      </div>
    </div>
  );
}
