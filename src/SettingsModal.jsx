// src/SettingsModal.jsx
import React, { useState, useEffect } from 'react';
import { useTranslation, LANGUAGES } from './i18n';
import axios from 'axios';

const encodeEnginePath = (name) => {
  return name.replace(/^\/+|\/+$/g, '')
    .split('/')
    .map(segment => encodeURIComponent(segment))
    .join('/');
};

export default function SettingsModal({
  darkMode,
  onToggleDarkMode,
  visibleColumns,
  onToggleColumn,
  discoveredTags = [],
  isAdmin = false,
  isModerator = false,
  onClose,
  appVersion = '1.1.0',
  secretEngines = [],
  appMode = 'enterprise',
  vaultUrl = '',
  token = '',
  axiosConfig = () => ({}),
  baseHeaders = () => ({}),
  showToast = () => {}
}) {
  const { t, lang, setLang } = useTranslation();
  const [activeTab, setActiveTab] = useState('appearance');
  const [exportEngine, setExportEngine] = useState('');
  const [exportFormat, setExportFormat] = useState('csv');
  const [exporting, setExporting] = useState(false);
  const [importEngine, setImportEngine] = useState('');
  const [importFile, setImportFile] = useState(null); // { name, content }
  const [importing, setImporting] = useState(false);
  const [importDuplicateMode, setImportDuplicateMode] = useState('skip'); // 'skip' or 'overwrite'

  // État des règles CLI d'auto-approbation (persisté en localStorage)
  const [cliAutoApprove, setCliAutoApprove] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('rdvault-cli-auto-approve') || '{}');
    } catch { return {}; }
  });

  // État du listing par coffre (persisté en localStorage)
  const [cliListApprove, setCliListApprove] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('rdvault-cli-list-approve') || '{}');
    } catch { return {}; }
  });

  // Synchroniser les deux états (auto-approve + list) avec le serveur CLI
  useEffect(() => {
    localStorage.setItem('rdvault-cli-auto-approve', JSON.stringify(cliAutoApprove));
    localStorage.setItem('rdvault-cli-list-approve', JSON.stringify(cliListApprove));
    // Construire la liste des règles au format "engine/*"
    const rules = Object.entries(cliAutoApprove)
      .filter(([, enabled]) => enabled)
      .map(([engine]) => `${engine.replace(/\/+$/, '')}/*`);
    // Envoyer les règles d'auto-approbation via IPC
    if (window.electronCLI?.setAutoApproveRules) {
      window.electronCLI.setAutoApproveRules(rules);
    }
    // Envoyer la liste des engines autorisés pour le listing via IPC
    const allowedEngines = Object.entries(cliListApprove)
      .filter(([, enabled]) => enabled)
      .map(([engine]) => engine.replace(/\/+$/, ''));
    if (window.electronCLI?.setListSecretsEngines) {
      window.electronCLI.setListSecretsEngines(allowedEngines);
    }
  }, [cliAutoApprove, cliListApprove]);

  const toggleCLIAutoApprove = (engineName) => {
    setCliAutoApprove(prev => ({
      ...prev,
      [engineName]: !prev[engineName]
    }));
  };

  const toggleCLIListApprove = (engineName) => {
    setCliListApprove(prev => ({
      ...prev,
      [engineName]: !prev[engineName]
    }));
  };

  // ========================================
  // EXPORT
  // ========================================
  const handleExport = async () => {
    if (!exportEngine || !vaultUrl || !token) return;
    setExporting(true);

    try {
      const engine = secretEngines.find(e => e.name === exportEngine);
      if (!engine) { showToast(t('export.error'), 'error'); return; }

      // Lister les clés récursivement
      const allKeys = [];
      const listKeys = async (prefix = '') => {
        const url = engine.version === 2
          ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/metadata/${prefix ? prefix.split('/').map(s => encodeURIComponent(s)).join('/') : ''}?list=true`
          : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}${prefix ? '/' + prefix : ''}?list=true`;
        try {
          const res = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
          const keys = res.data?.data?.keys || [];
          for (const key of keys) {
            if (key.endsWith('/')) {
              await listKeys(prefix ? `${prefix}${key}` : key);
            } else {
              allKeys.push(prefix ? `${prefix}${key}` : key);
            }
          }
        } catch { /* ignore 404 */ }
      };
      await listKeys();

      if (allKeys.length === 0) {
        showToast(t('export.noSecrets'), 'warning');
        return;
      }

      // Lire tous les secrets
      const secrets = [];
      for (const key of allKeys) {
        try {
          const url = engine.version === 2
            ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(key)}`
            : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(key)}`;
          const res = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
          const data = engine.version === 2 ? (res.data?.data?.data || {}) : (res.data?.data || {});
          const portField = (data.CustomFields || []).find(f => f.key === 'Port' || f.key === 'port');
          secrets.push({
            name: key,
            username: data.Username || '',
            password: data.Password || '',
            url: data.URL || '',
            notes: data.Notes || '',
            tags: data.Tags || '',
            port: portField ? portField.value : ''
          });
        } catch { /* skip unreadable secrets */ }
      }

      // Générer le contenu
      let content = '';
      let extension = exportFormat;
      if (exportFormat === 'csv') {
        const escCsv = (v) => {
          let s = String(v);
          // Neutraliser l'injection de formules Excel (=, +, -, @, |)
          if (/^[=+\-@|\t\r]/.test(s)) s = "'" + s;
          return `"${s.replace(/"/g, '""')}"`;
        };
        content = 'Name,Username,Password,URL,Notes,Tags,Port\n';
        content += secrets.map(s =>
          [s.name, s.username, s.password, s.url, s.notes, s.tags, s.port].map(escCsv).join(',')
        ).join('\n');
      } else {
        content = '<?xml version="1.0" encoding="UTF-8"?>\n<vault>\n';
        const escXml = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        for (const s of secrets) {
          content += `  <secret>\n`;
          content += `    <name>${escXml(s.name)}</name>\n`;
          content += `    <username>${escXml(s.username)}</username>\n`;
          content += `    <password>${escXml(s.password)}</password>\n`;
          content += `    <url>${escXml(s.url)}</url>\n`;
          content += `    <notes>${escXml(s.notes)}</notes>\n`;
          content += `    <tags>${escXml(s.tags)}</tags>\n`;
          content += `    <port>${escXml(s.port)}</port>\n`;
          content += `  </secret>\n`;
        }
        content += '</vault>';
      }

      // Sauvegarder via dialogue Electron
      if (window.electronExport?.saveFile) {
        const result = await window.electronExport.saveFile({
          defaultName: `${engine.name.replace(/\//g, '-')}-export.${extension}`,
          filters: exportFormat === 'csv'
            ? [{ name: 'CSV', extensions: ['csv'] }]
            : [{ name: 'XML', extensions: ['xml'] }],
          content
        });
        if (result.success) {
          showToast(t('export.success', { count: secrets.length }), 'success');
        } else if (!result.canceled) {
          showToast(t('export.error'), 'error');
        }
      }
    } catch (err) {
      showToast(t('export.error'), 'error');
    } finally {
      setExporting(false);
    }
  };

  // ========================================
  // IMPORT
  // ========================================
  const handleSelectFile = async () => {
    if (!window.electronExport?.openFile) return;
    const result = await window.electronExport.openFile({
      filters: [
        { name: 'CSV / XML', extensions: ['csv', 'xml'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });
    if (result.success) {
      const name = result.filePath.split(/[/\\]/).pop();
      setImportFile({ name, content: result.content });
    }
  };

  const parseCSV = (content) => {
    const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length < 2) return [];
    // Détecter le séparateur (virgule ou point-virgule)
    const sep = lines[0].includes(';') ? ';' : ',';
    const header = lines[0].split(sep).map(h => h.replace(/^"|"$/g, '').trim().toLowerCase());
    const secrets = [];
    for (let i = 1; i < lines.length; i++) {
      const values = [];
      let current = '';
      let inQuotes = false;
      for (const char of lines[i]) {
        if (char === '"') { inQuotes = !inQuotes; continue; }
        if (char === sep && !inQuotes) { values.push(current.trim()); current = ''; continue; }
        current += char;
      }
      values.push(current.trim());
      const row = {};
      header.forEach((h, idx) => { row[h] = values[idx] || ''; });
      if (row.name || row.nom) {
        secrets.push({
          name: row.name || row.nom || '',
          Username: row.username || row.identifiant || row.user || '',
          Password: row.password || row['mot de passe'] || row.mdp || '',
          URL: row.url || '',
          Notes: row.notes || row.note || '',
          Tags: row.tags || row.tag || '',
          Port: row.port || ''
        });
      }
    }
    return secrets;
  };

  const parseXML = (content) => {
    const secrets = [];
    const secretRegex = /<secret>([\s\S]*?)<\/secret>/gi;
    let match;
    while ((match = secretRegex.exec(content)) !== null) {
      const block = match[1];
      const get = (tag) => {
        const m = block.match(new RegExp(`<${tag}>(.*?)</${tag}>`, 's'));
        return m ? m[1].replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"') : '';
      };
      secrets.push({
        name: get('name'),
        Username: get('username'),
        Password: get('password'),
        URL: get('url'),
        Notes: get('notes'),
        Tags: get('tags'),
        Port: get('port')
      });
    }
    return secrets;
  };

  const handleImport = async () => {
    if (!importEngine || !importFile || !vaultUrl || !token) return;
    setImporting(true);

    try {
      const engine = secretEngines.find(e => e.name === importEngine);
      if (!engine) { showToast(t('export.importError'), 'error'); return; }

      // Parser le fichier
      const isXml = importFile.name.toLowerCase().endsWith('.xml') || importFile.content.trim().startsWith('<?xml') || importFile.content.trim().startsWith('<vault');
      const parsed = isXml ? parseXML(importFile.content) : parseCSV(importFile.content);

      if (parsed.length === 0) {
        showToast(t('export.importNoData'), 'warning');
        return;
      }

      let imported = 0;
      for (const secret of parsed) {
        if (!secret.name) continue;
        // Validation du nom : pas de path traversal, pas de caractères de contrôle
        if (secret.name.includes('..') || /[\x00-\x1F]/.test(secret.name) || secret.name.length > 512) continue;
        try {
          // Si mode skip, vérifier si le secret existe déjà
          if (importDuplicateMode === 'skip') {
            try {
              const checkUrl = engine.version === 2
                ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(secret.name)}`
                : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(secret.name)}`;
              await axios.get(checkUrl, axiosConfig({ headers: baseHeaders() }));
              continue; // Existe déjà, skip
            } catch { /* N'existe pas, on continue */ }
          }

          // Écrire le secret
          const data = {
            Username: secret.Username,
            Password: secret.Password,
            URL: secret.URL,
            Notes: secret.Notes,
            Tags: secret.Tags
          };
          if (secret.Port) {
            data.CustomFields = [{ key: 'Port', value: secret.Port }];
          }

          if (engine.version === 2) {
            await axios.post(
              `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(secret.name)}`,
              { data },
              axiosConfig({ headers: baseHeaders() })
            );
          } else {
            await axios.post(
              `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(secret.name)}`,
              data,
              axiosConfig({ headers: baseHeaders() })
            );
          }
          imported++;
        } catch { /* skip erreur individuelle */ }
      }

      showToast(t('export.importSuccess', { count: imported }), 'success');
      setImportFile(null);
    } catch (err) {
      showToast(t('export.importError'), 'error');
    } finally {
      setImporting(false);
    }
  };

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onClose]);

  const allColumns = [
    { key: 'name', label: t('table.name'), locked: true },
    { key: 'username', label: t('table.username') },
    { key: 'password', label: t('table.password') },
    { key: 'url', label: t('table.url') },
    { key: 'notes', label: t('table.notes') },
    { key: 'tags', label: t('table.tags') },
    { key: 'customFields', label: t('table.customFields') },
    { key: 'actions', label: t('table.actions'), locked: true }
  ];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '750px', maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}
      >
        <div className="modal-header" style={{ borderBottom: '2px solid var(--border-color)' }}>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)', margin: 0 }}>
            <span style={{ fontSize: '24px' }}>⚙️</span>
            <span>{t('settings.title')}</span>
          </h2>
        </div>

        {/* Onglets — en dehors du scroll */}
        <div style={{
          display: 'flex',
          gap: 'var(--sp-1)',
          borderBottom: '2px solid var(--border-color)',
          background: 'var(--bg-primary)',
          padding: 'var(--sp-2) var(--sp-6) 0 var(--sp-6)',
          flexShrink: 0
        }}>
          <button
            onClick={() => setActiveTab('appearance')}
            className={activeTab === 'appearance' ? 'tab-button tab-button-active' : 'tab-button'}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="4"/>
              <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41"/>
            </svg>
            <span>{t('settings.appearance')}</span>
          </button>
          <button
            onClick={() => setActiveTab('columns')}
            className={activeTab === 'columns' ? 'tab-button tab-button-active' : 'tab-button'}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
            </svg>
            <span>{t('settings.columns')}</span>
          </button>
          <button
            onClick={() => setActiveTab('cli')}
            className={activeTab === 'cli' ? 'tab-button tab-button-active' : 'tab-button'}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="4 17 10 11 4 5"/>
              <line x1="12" y1="19" x2="20" y2="19"/>
            </svg>
            <span>{t('settings.cli')}</span>
          </button>
          <button
            onClick={() => setActiveTab('language')}
            className={activeTab === 'language' ? 'tab-button tab-button-active' : 'tab-button'}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="2" y1="12" x2="22" y2="12"/>
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            <span>{t('settings.language')}</span>
          </button>
          <button
            onClick={() => setActiveTab('export')}
            className={activeTab === 'export' ? 'tab-button tab-button-active' : 'tab-button'}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            <span>{t('export.title')}</span>
          </button>
          <button
            onClick={() => setActiveTab('about')}
            className={activeTab === 'about' ? 'tab-button tab-button-active' : 'tab-button'}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            <span>{t('settings.about')}</span>
          </button>
        </div>

        {/* Contenu scrollable */}
        <div className="modal-body" style={{ overflowY: 'auto', maxHeight: 'calc(85vh - 200px)' }}>
          {/* Onglet Apparence */}
          {activeTab === 'appearance' && (
            <div>
              <h3 style={{
                fontSize: 'var(--text-lg)',
                fontWeight: 'var(--weight-bold)',
                marginBottom: 'var(--sp-4)',
                color: 'var(--text-primary)'
              }}>
                {t('settings.selectTheme')}
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-4)' }}>
                <label style={{
                  padding: 'var(--sp-4)',
                  border: !darkMode ? '3px solid var(--accent)' : '2px solid var(--border-color)',
                  borderRadius: 'var(--radius-lg)',
                  cursor: 'pointer',
                  transition: 'all var(--duration-base)',
                  background: !darkMode ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 'var(--sp-3)',
                  boxShadow: !darkMode ? '0 4px 12px rgba(0,0,0,0.1)' : 'none'
                }}>
                  <input
                    type="radio"
                    name="theme"
                    checked={!darkMode}
                    onChange={() => !darkMode ? null : onToggleDarkMode()}
                    style={{ display: 'none' }}
                  />
                  <div style={{ fontSize: '48px', lineHeight: 1 }}>☀️</div>
                  <div style={{
                    fontSize: 'var(--text-base)',
                    fontWeight: 'var(--weight-bold)',
                    color: 'var(--text-primary)'
                  }}>
                    {t('settings.lightMode')}
                  </div>
                  <div style={{
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                    textAlign: 'center'
                  }}>
                    {t('settings.lightModeDesc')}
                  </div>
                </label>
                <label style={{
                  padding: 'var(--sp-4)',
                  border: darkMode ? '3px solid var(--accent)' : '2px solid var(--border-color)',
                  borderRadius: 'var(--radius-lg)',
                  cursor: 'pointer',
                  transition: 'all var(--duration-base)',
                  background: darkMode ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 'var(--sp-3)',
                  boxShadow: darkMode ? '0 4px 12px rgba(0,0,0,0.1)' : 'none'
                }}>
                  <input
                    type="radio"
                    name="theme"
                    checked={darkMode}
                    onChange={() => darkMode ? null : onToggleDarkMode()}
                    style={{ display: 'none' }}
                  />
                  <div style={{ fontSize: '48px', lineHeight: 1 }}>🌙</div>
                  <div style={{
                    fontSize: 'var(--text-base)',
                    fontWeight: 'var(--weight-bold)',
                    color: 'var(--text-primary)'
                  }}>
                    {t('settings.darkMode')}
                  </div>
                  <div style={{
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                    textAlign: 'center'
                  }}>
                    {t('settings.darkModeDesc')}
                  </div>
                </label>
              </div>
            </div>
          )}

          {/* Onglet Colonnes */}
          {activeTab === 'columns' && (
            <div>
              <h3 style={{
                fontSize: 'var(--text-lg)',
                fontWeight: 'var(--weight-bold)',
                marginBottom: 'var(--sp-2)',
                color: 'var(--text-primary)'
              }}>
                {t('settings.columnsTitle')}
              </h3>
              <p style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                marginBottom: 'var(--sp-4)'
              }}>
                {t('settings.columnsDesc')}
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-2)' }}>
                {allColumns.map(col => (
                  <label
                    key={col.key}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 'var(--sp-2)',
                      padding: 'var(--sp-3)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius)',
                      cursor: col.locked ? 'not-allowed' : 'pointer',
                      background: visibleColumns[col.key] !== false ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                      transition: 'all var(--duration-base)',
                      opacity: col.locked ? 0.6 : 1
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={visibleColumns[col.key] !== false}
                      onChange={() => !col.locked && onToggleColumn(col.key)}
                      disabled={col.locked}
                      style={{ cursor: col.locked ? 'not-allowed' : 'pointer' }}
                    />
                    <div style={{ flex: 1 }}>
                      <div style={{
                        fontSize: 'var(--text-base)',
                        fontWeight: 'var(--weight-medium)',
                        color: 'var(--text-primary)'
                      }}>
                        {col.label}
                      </div>
                      {col.locked && (
                        <div style={{
                          fontSize: 'var(--text-xs)',
                          color: 'var(--text-tertiary)',
                          marginTop: '2px'
                        }}>
                          {t('settings.lockedColumn')}
                        </div>
                      )}
                    </div>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Onglet CLI */}
          {activeTab === 'cli' && (
            <div>
              <h3 style={{
                fontSize: 'var(--text-lg)',
                fontWeight: 'var(--weight-bold)',
                marginBottom: 'var(--sp-2)',
                color: 'var(--text-primary)'
              }}>
                {t('cli.title')}
              </h3>
              <p style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                marginBottom: 'var(--sp-4)',
                lineHeight: 1.6
              }}>
                {t('cli.description', { cli: 'mvault' })}
              </p>

              {secretEngines.length === 0 ? (
                <div style={{
                  padding: 'var(--sp-4)',
                  textAlign: 'center',
                  color: 'var(--text-tertiary)',
                  background: 'var(--bg-surface)',
                  borderRadius: 'var(--radius-lg)',
                  border: '1px solid var(--border-color)'
                }}>
                  {t('cli.noEngines')}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
                  {/* En-tête du tableau */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '0 var(--sp-4) var(--sp-2) var(--sp-4)',
                    borderBottom: '1px solid var(--border-color)',
                    gap: 'var(--sp-3)'
                  }}>
                    <div style={{ flex: 1, fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-bold)', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {t('cli.vault')}
                    </div>
                    <div style={{ width: '80px', textAlign: 'center', fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-bold)', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {t('cli.listing')}
                    </div>
                    <div style={{ width: '80px', textAlign: 'center', fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-bold)', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {t('cli.autoGet')}
                    </div>
                  </div>
                  {secretEngines.map(engine => {
                    const engineKey = engine.name.replace(/\/+$/, '');
                    const autoApproved = !!cliAutoApprove[engineKey];
                    const listApproved = !!cliListApprove[engineKey];
                    return (
                      <div
                        key={engine.name}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          padding: 'var(--sp-3) var(--sp-4)',
                          border: '1px solid var(--border-color)',
                          borderRadius: 'var(--radius)',
                          background: (autoApproved || listApproved) ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                          transition: 'all var(--duration-base)',
                          gap: 'var(--sp-3)'
                        }}
                      >
                        {/* Nom du coffre */}
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{
                            fontSize: 'var(--text-sm)',
                            fontWeight: 'var(--weight-medium)',
                            color: 'var(--text-primary)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 'var(--sp-2)',
                            overflow: 'hidden'
                          }}>
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{engineKey}</span>
                            <span style={{
                              fontSize: 'var(--text-xs)',
                              color: 'var(--text-tertiary)',
                              background: 'var(--bg-primary)',
                              padding: '1px 5px',
                              borderRadius: 'var(--radius-sm)',
                              flexShrink: 0
                            }}>
                              v{engine.version}
                            </span>
                          </div>
                        </div>
                        {/* Toggle Listing */}
                        <div style={{ width: '80px', display: 'flex', justifyContent: 'center' }}>
                          <button
                            onClick={() => toggleCLIListApprove(engineKey)}
                            type="button"
                            title={listApproved ? t('cli.listingApproved') : t('cli.listingDenied')}
                            style={{
                              position: 'relative',
                              width: '40px',
                              height: '22px',
                              borderRadius: '11px',
                              border: 'none',
                              cursor: 'pointer',
                              background: listApproved ? 'var(--accent)' : 'var(--border-color)',
                              transition: 'background var(--duration-base)',
                              flexShrink: 0
                            }}
                          >
                            <span style={{
                              position: 'absolute',
                              top: '2px',
                              left: listApproved ? '20px' : '2px',
                              width: '18px',
                              height: '18px',
                              borderRadius: '50%',
                              background: '#fff',
                              transition: 'left var(--duration-base)',
                              boxShadow: '0 1px 3px rgba(0,0,0,0.2)'
                            }} />
                          </button>
                        </div>
                        {/* Toggle Auto-get */}
                        <div style={{ width: '80px', display: 'flex', justifyContent: 'center' }}>
                          <button
                            onClick={() => toggleCLIAutoApprove(engineKey)}
                            type="button"
                            title={autoApproved ? t('cli.autoApproved') : t('cli.confirmRequired')}
                            style={{
                              position: 'relative',
                              width: '40px',
                              height: '22px',
                              borderRadius: '11px',
                              border: 'none',
                              cursor: 'pointer',
                              background: autoApproved ? 'var(--accent)' : 'var(--border-color)',
                              transition: 'background var(--duration-base)',
                              flexShrink: 0
                            }}
                          >
                            <span style={{
                              position: 'absolute',
                              top: '2px',
                              left: autoApproved ? '20px' : '2px',
                              width: '18px',
                              height: '18px',
                              borderRadius: '50%',
                              background: '#fff',
                              transition: 'left var(--duration-base)',
                              boxShadow: '0 1px 3px rgba(0,0,0,0.2)'
                            }} />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              <div style={{
                marginTop: 'var(--sp-4)',
                padding: 'var(--sp-3)',
                background: 'var(--bg-surface)',
                borderRadius: 'var(--radius)',
                border: '1px solid var(--border-color)'
              }}>
                <h4 style={{
                  fontSize: 'var(--text-sm)',
                  fontWeight: 'var(--weight-bold)',
                  marginBottom: 'var(--sp-2)',
                  color: 'var(--text-primary)'
                }}>
                  {t('cli.quickUsage')}
                </h4>
                <div style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--text-secondary)',
                  fontFamily: 'monospace',
                  lineHeight: 1.8
                }}>
                  <div>mvault engines<span style={{ color: 'var(--text-tertiary)', marginLeft: '16px' }}>{t('cli.listEngines')}</span></div>
                  <div>mvault get engine/secret<span style={{ color: 'var(--text-tertiary)', marginLeft: '16px' }}>{t('cli.readSecret')}</span></div>
                  <div>mvault get engine/secret -k password<span style={{ color: 'var(--text-tertiary)', marginLeft: '16px' }}>{t('cli.extractField')}</span></div>
                </div>
              </div>
            </div>
          )}

          {/* Onglet Langue */}
          {activeTab === 'language' && (
            <div>
              <h3 style={{
                fontSize: 'var(--text-lg)',
                fontWeight: 'var(--weight-bold)',
                marginBottom: 'var(--sp-2)',
                color: 'var(--text-primary)'
              }}>
                {t('settings.selectLanguage')}
              </h3>
              <p style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                marginBottom: 'var(--sp-4)'
              }}>
                {t('settings.languageDesc')}
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--sp-2)' }}>
                {LANGUAGES.map(language => {
                  const isSelected = lang === language.code;
                  return (
                    <button
                      key={language.code}
                      onClick={() => setLang(language.code)}
                      type="button"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 'var(--sp-3)',
                        padding: 'var(--sp-3) var(--sp-4)',
                        border: isSelected ? '2px solid var(--accent)' : '1px solid var(--border-color)',
                        borderRadius: 'var(--radius)',
                        cursor: 'pointer',
                        background: isSelected ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                        transition: 'all var(--duration-base)',
                        textAlign: 'left',
                        width: '100%'
                      }}
                    >
                      <span style={{ fontSize: '24px' }}>{language.flag}</span>
                      <div>
                        <div style={{
                          fontSize: 'var(--text-base)',
                          fontWeight: isSelected ? 'var(--weight-bold)' : 'var(--weight-medium)',
                          color: 'var(--text-primary)'
                        }}>
                          {language.name}
                        </div>
                        <div style={{
                          fontSize: 'var(--text-xs)',
                          color: 'var(--text-tertiary)'
                        }}>
                          {language.code.toUpperCase()}
                        </div>
                      </div>
                      {isSelected && (
                        <span style={{ marginLeft: 'auto', color: 'var(--accent)', fontSize: '18px' }}>✓</span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Onglet Export */}
          {activeTab === 'export' && (
            <div>
              <h3 style={{
                fontSize: 'var(--text-lg)',
                fontWeight: 'var(--weight-bold)',
                marginBottom: 'var(--sp-2)',
                color: 'var(--text-primary)'
              }}>
                {t('export.title')}
              </h3>
              <p style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                marginBottom: 'var(--sp-4)'
              }}>
                {t('export.description')}
              </p>

              {/* Sélection du coffre */}
              <label style={{
                display: 'block',
                fontSize: 'var(--text-sm)',
                fontWeight: 'var(--weight-bold)',
                color: 'var(--text-primary)',
                marginBottom: 'var(--sp-2)'
              }}>
                {t('export.selectVault')}
              </label>
              <select
                value={exportEngine}
                onChange={(e) => setExportEngine(e.target.value)}
                style={{
                  width: '100%',
                  padding: 'var(--sp-2) var(--sp-3)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius)',
                  background: 'var(--bg-surface)',
                  color: 'var(--text-primary)',
                  fontSize: 'var(--text-base)',
                  marginBottom: 'var(--sp-4)'
                }}
              >
                <option value="">--</option>
                {secretEngines
                  .filter(e => appMode === 'local' || e.canWrite !== false)
                  .map(e => (
                    <option key={e.name} value={e.name}>
                      {e.name} (KV v{e.version})
                    </option>
                  ))
                }
              </select>

              {/* Sélection du format */}
              <label style={{
                display: 'block',
                fontSize: 'var(--text-sm)',
                fontWeight: 'var(--weight-bold)',
                color: 'var(--text-primary)',
                marginBottom: 'var(--sp-2)'
              }}>
                {t('export.format')}
              </label>
              <div style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
                <label style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--sp-2)',
                  padding: 'var(--sp-2) var(--sp-3)',
                  border: exportFormat === 'csv' ? '2px solid var(--accent)' : '1px solid var(--border-color)',
                  borderRadius: 'var(--radius)',
                  cursor: 'pointer',
                  background: exportFormat === 'csv' ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                  flex: 1
                }}>
                  <input type="radio" name="exportFormat" value="csv" checked={exportFormat === 'csv'} onChange={() => setExportFormat('csv')} />
                  {t('export.csv')}
                </label>
                <label style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--sp-2)',
                  padding: 'var(--sp-2) var(--sp-3)',
                  border: exportFormat === 'xml' ? '2px solid var(--accent)' : '1px solid var(--border-color)',
                  borderRadius: 'var(--radius)',
                  cursor: 'pointer',
                  background: exportFormat === 'xml' ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                  flex: 1
                }}>
                  <input type="radio" name="exportFormat" value="xml" checked={exportFormat === 'xml'} onChange={() => setExportFormat('xml')} />
                  {t('export.xml')}
                </label>
              </div>

              {/* Bouton export */}
              <button
                onClick={handleExport}
                disabled={!exportEngine || exporting}
                className="btn btn-primary"
                type="button"
                style={{ width: '100%', fontSize: 'var(--text-base)' }}
              >
                {exporting ? t('export.exporting') : t('export.exportBtn')}
              </button>

              {/* Séparateur */}
              <div style={{
                borderTop: '2px solid var(--border-color)',
                margin: 'var(--sp-5) 0',
                paddingTop: 'var(--sp-4)'
              }}>
                <h3 style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 'var(--weight-bold)',
                  marginBottom: 'var(--sp-2)',
                  color: 'var(--text-primary)'
                }}>
                  {t('export.importTitle')}
                </h3>
                <p style={{
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-secondary)',
                  marginBottom: 'var(--sp-4)'
                }}>
                  {t('export.importDescription')}
                </p>

                {/* Sélection du coffre de destination */}
                <label style={{
                  display: 'block',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 'var(--weight-bold)',
                  color: 'var(--text-primary)',
                  marginBottom: 'var(--sp-2)'
                }}>
                  {t('export.importSelectVault')}
                </label>
                <select
                  value={importEngine}
                  onChange={(e) => setImportEngine(e.target.value)}
                  style={{
                    width: '100%',
                    padding: 'var(--sp-2) var(--sp-3)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius)',
                    background: 'var(--bg-surface)',
                    color: 'var(--text-primary)',
                    fontSize: 'var(--text-base)',
                    marginBottom: 'var(--sp-4)'
                  }}
                >
                  <option value="">--</option>
                  {secretEngines
                    .filter(e => appMode === 'local' || e.canWrite !== false)
                    .map(e => (
                      <option key={e.name} value={e.name}>
                        {e.name} (KV v{e.version})
                      </option>
                    ))
                  }
                </select>

                {/* Sélection du fichier */}
                <div style={{
                  display: 'flex',
                  gap: 'var(--sp-3)',
                  alignItems: 'center',
                  marginBottom: 'var(--sp-3)'
                }}>
                  <button
                    onClick={handleSelectFile}
                    className="btn btn-secondary"
                    type="button"
                    style={{ flexShrink: 0 }}
                  >
                    {t('export.importSelectFile')}
                  </button>
                  <span style={{
                    fontSize: 'var(--text-sm)',
                    color: importFile ? 'var(--text-primary)' : 'var(--text-tertiary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap'
                  }}>
                    {importFile ? importFile.name : t('export.importNoFile')}
                  </span>
                </div>

                {/* Mode doublons */}
                <div style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
                  <label style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--sp-2)',
                    fontSize: 'var(--text-sm)',
                    cursor: 'pointer'
                  }}>
                    <input
                      type="radio"
                      name="importDuplicate"
                      checked={importDuplicateMode === 'skip'}
                      onChange={() => setImportDuplicateMode('skip')}
                    />
                    {t('export.importDuplicate')}
                  </label>
                  <label style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--sp-2)',
                    fontSize: 'var(--text-sm)',
                    cursor: 'pointer'
                  }}>
                    <input
                      type="radio"
                      name="importDuplicate"
                      checked={importDuplicateMode === 'overwrite'}
                      onChange={() => setImportDuplicateMode('overwrite')}
                    />
                    {t('export.importOverwrite')}
                  </label>
                </div>

                {/* Bouton import */}
                <button
                  onClick={handleImport}
                  disabled={!importEngine || !importFile || importing}
                  className="btn btn-primary"
                  type="button"
                  style={{ width: '100%', fontSize: 'var(--text-base)' }}
                >
                  {importing ? t('export.importing') : t('export.importBtn')}
                </button>
              </div>
            </div>
          )}

          {/* Onglet À propos */}
          {activeTab === 'about' && (
            <div>
              <div style={{
                textAlign: 'center',
                padding: 'var(--sp-5)',
                background: 'linear-gradient(135deg, var(--bg-surface) 0%, var(--bg-primary) 100%)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--border-color)',
                marginBottom: 'var(--sp-4)'
              }}>
                <img src={process.env.PUBLIC_URL + '/logo.png'} alt="RDVAULT" style={{ height: '100px', width: 'auto', marginBottom: 'var(--sp-3)' }} />
                <h2 style={{
                  fontSize: '2.5rem',
                  marginBottom: 'var(--sp-2)',
                  fontWeight: 'var(--weight-bold)',
                  color: 'var(--text-primary)'
                }}>
                  RDVAULT
                </h2>
                <p style={{
                  fontSize: 'var(--text-lg)',
                  color: 'var(--text-secondary)',
                  marginBottom: 'var(--sp-2)',
                  fontWeight: 'var(--weight-medium)'
                }}>
                  {t('aboutPage.version', { version: appVersion })}
                </p>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)', lineHeight: 1.6 }}>
                  <p style={{ margin: 'var(--sp-1) 0' }}>{t('aboutPage.description')}</p>
                  <p style={{ margin: 'var(--sp-1) 0' }}>{t('aboutPage.copyright', { year: new Date().getFullYear() })}</p>
                </div>
              </div>

              <div style={{
                padding: 'var(--sp-4)',
                background: 'var(--bg-surface)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--border-color)'
              }}>
                <h4 style={{
                  fontSize: 'var(--text-lg)',
                  fontWeight: 'var(--weight-bold)',
                  marginBottom: 'var(--sp-3)',
                  color: 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--sp-2)'
                }}>
                  <span>🆕</span>
                  <span>{t('aboutPage.whatsNew', { version: '1.4.0' })}</span>
                </h4>
                <ul style={{
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-secondary)',
                  paddingLeft: 'var(--sp-4)',
                  lineHeight: 1.8,
                  margin: 0
                }}>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.framelessWindow')}</strong> - {t('aboutPage.framelessWindowDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.customButtons')}</strong> - {t('aboutPage.customButtonsDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.improvedSearch')}</strong> - {t('aboutPage.improvedSearchDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.tagSearch')}</strong> - {t('aboutPage.tagSearchDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.tagCreation')}</strong> - {t('aboutPage.tagCreationDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.restoreDeleted')}</strong> - {t('aboutPage.restoreDeletedDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.shiftClick')}</strong> - {t('aboutPage.shiftClickDesc')}
                  </li>
                  <li>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.bugFixes')}</strong> - {t('aboutPage.bugFixesDesc')}
                  </li>
                </ul>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer" style={{
          borderTop: '2px solid var(--border-color)',
          padding: 'var(--sp-4)',
          display: 'flex',
          justifyContent: 'flex-end'
        }}>
          <button
            onClick={onClose}
            className="btn btn-primary"
            type="button"
            style={{ minWidth: '120px', fontSize: 'var(--text-base)' }}
          >
            {t('common.close')}
          </button>
        </div>
      </div>
    </div>
  );
}
