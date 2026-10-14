// src/SettingsModal.jsx
// Accessibilité de la modale (hook useDialogA11y du squelette commun Modal) : role="dialog" +
// aria-modal + aria-labelledby (titre), focus initial, piège de focus, retour du focus,
// Échap réservé à la modale du dessus.
import React, { useState, useEffect, useId, useLayoutEffect, useRef } from 'react';
import { useTranslation, LANGUAGES } from './i18n';
import { useDialogA11y } from './components/common/Modal';
import axios from 'axios';
import { encodeEnginePath, encodeSecretPath } from './utils/security';
import { escapeCsvField, parseCsv } from './utils/csv';
import { escapeXml, readXmlTag, hasXmlTag } from './utils/xml';
import { validateSecretName } from './validation';
import { isInternalSecretKey } from './utils/passkeyEngine';
import { engineDisplayName } from './components/layout/Sidebar';
import ExtensionTab from './components/settings/ExtensionTab';
import SecurityTab from './components/settings/SecurityTab';

// Texte technique dans un <option> (qui n'accepte pas d'élément <bdi>) : isolé et lu de gauche à
// droite par les caractères LRI (U+2066) … PDI (U+2069). En arabe, « Comptabilite/ (KV v2) »
// s'affichait « (Comptabilite/ (KV v2 » ; invisibles et sans effet dans les langues LTR.
const ltrIsolate = (text) => `\u2066${text}\u2069`;

// Libellé traduit suivi d'une liste de commandes entre parenthèses (« Lecture auto (get, ssh, winrm) ») :
// la parenthèse (commandes mvault) est isolée en ltr. En arabe, l'en-tête étroit passait à la ligne
// au milieu des parenthèses, mal appariées (« (WINRM »). Texte rendu identique à la traduction.
const withLtrParenthetical = (text) => {
  const m = /^(.*\S)(\s+)(\([^()]*\))$/.exec(String(text));
  return m ? <>{m[1]}{m[2]}<bdi dir="ltr" className="bidi-ltr">{m[3]}</bdi></> : text;
};

// ========================================
// EXPORT / IMPORT : règles communes
// ========================================

// Secrets internes RDVAULT (« .rdvault-passkeys », qui contient les clés privées des passkeys, et le
// témoin « .rdvault-keycheck ») : masqués de l'interface (useSecrets, readAllSecrets), jamais exportés et
// jamais écrasés par un import. COMPAT-2 : noms EXACTS à la racine du coffre (isInternalSecretKey) ; une
// entrée utilisateur « .rdvault-notes » ou « .rdvault » (permise en 1.5.0) est exportée et importée.
const isInternalSecretName = (name) => isInternalSecretKey(name);

// Nom importable : règles de l'éditeur (validateSecretName : longueur, « .. », « \ », contrôle),
// aucun segment vide ou « . » (« . », « /x », « x/ », « a//b » donnent des entrées illisibles),
// et jamais un nom réservé.
const isImportableName = (name) => validateSecretName(name).valid
  && !name.split('/').some(s => s === '' || s === '.' || s === '..')
  && !isInternalSecretName(name);

// SÉCURITÉ : champs « identifiants » (utilisateur, URL, tags, site, noms de champs) nettoyés des
// caractères de contrôle, sauf tabulation et sauts de ligne.
// IMPORT-5 : plus aucune troncature (avant : coupe silencieuse à 10 000 caractères) ; les notes et
// les valeurs de champs personnalisés sont reprises telles quelles, comme le mot de passe (l'éditeur
// les accepte avec leurs caractères de contrôle). Une valeur longue est signalée (hasLongValue).
// eslint-disable-next-line no-control-regex -- caractères de contrôle volontairement ciblés
const sanitizeField = (v) => typeof v === 'string' ? v.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') : '';
const verbatimField = (v) => (typeof v === 'string' ? v : '');

// Limite de l'éditeur pour les notes et les valeurs de champs personnalisés (validateSecret,
// EditSecretModal) : une entrée importée au-delà est conservée en entier mais signalée, car
// l'éditeur demandera de la raccourcir avant de l'enregistrer.
const EDITOR_TEXT_MAX = 10000;
const hasLongValue = (data) => ['Username', 'URL', 'Notes', 'Tags', 'Website']
  .some(k => typeof data[k] === 'string' && data[k].length > EDITOR_TEXT_MAX)
  || (Array.isArray(data.CustomFields)
    && data.CustomFields.some(f => f && typeof f.value === 'string' && f.value.length > EDITOR_TEXT_MAX));

// IMPORT-2 : le nom n'est plus rogné (« Banque » et « Banque␠ » sont deux entrées distinctes,
// permises par l'éditeur et le coffre ; avant : fusionnées sans avertissement). Seuls les blancs de
// MISE EN PAGE sont retirés : une suite d'espaces en début ou fin de nom qui contient un retour à la
// ligne ou une tabulation (XML indenté par un outil tiers ; un nom ne peut pas en contenir).
// Parcours linéaire (pas d'expression régulière à retour arrière sur un fichier arbitraire).
const stripLayoutWhitespace = (value) => {
  const s = String(value ?? '');
  let start = 0;
  while (start < s.length && /\s/.test(s[start])) start++;
  let end = s.length;
  while (end > start && /\s/.test(s[end - 1])) end--;
  const lead = s.slice(0, start);
  const trail = s.slice(end);
  return (/[\t\n\r]/.test(lead) ? '' : lead) + s.slice(start, end) + (/[\t\n\r]/.test(trail) ? '' : trail);
};

// Types d'entrée acceptés à l'import (« folder » n'est jamais stocké : c'est une action de l'éditeur)
const IMPORTABLE_ENTRY_TYPES = ['secret', 'ssh', 'placeholder'];
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

// Colonne « CustomFields » (JSON [{ key, value, protected? }]) → tableau nettoyé, ou null si invalide
const parseCustomFieldsCell = (raw) => {
  let list;
  try { list = JSON.parse(raw); } catch { return null; }
  if (!Array.isArray(list)) return null;
  const out = [];
  for (const f of list) {
    if (!f || typeof f !== 'object' || Array.isArray(f) || typeof f.key !== 'string') return null;
    if (f.value != null && !['string', 'number', 'boolean'].includes(typeof f.value)) return null;
    const field = { key: sanitizeField(f.key).slice(0, 256), value: verbatimField(f.value == null ? '' : String(f.value)) };
    if (typeof f.protected === 'boolean') field.protected = f.protected;
    out.push(field);
  }
  return out;
};

// Colonne « Attachments » (JSON [{ name, size?, type?, data (base64) }]) → tableau nettoyé, ou null si invalide
const parseAttachmentsCell = (raw) => {
  let list;
  try { list = JSON.parse(raw); } catch { return null; }
  if (!Array.isArray(list)) return null;
  const out = [];
  for (const a of list) {
    if (!a || typeof a !== 'object' || Array.isArray(a)) return null;
    if (typeof a.name !== 'string' || typeof a.data !== 'string' || !BASE64_RE.test(a.data)) return null;
    const att = { name: sanitizeField(a.name).slice(0, 255) };
    if (typeof a.size === 'number' && Number.isFinite(a.size) && a.size >= 0) att.size = a.size;
    if (typeof a.type === 'string') att.type = sanitizeField(a.type).slice(0, 255);
    att.data = a.data;
    out.push(att);
  }
  return out;
};

/**
 * Construit les données à écrire pour une ligne importée.
 * - `existing` : données actuelles du secret (mode « écraser les doublons ») ou null (nouveau secret).
 *   Les données existantes sont FUSIONNÉES : seules les colonnes présentes dans le fichier les
 *   remplacent (pièces jointes, champs personnalisés, etc. absents du fichier sont conservés).
 * - Colonnes étendues (Website, EntryType, CustomFields, Attachments) : une cellule vide ne change rien.
 * - La colonne Port met à jour (ou ajoute) le champ personnalisé « Port ».
 * @returns {Object|null} null si une colonne JSON est invalide (ligne refusée)
 */
const buildImportData = (rec, existing) => {
  let customFields;
  let attachments;
  if (rec.CustomFields !== undefined) {
    customFields = parseCustomFieldsCell(rec.CustomFields);
    if (!customFields) return null;
  }
  if (rec.Attachments !== undefined) {
    attachments = parseAttachmentsCell(rec.Attachments);
    if (!attachments) return null;
  }

  const data = existing
    ? { ...existing }
    : { Username: '', Password: '', URL: '', Notes: '', Tags: '' };
  for (const [k, v] of Object.entries(rec.fields)) {
    data[k] = k === 'Password' || k === 'Notes' ? verbatimField(v) : sanitizeField(v);
  }
  if (rec.Website !== undefined) data.Website = sanitizeField(rec.Website);
  if (rec.EntryType !== undefined && IMPORTABLE_ENTRY_TYPES.includes(rec.EntryType)) data.EntryType = rec.EntryType;

  let fields = customFields !== undefined
    ? customFields
    : (Array.isArray(data.CustomFields) ? data.CustomFields : undefined);
  if (rec.Port) {
    fields = Array.isArray(fields) ? fields.map(f => ({ ...f })) : [];
    const i = fields.findIndex(f => f && (f.key === 'Port' || f.key === 'port'));
    if (i >= 0) fields[i] = { ...fields[i], value: rec.Port };
    else fields.push({ key: 'Port', value: rec.Port });
  }
  if (fields !== undefined) {
    if (fields.length > 0) data.CustomFields = fields;
    else delete data.CustomFields;
  }
  if (attachments !== undefined) {
    if (attachments.length > 0) data.Attachments = attachments;
    else delete data.Attachments;
  }
  return data;
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
  appVersion = '1.7.0',
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
            const full = prefix ? `${prefix}${key}` : key;
            // Secrets internes (stockage des passkeys) : jamais exportés. Un réimport de l'export
            // en mode « écraser les doublons » remplaçait sinon les passkeys par une entrée vide.
            if (isInternalSecretName(full)) continue;
            if (key.endsWith('/')) {
              await listKeys(full);
            } else {
              allKeys.push(full);
            }
          }
        } catch { /* ignore 404 */ }
      };
      await listKeys();

      if (allKeys.length === 0) {
        showToast(t('export.noSecrets'), 'warning');
        return;
      }

      // Lire tous les secrets — les échecs de lecture individuels sont comptés
      // et signalés (export partiel) au lieu d'être silencieusement ignorés.
      const secrets = [];
      let failedReads = 0;
      for (const key of allKeys) {
        try {
          const url = engine.version === 2
            ? `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/data/${encodeURIComponent(key)}`
            : `${vaultUrl}/v1/${encodeEnginePath(engine.name)}/${encodeURIComponent(key)}`;
          const res = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
          const data = engine.version === 2 ? (res.data?.data?.data || {}) : (res.data?.data || {});
          const customFields = Array.isArray(data.CustomFields) ? data.CustomFields : [];
          const attachments = Array.isArray(data.Attachments) ? data.Attachments : [];
          const portField = customFields.find(f => f && (f.key === 'Port' || f.key === 'port'));
          secrets.push({
            name: key,
            username: data.Username || '',
            password: data.Password || '',
            url: data.URL || '',
            notes: data.Notes || '',
            tags: data.Tags || '',
            port: portField ? portField.value : '',
            // Colonnes étendues : l'export est une sauvegarde complète, réimportable sans perte
            website: data.Website || '',
            entryType: data.EntryType || '',
            customFields: customFields.length > 0 ? JSON.stringify(customFields) : '',
            attachments: attachments.length > 0 ? JSON.stringify(attachments) : ''
          });
        } catch (err) {
          // KV v2 : une entrée supprimée (suppression douce, dossier supprimé, source d'un
          // déplacement) reste listée mais sa lecture renvoie 404 avec metadata.deletion_time
          // (ou destroyed). Rien à exporter : ce n'est pas un échec de lecture.
          const meta = err?.response?.data?.data?.metadata;
          if (err?.response?.status === 404 && meta && (meta.deletion_time || meta.destroyed)) continue;
          failedReads++;
        }
      }

      if (secrets.length === 0) {
        if (failedReads > 0) showToast(t('export.error'), 'error');
        else showToast(t('export.noSecrets'), 'warning');
        return;
      }

      // Générer le contenu
      let content = '';
      let extension = exportFormat;
      if (exportFormat === 'csv') {
        // SÉCURITÉ : escapeCsvField neutralise l'injection de formules tableur
        // (=, +, -, @, |, tab, CR) — utilitaire partagé avec l'export admin.
        const escCsv = (v) => escapeCsvField(v, { separator: ',', alwaysQuote: true });
        // Les 7 premières colonnes gardent leur ordre historique (outils tiers, anciens imports) ;
        // CustomFields et Attachments sont du JSON.
        content = 'Name,Username,Password,URL,Notes,Tags,Port,Website,EntryType,CustomFields,Attachments\n';
        content += secrets.map(s =>
          [s.name, s.username, s.password, s.url, s.notes, s.tags, s.port,
            s.website, s.entryType, s.customFields, s.attachments].map(escCsv).join(',')
        ).join('\n');
      } else {
        content = '<?xml version="1.0" encoding="UTF-8"?>\n<vault>\n';
        const escXml = escapeXml;
        for (const s of secrets) {
          content += `  <secret>\n`;
          content += `    <name>${escXml(s.name)}</name>\n`;
          content += `    <username>${escXml(s.username)}</username>\n`;
          content += `    <password>${escXml(s.password)}</password>\n`;
          content += `    <url>${escXml(s.url)}</url>\n`;
          content += `    <notes>${escXml(s.notes)}</notes>\n`;
          content += `    <tags>${escXml(s.tags)}</tags>\n`;
          content += `    <port>${escXml(s.port)}</port>\n`;
          content += `    <website>${escXml(s.website)}</website>\n`;
          content += `    <entryType>${escXml(s.entryType)}</entryType>\n`;
          content += `    <customFields>${escXml(s.customFields)}</customFields>\n`;
          content += `    <attachments>${escXml(s.attachments)}</attachments>\n`;
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
          if (failedReads > 0) {
            showToast(t('export.partialSuccess', { count: secrets.length, failed: failedReads }), 'warning', 5000);
          } else {
            showToast(t('export.success', { count: secrets.length }), 'success');
          }
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
        { name: t('export.allFiles'), extensions: ['*'] }
      ]
    });
    if (result.success) {
      const name = result.filePath.split(/[/\\]/).pop();
      setImportFile({ name, content: result.content });
    }
  };

  // Format commun des lignes analysées :
  // { name, fields: { Username?, Password?, URL?, Notes?, Tags? } (colonnes PRÉSENTES dans le fichier),
  //   Port, Website?, EntryType?, CustomFields? (JSON brut), Attachments? (JSON brut) }
  // Une colonne étendue absente ou vide vaut undefined (aucun changement).
  const parseCSV = (content) => {
    // Parseur RFC 4180 partagé (src/utils/csv.js) : guillemets doublés, champs multi-lignes,
    // BOM Excel, séparateur détecté. Les valeurs ne sont pas tronquées. Le nom n'est jamais rogné
    // (IMPORT-2) ; dans un fichier tiers, utilisateur, URL, tags et port sont nettoyés de leurs espaces.
    const { header, rows } = parseCsv(content);
    const has = (k) => header.includes(k);
    const pick = (row, keys) => {
      for (const k of keys) {
        if (typeof row[k] === 'string' && row[k] !== '') return row[k];
      }
      return '';
    };
    const optional = (row, key) => (has(key) && row[key] && row[key].trim() ? row[key].trim() : undefined);
    // Colonnes « url » ET « website » (export RDVAULT) : deux champs distincts. Une colonne
    // « website » sans colonne « url » (fichiers tiers) reste l'URL, comme avant.
    const websiteSeparate = has('url') && has('website');
    // IMPORT-4 : export RDVAULT (7 colonnes historiques en tête, ou colonne EntryType) → valeurs
    // reprises à l'identique. L'identifiant d'une clé SSH est sa phrase de passe : rognée, la clé
    // privée restaurée ne s'ouvrait plus. Les fichiers tiers restent nettoyés comme avant.
    const rdvaultExport = has('entrytype')
      || ['name', 'username', 'password', 'url', 'notes', 'tags', 'port'].every((k, i) => header[i] === k);
    const columns = {
      Username: { keys: ['username', 'identifiant', 'user', 'login'], trim: true },
      Password: { keys: ['password', 'mot de passe', 'mdp', 'pass'], trim: false },
      URL: { keys: websiteSeparate ? ['url', 'site'] : ['url', 'website', 'site'], trim: true },
      Notes: { keys: ['notes', 'note', 'commentaire'], trim: false },
      Tags: { keys: ['tags', 'tag'], trim: true }
    };
    return rows
      .filter(row => pick(row, ['name', 'nom']).trim())
      .map(row => {
        const fields = {};
        for (const [field, { keys, trim }] of Object.entries(columns)) {
          if (!keys.some(has)) continue;
          const v = pick(row, keys);
          fields[field] = trim && !rdvaultExport ? v.trim() : v;
        }
        return {
          name: stripLayoutWhitespace(pick(row, ['name', 'nom'])),
          fields,
          Port: pick(row, ['port']).trim(),
          Website: websiteSeparate ? optional(row, 'website') : undefined,
          EntryType: optional(row, 'entrytype'),
          CustomFields: optional(row, 'customfields'),
          Attachments: optional(row, 'attachments')
        };
      });
  };

  const parseXML = (content) => {
    const secrets = [];
    const secretRegex = /<secret(?:\s[^>]*)?>([\s\S]*?)<\/secret>/gi;
    let match;
    while ((match = secretRegex.exec(content)) !== null) {
      const block = match[1];
      const fields = {};
      for (const [field, tag] of [['Username', 'username'], ['Password', 'password'], ['URL', 'url'], ['Notes', 'notes'], ['Tags', 'tags']]) {
        if (hasXmlTag(block, tag)) fields[field] = readXmlTag(block, tag);
      }
      const optional = (tag) => readXmlTag(block, tag).trim() || undefined;
      secrets.push({
        name: stripLayoutWhitespace(readXmlTag(block, 'name')),
        fields,
        Port: readXmlTag(block, 'port'),
        Website: optional('website'),
        EntryType: optional('entryType'),
        CustomFields: optional('customFields'),
        Attachments: optional('attachments')
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

      const engineBase = `${vaultUrl}/v1/${encodeEnginePath(engine.name)}`;
      const dataUrl = (name) => engine.version === 2
        ? `${engineBase}/data/${encodeURIComponent(name)}`
        : `${engineBase}/${encodeURIComponent(name)}`;

      // Test d'existence : un LIST par dossier (mis en cache) au lieu d'un GET par clé.
      // - nom absent du listing, ou dossier inexistant (404) → absent : aucun GET ;
      // - nom listé → GET, comme avant (une entrée supprimée en KV v2 reste listée mais
      //   sa lecture renvoie 404 : elle est considérée absente, comme avant) ;
      // - LIST impossible (403, réseau…) → repli sur le GET par clé, comme avant.
      const folderListings = new Map(); // dossier → Set des noms listés, ou null (listing indisponible)
      const splitName = (name) => {
        const i = name.lastIndexOf('/');
        return { folder: name.slice(0, i + 1), leaf: name.slice(i + 1) };
      };
      const listFolder = async (folder) => {
        if (folderListings.has(folder)) return folderListings.get(folder);
        let names = null;
        try {
          const url = engine.version === 2
            ? `${engineBase}/metadata/${encodeSecretPath(folder)}?list=true`
            : `${engineBase}${folder ? '/' + encodeSecretPath(folder) : ''}?list=true`;
          const res = await axios.get(url, axiosConfig({ headers: baseHeaders() }));
          const keys = res.data?.data?.keys;
          names = Array.isArray(keys) ? new Set(keys) : null;
        } catch (err) {
          names = err?.response?.status === 404 ? new Set() : null;
        }
        folderListings.set(folder, names);
        return names;
      };
      // → { exists, data } : data = contenu actuel du secret quand il existe.
      // Seule une 404 signifie « absente » (KV v2 : aussi une entrée supprimée en douceur). Toute autre
      // erreur (500 « decryption failed », réseau, 403…) est levée : l'entrée existe peut-être et ne
      // doit être ni écrasée (mode « ignorer ») ni remplacée sans fusion (mode « écraser ») ; la ligne
      // est alors comptée en échec par l'appelant.
      const readExisting = async (name) => {
        const { folder, leaf } = splitName(name);
        const names = await listFolder(folder);
        if (names && !names.has(leaf)) return { exists: false, data: null };
        try {
          const res = await axios.get(dataUrl(name), axiosConfig({ headers: baseHeaders() }));
          const current = engine.version === 2 ? res.data?.data?.data : res.data?.data;
          return { exists: true, data: current && typeof current === 'object' && !Array.isArray(current) ? current : {} };
        } catch (err) {
          if (err?.response?.status === 404) return { exists: false, data: null };
          throw err;
        }
      };

      // Import partiel : les entrées invalides ou en échec d'écriture sont comptées
      // et signalées à l'utilisateur (doublons ignorés volontairement non comptés).
      let imported = 0;
      let failed = 0;
      let longValues = 0; // IMPORT-5 : entrées importées en entier au-delà de la limite de l'éditeur
      for (const secret of parsed) {
        // Nom vide ou blanc, invalide (« .. », « \ », contrôle, segment vide ou « . ») ou réservé (nom exact
        // « .rdvault-passkeys » : stockage des passkeys, jamais écrasé ; « .rdvault-keycheck ») → refusé et compté
        if (!secret.name || !secret.name.trim() || !isImportableName(secret.name)) { failed++; continue; }

        try {
          const existing = await readExisting(secret.name);
          // Mode « ignorer » : un secret existant n'est pas touché
          if (existing.exists && importDuplicateMode === 'skip') continue;

          // Mode « écraser » : fusion avec les données existantes (rien n'est perdu)
          const data = buildImportData(secret, existing.exists ? existing.data : null);
          if (!data) { failed++; continue; } // colonne JSON invalide

          await axios.post(
            dataUrl(secret.name),
            engine.version === 2 ? { data } : data,
            axiosConfig({ headers: baseHeaders() })
          );
          // Le nom existe désormais : un doublon plus loin dans le fichier sera détecté
          const { folder, leaf } = splitName(secret.name);
          folderListings.get(folder)?.add(leaf);
          imported++;
          if (hasLongValue(data)) longValues++;
        } catch {
          failed++;
        }
      }

      // IMPORT-5 : les valeurs longues ne sont plus tronquées en silence ; elles sont signalées
      const longNote = longValues > 0 ? ' ' + t('export.importLongValues', { count: longValues }) : '';
      if (failed > 0) {
        showToast(t('export.importPartial', { count: imported, failed }) + longNote, imported > 0 ? 'warning' : 'error', longNote ? 8000 : 5000);
      } else if (longNote) {
        showToast(t('export.importSuccess', { count: imported }) + longNote, 'warning', 8000);
      } else {
        showToast(t('export.importSuccess', { count: imported }), 'success');
      }
      setImportFile(null);
    } catch (err) {
      showToast(t('export.importError'), 'error');
    } finally {
      setImporting(false);
    }
  };

  // Focus initial, piège de focus, Échap (modale du dessus uniquement), retour du focus.
  // Auparavant : écouteur Échap global sans condition (fermait aussi sous une sous-modale),
  // ni focus initial ni piège de focus (Tab sortait vers l'application en arrière-plan).
  const panelRef = useRef(null);
  const titleId = useId();
  // UI-35 : identifiants des champs de l'onglet Export / Import (libellés reliés par htmlFor / id)
  const fieldIdBase = useId();
  const exportVaultId = `${fieldIdBase}-export-vault`;
  const exportFormatLabelId = `${fieldIdBase}-export-format`;
  const importVaultId = `${fieldIdBase}-import-vault`;
  useDialogA11y(panelRef, { onEscape: onClose });

  // SETTINGS-13 : tous les onglets partagent le même corps défilant ; sans remise à zéro, l'onglet
  // ouvert héritait de la position du précédent (Export s'affichait défilé, titre caché)
  // (avant l'affichage : pas d'image intermédiaire défilée)
  const bodyRef = useRef(null);
  useLayoutEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = 0;
  }, [activeTab]);

  // IMPORT-37 : sémantique d'onglets (motif WAI-ARIA APG « Tabs », activation automatique).
  // Avant : boutons dans un <div> neutre, onglet actif signalé par la seule classe CSS.
  // - role tablist / tab / tabpanel, aria-selected, aria-controls, aria-labelledby ;
  // - tabIndex itinérant : seul l'onglet affiché est dans l'ordre de tabulation ;
  // - flèches gauche/droite (sens inversé en RTL, avec bouclage), Début, Fin.
  // Apparence inchangée (mêmes classes .tab-button / .tab-button-active).
  const tabIdBase = useId();
  const tabDomId = (key) => `${tabIdBase}-tab-${key}`;
  const tabPanelId = `${tabIdBase}-panel`;
  const tabRefs = useRef({});
  const SETTINGS_TABS = ['appearance', 'columns', 'cli', 'language', 'export', 'extension', 'security', 'about'];
  const handleTabKeyDown = (e) => {
    // Tab / Maj+Tab : laissés au piège de focus de la modale (useDialogA11y), qui ignore désormais
    // les onglets inactifs (tabIndex -1) ; la compensation locale qui bouclait ici est devenue inutile.
    const rtl = e.currentTarget.closest('[dir]')?.getAttribute('dir') === 'rtl';
    const index = SETTINGS_TABS.indexOf(activeTab);
    let next = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      const step = (e.key === 'ArrowRight') !== rtl ? 1 : -1;
      next = SETTINGS_TABS[(index + step + SETTINGS_TABS.length) % SETTINGS_TABS.length];
    } else if (e.key === 'Home') {
      next = SETTINGS_TABS[0];
    } else if (e.key === 'End') {
      next = SETTINGS_TABS[SETTINGS_TABS.length - 1];
    }
    if (!next) return;
    e.preventDefault();
    setActiveTab(next);
    tabRefs.current[next]?.focus();
  };
  // Attributs communs d'un onglet
  const tabProps = (key) => ({
    ref: (el) => { tabRefs.current[key] = el; },
    id: tabDomId(key),
    role: 'tab',
    'aria-selected': activeTab === key,
    'aria-controls': tabPanelId,
    tabIndex: activeTab === key ? 0 : -1,
    onClick: () => setActiveTab(key),
    onKeyDown: handleTabKeyDown,
    className: activeTab === key ? 'tab-button tab-button-active' : 'tab-button',
    type: 'button'
  });

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

  // Fermeture au clic sur le fond : mousedown ET mouseup sur le fond, à moins de 5 px
  // (même logique que components/common/Modal). Une sélection de texte commencée dans le
  // panneau et relâchée sur le fond produit un « click » sur le fond : elle ne ferme plus.
  const overlayDownRef = useRef(null);
  const handleOverlayMouseDown = (e) => {
    overlayDownRef.current = e.target === e.currentTarget ? { x: e.clientX, y: e.clientY } : null;
  };
  const handleOverlayMouseUp = (e) => {
    const start = overlayDownRef.current;
    overlayDownRef.current = null;
    if (!start || e.target !== e.currentTarget) return;
    if (Math.abs(e.clientX - start.x) < 5 && Math.abs(e.clientY - start.y) < 5) onClose();
  };

  // Radios de thème : visuellement masqués mais focalisables (flèches / Espace). La carte
  // affiche un anneau de focus quand le radio a le focus clavier (:focus-visible).
  const [themeFocus, setThemeFocus] = useState(null); // 'light' | 'dark' | null
  const onThemeFocus = (which) => (e) => {
    let visible = true;
    try { visible = e.target.matches(':focus-visible'); } catch { /* sélecteur non supporté */ }
    setThemeFocus(visible ? which : null);
  };
  const onThemeBlur = () => setThemeFocus(null);
  const visuallyHidden = {
    position: 'absolute', width: '1px', height: '1px', margin: 0, padding: 0,
    opacity: 0, overflow: 'hidden', pointerEvents: 'none'
  };
  const themeFocusRing = (which) => (themeFocus === which
    ? { outline: '2px solid var(--border-focus, var(--accent))', outlineOffset: '2px' }
    : {});

  return (
    <div className="modal-overlay" onMouseDown={handleOverlayMouseDown} onMouseUp={handleOverlayMouseUp}>
      <div
        ref={panelRef}
        className="modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '750px', maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}
      >
        <div className="modal-header" style={{ borderBottom: '2px solid var(--border-color)' }}>
          <h2 id={titleId} style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-2)', margin: 0 }}>
            <span aria-hidden="true" style={{ fontSize: '24px' }}>⚙️</span>
            <span>{t('settings.title')}</span>
          </h2>
        </div>

        {/* Onglets — en dehors du scroll. SETTINGS-12 : onglets compacts (.tab-button), sur une
            ligne dans les 12 langues à la taille par défaut ; sur une fenêtre étroite, retour à la
            ligne propre (libellés jamais coupés) au lieu d'une barre de défilement horizontale.
            IMPORT-37 : role="tablist" nommé par le titre de la modale. */}
        <div role="tablist" aria-labelledby={titleId} style={{
          display: 'flex',
          flexWrap: 'wrap',
          columnGap: 'var(--sp-1)',
          rowGap: 'var(--sp-1)',
          borderBottom: '2px solid var(--border-color)',
          background: 'var(--bg-primary)',
          padding: 'var(--sp-2) var(--sp-6) 0 var(--sp-6)',
          flexShrink: 0
        }}>
          <button {...tabProps('appearance')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="4"/>
              <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41"/>
            </svg>
            <span>{t('settings.appearance')}</span>
          </button>
          <button {...tabProps('columns')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="3" width="7" height="7" rx="1"/>
              <rect x="14" y="14" width="7" height="7" rx="1"/>
              <rect x="3" y="14" width="7" height="7" rx="1"/>
            </svg>
            <span>{t('settings.columns')}</span>
          </button>
          <button {...tabProps('cli')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="4 17 10 11 4 5"/>
              <line x1="12" y1="19" x2="20" y2="19"/>
            </svg>
            <span>{t('settings.cli')}</span>
          </button>
          <button {...tabProps('language')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="2" y1="12" x2="22" y2="12"/>
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            <span>{t('settings.language')}</span>
          </button>
          <button {...tabProps('export')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            <span>{t('export.title')}</span>
          </button>
          <button {...tabProps('extension')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 3h6v3a2 2 0 1 0 4 0V3h2v6h-3a2 2 0 1 0 0 4h3v8h-6v-3a2 2 0 1 0-4 0v3H3v-6h3a2 2 0 1 0 0-4H3V3h6z"/>
            </svg>
            <span>{t('extensionTab.tab')}</span>
          </button>
          <button {...tabProps('security')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span>{t('settings.security')}</span>
          </button>
          <button {...tabProps('about')}>
            <svg aria-hidden="true" focusable="false" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            <span>{t('settings.about')}</span>
          </button>
        </div>

        {/* Contenu scrollable (repart du haut à chaque changement d'onglet : SETTINGS-13) */}
        <div
          ref={bodyRef}
          id={tabPanelId}
          role="tabpanel"
          aria-labelledby={tabDomId(activeTab)}
          className="modal-body"
          style={{ overflowY: 'auto', maxHeight: 'calc(85vh - 200px)' }}>
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
                  transition: 'background-color var(--duration-base), border-color var(--duration-base)',
                  background: !darkMode ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 'var(--sp-3)',
                  boxShadow: !darkMode ? '0 4px 12px rgba(0,0,0,0.1)' : 'none',
                  position: 'relative',
                  ...themeFocusRing('light')
                }}>
                  <input
                    type="radio"
                    name="theme"
                    checked={!darkMode}
                    onChange={() => !darkMode ? null : onToggleDarkMode()}
                    onFocus={onThemeFocus('light')}
                    onBlur={onThemeBlur}
                    style={visuallyHidden}
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
                  transition: 'background-color var(--duration-base), border-color var(--duration-base)',
                  background: darkMode ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 'var(--sp-3)',
                  boxShadow: darkMode ? '0 4px 12px rgba(0,0,0,0.1)' : 'none',
                  position: 'relative',
                  ...themeFocusRing('dark')
                }}>
                  <input
                    type="radio"
                    name="theme"
                    checked={darkMode}
                    onChange={() => darkMode ? null : onToggleDarkMode()}
                    onFocus={onThemeFocus('dark')}
                    onBlur={onThemeBlur}
                    style={visuallyHidden}
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
                      transition: 'background-color var(--duration-base), border-color var(--duration-base)',
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
                    <div style={{ width: '120px', textAlign: 'center', fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-bold)', color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      {withLtrParenthetical(t('cli.autoGet'))}
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
                          transition: 'background-color var(--duration-base), border-color var(--duration-base)',
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
                            {/* Chemin de coffre : isolé et lu de gauche à droite (en arabe, les barres
                                obliques ne changent plus de côté) */}
                            <bdi dir="ltr" className="bidi-ltr" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{engineKey}</bdi>
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
                              background: listApproved ? 'var(--accent-fill, var(--accent))' : 'var(--border-color)',
                              transition: 'background var(--duration-base)',
                              flexShrink: 0
                            }}
                          >
                            {/* Pastille : position logique (interrupteur en miroir en arabe) */}
                            <span style={{
                              position: 'absolute',
                              top: '2px',
                              insetInlineStart: listApproved ? '20px' : '2px',
                              width: '18px',
                              height: '18px',
                              borderRadius: '50%',
                              background: '#fff',
                              transition: 'inset-inline-start var(--duration-base)',
                              boxShadow: '0 1px 3px rgba(0,0,0,0.2)'
                            }} />
                          </button>
                        </div>
                        {/* Toggle Auto-get */}
                        <div style={{ width: '120px', display: 'flex', justifyContent: 'center' }}>
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
                              background: autoApproved ? 'var(--accent-fill, var(--accent))' : 'var(--border-color)',
                              transition: 'background var(--duration-base)',
                              flexShrink: 0
                            }}
                          >
                            <span style={{
                              position: 'absolute',
                              top: '2px',
                              insetInlineStart: autoApproved ? '20px' : '2px',
                              width: '18px',
                              height: '18px',
                              borderRadius: '50%',
                              background: '#fff',
                              transition: 'inset-inline-start var(--duration-base)',
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
                {/* Exemples de commandes : toujours de gauche à droite (dir="ltr"), y compris en
                    arabe ; le commentaire traduit garde son propre sens (dir="auto") et la police
                    du texte (seule la commande est en chasse fixe).
                    SETTINGS-10 : l'espacement est porté par la commande, toujours en ltr (marge de
                    fin = à droite). Sur le commentaire, une marge de début devenait une marge
                    DROITE en arabe (commentaire en rtl) : commentaire collé à la commande. */}
                <div dir="ltr" style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.8
                }}>
                  {[
                    ['mvault engines', t('cli.listEngines')],
                    ['mvault get engine/secret', t('cli.readSecret')],
                    ['mvault get engine/secret -k password', t('cli.extractField')],
                  ].map(([command, comment]) => (
                    <div key={command}>
                      <code style={{ fontFamily: 'var(--font-mono, monospace)', marginInlineEnd: '16px' }}>{command}</code>
                      <span dir="auto" style={{ color: 'var(--text-tertiary)' }}>{comment}</span>
                    </div>
                  ))}
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
                        transition: 'background-color var(--duration-base), border-color var(--duration-base)',
                        // SETTINGS-14 : alignement logique (à droite en arabe)
                        textAlign: 'start',
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
                        // SETTINGS-14 : marge logique, la coche reste en bout de bouton en arabe
                        <span style={{ marginInlineStart: 'auto', color: 'var(--accent)', fontSize: '18px' }}>✓</span>
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
              {/* Contenu du fichier : données en clair ; passkeys et clés TOTP non incluses */}
              <p style={{
                fontSize: 'var(--text-sm)',
                color: 'var(--text-secondary)',
                marginBottom: 'var(--sp-4)'
              }}>
                {t('export.contentNote')}
              </p>

              {/* Sélection du coffre (UI-35 : libellé relié au <select>) */}
              <label htmlFor={exportVaultId} style={{
                display: 'block',
                fontSize: 'var(--text-sm)',
                fontWeight: 'var(--weight-bold)',
                color: 'var(--text-primary)',
                marginBottom: 'var(--sp-2)'
              }}>
                {t('export.selectVault')}
              </label>
              <select
                id={exportVaultId}
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
                    // Libellé : nom d'un coffre 1.5.0 enregistré encodé affiché décodé ; valeur = nom technique
                    <option key={e.name} value={e.name}>
                      {ltrIsolate(`${engineDisplayName(e.name)} (KV v${e.version})`)}
                    </option>
                  ))
                }
              </select>

              {/* Sélection du format : libellé du groupe de boutons radio */}
              <label id={exportFormatLabelId} style={{
                display: 'block',
                fontSize: 'var(--text-sm)',
                fontWeight: 'var(--weight-bold)',
                color: 'var(--text-primary)',
                marginBottom: 'var(--sp-2)'
              }}>
                {t('export.format')}
              </label>
              <div role="radiogroup" aria-labelledby={exportFormatLabelId} style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-4)' }}>
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

                {/* Sélection du coffre de destination (UI-35 : libellé relié au <select>) */}
                <label htmlFor={importVaultId} style={{
                  display: 'block',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 'var(--weight-bold)',
                  color: 'var(--text-primary)',
                  marginBottom: 'var(--sp-2)'
                }}>
                  {t('export.importSelectVault')}
                </label>
                <select
                  id={importVaultId}
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
                      // Libellé décodé (coffre 1.5.0), valeur = nom technique utilisé pour les requêtes
                      <option key={e.name} value={e.name}>
                        {ltrIsolate(`${engineDisplayName(e.name)} (KV v${e.version})`)}
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
                  {/* Nom de fichier : sens selon son contenu (dir="auto"), ellipse du bon côté en arabe */}
                  <span dir="auto" style={{
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

          {/* Onglet Extension */}
          {activeTab === 'extension' && <ExtensionTab />}

          {/* Onglet Sécurité : délai de verrouillage automatique */}
          {activeTab === 'security' && <SecurityTab />}

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
                  <span>{t('aboutPage.whatsNew', { version: appVersion })}</span>
                </h4>
                <ul style={{
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-secondary)',
                  paddingInlineStart: 'var(--sp-4)',
                  lineHeight: 1.8,
                  margin: 0
                }}>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.v17Passkeys')}</strong> - {t('aboutPage.v17PasskeysDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.v17Remote')}</strong> - {t('aboutPage.v17RemoteDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.v17Audit')}</strong> - {t('aboutPage.v17AuditDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.v17Crypto')}</strong> - {t('aboutPage.v17CryptoDesc')}
                  </li>
                  <li style={{ marginBottom: 'var(--sp-2)' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.v17Ui')}</strong> - {t('aboutPage.v17UiDesc')}
                  </li>
                  <li>
                    <strong style={{ color: 'var(--text-primary)' }}>{t('aboutPage.bugFixes')}</strong> - {t('aboutPage.v17FixesDesc')}
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
