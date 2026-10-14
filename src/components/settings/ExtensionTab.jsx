// src/components/settings/ExtensionTab.jsx
// Onglet « Extension » des Paramètres : l'extension navigateur est livrée avec l'application
// (resources/chrome-extension). Chrome n'autorise pas une application à l'installer elle-même (hors
// Chrome Web Store) : on guide l'utilisateur pour la charger une fois (« Charger l'extension non
// empaquetée »). Le processus principal fournit le dossier, ouvre l'Explorateur et copie dans le
// presse-papiers des valeurs non secrètes choisies dans une liste fermée (chemin, page des extensions).
import React, { useEffect, useRef, useState } from 'react';
import { useTranslation } from '../../i18n';

const BROWSER_PAGES = [
  { key: 'chrome', url: 'chrome://extensions', label: 'Chrome' },
  { key: 'edge', url: 'edge://extensions', label: 'Edge' },
  { key: 'brave', url: 'brave://extensions', label: 'Brave' },
];

const boxStyle = {
  padding: 'var(--sp-4)',
  background: 'var(--bg-surface)',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-lg)',
  marginBottom: 'var(--sp-4)',
};

const codeStyle = {
  display: 'block',
  padding: 'var(--sp-2) var(--sp-3)',
  background: 'var(--bg-app)',
  border: '1px solid var(--border-color)',
  borderRadius: 'var(--radius-md)',
  fontSize: 'var(--text-sm)',
  wordBreak: 'break-all',
  textAlign: 'start',
};

export default function ExtensionTab() {
  const { t } = useTranslation();
  const [info, setInfo] = useState(null);
  const [copied, setCopied] = useState(null);
  const timerRef = useRef(null);
  const api = typeof window !== 'undefined' ? window.electronExtension : undefined;

  useEffect(() => {
    let alive = true;
    if (api && typeof api.info === 'function') {
      api.info().then((r) => { if (alive) setInfo(r || { available: false }); }).catch(() => { if (alive) setInfo({ available: false }); });
    } else {
      setInfo({ available: false });
    }
    return () => { alive = false; clearTimeout(timerRef.current); };
  }, [api]);

  const copy = async (what) => {
    if (!api) return;
    const r = await api.copy(what).catch(() => null);
    if (r && r.success) {
      setCopied(what);
      clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setCopied(null), 2000);
    }
  };

  if (!info) return null;

  return (
    <div className="extension-tab">
      <div style={boxStyle}>
        <h3 style={{ marginTop: 0, marginBottom: 'var(--sp-2)', color: 'var(--text-primary)' }}>{t('extensionTab.title')}</h3>
        <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{t('extensionTab.intro')}</p>
      </div>

      {!info.available ? (
        <div role="alert" style={{ ...boxStyle, borderColor: 'var(--warning, var(--border-color))' }}>
          {t('extensionTab.unavailable')}
        </div>
      ) : (
        <>
          <div style={boxStyle}>
            <div style={{ fontWeight: 'var(--weight-semibold)', marginBottom: 'var(--sp-2)' }}>{t('extensionTab.folderLabel')}</div>
            <code dir="ltr" className="bidi-ltr" style={codeStyle} data-testid="extension-folder">{info.folder}</code>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--sp-2)', marginTop: 'var(--sp-3)' }}>
              <button type="button" className="btn btn-primary" onClick={() => api.openFolder()}>{t('extensionTab.openFolder')}</button>
              <button type="button" className="btn btn-secondary" onClick={() => copy('folder')}>
                {copied === 'folder' ? t('extensionTab.copied') : t('extensionTab.copyPath')}
              </button>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', columnGap: 'var(--sp-4)', rowGap: 'var(--sp-1)', marginTop: 'var(--sp-3)', fontSize: 'var(--text-sm)', color: 'var(--text-tertiary)' }}>
              <span><strong>{t('extensionTab.versionLabel')}</strong> <bdi dir="ltr">{info.version}</bdi></span>
              {info.id && (
                <span><strong>{t('extensionTab.idLabel')}</strong> <bdi dir="ltr"><code>{info.id}</code></bdi></span>
              )}
            </div>
          </div>

          <div style={boxStyle}>
            <div style={{ fontWeight: 'var(--weight-semibold)', marginBottom: 'var(--sp-2)' }}>{t('extensionTab.stepsTitle')}</div>
            <ol style={{ margin: 0, paddingInlineStart: 'var(--sp-5)', lineHeight: 1.7 }}>
              <li>
                {t('extensionTab.step1')}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--sp-2)', margin: 'var(--sp-2) 0' }}>
                  {BROWSER_PAGES.map((b) => (
                    <button key={b.key} type="button" className="btn btn-secondary" onClick={() => copy(b.key)}
                      title={b.label} aria-label={`${b.label} — ${b.url}`}>
                      <bdi dir="ltr">{copied === b.key ? `✓ ${t('extensionTab.copied')}` : b.url}</bdi>
                    </button>
                  ))}
                </div>
              </li>
              <li>{t('extensionTab.step2')}</li>
              <li>{t('extensionTab.step3')}</li>
              <li>{t('extensionTab.step4')}</li>
            </ol>
          </div>

          <div style={{ ...boxStyle, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            <p style={{ marginTop: 0 }}>{t('extensionTab.update')}</p>
            <p style={{ marginBottom: 0 }}>{t('extensionTab.sharedWarning')}</p>
          </div>
        </>
      )}
    </div>
  );
}
