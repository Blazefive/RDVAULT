// ========================================
// TESTS : menu contextuel des secrets — vague G
// ========================================
// TABLE-20 : l'intertitre de section « Migrer vers... » répétait l'action « Migrer vers... » juste en
// dessous (12 langues : même valeur), et « Historique des versions » semblait faire partie de la
// section, faute de séparateur. Attendu : intertitre distinct (« Autre coffre »), aucun intertitre
// identique à une action, séparateur avant « Historique des versions » (sans séparateur doublé en KV v1).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretContextMenu from './SecretContextMenu';
import fr from '../../locales/fr.json';
import en from '../../locales/en.json';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const tFor = (dict) => (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), dict);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

const SECRET = { name: 'banque', username: 'alice', password: 'pw-alice', url: '' };

function mount({ dict = fr, engineVersion = 2, contextMenu } = {}) {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => {
    mountInRoot(root, (
      <SecretContextMenu
        contextMenu={contextMenu || { x: 1, y: 1, secret: SECRET, field: 'name', value: 'banque' }}
        contextMenuRef={{ current: null }}
        setContextMenu={jest.fn()}
        selectedEngine={{ name: 'kv', version: engineVersion }}
        isCurrentEngineRbiOnly={false}
        isSecretRbiOnly={() => false}
        treeViewEnabled={false}
        currentPath=""
        setShowCreateFolderModal={jest.fn()}
        setNewFolderName={jest.fn()}
        setEditSecret={jest.fn()}
        startClipboardTimer={jest.fn()}
        setMoveToFolder={jest.fn()}
        setMigrateSecrets={jest.fn()}
        confirmDeleteSecret={jest.fn()}
        undeleteSecret={jest.fn()}
        getTotpKeyName={(n) => n}
        getTotpCode={jest.fn()}
        handleShowTotp={jest.fn()}
        handleCopyTotp={jest.fn()}
        handleConfigureTotp={jest.fn()}
        handleDeleteTotp={jest.fn()}
        setShareRbiSecret={jest.fn()}
        setVersionHistory={jest.fn()}
        selectedSecrets={new Set()}
        secrets={[SECRET]}
        installedBrowsers={[]}
        appMode="local"
        showToast={jest.fn()}
        t={tFor(dict)}
      />
    ));
  });
  mounted.push(root);
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  document.body.innerHTML = '';
});

// Enfants directs du menu, dans l'ordre : { kind: 'item' | 'label' | 'sep', text }
const sequence = () => Array.from(document.querySelector('.context-menu').querySelectorAll('[role="menuitem"], .context-menu-label, [role="separator"]'))
  .map((el) => ({
    kind: el.getAttribute('role') === 'separator' ? 'sep' : (el.classList.contains('context-menu-label') ? 'label' : 'item'),
    text: el.textContent.trim(),
  }));
const indexOfItem = (seq, text) => seq.findIndex((e) => e.kind === 'item' && e.text.includes(text));

describe.each([['fr', fr], ['en', en]])('TABLE-20 — section « autre coffre » (%s)', (_, dict) => {
  test('aucun intertitre identique à une action du menu', () => {
    mount({ dict });
    const seq = sequence();
    const itemTexts = seq.filter((e) => e.kind === 'item').map((e) => e.text);
    for (const label of seq.filter((e) => e.kind === 'label').map((e) => e.text)) {
      expect(itemTexts.some((it) => it === label || it.endsWith(` ${label}`))).toBe(false);
    }
    // Avant : intertitre « Migrer vers... » = action « Migrer vers... »
    expect(seq.filter((e) => e.kind === 'label').map((e) => e.text)).not.toContain(dict.migrate.migrateTitle);
  });

  test('intertitre distinct juste avant « Copier vers... » et « Migrer vers... »', () => {
    mount({ dict });
    const seq = sequence();
    const copy = indexOfItem(seq, dict.contextMenu.copyTo);
    expect(dict.contextMenu.otherVaultSection).toEqual(expect.any(String));
    expect(seq[copy - 1]).toEqual({ kind: 'label', text: dict.contextMenu.otherVaultSection });
    expect(indexOfItem(seq, dict.contextMenu.migrate)).toBe(copy + 1);
  });

  test('séparateur avant « Historique des versions » (KV v2)', () => {
    mount({ dict });
    const seq = sequence();
    const history = indexOfItem(seq, dict.contextMenu.history);
    expect(history).toBeGreaterThan(0);
    expect(seq[history - 1].kind).toBe('sep');
    expect(seq[history - 2].text).toContain(dict.contextMenu.migrate);
  });
});

test('KV v1 (pas d\'historique) : aucun séparateur doublé ni séparateur en bout de section', () => {
  mount({ engineVersion: 1 });
  const seq = sequence();
  expect(indexOfItem(seq, fr.contextMenu.history)).toBe(-1);
  for (let i = 1; i < seq.length; i++) {
    expect(seq[i].kind === 'sep' && seq[i - 1].kind === 'sep').toBe(false);
  }
});
