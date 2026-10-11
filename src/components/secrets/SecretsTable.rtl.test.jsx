// ========================================
// TESTS : tableau des secrets — espacement des icônes en écriture de droite à gauche
// ========================================
// Suite I18N-31 : les icônes (✓ de sélection, 🔑 SSH, 📁 chemin Windows, 🔑 URL SSH) et le mot de
// passe masqué avaient une marge DROITE fixe : en arabe (dir="rtl"), l'espace se retrouvait du
// mauvais côté et l'icône collait au texte. Marges logiques (margin-inline-end / -start) désormais.
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretsTable from './SecretsTable';
import en from '../../locales/en.json';

jest.mock('../../utils/urlHandler', () => ({ handleUrlAction: jest.fn().mockResolvedValue(undefined) }));

global.IS_REACT_ACT_ENVIRONMENT = true;

const mountInRoot = (reactRoot, element) => reactRoot.render(element);
const t = (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

const SECRETS = [
  { name: 'cle-ssh', username: 'root', password: 'pw', url: 'ssh://srv.example.com', notes: '', tags: '', entryType: 'ssh' },
  { name: 'partage', username: 'u', password: 'pw2', url: '\\\\nas\\partage', notes: '', tags: '' },
];

let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
});

function mount() {
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  const noop = () => {};
  act(() => {
    mountInRoot(root, (
      <SecretsTable
        filteredSecrets={SECRETS} secrets={SECRETS} allVaultSecrets={[]}
        selectedEngine={{ name: 'kv', version: 2 }} loadingSecrets={false}
        multiVaultSearch={false} search="" visiblePasswords={{}}
        effectiveVisibleColumns={{ name: true, username: true, password: true, url: true, notes: false, tags: false, customFields: false }}
        columnWidths={{}} resizingColumn={null} isCurrentEngineRbiOnly={false} token="tok"
        selectedSecrets={new Set(['cle-ssh', 'partage'])} isSecretSelected={() => true}
        displayedSecretsRef={{ current: null }} isDragging={false} dragOverTarget={null}
        toggleSecretSelection={noop} setVisiblePasswords={noop} setCurrentPath={noop}
        handleCellRightClick={noop} handleFolderRightClick={noop} handleEmptyAreaRightClick={noop}
        handleTagCellRightClick={noop} handleColumnHeaderRightClick={noop}
        handleDragStart={noop} handleDragEnd={noop} handleDragOver={noop} handleDragLeave={noop} handleDropOnFolder={noop}
        handleColumnResizeStart={noop} autoFitColumn={noop}
        isSecretRbiOnly={() => false} startClipboardTimer={noop} setNotesPopup={noop}
        getTagColor={() => '#888'} getTotpKeyName={(n) => n} getTotpCode={noop} showToast={noop} t={t}
      />
    ));
  });
  return host;
}

const spanWithText = (scope, text) => Array.from(scope.querySelectorAll('span')).find(s => s.textContent === text);

test('icônes et mot de passe masqué : marge logique (fin de ligne), plus de margin-right fixe', () => {
  const host = mount();
  const rows = host.querySelectorAll('tbody tr');
  const check = spanWithText(rows[0], '✓');
  const sshName = spanWithText(rows[0].querySelector('td.cell-name'), '🔑');
  const sshUrl = spanWithText(rows[0].querySelectorAll('td')[3], '🔑');
  const winPath = spanWithText(rows[1], '📁');
  const masked = spanWithText(rows[0], '••••••');
  for (const el of [check, sshName, sshUrl, winPath, masked]) {
    expect(el).toBeTruthy();
    expect(el.style.marginRight).toBe('');
    expect(el.style.marginInlineEnd).not.toBe('');
  }
});

test('le source n\'utilise plus de marginRight / marginLeft fixes', () => {
  const fs = require('fs');
  const path = require('path');
  const src = fs.readFileSync(path.join(__dirname, 'SecretsTable.jsx'), 'utf8');
  expect(src).not.toMatch(/marginRight:/);
  expect(src).not.toMatch(/marginLeft:/);
});
