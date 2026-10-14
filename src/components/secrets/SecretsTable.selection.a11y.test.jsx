// ========================================
// TESTS : UI-38 — ligne sélectionnée exposée aux technologies d'assistance (SecretsTable)
// ========================================
// Avant : la sélection (Espace, clic, Ctrl/Maj) ne passait que par la classe row-selected,
// le fond et le contour : un lecteur d'écran ne savait pas quelles entrées partiraient dans
// une action par lot (« Déplacer / Copier vers / Migrer (N) »). Le tableau reste un <table>
// statique (aria-selected n'y est pas valide) : un texte réservé aux lecteurs d'écran
// « sélectionnée » est ajouté dans la cellule Nom de chaque ligne sélectionnée.

import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SecretsTable from './SecretsTable';
import en from '../../locales/en.json';

jest.mock('../../utils/urlHandler', () => ({ handleUrlAction: jest.fn().mockResolvedValue(undefined) }));

global.IS_REACT_ACT_ENVIRONMENT = true;
// Rendu dans un root React 18 (hors Testing Library)
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

const t = (key, vars = {}) => {
  const v = key.split('.').reduce((o, k) => (o ? o[k] : undefined), en);
  return typeof v === 'string' ? v.replace(/\{\{(\w+)\}\}/g, (_, n) => vars[n] ?? '') : key;
};

const SECRETS = [
  { name: 'alpha', username: 'a', password: 'p1', url: '', notes: '', tags: '' },
  { name: 'beta', username: 'b', password: 'p2', url: '', notes: '', tags: '' },
];

let root = null;
afterEach(() => {
  if (root) act(() => root.unmount());
  root = null;
  document.body.innerHTML = '';
});

function render(host, selected) {
  const noop = () => {};
  act(() => {
    mountInRoot(root, (
      <SecretsTable
        filteredSecrets={SECRETS} secrets={SECRETS} allVaultSecrets={[]}
        selectedEngine={{ name: 'kv', version: 2 }} loadingSecrets={false} multiVaultSearch={false} search=""
        visiblePasswords={{}} setVisiblePasswords={noop}
        effectiveVisibleColumns={{ name: true, username: true, password: false, url: false, notes: false, tags: false, customFields: false }}
        columnWidths={{}} resizingColumn={null} isCurrentEngineRbiOnly={false} token="tok"
        selectedSecrets={selected} isSecretSelected={(k) => selected.has(k)} toggleSecretSelection={noop}
        displayedSecretsRef={{ current: null }} isDragging={false} dragOverTarget={null}
        handleDragStart={noop} handleDragEnd={noop} handleDragOver={noop} handleDragLeave={noop} handleDropOnFolder={noop}
        handleColumnResizeStart={noop} autoFitColumn={noop} handleColumnHeaderRightClick={noop}
        handleEmptyAreaRightClick={noop} handleCellRightClick={noop} handleFolderRightClick={noop} handleTagCellRightClick={noop}
        isSecretRbiOnly={() => false} startClipboardTimer={noop} setNotesPopup={noop} setCurrentPath={noop}
        getTagColor={() => '#888'} getTotpKeyName={(n) => n} getTotpCode={noop} showToast={noop} t={t}
      />
    ));
  });
}

const rowText = (host, name) => Array.from(host.querySelectorAll('tbody tr')).find(r => r.textContent.includes(name));
const srText = (row) => Array.from(row.querySelectorAll('.sr-only')).map(s => s.textContent).join('|');

test('ligne sélectionnée : texte « selected » réservé aux lecteurs d\'écran ; autres lignes sans', () => {
  const host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
  render(host, new Set());
  expect(srText(rowText(host, 'alpha'))).not.toContain(en.table.rowSelected);

  render(host, new Set(['beta']));
  expect(srText(rowText(host, 'beta'))).toContain(en.table.rowSelected);
  expect(srText(rowText(host, 'alpha'))).not.toContain(en.table.rowSelected);

  // Sélection multiple (lot) : chaque ligne concernée l'indique
  render(host, new Set(['alpha', 'beta']));
  expect(srText(rowText(host, 'alpha'))).toContain(en.table.rowSelected);
  expect(srText(rowText(host, 'beta'))).toContain(en.table.rowSelected);
});
