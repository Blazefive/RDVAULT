// ========================================
// TESTS : useContextMenus — réponse tardive d'un clic droit sur une ligne (APP-3)
// ========================================
// Le menu d'une ligne s'ouvre après la vérification TOTP (requête). Une numérotation commune à tous les
// menus garantit que cette réponse, si elle arrive tard, ne remplace jamais un menu ouvert depuis (zone
// vide, dossier, en-tête de colonne, tag, coffre, autre ligne) et ne rouvre rien après une fermeture
// (clic extérieur, Échap, remise à zéro par l'appelant, changement de session).
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useContextMenus } from './useContextMenus';

global.IS_REACT_ACT_ENVIRONMENT = true;

let mounted = [];
let api = null;
let pending = [];
const mountInRoot = (reactRoot, element) => reactRoot.render(element);

// Vérification TOTP différée : chaque appel attend que le test la résolve (resolveCheck)
const slowCheck = () => new Promise((resolve, reject) => { pending.push({ resolve, reject }); });

function Harness({ check, sessionTokenRef }) {
  api = useContextMenus({ getTotpKeyName: (n) => n, checkTotpExists: check, discoveredTags: ['#a'], sessionTokenRef });
  const cell = api.contextMenu ? (api.contextMenu.type || api.contextMenu.secret?.name) : null;
  return (
    <div id="state">{JSON.stringify({
      cell, totp: api.contextMenu ? !!api.contextMenu.totpExists : null,
      engine: !!api.engineContextMenu, folder: !!api.folderContextMenu,
      column: !!api.columnContextMenu, tag: !!api.tagContextMenu,
    })}</div>
  );
}

function mount(props = {}) {
  localStorage.setItem('vault-client.username', 'alice');
  const host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => { mountInRoot(root, <Harness check={slowCheck} {...props} />); });
  mounted.push(root);
  return host;
}

afterEach(() => {
  mounted.forEach(root => act(() => root.unmount()));
  mounted = [];
  api = null;
  pending = [];
  document.body.innerHTML = '';
  localStorage.clear();
});

const state = () => JSON.parse(document.getElementById('state').textContent);
const openMenus = () => Object.entries(state()).filter(([k, v]) => k !== 'totp' && v).map(([k]) => k);
const ev = (target = document.body) => ({ preventDefault() {}, stopPropagation() {}, clientX: 10, clientY: 10, target });

// Clic droit sur une ligne : la vérification TOTP reste en attente (promesse renvoyée)
const rowRightClick = (name) => {
  let promise;
  act(() => { promise = api.handleCellRightClick(ev(), { name }, 'name', name); });
  return promise;
};
const resolveCheck = async (index, value = true) => {
  await act(async () => { pending[index].resolve(value); });
};

describe('APP-3 : la réponse tardive d\'un clic droit sur une ligne ne remplace aucun menu ouvert ensuite', () => {
  test.each([
    ['zone vide (« Nouvelle entrée »)', () => api.handleEmptyAreaRightClick(ev()), { cell: 'create' }],
    ['dossier', () => api.handleFolderRightClick(ev(), 'Dossier'), { folder: true }],
    ['en-tête de colonne', () => api.handleColumnHeaderRightClick(ev()), { column: true }],
    ['tag', () => api.handleTagCellRightClick(ev(), { name: 's', tags: '' }), { tag: true }],
    ['coffre', () => api.handleEngineRightClick(ev(), { name: 'users/alice/perso' }), { engine: true }],
  ])('menu %s ouvert pendant la vérification : il reste le seul menu affiché', async (_label, openOther, expected) => {
    mount();
    rowRightClick('banque');
    act(() => { openOther(); });
    await resolveCheck(0);
    expect(state()).toMatchObject(expected);
    expect(openMenus()).toHaveLength(1);
    expect(state().cell).not.toBe('banque');
  });

  test('deux lignes : la réponse du premier clic, arrivée après celle du second, ne remplace pas son menu', async () => {
    mount();
    rowRightClick('banque');
    rowRightClick('wifi');
    await resolveCheck(1, false);
    expect(state().cell).toBe('wifi');
    await resolveCheck(0, true);
    expect(state().cell).toBe('wifi');
    expect(state().totp).toBe(false);
  });

  test('clic extérieur pendant la vérification : aucun menu ne s\'ouvre ensuite', async () => {
    mount();
    rowRightClick('banque');
    act(() => { document.body.click(); });
    await resolveCheck(0);
    expect(openMenus()).toEqual([]);
  });

  test('remise à zéro par l\'appelant (fermeture, déconnexion) : la réponse n\'ouvre plus le menu', async () => {
    mount();
    rowRightClick('banque');
    act(() => { api.setContextMenu(null); });
    await resolveCheck(0);
    expect(openMenus()).toEqual([]);
  });

  test('sessionTokenRef fourni : réponse arrivée après un changement de session ignorée', async () => {
    const sessionTokenRef = { current: 'tok-alice' };
    mount({ sessionTokenRef });
    rowRightClick('banque');
    sessionTokenRef.current = '';
    await resolveCheck(0);
    expect(openMenus()).toEqual([]);
  });

  test('vérification TOTP en échec : le menu s\'ouvre quand même, sans TOTP (plus de rejet non géré)', async () => {
    mount();
    const promise = rowRightClick('banque');
    await act(async () => { pending[0].reject(new Error('réseau')); });
    await act(async () => { await expect(promise).resolves.toBeUndefined(); });
    expect(state()).toMatchObject({ cell: 'banque', totp: false });
  });

  test('témoin : rien entre le clic droit et la réponse, le menu de la ligne s\'ouvre', async () => {
    mount();
    rowRightClick('banque');
    expect(openMenus()).toEqual([]);
    await resolveCheck(0, true);
    expect(state()).toMatchObject({ cell: 'banque', totp: true });
    expect(openMenus()).toEqual(['cell']);
  });

  test('setters exposés : stables d\'un rendu à l\'autre', () => {
    mount();
    const first = api.setContextMenu;
    act(() => { api.handleFolderRightClick(ev(), 'Dossier'); });
    expect(api.setContextMenu).toBe(first);
  });
});
