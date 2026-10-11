// ========================================
// TESTS : useTags / App.jsx — tags et modifications en recherche multi-coffres (APP-5)
// ========================================
// Après l'ajout ou le retrait d'un tag depuis les résultats multi-coffres, la liste du coffre
// SÉLECTIONNÉ est relue elle aussi : « Modifier » depuis les résultats est reconnu comme une
// modification, et la liste affichée une fois la recherche vidée n'est pas périmée. Après un
// enregistrement, les résultats de ce coffre sont alignés sur sa liste relue.
import fr from './locales/fr.json';
import {
  act, setupVault, flush, installBridges, removeBridges, createHost, renderApp, login, typeSearch,
  multiBox, rowByName, tableRows, rightClick, menuItem, toastText, setInput, quiet,
} from './hooks/testUtils/appHarness.jsx';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));

global.IS_REACT_ACT_ENVIRONMENT = true;

let host; let root;
beforeEach(() => {
  jest.useFakeTimers();
  quiet();
  localStorage.clear();
  localStorage.setItem('rdvault-lang', 'fr');
  installBridges();
  ({ host, root } = createHost());
});
afterEach(() => {
  act(() => root.unmount());
  document.body.innerHTML = '';
  removeBridges();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

// Ligne des résultats multi-coffres d'un coffre donné (colonne « coffre » = 2e cellule)
const resultRow = (engine, name) => tableRows(host).find(tr => {
  const td = tr.querySelectorAll('td');
  return td[1]?.textContent.trim() === engine && td[0]?.textContent.trim().replace(/^✓/, '') === name;
}) || null;

async function removeTagViaMenu(row, tag) {
  const tagCell = Array.from(row.querySelectorAll('td')).find(td => td.querySelector('.tag-badge'));
  await rightClick(tagCell);
  const btn = Array.from(document.querySelectorAll('.tag-context-menu .context-menu-item'))
    .find(b => b.textContent.includes(fr.contextMenu.removeTag) && b.textContent.includes(tag));
  await act(async () => { btn.click(); });
  await flush(120);
}

// « Modifier » depuis la ligne, mot de passe affiché dans la fiche remplacé, « Enregistrer »
async function editPasswordAndSave(row, newPwd) {
  await rightClick(row.querySelector('td.cell-name'));
  await act(async () => { menuItem(fr.contextMenu.edit).click(); });
  await flush(40);
  const modal = document.querySelector('[role="dialog"]');
  const label = Array.from(modal.querySelectorAll('label')).find(l => l.textContent.trim() === fr.editSecret.password);
  const pwd = document.getElementById(label.htmlFor);
  const shown = pwd.value;
  await act(async () => { setInput(pwd, newPwd); });
  const save = Array.from(modal.querySelectorAll('button')).find(b => b.textContent.trim() === fr.editSecret.save);
  await act(async () => { save.click(); });
  await flush(150);
  return shown;
}

function seed() {
  const vault = setupVault();
  vault.addEngine('Alpha');
  vault.addEngine('Beta');
  vault.writeRaw('Alpha', 'banque', { Username: 'alice', Password: 'pass-1', Tags: 'urgent' });
  vault.writeRaw('Beta', 'banque-pro', { Username: 'bob', Password: 'b' });
  return vault;
}

async function openResults() {
  await renderApp(root);
  await login(host);
  await typeSearch(host, 'banque');
  await act(async () => { multiBox(host).click(); });
  await flush(120);
  expect(resultRow('Alpha', 'banque')).not.toBeNull();
}

test('retrait d\'un tag depuis les résultats, puis « Modifier » depuis les résultats : modification enregistrée', async () => {
  const vault = seed();
  await openResults();
  await removeTagViaMenu(resultRow('Alpha', 'banque'), 'urgent');
  expect(vault.latest('Alpha', 'banque').data.Tags).toBe('');

  await editPasswordAndSave(resultRow('Alpha', 'banque'), 'pass-2');
  expect(toastText()).not.toContain(fr.error.secretNameExists.replace('{{name}}', 'banque'));
  expect(vault.latest('Alpha', 'banque').data.Password).toBe('pass-2');
  expect(vault.latest('Alpha', 'banque').data.Tags).toBe('');
});

test('retrait d\'un tag, recherche vidée : la liste d\'Alpha n\'a plus le tag et « Enregistrer » ne le ressuscite pas', async () => {
  const vault = seed();
  await openResults();
  await removeTagViaMenu(resultRow('Alpha', 'banque'), 'urgent');

  await typeSearch(host, '');
  await flush(40);
  expect(multiBox(host).checked).toBe(false);
  const listed = rowByName(host, 'banque');
  expect(listed.textContent).not.toContain('urgent');

  await editPasswordAndSave(listed, 'pass-2');
  expect(vault.latest('Alpha', 'banque').data.Password).toBe('pass-2');
  expect(vault.latest('Alpha', 'banque').data.Tags).toBe('');
});

test('ajout d\'un tag depuis les résultats : liste d\'Alpha relue (le tag y figure une fois la recherche vidée)', async () => {
  const vault = seed();
  vault.writeRaw('Beta', 'banque-pro', { Username: 'bob', Password: 'b', Tags: 'perso' }); // tag « perso » découvert
  await openResults();
  const tagCell = Array.from(resultRow('Alpha', 'banque').querySelectorAll('td')).find(td => td.querySelector('.tag-badge'));
  await rightClick(tagCell);
  const add = Array.from(document.querySelectorAll('.tag-context-menu .context-menu-item'))
    .find(b => b.textContent.includes(`${fr.contextMenu.addTag} "perso"`));
  await act(async () => { add.click(); });
  await flush(120);
  expect(vault.latest('Alpha', 'banque').data.Tags).toBe('urgent perso');

  await typeSearch(host, '');
  await flush(40);
  expect(rowByName(host, 'banque').textContent).toContain('perso');
});

test('deux « Modifier » successifs depuis les résultats : le second voit la valeur enregistrée et est accepté', async () => {
  const vault = seed();
  await openResults();
  const first = await editPasswordAndSave(resultRow('Alpha', 'banque'), 'pass-2');
  expect(first).toBe('pass-1');
  expect(vault.latest('Alpha', 'banque').data.Password).toBe('pass-2');

  const second = await editPasswordAndSave(resultRow('Alpha', 'banque'), 'pass-3');
  expect(second).toBe('pass-2');
  expect(toastText()).not.toContain(fr.error.secretNameExists.replace('{{name}}', 'banque'));
  expect(vault.latest('Alpha', 'banque').data.Password).toBe('pass-3');
  // Résultats d'un autre coffre intacts, ordre conservé
  expect(resultRow('Beta', 'banque-pro')).not.toBeNull();
});
