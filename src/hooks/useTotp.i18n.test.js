// ========================================
// TESTS : useTotp — libellé du minuteur de presse-papiers traduit (I18N-32)
// ========================================
// « Copier TOTP » (menu contextuel) passait le libellé littéral 'Code TOTP' au minuteur :
// « Code TOTP copied » en anglais. Le libellé vient désormais de t('totp.title').
import { act } from 'react';
import { createFakeVault, renderHook } from './testUtils/fakeVault';
import { useTotp } from './useTotp';
import en from '../locales/en.json';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

global.IS_REACT_ACT_ENVIRONMENT = true;

// Traducteur anglais minimal (vraies chaînes de en.json)
const tEn = (key) => key.split('.').reduce((o, k) => (o == null ? o : o[k]), en) ?? key;

let vault;
beforeEach(() => {
  vault = createFakeVault();
  axios.get.mockImplementation(vault.axios.get);
});
afterEach(() => { document.body.innerHTML = ''; });

test('handleCopyTotp : le minuteur reçoit t(\'totp.title\') et le code', async () => {
  vault.addTotp('KV-github', { period: 30 });
  const copies = [];
  const { result } = renderHook(() => useTotp({
    vaultUrl: vault.VAULT_URL, baseHeaders: () => ({}), axiosConfig: (c = {}) => c,
    selectedEngine: { name: 'kv', version: 2 },
    startClipboardTimer: async (label, code) => { copies.push([label, code]); },
    showToast: () => {}, t: tEn, restoreFocus: () => {},
  }));
  await act(async () => { await result.current.handleCopyTotp({ name: 'github' }); });
  expect(copies).toEqual([['TOTP Code', '123456']]);
});
