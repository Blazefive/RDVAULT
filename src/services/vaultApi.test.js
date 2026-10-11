// ========================================
// TESTS : vaultApi — validation avant écriture (DATA-3 : entrées « Clé SSH »)
// ========================================
// EditSecretModal range la clé privée (multi-lignes) dans `password` et la clé publique dans `url` :
// l'écriture d'une entrée SSH ne doit pas être refusée pour ses retours à la ligne, tandis que
// les autres contrôles (NUL…) restent refusés et que les entrées classiques gardent leur validation.
import { createVaultApi } from './vaultApi';

jest.mock('axios', () => ({ __esModule: true, default: { get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() } }));
// eslint-disable-next-line import/first
import axios from 'axios';

const PRIV = [
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
  'QyNTUxOQAAACDw2Kq4q1tEYKmJrJb2cQ1vJmJ9xvR3W3q0tqN0r0N5UwAAAJgAAAAA',
  '-----END OPENSSH PRIVATE KEY-----',
  ''
].join('\r\n');
const PUB = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDYqrirW0RgqYmsl user@poste\n';
const sshEntry = (over = {}) => ({ name: 'serveur-prod', username: '', password: PRIV, url: PUB, website: '', notes: '', tags: '', customFields: [], attachments: [], entryType: 'ssh', ...over });

let api;
beforeEach(() => {
  axios.post.mockResolvedValue({ status: 200, data: {} });
  api = createVaultApi('http://v', 'tok');
});

test('writeSecretV2 : une clé SSH multi-lignes est enregistrée telle quelle', async () => {
  await api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry());
  expect(axios.post).toHaveBeenCalledTimes(1);
  const [url, body] = axios.post.mock.calls[0];
  expect(url).toBe('http://v/v1/kv/data/serveur-prod');
  expect(body.data).toMatchObject({ Password: PRIV, URL: PUB, EntryType: 'ssh' });
});

test('writeSecretV1 : même règle pour un coffre KV v1', async () => {
  await api.writeSecretV1({ name: 'kv1', version: 1 }, sshEntry());
  expect(axios.post).toHaveBeenCalledTimes(1);
  expect(axios.post.mock.calls[0][1]).toMatchObject({ Password: PRIV, EntryType: 'ssh' });
});

test('clé SSH : un caractère NUL (ou autre contrôle) reste refusé', async () => {
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ password: 'abc\u0000def' }))).rejects.toThrow(/Validation/);
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ url: 'ssh-ed25519 AAA\u001b[31m' }))).rejects.toThrow(/Validation/);
  expect(axios.post).not.toHaveBeenCalled();
});

test('clé SSH : les autres champs restent validés (nom, passphrase, notes)', async () => {
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ name: '../x' }))).rejects.toThrow(/Validation/);
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ username: 'pass\nphrase' }))).rejects.toThrow(/Validation/);
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ notes: 'n'.repeat(10001) }))).rejects.toThrow(/Validation/);
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, sshEntry({ password: 'A'.repeat(70000) }))).rejects.toThrow(/Validation/);
  expect(axios.post).not.toHaveBeenCalled();
});

test('entrée classique : un mot de passe multi-lignes ou une URL non autorisée restent refusés', async () => {
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, { name: 'a', password: 'x\ny', url: '', notes: '' })).rejects.toThrow(/caractères de contrôle/);
  await expect(api.writeSecretV2({ name: 'kv', version: 2 }, { name: 'a', password: 'x', url: ['javascript', 'alert(1)'].join(':'), notes: '' })).rejects.toThrow(/URL invalide/);
  expect(axios.post).not.toHaveBeenCalled();
});
