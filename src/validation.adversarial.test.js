// ========================================
// TESTS ADVERSARIAUX : validation (chasse aux rejets de données LÉGITIMES)
// ========================================
// validateSecret est appelé à CHAQUE écriture (y compris import). Un rejet de
// données légitimes = impossibilité d'enregistrer/importer un secret valide.

import {
  validateUsername, isValidUrl, validateSecret,
} from './validation';

describe('validateUsername — données légitimes', () => {
  it("accepte une apostrophe (ex. O'Brien, d'Artagnan)", () => {
    expect(validateUsername("O'Brien").valid).toBe(true);
  });
  it('accepte une adresse email', () => {
    expect(validateUsername('jean.dupont@example.com').valid).toBe(true);
  });
  it('rejette toujours les caractères de contrôle', () => {
    expect(validateUsername('a\u0000b').valid).toBe(false);
  });
});

describe('isValidUrl — schémas', () => {
  it('accepte ssh:// et une URL https normale', () => {
    expect(isValidUrl('ssh://host:22')).toBe(true);
    expect(isValidUrl('https://example.com/login')).toBe(true);
  });
  it('rejette javascript: et data: (anti-XSS)', () => {
    // eslint-disable-next-line no-script-url -- volontaire : charge utile malveillante que le test doit voir refusée
    expect(isValidUrl('javascript:alert(1)')).toBe(false);
    expect(isValidUrl('data:text/html,<script>1</script>')).toBe(false);
    expect(isValidUrl('vbscript:msgbox(1)')).toBe(false);
  });
  it('accepte les chemins fichier locaux Windows et UNC (affichés comme liens par l\'UI)', () => {
    expect(isValidUrl('C:\\dossier\\fichier')).toBe(true); // runtime: C:\dossier\fichier
    expect(isValidUrl('D:/x/y')).toBe(true);
    expect(isValidUrl('\\\\serveur\\partage')).toBe(true); // runtime: \\serveur\partage
  });
});

describe('validateSecret — bout en bout', () => {
  it("enregistre un secret dont l'identifiant contient une apostrophe", () => {
    const res = validateSecret({ name: 'compte', username: "O'Brien", password: 'Str0ng!pass' });
    expect(res.valid).toBe(true);
  });
  it('rejette un nom avec traversée de chemin (..)', () => {
    expect(validateSecret({ name: '../evil', password: 'p' }).valid).toBe(false);
  });
});
