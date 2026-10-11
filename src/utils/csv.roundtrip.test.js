// ========================================
// TESTS ADVERSARIAUX : round-trip CSV export → import (chasse aux « décalages »)
// ========================================
// Reproduit la logique réelle d'export (en-tête + lignes via escapeCsvField) puis
// réimporte avec parseCsv, et exige une égalité EXACTE champ par champ sur des
// valeurs piégeuses. Objectif : détecter tout décalage de colonnes, perte de
// données ou corruption de caractères, y compris sur lignes irrégulières.

import { escapeCsvField, parseCsv } from './csv';

const COLS = ['name', 'username', 'password', 'url', 'notes', 'tags'];

// Construit un document CSV comme l'export réel : 1 ligne d'en-tête + 1 ligne/enregistrement.
function exportCsv(records, sep = ';') {
  const lines = [COLS.join(sep)];
  for (const rec of records) {
    lines.push(COLS.map(c => escapeCsvField(rec[c] ?? '', { separator: sep })).join(sep));
  }
  return lines.join('\r\n');
}

// Valeurs piégeuses : séparateurs, guillemets, sauts de ligne, formules, apostrophes, unicode, espaces
const NASTY = [
  'simple',
  'a;b',               // séparateur ;
  'a,b',               // séparateur ,
  'a\tb',              // tabulation
  'quote"inside"',     // guillemets
  'he said ""hi""',    // guillemets doublés littéraux
  'line1\nline2',      // LF
  'line1\r\nline2',    // CRLF
  'line1\rline2',      // CR seul
  '=SUM(A1)',          // formule
  '+33612345678',      // numéro (formule +)
  '-tiret',            // formule -
  '@handle',           // formule @
  '|pipe',             // formule |
  "'deja apostrophe",  // commence par apostrophe
  "''double apos",
  '',                  // vide
  '   espaces   ',     // espaces de bord (ne doivent PAS être rognés pour un mot de passe)
  'ünïcödé ✓ — «x»',   // unicode
  '🔐🗝️',              // emoji
  'a";b\nc,d\te',      // cocktail de tout
  ';',                 // séparateur seul
  '"',                 // guillemet seul
  'null', 'undefined',
];

describe('round-trip CSV : aucune perte ni décalage', () => {
  for (const sep of [';', ',', '\t']) {
    it(`séparateur ${JSON.stringify(sep)} : chaque champ piégeux est préservé exactement`, () => {
      // Un enregistrement par valeur piégeuse, répartie sur toutes les colonnes
      const records = NASTY.map((v, i) => ({
        name: `entry-${i}`,
        username: v,
        password: v + 'X', // garantit un champ non vide pour éviter le filtrage de ligne vide
        url: v,
        notes: v,
        tags: v,
      }));
      const csv = exportCsv(records, sep);
      const { header, rows } = parseCsv(csv, { separator: sep });
      expect(header).toEqual(COLS);
      expect(rows).toHaveLength(records.length);
      records.forEach((rec, i) => {
        for (const c of COLS) {
          expect(`${c}[${i}]=${JSON.stringify(rows[i][c])}`).toBe(`${c}[${i}]=${JSON.stringify(rec[c] ?? '')}`);
        }
      });
    });
  }

  it('ligne avec MOINS de champs que l\'en-tête : colonnes manquantes = vide, pas de décalage', () => {
    const csv = ['name;username;password;url', 'onlyname;;;'].join('\r\n');
    const { rows } = parseCsv(csv, { separator: ';' });
    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe('onlyname');
    expect(rows[0].username).toBe('');
    expect(rows[0].password).toBe('');
    expect(rows[0].url).toBe('');
  });

  it('ligne avec PLUS de champs que l\'en-tête : surplus dans __extra, colonnes alignées', () => {
    const csv = ['name;username', 'a;b;c;d'].join('\r\n');
    const { rows } = parseCsv(csv, { separator: ';' });
    expect(rows[0].name).toBe('a');
    expect(rows[0].username).toBe('b');
    expect(rows[0].__extra).toEqual(['c', 'd']);
  });

  it('champ quoté contenant le séparateur ET un saut de ligne ne décale pas les colonnes', () => {
    const rec = { name: 'x', username: 'a;b\nc', password: 'p', url: 'u', notes: 'n', tags: 't' };
    const { rows } = parseCsv(exportCsv([rec]), { separator: ';' });
    expect(rows[0].username).toBe('a;b\nc');
    expect(rows[0].password).toBe('p');
    expect(rows[0].tags).toBe('t');
  });

  it('BOM UTF-8 en tête de fichier est ignoré', () => {
    const csv = '﻿' + ['name;password', 'x;y'].join('\r\n');
    const { header, rows } = parseCsv(csv, { separator: ';' });
    expect(header).toEqual(['name', 'password']);
    expect(rows[0].name).toBe('x');
  });
});
