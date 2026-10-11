// ========================================
// TESTS : libellés de la règle CLI « Auto-get » (onglet CLI des paramètres)
// ========================================
// La règle d'auto-approbation par coffre couvre mvault get, mais aussi mvault ssh et
// mvault winrm (cliServer.requestApproval). Les 12 locales doivent le dire, dans leur langue.

import ar from './locales/ar.json';
import de from './locales/de.json';
import en from './locales/en.json';
import es from './locales/es.json';
import fr from './locales/fr.json';
import it from './locales/it.json';
import ja from './locales/ja.json';
import ko from './locales/ko.json';
import pt from './locales/pt.json';
import ru from './locales/ru.json';
import tr from './locales/tr.json';
import zh from './locales/zh.json';

const locales = { ar, de, en, es, fr, it, ja, ko, pt, ru, tr, zh };

describe.each(Object.keys(locales))('locale %s', (code) => {
  const { autoGet, description } = locales[code].cli;

  test('cli.autoGet indique les commandes couvertes (get, ssh, winrm)', () => {
    expect(autoGet).toMatch(/\bget\b/);
    expect(autoGet).toMatch(/\bssh\b/);
    expect(autoGet).toMatch(/\bwinrm\b/);
  });

  test('cli.description mentionne {{cli}} ssh et {{cli}} winrm', () => {
    expect(description).toContain('{{cli}} ssh');
    expect(description).toContain('{{cli}} winrm');
    // Seule variable autorisée : {{cli}}
    expect((description.match(/\{\{\w+\}\}/g) || []).every(v => v === '{{cli}}')).toBe(true);
  });

  if (code !== 'en') {
    test('libellés traduits (pas de copie anglaise)', () => {
      expect(autoGet).not.toBe(en.cli.autoGet);
      expect(description).not.toBe(en.cli.description);
    });
  }
});
