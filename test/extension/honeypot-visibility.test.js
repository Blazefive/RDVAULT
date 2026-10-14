// Règle « pot de miel sr-only » des deux content scripts (chrome-extension/content.js et
// chrome-extension/vault-autofill-extension/content.js) : un champ dont la zone visible fait
// ≤ 2 px (boîte de 1×1 px, découpage clip / clip-path du champ ou d'un ancêtre proche, conteneur
// de ≤ 2×2 px à débordement masqué) n'est ni rempli, ni compté comme mot de passe présent.
// Les fonctions (cssLengthToPx, clipVisibleSize, isNegligibleArea, isCollapsedOrClipped) sont
// extraites telles quelles de chaque content.js et exécutées dans un vrai Chrome (mise en page
// réelle) : cas exclus ET garde-fous (découpages décoratifs, éléments qui échappent au débordement).
// Le parcours complet (détection, icône, remplissage) est couvert par test/e2e/run.js
// (site/honeypot-sronly.html).
// Lancement : E2E_BROWSER=<chrome.exe de Chrome for Testing> node --test test/extension/honeypot-visibility.test.js
// Sans E2E_BROWSER, le test est ignoré (skip).
'use strict'; // eslint-disable-line strict -- script CommonJS exécuté par node --test, pas un module ES
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const CHROME = process.env.E2E_BROWSER;
const SCRIPTS = {
  simple: path.join(ROOT, 'chrome-extension/content.js'),
  enrichie: path.join(ROOT, 'chrome-extension/vault-autofill-extension/content.js'),
};

/** Source des fonctions de la règle, de cssLengthToPx à la fin d'isCollapsedOrClipped */
function extractRule(file) {
  const src = fs.readFileSync(file, 'utf8');
  const start = src.indexOf('  function cssLengthToPx(');
  const fnStart = src.indexOf('  function isCollapsedOrClipped(');
  const end = fnStart >= 0 ? src.indexOf('\n  }\n', fnStart) : -1;
  assert.ok(start >= 0 && fnStart > start && end > fnStart, `fonctions de la règle introuvables dans ${file}`);
  const constant = /const NEGLIGIBLE_SIZE_PX = (\d+);/.exec(src);
  const depth = /const ANCESTOR_OPACITY_DEPTH = (\d+);/.exec(src);
  assert.ok(constant && depth, `constantes introuvables dans ${file}`);
  return `const NEGLIGIBLE_SIZE_PX = ${constant[1]}; const ANCESTOR_OPACITY_DEPTH = ${depth[1]};\n` +
    src.slice(start, end + 4);
}

// data-exp="true" : doit être EXCLU (zone négligeable) ; "false" : doit rester présenté
const PAGE = `<!doctype html><html><body style="margin:0">
<style>.f { width: 200px; height: 30px; }</style>
<input class="f" data-exp="true" id="sr_only_tailwind" style="position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border-width:0">
<input class="f" data-exp="true" id="tiny_1x1" style="width:1px;height:1px;padding:0;border:0">
<input class="f" data-exp="true" id="height_1px" style="height:1px;padding:0;border:0">
<input class="f" data-exp="true" id="clip_rect_wp" style="position:absolute;top:300px;left:0;clip:rect(1px 1px 1px 1px)">
<input class="f" data-exp="true" id="clip_rect_auto" style="position:fixed;top:340px;left:0;clip:rect(0px, auto, 0px, auto)">
<input class="f" data-exp="true" id="clip_path_inset50" style="clip-path:inset(50%)">
<input class="f" data-exp="true" id="clip_path_inset100_box" style="clip-path:inset(100%) border-box">
<input class="f" data-exp="true" id="clip_path_inset_px" style="clip-path:inset(17px 0)">
<input class="f" data-exp="true" id="clip_path_circle0" style="clip-path:circle(0 at 10px 10px)">
<input class="f" data-exp="true" id="clip_path_ellipse" style="clip-path:ellipse(0 10px)">
<input class="f" data-exp="true" id="clip_path_polygon" style="clip-path:polygon(evenodd, 0 0, 100% 0, 100% 1px)">
<div style="position:absolute;top:380px;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)"><input class="f" data-exp="true" id="in_sr_only_wrapper"></div>
<div style="clip-path:inset(50%)"><div><div><input class="f" data-exp="true" id="in_clipped_ancestor"></div></div></div>
<div style="position:absolute;top:420px;width:2px;height:2px;overflow:hidden"><div><input class="f" data-exp="true" id="in_2x2_overflow_box"></div></div>
<div style="position:relative;width:1px;height:1px;overflow:hidden"><input class="f" data-exp="true" id="abs_in_positioned_box" style="position:absolute"></div>
<input class="f" data-exp="false" id="plain">
<input class="f" data-exp="false" id="transparent_floating_label" style="opacity:0">
<input class="f" data-exp="false" id="clip_path_rounded" style="clip-path:inset(0 round 8px)">
<input class="f" data-exp="false" id="clip_path_circle50" style="clip-path:circle(50%)">
<input class="f" data-exp="false" id="clip_path_closest_side" style="clip-path:circle(closest-side)">
<input class="f" data-exp="false" id="clip_path_url" style="clip-path:url(#absent)">
<input class="f" data-exp="false" id="clip_path_calc" style="clip-path:inset(calc(10% + 1px))">
<div style="clip-path:polygon(0 0, 100% 0, 100% 100%, 0 100%)"><input class="f" data-exp="false" id="in_full_polygon"></div>
<input class="f" data-exp="false" id="clip_on_static" style="clip:rect(0 0 0 0)">
<input class="f" data-exp="false" id="clip_large" style="position:absolute;top:540px;left:300px;clip:rect(0px, 500px, 500px, 0px)">
<div style="width:1px;height:1px;overflow:hidden"><input class="f" data-exp="false" id="abs_escapes_static_box" style="position:absolute;top:600px;left:300px"></div>
<div style="width:1px;height:1px;overflow:hidden"><input class="f" data-exp="false" id="fixed_escapes_box" style="position:fixed;top:640px;left:300px"></div>
<div style="width:1px;height:1px"><input class="f" data-exp="false" id="in_1x1_overflow_visible"></div>
<div style="height:0;overflow:hidden"><input class="f" data-exp="false" id="in_collapsed_full_width_section"></div>
<span style="overflow:hidden;font-size:0"><input class="f" data-exp="false" id="in_inline_overflow"></span>
<div style="display:contents;clip-path:inset(50%)"><input class="f" data-exp="false" id="in_display_contents"></div>
</body></html>`;

test('pots de miel sr-only : règle de visibilité identique dans les deux extensions', { skip: CHROME ? false : 'E2E_BROWSER non défini (chemin de chrome.exe de Chrome for Testing)' }, async (t) => {
  const puppeteer = require(path.join(ROOT, 'node_modules/puppeteer-core'));
  const os = require('node:os');
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'rdvault-ext-visibility-'));
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, userDataDir: profile, args: ['--no-first-run', '--no-default-browser-check'] });
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1180, height: 800 });
    await page.setContent(PAGE);
    for (const [name, file] of Object.entries(SCRIPTS)) {
      await t.test(`extension ${name}`, async () => {
        const results = await page.evaluate((ruleSrc) => {
          // eslint-disable-next-line no-new-func
          const isCollapsedOrClipped = new Function(`
            function getParentElement(node) {
              if (!node) return null;
              if (node.parentElement) return node.parentElement;
              return node.parentNode && node.parentNode.host ? node.parentNode.host : null;
            }
            ${ruleSrc}
            return isCollapsedOrClipped;`)();
          return Array.from(document.querySelectorAll('[data-exp]')).map(el => ({
            id: el.id,
            expected: el.dataset.exp === 'true',
            got: isCollapsedOrClipped(el, el.getBoundingClientRect(), getComputedStyle(el)),
          }));
        }, extractRule(file));
        assert.ok(results.length >= 30, 'page de cas chargée');
        const wrong = results.filter(r => r.got !== r.expected).map(r => `${r.id} (attendu ${r.expected ? 'exclu' : 'présenté'})`);
        assert.deepEqual(wrong, [], 'cas mal classés : ' + wrong.join(', '));
      });
    }
  } finally {
    await browser.close();
    fs.rmSync(profile, { recursive: true, force: true });
  }
});
