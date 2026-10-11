// Transmission de la langue de l'interface par le preload (MAIN-26) — node --test electron/preload.uiLanguage.test.js
// preload.js RÉEL chargé sous Node avec un module electron simulé (contextBridge / ipcRenderer) et un DOM jsdom.
// I18nProvider reflète la langue dans <html lang> ; le preload l'observe et l'envoie au processus principal
// ('set-ui-language', IPC à sens unique). Le lang="en" statique d'index.html n'est jamais transmis.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const path = require('path');

let JSDOM = null;
try { ({ JSDOM } = require('jsdom')); } catch { /* jsdom absent : test ignoré */ }

test('preload : langue de <html lang> transmise au processus principal (liste blanche, sans doublon)', { skip: !JSDOM && 'jsdom indisponible' }, async () => {
  const dom = new JSDOM('<!DOCTYPE html><html lang="en"><head></head><body><div id="root"></div></body></html>');
  const sent = [];
  const exposed = {};
  const electronMock = {
    contextBridge: { exposeInMainWorld: (name, api) => { exposed[name] = api; } },
    ipcRenderer: { send: (ch, ...a) => sent.push([ch, ...a]), invoke: async () => ({}), on() {}, removeListener() {} },
  };
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'electron') return electronMock;
    return origLoad.call(this, request, parent, isMain);
  };
  global.document = dom.window.document;
  global.MutationObserver = dom.window.MutationObserver;
  try {
    require(path.join(__dirname, 'preload.js'));
    const html = dom.window.document.documentElement;
    const tick = () => new Promise((r) => setImmediate(r));
    const langs = () => sent.filter(([ch]) => ch === 'set-ui-language').map(([, l]) => l);

    await tick();
    assert.deepEqual(langs(), [], 'lang="en" statique d\'index.html : jamais transmis (LANG de config.cfg conservé)');
    html.lang = 'fr'; // effet d'I18nProvider au montage
    await tick();
    assert.deepEqual(langs(), ['fr']);
    html.lang = 'fr'; // même valeur : pas de doublon
    await tick();
    assert.deepEqual(langs(), ['fr']);
    html.lang = 'de'; // changement de langue dans les paramètres
    await tick();
    assert.deepEqual(langs(), ['fr', 'de']);
    html.setAttribute('lang', 'xx-evil'); // valeur hors liste : ignorée
    dom.window.document.getElementById('root').setAttribute('lang', 'ja'); // autre élément : ignoré
    await tick();
    assert.deepEqual(langs(), ['fr', 'de']);
    html.lang = 'en'; // langue par défaut choisie explicitement : transmise
    await tick();
    assert.deepEqual(langs(), ['fr', 'de', 'en']);
    assert.ok(!Object.keys(exposed).some(k => /i18n|lang/i.test(k)), 'aucune API supplémentaire exposée à la page');
  } finally {
    Module._load = origLoad;
    delete global.document;
    delete global.MutationObserver;
    dom.window.close();
  }
});
