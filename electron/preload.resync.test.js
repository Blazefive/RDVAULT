// Demande de republication de l'état de synchronisation (vague F) — node --test electron/preload.resync.test.js
// preload.js RÉEL chargé sous Node avec un module electron simulé (contextBridge / ipcRenderer).
// Le processus principal envoie 'sync-resync-request' quand la fenêtre redevient réactive après un gel
// ('responsive') : electronSync.onResyncRequest le relaie au renderer (useSync), sans objet IPC ni donnée,
// avec un seul écouteur actif et une fonction de désabonnement.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('module');
const path = require('path');
const { EventEmitter } = require('events');

test('preload : onResyncRequest relaie sync-resync-request (un seul écouteur, désabonnement, aucune donnée)', () => {
  const ipc = new EventEmitter();
  const exposed = {};
  const electronMock = {
    contextBridge: { exposeInMainWorld: (name, api) => { exposed[name] = api; } },
    ipcRenderer: {
      send() {}, invoke: async () => ({}),
      on: (ch, fn) => ipc.on(ch, fn),
      removeListener: (ch, fn) => ipc.removeListener(ch, fn),
    },
  };
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'electron') return electronMock;
    return origLoad.call(this, request, parent, isMain);
  };
  try {
    require(path.join(__dirname, 'preload.js'));
    const api = exposed.electronSync;
    assert.equal(typeof api.onResyncRequest, 'function');

    const calls = [];
    const off1 = api.onResyncRequest((...args) => calls.push(['premier', args]));
    const off2 = api.onResyncRequest((...args) => calls.push(['second', args]));
    assert.equal(ipc.listenerCount('sync-resync-request'), 1, 'un seul écouteur actif (le précédent est retiré)');

    // L'objet évènement IPC et tout argument éventuel ne sont jamais transmis à la page
    ipc.emit('sync-resync-request', { sender: 'objet IPC' }, { inattendu: true });
    assert.deepEqual(calls, [['second', []]]);

    off1(); // ancien désabonnement : sans effet sur l'écouteur courant
    assert.equal(ipc.listenerCount('sync-resync-request'), 1);
    off2();
    assert.equal(ipc.listenerCount('sync-resync-request'), 0);
    ipc.emit('sync-resync-request', {});
    assert.equal(calls.length, 1);

    // Rappel invalide : refusé sans écouteur enregistré
    const noop = api.onResyncRequest('pas une fonction');
    assert.equal(typeof noop, 'function');
    assert.equal(ipc.listenerCount('sync-resync-request'), 0);
  } finally {
    Module._load = origLoad;
  }
});
