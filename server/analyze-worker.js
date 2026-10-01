'use strict';
// Runs analyzeParts() off the main thread, so analysing a large org doesn't stall the server's other requests.
// Started per scan by analyzeInWorker() in mcnexus-server.js; replies once and exits.
const { parentPort, workerData } = require('worker_threads');
const { analyzeParts } = require('./analyze');

try { parentPort.postMessage({ ok: true, ...analyzeParts(workerData.parts, workerData.o) }); }
catch (e) { parentPort.postMessage({ ok: false, error: e.message }); }
