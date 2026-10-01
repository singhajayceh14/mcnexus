'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { loadServer, startApp } = require('./helpers');

const { srv, cleanup } = loadServer();
const DS = '/_ds/industry-8b9c740a-b261-4afe-b3cb-5420d91a6939';
let app;
before(async () => { app = await startApp(srv.handle); });
after(async () => { await app.close(); cleanup(); });

test('root redirects to the app', async () => {
  const r = await app.call('GET', '/');
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/MCNexus%20App.dc.html');
});

test('serves the files the UI loads', async () => {
  for (const p of ['/MCNexus%20App.dc.html', '/support.js', DS + '/styles.css', DS + '/_ds_bundle.js']) {
    assert.equal(await app.raw(p), 200, p);
  }
});

test('never serves server code, data, docs or dotfiles — in any letter case', async () => {
  const blocked = [
    '/server/mcnexus-server.js', '/SERVER/mcnexus-server.js', '/Server/README.md', '/server/data/store.json', '/SERVER/data/store.json',
    '/server/data/.key', '/uploads/MCNexus_Solution_Design.md', '/HANDOVER.md', '/CLAUDE.md', '/package.json',
    '/.gitignore', '/.vscode/settings.json', '/.thumbnail', '/SUPPORT.JS', DS + '/_ds_manifest.json', DS + '/readme.md',
    DS + '/../../server/README.md', DS + '/..%5c..%5cserver%5cREADME.md', DS + '/%2e%2e/%2e%2e/server/README.md',
    '/support.js%00', '/%E0%A4%A', '/test/helpers.js',
  ];
  for (const p of blocked) assert.equal(await app.raw(p), 404, p);
});

test('allow-list regex only admits UI paths', () => {
  assert.ok(srv.STATIC_OK.test('MCNexus App.dc.html'));
  assert.ok(srv.STATIC_OK.test('_ds/x/styles.css'));
  assert.ok(!srv.STATIC_OK.test('server/mcnexus-server.js'));
  assert.ok(!srv.STATIC_OK.test('_ds/x/y/z.js'));
  assert.ok(!srv.STATIC_OK.test('sub/MCNexus App.dc.html'));
});
