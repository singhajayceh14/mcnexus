'use strict';
// One contract, every backend: JsonStore, PgStore on PGlite, and PgStore on a real database when
// MCNEXUS_TEST_PG is set (use an empty Neon branch — this suite deletes every row it can see).
const { describe, test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { JsonStore } = require('../server/store');
const { PgStore, neonAdapter, splitSql } = require('../server/store-pg');
const { pgliteAdapter, SCHEMA, PG_TABLES } = require('./helpers');
const HAS_PGLITE = (() => { try { require.resolve('@electric-sql/pglite'); return true; } catch { return false; } })();
const NO_PGLITE = HAS_PGLITE ? false : 'PGlite not installed (npm install)';

const conn = (id, o = {}) => ({ id, name: 'Org ' + id, env: 'Production', sub: 'mctenant0123456789', cid: 'abcd1234efgh5678', mid: '', secEnc: 'aXY=.dGFn.ZGF0YQ==', status: 'Connected', validated: '01 Oct 2026 10:00',
  buList: [{ mid: '100', name: 'Ent', parentMid: null }], buOff: { 200: true }, access: [['Authentication', 'ok', 'Token issued']], scopes: ['email_read'], created: '2026-10-01T10:00:00.000Z', ...o });
const summary = (n) => ({ n, id: '#' + String(n).padStart(3, '0'), date: '01 Oct 2026', health: 80 + n, cov: 100, sev: [0, 1, 2, 3, 0], rules: 'v2.1', assets: 10, dom: [1, 2, 3, 4, 5, 6, 7, 8, 9], clean: 50, mode: 'Full', by: 'Owner' });
// Key order matters to the UI's graph map; snapshots must round-trip exactly.
const snapshot = (n) => ({ zeta: 1, alpha: { b: 2, a: [n, { y: 1, x: 2 }] }, graph: { nodes: { 'DV:_sent': ['_Sent', 'Data View', 'Ent'] }, edges: [['a', 'b', 'READS']] }, findings: [{ id: 'F-ABC123', sev: 'HIGH' }], scan: summary(n) });
const owner = (email = 'owner@example.test') => ({ email, name: 'Owner', role: 'Owner', salt: 'aa', hash: 'bb' });

function contract(name, make) {
  describe(name, () => {
    let store, ctx;
    before(async () => { ctx = await make(); store = ctx.store; await store.init(); });
    after(async () => { await store.close(); if (ctx.cleanup) await ctx.cleanup(); });

    test('first owner is created exactly once, even under concurrency', async () => {
      assert.equal(await store.countUsers(), 0);
      const results = await Promise.all([1, 2, 3, 4, 5].map(i => store.createFirstOwner(owner('owner' + i + '@example.test'))));
      assert.equal(results.filter(Boolean).length, 1);
      assert.equal(await store.countUsers(), 1);
      assert.equal(await store.createFirstOwner(owner('late@example.test')), false);
    });

    test('users: get, list without secrets, change password', async () => {
      const [u] = await store.listUsers();
      assert.deepEqual(Object.keys(u).sort(), ['email', 'name', 'role']);
      const full = await store.getUser(u.email);
      assert.deepEqual(full, { email: u.email, name: 'Owner', role: 'Owner', salt: 'aa', hash: 'bb' });
      assert.equal(await store.getUser('nobody@example.test'), null);
      assert.equal(await store.setPassword(u.email, 'cc', 'dd'), true);
      assert.deepEqual([(await store.getUser(u.email)).salt, (await store.getUser(u.email)).hash], ['cc', 'dd']);
      assert.equal(await store.setPassword('nobody@example.test', 'x', 'y'), false);
    });

    test('settings: sections round-trip, unknown sections are rejected', async () => {
      assert.deepEqual(await store.getSettings(), {});
      await store.putSettings({ rulesX: { 'SQL-001': { enabled: false } }, naming: [['Data Extension', 'DE_<NAME>']] });
      await store.putSettings({ scan: { mode: 'Quick Scan', modules: null, maxPages: 40 }, naming: null });
      assert.deepEqual(await store.getSettings(), { rulesX: { 'SQL-001': { enabled: false } }, naming: null, scan: { mode: 'Quick Scan', modules: null, maxPages: 40 } });
      await assert.rejects(store.putSettings({ secrets: 1 }), /unknown field/);
    });

    test('connections: create, read, patch, unknown fields rejected', async () => {
      await store.createConnection(conn('c1'));
      await store.createConnection(conn('c2', { secretUpdated: '2026-10-01T11:00:00.000Z' }));
      assert.deepEqual(await store.getConnection('c1'), conn('c1'));
      assert.deepEqual((await store.listConnections()).map(c => c.id), ['c1', 'c2']);
      assert.equal((await store.getConnection('c2')).secretUpdated, '2026-10-01T11:00:00.000Z');
      const u = await store.updateConnection('c1', { status: 'Needs re-auth', buOff: {}, name: 'Renamed' });
      assert.deepEqual(u, { ...conn('c1'), status: 'Needs re-auth', buOff: {}, name: 'Renamed' });
      assert.equal(await store.updateConnection('nope', { status: 'x' }), null);
      await assert.rejects(store.updateConnection('c1', { password: 'x' }), /unknown field/);
      await assert.rejects(store.createConnection({ ...conn('c3'), extra: 1 }), /unknown field/);
      const copy = await store.getConnection('c1'); copy.name = 'mutated';
      assert.equal((await store.getConnection('c1')).name, 'Renamed', 'returned objects are copies');
    });

    test('scans: add, list in order, exact snapshot round-trip, prune, clear', async () => {
      assert.equal(await store.addScan('missing', summary(1), snapshot(1)), false, 'no scan for a deleted connection');
      for (const n of [1, 2, 3]) assert.equal(await store.addScan('c1', summary(n), snapshot(n)), true);
      assert.deepEqual((await store.listScans('c1')).map(s => s.id), ['#001', '#002', '#003']);
      assert.deepEqual(await store.listScans('c1'), [1, 2, 3].map(summary));
      assert.equal(JSON.stringify(await store.getSnapshot('c1', 2)), JSON.stringify(snapshot(2)));
      assert.equal(await store.getSnapshot('c1', 9), null);
      assert.equal(await store.pruneScans('c1', 0), 0, 'keep 0 = keep all');
      assert.equal(await store.pruneScans('c1', 2), 1);
      assert.deepEqual((await store.listScans('c1')).map(s => s.n), [2, 3]);
      assert.equal(await store.getSnapshot('c1', 1), null);
      assert.equal(await store.addScan('c2', summary(1), snapshot(1)), true);
      assert.equal(await store.clearScans('c2'), 1);
      assert.deepEqual(await store.listScans('c2'), []);
      assert.equal(await store.getSnapshot('c2', 1), null);
    });

    test('triage: replace per connection; unknown connection rejected', async () => {
      assert.deepEqual(await store.getTriage('c1'), {});
      assert.equal(await store.putTriage('c1', { 'F-AAA111': { status: 'In review', owner: 'Owner · Owner', notes: [] }, 'F-BBB222': { status: 'Accepted' } }), true);
      assert.equal(await store.putTriage('c1', { 'F-BBB222': { status: 'Resolved' } }), true);
      assert.deepEqual(await store.getTriage('c1'), { 'F-BBB222': { status: 'Resolved' } });
      assert.equal(await store.putTriage('missing', { x: {} }), false);
    });

    test('stats count what is stored', async () => {
      const s = await store.stats();
      assert.deepEqual([s.connections, s.scans, s.users], [2, 2, 1]);
      assert.ok(s.bytes > 0);
    });

    test('deleting a connection removes its scans, snapshots and triage', async () => {
      assert.equal(await store.deleteConnection('c1'), true);
      assert.equal(await store.deleteConnection('c1'), false);
      await store.createConnection(conn('c1'));
      assert.deepEqual(await store.listScans('c1'), []);
      assert.equal(await store.getSnapshot('c1', 3), null);
      assert.deepEqual(await store.getTriage('c1'), {});
    });
  });
}

contract('JsonStore', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcnexus-store-'));
  return { store: new JsonStore(dir), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
});

if (HAS_PGLITE) contract('PgStore on PGlite', async () => {
  const a = await pgliteAdapter(); await a.exec(SCHEMA());
  return { store: new PgStore(a) };
});
else test('PgStore on PGlite', { skip: NO_PGLITE }, () => { });

if (process.env.MCNEXUS_TEST_PG) contract('PgStore on MCNEXUS_TEST_PG', async () => {
  const a = neonAdapter(process.env.MCNEXUS_TEST_PG);
  await a.exec(SCHEMA());
  for (const t of PG_TABLES) await a.query(`DELETE FROM ${t}`, []);
  return { store: new PgStore(a) };
});

describe('PostgreSQL schema', { skip: NO_PGLITE }, () => {
  let a;
  before(async () => { if (HAS_PGLITE) a = await pgliteAdapter(); });
  after(async () => { if (a) await a.close(); });

  test('splitSql yields one statement per table/index/insert', () => {
    const st = splitSql(SCHEMA());
    assert.ok(st.length >= 12);
    for (const s of st) { assert.ok(!s.includes(';'), 'stray ; in: ' + s.slice(0, 60)); assert.match(s, /^(CREATE|INSERT)/); }
  });

  test('PgStore.init refuses an empty database, then the schema applies twice cleanly', async () => {
    await assert.rejects(new PgStore(a).init(), /schema is not installed.*db:schema/);
    await a.exec(SCHEMA()); await a.exec(SCHEMA());
    await new PgStore(a).init();
    assert.deepEqual(await a.query('SELECT version FROM schema_version', []), [{ version: 1 }]);
  });

  test('constraints: lower-case emails, known roles and settings sections only', async () => {
    await assert.rejects(a.query("INSERT INTO app_user (email, name, pw_salt, pw_hash) VALUES ('Mixed@Case.test', 'x', 'a', 'b')", []));
    await assert.rejects(a.query("INSERT INTO app_user (email, name, role, pw_salt, pw_hash) VALUES ('x@y.test', 'x', 'God', 'a', 'b')", []));
    await assert.rejects(a.query("INSERT INTO app_setting (section, value) VALUES ('other', '1')", []));
  });
});
