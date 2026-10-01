'use strict';
// JSON data folder → PostgreSQL (PGlite). The migrated database must read back identically through PgStore.
const { describe, test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const { JsonStore } = require('../server/store');
const { PgStore } = require('../server/store-pg');
const { migrate, keyOpens } = require('../server/migrate-json-to-pg');
const { pgliteAdapter } = require('./helpers');

let HAS = true; try { require.resolve('@electric-sql/pglite'); } catch { HAS = false; }
const KEY = crypto.randomBytes(32).toString('hex');
const enc = (t, k = KEY) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', Buffer.from(k, 'hex'), iv); const d = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), d].map(b => b.toString('base64')).join('.'); };
const SECRET = 'migrate-me-secret-0123456789';

async function sourceFolder() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcnexus-migrate-'));
  const js = new JsonStore(dir);
  await js.createFirstOwner({ email: 'owner@example.test', name: 'Owner', role: 'Owner', salt: 's1', hash: 'h1' });
  await js.putSettings({ rulesX: { 'SQL-001': { sev: 'HIGH' } }, naming: [['Data Extension', 'DE_<NAME>']], data: { keepScans: 5 } });
  for (const id of ['c1', 'c2']) await js.createConnection({ id, name: 'Org ' + id, env: 'Sandbox', sub: 'mctenant0123456789', cid: 'abcd1234efgh5678', mid: '', secEnc: enc(SECRET), secretUpdated: '2026-09-30T08:00:00.000Z', status: 'Connected', validated: '30 Sep 2026 08:00', buList: [{ mid: '100', name: 'Ent' }], buOff: {}, access: [], scopes: ['email_read'], created: '2026-09-01T00:00:00.000Z' });
  for (const n of [1, 2]) await js.addScan('c1', { n, id: '#00' + n, health: 70 + n, sev: [0, 0, 1, 0, 0], dom: [1, 2, 3, 4, 5, 6, 7, 8, 9] }, { zeta: n, alpha: { b: 1, a: 2 }, findings: [{ id: 'F-00000' + n }], scan: { n } });
  await js.putTriage('c1', { 'F-000001': { status: 'Accepted', owner: 'Owner · Owner' } });
  return { dir, js };
}

describe('migrate-json-to-pg', { skip: HAS ? false : 'PGlite not installed (npm install)' }, () => {
  let src, a; const lines = [];
  before(async () => { src = await sourceFolder(); a = await pgliteAdapter(); });
  after(async () => { await a.close(); fs.rmSync(src.dir, { recursive: true, force: true }); });

  test('copies everything and verifies, with the right key', async () => {
    const r = await migrate({ from: src.dir, adapter: a, key: KEY, log: (l) => lines.push(l) });
    assert.deepEqual(r.mismatches, []);
    assert.deepEqual(r.copied, { settings: 3, users: 1, connections: 2, scans: 2, triage: 1 });
    assert.equal(r.key, true);
    assert.ok(lines.includes('Migration verified.'));
  });

  test('PgStore reads back exactly what JsonStore holds', async () => {
    const pg = new PgStore(a); await pg.init(); const js = src.js;
    assert.deepEqual(await pg.getUser('owner@example.test'), await js.getUser('owner@example.test'));
    assert.deepEqual(await pg.getSettings(), await js.getSettings());
    assert.deepEqual(await pg.listConnections(), await js.listConnections());
    assert.deepEqual(await pg.listScans('c1'), await js.listScans('c1'));
    for (const n of [1, 2]) assert.equal(JSON.stringify(await pg.getSnapshot('c1', n)), JSON.stringify(await js.getSnapshot('c1', n)));
    assert.deepEqual(await pg.getTriage('c1'), await js.getTriage('c1'));
  });

  test('secrets travel as ciphertext only', async () => {
    let dump = ''; for (const t of ['connection', 'app_setting', 'scan', 'scan_snapshot', 'triage', 'app_user']) dump += JSON.stringify(await a.query(`SELECT * FROM ${t}`, []));
    assert.ok(!dump.includes(SECRET));
    assert.ok(!lines.join('\n').includes(KEY), 'key never printed');
  });

  test('re-running never overwrites rows edited in Postgres', async () => {
    const pg = new PgStore(a);
    await pg.updateConnection('c1', { name: 'Edited in Postgres' });
    await pg.putTriage('c1', { 'F-000001': { status: 'Resolved' } });
    const r = await migrate({ from: src.dir, adapter: a, key: KEY, log: () => { } });
    assert.deepEqual(r.copied, {});
    assert.deepEqual(r.present, { settings: 3, users: 1, connections: 2, scans: 2, triage: 1 });
    assert.equal((await pg.getConnection('c1')).name, 'Edited in Postgres');
    assert.deepEqual(await pg.getTriage('c1'), { 'F-000001': { status: 'Resolved' } });
  });

  test('a wrong key is reported, and a missing snapshot file is a warning', async () => {
    fs.unlinkSync(path.join(src.dir, 'scans', 'c1', '2.json'));
    const b = await pgliteAdapter(), out = [];
    const r = await migrate({ from: src.dir, adapter: b, key: crypto.randomBytes(32).toString('hex'), log: (l) => out.push(l) });
    await b.close();
    assert.equal(r.key, false);
    assert.ok(out.some(l => /does NOT decrypt/.test(l)));
    assert.ok(r.warnings.some(w => /#002: snapshot file missing/.test(w)));
    assert.deepEqual(r.mismatches, []);
  });

  test('refuses a folder without store.json', async () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'mcnexus-empty-'));
    await assert.rejects(migrate({ from: empty, adapter: a, log: () => { } }), /No store.json/);
    fs.rmSync(empty, { recursive: true, force: true });
  });
});

test('keyOpens', () => {
  assert.equal(keyOpens(enc('x'), KEY), true);
  assert.equal(keyOpens(enc('x'), crypto.randomBytes(32).toString('hex')), false);
  assert.equal(keyOpens(null, KEY), null);
  assert.equal(keyOpens(enc('x'), null), null);
});
