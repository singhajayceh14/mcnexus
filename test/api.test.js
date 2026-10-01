'use strict';
// API routes through the real request handler on an ephemeral port, with SFMC faked.
// Tests run in order and share one server, one store and one session.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path');
const { loadServer, fakeSfmc, assertReadOnly, sfmcOrg, startApp, SUB, CID, SEC } = require('./helpers');

const { srv, dir, cleanup } = loadServer();
const { DOMAINS, RULES } = srv;
let app, fake; const bodies = [];
const call = async (...a) => { const r = await app.call(...a); bodies.push(r.text); return r; };
const OWNER = { email: 'owner@example.test', password: 'correct-horse' };
const state = {};

before(async () => { fake = fakeSfmc(sfmcOrg({ latency: 2 })).install(); app = await startApp(srv.handle); });
after(async () => { await app.close(); fake.restore(); cleanup(); });

async function waitJob(id) {
  for (let i = 0; i < 200; i++) { const r = await call('GET', '/api/jobs/' + id); if (r.json.done) return r.json; await new Promise(ok => setTimeout(ok, 25)); }
  throw new Error('job did not finish');
}

test('health is public and reports first run', async () => {
  const r = await call('GET', '/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.firstRun, true);
  assert.equal(r.json.ruleset, srv.RULESET);
});

test('everything else needs a session', async () => {
  for (const [m, p] of [['GET', '/api/connections'], ['GET', '/api/settings'], ['POST', '/api/scans'], ['GET', '/api/about'], ['GET', '/api/connections/x/dataset']]) {
    assert.equal((await call(m, p, m === 'POST' ? {} : undefined)).status, 401, m + ' ' + p);
  }
  assert.equal((await call('GET', '/api/session')).json.user, null);
});

test('first sign-in validates input, then creates the Owner', async () => {
  assert.equal((await call('POST', '/api/login', { email: 'not-an-email', password: 'whatever1' })).status, 400);
  assert.equal((await call('POST', '/api/login', { email: OWNER.email, password: 'short' })).status, 400);
  const r = await call('POST', '/api/login', OWNER);
  assert.equal(r.status, 200);
  assert.equal(r.json.user.role, 'Owner');
  assert.match(r.headers.get('set-cookie'), /^mcx=[0-9a-f]{64}; HttpOnly; SameSite=Strict; Path=\//);
  assert.equal((await call('GET', '/api/health')).json.firstRun, false);
  assert.equal((await call('GET', '/api/session')).json.user.email, OWNER.email);
});

test('wrong password and unknown users are rejected the same way', async () => {
  const saved = await call('GET', '/api/session');
  app.setCookie('');
  const a = await call('POST', '/api/login', { email: OWNER.email, password: 'wrong-password' });
  const b = await call('POST', '/api/login', { email: 'nobody@example.test', password: 'wrong-password' });
  assert.equal(a.status, 401); assert.equal(b.status, 401);
  assert.equal(a.json.error, b.json.error);
  await call('POST', '/api/login', OWNER);
  assert.equal((await call('GET', '/api/session')).json.user.email, saved.json.user.email);
});

test('connection test discovers BUs; bad input is rejected', async () => {
  assert.equal((await call('POST', '/api/connections/test', { sub: 'x', cid: CID, sec: SEC })).status, 400);
  const r = await call('POST', '/api/connections/test', { sub: `https://${SUB}.auth.marketingcloudapis.com/`, cid: CID, sec: SEC });
  assert.equal(r.status, 200);
  assert.equal(r.json.ok, true);
  assert.deepEqual(r.json.bus.map(b => b.mid), ['100', '200']);
  state.bus = r.json.bus;
});

test('create connection: secret is encrypted at rest and never returned', async () => {
  const r = await call('POST', '/api/connections', { name: 'Acme Prod', env: 'Production', sub: SUB, cid: CID, sec: SEC, bus: state.bus });
  assert.equal(r.status, 200);
  const c = r.json.connection; state.cid = c.id;
  assert.equal(c.sub, SUB);
  assert.equal(c.cidHint, CID.slice(0, 4) + '…' + CID.slice(-4));
  for (const k of ['sec', 'secEnc', 'cid']) assert.ok(!(k in c), 'publicConn exposes ' + k);
  const store = fs.readFileSync(path.join(dir, 'store.json'), 'utf8');
  assert.ok(!store.includes(SEC), 'plaintext secret in store.json');
  assert.match(JSON.parse(store).connections[0].secEnc, /^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
  const list = await call('GET', '/api/connections');
  assert.equal(list.json.connections.length, 1);
});

test('PATCH validates fields and saves nothing when the credential test fails', async () => {
  const p = '/api/connections/' + state.cid;
  assert.equal((await call('PATCH', p, { cid: 'bad id!' })).status, 400);
  assert.equal((await call('PATCH', p, { mid: '12ab' })).status, 400);
  const r = await call('PATCH', p, { sec: 'wrong-secret' });
  assert.equal(r.status, 400);
  assert.match(r.json.error, /nothing was saved/);
  const ok = await call('PATCH', p, { name: 'Acme Production' });
  assert.equal(ok.json.connection.name, 'Acme Production');
  assert.equal(ok.json.credsChanged, false);
});

test('access assessment records per-area results', async () => {
  const r = await call('POST', '/api/connections/' + state.cid + '/access');
  assert.equal(r.status, 200);
  const rows = Object.fromEntries(r.json.connection.access.map(x => [x[0], x[1]]));
  assert.equal(rows.Authentication, 'ok');
  assert.equal(rows['Data Extensions'], 'ok');
  assert.equal(r.json.connection.status, 'Connected');
});

test('scan runs as a job and the dataset matches the UI data contract', async () => {
  const s = await call('POST', '/api/scans', { connId: state.cid, mode: 'Full Assessment' });
  assert.equal(s.status, 200);
  assert.equal(s.json.scanId, '#001');
  const job = await waitJob(s.json.jobId);
  assert.equal(job.error, null);
  assert.equal(job.pct, 100);
  assert.ok(!('t0' in job));

  const d = (await call('GET', '/api/connections/' + state.cid + '/dataset')).json;
  for (const k of ['scans', 'bus', 'domains', 'findings', 'assets', 'graph', 'typeCounts', 'model', 'modules', 'inventory', 'limits', 'archNotes', 'quickWins', 'triage', 'owners']) assert.ok(k in d, 'dataset.' + k);
  const sc = d.scans[0];
  for (const k of ['id', 'date', 'health', 'cov', 'sev', 'rules', 'assets', 'dom', 'clean', 'mode', 'by']) assert.ok(k in sc, 'scan.' + k);
  assert.equal(sc.sev.length, 5);
  assert.equal(sc.dom.length, DOMAINS.length);
  assert.equal(sc.rules, 'v' + srv.RULESET);
  assert.equal(sc.mode, 'Full');
  assert.deepEqual(d.domains.map(x => x.name), DOMAINS);
  assert.ok(d.findings.length > 0);
  for (const f of d.findings) assert.ok(RULES.some(r => r[0] === f.rule));
  for (const a of d.assets) for (const k of ['key', 'name', 'type', 'bu', 'health', 'status', 'config', 'deps', 'dependents', 'history', 'degree']) assert.ok(k in a, 'asset.' + k);
  assert.ok(Array.isArray(d.graph.edges) && typeof d.graph.nodes === 'object');
  assert.deepEqual(d.owners, ['Owner · Owner']);
  state.findings = d.findings;
});

test('only one scan per connection at a time', async () => {
  const rs = await Promise.all([call('POST', '/api/scans', { connId: state.cid }), call('POST', '/api/scans', { connId: state.cid })]);
  assert.deepEqual(rs.map(r => r.status).sort(), [200, 409]);
  await waitJob(rs.find(r => r.status === 200).json.jobId);
});

test('triage persists and compare uses stable finding IDs', async () => {
  const fid = state.findings[0].id;
  assert.equal((await call('PUT', '/api/connections/' + state.cid + '/triage', { fx: { [fid]: { status: 'In review', owner: 'Owner · Owner' } } })).status, 200);
  const d = (await call('GET', '/api/connections/' + state.cid + '/dataset?scan=%23001')).json;
  assert.equal(d.triage[fid].status, 'In review');
  assert.equal(d.scan.id, '#001');
  const cmp = (await call('GET', '/api/connections/' + state.cid + '/compare?a=%23001&b=%23002')).json;
  assert.deepEqual([cmp.added, cmp.resolved], [0, 0], 'same org, same IDs');
  assert.equal((await call('GET', '/api/connections/' + state.cid + '/compare?a=%23001&b=%23999')).status, 400);
});

test('settings: limits are clamped and logo type is checked', async () => {
  const r = await call('PUT', '/api/settings', { scan: { mode: 'Quick Scan', maxPages: 99999, maxDetail: 1, concurrency: 0 } });
  assert.deepEqual([r.json.scan.maxPages, r.json.scan.maxDetail, r.json.scan.concurrency], [500, 10, 1]);
  assert.equal(r.json.scan.mode, 'Quick Scan');
  assert.equal((await call('PUT', '/api/settings', { report: { logo: 'data:text/html;base64,PHNjcmlwdD4=' } })).status, 400);
  await call('PUT', '/api/settings', { scan: { maxPages: 40, maxDetail: 400, concurrency: 6 } });
});

test('export contains snapshots and triage but no secret', async () => {
  const r = await call('GET', '/api/connections/' + state.cid + '/export');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-disposition'), /attachment; filename="MCNexus_Acme_Production_export\.json"/);
  assert.equal(r.json.scans.length, 2);
  assert.ok(r.json.scans[0].snapshot.findings.length > 0);
});

test('password change requires the current password and signs out other sessions', async () => {
  const mine = await call('GET', '/api/session');
  const other = await startApp(srv.handle); await other.call('POST', '/api/login', OWNER);
  assert.equal((await call('POST', '/api/me/password', { current: 'nope-nope', next: 'new-password-1' })).status, 400);
  assert.equal((await call('POST', '/api/me/password', { current: OWNER.password, next: 'short' })).status, 400);
  assert.equal((await call('POST', '/api/me/password', { current: OWNER.password, next: 'new-password-1' })).status, 200);
  assert.equal((await other.call('GET', '/api/connections')).status, 401, 'other session ended');
  assert.equal((await call('GET', '/api/session')).json.user.email, mine.json.user.email, 'current session kept');
  await other.close();
  OWNER.password = 'new-password-1';
});

test('clearing scans keeps the connection; deleting removes scans and triage from disk', async () => {
  const p = '/api/connections/' + state.cid;
  assert.equal((await call('DELETE', p + '/scans')).json.deleted, 2);
  assert.equal((await call('GET', p + '/dataset')).json.scans.length, 0);
  assert.ok(!fs.existsSync(path.join(dir, 'scans', state.cid)));
  assert.equal((await call('DELETE', p)).status, 200);
  assert.equal((await call('GET', p + '/dataset')).status, 404);
  const store = JSON.parse(fs.readFileSync(path.join(dir, 'store.json'), 'utf8'));
  assert.equal(store.connections.length, 0);
  assert.ok(!(state.cid in store.triage));
});

test('logout ends the session', async () => {
  assert.equal((await call('POST', '/api/logout')).status, 200);
  assert.equal((await call('GET', '/api/connections')).status, 401);
});

test('no response ever carried the client secret, and SFMC was only read', () => {
  for (const b of bodies) { assert.ok(!b.includes(SEC), 'secret in a response'); assert.ok(!b.includes('secEnc'), 'secEnc in a response'); }
  assertReadOnly(fake.calls);
});
