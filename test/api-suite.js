'use strict';
// API routes through the real request handler on an ephemeral port, with SFMC faked.
// Shared by api.test.js (JsonStore) and api-pg.test.js (PgStore on PGlite).
// setup() → { store, reopen: () => a new store on the same data, raw: async () => every persisted byte as text, cleanup? }.
// Tests run in order and share one server, one store and one session.
const { describe, test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { loadServer, fakeSfmc, assertReadOnly, sfmcOrg, startApp, SUB, CID, SEC } = require('./helpers');

module.exports = function apiSuite(label, setup) {
describe(label, () => {
// Low sign-in cap so the throttle test is quick; trust X-Forwarded-* like a deployment behind a proxy.
const { srv, cleanup } = loadServer({ MCNEXUS_LOGIN_MAX: '3', MCNEXUS_TRUST_PROXY: '1' });
const { DOMAINS, RULES } = srv;
let app, fake, ctx; const bodies = [];
const call = async (...a) => { const r = await app.call(...a); bodies.push(r.text); return r; };
const OWNER = { email: 'owner@example.test', password: 'correct-horse' };
const state = {};

before(async () => { ctx = await setup(); srv.useStore(ctx.store); fake = fakeSfmc(sfmcOrg({ latency: 2 })).install(); app = await startApp(srv.handle); });
after(async () => { await app.close(); fake.restore(); await ctx.store.close(); if (ctx.cleanup) await ctx.cleanup(); cleanup(); });

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
  assert.ok(!(await ctx.raw()).includes(SEC), 'plaintext secret in storage');
  assert.match((await ctx.store.getConnection(c.id)).secEnc, /^[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
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
  const ok = rs.find(r => r.status === 200), busy = rs.find(r => r.status === 409);
  assert.equal(busy.json.jobId, ok.json.jobId, '409 names the running job so the UI can re-attach');
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

// ---------- resumable scans ----------
const TOKEN_RE = /tok-\d+-\d+/;   // the fake tenant's access tokens
const lastTwo = async () => { const d = (await call('GET', '/api/connections/' + state.cid + '/dataset')).json; return d.scans.slice(-2); };
const findingIds = async (sid) => (await call('GET', '/api/connections/' + state.cid + '/dataset?scan=' + encodeURIComponent(sid))).json.findings.map(f => f.id).sort();
const inventory = async (sid) => (await call('GET', '/api/connections/' + state.cid + '/dataset?scan=' + encodeURIComponent(sid))).json.inventory;

test('poll mode: one step per poll, overlapping polls never repeat a step, result matches a background scan', async () => {
  srv.setScanMode('poll');
  try {
    const calls0 = fake.calls.length;
    const id = (await call('POST', '/api/scans', { connId: state.cid, mode: 'Full Assessment' })).json.jobId;
    assert.equal((await ctx.store.getJob(id)).state.at, 0, 'nothing runs until polled');
    await call('GET', '/api/jobs/' + id);
    assert.equal((await ctx.store.getJob(id)).state.at, 1, 'one step per poll');
    let done = null;
    for (let i = 0; i < 100 && !done; i++) done = (await Promise.all([1, 2, 3].map(() => call('GET', '/api/jobs/' + id)))).map(r => r.json).find(j => j.done) || null;
    assert.ok(done, 'finished');
    assert.equal(done.error, null);
    assert.equal(done.pct, 100);
    for (const k of ['plan', 'tok', 'opts', 'cov', 'org', 'cursor']) assert.ok(!(k in done), 'job response exposes ' + k);
    const [a, b] = await lastTwo();
    assert.deepEqual(await inventory(b.id), await inventory(a.id), 'no duplicated data');
    // Steps are idempotent (a re-run rewrites the same part), so duplicates show up only as repeated SFMC calls.
    const deRetrieves = fake.calls.slice(calls0).filter(c => /<ObjectType>DataExtension</.test(c.body) && !/__mcnexus_probe__/.test(c.body));
    assert.equal(deRetrieves.length, 2, 'one DataExtension retrieve per BU — the lease stopped concurrent polls repeating a step');
    assert.deepEqual(await findingIds(b.id), await findingIds(a.id));
    assert.equal(await ctx.store.getJobPart(id, 0), null, 'parts deleted when the job ends');
  } finally { srv.setScanMode('background'); }
});

test('cancel ends a job at the next step and frees the connection', async () => {
  srv.setScanMode('poll');
  try {
    const before = (await lastTwo()).length;
    const id = (await call('POST', '/api/scans', { connId: state.cid })).json.jobId;
    await call('GET', '/api/jobs/' + id);
    const j = (await call('POST', '/api/jobs/' + id + '/cancel')).json;
    assert.deepEqual([j.done, j.cancelled, j.error], [true, true, 'Cancelled by user']);
    const again = await call('POST', '/api/scans', { connId: state.cid });
    assert.equal(again.status, 200, 'connection free again');
    assert.equal((await call('POST', '/api/jobs/' + again.json.jobId + '/cancel')).json.done, true);
    assert.equal((await lastTwo()).length, before, 'no scan stored');
  } finally { srv.setScanMode('background'); }
});

test('an interrupted scan resumes after a restart; tokens stay encrypted throughout', async () => {
  srv.setScanMode('poll');
  const id = (await call('POST', '/api/scans', { connId: state.cid })).json.jobId;
  await call('GET', '/api/jobs/' + id); await call('GET', '/api/jobs/' + id);   // org + security done
  const mid = await ctx.store.getJob(id);
  assert.ok(mid.state.at >= 2 && mid.state.tok, 'token cache carried between steps');
  assert.doesNotMatch(await ctx.raw(), TOKEN_RE, 'access token stored in plaintext');
  await ctx.store.claimJob(id, Date.now(), 50);   // a worker died holding a short lease
  ctx.store = ctx.reopen(); srv.useStore(ctx.store); srv.setScanMode('background');   // restart, local mode
  const r = await call('POST', '/api/scans', { connId: state.cid });
  assert.deepEqual([r.status, r.json.jobId], [409, id], 'start again → re-attach to the stalled job');
  await new Promise(ok => setTimeout(ok, 60));   // let the dead worker's lease lapse
  const j = await waitJob(id);
  assert.equal(j.error, null);
  const [a, b] = await lastTwo();
  assert.deepEqual(await findingIds(b.id), await findingIds(a.id));
  assert.equal((await ctx.store.getJob(id)).state.tok, null, 'token cache dropped at the end');
  for (const body of bodies) assert.doesNotMatch(body, TOKEN_RE, 'access token in a response');
});

test('clearing scans keeps the connection; deleting removes scans and triage from disk', async () => {
  const p = '/api/connections/' + state.cid;
  const had = (await call('GET', p + '/dataset')).json.scans.length;
  assert.equal((await call('DELETE', p + '/scans')).json.deleted, had);
  assert.equal((await call('GET', p + '/dataset')).json.scans.length, 0);
  assert.equal(await ctx.store.getSnapshot(state.cid, 1), null);
  assert.equal((await call('DELETE', p)).status, 200);
  assert.equal((await call('GET', p + '/dataset')).status, 404);
  assert.equal((await ctx.store.listConnections()).length, 0);
  assert.deepEqual(await ctx.store.getTriage(state.cid), {});
});

test('sessions survive a restart; only a hash of the token is stored', async () => {
  const tok = app.cookie().replace(/^mcx=/, '');
  ctx.store = ctx.reopen(); srv.useStore(ctx.store);   // later tests read through the same instance the server uses
  assert.equal((await call('GET', '/api/session')).json.user.email, OWNER.email);
  const raw = await ctx.raw();
  assert.ok(!raw.includes(tok), 'raw session token in storage');
  assert.ok(raw.includes(crypto.createHash('sha256').update(tok).digest('hex')));
});

test('an idle-expired session is rejected and removed', async () => {
  const mine = app.cookie(), tok = crypto.randomBytes(32).toString('hex'), hash = crypto.createHash('sha256').update(tok).digest('hex'), now = Date.now();
  await ctx.store.createSession({ hash, email: OWNER.email, created: now - 9 * 3600e3, seen: now - 9 * 3600e3, expires: now - 3600e3, ua: '', ip: '' });
  app.setCookie('mcx=' + tok);
  assert.equal((await call('GET', '/api/connections')).status, 401);
  assert.equal(await ctx.store.getSession(hash), null);
  app.setCookie(mine);
});

test('activity slides the idle expiry but never past the absolute lifetime', async () => {
  const mine = app.cookie(), tok = crypto.randomBytes(32).toString('hex'), hash = crypto.createHash('sha256').update(tok).digest('hex'), now = Date.now();
  const created = now - srv.SESSION_MAX + 30e3;
  await ctx.store.createSession({ hash, email: OWNER.email, created, seen: now - 5 * 60e3, expires: created + srv.SESSION_MAX, ua: '', ip: '' });
  app.setCookie('mcx=' + tok);
  assert.equal((await call('GET', '/api/connections')).status, 200);
  const x = await ctx.store.getSession(hash);
  assert.ok(x.seen >= now, 'last seen updated');
  assert.equal(x.expires, created + srv.SESSION_MAX, 'capped at the absolute lifetime, not now + idle');
  await ctx.store.deleteSession(hash);
  app.setCookie(mine);
});

test('sessions list shows every device; sign out others ends the rest', async () => {
  const other = await startApp(srv.handle); try {
  await other.call('POST', '/api/login', OWNER, { 'user-agent': 'OtherDevice/1.0', 'x-forwarded-for': '203.0.113.9' });
  const list = (await call('GET', '/api/me/sessions')).json.sessions;
  assert.equal(list.filter(x => x.current).length, 1);
  const o = list.find(x => x.ua === 'OtherDevice/1.0');
  assert.ok(o && !o.current && o.ip === '203.0.113.9', JSON.stringify(list));
  assert.ok(typeof o.created === 'number' && typeof o.seen === 'number');
  assert.ok((await call('POST', '/api/me/signout-others')).json.ended >= 1);
  assert.equal((await other.call('GET', '/api/connections')).status, 401);
  assert.deepEqual((await call('GET', '/api/me/sessions')).json.sessions.map(x => x.current), [true]);
  } finally { await other.close(); }
});

test('sign-in is throttled per email after repeated failures', async () => {
  const c = await startApp(srv.handle); try {
  for (let i = 0; i < 3; i++) assert.equal((await c.call('POST', '/api/login', { email: OWNER.email, password: 'wrong-' + i })).status, 401);
  const r = await c.call('POST', '/api/login', OWNER);
  assert.equal(r.status, 429, 'blocked even with the right password');
  assert.ok(+r.headers.get('retry-after') > 0);
  assert.match(r.json.error, /Too many sign-in attempts/);
  await ctx.store.clearFailures('email:' + OWNER.email);
  assert.equal((await c.call('POST', '/api/login', OWNER)).status, 200);
  } finally { await c.close(); }
});

test('cookie gets Secure only over HTTPS (here via a trusted proxy)', async () => {
  const c = await startApp(srv.handle); try {
  assert.doesNotMatch((await c.call('POST', '/api/login', OWNER)).headers.get('set-cookie'), /Secure/);
  assert.match((await c.call('POST', '/api/login', OWNER, { 'x-forwarded-proto': 'https' })).headers.get('set-cookie'), /; Secure$/);
  } finally { await c.close(); }
});

test('logout ends the session', async () => {
  const hash = crypto.createHash('sha256').update(app.cookie().replace(/^mcx=/, '')).digest('hex');
  assert.equal((await call('POST', '/api/logout')).status, 200);
  assert.equal((await call('GET', '/api/connections')).status, 401);
  assert.equal(await ctx.store.getSession(hash), null, 'removed from storage');
});

test('no response ever carried the client secret, and SFMC was only read', () => {
  for (const b of bodies) { assert.ok(!b.includes(SEC), 'secret in a response'); assert.ok(!b.includes('secEnc'), 'secEnc in a response'); }
  assertReadOnly(fake.calls);
});
});
};
