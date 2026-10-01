'use strict';
// runScan() end to end against the fake SFMC tenant in helpers.js.
const { test, after, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { loadServer, fakeSfmc, assertReadOnly, sfmcOrg, newJob, SUB, CID, SEC } = require('./helpers');

const { srv, cleanup } = loadServer();
after(cleanup);
const { runScan, testConnection, enc, MODULES } = srv;
const conn = (o = {}) => ({ id: 'c-test', sub: SUB, cid: CID, secEnc: enc(SEC), mid: '', ...o });
let fake;
const install = (org) => (fake = fakeSfmc(org).install());
afterEach(() => { if (fake) { assertReadOnly(fake.calls); fake.restore(); fake = null; } });

const EXPECTED = ['AUTO-FAIL-002', 'CP-002', 'DE-RET-001', 'JRN-COR-004', 'SEC-SCR-001', 'SQL-001', 'USR-INA-001'];

test('full scan collects every module, builds the graph and raises the expected findings', async () => {
  install(sfmcOrg());
  const job = newJob();
  const { ds, api } = await runScan(job, conn(), {});
  assert.deepEqual([...new Set(ds.findings.map(f => f.rule))].sort(), EXPECTED);
  for (const m of MODULES) assert.equal(job.mods[m], 'SUCCESS', m);
  assert.equal(ds.summary.cov, 100);
  assert.deepEqual(ds.limits.map(l => l[0]), ['Installed packages', 'Tracking']);
  assert.deepEqual(ds.bus.map(b => b.mid).sort(), ['100', '200']);
  assert.equal(ds.inventory.find(r => r[0] === 'Data Extensions')[1], 3);
  const cor = ds.findings.find(f => f.rule === 'JRN-COR-004');
  assert.deepEqual(cor.chain, ['Retail Daily Feed', 'Q_Retail_Feed', 'Retail_Entry', 'Welcome Journey']);
  assert.ok(ds.graph.edges.some(e => e[0] === 'DE:100:shared_subs' && e[1] === 'SQL:200:q_retail_feed'), 'ENT. source resolved across BUs');
  assert.ok(ds.graph.edges.some(e => e[0] === 'JRN:200:welcome' && e[1] === 'CNT:200:501' && e[2] === 'SENDS'), 'journey email resolved via legacyId');
  assert.ok(api.calls > 0);
  const cp = ds.findings.find(f => f.rule === 'CP-002');
  assert.deepEqual(cp.evidence.find(e => e[0] === 'Location'), ['Location', 'views.html · line 3, col 7'], 'CloudPage secret located in views.html');
  assert.ok(!JSON.stringify(ds).includes('pageSecret0123456789'), 'secret never in the dataset');
  // a BU-scoped token was requested for each scanned BU
  const mids = fake.calls.filter(c => c.path === '/v2/token').map(c => JSON.parse(c.body).account_id).filter(Boolean);
  assert.ok(mids.includes('100') && mids.includes('200'));
});

test('scan respects the selected BUs and modules', async () => {
  install(sfmcOrg());
  const job = newJob();
  const { ds } = await runScan(job, conn(), { mids: ['200'], modules: ['Organization', 'SQL'] });
  assert.equal(job.mods.Data, 'SKIPPED');
  assert.equal(job.mods.SQL, 'SUCCESS');
  assert.deepEqual(ds.bus.map(b => b.mid), ['200']);
  assert.ok(!fake.calls.some(c => /<ObjectType>DataExtension</.test(c.body) && !/__mcnexus_probe__/.test(c.body)), 'no DE retrieve');
  assert.deepEqual([...new Set(ds.findings.map(f => f.rule))], ['SQL-001']);
});

test('SOAP paging follows ContinueRequest until OK', async () => {
  install(sfmcOrg({ soapPage: 1 }));
  const { ds } = await runScan(newJob(), conn(), {});
  assert.equal(ds.inventory.find(r => r[0] === 'Data Extensions')[1], 3);
  assert.ok(fake.calls.some(c => /<ContinueRequest>DataExtension:1</.test(c.body)));
});

test('a rejected SOAP property falls back to the minimal list', async () => {
  install(sfmcOrg({ rejectProps: { DataExtension: ['DataRetentionPeriodLength'] } }));
  const job = newJob();
  const { ds } = await runScan(job, conn(), {});
  assert.equal(ds.inventory.find(r => r[0] === 'Data Extensions')[1], 3);
  assert.equal(job.mods.Data, 'SUCCESS');
  assert.ok(!ds.findings.some(f => f.rule === 'DE-RET-001'), 'retention unknown → not flagged');
});

test('REST 429 is retried', async () => {
  install(sfmcOrg({ fail429: 1 }));
  const job = newJob();
  await runScan(job, conn(), {});
  for (const m of MODULES) assert.equal(job.mods[m], 'SUCCESS', m);
});

test('a BU the package cannot access is reported as partial coverage, not a crash', async () => {
  const org = sfmcOrg(); org.mids[100].soap.BusinessUnit.push({ ID: '300', Name: 'Locked BU', ParentID: '100' });
  install(org);
  const job = newJob();
  const { ds } = await runScan(job, conn(), {});
  assert.equal(job.mods.Data, 'PARTIAL');
  assert.ok(ds.summary.cov < 100);
  assert.ok(ds.limits.some(l => l[0] === 'Data' && /Locked BU/.test(l[2])));
  assert.ok(job.log.some(l => /Locked BU: no access/.test(l.m)));
});

test('a cancelled scan stops before calling SFMC', async () => {
  install(sfmcOrg());
  const job = newJob(); job.cancelled = true;
  await assert.rejects(runScan(job, conn(), {}), /Cancelled by user/);
  assert.equal(fake.calls.length, 0);
  fake.restore(); fake = null;
});

test('a bad client secret fails the scan with an auth error', async () => {
  install(sfmcOrg());
  await assert.rejects(runScan(newJob(), conn({ secEnc: enc('wrong') }), {}), (e) => e.status === 401 && /invalid_client/.test(e.message));
});

test('testConnection reports each step and discovers BUs', async () => {
  install(sfmcOrg());
  const ok = await testConnection({ sub: SUB, cid: CID, sec: SEC, mid: null });
  assert.equal(ok.ok, true);
  assert.ok(ok.steps.every(s => s.ok), JSON.stringify(ok.steps));
  assert.deepEqual(ok.bus.map(b => b.mid), ['100', '200']);
  assert.equal(ok.entId, '100');
  const bad = await testConnection({ sub: SUB, cid: CID, sec: 'nope', mid: null });
  assert.equal(bad.ok, false);
  assert.match(bad.steps[1].note, /invalid_client/);
});
