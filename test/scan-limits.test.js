'use strict';
// Page caps. MCNEXUS_MAX_PAGES=2 so the fixtures can hit the cap with a handful of rows.
const { test, after, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { loadServer, fakeSfmc, assertReadOnly, sfmcOrg, newJob, SUB, CID, SEC, RECENT } = require('./helpers');

const { srv, cleanup } = loadServer({ MCNEXUS_MAX_PAGES: '2' });
after(cleanup);
const { runScan, enc } = srv;
const conn = () => ({ id: 'c-test', sub: SUB, cid: CID, secEnc: enc(SEC), mid: '' });
let fake;
afterEach(() => { if (fake) { assertReadOnly(fake.calls); fake.restore(); fake = null; } });
const inv = (ds, k) => ds.inventory.find(r => r[0] === k)[1];
const auto = (id) => ({ id, name: 'Auto ' + id, key: id, statusId: 6, lastRunTime: RECENT, steps: [{ step: 1, activities: [{ name: 'w', objectTypeId: 467, activityObjectId: 'w' }] }] });

test('SOAP results cut off by the page cap are reported as partial coverage', async () => {
  const org = sfmcOrg({ soapPage: 1 });
  // BU 200 gets a third DE placed first, so Retail_Entry (the query target) falls past the cap.
  org.mids[200].soap.DataExtension.unshift({ ObjectID: 'de-oid-early', CustomerKey: 'early', Name: 'Early', IsSendable: 'false', CreatedDate: RECENT, ModifiedDate: RECENT });
  fake = fakeSfmc(org).install();
  const job = newJob();
  const { ds } = await runScan(job, conn(), {});
  assert.equal(job.mods.Organization, 'SUCCESS', '2 BUs fit in 2 pages exactly');
  assert.equal(job.mods.Data, 'PARTIAL');
  assert.equal(job.mods.Security, 'PARTIAL', '3 users do not fit in 2 pages');
  assert.ok(ds.limits.some(l => l[0] === 'Data' && /page limit/.test(l[2])), JSON.stringify(ds.limits));
  assert.ok(job.log.some(l => /page limit/.test(l.m)));
  const rules = ds.findings.map(f => f.rule);
  assert.ok(!rules.includes('SQL-TGT-001'), 'target past the cap is not "missing"');
  assert.ok(!rules.includes('DE-PK-001'), 'field list cut off mid-DE is not "no primary key"');
});

test('REST paging continues when SFMC returns smaller pages than requested', async () => {
  const org = sfmcOrg({ restPageCap: 1 });
  org.mids[200].rest.automations.push(auto('auto-2'));
  fake = fakeSfmc(org).install();
  const job = newJob();
  const { ds } = await runScan(job, conn(), {});
  assert.equal(inv(ds, 'Automations'), 2);
  assert.equal(job.mods.Automation, 'SUCCESS');
});

test('REST results cut off by the page cap are reported as partial coverage', async () => {
  const org = sfmcOrg({ restPageCap: 1 });
  org.mids[200].rest.automations.push(auto('auto-2'), auto('auto-3'));
  fake = fakeSfmc(org).install();
  const job = newJob();
  const { ds } = await runScan(job, conn(), {});
  assert.equal(inv(ds, 'Automations'), 2);
  assert.equal(job.mods.Automation, 'PARTIAL');
  assert.ok(ds.limits.some(l => l[0] === 'Automation' && /page limit/.test(l[2])), JSON.stringify(ds.limits));
});
