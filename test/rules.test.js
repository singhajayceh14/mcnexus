'use strict';
// analyze() on hand-built raw models (the shape runScan collects into M). No SFMC involved.
const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { loadServer, RECENT, OLD } = require('./helpers');

const { srv, cleanup } = loadServer();
after(cleanup);
const { analyze, RULES, DOMAINS, DOMAIN_OF, MODULES, SEVS, W, score } = srv;

const ENT = '100', BU = { mid: ENT, name: 'Acme', short: 'Acme', parentMid: null, parent: '—' };
const tag = (o, mid = ENT, bu = 'Acme') => ({ mid, bu, ...o });
const de = (o) => tag({ objectId: 'oid-' + o.ck, sendable: false, categoryId: '1', created: RECENT, modified: RECENT, retLen: '30', retPeriod: 'Days', rowRet: false, retKnown: true, ...o });
const fields = (...names) => names.map(n => ({ name: n.replace('*', ''), pk: n.endsWith('*'), type: 'Text' }));
const q = (o) => tag({ objectId: 'oid-' + o.ck, update: 'Overwrite', created: RECENT, modified: RECENT, ...o });
const auto = (o) => tag({ status: 'Scheduled', lastRun: RECENT, steps: [], detailed: true, created: RECENT, modified: RECENT, ...o });
const jrn = (o) => tag({ version: 1, status: 'Published', emails: [], acts: 1, goal: false, created: RECENT, modified: RECENT, versions: [], ...o });
const cnt = (o) => tag({ typeName: 'htmlemail', isPage: false, folder: 'Content Builder', created: RECENT, modified: RECENT, text: '', ...o });
const user = (id, last, o = {}) => ({ ID: id, UserID: 'u' + id, Name: 'User ' + id, ActiveFlag: 'true', IsAPIUser: 'false', LastSuccessfulLogin: last, Client: { ID: ENT }, ...o });
const empty = () => ({ des: [], fields: {}, folders: {}, queries: [], autos: [], imports: [], scripts: [], journeys: [], evs: [], content: [], users: [] });

function run(M, { mods = MODULES, rulesX = {}, naming = null, bus = [BU] } = {}) {
  const cov = {}; MODULES.forEach(m => cov[m] = { ok: 1, fail: 0, notes: [] });
  const job = { counts: {} }, log = [];
  const ds = analyze(M, { bus, allBus: bus, entMid: ENT, mods: new Set(mods), cov, naming, rulesX, L: (m) => log.push(m), job });
  return { ds, job, log, rules: ds.findings.map(f => f.rule) };
}

// One trigger per rule.
function dirtyOrg() {
  const M = empty();
  M.des.push(
    de({ ck: 'subs_noret', name: 'Subscribers_NoRet', sendable: true, retLen: '' }),       // DE-RET-001
    de({ ck: 'leads_nopk', name: 'Leads_NoPK', sendable: true }),                          // DE-PK-001
    de({ ck: 'old_archive', name: 'Old_Archive', modified: OLD, created: OLD }),           // DE-ORP-001
    de({ ck: 'journey_entry', name: 'Journey_Entry', sendable: true }),
    de({ ck: 'source_table', name: 'Source_Table' }),
  );
  M.fields = { [ENT + '|subs_noret']: fields('SubscriberKey*'), [ENT + '|leads_nopk']: fields('Email', 'Name'), [ENT + '|journey_entry']: fields('SubscriberKey*'), [ENT + '|source_table']: fields('Id*') };
  M.queries.push(
    q({ ck: 'q_star', name: 'Q_Star', text: 'SELECT * FROM Source_Table', targetName: 'Subscribers_NoRet', targetCk: 'subs_noret' }),     // SQL-001
    q({ ck: 'q_deep', name: 'Q_Deep', text: 'SELECT a FROM (SELECT a FROM (SELECT a FROM (SELECT a FROM (SELECT a FROM Source_Table) a) b) c) d', targetName: 'Source_Table', targetCk: 'source_table' }), // SQL-007
    q({ ck: 'q_tgt', name: 'Q_Tgt', text: 'SELECT Id FROM Source_Table', targetName: 'Missing_Target', targetCk: 'missing_target' }),       // SQL-TGT-001
    q({ ck: 'q_src', name: 'Q_Src', text: 'SELECT g.Id FROM Ghost_Table g JOIN _Sent s ON s.SubscriberKey = g.Id', targetName: 'Leads_NoPK', targetCk: 'leads_nopk' }), // SQL-SRC-001
    q({ ck: 'q_feed', name: 'Q_Feed', objectId: 'oid-feed', text: 'SELECT Id FROM Source_Table', targetName: 'Journey_Entry', targetCk: 'journey_entry' }),
  );
  M.autos.push(
    auto({ id: 'a-err', name: 'Auto_Err', status: 'Error', steps: [{ name: 'Feed', typeId: 300, objectId: 'oid-feed', step: 1 }] }),   // AUTO-FAIL-002 → JRN-COR-004
    auto({ id: 'a-stale', name: 'Auto_Stale', status: 'Scheduled', lastRun: OLD, steps: [{ name: 'x', typeId: 467, objectId: 'w', step: 1 }] }), // AUTO-STL-001
    auto({ id: 'a-empty', name: 'Auto_Empty', status: 'Ready', steps: [] }),                                                                // AUTO-EMP-001
  );
  M.evs.push(tag({ key: 'ev1', deId: 'oid-journey_entry', deName: 'Journey_Entry', type: 'EmailAudience' }), tag({ key: 'ev2', deId: 'oid-gone', deName: 'Gone_DE', type: 'EmailAudience' }));
  M.journeys.push(
    jrn({ id: 'j1', key: 'welcome', name: 'Welcome', version: 4, status: 'Running', evKey: 'ev1', emails: [{ name: 'Welcome Email', emailId: '555' }],
      versions: [1, 2, 3].map(v => ({ v, status: 'Stopped', modified: OLD })).concat([{ v: 4, status: 'Running', modified: RECENT }]) }), // JRN-COR-004 + JRN-VER-002
    jrn({ id: 'j2', key: 'winback', name: 'Winback', status: 'Published', evKey: 'ev2' }),                                                // JRN-ENT-001
  );
  M.content.push(
    cnt({ id: '501', ck: 'page1', name: 'Landing', typeName: 'webpage', isPage: true, text: '<script runat=server>var client_secret = "abcdef1234567890xyz";</script>' }), // CP-002
    cnt({ id: '502', ck: 'welcome-email', name: 'Welcome Email', legacyId: '555', text: '%%=ContentBlockByKey("missing-block")=%% %%=Lookup("Ghost_DE","a","b","c")=%%' }),  // CNT-REF-002 + CNT-DE-001
  );
  M.scripts.push(tag({ id: 'scr1', name: 'Script_Secret', ck: 'scr1', text: 'var apiKey = "ZZZZsecretvalue123";', created: RECENT, modified: RECENT })); // SEC-SCR-001
  M.users.push(user('1', RECENT), user('2', OLD), user('3', OLD, { IsAPIUser: 'true' }), user('4', OLD, { ActiveFlag: 'false' }));      // USR-INA-001 (1 of 4)
  return M;
}
const DIRTY_NAMING = [['Data Extension', 'DE_<NAME>']];                                                                                   // GOV-NAM-001

// Nothing should fire.
function cleanOrg() {
  const M = empty(), CHILD = '200';
  M.des.push(
    de({ ck: 'subs', name: 'Subscribers', sendable: true }),
    de({ ck: 'stage', name: 'Stage', sendable: false }),
    de({ ck: 'shared', name: 'Shared_Lookup' }),
  );
  M.fields = { [ENT + '|subs']: fields('SubscriberKey*', 'Email'), [ENT + '|stage']: fields('SubscriberKey', 'Email'), [ENT + '|shared']: fields('K*') };
  M.queries.push(q({ ck: 'q1', name: 'Q_Build', objectId: 'oid-q1', text: 'SELECT s.SubscriberKey, s.Email FROM Stage s JOIN _Subscribers x ON x.SubscriberKey = s.SubscriberKey', targetName: 'Subscribers', targetCk: 'subs' }));
  M.queries.push(q({ ck: 'q2', name: 'Q_Child', mid: CHILD, bu: 'Child', objectId: 'oid-q2', text: 'SELECT K FROM ENT.Shared_Lookup', targetName: 'Child_Target', targetCk: 'child_target' }));
  M.des.push(de({ ck: 'child_target', name: 'Child_Target', mid: CHILD, bu: 'Child' }));
  M.fields[CHILD + '|child_target'] = fields('K*');
  M.autos.push(auto({ id: 'a1', name: 'Auto_Build', status: 'Scheduled', steps: [{ name: 'Build', typeId: 300, objectId: 'oid-q1', step: 1 }] }));
  M.evs.push(tag({ key: 'ev1', deId: 'oid-subs', deName: 'Subscribers' }));
  M.journeys.push(jrn({ id: 'j1', key: 'welcome', name: 'Welcome', status: 'Published', evKey: 'ev1', versions: [{ v: 1, status: 'Published', modified: RECENT }] }));
  M.content.push(
    cnt({ id: '601', ck: 'hdr', name: 'Header', typeName: 'htmlblock', text: '<h1>Hi</h1>' }),
    cnt({ id: '602', ck: 'email', name: 'Email', text: '%%=ContentBlockByKey("hdr")=%% %%=ContentBlockById("601")=%% %%=Lookup("Subscribers","Email","SubscriberKey",_subscriberkey)=%%' }),
    cnt({ id: '603', ck: 'page', name: 'Page', typeName: 'webpage', isPage: true, text: '<p>%%=Lookup("ENT.Shared_Lookup","K","K","1")=%%</p>' }),
  );
  M.scripts.push(tag({ id: 's1', name: 'Script', ck: 's1', text: 'var de = DataExtension.Init("stage");', created: RECENT, modified: RECENT }));
  M.users.push(user('1', RECENT));
  return { M, bus: [BU, { mid: CHILD, name: 'Child', short: 'Child', parentMid: ENT, parent: 'Acme' }] };
}

describe('rule catalog', () => {
  test('every rule category maps to a domain, and IDs are unique', () => {
    assert.equal(new Set(RULES.map(r => r[0])).size, RULES.length);
    for (const r of RULES) { assert.ok(DOMAIN_OF[r[2]], r[0] + ' category ' + r[2]); assert.ok(DOMAINS.includes(DOMAIN_OF[r[2]])); assert.ok(SEVS.includes(r[4])); }
  });
  test('domain order is fixed (append only — hard rule 7)', () => {
    assert.deepEqual(DOMAINS.slice(0, 9), ['Security', 'Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages', 'Governance', 'Organization']);
  });
});

describe('dirty org', () => {
  const { ds, job, rules } = run(dirtyOrg(), { naming: DIRTY_NAMING });

  test('every rule fires exactly once', () => {
    const counts = {}; rules.forEach(r => counts[r] = (counts[r] || 0) + 1);
    for (const [id] of RULES) assert.equal(counts[id], 1, id + ' fired ' + (counts[id] || 0) + ' times');
    assert.equal(ds.findings.length, RULES.length);
    assert.equal(job.counts.findings, RULES.length);
  });

  test('findings point at the expected objects', () => {
    const by = Object.fromEntries(ds.findings.map(f => [f.rule, f]));
    assert.equal(by['DE-RET-001'].obj, 'Subscribers_NoRet');
    assert.equal(by['DE-PK-001'].obj, 'Leads_NoPK');
    assert.equal(by['DE-ORP-001'].obj, 'Old_Archive');
    assert.equal(by['SQL-001'].obj, 'Q_Star');
    assert.equal(by['SQL-007'].obj, 'Q_Deep');
    assert.equal(by['SQL-TGT-001'].obj, 'Q_Tgt');
    assert.equal(by['SQL-SRC-001'].obj, 'Q_Src');
    assert.match(by['SQL-SRC-001'].evidence[0][1], /Ghost_Table/);
    assert.doesNotMatch(by['SQL-SRC-001'].evidence[0][1], /_Sent/, 'data views are not unresolved sources');
    assert.equal(by['AUTO-FAIL-002'].obj, 'Auto_Err');
    assert.equal(by['AUTO-STL-001'].obj, 'Auto_Stale');
    assert.equal(by['AUTO-EMP-001'].obj, 'Auto_Empty');
    assert.equal(by['JRN-COR-004'].obj, 'Welcome');
    assert.deepEqual(by['JRN-COR-004'].chain, ['Auto_Err', 'Q_Feed', 'Journey_Entry', 'Welcome']);
    assert.equal(by['JRN-ENT-001'].obj, 'Winback');
    assert.equal(by['JRN-VER-002'].obj, 'Welcome');
    assert.equal(by['CP-002'].obj, 'Landing');
    assert.doesNotMatch(JSON.stringify(by['CP-002'].evidence), /abcdef1234567890xyz/, 'secret is masked');
    assert.equal(by['SEC-SCR-001'].obj, 'Script_Secret');
    assert.doesNotMatch(JSON.stringify(by['SEC-SCR-001'].evidence), /ZZZZsecretvalue123/);
    assert.equal(by['USR-INA-001'].evidence[0][1], '1 of 4');
    assert.equal(by['CNT-REF-002'].obj, 'Welcome Email');
    assert.equal(by['CNT-DE-001'].obj, 'Welcome Email');
    assert.equal(by['GOV-NAM-001'].objType, 'Data Extension');
  });

  test('finding IDs are F- + sha1(rule|objKey)[0:6] and stable across runs (hard rule 6)', () => {
    for (const f of ds.findings) assert.equal(f.id, 'F-' + crypto.createHash('sha1').update(f.rule + '|' + f.objKey).digest('hex').slice(0, 6).toUpperCase());
    const again = run(dirtyOrg(), { naming: DIRTY_NAMING }).ds.findings.map(f => f.id).sort();
    assert.deepEqual(again, ds.findings.map(f => f.id).sort());
  });

  test('findings carry the data-contract fields', () => {
    for (const f of ds.findings) {
      for (const k of ['id', 'rule', 'sev', 'domain', 'bu', 'objType', 'obj', 'objKey', 'title', 'why', 'evidence', 'affected', 'rec', 'limit']) assert.ok(f[k] !== undefined, f.rule + ' missing ' + k);
      assert.ok(DOMAINS.includes(f.domain));
      assert.ok(Array.isArray(f.evidence) && f.evidence.every(e => Array.isArray(e) && e.length === 2));
    }
  });

  test('findings are sorted by severity', () => {
    const ranks = ds.findings.map(f => SEVS.indexOf(f.sev));
    assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  });

  test('asset and virtual node keys follow TYPE:MID:id', () => {
    for (const a of ds.assets) assert.match(a.key, /^(DE|SQL|AUTO|IMP|SCR|JRN|CNT):\d+:.+/);
    for (const k of Object.keys(ds.graph.nodes)) assert.match(k, /^(DV|EML|USR|NAM):/);
    const rels = new Set(ds.graph.edges.map(e => e[2]));
    for (const r of ['WRITES', 'READS', 'CONTAINS', 'ENTRY_SOURCE', 'SENDS']) assert.ok(rels.has(r), 'edge type ' + r);
  });

  test('scores: org health and per-domain scores follow the documented formula, dom[] aligned to DOMAINS', () => {
    const P = ds.findings.reduce((n, f) => n + W[f.sev], 0);
    assert.equal(ds.summary.health, score(P, ds.assets.length));
    assert.deepEqual(ds.domains.map(d => d.name), DOMAINS);
    assert.deepEqual(ds.summary.dom, ds.domains.map(d => d.score));
    assert.deepEqual(ds.summary.sev, SEVS.map(s => ds.findings.filter(f => f.sev === s).length));
    for (const a of ds.assets) assert.ok(a.health >= 20 && a.health <= 100);
  });
});

describe('clean org', () => {
  const { M, bus } = cleanOrg();
  const { ds } = run(M, { bus });
  test('no rule fires', () => assert.deepEqual(ds.findings.map(f => f.rule + ' ' + f.obj), []));
  test('references resolve into graph edges (ENT., content blocks by key and id, DataExtension.Init, journey entry)', () => {
    const e = ds.graph.edges.map(x => x.join(' '));
    assert.ok(e.includes('DE:100:shared SQL:200:q2 READS'), 'ENT. source');
    assert.ok(e.includes('CNT:100:601 CNT:100:602 EMBEDDED_IN'));
    assert.ok(e.includes('DE:100:stage SCR:100:s1 REFERENCES'));
    assert.ok(e.includes('DE:100:subs JRN:100:welcome ENTRY_SOURCE'));
    assert.ok(e.includes('AUTO:100:a1 SQL:100:q1 CONTAINS'));
    assert.ok(e.includes('DV:_subscribers SQL:100:q1 READS'));
  });
  test('health is 100 with no findings', () => assert.equal(ds.summary.health, 100));
});

describe('analyzeParts (what the analysis worker runs)', () => {
  test('packed parts give exactly what analyze() gives on the merged model', () => {
    const { analyzeParts, packPart, emptyM } = require('../server/analyze');
    const org = () => Object.assign(dirtyOrg(), { deDone: [ENT] });   // real scans always record which BUs' DEs were collected
    const whole = run(org(), { naming: DIRTY_NAMING }).ds;
    // split the org into two parts, as two scan steps would
    const M = org(), a = emptyM(), b = emptyM();
    for (const k of Object.keys(a)) { if (Array.isArray(M[k])) { a[k] = M[k].slice(0, 1); b[k] = M[k].slice(1); } else a[k] = M[k]; }
    const cov = {}; MODULES.forEach(m => cov[m] = { ok: 1, fail: 0, notes: [] });
    const r = analyzeParts([packPart(a), null, packPart(b)], { bus: [BU], allBus: [BU], entMid: ENT, mods: new Set(MODULES), cov, naming: DIRTY_NAMING, rulesX: {}, counts: { assets: 7 } });
    assert.deepEqual(r.ds.findings.map(f => f.id).sort(), whole.findings.map(f => f.id).sort());
    assert.deepEqual(r.ds.summary, whole.summary);
    assert.ok(r.log.some(l => /Dependency graph built/.test(l)), 'log lines returned');
    assert.equal(r.counts.assets, 7, 'existing counts kept');
    assert.equal(r.counts.findings, whole.findings.length);
  });
});

describe('gating and overrides', () => {
  test('rules only run for selected modules', () => {
    const { rules } = run(dirtyOrg(), { mods: ['Data'], naming: DIRTY_NAMING });
    assert.deepEqual([...new Set(rules)].sort(), ['DE-PK-001', 'DE-RET-001'], 'no orphan verdict without the link-producing modules');
  });
  test('a disabled rule is skipped and a severity override applies', () => {
    const { ds, rules } = run(dirtyOrg(), { rulesX: { 'SQL-001': { enabled: false }, 'DE-ORP-001': { sev: 'HIGH' } } });
    assert.ok(!rules.includes('SQL-001'));
    assert.equal(ds.findings.find(f => f.rule === 'DE-ORP-001').sev, 'HIGH');
  });
  test('DE-RET-001 is not raised when retention fields were not collected', () => {
    const M = empty(); M.des.push(de({ ck: 'x', name: 'X', sendable: true, retLen: undefined, retKnown: false })); M.fields[ENT + '|x'] = fields('K*');
    assert.deepEqual(run(M).rules, []);
  });
  test('DE-PK-001 is not raised when fields were not collected', () => {
    const M = empty(); M.des.push(de({ ck: 'x', name: 'X', sendable: true }));
    assert.deepEqual(run(M).rules, []);
  });
  test('AUTO-EMP-001 needs automation detail (list-only rows are skipped)', () => {
    const M = empty(); M.autos.push(auto({ id: 'a', name: 'A', detailed: false }));
    assert.deepEqual(run(M).rules, []);
  });
  test('API users and inactive users are not counted as dormant', () => {
    const M = empty(); M.users.push(user('1', OLD, { IsAPIUser: 'true' }), user('2', OLD, { ActiveFlag: 'false' }));
    assert.deepEqual(run(M).rules, []);
  });
});

describe('no "missing" verdicts without the data to back them', () => {
  const MISSING_RULES = ['SQL-TGT-001', 'SQL-SRC-001', 'JRN-ENT-001', 'CNT-DE-001'];
  test('dirty org without the Data module raises no missing-DE findings', () => {
    const { rules } = run(dirtyOrg(), { mods: MODULES.filter(m => m !== 'Data') });
    for (const r of MISSING_RULES) assert.ok(!rules.includes(r), r);
    assert.ok(rules.includes('SQL-001'), 'other SQL rules still run');
  });
  test('a BU whose DE retrieve failed raises no missing-DE findings', () => {
    const M = dirtyOrg(); M.deDone = [];
    const { rules } = run(M);
    for (const r of MISSING_RULES) assert.ok(!rules.includes(r), r);
  });
  test('ENT. references are not "missing" when the enterprise BU was not scanned', () => {
    const M = empty(), CHILD = '200', child = { mid: CHILD, name: 'Child', short: 'Child', parentMid: ENT, parent: 'Acme' };
    M.des.push(de({ ck: 't', name: 'T', mid: CHILD, bu: 'Child' })); M.fields[CHILD + '|t'] = fields('K*');
    M.queries.push(q({ ck: 'q', name: 'Q', mid: CHILD, bu: 'Child', text: 'SELECT K FROM ENT.Shared_Lookup', targetName: 'T', targetCk: 't' }));
    M.content.push(cnt({ id: '1', ck: 'e', name: 'E', mid: CHILD, bu: 'Child', text: '%%=Lookup("ENT.Shared_Lookup","K","K","1")=%%' }));
    M.deDone = [CHILD];
    assert.deepEqual(run(M, { bus: [child] }).rules, []);
    M.deDone = [CHILD, ENT];   // enterprise DEs collected and still absent → genuinely missing
    assert.deepEqual(run(M, { bus: [child] }).rules.sort(), ['CNT-DE-001', 'SQL-SRC-001']);
  });
  test('Quick Scan modules do not mark DEs as orphaned', () => {
    const { rules, log } = run(dirtyOrg(), { mods: ['Organization', 'Security', 'Data', 'Automation'] });
    assert.ok(!rules.includes('DE-ORP-001'));
    assert.ok(log.some(m => /Orphan check \(DE-ORP-001\) skipped/.test(m)));
  });
  test('a failure in a link-producing module suppresses orphan verdicts', () => {
    const M = dirtyOrg(), cov = {}; MODULES.forEach(m => cov[m] = { ok: 1, fail: m === 'Journey' ? 1 : 0, notes: [] });
    const ds = analyze(M, { bus: [BU], allBus: [BU], entMid: ENT, mods: new Set(MODULES), cov, naming: null, rulesX: {}, L: () => { }, job: { counts: {} } });
    assert.ok(!ds.findings.some(f => f.rule === 'DE-ORP-001'));
  });
});
