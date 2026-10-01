'use strict';
// MCNexus analysis: the rule catalog, the raw-model helpers and analyze(), which turns a collected org model into
// the dataset the UI renders (findings, assets, graph, scores …). No I/O and no server state, so it also runs in the
// analysis worker (analyze-worker.js). The server imports everything it needs from here.
const crypto = require('crypto'), zlib = require('zlib');

const RULESET = '2.1';
const arr = (x) => x == null ? [] : Array.isArray(x) ? x : [x];
const dig = (o, ...k) => k.reduce((a, x) => (a && typeof a === 'object') ? a[x] : undefined, o);
const fmtD = (x) => { if (!x) return '—'; const d = new Date(x); return isNaN(d) ? '—' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); };
const ageDays = (x) => { if (!x) return Infinity; const d = new Date(x); return isNaN(d) ? Infinity : (Date.now() - d.getTime()) / 864e5; };
const hid = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 6).toUpperCase();
const plural = (n, w) => n + ' ' + (n === 1 ? w : (w.endsWith('y') ? w.slice(0, -1) + 'ies' : w + 's'));
const bool = (v) => v === true || v === 'true';

// ---------- rules ----------
const RULES = [
  ['DE-RET-001', 'Retention not configured on sendable DE', 'DATA', 'Data Extension', 'MEDIUM', '2.0'],
  ['DE-PK-001', 'Sendable DE without primary key', 'DATA', 'Data Extension', 'HIGH', '2.0'],
  ['DE-ORP-001', 'Orphaned data extension (no links, 365d unchanged)', 'GOVERNANCE', 'Data Extension', 'LOW', '2.0'],
  ['SQL-001', 'SELECT * detected', 'SQL', 'SQL Query', 'MEDIUM', '2.0'],
  ['SQL-007', 'Nested subquery depth > 3', 'SQL', 'SQL Query', 'MEDIUM', '2.0'],
  ['SQL-TGT-001', 'Query targets a missing data extension', 'SQL', 'SQL Query', 'HIGH', '2.0'],
  ['SQL-SRC-001', 'Query reads an unresolved data extension', 'SQL', 'SQL Query', 'MEDIUM', '2.0'],
  ['AUTO-FAIL-002', 'Automation in error state', 'AUTOMATION', 'Automation', 'HIGH', '2.0'],
  ['AUTO-STL-001', 'Stale automation (no run in 90 days)', 'AUTOMATION', 'Automation', 'LOW', '2.0'],
  ['AUTO-EMP-001', 'Automation without activities', 'AUTOMATION', 'Automation', 'LOW', '2.0'],
  ['JRN-COR-004', 'Running journey fed by a failing automation', 'JOURNEY', 'Journey', 'CRITICAL', '2.0'],
  ['JRN-ENT-001', 'Running journey entry source not found', 'JOURNEY', 'Journey', 'HIGH', '2.0'],
  ['JRN-VER-002', 'Stale journey versions', 'JOURNEY', 'Journey', 'MEDIUM', '2.0'],
  ['CP-002', 'Hard-coded secret in CloudPage code', 'CLOUDPAGES', 'CloudPage', 'CRITICAL', '2.0'],
  ['SEC-SCR-001', 'Hard-coded secret in script activity', 'SECURITY', 'Script', 'CRITICAL', '2.0'],
  ['USR-INA-001', 'Active users with no login in 90 days', 'SECURITY', 'User', 'MEDIUM', '2.0'],
  ['CNT-REF-002', 'Broken content block reference', 'CONTENT', 'Content', 'MEDIUM', '2.0'],
  ['CNT-DE-001', 'Content references an unresolved data extension', 'CONTENT', 'Content', 'MEDIUM', '2.0'],
  ['GOV-NAM-001', 'Naming convention violation', 'GOVERNANCE', 'Multiple', 'LOW', '2.0'],
];
const RULE = Object.fromEntries(RULES.map(r => [r[0], r]));
const DOMAIN_OF = { DATA: 'Data', SQL: 'SQL', AUTOMATION: 'Automation', JOURNEY: 'Journey', CLOUDPAGES: 'CloudPages', SECURITY: 'Security', CONTENT: 'Content', GOVERNANCE: 'Governance', ORGANIZATION: 'Organization' };
const DOMAINS = ['Security', 'Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages', 'Governance', 'Organization'];
const MODULES = ['Organization', 'Security', 'Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages', 'Governance'];
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const W = { CRITICAL: 10, HIGH: 4, MEDIUM: 1.5, LOW: 0.4, INFO: 0 };
const PEN = { CRITICAL: 45, HIGH: 25, MEDIUM: 12, LOW: 5, INFO: 0 };
const score = (pen, n) => Math.round(100 - 100 * pen / (pen + 10 + n * 1.5));

const AUTO_STATUS = { '-1': 'Error', 0: 'Building error', 1: 'Building', 2: 'Ready', 3: 'Running', 4: 'Paused', 5: 'Stopped', 6: 'Scheduled', 7: 'Awaiting trigger', 8: 'Inactive trigger' };
const ACT_TYPE = { 300: 'SQL Query', 423: 'Script', 43: 'Import', 53: 'File Transfer', 42: 'Email Send', 303: 'Filter', 73: 'Data Extract', 1101: 'Journey Entry', 467: 'Wait', 84: 'Report', 725: 'SMS', 736: 'Push', 1000: 'Verification', 749: 'Fire Event' };
const CONTENT_TYPES = ['htmlemail', 'templatebasedemail', 'textonlyemail', 'htmlblock', 'codesnippetblock', 'freeformblock', 'textblock', 'smartcaptureblock'];
const PAGE_TYPES = ['webpage', 'jscoderesource', 'jsoncoderesource', 'textcoderesource', 'rsscoderesource', 'csscoderesource', 'xmlcoderesource'];
const SECRET_RE = /(client_?secret|clientsecret|api_?key|apikey|password|passwd|access_?token|bearer)\s*["']?\s*[:=]\s*["']([^"'\s]{12,})["']/i;
const DE_FN_RE = /\b(?:Lookup|LookupRows|LookupRowsCS|LookupOrderedRows|LookupOrderedRowsCS|UpsertData|UpdateData|InsertData|DeleteData|UpsertDE|UpdateDE|InsertDE|DeleteDE|ClaimRow|ClaimRowValue|DataExtensionRowCount)\s*\(\s*\\?["']([^"'\\]+)\\?["']/gi;
const DE_INIT_RE = /DataExtension\.Init\s*\(\s*\\?["']([^"'\\]+)\\?["']/gi;
const CB_ID_RE = /ContentBlockBy(?:Id|ID)\s*\(\s*\\?["']?(\d+)/g;
const CB_KEY_RE = /ContentBlockByKey\s*\(\s*\\?["']([^"'\\]+)\\?["']/gi;

// ---------- code locations (CloudPages, content, script activities) ----------
// Asset code is kept as labelled segments — the asset's own content plus every content / superContent string under
// views (views.html, slots, blocks) — joined into one text for the reference and secret scans. segs records where
// each segment starts in that text, so a match index maps back to segment, line and column.
const CODE_MAX = 300000, LINE_MAX = 200;
function assetCode(a) {
  const parts = [], add = (label, s) => { if (typeof s === 'string' && s.trim()) parts.push([label, s]); };
  add('content', a.content);
  const walk = (o, p, d) => { if (!o || typeof o !== 'object' || d > 8) return; for (const [k, v] of Object.entries(o)) { if ((k === 'content' || k === 'superContent') && typeof v === 'string') add(k === 'content' ? p : p + '.superContent', v); else walk(v, p + '.' + k, d + 1); } };
  walk(a.views, 'views', 0);
  let text = ''; const segs = [];
  for (const [label, s] of parts) { if (text.length >= CODE_MAX) break; if (text) text += '\n'; segs.push([label, text.length]); text += s; }
  return { text: text.slice(0, CODE_MAX), segs };
}
// Segment, 1-based line and column of an index into the joined text, plus the segment's bounds.
function locate(text, segs, idx, fallback = 'code') {
  const list = segs && segs.length ? segs : [[fallback, 0]]; let where = list[0][0], start = 0, end = text.length;
  list.forEach(([label, s], i) => { if (s <= idx) { where = label; start = s; end = i + 1 < list.length ? list[i + 1][1] - 1 : text.length; } });
  const before = text.slice(start, idx);
  return { where, line: before.split('\n').length, col: idx - start - before.lastIndexOf('\n'), start, end };
}
const mask = (v) => v.slice(0, 2) + '••••••' + v.slice(-2);
const SECRET_G = () => new RegExp(SECRET_RE.source, 'gi');
const maskSecrets = (s) => s.replace(SECRET_G(), (m, name, val) => { const i = m.lastIndexOf(val); return m.slice(0, i) + mask(val) + m.slice(i + val.length); });
// Lines around a location, credential values masked (on the full line, before long lines are trimmed).
function excerpt(text, loc, ctx = 2) {
  const lines = text.slice(loc.start, loc.end).split('\n'), from = Math.max(1, loc.line - ctx), to = Math.min(lines.length, loc.line + ctx);
  const clip = (s, hit) => { if (s.length <= LINE_MAX) return s; const a = hit ? Math.max(0, loc.col - 1 - 60) : 0; return (a ? '… ' : '') + s.slice(a, a + LINE_MAX) + (a + LINE_MAX < s.length ? ' …' : ''); };
  const rows = []; for (let n = from; n <= to; n++) rows.push([n, clip(maskSecrets(lines[n - 1].replace(/\r$/, '').replace(/\t/g, '  ')), n === loc.line), n === loc.line]);
  return { where: loc.where, line: loc.line, col: loc.col, lines: rows };
}
const at = (l) => l.where + ' · line ' + l.line + ', col ' + l.col;
// Every credential-like literal (first 5 located), with a total count.
function secretHits(text, segs, fallback) {
  const re = SECRET_G(), hits = []; let m, total = 0;
  while ((m = re.exec(text))) { total++; if (hits.length < 5) hits.push({ name: m[1], masked: mask(m[2]), ...locate(text, segs, m.index, fallback) }); }
  return { hits, total };
}

function sqlSources(text) {
  const t = String(text || '').replace(/--.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  const re = /\b(?:from|join)\s+(\[[^\]]+\]|"[^"]+"|[A-Za-z0-9_.\-]+)/gi; const out = new Set(); let m;
  while ((m = re.exec(t))) { const n = m[1].replace(/^\[|\]$|^"|"$/g, '').trim(); if (n && !/^(select|\()$/i.test(n)) out.add(n); }
  return [...out];
}
function sqlDepth(text) {
  const t = String(text || '').toLowerCase(); let depth = 0, max = 0; const stack = [];
  for (let i = 0; i < t.length; i++) {
    if (t[i] === '(') { const isSel = /^\(\s*select\b/.test(t.slice(i, i + 20)); stack.push(isSel); if (isSel) { depth++; max = Math.max(max, depth); } }
    else if (t[i] === ')') { if (stack.pop()) depth--; }
  }
  return max;
}
const patternRe = (p) => new RegExp('^' + p.split(/(<[A-Z_]+>)/).map((x, i, a) => /^<[A-Z_]+>$/.test(x) ? (i === a.length - 2 ? '[A-Za-z0-9_\\-]+' : '[A-Za-z0-9]+') : x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('') + '$');

// ---------- raw model ----------
// M: what a scan collects. Steps each fill a fragment ("part"); parts are merged before analysis.
const emptyM = () => ({ des: [], fields: {}, folders: {}, queries: [], autos: [], imports: [], scripts: [], journeys: [], evs: [], content: [], users: [], deDone: [] });
const mergeM = (into, p) => { for (const k of Object.keys(into)) { if (Array.isArray(into[k])) into[k].push(...(p[k] || [])); else Object.assign(into[k], p[k] || {}); } return into; };
const packPart = (p) => zlib.gzipSync(JSON.stringify(p)).toString('base64');
const unpackPart = (s) => JSON.parse(zlib.gunzipSync(Buffer.from(s, 'base64')).toString('utf8'));
const hasData = (p) => Object.values(p).some(v => Array.isArray(v) ? v.length : Object.keys(v).length);

// Merges gzipped parts and analyses them. o = analyze() options minus L/job, plus counts. Returns the dataset,
// the log lines analyze() wrote (in order) and the updated counts — plain data, so it can cross a worker boundary.
function analyzeParts(parts, o) {
  const M = emptyM(); for (const p of parts) if (p) mergeM(M, unpackPart(p));
  const log = [], job = { counts: { ...(o.counts || {}) } };
  const ds = analyze(M, { ...o, L: (m) => log.push(m), job });
  return { ds, log, counts: job.counts };
}

function analyze(M, o) {
  const { bus, entMid, mods, cov, L, job } = o;
  const A = new Map(), edges = [], eset = new Set(), vnodes = {};
  const add = (a) => { A.set(a.key, a); return a; };
  const link = (a, b, rel) => { if (!a || !b || a === b) return; const k = a + '>' + b + '>' + rel; if (eset.has(k)) return; eset.add(k); edges.push([a, b, rel]); };
  const idx = (list, f) => { const m = {}; list.forEach(x => { const k = f(x); if (k) m[k] = m[k] || x; }); return m; };
  const deByName = idx(M.des, d => d.mid + '|' + String(d.name).toLowerCase()), deByCk = idx(M.des, d => d.mid + '|' + String(d.ck).toLowerCase()), deByOid = idx(M.des, d => String(d.objectId).toLowerCase());
  const folderPath = (mid, id) => { const out = []; let cur = id, n = 0; while (cur && M.folders[mid + '|' + cur] && n++ < 12) { const f = M.folders[mid + '|' + cur]; out.unshift(f.name); cur = f.parent; } return out.length ? '/' + out.join('/') : '—'; };
  const findDe = (mid, name) => {
    const n = String(name || '').trim(); if (!n) return null;
    const ent = /^ent\./i.test(n); const bare = n.replace(/^ent\./i, '').toLowerCase();
    return (ent ? deByName[entMid + '|' + bare] : deByName[mid + '|' + bare]) || deByCk[mid + '|' + bare] || (entMid && deByName[entMid + '|' + bare]) || null;
  };

  M.des.forEach(d => { d.key = 'DE:' + d.mid + ':' + d.ck; const f = M.fields[d.mid + '|' + d.ck]; d.fieldList = f || null; d.pk = f ? f.filter(x => x.pk).map(x => x.name) : null;
    d.hasRet = !!((d.retLen && +d.retLen > 0) || d.retainUntil && !/^0001/.test(d.retainUntil)); add({ key: d.key, name: d.name, type: 'Data Extension', raw: d }); });
  M.queries.forEach(q => { q.key = 'SQL:' + q.mid + ':' + q.ck; add({ key: q.key, name: q.name, type: 'SQL Query', raw: q }); });
  M.imports.forEach(i => { i.key = 'IMP:' + i.mid + ':' + i.id; add({ key: i.key, name: i.name, type: 'Import', raw: i }); });
  M.scripts.forEach(s => { s.key = 'SCR:' + s.mid + ':' + s.id; add({ key: s.key, name: s.name, type: 'Script', raw: s }); });
  M.autos.forEach(a => { a.key = 'AUTO:' + a.mid + ':' + a.id; add({ key: a.key, name: a.name, type: 'Automation', raw: a }); });
  M.journeys.forEach(j => { j.key = 'JRN:' + j.mid + ':' + j.key; add({ key: j.key, name: j.name, type: 'Journey', raw: j }); });
  M.content.forEach(c => { c.key = 'CNT:' + c.mid + ':' + c.id; add({ key: c.key, name: c.name, type: c.isPage ? 'CloudPage' : 'Content', raw: c }); });
  const qByOid = idx(M.queries, q => String(q.objectId).toLowerCase()), impById = idx(M.imports, i => String(i.id).toLowerCase()), scrById = idx(M.scripts, s => String(s.id).toLowerCase());
  const cById = idx(M.content, c => c.mid + '|' + c.id), cByIdAny = idx(M.content, c => c.id), cByCk = idx(M.content, c => c.mid + '|' + String(c.ck).toLowerCase()), cByLegacy = idx(M.content, c => c.legacyId ? c.mid + '|' + c.legacyId : null);
  const evByKey = idx(M.evs, e => e.mid + '|' + e.key);

  // "Missing DE" findings are only sound for BUs whose DE list was collected (ENT. names resolve in the enterprise BU).
  // Hand-built models without deDone count every scanned BU as collected when Data ran.
  const deDone = new Set(mods.has('Data') ? (M.deDone || bus.map(b => b.mid)) : []);
  const canMiss = (mid, name) => deDone.has(/^ent./i.test(String(name || '').trim()) ? entMid : mid);
  // An orphan verdict needs every module that creates DE links to have run without failures.
  const linksDone = ['SQL', 'Automation', 'Journey', 'Content', 'CloudPages'].every(m => mods.has(m) && cov[m] && !cov[m].fail);
  const F = []; const rx = o.rulesX || {};
  const finding = (rule, a, x) => {
    const r = RULE[rule]; if (!r) return; const ov = rx[rule] || {}; if (ov.enabled === false) return;
    const sev = ov.sev || x.sev || r[4];
    F.push({ id: 'F-' + hid(rule + '|' + (x.objKey || a.key)), rule, sev, domain: DOMAIN_OF[r[2]], bu: x.bu || (a.raw && a.raw.bu) || '—', objType: x.objType || a.type, obj: x.obj || a.name, objKey: x.objKey || a.key, title: x.title || r[1], impact: x.impact || (sev === 'CRITICAL' || sev === 'HIGH' ? 'HIGH' : sev === 'MEDIUM' ? 'MEDIUM' : 'LOW'), like: x.like || 'MEDIUM', conf: x.conf || 'HIGH', effort: x.effort || 'LOW', status: 'OPEN', why: x.why, evidence: x.evidence || [], affected: x.affected || '', rec: x.rec, limit: x.limit || 'None', chain: x.chain, code: x.code });
  };

  // edges: SQL
  M.queries.forEach(q => {
    const tgt = (q.targetCk && deByCk[q.mid + '|' + String(q.targetCk).toLowerCase()]) || findDe(q.mid, q.targetName);
    q.tgt = tgt; if (tgt) link(q.key, tgt.key, 'WRITES');
    q.srcs = sqlSources(q.text).map(n => {
      if (/^_/.test(n.replace(/^ent\./i, ''))) { const k = 'DV:' + n.replace(/^ent\./i, '').toLowerCase(); vnodes[k] = [n.replace(/^ent\./i, ''), 'Data View', q.bu]; link(k, q.key, 'READS'); return { n, dv: true }; }
      const d = findDe(q.mid, n); if (d) link(d.key, q.key, 'READS'); return { n, d };
    });
  });
  M.imports.forEach(i => { const d = i.destId && deByOid[String(i.destId).toLowerCase()]; i.dest = d; if (d) link(i.key, d.key, 'WRITES'); });
  M.autos.forEach(a => a.steps.forEach(s => {
    const oid = String(s.objectId || '').toLowerCase();
    const tgt = s.typeId == 300 ? qByOid[oid] : s.typeId == 43 ? impById[oid] : s.typeId == 423 ? scrById[oid] : null;
    if (tgt) link(a.key, tgt.key, 'CONTAINS');
  }));
  const deRefs = (text, mid, key, list) => { let m; const seen = new Set();
    DE_FN_RE.lastIndex = 0; while ((m = DE_FN_RE.exec(text))) { const n = m[1]; if (seen.has(n.toLowerCase())) continue; seen.add(n.toLowerCase()); const d = findDe(mid, n); if (d) link(d.key, key, 'REFERENCES'); else list.push({ n, i: m.index }); }
    DE_INIT_RE.lastIndex = 0; while ((m = DE_INIT_RE.exec(text))) { const n = m[1]; if (seen.has(n.toLowerCase())) continue; seen.add(n.toLowerCase()); const d = deByCk[mid + '|' + n.toLowerCase()] || findDe(mid, n); if (d) link(d.key, key, 'REFERENCES'); else list.push({ n, i: m.index }); } };
  M.scripts.forEach(s => { s.missing = []; deRefs(s.text, s.mid, s.key, s.missing); });
  M.content.forEach(c => {
    c.missing = []; c.brokenCb = []; deRefs(c.text, c.mid, c.key, c.missing); let m;
    CB_ID_RE.lastIndex = 0; while ((m = CB_ID_RE.exec(c.text))) { const b = cById[c.mid + '|' + m[1]] || cByIdAny[m[1]]; if (b) link(b.key, c.key, 'EMBEDDED_IN'); else if (!c.brokenCb.some(x => x.n === m[1])) c.brokenCb.push({ n: m[1], i: m.index }); }
    CB_KEY_RE.lastIndex = 0; while ((m = CB_KEY_RE.exec(c.text))) { const b = cByCk[c.mid + '|' + m[1].toLowerCase()]; if (b) link(b.key, c.key, 'EMBEDDED_IN'); else if (!c.brokenCb.some(x => x.n === m[1])) c.brokenCb.push({ n: m[1], i: m.index }); }
  });
  M.journeys.forEach(j => {
    const ev = j.evKey && evByKey[j.mid + '|' + j.evKey];
    j.entry = ev ? ((ev.deId && deByOid[String(ev.deId).toLowerCase()]) || findDe(j.mid, ev.deName)) : null; j.ev = ev;
    if (j.entry) link(j.entry.key, j.key, 'ENTRY_SOURCE');
    j.emails.forEach(e => { const c = e.emailId && cByLegacy[j.mid + '|' + e.emailId]; if (c) link(j.key, c.key, 'SENDS'); else { const k = 'EML:' + j.mid + ':' + (e.emailId || e.name); vnodes[k] = [e.name || ('Email ' + e.emailId), 'Email', j.bu]; link(j.key, k, 'SENDS'); } });
  });
  job.counts.rels = edges.length; L('Dependency graph built · ' + edges.length.toLocaleString('en-US') + ' edges');

  const out = {}, inn = {}; edges.forEach(e => { (out[e[0]] = out[e[0]] || []).push(e); (inn[e[1]] = inn[e[1]] || []).push(e); });
  const typeOf = (k) => (A.get(k) || {}).type || (vnodes[k] || [])[1] || '';
  const down = (k, max = 400) => { const seen = new Set([k]), q = [k]; while (q.length && seen.size < max) { const c = q.shift(); (out[c] || []).forEach(e => { if (!seen.has(e[1])) { seen.add(e[1]); q.push(e[1]); } }); } seen.delete(k); return [...seen]; };
  const blastTxt = (k) => { const d = down(k); if (!d.length) return 'No downstream assets'; const by = {}; d.forEach(x => { const t = typeOf(x); by[t] = (by[t] || 0) + 1; }); const parts = Object.entries(by).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([t, n]) => plural(n, t)); return parts.join(' · ') + (d.length > 3 ? ' · ' + d.length + ' downstream total' : ''); };

  // rules: data
  let rulesRun = 0;
  if (mods.has('Data')) M.des.forEach(d => {
    const a = A.get(d.key); rulesRun += linksDone ? 3 : 2;
    if (d.sendable && d.retKnown && !d.hasRet) finding('DE-RET-001', a, { why: 'Retention is not configured on a sendable data extension. Personal data accumulates indefinitely unless an external process deletes it.', evidence: [['DataRetentionPeriodLength', d.retLen || 'empty'], ['RowBasedRetention', String(d.rowRet)], ['Sendable', 'true'], ['Source', 'SOAP DataExtension retrieve']], affected: blastTxt(d.key), rec: 'Confirm the retention requirement with the data owner and configure row- or DE-level retention.', effort: 'MEDIUM' });
    if (d.sendable && d.pk && d.pk.length === 0) finding('DE-PK-001', a, { why: 'Without a primary key, imports append duplicates and sends may reach the same contact more than once.', evidence: [['Primary key', 'None'], ['Sendable', 'true'], ['Fields', String(d.fieldList.length)]], affected: blastTxt(d.key), like: 'HIGH', rec: 'Define a primary key on the subscriber identifier and de-duplicate existing rows.', limit: 'Row-level data is not read — duplicate rate not measured.' });
    if (linksDone && !(out[d.key] || []).length && !(inn[d.key] || []).length && ageDays(d.modified) > 365) finding('DE-ORP-001', a, { why: 'No query, import, journey, script or content reference was found, and the DE has not changed in over a year.', evidence: [['Modified', fmtD(d.modified)], ['Dependencies', 'None found']], affected: '1 Data Extension', like: 'LOW', conf: 'MEDIUM', rec: 'Review with the owner before archiving or deleting.', limit: 'Use by external systems via API is not observable.' });
  });
  if (mods.has('SQL')) M.queries.forEach(q => {
    const a = A.get(q.key); rulesRun += 4;
    if (/select\s+(top\s+\d+\s+)?(distinct\s+)?\*|,\s*\*\s|\.\*/i.test(q.text)) finding('SQL-001', a, { why: 'Schema changes to the source may silently change what is written to the target.', evidence: [['Statement', q.text.replace(/\s+/g, ' ').slice(0, 140)], ['Target', (q.targetName || '—') + ' · ' + (q.update || '—')]], affected: q.tgt ? blastTxt(q.tgt.key) : '1 Query', rec: 'Select the required columns explicitly.' });
    const dep = sqlDepth(q.text); if (dep > 3) finding('SQL-007', a, { why: 'Deep nesting increases the risk of hitting the 30-minute query timeout.', evidence: [['Depth', String(dep)]], rec: 'Split into staged queries writing to intermediate DEs.', effort: 'MEDIUM' });
    if (q.targetName && !q.tgt && canMiss(q.mid, q.targetName)) finding('SQL-TGT-001', a, { why: 'The target data extension could not be found in the scanned Business Units. The query will fail when it runs.', evidence: [['Target', q.targetName], ['Customer key', q.targetCk || '—']], like: 'HIGH', rec: 'Recreate the target DE or repoint the query.', limit: 'Target could live in an unscanned BU.' });
    const miss = q.srcs.filter(s => !s.d && !s.dv && canMiss(q.mid, s.n)); if (miss.length) finding('SQL-SRC-001', a, { why: 'One or more source tables could not be resolved to a data extension in the scanned BUs.', evidence: [['Unresolved', miss.map(s => s.n).slice(0, 6).join(', ')]], conf: 'MEDIUM', rec: 'Confirm the source exists; use ENT. for shared DEs.', limit: 'Sources in unscanned BUs or aliases may be reported here.' });
  });
  if (mods.has('Automation')) M.autos.forEach(a0 => {
    const a = A.get(a0.key); rulesRun += 3;
    const err = /error/i.test(a0.status) || /error/i.test(a0.lastRunStatus || '');
    a0.err = err;
    if (err) finding('AUTO-FAIL-002', a, { why: 'The automation reports an error state. Downstream data is not being refreshed.', evidence: [['Status', a0.status], ['Last run', fmtD(a0.lastRun)], ['Activities', String(a0.steps.length)], ['Source', 'REST automation API']], affected: blastTxt(a0.key), like: 'HIGH', effort: 'MEDIUM', rec: 'Open Automation Studio activity history, fix the failing step and add failure notifications.', limit: 'Run history detail is not exposed by the public API.' });
    const sched = /scheduled|ready|paused/i.test(a0.status);
    if (sched && a0.lastRun && ageDays(a0.lastRun) > 90) finding('AUTO-STL-001', a, { why: 'Scheduled or ready but no run in over 90 days.', evidence: [['Status', a0.status], ['Last run', fmtD(a0.lastRun)]], like: 'LOW', rec: 'Retire the automation or document why it is dormant.' });
    if (a0.detailed && !a0.steps.length) finding('AUTO-EMP-001', a, { why: 'The automation has no activities.', evidence: [['Steps', '0']], like: 'LOW', rec: 'Delete or complete the automation.' });
  });
  if (mods.has('Journey')) M.journeys.forEach(j => {
    const a = A.get(j.key); rulesRun += 3; const running = /published|running/i.test(j.status || '');
    if (running && j.ev && j.ev.deId && !j.entry && canMiss(j.mid, j.ev.deName)) finding('JRN-ENT-001', a, { why: 'The journey is running but its entry data extension could not be found.', evidence: [['Event definition', j.evKey], ['DE id', j.ev.deId], ['DE name', j.ev.deName || '—']], rec: 'Verify the entry source and republish.', conf: 'MEDIUM' });
    if (running && j.entry) {
      const feeders = (inn[j.entry.key] || []).filter(e => e[2] === 'WRITES').map(e => e[0]);
      for (const f of feeders) { const autos = (inn[f] || []).filter(e => e[2] === 'CONTAINS').map(e => A.get(e[0])).filter(x => x && x.raw.err);
        if (autos.length) { const au = autos[0]; finding('JRN-COR-004', a, { why: 'The entry data extension is populated by an automation that is in an error state. Contacts may enter with stale data, or not at all.', evidence: [['Automation', au.name], ['Automation status', au.raw.status], ['Feeder', (A.get(f) || {}).name || f], ['Entry DE', j.entry.name], ['Journey', j.status + ' · v' + j.version]], affected: blastTxt(j.key), like: 'HIGH', effort: 'MEDIUM', rec: 'Fix the upstream automation before the next entry window; consider pausing entry on failure.', chain: [au.name, (A.get(f) || {}).name, j.entry.name, j.name] }); break; } }
    }
    const stale = j.versions.filter(v => v.v !== j.version && /stopped|draft|unpublished/i.test(v.status || '') && ageDays(v.modified) > 180);
    if (stale.length >= 3) finding('JRN-VER-002', a, { why: stale.length + ' old versions are stopped or draft and unmodified for 180+ days.', evidence: [['Versions', String(j.versions.length)], ['Stale', String(stale.length)]], rec: 'Review and retire unused versions.' });
  });
  // Code findings say where: a Location evidence row per occurrence and code excerpts (secrets masked) in f.code.
  const secretEvidence = (r) => [['Pattern', r.hits[0].name + ' = "' + r.hits[0].masked + '"'], ['Occurrences', String(r.total)], ...r.hits.map(h => ['Location', at(h)])];
  const refEvidence = (text, segs, refs) => refs.slice(0, 5).map(r => ({ r, l: locate(text, segs, r.i) }));
  if (mods.has('CloudPages')) M.content.filter(c => c.isPage).forEach(c => { rulesRun++; const r = secretHits(c.text, c.segs); if (r.total) finding('CP-002', A.get(c.key), { why: 'A credential-like value is embedded in page code. Anyone with Content Builder access can read it.', evidence: [...secretEvidence(r), ['Source', 'Static analysis — code not executed']], code: r.hits.map(h => excerpt(c.text, h)), like: 'MEDIUM', conf: 'MEDIUM', rec: 'Rotate the credential and move it server-side (e.g. encrypted DE or key management).' }); });
  if (mods.has('Security') || mods.has('Automation')) M.scripts.forEach(s => { rulesRun++; const r = secretHits(s.text, null, 'script'); if (r.total) finding('SEC-SCR-001', A.get(s.key), { why: 'A credential-like value is embedded in an SSJS script activity.', evidence: secretEvidence(r), code: r.hits.map(h => excerpt(s.text, h)), conf: 'MEDIUM', rec: 'Rotate the credential and load it from a protected store.' }); });
  if (mods.has('Content')) M.content.forEach(c => { rulesRun += 2; const a = A.get(c.key);
    if (c.brokenCb.length) { const ls = refEvidence(c.text, c.segs, c.brokenCb); finding('CNT-REF-002', a, { why: 'The asset references content blocks that could not be found.', evidence: [['References', c.brokenCb.slice(0, 5).map(x => x.n).join(', ')], ...ls.map(({ r, l }) => ['Location', r.n + ' — ' + at(l)])], code: ls.map(({ l }) => excerpt(c.text, l)), conf: 'MEDIUM', rec: 'Replace or remove the reference.', limit: 'Shared/other-BU content may not be visible to this package.' }); }
    const cMiss = c.missing.filter(x => canMiss(c.mid, x.n)); if (cMiss.length) { const ls = refEvidence(c.text, c.segs, cMiss); finding('CNT-DE-001', a, { why: 'AMPscript/SSJS references a data extension that could not be resolved.', evidence: [['Unresolved', cMiss.slice(0, 5).map(x => x.n).join(', ')], ...ls.map(({ r, l }) => ['Location', r.n + ' — ' + at(l)])], code: ls.map(({ l }) => excerpt(c.text, l)), conf: 'MEDIUM', rec: 'Confirm the DE name; use ENT. for shared DEs.', limit: 'Names built dynamically are not resolved.' }); } });
  if (mods.has('Security') && M.users.length) {
    rulesRun++;
    const ina = M.users.filter(u => bool(u.ActiveFlag) && !bool(u.IsAPIUser) && ageDays(u.LastSuccessfulLogin) > 90);
    if (ina.length) { const key = 'USR:' + (entMid || 'ent'); vnodes[key] = [plural(ina.length, 'user'), 'User', (bus[0] || {}).name];
      finding('USR-INA-001', { key, name: plural(ina.length, 'user'), type: 'User' }, { bu: (bus.find(b => b.mid === entMid) || bus[0] || {}).name, why: plural(ina.length, 'active user') + ' have not logged in for 90+ days.', evidence: [['Users', ina.length + ' of ' + M.users.length], ['Examples', ina.slice(0, 5).map(u => u.UserID || u.Name).join(', ')]], conf: 'MEDIUM', rec: 'Deactivate or review dormant accounts; confirm roles.', limit: 'Role assignments are not retrieved.' }); }
  }
  if (mods.has('Governance') && Array.isArray(o.naming) && o.naming.length) {
    const pats = Object.fromEntries(o.naming.filter(p => p[1]).map(([t, p]) => [t, patternRe(p)]));
    const map = { 'Data Extension': 'Data Extension', 'Automation': 'Automation', 'SQL Query': 'SQL Query', 'Journey': 'Journey', 'Content': 'Email', 'CloudPage': 'CloudPage' };
    bus.forEach(b => Object.entries(map).forEach(([type, pt]) => { const re = pats[pt]; if (!re) return;
      const list = [...A.values()].filter(a => a.type === type && a.raw.mid === b.mid && (type !== 'Content' || /email/.test(a.raw.typeName)));
      const bad = list.filter(a => !re.test(a.name)); rulesRun += list.length;
      if (bad.length) { const key = 'NAM:' + b.mid + ':' + type; vnodes[key] = [bad.length + ' ' + type + ' names', 'Multiple', b.name];
        finding('GOV-NAM-001', { key, name: bad.length + ' ' + type + ' names', type: 'Multiple' }, { bu: b.name, objType: type, why: bad.length + ' of ' + list.length + ' ' + type + ' assets do not match the configured pattern.', evidence: [['Pattern', o.naming.find(n => n[0] === pt)[1]], ['Examples', bad.slice(0, 5).map(a => a.name).join(', ')]], affected: plural(bad.length, 'asset'), like: 'HIGH', effort: 'MEDIUM', rec: 'Rename on next change; enforce in the build checklist.' }); }
    }));
  }
  if (mods.has('Data') && !linksDone) L('Orphan check (DE-ORP-001) skipped — needs SQL, Automation, Journey, Content and CloudPages fully collected');
  job.counts.rules = rulesRun; job.counts.findings = F.length;
  L('Executed ' + RULES.filter(r => !(rx[r[0]] && rx[r[0]].enabled === false)).length + ' rules · ' + rulesRun.toLocaleString('en-US') + ' evaluations · ' + plural(F.length, 'finding'));

  // scoring
  const fBy = {}; F.forEach(f => (fBy[f.objKey] = fBy[f.objKey] || []).push(f));
  const rank = (s) => SEVS.indexOf(s);
  const assetHealth = (k) => Math.max(20, 100 - (fBy[k] || []).reduce((n, f) => n + PEN[f.sev], 0));
  const sevCount = (list) => SEVS.map(s => list.filter(f => f.sev === s).length);
  const pen = (list) => list.reduce((n, f) => n + W[f.sev], 0);
  const assetsArr = [...A.values()];
  const covPct = (m) => { const c = cov[m]; if (!mods.has(m)) return 0; const t = c.ok + c.fail; return t ? Math.round(100 * c.ok / t) : 100; };
  const domPop = { Security: M.users.length + M.scripts.length, Data: M.des.length, SQL: M.queries.length, Automation: M.autos.length, Journey: M.journeys.length, Content: M.content.filter(c => !c.isPage).length, CloudPages: M.content.filter(c => c.isPage).length, Governance: assetsArr.length, Organization: bus.length };
  const domCov = { Security: covPct('Security'), Data: covPct('Data'), SQL: covPct('SQL'), Automation: covPct('Automation'), Journey: covPct('Journey'), Content: covPct('Content'), CloudPages: covPct('CloudPages'), Governance: mods.has('Governance') ? 100 : 0, Organization: covPct('Organization') };
  const domains = DOMAINS.map(d => { const list = F.filter(f => f.domain === d); return { name: d, score: score(pen(list), domPop[d]), cov: domCov[d], crit: list.filter(f => f.sev === 'CRITICAL').length, high: list.filter(f => f.sev === 'HIGH').length, f: d }; });
  const ranMods = MODULES.filter(m => mods.has(m));
  const coverage = ranMods.length ? Math.round(ranMods.reduce((n, m) => n + covPct(m), 0) / ranMods.length) : 0;
  const health = score(pen(F), assetsArr.length);

  const BUS = bus.map(b => { const list = F.filter(f => f.bu === b.name); const my = assetsArr.filter(a => a.raw.mid === b.mid);
    return { name: b.name, short: b.name, mid: b.mid, parent: b.parent, health: score(pen(list), my.length), findings: list.length, des: my.filter(a => a.type === 'Data Extension').length, autos: my.filter(a => a.type === 'Automation').length, jrns: my.filter(a => a.type === 'Journey').length, users: M.users.filter(u => String(dig(u, 'Client', 'ID')) === b.mid).length, pkgs: '—', tz: '—', locale: '—' }; });

  const cnt = (k) => (out[k] || []).length + (inn[k] || []).length;
  const rels = (list, dir) => list.slice(0, 60).map(e => { const k = dir === 'in' ? e[0] : e[1]; const x = A.get(k); return [x ? x.name : (vnodes[k] || [k])[0], x ? x.type : (vnodes[k] || [])[1] || '', e[2], k]; });
  const usage = (k) => { const by = {}; (out[k] || []).forEach(e => { const t = typeOf(e[1]); by[t] = (by[t] || 0) + 1; }); const s = Object.entries(by).map(([t, n]) => plural(n, t)).join(' · '); return s || 'No known dependents'; };
  const assets = assetsArr.map(a => {
    const r = a.raw; let config = [], status = '';
    if (a.type === 'Data Extension') { status = r.sendable ? 'Sendable' : 'Standard'; config = [['Customer Key', r.ck], ['Folder', folderPath(r.mid, r.categoryId)], ['Sendable', r.sendable ? 'Yes' + (r.sendField ? ' · ' + r.sendField + ' → ' + (r.subField || 'Subscriber Key') : '') : 'No'], ['Primary key', r.pk ? (r.pk.length ? r.pk.join(', ') : 'None') : 'Not collected'], ['Retention', r.hasRet ? (r.retLen ? r.retLen + ' ' + (r.retPeriod || '') + (r.rowRet ? ' · rows' : ' · all') : 'Until ' + fmtD(r.retainUntil)) : (r.retKnown ? 'Not configured' : 'Not collected')], ['Fields', r.fieldList ? String(r.fieldList.length) : '—'], ['Created', fmtD(r.created)]]; }
    else if (a.type === 'SQL Query') { status = r.update || 'Query'; config = [['Customer Key', r.ck], ['Target', r.targetName || '—'], ['Update type', r.update || '—'], ['Sources', r.srcs.map(s => s.n).join(', ') || '—'], ['Statement', r.text.replace(/\s+/g, ' ').slice(0, 220)], ['Created', fmtD(r.created)]]; }
    else if (a.type === 'Automation') { status = r.status; const types = {}; r.steps.forEach(s => { const t = ACT_TYPE[s.typeId] || ('Type ' + s.typeId); types[t] = (types[t] || 0) + 1; }); config = [['Key', r.key || '—'], ['Status', r.status], ['Schedule', r.schedule ? (r.schedule.icalRecur || r.schedule.scheduleStatus || 'Configured') : 'None'], ['Activities', r.steps.length + (r.steps.length ? ' (' + Object.entries(types).map(([t, n]) => n + ' ' + t).join(', ') + ')' : '')], ['Last run', r.lastRun ? fmtD(r.lastRun) + (r.lastRunStatus ? ' · ' + r.lastRunStatus : '') : '—']]; }
    else if (a.type === 'Journey') { status = (r.status || '—') + ' · v' + r.version; config = [['Key', r.key.split(':').pop()], ['Status', r.status || '—'], ['Entry source', r.entry ? 'Data Extension · ' + r.entry.name : (r.ev ? (r.ev.type || 'Event') + ' · ' + (r.ev.deName || r.evKey) : (r.entryMode || '—'))], ['Activities', String(r.acts)], ['Emails', String(r.emails.length)], ['Goal', r.goal ? 'Configured' : 'Not configured'], ['Versions', String(r.versions.length)]]; }
    else if (a.type === 'Content' || a.type === 'CloudPage') { status = r.typeName + (r.status ? ' · ' + r.status : ''); config = [['Asset type', r.typeName], ['Customer Key', r.ck || '—'], ['Folder', r.folder || '—'], ['Asset ID', r.id], ['Created', fmtD(r.created)]]; }
    else if (a.type === 'Import') { status = 'Import'; config = [['Customer Key', r.ck || '—'], ['Destination', r.dest ? r.dest.name : (r.destName || '—')]]; }
    else if (a.type === 'Script') { status = 'SSJS'; config = [['Key', r.ck || '—'], ['Length', r.text.length.toLocaleString('en-US') + ' chars']]; }
    const hist = [[fmtD(r.modified), 'Modified'], [fmtD(r.created), 'Created']].filter(h => h[0] !== '—');
    return { key: a.key, name: a.name, type: a.type, bu: r.bu, health: assetHealth(a.key), modified: fmtD(r.modified), status, config, usage: usage(a.key), deps: rels(inn[a.key] || [], 'in'), dependents: rels(out[a.key] || [], 'out'), history: hist, degree: cnt(a.key) };
  });
  const TYPES = ['Data Extension', 'SQL Query', 'Automation', 'Journey', 'Content', 'CloudPage', 'Import', 'Script'];
  const typeCounts = TYPES.map(t => [t, assets.filter(a => a.type === t).length]).filter(([t, n]) => n > 0 || ['Data Extension', 'Automation', 'Journey', 'Content', 'CloudPage'].includes(t));

  // data model (sendable DEs most connected)
  const sendables = M.des.filter(d => d.sendable).sort((a, b) => cnt(b.key) - cnt(a.key)).slice(0, 8);
  const pos = [[290, 20], [290, 185], [290, 350], [590, 20], [590, 185], [590, 350], [880, 20], [880, 185], [880, 350]];
  const mNodes = [{ id: 'contact', name: 'Contact', sub: 'Contact Builder root', x: 30, y: 185, fields: ['Contact Key (PK)', 'Contact ID'], root: true }];
  const mEdges = [];
  sendables.forEach((d, i) => { const f = (d.fieldList || []).slice().sort((a, b) => b.pk - a.pk).slice(0, 4).map(x => x.name + (x.pk ? ' (PK)' : '')); const risk = (fBy[d.key] || []).map(x => x.sev).sort((a, b) => rank(a) - rank(b))[0];
    mNodes.push({ id: 'm' + i, key: d.key, name: d.name, sub: d.bu + ' · ' + (d.fieldList ? d.fieldList.length + ' fields · ' : '') + 'sendable', x: pos[i][0], y: pos[i][1], fields: f.length ? f : ['Fields not collected'], risk }); mEdges.push(['contact', 'm' + i, '1 : 1', 'Contact Key = ' + (d.sendField || 'SubscriberKey')]); });
  for (let i = 0; i < sendables.length; i++) for (let j = 0; j < sendables.length; j++) { if (i === j || mEdges.length > 16) continue; const a = sendables[i], b = sendables[j]; const pk = (a.pk || [])[0]; if (!pk || !b.fieldList) continue; const bf = b.fieldList.find(x => x.name.toLowerCase() === pk.toLowerCase()); if (bf && !bf.pk) mEdges.push(['m' + i, 'm' + j, '1 : N', pk]); }

  const sev = sevCount(F);
  const inventory = [['Business Units', bus.length], ['Data Extensions', M.des.length], ['SQL Queries', M.queries.length], ['Automations', M.autos.length], ['Journeys', M.journeys.length], ['Content assets', M.content.filter(c => !c.isPage).length], ['CloudPages', M.content.filter(c => c.isPage).length], ['Users', M.users.length]];
  const limits = MODULES.filter(m => mods.has(m) && covPct(m) < 100).map(m => [m, covPct(m) + '%', cov[m].notes[0] || 'Some calls failed']);
  limits.push(['Installed packages', 'Manual', 'No public API lists installed packages']); limits.push(['Tracking', 'Excluded', 'Send/open tracking not collected in this version']);
  const hubs = M.des.map(d => ({ d, n: down(d.key).length, j: down(d.key).filter(k => typeOf(k) === 'Journey').length })).sort((a, b) => b.n - a.n);
  const archNotes = [];
  if (hubs[0] && hubs[0].n > 0) archNotes.push(['Single point of dependency', hubs[0].d.name + ' (' + hubs[0].d.bu + ') feeds ' + plural(hubs[0].n, 'downstream asset') + (hubs[0].j ? ' including ' + plural(hubs[0].j, 'journey') : '') + '.']);
  const errAutos = M.autos.filter(a => a.err); if (errAutos.length) archNotes.push(['Failing automations', plural(errAutos.length, 'automation') + ' in error state, affecting ' + errAutos.reduce((n, a) => n + down(a.key).length, 0) + ' downstream assets.']);
  const entRefs = edges.filter(e => { const a = A.get(e[0]), b = A.get(e[1]); return a && b && a.raw.mid !== b.raw.mid; }).length; if (entRefs) archNotes.push(['Cross-BU dependencies', plural(entRefs, 'relationship') + ' cross Business Unit boundaries (shared DEs / ENT.).']);
  const orph = F.filter(f => f.rule === 'DE-ORP-001').length; if (archNotes.length < 3 && orph) archNotes.push(['Unused data', plural(orph, 'orphaned data extension') + ' with no known dependency.']);
  if (!archNotes.length) archNotes.push(['No structural hotspots', 'No asset has more than a handful of dependents in the scanned scope.']);
  const qw = [[F.filter(f => f.rule === 'DE-RET-001').length, 'Retention reviews on sendable DEs'], [orph, 'Orphaned DEs to review'], [F.filter(f => f.rule === 'AUTO-STL-001').length, 'Stale automations to retire'], [F.filter(f => f.rule === 'SQL-001').length, 'SELECT * queries to tighten'], [F.filter(f => f.rule === 'JRN-VER-002').length, 'Journeys with stale versions']].filter(x => x[0] > 0).slice(0, 4).map(([n, l]) => [String(n), l]);
  const clean = assets.length ? Math.round(100 * assets.filter(a => !fBy[a.key]).length / assets.length) : 100;

  F.sort((a, b) => rank(a.sev) - rank(b.sev) || a.rule.localeCompare(b.rule) || a.obj.localeCompare(b.obj));
  const gnodes = {}; Object.entries(vnodes).forEach(([k, v]) => { gnodes[k] = v; });
  return {
    summary: { health, cov: coverage, sev, rules: 'v' + RULESET, assets: assets.length, dom: domains.map(d => d.score), bus: bus.length, clean, rels: edges.length },
    bus: BUS, domains, findings: F, assets, graph: { nodes: gnodes, edges }, typeCounts, model: { nodes: mNodes, edges: mEdges }, modules: MODULES.map(m => [m, mods.has(m) ? covPct(m) : 100]),
    inventory, limits, archNotes, quickWins: qw, clean,
  };
}

module.exports = { assetCode, locate, excerpt, maskSecrets, secretHits, RULESET, arr, dig, fmtD, ageDays, hid, plural, bool, RULES, RULE, DOMAIN_OF, DOMAINS, MODULES, SEVS, W, PEN, score, AUTO_STATUS, ACT_TYPE, CONTENT_TYPES, PAGE_TYPES, SECRET_RE, sqlSources, sqlDepth, patternRe, analyze, analyzeParts, emptyM, mergeM, packPart, unpackPart, hasData };
