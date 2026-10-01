#!/usr/bin/env node
// MCNexus server — zero-dependency (Node 18+). Serves the app and proxies read-only SFMC API calls.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');

const PORT = +process.env.PORT || 8787, HOST = process.env.HOST || '127.0.0.1';
const ROOT = path.resolve(__dirname, '..'), DATA = process.env.MCNEXUS_DATA || path.join(__dirname, 'data');
const RULESET = '2.1', VERSION = '1.0.0';
const ENV_LIM = { maxPages: +process.env.MCNEXUS_MAX_PAGES || 40, maxDetail: +process.env.MCNEXUS_MAX_DETAIL || 400, concurrency: +process.env.MCNEXUS_CONCURRENCY || 6 };
let MAX_PAGES = ENV_LIM.maxPages, MAX_DETAIL = ENV_LIM.maxDetail, CONCURRENCY = ENV_LIM.concurrency; // overridden by Settings → Scan defaults
const STARTED = Date.now();
const SESSION_IDLE = 8 * 3600e3;
fs.mkdirSync(path.join(DATA, 'scans'), { recursive: true });

// ---------- crypto / store ----------
const KEY = (() => {
  if (process.env.MCNEXUS_KEY) return Buffer.from(process.env.MCNEXUS_KEY, 'hex');
  const f = path.join(DATA, '.key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
})();
const enc = (t) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv); const d = Buffer.concat([c.update(String(t), 'utf8'), c.final()]); return [iv, c.getAuthTag(), d].map(b => b.toString('base64')).join('.'); };
const dec = (s) => { const [iv, tag, d] = s.split('.').map(x => Buffer.from(x, 'base64')); const c = crypto.createDecipheriv('aes-256-gcm', KEY, iv); c.setAuthTag(tag); return Buffer.concat([c.update(d), c.final()]).toString('utf8'); };
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');

const STORE = path.join(DATA, 'store.json');
let db = fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, 'utf8')) : {};
db = { users: [], connections: [], scans: {}, triage: {}, settings: { rulesX: {}, naming: null }, ...db };
db.settings = { rulesX: {}, naming: null, ...db.settings };
db.settings.scan = { mode: 'Full Assessment', modules: null, maxPages: ENV_LIM.maxPages, maxDetail: ENV_LIM.maxDetail, concurrency: ENV_LIM.concurrency, ...(db.settings.scan || {}) };
db.settings.report = { firm: '', disclaimer: '', format: 'PDF', logo: '', ...(db.settings.report || {}) };
db.settings.data = { keepScans: 0, ...(db.settings.data || {}) };
const clampN = (v, lo, hi, d) => { const n = parseInt(v, 10); return isNaN(n) ? d : Math.min(hi, Math.max(lo, n)); };
function applyLimits() { const sc = db.settings.scan; sc.maxPages = clampN(sc.maxPages, 1, 500, 40); sc.maxDetail = clampN(sc.maxDetail, 10, 5000, 400); sc.concurrency = clampN(sc.concurrency, 1, 12, 6); MAX_PAGES = sc.maxPages; MAX_DETAIL = sc.maxDetail; CONCURRENCY = sc.concurrency; }
applyLimits();
function prune(cid) { const keep = +db.settings.data.keepScans || 0; const list = db.scans[cid] || []; let n = 0; while (keep > 0 && list.length > keep) { const o = list.shift(); n++; try { fs.unlinkSync(scanPath(cid, o.n)); } catch { } } return n; }
const save = () => { const tmp = STORE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db, null, 1), { mode: 0o600 }); fs.renameSync(tmp, STORE); };
const scanPath = (cid, n) => path.join(DATA, 'scans', cid, n + '.json');
const loadScan = (cid, n) => { try { return JSON.parse(fs.readFileSync(scanPath(cid, n), 'utf8')); } catch { return null; } };

// ---------- utils ----------
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const arr = (x) => x == null ? [] : Array.isArray(x) ? x : [x];
const dig = (o, ...k) => k.reduce((a, x) => (a && typeof a === 'object') ? a[x] : undefined, o);
const fmtD = (x) => { if (!x) return '—'; const d = new Date(x); return isNaN(d) ? '—' : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); };
const ageDays = (x) => { if (!x) return Infinity; const d = new Date(x); return isNaN(d) ? Infinity : (Date.now() - d.getTime()) / 864e5; };
const xesc = (s) => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
const hid = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 6).toUpperCase();
const plural = (n, w) => n + ' ' + (n === 1 ? w : (w.endsWith('y') ? w.slice(0, -1) + 'ies' : w + 's'));
async function pMap(items, n, fn) { const out = new Array(items.length); let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } })); return out; }
const bool = (v) => v === true || v === 'true';

function decodeEnt(s) { return s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-f]+);/gi, (m, e) => ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[e.toLowerCase()] || (e[1] && e[1].toLowerCase() === 'x' ? String.fromCodePoint(parseInt(e.slice(2), 16)) : String.fromCodePoint(+e.slice(1))))); }
function xmlObj(xml) {
  const root = { children: [], text: '' }, stack = [root];
  const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w:.-]*)([^>]*?)(\/?)>|<[?!][^>]*>|([^<]+)/g; let m;
  while ((m = re.exec(xml))) {
    const top = stack[stack.length - 1];
    if (m[1] != null) top.text += m[1];
    else if (m[6] != null) top.text += decodeEnt(m[6]);
    else if (m[3]) {
      if (m[2]) { if (stack.length > 1) stack.pop(); }
      else { const node = { name: m[3].split(':').pop(), children: [], text: '' }; top.children.push(node); if (!m[5]) stack.push(node); }
    }
  }
  const conv = (n) => { if (!n.children.length) return n.text.trim(); const o = {}; n.children.forEach(c => { const v = conv(c); if (o[c.name] !== undefined) { if (!Array.isArray(o[c.name])) o[c.name] = [o[c.name]]; o[c.name].push(v); } else o[c.name] = v; }); return o; };
  return conv(root);
}

// ---------- SFMC client ----------
class ApiErr extends Error { constructor(m, status, code) { super(m); this.status = status; this.code = code; } }
class SFMC {
  constructor({ sub, cid, sec }) { Object.assign(this, { sub, cid, sec, tokens: {}, calls: 0 }); }
  async token(mid) {
    const k = mid || '_', t = this.tokens[k];
    if (t && t.exp > Date.now() + 60e3) return t;
    const body = { grant_type: 'client_credentials', client_id: this.cid, client_secret: this.sec };
    if (mid) body.account_id = String(mid);
    let r; this.calls++;
    try { r = await fetch(`https://${this.sub}.auth.marketingcloudapis.com/v2/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); }
    catch (e) { throw new ApiErr('Cannot reach auth endpoint (' + ((e.cause && e.cause.code) || e.message) + ')', 0, 'network'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiErr((j.error || 'HTTP ' + r.status) + (j.error_description ? ' — ' + j.error_description : ''), r.status, j.error || 'auth');
    const nt = { access: j.access_token, exp: Date.now() + (j.expires_in || 1080) * 1000, ttl: j.expires_in, rest: String(j.rest_instance_url || '').replace(/\/$/, ''), soap: String(j.soap_instance_url || '').replace(/\/$/, ''), scope: j.scope || '' };
    this.tokens[k] = nt; return nt;
  }
  async req(url, opt, parse) {
    for (let i = 0; ; i++) {
      this.calls++; let r;
      try { r = await fetch(url, opt); } catch (e) { if (i < 2) { await sleep(800 * (i + 1)); continue; } throw new ApiErr('Network error: ' + e.message, 0, 'network'); }
      if ((r.status === 429 || r.status >= 500) && i < 3) { const ra = +r.headers.get('retry-after'); await sleep(ra ? ra * 1000 : 1000 * 2 ** i); continue; }
      const txt = await r.text();
      if (!r.ok) {
        let m = 'HTTP ' + r.status;
        try { const j = JSON.parse(txt); const d = j.message || j.error_description || j.error || (j.errors && j.errors[0] && (j.errors[0].message || j.errors[0].errorMessage)); if (d) m += ' — ' + d; }
        catch { const f = txt.match(/<faultstring[^>]*>([^<]+)/); if (f) m += ' — ' + f[1]; }
        throw new ApiErr(m, r.status);
      }
      return parse(txt);
    }
  }
  async rest(mid, method, p, body) {
    const t = await this.token(mid);
    return this.req(t.rest + p, { method, headers: { authorization: 'Bearer ' + t.access, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }, (x) => x ? JSON.parse(x) : {});
  }
  // Results cut off by the page cap come back with out.truncated = true; callers report that as partial coverage.
  async restPages(mid, p, { size = 200, sizeParam = '$pagesize', key = 'items', max = MAX_PAGES } = {}) {
    const out = [];
    for (let page = 1; ; page++) {
      if (page > max) { out.truncated = true; break; }
      const j = await this.rest(mid, 'GET', `${p}${p.includes('?') ? '&' : '?'}$page=${page}&${sizeParam}=${size}`);
      const items = j[key] || []; out.push(...items);
      const total = j.count != null ? j.count : j.totalCount;
      // SFMC may cap the page size below `size`, so a short page only means "last page" when no total is given.
      if (!items.length || (total != null ? out.length >= total : items.length < size)) break;
    }
    return out;
  }
  async soap(mid, action, bodyXml) {
    const t = await this.token(mid);
    const env = `<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><s:Header><a:Action s:mustUnderstand="1">${action}</a:Action><a:To s:mustUnderstand="1">${t.soap}/Service.asmx</a:To><fueloauth xmlns="http://exacttarget.com">${t.access}</fueloauth></s:Header><s:Body>${bodyXml}</s:Body></s:Envelope>`;
    return this.req(t.soap + '/Service.asmx', { method: 'POST', headers: { 'content-type': 'text/xml; charset=utf-8', soapaction: action }, body: env }, xmlObj);
  }
  async retrieve(mid, type, props, { filter = '', all = false, max = MAX_PAGES } = {}) {
    const out = []; let reqId = null;
    for (let page = 0; ; page++) {
      if (page >= max) { out.truncated = true; break; }
      const inner = `<ObjectType>${type}</ObjectType>${props.map(p => `<Properties>${p}</Properties>`).join('')}${filter}${reqId ? `<ContinueRequest>${reqId}</ContinueRequest>` : ''}${all ? '<QueryAllAccounts>true</QueryAllAccounts>' : ''}`;
      const o = await this.soap(mid, 'Retrieve', `<RetrieveRequestMsg xmlns="http://exacttarget.com/wsdl/partnerAPI"><RetrieveRequest>${inner}</RetrieveRequest></RetrieveRequestMsg>`);
      const m = dig(o, 'Envelope', 'Body', 'RetrieveResponseMsg') || {};
      const st = String(m.OverallStatus || '');
      if (/^Error/i.test(st)) throw new ApiErr('SOAP ' + type + ': ' + st.slice(0, 240), 200, 'soap');
      out.push(...arr(m.Results));
      if (st !== 'MoreDataAvailable' || !m.RequestID) break;
      reqId = m.RequestID;
    }
    return out;
  }
  // tries full property list, falls back to a minimal one if SFMC rejects a property
  async retrieveSafe(mid, type, props, minimal, opt) {
    try { return await this.retrieve(mid, type, props, opt); }
    catch (e) { if (minimal && e.code === 'soap') return this.retrieve(mid, type, minimal, opt); throw e; }
  }
}
const eqFilter = (prop, val) => `<Filter xsi:type="SimpleFilterPart"><Property>${prop}</Property><SimpleOperator>equals</SimpleOperator><Value>${xesc(val)}</Value></Filter>`;

// ---------- discovery / access ----------
async function discoverBus(api, mid) {
  const ctx = await api.rest(mid, 'GET', '/platform/v1/tokenContext').catch(() => null);
  const entId = ctx && ctx.enterprise && ctx.enterprise.id ? String(ctx.enterprise.id) : null;
  let rows = [], err = null;
  try { rows = await api.retrieve(mid, 'BusinessUnit', ['ID', 'Name', 'ParentID'], { all: true }); } catch (e) { err = e; }
  const truncated = !!rows.truncated;
  let bus = rows.map(r => ({ mid: String(r.ID), name: r.Name || ('Business Unit ' + r.ID), parentMid: r.ParentID && r.ParentID !== '0' && String(r.ParentID) !== String(r.ID) ? String(r.ParentID) : null }));
  const seen = new Set(); bus = bus.filter(b => !seen.has(b.mid) && seen.add(b.mid));
  if (entId && !bus.find(b => b.mid === entId)) bus.unshift({ mid: entId, name: 'Enterprise ' + entId, parentMid: null });
  if (!bus.length) { const id = (ctx && ctx.organization && String(ctx.organization.id)) || mid || 'unknown'; bus = [{ mid: id, name: 'Business Unit ' + id, parentMid: null }]; }
  bus.forEach(b => { if (entId && b.mid === entId) b.parentMid = null; });
  bus.sort((a, b) => (a.parentMid ? 1 : 0) - (b.parentMid ? 1 : 0) || a.name.localeCompare(b.name));
  const byMid = Object.fromEntries(bus.map(b => [b.mid, b]));
  return { ctx, entId, err, truncated, bus: bus.map(b => ({ mid: b.mid, name: b.name, short: b.name, parentMid: b.parentMid, parent: b.parentMid ? (byMid[b.parentMid] ? byMid[b.parentMid].name : b.parentMid) : '—' })) };
}
const scopeList = (s) => String(s || '').split(/\s+/).filter(Boolean);

async function testConnection({ sub, cid, sec, mid }) {
  const api = new SFMC({ sub, cid, sec }), steps = []; let bus = [], scopes = [], entId = null;
  const url = `https://${sub}.auth.marketingcloudapis.com/v2/token`;
  let t;
  try { t = await api.token(mid || null); steps.push({ ok: true, note: url }, { ok: true, note: 'Token issued · expires in ' + (t.ttl || '?') + ' s' }); }
  catch (e) { if (e.code === 'network') steps.push({ ok: false, note: e.message }); else steps.push({ ok: true, note: url }, { ok: false, note: e.message }); return { ok: false, steps, bus, scopes }; }
  scopes = scopeList(t.scope); const writes = scopes.filter(s => /_(write|send|execute|publish)$/.test(s)).length;
  steps.push({ ok: scopes.length > 0, note: scopes.length + ' scopes · ' + writes + ' write/execute' + (writes ? ' (read-only is enough for MCNexus)' : '') });
  const d = await discoverBus(api, mid || null); entId = d.entId; bus = d.bus;
  steps.push({ ok: !!(d.ctx), note: d.ctx ? ('Enterprise MID ' + (entId || '?') + ' · context MID ' + (d.ctx.organization && d.ctx.organization.id)) : 'tokenContext unavailable' });
  steps.push({ ok: !d.err, note: d.err ? ('BU discovery limited — ' + d.err.message) : plural(bus.length, 'Business Unit') + ' found' });
  let rs = 'REST ✓', ss = 'SOAP ✓', ok = true;
  try { await api.rest(mid || null, 'GET', '/platform/v1/tokenContext'); } catch (e) { rs = 'REST ✗ ' + e.message; ok = false; }
  try { await api.retrieve(mid || null, 'DataExtension', ['Name'], { filter: eqFilter('Name', '__mcnexus_probe__'), max: 1 }); } catch (e) { ss = 'SOAP ✗ ' + e.message; ok = false; }
  steps.push({ ok, note: rs + ' · ' + ss });
  return { ok: steps.every(s => s.ok) || steps.slice(0, 2).every(s => s.ok), steps, bus, scopes, entId, restUri: t.rest, soapUri: t.soap };
}

async function accessAssessment(conn) {
  const api = new SFMC({ sub: conn.sub, cid: conn.cid, sec: dec(conn.secEnc) }); const mid = conn.mid || null; const rows = [];
  const check = async (label, fn, partial) => { try { const n = await fn(); rows.push([label, 'ok', n || '']); } catch (e) { rows.push([label, partial ? 'partial' : 'fail', e.message.slice(0, 140)]); } };
  let t;
  try { t = await api.token(mid); rows.push(['Authentication', 'ok', 'Token issued'], ['OAuth', 'ok', 'Client credentials grant']); }
  catch (e) { rows.push(['Authentication', 'fail', e.message], ['OAuth', 'fail', ''], ['Enterprise discovery', 'fail', 'Blocked by auth'], ['BU discovery', 'fail', 'Blocked by auth']); return { rows, scopes: [], status: 'Needs re-auth' }; }
  await check('Enterprise discovery', async () => { const c = await api.rest(mid, 'GET', '/platform/v1/tokenContext'); return 'Enterprise ' + dig(c, 'enterprise', 'id'); });
  await check('BU discovery', async () => { const r = await api.retrieve(mid, 'BusinessUnit', ['ID'], { all: true }); return plural(r.length, 'BU') + ' listed'; }, true);
  await check('REST API', async () => { await api.rest(mid, 'GET', '/platform/v1/tokenContext'); return t.rest; });
  await check('SOAP API', async () => { await api.retrieve(mid, 'DataExtension', ['Name'], { filter: eqFilter('Name', '__mcnexus_probe__'), max: 1 }); return t.soap; });
  await check('Data Extensions', async () => { await api.retrieve(mid, 'DataExtension', ['Name'], { filter: eqFilter('Name', '__mcnexus_probe__'), max: 1 }); return 'Read'; });
  await check('SQL Queries', async () => { await api.retrieve(mid, 'QueryDefinition', ['Name'], { filter: eqFilter('Name', '__mcnexus_probe__'), max: 1 }); return 'Read'; });
  await check('Automations', async () => { await api.rest(mid, 'GET', '/automation/v1/automations?$page=1&$pagesize=1'); return 'Read'; });
  await check('Journeys', async () => { await api.rest(mid, 'GET', '/interaction/v1/interactions?$page=1&$pageSize=1'); return 'Read'; });
  await check('Content', async () => { await api.rest(mid, 'GET', '/asset/v1/content/assets?$page=1&$pagesize=1'); return 'Read'; });
  await check('CloudPages', async () => { await api.rest(mid, 'POST', '/asset/v1/content/assets/query', { page: { page: 1, pageSize: 1 }, query: { property: 'assetType.name', simpleOperator: 'equal', value: 'webpage' } }); return 'Read (page code via Content Builder)'; }, true);
  await check('Users', async () => { await api.retrieve(mid, 'AccountUser', ['ID'], { filter: eqFilter('ID', '0'), max: 1 }); return 'Read'; }, true);
  rows.push(['Installed packages', 'partial', 'No public API lists installed packages — reviewed manually']);
  rows.push(['Tracking', 'partial', 'Send/open tracking not collected in this version']);
  const authFail = rows.slice(0, 2).some(r => r[1] === 'fail');
  return { rows, scopes: scopeList(t.scope), status: authFail ? 'Needs re-auth' : 'Connected' };
}

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

// ---------- scan ----------
const jobs = {};
const elapsed = (t0) => { const s = Math.floor((Date.now() - t0) / 1000); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };

async function runScan(job, conn, opts) {
  const api = new SFMC({ sub: conn.sub, cid: conn.cid, sec: dec(conn.secEnc) });
  const L = (m) => { job.log.unshift({ t: elapsed(job.t0), m }); if (job.log.length > 300) job.log.pop(); };
  const mods = new Set(opts.modules && opts.modules.length ? opts.modules : MODULES);
  const cov = {}; MODULES.forEach(m => cov[m] = { ok: 0, fail: 0, notes: [] });
  const mark = (m, ok, note) => { const c = cov[m]; ok ? c.ok++ : c.fail++; if (note && c.notes.length < 4 && !c.notes.includes(note)) c.notes.push(note); if (!ok) job.counts.warnings++; };
  const setMod = (m, st) => { job.mods[m] = st; };
  const check = () => { if (job.cancelled) throw new ApiErr('Cancelled by user', 0, 'cancel'); };
  const capped = (m, label, list) => { if (list && list.truncated) { mark(m, false, label + ': page limit reached (' + MAX_PAGES + ' pages)'); L(label + ': stopped at the page limit, results incomplete'); } return list; };
  MODULES.forEach(m => job.mods[m] = mods.has(m) ? 'QUEUED' : 'SKIPPED');
  const M = { des: [], fields: {}, folders: {}, queries: [], autos: [], imports: [], scripts: [], journeys: [], evs: [], content: [], users: [], deDone: [] };

  // Organization
  job.cur = 'Organization'; setMod('Organization', 'RUNNING');
  const t = await api.token(conn.mid || null); L('Token issued · ' + scopeList(t.scope).length + ' scopes');
  const disc = await discoverBus(api, conn.mid || null);
  const entMid = disc.entId || (disc.bus[0] && disc.bus[0].mid);
  mark('Organization', !disc.err, disc.err && ('BU discovery: ' + disc.err.message)); capped('Organization', 'BU discovery', disc.truncated && { truncated: true });
  const allBus = disc.bus; const wanted = new Set((opts.mids && opts.mids.length ? opts.mids : allBus.map(b => b.mid)).map(String));
  const bus = allBus.filter(b => wanted.has(b.mid));
  L('Discovered ' + plural(allBus.length, 'Business Unit') + (entMid ? ' under Enterprise ' + entMid : '') + ' · scanning ' + bus.length);
  setMod('Organization', disc.err || disc.truncated ? 'PARTIAL' : 'SUCCESS');
  const totalSteps = bus.length * 6 + 3; let done = 1;
  const tick = () => { done++; job.pct = Math.min(97, Math.round(done / totalSteps * 100)); };
  tick();

  if (mods.has('Security')) {
    job.cur = 'Security'; setMod('Security', 'RUNNING');
    try { M.users = capped('Security', 'Users', await api.retrieveSafe(conn.mid || null, 'AccountUser', ['ID', 'UserID', 'Name', 'Email', 'ActiveFlag', 'IsAPIUser', 'LastSuccessfulLogin', 'CreatedDate', 'Client.ID'], ['ID', 'UserID', 'Name', 'ActiveFlag', 'LastSuccessfulLogin'], { all: true })); mark('Security', true); L('Collected ' + plural(M.users.length, 'user') + ' (SOAP AccountUser)'); }
    catch (e) { mark('Security', false, 'Users: ' + e.message); L('Users unavailable — ' + e.message); }
  }
  tick();

  for (const bu of bus) {
    check();
    const mid = bu.mid, B = bu.name;
    try { await api.token(mid); } catch (e) { L(B + ': no access for this package — ' + e.message); ['Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages'].forEach(m => mods.has(m) && mark(m, false, B + ': ' + e.message)); done += 6; job.pct = Math.min(97, Math.round(done / totalSteps * 100)); continue; }
    const tag = (o) => Object.assign(o, { mid, bu: B });

    if (mods.has('Data')) {
      job.cur = 'Data · ' + B; setMod('Data', 'RUNNING');
      try {
        const des = capped('Data', B + ' DEs', await api.retrieveSafe(mid, 'DataExtension', ['ObjectID', 'CustomerKey', 'Name', 'IsSendable', 'CategoryID', 'CreatedDate', 'ModifiedDate', 'DataRetentionPeriodLength', 'DataRetentionPeriod', 'RowBasedRetention', 'RetainUntil', 'DeleteAtEndOfRetentionPeriod', 'Description', 'SendableDataExtensionField.Name', 'SendableSubscriberField.Name'], ['ObjectID', 'CustomerKey', 'Name', 'IsSendable', 'CategoryID', 'CreatedDate', 'ModifiedDate']));
        des.forEach(d => M.des.push(tag({ objectId: d.ObjectID, ck: d.CustomerKey, name: d.Name, sendable: bool(d.IsSendable), categoryId: d.CategoryID, created: d.CreatedDate, modified: d.ModifiedDate, retLen: d.DataRetentionPeriodLength, retPeriod: d.DataRetentionPeriod, rowRet: bool(d.RowBasedRetention), retainUntil: d.RetainUntil, deleteAtEnd: bool(d.DeleteAtEndOfRetentionPeriod), retKnown: d.DataRetentionPeriodLength !== undefined || d.RowBasedRetention !== undefined, desc: d.Description, sendField: dig(d, 'SendableDataExtensionField', 'Name'), subField: dig(d, 'SendableSubscriberField', 'Name') })));
        L(B + ': ' + plural(des.length, 'Data Extension') + ' (SOAP)'); job.counts.assets += des.length; mark('Data', true); if (!des.truncated) M.deDone.push(mid);
        try {
          const fs_ = capped('Data', B + ' DE fields', await api.retrieveSafe(mid, 'DataExtensionField', ['Name', 'IsPrimaryKey', 'FieldType', 'IsRequired', 'DataExtension.CustomerKey'], ['Name', 'IsPrimaryKey', 'DataExtension.CustomerKey']));
          // A cut-off field list can end mid-DE; leave fields uncollected rather than report a false "no primary key".
          if (!fs_.truncated) fs_.forEach(f => { const k = mid + '|' + dig(f, 'DataExtension', 'CustomerKey'); (M.fields[k] = M.fields[k] || []).push({ name: f.Name, pk: bool(f.IsPrimaryKey), type: f.FieldType }); });
          L(B + ': ' + fs_.length.toLocaleString('en-US') + ' DE fields');
        } catch (e) { mark('Data', false, B + ' fields: ' + e.message); }
        try { const fo = await api.retrieve(mid, 'DataFolder', ['ID', 'Name', 'ParentFolder.ID', 'ContentType']); fo.forEach(f => { M.folders[mid + '|' + f.ID] = { name: f.Name, parent: dig(f, 'ParentFolder', 'ID') }; }); } catch { }
      } catch (e) { mark('Data', false, B + ': ' + e.message); L(B + ': Data Extensions failed — ' + e.message); }
    }
    tick(); check();

    if (mods.has('SQL')) {
      job.cur = 'SQL · ' + B; setMod('SQL', 'RUNNING');
      try {
        const qs = capped('SQL', B + ' queries', await api.retrieveSafe(mid, 'QueryDefinition', ['ObjectID', 'CustomerKey', 'Name', 'QueryText', 'TargetType', 'DataExtensionTarget.Name', 'DataExtensionTarget.CustomerKey', 'TargetUpdateType', 'CreatedDate', 'ModifiedDate', 'CategoryID'], ['ObjectID', 'CustomerKey', 'Name', 'QueryText', 'DataExtensionTarget.Name', 'DataExtensionTarget.CustomerKey', 'TargetUpdateType', 'CreatedDate', 'ModifiedDate']));
        qs.forEach(q => M.queries.push(tag({ objectId: q.ObjectID, ck: q.CustomerKey, name: q.Name, text: q.QueryText || '', targetName: dig(q, 'DataExtensionTarget', 'Name'), targetCk: dig(q, 'DataExtensionTarget', 'CustomerKey'), update: q.TargetUpdateType, created: q.CreatedDate, modified: q.ModifiedDate })));
        L(B + ': ' + plural(qs.length, 'SQL Query') + ' (SOAP)'); job.counts.assets += qs.length; mark('SQL', true);
      } catch (e) { mark('SQL', false, B + ': ' + e.message); L(B + ': SQL failed — ' + e.message); }
    }
    tick(); check();

    if (mods.has('Automation')) {
      job.cur = 'Automation · ' + B; setMod('Automation', 'RUNNING');
      try {
        const list = capped('Automation', B + ' automations', await api.restPages(mid, '/automation/v1/automations', { size: 200 }));
        const det = await pMap(list.slice(0, MAX_DETAIL), CONCURRENCY, a => api.rest(mid, 'GET', '/automation/v1/automations/' + a.id).catch(() => a));
        det.concat(list.slice(MAX_DETAIL)).forEach(a => {
          const sid = a.statusId != null ? a.statusId : a.status;
          const status = typeof a.status === 'string' && isNaN(+a.status) ? a.status : (AUTO_STATUS[sid] || 'Unknown');
          const steps = arr(a.steps).flatMap(s => arr(s.activities).map(x => ({ name: x.name, typeId: x.objectTypeId, objectId: x.activityObjectId, step: s.step || s.stepNumber })));
          M.autos.push(tag({ id: a.id, key: a.key || a.customerKey, name: a.name, status, lastRun: a.lastRunTime, lastRunStatus: a.lastRunStatus, schedule: a.schedule, steps, created: a.createdDate, modified: a.modifiedDate || a.lastSavedDate, detailed: !!a.steps }));
        });
        if (list.length > MAX_DETAIL) mark('Automation', false, B + ': detail limited to ' + MAX_DETAIL + ' automations');
        L(B + ': ' + plural(list.length, 'Automation') + ' · ' + M.autos.filter(a => a.mid === mid).reduce((n, a) => n + a.steps.length, 0) + ' activities (REST)'); job.counts.assets += list.length; mark('Automation', true);
      } catch (e) { mark('Automation', false, B + ': ' + e.message); L(B + ': Automations failed — ' + e.message); }
      try { const im = capped('Automation', B + ' imports', await api.restPages(mid, '/automation/v1/imports', { size: 200 })); im.forEach(i => M.imports.push(tag({ id: i.importDefinitionId || i.id, name: i.name, ck: i.customerKey, destId: i.destinationObjectId, destName: i.destinationName, modified: i.modifiedDate }))); job.counts.assets += im.length; } catch (e) { mark('Automation', false, B + ' imports: ' + e.message); }
      try { const sc = capped('Automation', B + ' scripts', await api.restPages(mid, '/automation/v1/scripts', { size: 200 })); sc.forEach(x => M.scripts.push(tag({ id: x.ssjsActivityId || x.id, name: x.name, ck: x.key, text: x.script || '', modified: x.modifiedDate, created: x.createdDate }))); job.counts.assets += sc.length; } catch (e) { mark('Automation', false, B + ' scripts: ' + e.message); }
    }
    tick(); check();

    if (mods.has('Journey')) {
      job.cur = 'Journey · ' + B; setMod('Journey', 'RUNNING');
      try {
        const js = capped('Journey', B + ' journeys', await api.restPages(mid, '/interaction/v1/interactions?mostRecentVersionOnly=false', { size: 100, sizeParam: '$pageSize' }));
        const evs = capped('Journey', B + ' event definitions', await api.restPages(mid, '/interaction/v1/eventDefinitions', { size: 100, sizeParam: '$pageSize' }).catch(() => []));
        evs.forEach(e => M.evs.push(tag({ key: e.eventDefinitionKey, deId: e.dataExtensionId, deName: e.dataExtensionName, type: e.type })));
        const byKey = {}; js.forEach(j => { const k = j.key || j.id; (byKey[k] = byKey[k] || []).push(j); });
        const latest = Object.values(byKey).map(v => v.sort((a, b) => (b.version || 0) - (a.version || 0))[0]);
        const det = await pMap(latest.slice(0, MAX_DETAIL), CONCURRENCY, j => api.rest(mid, 'GET', '/interaction/v1/interactions/' + j.id).catch(() => j));
        det.forEach(j => {
          const vers = byKey[j.key || j.id] || [j];
          const trig = arr(j.triggers)[0] || {};
          const evKey = dig(trig, 'metaData', 'eventDefinitionKey') || dig(trig, 'configurationArguments', 'eventDefinitionKey');
          const emails = arr(j.activities).filter(a => /EMAIL/i.test(a.type || '')).map(a => ({ name: a.name, emailId: dig(a, 'configurationArguments', 'triggeredSend', 'emailId'), subject: dig(a, 'configurationArguments', 'triggeredSend', 'emailSubject') }));
          M.journeys.push(tag({ id: j.id, key: j.key || j.id, name: j.name, version: j.version, status: j.status, entryMode: j.entryMode, evKey, emails, acts: arr(j.activities).length, goal: !!(j.goals && j.goals.length), created: j.createdDate, modified: j.modifiedDate, versions: vers.map(v => ({ v: v.version, status: v.status, modified: v.modifiedDate })) }));
        });
        if (latest.length > MAX_DETAIL) mark('Journey', false, B + ': detail limited to ' + MAX_DETAIL + ' journeys');
        L(B + ': Journey API returned ' + plural(latest.length, 'journey') + ' · ' + js.length + ' versions'); job.counts.assets += latest.length; mark('Journey', true);
      } catch (e) { mark('Journey', false, B + ': ' + e.message); L(B + ': Journeys failed — ' + e.message); }
    }
    tick(); check();

    if (mods.has('Content') || mods.has('CloudPages')) {
      const types = [...(mods.has('Content') ? CONTENT_TYPES : []), ...(mods.has('CloudPages') ? PAGE_TYPES : [])];
      job.cur = 'Content · ' + B; if (mods.has('Content')) setMod('Content', 'RUNNING'); if (mods.has('CloudPages')) setMod('CloudPages', 'RUNNING');
      try {
        let page = 1, got = 0, total = null, cut = false;
        for (; ; page++) {
          if (page > MAX_PAGES) { cut = true; break; }
          const j = await api.rest(mid, 'POST', '/asset/v1/content/assets/query', { page: { page, pageSize: 200 }, query: { property: 'assetType.name', simpleOperator: 'in', value: types }, fields: ['id', 'customerKey', 'name', 'assetType', 'category', 'modifiedDate', 'createdDate', 'content', 'views', 'legacyData', 'status'] });
          const items = j.items || []; total = j.count; got += items.length;
          items.forEach(a => {
            const tn = dig(a, 'assetType', 'name') || '';
            let text = (a.content || '') + '\n' + (a.views ? JSON.stringify(a.views) : ''); if (text.length > 300000) text = text.slice(0, 300000);
            M.content.push(tag({ id: String(a.id), ck: a.customerKey, name: a.name, typeName: tn, isPage: PAGE_TYPES.includes(tn), folder: dig(a, 'category', 'name'), modified: a.modifiedDate, created: a.createdDate, legacyId: dig(a, 'legacyData', 'legacyId'), status: dig(a, 'status', 'name'), text }));
          });
          if (!items.length || (total != null ? got >= total : items.length < 200)) break;
        }
        if (cut || (total != null && got < total)) { ['Content', 'CloudPages'].forEach(m => mods.has(m) && mark(m, false, B + ': ' + got + ' of ' + (total != null ? total : '?') + ' assets paged (page limit)')); }
        L(B + ': Content Builder ' + got.toLocaleString('en-US') + ' assets paged'); job.counts.assets += got;
        if (mods.has('Content')) mark('Content', true); if (mods.has('CloudPages')) mark('CloudPages', true);
      } catch (e) { ['Content', 'CloudPages'].forEach(m => mods.has(m) && mark(m, false, B + ': ' + e.message)); L(B + ': Content failed — ' + e.message); }
    }
    tick(); tick();
  }
  ['Security', 'Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages'].forEach(m => { if (!mods.has(m)) return; const c = cov[m]; setMod(m, !c.ok ? 'FAILED' : c.fail ? 'PARTIAL' : 'SUCCESS'); });

  job.cur = 'Analysis'; setMod('Governance', mods.has('Governance') ? 'RUNNING' : 'SKIPPED');
  const ds = analyze(M, { bus, allBus, entMid, mods, cov, naming: opts.naming, rulesX: db.settings.rulesX || {}, L, job });
  if (mods.has('Governance')) { mark('Governance', true); setMod('Governance', 'SUCCESS'); }
  return { ds, api };
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
    F.push({ id: 'F-' + hid(rule + '|' + (x.objKey || a.key)), rule, sev, domain: DOMAIN_OF[r[2]], bu: x.bu || (a.raw && a.raw.bu) || '—', objType: x.objType || a.type, obj: x.obj || a.name, objKey: x.objKey || a.key, title: x.title || r[1], impact: x.impact || (sev === 'CRITICAL' || sev === 'HIGH' ? 'HIGH' : sev === 'MEDIUM' ? 'MEDIUM' : 'LOW'), like: x.like || 'MEDIUM', conf: x.conf || 'HIGH', effort: x.effort || 'LOW', status: 'OPEN', why: x.why, evidence: x.evidence || [], affected: x.affected || '', rec: x.rec, limit: x.limit || 'None', chain: x.chain });
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
    DE_FN_RE.lastIndex = 0; while ((m = DE_FN_RE.exec(text))) { const n = m[1]; if (seen.has(n.toLowerCase())) continue; seen.add(n.toLowerCase()); const d = findDe(mid, n); if (d) link(d.key, key, 'REFERENCES'); else list.push(n); }
    DE_INIT_RE.lastIndex = 0; while ((m = DE_INIT_RE.exec(text))) { const n = m[1]; if (seen.has(n.toLowerCase())) continue; seen.add(n.toLowerCase()); const d = deByCk[mid + '|' + n.toLowerCase()] || findDe(mid, n); if (d) link(d.key, key, 'REFERENCES'); else list.push(n); } };
  M.scripts.forEach(s => { s.missing = []; deRefs(s.text, s.mid, s.key, s.missing); });
  M.content.forEach(c => {
    c.missing = []; c.brokenCb = []; deRefs(c.text, c.mid, c.key, c.missing); let m;
    CB_ID_RE.lastIndex = 0; while ((m = CB_ID_RE.exec(c.text))) { const b = cById[c.mid + '|' + m[1]] || cByIdAny[m[1]]; if (b) link(b.key, c.key, 'EMBEDDED_IN'); else if (!c.brokenCb.includes(m[1])) c.brokenCb.push(m[1]); }
    CB_KEY_RE.lastIndex = 0; while ((m = CB_KEY_RE.exec(c.text))) { const b = cByCk[c.mid + '|' + m[1].toLowerCase()]; if (b) link(b.key, c.key, 'EMBEDDED_IN'); else if (!c.brokenCb.includes(m[1])) c.brokenCb.push(m[1]); }
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
  const secretHit = (text) => { const m = String(text || '').match(SECRET_RE); if (!m) return null; const line = String(text).slice(0, m.index).split('\n').length; return { name: m[1], line, masked: m[2].slice(0, 2) + '••••••' + m[2].slice(-2) }; };
  if (mods.has('CloudPages')) M.content.filter(c => c.isPage).forEach(c => { rulesRun++; const h = secretHit(c.text); if (h) finding('CP-002', A.get(c.key), { why: 'A credential-like value is embedded in page code. Anyone with Content Builder access can read it.', evidence: [['Pattern', h.name + ' = "' + h.masked + '"'], ['Approx. line', String(h.line)], ['Source', 'Static analysis — code not executed']], like: 'MEDIUM', conf: 'MEDIUM', rec: 'Rotate the credential and move it server-side (e.g. encrypted DE or key management).' }); });
  if (mods.has('Security') || mods.has('Automation')) M.scripts.forEach(s => { rulesRun++; const h = secretHit(s.text); if (h) finding('SEC-SCR-001', A.get(s.key), { why: 'A credential-like value is embedded in an SSJS script activity.', evidence: [['Pattern', h.name + ' = "' + h.masked + '"'], ['Approx. line', String(h.line)]], conf: 'MEDIUM', rec: 'Rotate the credential and load it from a protected store.' }); });
  if (mods.has('Content')) M.content.forEach(c => { rulesRun += 2; const a = A.get(c.key);
    if (c.brokenCb.length) finding('CNT-REF-002', a, { why: 'The asset references content blocks that could not be found.', evidence: [['References', c.brokenCb.slice(0, 5).join(', ')]], conf: 'MEDIUM', rec: 'Replace or remove the reference.', limit: 'Shared/other-BU content may not be visible to this package.' });
    const cMiss = c.missing.filter(n => canMiss(c.mid, n)); if (cMiss.length) finding('CNT-DE-001', a, { why: 'AMPscript/SSJS references a data extension that could not be resolved.', evidence: [['Unresolved', cMiss.slice(0, 5).join(', ')]], conf: 'MEDIUM', rec: 'Confirm the DE name; use ENT. for shared DEs.', limit: 'Names built dynamically are not resolved.' }); });
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

// ---------- HTTP ----------
const sessions = new Map();
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.jsx': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.md': 'text/plain; charset=utf-8' };
function send(req, res, code, obj, headers = {}) {
  let body = typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj);
  const h = { 'content-type': typeof obj === 'object' && !Buffer.isBuffer(obj) ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers };
  if (body.length > 2048 && /gzip/.test(req.headers['accept-encoding'] || '')) { body = zlib.gzipSync(body); h['content-encoding'] = 'gzip'; }
  res.writeHead(code, h); res.end(body);
}
const readBody = (req) => new Promise((ok, bad) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 2e6) { bad(new Error('Body too large')); req.destroy(); } else c.push(d); }); req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c).toString('utf8')) : {}); } catch { bad(new Error('Invalid JSON')); } }); });
const cookie = (req, k) => ((req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(k + '=')) || '').slice(k.length + 1);
const session = (req) => { const s = sessions.get(cookie(req, 'mcx')); if (!s || s.exp < Date.now()) return null; s.exp = Date.now() + SESSION_IDLE; s.seen = Date.now(); return s; };
const subOk = (s) => /^[a-z0-9-]{10,60}$/.test(s || '');
const parseSub = (v) => { const t = String(v || '').trim().toLowerCase(); const m = t.match(/^https?:\/\/([a-z0-9-]+)\.(auth|rest|soap)\.marketingcloudapis\.com/); return m ? m[1] : t.replace(/[^a-z0-9-]/g, ''); };

function publicConn(c) {
  const list = db.scans[c.id] || []; const last = list[list.length - 1];
  return { id: c.id, name: c.name, env: c.env, mid: c.mid || '—', sub: c.sub, bus: (c.buList || []).filter(b => !(c.buOff || {})[b.mid]).length || (c.buList || []).length, buList: c.buList || [], buOff: c.buOff || {}, status: c.status || 'Connected', validated: c.validated || '—', access: c.access || [], scopes: c.scopes || [], cidHint: c.cid ? c.cid.slice(0, 4) + '…' + c.cid.slice(-4) : '—', secretUpdated: c.secretUpdated ? fmtD(c.secretUpdated) : (c.created ? fmtD(c.created) : '—'),
    health: last ? last.health : 0, coverage: last ? last.cov : 0, last: last ? last.date : 'Never', scan: last ? last.id : '—', crit: last ? last.sev[0] : 0, high: last ? last.sev[1] : 0, scans: list.length };
}

async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  if (p === '/api/health') return send(req, res, 200, { ok: true, version: VERSION, ruleset: RULESET, firstRun: db.users.length === 0 });
  if (p === '/api/session') { const s = session(req); const u = s && db.users.find(x => x.email === s.email); return send(req, res, 200, { user: u ? { email: u.email, name: u.name, role: u.role } : null }); }
  if (p === '/api/login' && m === 'POST') {
    const b = await readBody(req); const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return send(req, res, 400, { error: 'Enter a valid work email.' });
    let u = db.users.find(x => x.email === email);
    if (!db.users.length) { if (pw.length < 8) return send(req, res, 400, { error: 'First sign-in creates the owner account — choose a password of 8+ characters.' }); const salt = crypto.randomBytes(16).toString('hex'); u = { email, name: email.split('@')[0].replace(/[._-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), role: 'Owner', salt, hash: hashPw(pw, salt) }; db.users.push(u); save(); }
    else if (!u || !crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), 'hex'), Buffer.from(u.hash, 'hex'))) { await sleep(600); return send(req, res, 401, { error: 'Email or password not recognised.' }); }
    const tok = crypto.randomBytes(32).toString('hex'); sessions.set(tok, { email, exp: Date.now() + SESSION_IDLE, created: Date.now(), seen: Date.now(), ua: String(req.headers['user-agent'] || '').slice(0, 300), ip: req.socket.remoteAddress || '' });
    return send(req, res, 200, { user: { email: u.email, name: u.name, role: u.role } }, { 'set-cookie': `mcx=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_IDLE / 1000}` });
  }
  if (p === '/api/logout') { sessions.delete(cookie(req, 'mcx')); return send(req, res, 200, { ok: true }, { 'set-cookie': 'mcx=; Path=/; Max-Age=0' }); }
  const s = session(req); if (!s) return send(req, res, 401, { error: 'Not signed in' });
  const me = db.users.find(x => x.email === s.email) || { name: s.email };

  if (p === '/api/settings') {
    if (m === 'PUT') {
      const b = await readBody(req);
      if (b.rulesX) db.settings.rulesX = b.rulesX; if (b.naming) db.settings.naming = b.naming;
      if (b.scan) { const sc = b.scan; db.settings.scan = { ...db.settings.scan, mode: ['Quick Scan', 'Full Assessment', 'Custom Assessment'].includes(sc.mode) ? sc.mode : db.settings.scan.mode, modules: Array.isArray(sc.modules) ? sc.modules.filter(x => MODULES.includes(x)) : null, maxPages: sc.maxPages, maxDetail: sc.maxDetail, concurrency: sc.concurrency }; applyLimits(); }
      if (b.report) { const r = b.report; if (r.logo && (String(r.logo).length > 400000 || !/^data:image\/(png|jpeg|svg\+xml);base64,/.test(r.logo))) return send(req, res, 400, { error: 'Logo must be a PNG, JPG or SVG under 300 KB.' }); db.settings.report = { firm: String(r.firm || '').slice(0, 120), disclaimer: String(r.disclaimer || '').slice(0, 2000), format: ['PDF', 'Excel', 'HTML'].includes(r.format) ? r.format : 'PDF', logo: r.logo || '' }; }
      if (b.data) { db.settings.data = { keepScans: clampN(b.data.keepScans, 0, 1000, 0) }; Object.keys(db.scans).forEach(prune); }
      save();
    }
    return send(req, res, 200, { ...db.settings, rules: RULES, modules: MODULES });
  }
  if (p === '/api/me/password' && m === 'POST') {
    const b = await readBody(req); const u = db.users.find(x => x.email === s.email); if (!u) return send(req, res, 404, { error: 'User not found' });
    if (!crypto.timingSafeEqual(Buffer.from(hashPw(String(b.current || ''), u.salt), 'hex'), Buffer.from(u.hash, 'hex'))) { await sleep(600); return send(req, res, 400, { error: 'Current password is not correct.' }); }
    if (String(b.next || '').length < 8) return send(req, res, 400, { error: 'New password must be 8+ characters.' });
    u.salt = crypto.randomBytes(16).toString('hex'); u.hash = hashPw(String(b.next), u.salt); save();
    const cur = cookie(req, 'mcx'); for (const [k, v] of sessions) if (v.email === s.email && k !== cur) sessions.delete(k);
    return send(req, res, 200, { ok: true });
  }
  if (p === '/api/me/sessions') { const cur = cookie(req, 'mcx'); return send(req, res, 200, { sessions: [...sessions.entries()].filter(([, v]) => v.email === s.email && v.exp > Date.now()).map(([k, v]) => ({ id: hid(k), current: k === cur, created: v.created, seen: v.seen, ua: v.ua || '', ip: v.ip || '' })) }); }
  if (p === '/api/me/signout-others' && m === 'POST') { const cur = cookie(req, 'mcx'); let n = 0; for (const [k, v] of sessions) if (v.email === s.email && k !== cur) { sessions.delete(k); n++; } return send(req, res, 200, { ended: n }); }
  if (p === '/api/about') {
    let size = 0; const walk = (d) => { try { fs.readdirSync(d, { withFileTypes: true }).forEach(e => { const f = path.join(d, e.name); if (e.isDirectory()) walk(f); else size += fs.statSync(f).size; }); } catch { } }; walk(DATA);
    const up = Math.floor((Date.now() - STARTED) / 1000);
    return send(req, res, 200, { version: VERSION, ruleset: RULESET, node: process.version, platform: process.platform + ' ' + process.arch, started: new Date(STARTED).toISOString(), uptime: Math.floor(up / 86400) + 'd ' + Math.floor(up % 86400 / 3600) + 'h ' + Math.floor(up % 3600 / 60) + 'm', dataDir: DATA, dataSize: size > 1e6 ? (size / 1e6).toFixed(1) + ' MB' : Math.ceil(size / 1e3) + ' KB', connections: db.connections.length, scans: Object.values(db.scans).reduce((n, l) => n + l.length, 0), users: db.users.length, keySource: process.env.MCNEXUS_KEY ? 'MCNEXUS_KEY environment variable' : 'server/data/.key (generated)', listen: HOST + ':' + PORT });
  }
  if (p === '/api/connections' && m === 'GET') return send(req, res, 200, { connections: db.connections.map(publicConn) });
  if (p === '/api/connections/test' && m === 'POST') {
    const b = await readBody(req); const sub = parseSub(b.sub); let sec = b.sec;
    if (!sec && b.reauth) { const c = db.connections.find(x => x.id === b.reauth); if (c) sec = dec(c.secEnc); }
    if (!subOk(sub) || !b.cid || !sec) return send(req, res, 400, { error: 'Subdomain, Client ID and Client Secret are required.' });
    return send(req, res, 200, await testConnection({ sub, cid: String(b.cid).trim(), sec: String(sec).trim(), mid: String(b.mid || '').trim() || null }));
  }
  if (p === '/api/connections' && m === 'POST') {
    const b = await readBody(req); const sub = parseSub(b.sub);
    let c = b.reauth && db.connections.find(x => x.id === b.reauth);
    if (!c) { if (!subOk(sub) || !b.cid || !b.sec) return send(req, res, 400, { error: 'Missing package details.' }); c = { id: 'c' + crypto.randomBytes(5).toString('hex'), created: new Date().toISOString() }; db.connections.push(c); }
    Object.assign(c, { name: String(b.name || c.name || 'SFMC org').trim(), env: b.env || c.env || 'Production', sub: sub || c.sub, cid: String(b.cid || c.cid).trim(), mid: String(b.mid || c.mid || '').trim(), buOff: b.buOff || c.buOff || {}, buList: b.bus && b.bus.length ? b.bus : (c.buList || []), status: 'Connected', validated: fmtD(new Date()) + ' ' + new Date().toTimeString().slice(0, 5) });
    if (b.sec) { c.secEnc = enc(String(b.sec).trim()); c.secretUpdated = new Date().toISOString(); }
    save(); return send(req, res, 200, { connection: publicConn(c) });
  }
  let mm = p.match(/^\/api\/connections\/([\w-]+)(?:\/(\w+))?$/);
  if (mm) {
    const c = db.connections.find(x => x.id === mm[1]); if (!c) return send(req, res, 404, { error: 'Connection not found' });
    const sub = mm[2];
    if (!sub && m === 'DELETE') { db.connections = db.connections.filter(x => x !== c); delete db.scans[c.id]; delete db.triage[c.id]; save(); fs.rmSync(path.join(DATA, 'scans', c.id), { recursive: true, force: true }); return send(req, res, 200, { ok: true }); }
    if (!sub && m === 'PATCH') {
      const b = await readBody(req);
      const next = { name: String(b.name != null ? b.name : c.name).trim() || c.name, env: ['Production', 'Sandbox'].includes(b.env) ? b.env : c.env, sub: b.sub ? parseSub(b.sub) : c.sub, cid: b.cid ? String(b.cid).trim() : c.cid, mid: b.mid != null ? String(b.mid).trim() : (c.mid || '') };
      if (!subOk(next.sub)) return send(req, res, 400, { error: 'Enter a valid tenant subdomain.' });
      if (!/^[A-Za-z0-9]{8,64}$/.test(next.cid)) return send(req, res, 400, { error: 'Client ID is letters and digits only.' });
      if (next.mid && !/^\d{6,12}$/.test(next.mid)) return send(req, res, 400, { error: 'MID is digits only.' });
      const sec = b.sec ? String(b.sec).trim() : null;
      const credsChanged = !!sec || next.sub !== c.sub || next.cid !== c.cid || next.mid !== (c.mid || '');
      let test = null;
      if (credsChanged && b.test !== false) {
        test = await testConnection({ sub: next.sub, cid: next.cid, sec: sec || dec(c.secEnc), mid: next.mid || null });
        const authOk = test.steps.length >= 2 && test.steps[0].ok && test.steps[1].ok;
        if (!authOk) return send(req, res, 400, { error: 'Connection test failed — nothing was saved. ' + ((test.steps.find(x => !x.ok) || {}).note || ''), test });
      }
      Object.assign(c, next); if (sec) { c.secEnc = enc(sec); c.secretUpdated = new Date().toISOString(); }
      if (test) { c.status = 'Connected'; c.validated = fmtD(new Date()) + ' ' + new Date().toTimeString().slice(0, 5); if (test.bus && test.bus.length) c.buList = test.bus; c.scopes = test.scopes || c.scopes; }
      save(); return send(req, res, 200, { connection: publicConn(c), test, credsChanged });
    }
    if (sub === 'scans' && m === 'DELETE') { const n = (db.scans[c.id] || []).length; db.scans[c.id] = []; delete db.triage[c.id]; save(); fs.rmSync(path.join(DATA, 'scans', c.id), { recursive: true, force: true }); return send(req, res, 200, { deleted: n }); }
    if (sub === 'export') {
      const list = db.scans[c.id] || [];
      const out = { exported: new Date().toISOString(), app: 'MCNexus ' + VERSION, connection: publicConn(c), scans: list.map(x => ({ summary: x, snapshot: loadScan(c.id, x.n) })), triage: db.triage[c.id] || {} };
      return send(req, res, 200, JSON.stringify(out), { 'content-type': 'application/json; charset=utf-8', 'content-disposition': `attachment; filename="MCNexus_${String(c.name).replace(/[^A-Za-z0-9]+/g, '_')}_export.json"` });
    }
    if (sub === 'access' && m === 'POST') { const r = await accessAssessment(c); c.access = r.rows; c.scopes = r.scopes; c.status = r.status; c.validated = fmtD(new Date()) + ' ' + new Date().toTimeString().slice(0, 5); save(); return send(req, res, 200, { connection: publicConn(c) }); }
    if (sub === 'triage' && m === 'PUT') { const b = await readBody(req); db.triage[c.id] = b.fx || {}; save(); return send(req, res, 200, { ok: true }); }
    if (sub === 'dataset') {
      const list = db.scans[c.id] || []; const want = url.searchParams.get('scan'); const sm = (want && list.find(x => x.id === want)) || list[list.length - 1];
      const ds = sm ? loadScan(c.id, sm.n) : null;
      return send(req, res, 200, { connection: publicConn(c), scans: list, scan: sm || null, buList: c.buList || [], triage: db.triage[c.id] || {}, owners: db.users.map(u => u.name + ' · ' + u.role), ...(ds || {}) });
    }
    if (sub === 'compare') {
      const list = db.scans[c.id] || []; const A = list.find(x => x.id === url.searchParams.get('a')), B = list.find(x => x.id === url.searchParams.get('b'));
      if (!A || !B) return send(req, res, 400, { error: 'Pick two scans' });
      const fa = (loadScan(c.id, A.n) || {}).findings || [], fb = (loadScan(c.id, B.n) || {}).findings || [];
      const ia = new Set(fa.map(f => f.id)), ib = new Set(fb.map(f => f.id));
      const row = (f) => [f.sev, f.rule, f.title + ' · ' + f.obj];
      const added = fb.filter(f => !ia.has(f.id)), resolved = fa.filter(f => !ib.has(f.id));
      return send(req, res, 200, { added: added.length, resolved: resolved.length, newF: added.slice(0, 12).map(row), resF: resolved.slice(0, 12).map(row) });
    }
  }
  if (p === '/api/scans' && m === 'POST') {
    const b = await readBody(req); const c = db.connections.find(x => x.id === b.connId); if (!c) return send(req, res, 404, { error: 'Connection not found' });
    if (Object.values(jobs).some(j => j.connId === c.id && !j.done)) return send(req, res, 409, { error: 'A scan is already running for this connection.' });
    const list = db.scans[c.id] = db.scans[c.id] || []; const n = (list.length ? list[list.length - 1].n : 0) + 1; const id = '#' + String(n).padStart(3, '0');
    const job = jobs['j' + crypto.randomBytes(5).toString('hex')] = { connId: c.id, scanId: id, n, t0: Date.now(), pct: 0, cur: 'Starting', log: [], mods: {}, counts: { assets: 0, rels: 0, rules: 0, findings: 0, warnings: 0, errors: 0 }, done: false, error: null, cancelled: false };
    const jobId = Object.keys(jobs).find(k => jobs[k] === job);
    (async () => {
      try {
        const { ds, api: cl } = await runScan(job, c, b);
        const sum = { n, id, date: fmtD(new Date()), iso: new Date().toISOString(), ...ds.summary, mode: String(b.mode || 'Full').split(' ')[0], by: me.name, dur: elapsed(job.t0), calls: cl.calls };
        delete ds.summary; fs.mkdirSync(path.join(DATA, 'scans', c.id), { recursive: true });
        fs.writeFileSync(scanPath(c.id, n), JSON.stringify({ ...ds, scan: sum }));
        list.push(sum); prune(c.id); c.status = 'Connected'; save();
        job.pct = 100; job.cur = 'Complete'; job.log.unshift({ t: elapsed(job.t0), m: 'Scores calculated · snapshot ' + id + ' stored · ' + cl.calls + ' API calls' }); job.partial = ds.limits.length > 2;
      } catch (e) { job.error = e.message; job.counts.errors++; job.log.unshift({ t: elapsed(job.t0), m: 'Scan stopped — ' + e.message }); if (e.status === 401 || e.code === 'auth') { c.status = 'Needs re-auth'; save(); } }
      job.done = true; setTimeout(() => delete jobs[jobId], 3600e3).unref();
    })();
    return send(req, res, 200, { jobId, scanId: id });
  }
  mm = p.match(/^\/api\/jobs\/(\w+)(\/cancel)?$/);
  if (mm) { const j = jobs[mm[1]]; if (!j) return send(req, res, 404, { error: 'Job not found' }); if (mm[2]) j.cancelled = true; const { t0, ...pub } = j; return send(req, res, 200, { ...pub, log: j.log.slice(0, 60), elapsed: elapsed(t0) }); }
  return send(req, res, 404, { error: 'Unknown endpoint' });
}

// Allow-list of files the UI loads. Everything else (server/, uploads/, docs, dotfiles) is never served.
// Matched case-sensitively against the normalized path, so case-insensitive file systems can't bypass it.
const STATIC_OK = /^(?:[^/]+\.dc\.html|support\.js|_ds\/[^/]+\/[^/]+\.(?:css|js|woff2?|ttf|svg|png))$/;
function serveStatic(req, res, url) {
  let p; try { p = decodeURIComponent(url.pathname); } catch { return send(req, res, 404, 'Not found'); }
  if (p === '/') { res.writeHead(302, { location: '/' + encodeURIComponent('MCNexus App.dc.html') }); return res.end(); }
  const rel = path.posix.normalize(p.replace(/\\/g, '/')).replace(/^\/+/, '');
  if (p.includes('\0') || !STATIC_OK.test(rel) || rel.split('/').some(s => s.startsWith('.'))) return send(req, res, 404, 'Not found');
  const f = path.join(ROOT, rel);
  if (!f.startsWith(ROOT + path.sep)) return send(req, res, 404, 'Not found');
  fs.stat(f, (e, st) => {
    if (e || !st.isFile()) return send(req, res, 404, 'Not found');
    res.writeHead(200, { 'content-type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff' });
    fs.createReadStream(f).pipe(res);
  });
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  try { if (url.pathname.startsWith('/api/')) await api(req, res, url); else serveStatic(req, res, url); }
  catch (e) { console.error(e); send(req, res, e.status && e.status < 500 ? 400 : 500, { error: e.message }); }
}

if (require.main === module) http.createServer(handle).listen(PORT, HOST, () => console.log(`MCNexus ${VERSION} → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}/  (data: ${DATA})`));

// Internals exported for tests (test/). Set MCNEXUS_DATA / MCNEXUS_KEY before requiring: the store loads on require.
module.exports = { handle, analyze, runScan, testConnection, SFMC, ApiErr, xmlObj, sqlSources, sqlDepth, patternRe, enc, dec, hid, score,
  RULES, RULE, RULESET, VERSION, DOMAINS, DOMAIN_OF, MODULES, SEVS, W, PEN, SECRET_RE, STATIC_OK };
