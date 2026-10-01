#!/usr/bin/env node
// MCNexus server (Node 22+). Serves the app and proxies read-only SFMC API calls. Storage: server/store.js.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');
const { Worker } = require('worker_threads');
const { createStore } = require('./store');
const { RULESET, arr, dig, fmtD, ageDays, hid, plural, bool, RULES, RULE, DOMAIN_OF, DOMAINS, MODULES, SEVS, W, PEN, score, AUTO_STATUS, ACT_TYPE, CONTENT_TYPES, PAGE_TYPES, SECRET_RE, sqlSources, sqlDepth, patternRe, analyze, emptyM, mergeM, packPart, unpackPart, hasData, analyzeParts } = require('./analyze');

const PORT = +process.env.PORT || 8787, HOST = process.env.HOST || '127.0.0.1';
const ROOT = path.resolve(__dirname, '..'), DATA = process.env.MCNEXUS_DATA || path.join(__dirname, 'data');
const VERSION = '1.0.0';
const ENV_LIM = { maxPages: +process.env.MCNEXUS_MAX_PAGES || 40, maxDetail: +process.env.MCNEXUS_MAX_DETAIL || 400, concurrency: +process.env.MCNEXUS_CONCURRENCY || 6 };
let MAX_PAGES = ENV_LIM.maxPages, MAX_DETAIL = ENV_LIM.maxDetail, CONCURRENCY = ENV_LIM.concurrency; // overridden by Settings → Scan defaults
const STARTED = Date.now();
// Sessions: idle timeout, absolute lifetime, and how often last-seen is written back (keeps writes off hot paths).
const HOURS = (v, d) => (+v > 0 ? +v : d) * 3600e3;
const SESSION_IDLE = HOURS(process.env.MCNEXUS_SESSION_IDLE_H, 8), SESSION_MAX = HOURS(process.env.MCNEXUS_SESSION_MAX_H, 168), SESSION_TOUCH = 60e3;
// Sign-in throttling: failures per email and per client IP in a 15-minute window.
const LOGIN_WINDOW = 15 * 60e3, LOGIN_MAX_EMAIL = +process.env.MCNEXUS_LOGIN_MAX || 10, LOGIN_MAX_IP = +process.env.MCNEXUS_LOGIN_MAX_IP || 50;
// Behind a proxy (Vercel, nginx) the client IP and scheme come from X-Forwarded-For / X-Forwarded-Proto.
const TRUST_PROXY = process.env.MCNEXUS_TRUST_PROXY === '1';
const PG = !!process.env.DATABASE_URL;

// ---------- crypto / store ----------
const KEY = (() => {
  if (process.env.MCNEXUS_KEY) { const k = Buffer.from(process.env.MCNEXUS_KEY, 'hex'); if (k.length !== 32) throw new Error('MCNEXUS_KEY must be 64 hex characters (32 bytes).'); return k; }
  if (PG) throw new Error('MCNEXUS_KEY is required when DATABASE_URL is set: the encryption key never goes into the database.');
  fs.mkdirSync(DATA, { recursive: true });
  const f = path.join(DATA, '.key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
})();
const enc = (t) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv); const d = Buffer.concat([c.update(String(t), 'utf8'), c.final()]); return [iv, c.getAuthTag(), d].map(b => b.toString('base64')).join('.'); };
const dec = (s) => { const [iv, tag, d] = s.split('.').map(x => Buffer.from(x, 'base64')); const c = crypto.createDecipheriv('aes-256-gcm', KEY, iv); c.setAuthTag(tag); return Buffer.concat([c.update(d), c.final()]).toString('utf8'); };
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');

// JSON files in DATA by default; PostgreSQL when DATABASE_URL is set (server/store.js documents the contract).
let store = createStore({ dir: DATA }), storeReady = null;
const ready = () => storeReady || (storeReady = store.init().catch(e => { storeReady = null; throw e; }));
const useStore = (s) => { store = s; storeReady = null; };   // tests

const clampN = (v, lo, hi, d) => { const n = parseInt(v, 10); return isNaN(n) ? d : Math.min(hi, Math.max(lo, n)); };
// Stored settings sections + defaults. Scan limits are clamped here and applied to the client at scan start.
function withDefaults(raw = {}) {
  const sc = { mode: 'Full Assessment', modules: null, maxPages: ENV_LIM.maxPages, maxDetail: ENV_LIM.maxDetail, concurrency: ENV_LIM.concurrency, ...(raw.scan || {}) };
  sc.maxPages = clampN(sc.maxPages, 1, 500, 40); sc.maxDetail = clampN(sc.maxDetail, 10, 5000, 400); sc.concurrency = clampN(sc.concurrency, 1, 12, 6);
  return { rulesX: raw.rulesX || {}, naming: raw.naming == null ? null : raw.naming, scan: sc, report: { firm: '', disclaimer: '', format: 'PDF', logo: '', ...(raw.report || {}) }, data: { keepScans: 0, ...(raw.data || {}) } };
}
const settings = async () => withDefaults(await store.getSettings());
function applyLimits(sc) { MAX_PAGES = sc.maxPages; MAX_DETAIL = sc.maxDetail; CONCURRENCY = sc.concurrency; }

// ---------- utils ----------
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const xesc = (s) => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
async function pMap(items, n, fn) { const out = new Array(items.length); let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } })); return out; }

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

// ---------- scan: resumable steps ----------
// A scan is a job in the store, worked through in short steps so it survives restarts and fits short-lived
// serverless functions. Plan: org → security → per BU: bu (token check), data, sql, automation, journey, content
// (paged over several steps) → analyze. Each collecting step saves what it found as a gzipped part of the raw
// model; the analyze step merges the parts and runs analyze().
//   runStep(jobId)  advances a stored job by one step (holds a lease so no two workers run the same step)
//   runScan(...)    runs a whole scan in memory, no store (tests)
// Drivers: locally a background loop per job (kick); on Vercel (or MCNEXUS_SCAN_MODE=poll) each progress poll
// runs at most one step, so no request outlives a function.
const elapsed = (t0) => { const s = Math.floor((Date.now() - t0) / 1000); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
const STEP_LEASE = 10 * 60e3, CONTENT_PAGES_PER_STEP = 2;
let SCAN_POLL = process.env.MCNEXUS_SCAN_MODE === 'poll' || (!!process.env.VERCEL && process.env.MCNEXUS_SCAN_MODE !== 'background');
const setScanMode = (m) => { SCAN_POLL = m === 'poll'; };   // tests
const BU_STEPS = [['Data', 'data'], ['SQL', 'sql'], ['Automation', 'automation'], ['Journey', 'journey']];
const BU_MODS = ['Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages'];

function newScanState({ id, connId, n, scanId, by, opts = {} }) {
  const modules = opts.modules && opts.modules.length ? opts.modules.filter(m => MODULES.includes(m)) : MODULES;
  const st = {
    id, connId, n, scanId, by: by || '',
    opts: { modules, mids: opts.mids && opts.mids.length ? opts.mids.map(String) : null, mode: opts.mode || 'Full Assessment', naming: opts.naming || null, rulesX: opts.rulesX || {},
      limits: opts.limits || { maxPages: MAX_PAGES, maxDetail: MAX_DETAIL, concurrency: CONCURRENCY }, keepScans: +opts.keepScans || 0 },
    t0: Date.now(), pct: 0, cur: 'Starting', log: [], mods: {}, counts: { assets: 0, rels: 0, rules: 0, findings: 0, warnings: 0, errors: 0 }, cov: {},
    done: false, error: null, cancelled: false, partial: false, calls: 0, plan: [{ k: 'org' }], at: 0, cursor: null, parts: 0, org: null, tok: null,
  };
  MODULES.forEach(m => { st.cov[m] = { ok: 0, fail: 0, notes: [] }; st.mods[m] = modules.includes(m) ? 'QUEUED' : 'SKIPPED'; });
  return st;
}

// Helpers for one step. The SFMC token cache travels between steps encrypted in st.tok (never returned to clients).
function stepCtx(st, conn, api) {
  if (!api) { api = new SFMC({ sub: conn.sub, cid: conn.cid, sec: dec(conn.secEnc) }); if (st.tok) try { api.tokens = JSON.parse(dec(st.tok)); } catch { } }
  const L = (m) => { st.log.unshift({ t: elapsed(st.t0), m }); if (st.log.length > 300) st.log.pop(); };
  const mark = (m, ok, note) => { const c = st.cov[m]; ok ? c.ok++ : c.fail++; if (note && c.notes.length < 4 && !c.notes.includes(note)) c.notes.push(note); if (!ok) st.counts.warnings++; };
  const capped = (m, label, list) => { if (list && list.truncated) { mark(m, false, label + ': page limit reached (' + MAX_PAGES + ' pages)'); L(label + ': stopped at the page limit, results incomplete'); } return list; };
  return { api, conn, mods: new Set(st.opts.modules), L, mark, capped, setMod: (m, s) => { st.mods[m] = s; }, part: emptyM() };
}
const buOf = (st, mid) => st.org.bus.find(b => b.mid === mid);

const STEPS = {
  async org(st, x) {
    const { api, L, mark, capped, setMod, mods, conn } = x;
    st.cur = 'Organization'; setMod('Organization', 'RUNNING');
    const t = await api.token(conn.mid || null); L('Token issued · ' + scopeList(t.scope).length + ' scopes');
    const disc = await discoverBus(api, conn.mid || null);
    const entMid = disc.entId || (disc.bus[0] && disc.bus[0].mid);
    mark('Organization', !disc.err, disc.err && ('BU discovery: ' + disc.err.message)); capped('Organization', 'BU discovery', disc.truncated && { truncated: true });
    const allBus = disc.bus, wanted = new Set(st.opts.mids || allBus.map(b => b.mid));
    const bus = allBus.filter(b => wanted.has(b.mid));
    L('Discovered ' + plural(allBus.length, 'Business Unit') + (entMid ? ' under Enterprise ' + entMid : '') + ' · scanning ' + bus.length);
    setMod('Organization', disc.err || disc.truncated ? 'PARTIAL' : 'SUCCESS');
    st.org = { bus, allBus, entMid };
    const plan = [];
    if (mods.has('Security')) plan.push({ k: 'security' });
    for (const b of bus) {
      plan.push({ k: 'bu', mid: b.mid });
      for (const [m, k] of BU_STEPS) if (mods.has(m)) plan.push({ k, mid: b.mid });
      if (mods.has('Content') || mods.has('CloudPages')) plan.push({ k: 'content', mid: b.mid });
    }
    st.plan = [st.plan[0], ...plan, { k: 'analyze' }];
  },

  async security(st, x) {
    const { api, L, mark, capped, setMod, conn, part } = x;
    st.cur = 'Security'; setMod('Security', 'RUNNING');
    try { part.users = capped('Security', 'Users', await api.retrieveSafe(conn.mid || null, 'AccountUser', ['ID', 'UserID', 'Name', 'Email', 'ActiveFlag', 'IsAPIUser', 'LastSuccessfulLogin', 'CreatedDate', 'Client.ID'], ['ID', 'UserID', 'Name', 'ActiveFlag', 'LastSuccessfulLogin'], { all: true })); mark('Security', true); L('Collected ' + plural(part.users.length, 'user') + ' (SOAP AccountUser)'); }
    catch (e) { mark('Security', false, 'Users: ' + e.message); L('Users unavailable — ' + e.message); }
  },

  // Token check for a BU; without access, its module steps are dropped from the plan.
  async bu(st, x, step) {
    const b = buOf(st, step.mid);
    try { await x.api.token(b.mid); }
    catch (e) {
      x.L(b.name + ': no access for this package — ' + e.message);
      BU_MODS.forEach(m => x.mods.has(m) && x.mark(m, false, b.name + ': ' + e.message));
      st.plan = st.plan.filter((s, i) => i <= st.at || s.mid !== b.mid);
    }
  },

  async data(st, x, step) {
    const { api, L, mark, capped, setMod, part: M } = x, b = buOf(st, step.mid), mid = b.mid, B = b.name, tag = (o) => Object.assign(o, { mid, bu: B });
    st.cur = 'Data · ' + B; setMod('Data', 'RUNNING');
    try {
      const des = capped('Data', B + ' DEs', await api.retrieveSafe(mid, 'DataExtension', ['ObjectID', 'CustomerKey', 'Name', 'IsSendable', 'CategoryID', 'CreatedDate', 'ModifiedDate', 'DataRetentionPeriodLength', 'DataRetentionPeriod', 'RowBasedRetention', 'RetainUntil', 'DeleteAtEndOfRetentionPeriod', 'Description', 'SendableDataExtensionField.Name', 'SendableSubscriberField.Name'], ['ObjectID', 'CustomerKey', 'Name', 'IsSendable', 'CategoryID', 'CreatedDate', 'ModifiedDate']));
      des.forEach(d => M.des.push(tag({ objectId: d.ObjectID, ck: d.CustomerKey, name: d.Name, sendable: bool(d.IsSendable), categoryId: d.CategoryID, created: d.CreatedDate, modified: d.ModifiedDate, retLen: d.DataRetentionPeriodLength, retPeriod: d.DataRetentionPeriod, rowRet: bool(d.RowBasedRetention), retainUntil: d.RetainUntil, deleteAtEnd: bool(d.DeleteAtEndOfRetentionPeriod), retKnown: d.DataRetentionPeriodLength !== undefined || d.RowBasedRetention !== undefined, desc: d.Description, sendField: dig(d, 'SendableDataExtensionField', 'Name'), subField: dig(d, 'SendableSubscriberField', 'Name') })));
      L(B + ': ' + plural(des.length, 'Data Extension') + ' (SOAP)'); st.counts.assets += des.length; mark('Data', true); if (!des.truncated) M.deDone.push(mid);
      try {
        const fs_ = capped('Data', B + ' DE fields', await api.retrieveSafe(mid, 'DataExtensionField', ['Name', 'IsPrimaryKey', 'FieldType', 'IsRequired', 'DataExtension.CustomerKey'], ['Name', 'IsPrimaryKey', 'DataExtension.CustomerKey']));
        // A cut-off field list can end mid-DE; leave fields uncollected rather than report a false "no primary key".
        if (!fs_.truncated) fs_.forEach(f => { const k = mid + '|' + dig(f, 'DataExtension', 'CustomerKey'); (M.fields[k] = M.fields[k] || []).push({ name: f.Name, pk: bool(f.IsPrimaryKey), type: f.FieldType }); });
        L(B + ': ' + fs_.length.toLocaleString('en-US') + ' DE fields');
      } catch (e) { mark('Data', false, B + ' fields: ' + e.message); }
      try { const fo = await api.retrieve(mid, 'DataFolder', ['ID', 'Name', 'ParentFolder.ID', 'ContentType']); fo.forEach(f => { M.folders[mid + '|' + f.ID] = { name: f.Name, parent: dig(f, 'ParentFolder', 'ID') }; }); } catch { }
    } catch (e) { mark('Data', false, B + ': ' + e.message); L(B + ': Data Extensions failed — ' + e.message); }
  },

  async sql(st, x, step) {
    const { api, L, mark, capped, setMod, part: M } = x, b = buOf(st, step.mid), mid = b.mid, B = b.name, tag = (o) => Object.assign(o, { mid, bu: B });
    st.cur = 'SQL · ' + B; setMod('SQL', 'RUNNING');
    try {
      const qs = capped('SQL', B + ' queries', await api.retrieveSafe(mid, 'QueryDefinition', ['ObjectID', 'CustomerKey', 'Name', 'QueryText', 'TargetType', 'DataExtensionTarget.Name', 'DataExtensionTarget.CustomerKey', 'TargetUpdateType', 'CreatedDate', 'ModifiedDate', 'CategoryID'], ['ObjectID', 'CustomerKey', 'Name', 'QueryText', 'DataExtensionTarget.Name', 'DataExtensionTarget.CustomerKey', 'TargetUpdateType', 'CreatedDate', 'ModifiedDate']));
      qs.forEach(q => M.queries.push(tag({ objectId: q.ObjectID, ck: q.CustomerKey, name: q.Name, text: q.QueryText || '', targetName: dig(q, 'DataExtensionTarget', 'Name'), targetCk: dig(q, 'DataExtensionTarget', 'CustomerKey'), update: q.TargetUpdateType, created: q.CreatedDate, modified: q.ModifiedDate })));
      L(B + ': ' + plural(qs.length, 'SQL Query') + ' (SOAP)'); st.counts.assets += qs.length; mark('SQL', true);
    } catch (e) { mark('SQL', false, B + ': ' + e.message); L(B + ': SQL failed — ' + e.message); }
  },

  async automation(st, x, step) {
    const { api, L, mark, capped, setMod, part: M } = x, b = buOf(st, step.mid), mid = b.mid, B = b.name, tag = (o) => Object.assign(o, { mid, bu: B });
    st.cur = 'Automation · ' + B; setMod('Automation', 'RUNNING');
    try {
      const list = capped('Automation', B + ' automations', await api.restPages(mid, '/automation/v1/automations', { size: 200 }));
      const det = await pMap(list.slice(0, MAX_DETAIL), CONCURRENCY, a => api.rest(mid, 'GET', '/automation/v1/automations/' + a.id).catch(() => a));
      det.concat(list.slice(MAX_DETAIL)).forEach(a => {
        const sid = a.statusId != null ? a.statusId : a.status;
        const status = typeof a.status === 'string' && isNaN(+a.status) ? a.status : (AUTO_STATUS[sid] || 'Unknown');
        const steps = arr(a.steps).flatMap(s => arr(s.activities).map(y => ({ name: y.name, typeId: y.objectTypeId, objectId: y.activityObjectId, step: s.step || s.stepNumber })));
        M.autos.push(tag({ id: a.id, key: a.key || a.customerKey, name: a.name, status, lastRun: a.lastRunTime, lastRunStatus: a.lastRunStatus, schedule: a.schedule, steps, created: a.createdDate, modified: a.modifiedDate || a.lastSavedDate, detailed: !!a.steps }));
      });
      if (list.length > MAX_DETAIL) mark('Automation', false, B + ': detail limited to ' + MAX_DETAIL + ' automations');
      L(B + ': ' + plural(list.length, 'Automation') + ' · ' + M.autos.reduce((n, a) => n + a.steps.length, 0) + ' activities (REST)'); st.counts.assets += list.length; mark('Automation', true);
    } catch (e) { mark('Automation', false, B + ': ' + e.message); L(B + ': Automations failed — ' + e.message); }
    try { const im = capped('Automation', B + ' imports', await api.restPages(mid, '/automation/v1/imports', { size: 200 })); im.forEach(i => M.imports.push(tag({ id: i.importDefinitionId || i.id, name: i.name, ck: i.customerKey, destId: i.destinationObjectId, destName: i.destinationName, modified: i.modifiedDate }))); st.counts.assets += im.length; } catch (e) { mark('Automation', false, B + ' imports: ' + e.message); }
    try { const sc = capped('Automation', B + ' scripts', await api.restPages(mid, '/automation/v1/scripts', { size: 200 })); sc.forEach(s => M.scripts.push(tag({ id: s.ssjsActivityId || s.id, name: s.name, ck: s.key, text: s.script || '', modified: s.modifiedDate, created: s.createdDate }))); st.counts.assets += sc.length; } catch (e) { mark('Automation', false, B + ' scripts: ' + e.message); }
  },

  async journey(st, x, step) {
    const { api, L, mark, capped, setMod, part: M } = x, b = buOf(st, step.mid), mid = b.mid, B = b.name, tag = (o) => Object.assign(o, { mid, bu: B });
    st.cur = 'Journey · ' + B; setMod('Journey', 'RUNNING');
    try {
      const js = capped('Journey', B + ' journeys', await api.restPages(mid, '/interaction/v1/interactions?mostRecentVersionOnly=false', { size: 100, sizeParam: '$pageSize' }));
      const evs = capped('Journey', B + ' event definitions', await api.restPages(mid, '/interaction/v1/eventDefinitions', { size: 100, sizeParam: '$pageSize' }).catch(() => []));
      evs.forEach(e => M.evs.push(tag({ key: e.eventDefinitionKey, deId: e.dataExtensionId, deName: e.dataExtensionName, type: e.type })));
      const byKey = {}; js.forEach(j => { const k = j.key || j.id; (byKey[k] = byKey[k] || []).push(j); });
      const latest = Object.values(byKey).map(v => v.sort((a, c) => (c.version || 0) - (a.version || 0))[0]);
      const det = await pMap(latest.slice(0, MAX_DETAIL), CONCURRENCY, j => api.rest(mid, 'GET', '/interaction/v1/interactions/' + j.id).catch(() => j));
      det.forEach(j => {
        const vers = byKey[j.key || j.id] || [j];
        const trig = arr(j.triggers)[0] || {};
        const evKey = dig(trig, 'metaData', 'eventDefinitionKey') || dig(trig, 'configurationArguments', 'eventDefinitionKey');
        const emails = arr(j.activities).filter(a => /EMAIL/i.test(a.type || '')).map(a => ({ name: a.name, emailId: dig(a, 'configurationArguments', 'triggeredSend', 'emailId'), subject: dig(a, 'configurationArguments', 'triggeredSend', 'emailSubject') }));
        M.journeys.push(tag({ id: j.id, key: j.key || j.id, name: j.name, version: j.version, status: j.status, entryMode: j.entryMode, evKey, emails, acts: arr(j.activities).length, goal: !!(j.goals && j.goals.length), created: j.createdDate, modified: j.modifiedDate, versions: vers.map(v => ({ v: v.version, status: v.status, modified: v.modifiedDate })) }));
      });
      if (latest.length > MAX_DETAIL) mark('Journey', false, B + ': detail limited to ' + MAX_DETAIL + ' journeys');
      L(B + ': Journey API returned ' + plural(latest.length, 'journey') + ' · ' + js.length + ' versions'); st.counts.assets += latest.length; mark('Journey', true);
    } catch (e) { mark('Journey', false, B + ': ' + e.message); L(B + ': Journeys failed — ' + e.message); }
  },

  // Content Builder query, CONTENT_PAGES_PER_STEP pages per step; returns { more: cursor } until done.
  async content(st, x, step, cursor) {
    const { api, L, mark, setMod, mods, part: M } = x, b = buOf(st, step.mid), mid = b.mid, B = b.name, tag = (o) => Object.assign(o, { mid, bu: B });
    const types = [...(mods.has('Content') ? CONTENT_TYPES : []), ...(mods.has('CloudPages') ? PAGE_TYPES : [])];
    st.cur = 'Content · ' + B; if (mods.has('Content')) setMod('Content', 'RUNNING'); if (mods.has('CloudPages')) setMod('CloudPages', 'RUNNING');
    const c = cursor || { page: 1, got: 0, total: null };
    try {
      let end = false, cut = false;
      for (let i = 0; i < CONTENT_PAGES_PER_STEP; i++, c.page++) {
        if (c.page > MAX_PAGES) { cut = true; break; }
        const j = await api.rest(mid, 'POST', '/asset/v1/content/assets/query', { page: { page: c.page, pageSize: 200 }, query: { property: 'assetType.name', simpleOperator: 'in', value: types }, fields: ['id', 'customerKey', 'name', 'assetType', 'category', 'modifiedDate', 'createdDate', 'content', 'views', 'legacyData', 'status'] });
        const items = j.items || []; c.total = j.count != null ? j.count : c.total; c.got += items.length; st.counts.assets += items.length;
        items.forEach(a => {
          const tn = dig(a, 'assetType', 'name') || '';
          let text = (a.content || '') + '\n' + (a.views ? JSON.stringify(a.views) : ''); if (text.length > 300000) text = text.slice(0, 300000);
          M.content.push(tag({ id: String(a.id), ck: a.customerKey, name: a.name, typeName: tn, isPage: PAGE_TYPES.includes(tn), folder: dig(a, 'category', 'name'), modified: a.modifiedDate, created: a.createdDate, legacyId: dig(a, 'legacyData', 'legacyId'), status: dig(a, 'status', 'name'), text }));
        });
        if (!items.length || (c.total != null ? c.got >= c.total : items.length < 200)) { end = true; break; }
      }
      if (!end && !cut) return { more: c };
      if (cut || (c.total != null && c.got < c.total)) { ['Content', 'CloudPages'].forEach(m => mods.has(m) && mark(m, false, B + ': ' + c.got + ' of ' + (c.total != null ? c.total : '?') + ' assets paged (page limit)')); }
      L(B + ': Content Builder ' + c.got.toLocaleString('en-US') + ' assets paged');
      if (mods.has('Content')) mark('Content', true); if (mods.has('CloudPages')) mark('CloudPages', true);
    } catch (e) { ['Content', 'CloudPages'].forEach(m => mods.has(m) && mark(m, false, B + ': ' + e.message)); L(B + ': Content failed — ' + e.message); }
  },
};

// Module statuses before analysis; Governance after.
function beginAnalysis(st, x) {
  const { mods, setMod } = x;
  ['Security', 'Data', 'SQL', 'Automation', 'Journey', 'Content', 'CloudPages'].forEach(m => { if (!mods.has(m)) return; const c = st.cov[m]; setMod(m, !c.ok ? 'FAILED' : c.fail ? 'PARTIAL' : 'SUCCESS'); });
  st.cur = 'Analysis'; setMod('Governance', mods.has('Governance') ? 'RUNNING' : 'SKIPPED');
  const { bus, allBus, entMid } = st.org;
  return { bus, allBus, entMid, mods, cov: st.cov, naming: st.opts.naming, rulesX: st.opts.rulesX || {} };
}
function endAnalysis(st, x) { if (x.mods.has('Governance')) { x.mark('Governance', true); x.setMod('Governance', 'SUCCESS'); } }
function finishScan(st, x, M) { const o = beginAnalysis(st, x); const ds = analyze(M, { ...o, L: x.L, job: st }); endAnalysis(st, x); return ds; }

// Analyses stored parts in a worker thread (falls back to this thread if a worker can't start).
function analyzeInWorker(parts, o) {
  return new Promise((resolve, reject) => {
    let w; try { w = new Worker(path.join(__dirname, 'analyze-worker.js'), { workerData: { parts, o } }); } catch (e) { console.error('Analysis worker unavailable, analysing inline:', e.message); return resolve(analyzeParts(parts, o)); }
    w.once('message', (r) => r.ok ? resolve(r) : reject(new Error('Analysis failed — ' + r.error)));
    w.once('error', reject);
    w.once('exit', (code) => { if (code !== 0) reject(new Error('Analysis worker stopped (exit code ' + code + ')')); });
  });
}
async function finishScanParts(st, x, parts) {
  const r = await analyzeInWorker(parts, { ...beginAnalysis(st, x), counts: st.counts });
  r.log.forEach(x.L); Object.assign(st.counts, r.counts);
  endAnalysis(st, x); return r.ds;
}

// Whole scan in memory with one SFMC client. Throws on a fatal error, like a failed job.
async function runScan(job, conn, opts) {
  const cancelled = !!job.cancelled;
  const st = Object.assign(job, newScanState({ id: job.id || 'mem', connId: conn.id, n: job.n || 1, scanId: job.scanId || '#001', by: job.by, opts }));
  st.cancelled = cancelled;
  const M = emptyM(); let api = null;
  for (;;) {
    if (st.cancelled) throw new ApiErr('Cancelled by user', 0, 'cancel');
    const x = stepCtx(st, conn, api); api = x.api;
    const step = st.plan[st.at];
    if (step.k === 'analyze') { st.calls = api.calls; return { ds: finishScan(st, x, M), api: { calls: api.calls } }; }
    const r = await STEPS[step.k](st, x, step, st.cursor);
    mergeM(M, x.part);
    if (r && r.more) st.cursor = r.more; else { st.at++; st.cursor = null; }
  }
}

async function saveScanResult(st, ds, L) {
  const sum = { n: st.n, id: st.scanId, date: fmtD(new Date()), iso: new Date().toISOString(), ...ds.summary, mode: String(st.opts.mode || 'Full').split(' ')[0], by: st.by, dur: elapsed(st.t0), calls: st.calls };
  delete ds.summary;
  if (!(await store.addScan(st.connId, sum, { ...ds, scan: sum }))) throw new ApiErr('The connection was deleted during the scan — snapshot discarded', 0, 'gone');
  await store.pruneScans(st.connId, st.opts.keepScans);
  await store.updateConnection(st.connId, { status: 'Connected' });
  st.pct = 100; st.cur = 'Complete'; st.partial = ds.limits.length > 2; st.done = true;
  L('Scores calculated · snapshot ' + st.scanId + ' stored · ' + st.calls + ' API calls');
}

// Advances a stored job by one step. Returns the new state, or null when the job isn't runnable now
// (finished, unknown, or another worker holds the lease).
async function runStep(jobId) {
  const job = await store.claimJob(jobId, Date.now(), STEP_LEASE); if (!job) return null;
  const st = job.state;
  const log = (m) => { st.log.unshift({ t: elapsed(st.t0), m }); if (st.log.length > 300) st.log.pop(); };
  try {
    if (job.cancel) throw new ApiErr('Cancelled by user', 0, 'cancel');
    const conn = await store.getConnection(st.connId); if (!conn) throw new ApiErr('The connection was deleted during the scan — snapshot discarded', 0, 'gone');
    applyLimits(st.opts.limits);
    const x = stepCtx(st, conn), step = st.plan[st.at];
    if (step.k === 'analyze') {
      const parts = []; for (let i = 0; i < st.parts; i++) parts.push(await store.getJobPart(jobId, i));   // still compressed
      await saveScanResult(st, await finishScanParts(st, x, parts), log);
    } else {
      const r = await STEPS[step.k](st, x, step, st.cursor);
      st.calls += x.api.calls; st.tok = enc(JSON.stringify(x.api.tokens));
      // Part first, then state: if we die in between, the retry rewrites the same part number.
      if (hasData(x.part)) { await store.putJobPart(jobId, st.parts, packPart(x.part)); st.parts++; }
      if (r && r.more) st.cursor = r.more; else { st.at++; st.cursor = null; }
      st.pct = Math.min(97, Math.round(100 * st.at / st.plan.length));
    }
  } catch (e) {
    st.error = e.message; st.done = true; st.counts.errors++; log('Scan stopped — ' + e.message);
    if (e.code === 'cancel') st.cancelled = true;
    if (e.status === 401 || e.code === 'auth') await store.updateConnection(st.connId, { status: 'Needs re-auth' }).catch(() => { });
  }
  if (st.done) st.tok = null;
  await store.saveJob(jobId, st, !st.done ? 'running' : st.error ? 'failed' : 'done', Date.now());
  if (st.done) await store.deleteJobParts(jobId);
  return st;
}

// Background driver (local / long-running server): steps a job to the end. One loop per job per process.
const driving = new Set();
function kick(jobId) {
  if (driving.has(jobId)) return; driving.add(jobId);
  (async () => {
    try {
      for (;;) {
        const st = await runStep(jobId); if (st && !st.done) continue; if (st) break;
        // Not claimable: finished, or a lease is held (e.g. by a process that died). Retry when the lease lapses.
        const j = await store.getJob(jobId);
        if (j && j.status === 'running') setTimeout(() => kick(jobId), Math.max(1000, (j.leaseUntil || 0) - Date.now() + 500)).unref();
        break;
      }
    } catch (e) { console.error('Scan ' + jobId + ':', e); } finally { driving.delete(jobId); }
  })();
}
// Background mode: pick up jobs that were running when the server last stopped.
async function resumeRunningJobs() { if (SCAN_POLL) return 0; const js = await store.listRunningJobs(); js.forEach(j => kick(j.id)); return js.length; }
const pubJob = (j) => { const s = j.state; return { connId: s.connId, scanId: s.scanId, n: s.n, pct: s.pct, cur: s.cur, mods: s.mods, counts: s.counts, done: s.done, error: s.error, cancelled: !!(j.cancel || s.cancelled), partial: s.partial, log: s.log.slice(0, 60), elapsed: elapsed(s.t0) }; };

// ---------- HTTP ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.jsx': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf', '.md': 'text/plain; charset=utf-8' };
function send(req, res, code, obj, headers = {}) {
  let body = typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj);
  const h = { 'content-type': typeof obj === 'object' && !Buffer.isBuffer(obj) ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers };
  if (body.length > 2048 && /gzip/.test(req.headers['accept-encoding'] || '')) { body = zlib.gzipSync(body); h['content-encoding'] = 'gzip'; }
  res.writeHead(code, h); res.end(body);
}
const readBody = (req) => new Promise((ok, bad) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 2e6) { bad(new Error('Body too large')); req.destroy(); } else c.push(d); }); req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c).toString('utf8')) : {}); } catch { bad(new Error('Invalid JSON')); } }); });
const cookie = (req, k) => ((req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(k + '=')) || '').slice(k.length + 1);
const tokHash = (t) => crypto.createHash('sha256').update(t).digest('hex');
const clientIp = (req) => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '';
const isHttps = (req) => !!req.socket.encrypted || (TRUST_PROXY && /^https$/i.test(String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim()));
const sessionCookie = (req, tok, maxAge) => `mcx=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` + (isHttps(req) ? '; Secure' : '');
// Valid session for the request's cookie, or null. Slides the idle expiry, never past created + SESSION_MAX.
async function session(req) {
  const tok = cookie(req, 'mcx'); if (!/^[0-9a-f]{64}$/.test(tok)) return null;
  const hash = tokHash(tok), s = await store.getSession(hash), now = Date.now();
  if (!s) return null;
  if (s.expires <= now) { await store.deleteSession(hash); return null; }
  if (now - s.seen >= SESSION_TOUCH) { s.seen = now; s.expires = Math.min(now + SESSION_IDLE, s.created + SESSION_MAX); await store.touchSession(hash, s.seen, s.expires); }
  return s;
}
async function startSession(req, email) {
  const tok = crypto.randomBytes(32).toString('hex'), now = Date.now();
  await store.createSession({ hash: tokHash(tok), email, created: now, seen: now, expires: now + Math.min(SESSION_IDLE, SESSION_MAX), ua: String(req.headers['user-agent'] || '').slice(0, 300), ip: clientIp(req) });
  await store.purgeExpired(now);
  return sessionCookie(req, tok, Math.floor(SESSION_MAX / 1000));
}
const subOk = (s) => /^[a-z0-9-]{10,60}$/.test(s || '');
const parseSub = (v) => { const t = String(v || '').trim().toLowerCase(); const m = t.match(/^https?:\/\/([a-z0-9-]+)\.(auth|rest|soap)\.marketingcloudapis\.com/); return m ? m[1] : t.replace(/[^a-z0-9-]/g, ''); };

function publicConn(c, list = [], run = null) {
  const last = list[list.length - 1];
  return { id: c.id, name: c.name, env: c.env, mid: c.mid || '—', sub: c.sub, bus: (c.buList || []).filter(b => !(c.buOff || {})[b.mid]).length || (c.buList || []).length, buList: c.buList || [], buOff: c.buOff || {}, status: c.status || 'Connected', validated: c.validated || '—', access: c.access || [], scopes: c.scopes || [], cidHint: c.cid ? c.cid.slice(0, 4) + '…' + c.cid.slice(-4) : '—', secretUpdated: c.secretUpdated ? fmtD(c.secretUpdated) : (c.created ? fmtD(c.created) : '—'),
    health: last ? last.health : 0, coverage: last ? last.cov : 0, last: last ? last.date : 'Never', scan: last ? last.id : '—', crit: last ? last.sev[0] : 0, high: last ? last.sev[1] : 0, scans: list.length,
    running: run ? { jobId: run.id, scanId: run.scanId, pct: run.pct } : null };
}
const pubConn = async (c, runs) => publicConn(c, await store.listScans(c.id), (runs || await store.listRunningJobs()).find(j => j.connId === c.id));
const stamp = () => fmtD(new Date()) + ' ' + new Date().toTimeString().slice(0, 5);
const pwOk = (u, pw) => crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
// Unknown emails still pay for one scrypt, so response time doesn't reveal which accounts exist.
const NO_USER = { salt: '00'.repeat(16), hash: '00'.repeat(64) };

async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  if (p === '/api/health') return send(req, res, 200, { ok: true, version: VERSION, ruleset: RULESET, firstRun: (await store.countUsers()) === 0 });
  if (p === '/api/session') { const s = await session(req); const u = s && await store.getUser(s.email); return send(req, res, 200, { user: u ? { email: u.email, name: u.name, role: u.role } : null }); }
  if (p === '/api/login' && m === 'POST') {
    const b = await readBody(req); const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return send(req, res, 400, { error: 'Enter a valid work email.' });
    const now = Date.now(), keys = ['email:' + email, 'ip:' + clientIp(req)], caps = [LOGIN_MAX_EMAIL, LOGIN_MAX_IP];
    const over = (await Promise.all(keys.map(k => store.countFailures(k, now, LOGIN_WINDOW)))).filter((f, i) => f.count >= caps[i]);
    if (over.length) { const wait = Math.max(1, Math.ceil((Math.max(...over.map(f => f.resetAt)) - now) / 1000)); return send(req, res, 429, { error: 'Too many sign-in attempts. Try again in ' + Math.ceil(wait / 60) + ' min.' }, { 'retry-after': String(wait) }); }
    let u = await store.getUser(email);
    if ((await store.countUsers()) === 0) {
      if (pw.length < 8) return send(req, res, 400, { error: 'First sign-in creates the owner account — choose a password of 8+ characters.' });
      const salt = crypto.randomBytes(16).toString('hex');
      u = { email, name: email.split('@')[0].replace(/[._-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), role: 'Owner', salt, hash: hashPw(pw, salt) };
      if (!(await store.createFirstOwner(u))) { await sleep(600); return send(req, res, 401, { error: 'Email or password not recognised.' }); }   // lost a first-run race
    }
    else if (!pwOk(u || NO_USER, pw) || !u) {
      await Promise.all(keys.map(k => store.recordFailure(k, Date.now(), LOGIN_WINDOW)));
      await sleep(600); return send(req, res, 401, { error: 'Email or password not recognised.' });
    }
    else await store.clearFailures(keys[0]);

    return send(req, res, 200, { user: { email: u.email, name: u.name, role: u.role } }, { 'set-cookie': await startSession(req, email) });
  }
  if (p === '/api/logout') { const tok = cookie(req, 'mcx'); if (/^[0-9a-f]{64}$/.test(tok)) await store.deleteSession(tokHash(tok)); return send(req, res, 200, { ok: true }, { 'set-cookie': sessionCookie(req, '', 0) }); }
  const s = await session(req); if (!s) return send(req, res, 401, { error: 'Not signed in' });
  const me = (await store.getUser(s.email)) || { name: s.email };

  if (p === '/api/settings') {
    if (m === 'PUT') {
      const b = await readBody(req); const cur = await settings(); const patch = {};
      if (b.rulesX) patch.rulesX = b.rulesX; if (b.naming) patch.naming = b.naming;
      if (b.scan) { const sc = b.scan; patch.scan = withDefaults({ scan: { ...cur.scan, mode: ['Quick Scan', 'Full Assessment', 'Custom Assessment'].includes(sc.mode) ? sc.mode : cur.scan.mode, modules: Array.isArray(sc.modules) ? sc.modules.filter(x => MODULES.includes(x)) : null, maxPages: sc.maxPages, maxDetail: sc.maxDetail, concurrency: sc.concurrency } }).scan; }
      if (b.report) { const r = b.report; if (r.logo && (String(r.logo).length > 400000 || !/^data:image\/(png|jpeg|svg\+xml);base64,/.test(r.logo))) return send(req, res, 400, { error: 'Logo must be a PNG, JPG or SVG under 300 KB.' }); patch.report = { firm: String(r.firm || '').slice(0, 120), disclaimer: String(r.disclaimer || '').slice(0, 2000), format: ['PDF', 'Excel', 'HTML'].includes(r.format) ? r.format : 'PDF', logo: r.logo || '' }; }
      if (b.data) patch.data = { keepScans: clampN(b.data.keepScans, 0, 1000, 0) };
      if (Object.keys(patch).length) await store.putSettings(patch);
      if (patch.data) for (const c of await store.listConnections()) await store.pruneScans(c.id, patch.data.keepScans);
    }
    return send(req, res, 200, { ...(await settings()), rules: RULES, modules: MODULES });
  }
  if (p === '/api/me/password' && m === 'POST') {
    const b = await readBody(req); const u = await store.getUser(s.email); if (!u) return send(req, res, 404, { error: 'User not found' });
    if (!pwOk(u, String(b.current || ''))) { await sleep(600); return send(req, res, 400, { error: 'Current password is not correct.' }); }
    if (String(b.next || '').length < 8) return send(req, res, 400, { error: 'New password must be 8+ characters.' });
    const salt = crypto.randomBytes(16).toString('hex'); await store.setPassword(u.email, salt, hashPw(String(b.next), salt));
    await store.deleteSessions(s.email, s.hash);
    return send(req, res, 200, { ok: true });
  }
  if (p === '/api/me/sessions') { const now = Date.now(); return send(req, res, 200, { sessions: (await store.listSessions(s.email)).filter(x => x.expires > now).map(x => ({ id: x.hash.slice(0, 6).toUpperCase(), current: x.hash === s.hash, created: x.created, seen: x.seen, ua: x.ua || '', ip: x.ip || '' })) }); }
  if (p === '/api/me/signout-others' && m === 'POST') return send(req, res, 200, { ended: await store.deleteSessions(s.email, s.hash) });
  if (p === '/api/about') {
    const st = await store.stats(), up = Math.floor((Date.now() - STARTED) / 1000), size = st.bytes;
    return send(req, res, 200, { version: VERSION, ruleset: RULESET, node: process.version, platform: process.platform + ' ' + process.arch, started: new Date(STARTED).toISOString(), uptime: Math.floor(up / 86400) + 'd ' + Math.floor(up % 86400 / 3600) + 'h ' + Math.floor(up % 3600 / 60) + 'm', storage: PG ? 'PostgreSQL' : 'JSON files', dataDir: st.location, dataSize: size > 1e6 ? (size / 1e6).toFixed(1) + ' MB' : Math.ceil(size / 1e3) + ' KB', connections: st.connections, scans: st.scans, users: st.users, keySource: process.env.MCNEXUS_KEY ? 'MCNEXUS_KEY environment variable' : 'server/data/.key (generated)', listen: HOST + ':' + PORT });
  }
  if (p === '/api/connections' && m === 'GET') { const runs = await store.listRunningJobs(); return send(req, res, 200, { connections: await Promise.all((await store.listConnections()).map(c => pubConn(c, runs))) }); }
  if (p === '/api/connections/test' && m === 'POST') {
    const b = await readBody(req); const sub = parseSub(b.sub); let sec = b.sec;
    if (!sec && b.reauth) { const c = await store.getConnection(b.reauth); if (c) sec = dec(c.secEnc); }
    if (!subOk(sub) || !b.cid || !sec) return send(req, res, 400, { error: 'Subdomain, Client ID and Client Secret are required.' });
    return send(req, res, 200, await testConnection({ sub, cid: String(b.cid).trim(), sec: String(sec).trim(), mid: String(b.mid || '').trim() || null }));
  }
  if (p === '/api/connections' && m === 'POST') {
    const b = await readBody(req); const sub = parseSub(b.sub);
    const old = b.reauth ? await store.getConnection(b.reauth) : null, o = old || {};
    if (!old && (!subOk(sub) || !b.cid || !b.sec)) return send(req, res, 400, { error: 'Missing package details.' });
    const fields = { name: String(b.name || o.name || 'SFMC org').trim(), env: b.env || o.env || 'Production', sub: sub || o.sub, cid: String(b.cid || o.cid).trim(), mid: String(b.mid || o.mid || '').trim(), buOff: b.buOff || o.buOff || {}, buList: b.bus && b.bus.length ? b.bus : (o.buList || []), status: 'Connected', validated: stamp() };
    if (b.sec) Object.assign(fields, { secEnc: enc(String(b.sec).trim()), secretUpdated: new Date().toISOString() });
    let c;
    if (old) c = await store.updateConnection(old.id, fields);
    else { const id = 'c' + crypto.randomBytes(5).toString('hex'); await store.createConnection({ id, created: new Date().toISOString(), ...fields }); c = await store.getConnection(id); }
    return send(req, res, 200, { connection: await pubConn(c) });
  }
  let mm = p.match(/^\/api\/connections\/([\w-]+)(?:\/(\w+))?$/);
  if (mm) {
    const c = await store.getConnection(mm[1]); if (!c) return send(req, res, 404, { error: 'Connection not found' });
    const sub = mm[2];
    if (!sub && m === 'DELETE') { await store.deleteConnection(c.id); return send(req, res, 200, { ok: true }); }
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
      const upd = { ...next };
      if (sec) Object.assign(upd, { secEnc: enc(sec), secretUpdated: new Date().toISOString() });
      if (test) Object.assign(upd, { status: 'Connected', validated: stamp(), scopes: test.scopes || c.scopes, ...(test.bus && test.bus.length ? { buList: test.bus } : {}) });
      return send(req, res, 200, { connection: await pubConn(await store.updateConnection(c.id, upd)), test, credsChanged });
    }
    if (sub === 'scans' && m === 'DELETE') { const n = await store.clearScans(c.id); await store.putTriage(c.id, {}); return send(req, res, 200, { deleted: n }); }
    if (sub === 'export') {
      const list = await store.listScans(c.id), scans = [];
      for (const x of list) scans.push({ summary: x, snapshot: await store.getSnapshot(c.id, x.n) });
      const out = { exported: new Date().toISOString(), app: 'MCNexus ' + VERSION, connection: publicConn(c, list), scans, triage: await store.getTriage(c.id) };
      return send(req, res, 200, JSON.stringify(out), { 'content-type': 'application/json; charset=utf-8', 'content-disposition': `attachment; filename="MCNexus_${String(c.name).replace(/[^A-Za-z0-9]+/g, '_')}_export.json"` });
    }
    if (sub === 'access' && m === 'POST') { const r = await accessAssessment(c); const nc = await store.updateConnection(c.id, { access: r.rows, scopes: r.scopes, status: r.status, validated: stamp() }); return send(req, res, 200, { connection: await pubConn(nc) }); }
    if (sub === 'triage' && m === 'PUT') { const b = await readBody(req); await store.putTriage(c.id, b.fx || {}); return send(req, res, 200, { ok: true }); }
    if (sub === 'dataset') {
      const list = await store.listScans(c.id); const want = url.searchParams.get('scan'); const sm = (want && list.find(x => x.id === want)) || list[list.length - 1];
      const ds = sm ? await store.getSnapshot(c.id, sm.n) : null;
      return send(req, res, 200, { connection: publicConn(c, list), scans: list, scan: sm || null, buList: c.buList || [], triage: await store.getTriage(c.id), owners: (await store.listUsers()).map(u => u.name + ' · ' + u.role), ...(ds || {}) });
    }
    if (sub === 'compare') {
      const list = await store.listScans(c.id); const A = list.find(x => x.id === url.searchParams.get('a')), B = list.find(x => x.id === url.searchParams.get('b'));
      if (!A || !B) return send(req, res, 400, { error: 'Pick two scans' });
      const fa = ((await store.getSnapshot(c.id, A.n)) || {}).findings || [], fb = ((await store.getSnapshot(c.id, B.n)) || {}).findings || [];
      const ia = new Set(fa.map(f => f.id)), ib = new Set(fb.map(f => f.id));
      const row = (f) => [f.sev, f.rule, f.title + ' · ' + f.obj];
      const added = fb.filter(f => !ia.has(f.id)), resolved = fa.filter(f => !ib.has(f.id));
      return send(req, res, 200, { added: added.length, resolved: resolved.length, newF: added.slice(0, 12).map(row), resF: resolved.slice(0, 12).map(row) });
    }
  }
  if (p === '/api/scans' && m === 'POST') {
    const b = await readBody(req); const c = await store.getConnection(b.connId); if (!c) return send(req, res, 404, { error: 'Connection not found' });
    const [list, st] = await Promise.all([store.listScans(c.id), settings()]);
    const n = (list.length ? list[list.length - 1].n : 0) + 1, id = '#' + String(n).padStart(3, '0'), jobId = 'j' + crypto.randomBytes(5).toString('hex');
    const state = newScanState({ id: jobId, connId: c.id, n, scanId: id, by: me.name, opts: { modules: b.modules, mids: b.mids, mode: b.mode, naming: b.naming, rulesX: st.rulesX, keepScans: st.data.keepScans,
      limits: { maxPages: st.scan.maxPages, maxDetail: st.scan.maxDetail, concurrency: st.scan.concurrency } } });
    // One running job per connection, enforced by the store; the running job's id lets the UI re-attach to it.
    const r = await store.createJob({ id: jobId, connId: c.id, state, now: Date.now() });
    if (!r.ok) return send(req, res, 409, { error: 'A scan is already running for this connection.', jobId: r.running });
    if (!SCAN_POLL) kick(jobId);
    return send(req, res, 200, { jobId, scanId: id });
  }
  mm = p.match(/^\/api\/jobs\/(\w+)(\/cancel)?$/);
  if (mm) {
    const id = mm[1]; let j = await store.getJob(id); if (!j) return send(req, res, 404, { error: 'Job not found' });
    if (mm[2] && m === 'POST') await store.requestCancel(id);
    // Poll mode: this request runs the next step (if no one else is). Background mode: make sure a driver is
    // running — after a restart, the first poll resumes the job once the old lease has expired.
    if (j.status === 'running') { if (SCAN_POLL) await runStep(id); else kick(id); }
    j = await store.getJob(id);
    return send(req, res, 200, pubJob(j));
  }
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
  try {
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);
    try { await ready(); } catch (e) { console.error('Store unavailable:', e.message); return send(req, res, 503, { ok: false, error: 'Storage unavailable — ' + e.message }); }
    await api(req, res, url);
  }
  catch (e) { console.error(e); send(req, res, e.status && e.status < 500 ? 400 : 500, { error: e.message }); }
}

if (require.main === module) {
  http.createServer(handle).listen(PORT, HOST, () => {
    console.log(`MCNexus ${VERSION} → http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}/  (storage: ${PG ? 'PostgreSQL' : DATA})`);
    // Background mode: carry on with scans that were running when the server last stopped.
    ready().then(resumeRunningJobs).then(n => { if (n) console.log('Resuming ' + plural(n, 'scan')); }).catch(e => console.error('Could not resume scans:', e.message));
  });
}

// Internals exported for tests (test/). Set MCNEXUS_DATA / MCNEXUS_KEY before requiring: the store loads on require.
module.exports = { handle, useStore, withDefaults, SESSION_IDLE, SESSION_MAX, setScanMode, runStep, resumeRunningJobs, STEP_LEASE, packPart, unpackPart, analyze, runScan, testConnection, SFMC, ApiErr, xmlObj, sqlSources, sqlDepth, patternRe, enc, dec, hid, score,
  RULES, RULE, RULESET, VERSION, DOMAINS, DOMAIN_OF, MODULES, SEVS, W, PEN, SECRET_RE, STATIC_OK };
