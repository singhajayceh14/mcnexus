'use strict';
// Shared test helpers. Not a test file itself (node --test runs it as an empty suite).
//  - loadServer(): require the server against a throwaway data dir and key
//  - fakeSfmc(): an in-memory SFMC tenant served through globalThis.fetch, recording every call
//  - assertReadOnly(): hard rule 1 — only token, SOAP Retrieve, REST GET and the asset query POST
//  - sfmcOrg(): a small two-BU org that trips several rules end to end
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto'), http = require('http');
const assert = require('node:assert/strict');

const SUB = 'mcfaketenant0123456789ab';
const CID = 'abcd1234efgh5678ijkl9012';
const SEC = 'fake-client-secret-0123456789';
const RECENT = new Date(Date.now() - 5 * 864e5).toISOString();
const OLD = '2020-01-01T00:00:00';

function loadServer(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcnexus-test-'));
  Object.assign(process.env, { MCNEXUS_DATA: dir, MCNEXUS_KEY: crypto.randomBytes(32).toString('hex') }, env);
  const srv = require('../server/mcnexus-server.js');
  return { srv, dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

// ---------- fake SFMC ----------
const xesc = (s) => String(s).replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]));
const toXml = (o) => Object.entries(o).map(([k, v]) => v == null ? '' : typeof v === 'object' ? `<${k}>${toXml(v)}</${k}>` : `<${k}>${xesc(v)}</${k}>`).join('');
const get = (o, p) => p.split('.').reduce((a, k) => (a == null ? undefined : a[k]), o);
const json = (status, o) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
const soapEnv = (inner) => new Response(`<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soap:Body><RetrieveResponseMsg xmlns="http://exacttarget.com/wsdl/partnerAPI">${inner}</RetrieveResponseMsg></soap:Body></soap:Envelope>`, { status: 200, headers: { 'content-type': 'text/xml' } });

/**
 * org: { sub, cid, sec, ent, mids: { [mid]: { soap: { Type: rows[] }, rest: { automations, imports, scripts, interactions, eventDefinitions, assets } } },
 *        rejectProps: { Type: [prop] }, soapPage, restPageCap, fail429 }
 * BUs listed by BusinessUnit but missing from `mids` get an auth error (package has no access).
 */
function fakeSfmc(org) {
  const calls = [], tokens = new Map(), realFetch = globalThis.fetch;
  let throttle = org.fail429 || 0, seq = 0;
  const rejected = org.rejectProps || {};

  const page = (rows, q, cap) => {
    const p = +q.get('$page') || 1; let size = +(q.get('$pagesize') || q.get('$pageSize')) || 50; if (cap) size = Math.min(size, cap);
    return { count: rows.length, page: p, pageSize: size, items: rows.slice((p - 1) * size, p * size) };
  };
  const strip = (o, ...keys) => { const c = { ...o }; keys.forEach(k => delete c[k]); return c; };

  function token(body) {
    let b; try { b = JSON.parse(body); } catch { return json(400, { error: 'invalid_request' }); }
    if (b.grant_type !== 'client_credentials' || b.client_id !== org.cid || b.client_secret !== org.sec) return json(401, { error: 'invalid_client', error_description: 'Client authentication failed.' });
    const mid = b.account_id ? String(b.account_id) : org.ent;
    if (!org.mids[mid]) return json(401, { error: 'unauthorized_client', error_description: 'Package does not have access to account ' + mid });
    const t = 'tok-' + mid + '-' + (++seq); tokens.set(t, mid);
    return json(200, { access_token: t, token_type: 'Bearer', expires_in: 1079, scope: org.scope || 'email_read documents_and_images_read saved_content_read journeys_read list_and_subscribers_read data_extensions_read automations_read accounts_read users_read', soap_instance_url: `https://${org.sub}.soap.marketingcloudapis.com/`, rest_instance_url: `https://${org.sub}.rest.marketingcloudapis.com/` });
  }

  function soap(mid, body) {
    const type = (body.match(/<ObjectType>([^<]+)</) || [])[1];
    const props = [...body.matchAll(/<Properties>([^<]+)<\/Properties>/g)].map(m => m[1]);
    const bad = props.filter(p => (rejected[type] || []).includes(p));
    if (bad.length) return soapEnv(`<OverallStatus>Error: The Request Property(s) ${bad.join(', ')} do not match with the fields of ${type} retrieve</OverallStatus><RequestID>err</RequestID>`);
    let rows = ((org.mids[mid] || {}).soap || {})[type] || [];
    const f = body.match(/<Filter[^>]*><Property>([^<]+)<\/Property><SimpleOperator>equals<\/SimpleOperator><Value>([^<]*)<\/Value>/);
    if (f) rows = rows.filter(r => String(get(r, f[1])) === f[2]);
    const size = org.soapPage || 2500, cont = (body.match(/<ContinueRequest>([^<]+)</) || [])[1];
    const off = cont ? +cont.split(':')[1] : 0, more = off + size < rows.length;
    return soapEnv(`<OverallStatus>${more ? 'MoreDataAvailable' : 'OK'}</OverallStatus><RequestID>${type}:${off + size}</RequestID>` + rows.slice(off, off + size).map(r => `<Results xsi:type="${type}">${toXml(r)}</Results>`).join(''));
  }

  function rest(mid, method, u, body) {
    const R = (org.mids[mid] || {}).rest || {}, q = u.searchParams, p = u.pathname, cap = org.restPageCap;
    let m;
    if (method === 'GET' && p === '/platform/v1/tokenContext') return json(200, { enterprise: { id: +org.ent }, organization: { id: +mid }, user: { id: 1 } });
    if (method === 'GET' && p === '/automation/v1/automations') return json(200, page((R.automations || []).map(a => strip(a, 'steps')), q, cap));
    if (method === 'GET' && (m = p.match(/^\/automation\/v1\/automations\/([^/]+)$/))) { const a = (R.automations || []).find(x => x.id === m[1]); return a ? json(200, a) : json(404, { message: 'Automation not found' }); }
    if (method === 'GET' && p === '/automation/v1/imports') return json(200, page(R.imports || [], q, cap));
    if (method === 'GET' && p === '/automation/v1/scripts') return json(200, page(R.scripts || [], q, cap));
    if (method === 'GET' && p === '/interaction/v1/interactions') return json(200, page((R.interactions || []).map(j => strip(j, 'activities', 'triggers')), q, cap));
    if (method === 'GET' && (m = p.match(/^\/interaction\/v1\/interactions\/([^/]+)$/))) { const j = (R.interactions || []).find(x => x.id === m[1]); return j ? json(200, j) : json(404, { message: 'Interaction not found' }); }
    if (method === 'GET' && p === '/interaction/v1/eventDefinitions') return json(200, page(R.eventDefinitions || [], q, cap));
    if (method === 'GET' && p === '/asset/v1/content/assets') return json(200, page(R.assets || [], q, cap));
    if (method === 'POST' && p === '/asset/v1/content/assets/query') {
      const b = JSON.parse(body || '{}'), qq = b.query || {}, want = [].concat(qq.value);
      const rows = (R.assets || []).filter(a => want.includes(get(a, qq.property)));
      const pg = (b.page && b.page.page) || 1, size = Math.min((b.page && b.page.pageSize) || 50, cap || Infinity);
      return json(200, { count: rows.length, page: pg, pageSize: size, items: rows.slice((pg - 1) * size, pg * size) });
    }
    return json(404, { message: 'No route for ' + method + ' ' + p });
  }

  async function fetch(input, init = {}) {
    const u = new URL(String(input)), method = String(init.method || 'GET').toUpperCase();
    if (u.hostname === '127.0.0.1' || u.hostname === 'localhost') return realFetch(input, init);
    const h = Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
    const body = init.body == null ? '' : String(init.body);
    calls.push({ method, host: u.hostname, path: u.pathname, url: u.href, soapAction: h.soapaction, body });
    if (u.hostname === `${org.sub}.auth.marketingcloudapis.com`) return u.pathname === '/v2/token' && method === 'POST' ? token(body) : json(404, {});
    const tok = (h.authorization || '').replace(/^Bearer\s+/, '') || (body.match(/<fueloauth[^>]*>([^<]+)</) || [])[1];
    const mid = tokens.get(tok); if (!mid) return json(401, { message: 'Not Authorized' });
    if (u.hostname === `${org.sub}.soap.marketingcloudapis.com` && u.pathname === '/Service.asmx') return h.soapaction === 'Retrieve' ? soap(mid, body) : new Response('<faultstring>Unsupported in fake</faultstring>', { status: 500 });
    if (u.hostname === `${org.sub}.rest.marketingcloudapis.com`) {
      if (throttle > 0) { throttle--; return new Response('', { status: 429, headers: { 'retry-after': '0' } }); }
      return rest(mid, method, u, body);
    }
    throw new TypeError('fetch failed: unknown host ' + u.hostname);
  }
  return { calls, fetch, install() { globalThis.fetch = fetch; return this; }, restore() { globalThis.fetch = realFetch; } };
}

// Hard rule 1. Every SFMC call must be one of: token POST, SOAP Retrieve, REST GET, asset query POST.
function assertReadOnly(calls) {
  assert.ok(calls.length > 0, 'expected SFMC calls to have been recorded');
  for (const c of calls) {
    assert.match(c.host, /\.marketingcloudapis\.com$/, 'call to non-SFMC host ' + c.host);
    const ok = c.method === 'GET'
      || (c.method === 'POST' && /\.auth\./.test(c.host) && c.path === '/v2/token')
      || (c.method === 'POST' && /\.rest\./.test(c.host) && c.path === '/asset/v1/content/assets/query')
      || (c.method === 'POST' && /\.soap\./.test(c.host) && c.path === '/Service.asmx' && c.soapAction === 'Retrieve'
        && /<RetrieveRequestMsg[\s>]/.test(c.body) && !/<(Create|Update|Delete|Perform|Configure|Schedule|Execute|Extract)Request/i.test(c.body));
    assert.ok(ok, `non-read-only SFMC call: ${c.method} ${c.url} ${c.soapAction || ''}`);
  }
}

// ---------- fixture org ----------
// Enterprise 100 + child BU 200. BU 200 is wired so these fire: SQL-001, DE-RET-001, AUTO-FAIL-002,
// JRN-COR-004, SEC-SCR-001 (BU 200 script) and USR-INA-001 (one dormant user).
function sfmcOrg(over = {}) {
  const de = (oid, ck, name, sendable, ret) => ({ ObjectID: oid, CustomerKey: ck, Name: name, IsSendable: String(sendable), CategoryID: '1', CreatedDate: RECENT, ModifiedDate: RECENT, DataRetentionPeriodLength: ret ? '30' : '', DataRetentionPeriod: ret ? 'Days' : '', RowBasedRetention: 'false', ...(sendable ? { SendableDataExtensionField: { Name: 'SubscriberKey' }, SendableSubscriberField: { Name: 'Subscriber Key' } } : {}) });
  const fld = (ck, name, pk) => ({ Name: name, IsPrimaryKey: String(pk), FieldType: 'Text', DataExtension: { CustomerKey: ck } });
  return {
    sub: SUB, cid: CID, sec: SEC, ent: '100',
    mids: {
      100: {
        soap: {
          BusinessUnit: [{ ID: '100', Name: 'Acme Enterprise', ParentID: '0' }, { ID: '200', Name: 'Acme Retail', ParentID: '100' }],
          AccountUser: [
            { ID: '1', UserID: 'admin.user', Name: 'Admin', Email: 'admin@example.test', ActiveFlag: 'true', IsAPIUser: 'false', LastSuccessfulLogin: RECENT, CreatedDate: OLD, Client: { ID: '100' } },
            { ID: '2', UserID: 'dormant.user', Name: 'Dormant', Email: 'dormant@example.test', ActiveFlag: 'true', IsAPIUser: 'false', LastSuccessfulLogin: OLD, CreatedDate: OLD, Client: { ID: '200' } },
            { ID: '3', UserID: 'api.user', Name: 'API', Email: 'api@example.test', ActiveFlag: 'true', IsAPIUser: 'true', LastSuccessfulLogin: OLD, CreatedDate: OLD, Client: { ID: '100' } },
          ],
          DataExtension: [de('de-oid-shared', 'shared_subs', 'Shared_Subscribers', true, true)],
          DataExtensionField: [fld('shared_subs', 'SubscriberKey', true), fld('shared_subs', 'Email', false)],
          DataFolder: [{ ID: '1', Name: 'Data Extensions', ParentFolder: { ID: '0' }, ContentType: 'dataextension' }],
        },
        rest: {},
      },
      200: {
        soap: {
          DataExtension: [de('de-oid-entry', 'retail_entry', 'Retail_Entry', true, false), de('de-oid-stage', 'retail_stage', 'Retail_Staging', false, false)],
          DataExtensionField: [fld('retail_entry', 'SubscriberKey', true), fld('retail_entry', 'Email', false), fld('retail_stage', 'Id', false)],
          DataFolder: [],
          QueryDefinition: [{ ObjectID: 'q-oid-1', CustomerKey: 'q_retail_feed', Name: 'Q_Retail_Feed', QueryText: 'SELECT * FROM ENT.Shared_Subscribers', TargetType: 'DE', DataExtensionTarget: { Name: 'Retail_Entry', CustomerKey: 'retail_entry' }, TargetUpdateType: 'Overwrite', CreatedDate: RECENT, ModifiedDate: RECENT, CategoryID: '2' }],
        },
        rest: {
          automations: [{ id: 'auto-1', name: 'Retail Daily Feed', key: 'retail-daily', statusId: -1, lastRunTime: RECENT, createdDate: RECENT, modifiedDate: RECENT, steps: [{ step: 1, activities: [{ name: 'Feed', objectTypeId: 300, activityObjectId: 'q-oid-1' }] }] }],
          imports: [],
          scripts: [{ ssjsActivityId: 'scr-1', name: 'Token Refresh', key: 'token-refresh', script: 'var client_secret = "abcd1234efgh5678";', createdDate: RECENT, modifiedDate: RECENT }],
          interactions: [
            { id: 'j1-v1', key: 'welcome', name: 'Welcome Journey', version: 1, status: 'Stopped', modifiedDate: OLD, createdDate: OLD },
            { id: 'j1-v2', key: 'welcome', name: 'Welcome Journey', version: 2, status: 'Published', modifiedDate: RECENT, createdDate: OLD, entryMode: 'MultipleEntries',
              triggers: [{ metaData: { eventDefinitionKey: 'ev-retail' } }],
              activities: [{ type: 'EMAILV2', name: 'Welcome Email', configurationArguments: { triggeredSend: { emailId: 9001, emailSubject: 'Hi' } } }] },
          ],
          eventDefinitions: [{ eventDefinitionKey: 'ev-retail', dataExtensionId: 'de-oid-entry', dataExtensionName: 'Retail_Entry', type: 'EmailAudience' }],
          assets: [
            { id: 501, customerKey: 'welcome-email', name: 'Welcome Email', assetType: { name: 'htmlemail' }, category: { name: 'Content Builder' }, content: '<p>%%=ContentBlockByKey("hdr")=%%</p>', legacyData: { legacyId: 9001 }, status: { name: 'Draft' }, createdDate: RECENT, modifiedDate: RECENT },
            { id: 502, customerKey: 'hdr', name: 'Header', assetType: { name: 'htmlblock' }, category: { name: 'Blocks' }, content: '<h1>Hi</h1>', createdDate: RECENT, modifiedDate: RECENT },
          ],
        },
      },
    },
    ...over,
  };
}

const newJob = () => ({ connId: 'c-test', scanId: '#001', n: 1, t0: Date.now(), pct: 0, cur: 'Starting', log: [], mods: {}, counts: { assets: 0, rels: 0, rules: 0, findings: 0, warnings: 0, errors: 0 }, done: false, error: null, cancelled: false });

// Starts the request handler on an ephemeral port. `call` keeps the session cookie between requests.
async function startApp(handle) {
  const s = http.createServer(handle); await new Promise(r => s.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${s.address().port}`; let cookie = '';
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, redirect: 'manual', headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { }
    return { status: r.status, json, text, headers: r.headers };
  };
  // Sends the path exactly as given (fetch would normalise `..` and backslashes away).
  const raw = (p) => new Promise((ok, bad) => http.get({ host: '127.0.0.1', port: s.address().port, path: p }, (res) => { res.resume(); res.on('end', () => ok(res.statusCode)); }).on('error', bad));
  return { base, call, raw, setCookie: (c) => { cookie = c; }, close: () => { s.closeAllConnections && s.closeAllConnections(); return new Promise(r => s.close(r)); } };
}

module.exports = { SUB, CID, SEC, RECENT, OLD, loadServer, fakeSfmc, assertReadOnly, sfmcOrg, newJob, startApp };
