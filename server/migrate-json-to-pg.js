#!/usr/bin/env node
// Copies a JSON data folder (store.json + scans/) into PostgreSQL, or just installs the schema.
//
//   DATABASE_URL=postgres://… node server/migrate-json-to-pg.js --schema            install/upgrade schema only
//   DATABASE_URL=postgres://… node server/migrate-json-to-pg.js [--from server/data] schema + copy data
//
// Safe to re-run: rows that already exist are left alone (never overwritten), so edits made in Postgres
// after a first migration survive. Client secrets are copied as ciphertext — never decrypted. Afterwards every
// table count and every snapshot is compared with the source; the exit code is 1 on any mismatch.
// If MCNEXUS_KEY is set it is checked against the stored secrets (the key itself is never printed).
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const { SETTING_SECTIONS } = require('./store');

const SCHEMA_FILE = path.join(__dirname, 'schema.sql');
const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

// true / false / null (nothing to check). Same format as enc() in mcnexus-server.js: iv.tag.data, base64.
function keyOpens(secEnc, hexKey) {
  if (!secEnc || !hexKey) return null;
  try {
    const [iv, tag, d] = secEnc.split('.').map(x => Buffer.from(x, 'base64'));
    const c = crypto.createDecipheriv('aes-256-gcm', Buffer.from(hexKey, 'hex'), iv); c.setAuthTag(tag); Buffer.concat([c.update(d), c.final()]);
    return true;
  } catch { return false; }
}

async function installSchema(adapter) { await adapter.exec(fs.readFileSync(SCHEMA_FILE, 'utf8')); }

async function migrate({ from, adapter, key = null, log = console.log }) {
  const file = path.join(from, 'store.json');
  if (!fs.existsSync(file)) throw new Error('No store.json in ' + from);
  const src = { users: [], connections: [], scans: {}, triage: {}, settings: {}, ...readJson(file) };
  const report = { copied: {}, present: {}, warnings: [], mismatches: [] };
  const count = (k, inserted) => { const t = inserted ? report.copied : report.present; t[k] = (t[k] || 0) + 1; };
  const one = async (k, text, params) => count(k, (await adapter.query(text, params)).length > 0);

  await installSchema(adapter);

  for (const s of SETTING_SECTIONS) if (src.settings[s] !== undefined)
    await one('settings', 'INSERT INTO app_setting (section, value) VALUES ($1, $2::jsonb) ON CONFLICT (section) DO NOTHING RETURNING section', [s, JSON.stringify(src.settings[s])]);

  for (const u of src.users)
    await one('users', 'INSERT INTO app_user (email, name, role, pw_salt, pw_hash) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (email) DO NOTHING RETURNING email', [String(u.email).toLowerCase(), u.name, u.role || 'Consultant', u.salt, u.hash]);

  const conns = new Set();
  for (const c of src.connections) {
    if (!c.secEnc) { report.warnings.push('Connection ' + c.id + ' has no stored secret — skipped'); continue; }
    conns.add(c.id);
    await one('connections', `INSERT INTO connection (id, name, env, sub, client_id, mid, secret_enc, secret_updated, status, validated, bu_list, bu_off, access, scopes, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9, $10, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb, COALESCE($15::timestamptz, now())) ON CONFLICT (id) DO NOTHING RETURNING id`,
      [c.id, c.name || 'SFMC org', c.env || 'Production', c.sub, c.cid, c.mid || '', c.secEnc, c.secretUpdated || null, c.status || 'Connected', c.validated || null,
        JSON.stringify(c.buList || []), JSON.stringify(c.buOff || {}), JSON.stringify(c.access || []), JSON.stringify(c.scopes || []), c.created || null]);
  }

  const snapFile = (cid, n) => path.join(from, 'scans', cid, n + '.json');
  for (const [cid, list] of Object.entries(src.scans)) {
    if (!conns.has(cid)) { if (list.length) report.warnings.push(list.length + ' scan(s) for unknown connection ' + cid + ' — skipped'); continue; }
    for (const sm of list) {
      const f = snapFile(cid, sm.n), snap = fs.existsSync(f) ? readJson(f) : null;
      if (!snap) report.warnings.push('Scan ' + cid + ' ' + sm.id + ': snapshot file missing — summary copied without it');
      const q = [['INSERT INTO scan (conn_id, n, scan_id, summary) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (conn_id, n) DO NOTHING RETURNING n', [cid, sm.n, sm.id, JSON.stringify(sm)]]];
      if (snap) q.push(['INSERT INTO scan_snapshot (conn_id, n, data) VALUES ($1, $2, $3::json) ON CONFLICT (conn_id, n) DO NOTHING', [cid, sm.n, JSON.stringify(snap)]]);
      count('scans', (await adapter.tx(q))[0].length > 0);
    }
  }

  for (const [cid, fx] of Object.entries(src.triage)) {
    if (!conns.has(cid)) continue;
    for (const [fid, d] of Object.entries(fx || {}))
      await one('triage', 'INSERT INTO triage (conn_id, finding_id, data) VALUES ($1, $2, $3::jsonb) ON CONFLICT (conn_id, finding_id) DO NOTHING RETURNING finding_id', [cid, fid, JSON.stringify(d)]);
  }

  // ---------- verify ----------
  const n = async (t, where = '', p = []) => (await adapter.query(`SELECT count(*)::int AS n FROM ${t} ${where}`, p))[0].n;
  const expectAtLeast = async (label, t, want) => { const got = await n(t); if (got < want) report.mismatches.push(`${label}: ${want} in source, ${got} in database`); };
  await expectAtLeast('users', 'app_user', src.users.length);
  await expectAtLeast('connections', 'connection', conns.size);
  for (const cid of conns) {
    for (const sm of src.scans[cid] || []) {
      const f = snapFile(cid, sm.n); if (!fs.existsSync(f)) continue;
      const r = await adapter.query('SELECT data FROM scan_snapshot WHERE conn_id = $1 AND n = $2', [cid, sm.n]);
      const same = r[0] && JSON.stringify(r[0].data) === JSON.stringify(readJson(f));
      if (!same) report.mismatches.push('Snapshot ' + cid + ' ' + sm.id + ' differs from ' + f);
    }
    const tri = Object.keys(src.triage[cid] || {}).length;
    if ((await n('triage', 'WHERE conn_id = $1', [cid])) < tri) report.mismatches.push('Triage for ' + cid + ': fewer rows than the source');
  }

  const firstSecret = (src.connections.find(c => c.secEnc) || {}).secEnc;
  report.key = keyOpens(firstSecret, key);
  report.keyFile = fs.existsSync(path.join(from, '.key'));

  const fmt = (o) => Object.entries(o).map(([k, v]) => k + ' ' + v).join(', ') || 'nothing';
  log('Copied:          ' + fmt(report.copied));
  log('Already present: ' + fmt(report.present));
  report.warnings.forEach(w => log('Warning: ' + w));
  report.mismatches.forEach(m => log('MISMATCH: ' + m));
  if (report.key === true) log('MCNEXUS_KEY decrypts the stored client secrets.');
  else if (report.key === false) log('MCNEXUS_KEY does NOT decrypt the stored client secrets — connections will need re-authentication. Use the key these secrets were encrypted with' + (report.keyFile ? ' (' + path.join(from, '.key') + ').' : '.'));
  else if (firstSecret) log('Set MCNEXUS_KEY to the key the secrets were encrypted with' + (report.keyFile ? ' — the contents of ' + path.join(from, '.key') : '') + '. Keep it out of the repository and out of the database.');
  log(report.mismatches.length ? 'Migration finished WITH MISMATCHES.' : 'Migration verified.');
  return report;
}

async function main(argv) {
  const url = process.env.DATABASE_URL; if (!url) throw new Error('Set DATABASE_URL to the target PostgreSQL database.');
  const { neonAdapter } = require('./store-pg'); const adapter = neonAdapter(url);
  if (argv.includes('--schema')) { await installSchema(adapter); console.log('Schema installed (' + path.basename(SCHEMA_FILE) + ').'); return 0; }
  const i = argv.indexOf('--from'), from = i >= 0 ? argv[i + 1] : (process.env.MCNEXUS_DATA || path.join(__dirname, 'data'));
  const r = await migrate({ from: path.resolve(from), adapter, key: process.env.MCNEXUS_KEY || null });
  return r.mismatches.length || r.key === false ? 1 : 0;
}

if (require.main === module) main(process.argv.slice(2)).then(code => process.exit(code), e => { console.error('Error: ' + e.message); process.exit(1); });

module.exports = { migrate, installSchema, keyOpens };
