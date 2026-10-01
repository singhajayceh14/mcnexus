'use strict';
// PostgreSQL store (see the contract in store.js). Runs on a small adapter so the same code serves
// Neon in production (neonAdapter, HTTP driver — one round trip per query/transaction) and PGlite in tests.
//   adapter.query(text, params) → rows[]
//   adapter.tx([[text, params], …]) → rows[][]     (one transaction, non-interactive)
//   adapter.exec(sqlScript)                        (schema.sql: statements split on ';' at end of line)
//   adapter.close()
const { SETTING_SECTIONS, CONN_KEYS, checkKeys } = require('./store');

const SCHEMA_VERSION = 1;
const FIRST_OWNER_LOCK = 7243100;   // pg_advisory_xact_lock key: serialises concurrent first sign-ins

// connection object key → [column, kind]
const CONN_COLS = {
  id: ['id'], name: ['name'], env: ['env'], sub: ['sub'], cid: ['client_id'], mid: ['mid'], secEnc: ['secret_enc'],
  secretUpdated: ['secret_updated', 'ts'], status: ['status'], validated: ['validated'], buList: ['bu_list', 'json'],
  buOff: ['bu_off', 'json'], access: ['access', 'json'], scopes: ['scopes', 'json'], created: ['created_at', 'ts'],
};
const iso = (v) => v == null ? undefined : new Date(v).toISOString();
const toParam = (kind, v) => v == null ? null : kind === 'json' ? JSON.stringify(v) : kind === 'ts' ? iso(v) : v;
const cast = (kind) => kind === 'json' ? '::jsonb' : kind === 'ts' ? '::timestamptz' : '';
function rowToConn(r) {
  const c = {};
  for (const [k, [col, kind]] of Object.entries(CONN_COLS)) { const v = r[col]; if (v == null) continue; c[k] = kind === 'ts' ? iso(v) : v; }
  return c;
}
const rowToUser = (r) => ({ email: r.email, name: r.name, role: r.role, salt: r.pw_salt, hash: r.pw_hash });

class PgStore {
  constructor(adapter) { this.db = adapter; }

  async init() {
    const r = await this.db.query("SELECT to_regclass('public.schema_version') AS t", []);
    if (!r[0].t) throw new Error('PostgreSQL schema is not installed. Run: npm run db:schema');
    const v = await this.db.query('SELECT max(version) AS v FROM schema_version', []);
    if ((v[0].v || 0) < SCHEMA_VERSION) throw new Error('PostgreSQL schema is older than this server expects (v' + SCHEMA_VERSION + '). Run: npm run db:schema');
  }
  async close() { await this.db.close(); }

  // ---------- users ----------
  async countUsers() { return (await this.db.query('SELECT count(*)::int AS n FROM app_user', []))[0].n; }
  async listUsers() { return (await this.db.query('SELECT email, name, role FROM app_user ORDER BY created_at, email', [])).map(r => ({ email: r.email, name: r.name, role: r.role })); }
  async getUser(email) { const r = await this.db.query('SELECT * FROM app_user WHERE email = $1', [email]); return r[0] ? rowToUser(r[0]) : null; }
  async createFirstOwner(u) {
    const [, ins] = await this.db.tx([
      ['SELECT pg_advisory_xact_lock($1)', [FIRST_OWNER_LOCK]],
      ['INSERT INTO app_user (email, name, role, pw_salt, pw_hash) SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS (SELECT 1 FROM app_user) RETURNING email', [u.email, u.name, u.role, u.salt, u.hash]],
    ]);
    return ins.length === 1;
  }
  async setPassword(email, salt, hash) { return (await this.db.query('UPDATE app_user SET pw_salt = $2, pw_hash = $3, updated_at = now() WHERE email = $1 RETURNING email', [email, salt, hash])).length === 1; }

  // ---------- settings ----------
  async getSettings() { return Object.fromEntries((await this.db.query('SELECT section, value FROM app_setting', [])).map(r => [r.section, r.value])); }
  async putSettings(patch) {
    checkKeys(patch, SETTING_SECTIONS, 'settings');
    const q = Object.entries(patch).map(([s, v]) => ['INSERT INTO app_setting (section, value) VALUES ($1, $2::jsonb) ON CONFLICT (section) DO UPDATE SET value = excluded.value, updated_at = now()', [s, v === undefined ? null : JSON.stringify(v)]]);
    if (q.length) await this.db.tx(q);
  }

  // ---------- connections ----------
  async listConnections() { return (await this.db.query('SELECT * FROM connection ORDER BY created_at, id', [])).map(rowToConn); }
  async getConnection(id) { const r = await this.db.query('SELECT * FROM connection WHERE id = $1', [id]); return r[0] ? rowToConn(r[0]) : null; }
  async createConnection(c) {
    checkKeys(c, CONN_KEYS, 'connection');
    const keys = Object.keys(c).filter(k => c[k] !== undefined);
    await this.db.query(`INSERT INTO connection (${keys.map(k => CONN_COLS[k][0]).join(', ')}) VALUES (${keys.map((k, i) => '$' + (i + 1) + cast(CONN_COLS[k][1])).join(', ')})`, keys.map(k => toParam(CONN_COLS[k][1], c[k])));
  }
  async updateConnection(id, patch) {
    checkKeys(patch, CONN_KEYS, 'connection');
    const keys = Object.keys(patch).filter(k => k !== 'id' && patch[k] !== undefined);
    const sets = keys.map((k, i) => CONN_COLS[k][0] + ' = $' + (i + 2) + cast(CONN_COLS[k][1])).concat('updated_at = now()');
    const r = await this.db.query(`UPDATE connection SET ${sets.join(', ')} WHERE id = $1 RETURNING *`, [id, ...keys.map(k => toParam(CONN_COLS[k][1], patch[k]))]);
    return r[0] ? rowToConn(r[0]) : null;
  }
  async deleteConnection(id) { return (await this.db.query('DELETE FROM connection WHERE id = $1 RETURNING id', [id])).length === 1; }   // cascades

  // ---------- scans ----------
  async listScans(cid) { return (await this.db.query('SELECT summary FROM scan WHERE conn_id = $1 ORDER BY n', [cid])).map(r => r.summary); }
  async addScan(cid, summary, snapshot) {
    const [ins] = await this.db.tx([
      ['INSERT INTO scan (conn_id, n, scan_id, summary) SELECT $1, $2, $3, $4::jsonb WHERE EXISTS (SELECT 1 FROM connection WHERE id = $1) RETURNING n', [cid, summary.n, summary.id, JSON.stringify(summary)]],
      ['INSERT INTO scan_snapshot (conn_id, n, data) SELECT $1, $2, $3::json WHERE EXISTS (SELECT 1 FROM scan WHERE conn_id = $1 AND n = $2)', [cid, summary.n, JSON.stringify(snapshot)]],
    ]);
    return ins.length === 1;
  }
  async getSnapshot(cid, n) { const r = await this.db.query('SELECT data FROM scan_snapshot WHERE conn_id = $1 AND n = $2', [cid, +n]); return r[0] ? r[0].data : null; }
  async pruneScans(cid, keep) {
    if (!(keep > 0)) return 0;
    return (await this.db.query('DELETE FROM scan WHERE conn_id = $1 AND n NOT IN (SELECT n FROM scan WHERE conn_id = $1 ORDER BY n DESC LIMIT $2) RETURNING n', [cid, keep])).length;
  }
  async clearScans(cid) { return (await this.db.query('DELETE FROM scan WHERE conn_id = $1 RETURNING n', [cid])).length; }

  // ---------- triage ----------
  async getTriage(cid) { return Object.fromEntries((await this.db.query('SELECT finding_id, data FROM triage WHERE conn_id = $1', [cid])).map(r => [r.finding_id, r.data])); }
  async putTriage(cid, fx) {
    const [, , ok] = await this.db.tx([
      ['DELETE FROM triage WHERE conn_id = $1', [cid]],
      ['INSERT INTO triage (conn_id, finding_id, data) SELECT $1, key, value FROM jsonb_each($2::jsonb) WHERE EXISTS (SELECT 1 FROM connection WHERE id = $1)', [cid, JSON.stringify(fx || {})]],
      ['SELECT 1 FROM connection WHERE id = $1', [cid]],
    ]);
    return ok.length === 1;
  }

  async stats() {
    const r = (await this.db.query('SELECT (SELECT count(*) FROM connection)::int AS c, (SELECT count(*) FROM scan)::int AS s, (SELECT count(*) FROM app_user)::int AS u, pg_database_size(current_database())::bigint AS b', []))[0];
    return { connections: r.c, scans: r.s, users: r.u, bytes: Number(r.b), location: 'PostgreSQL' };
  }
}

// Splits schema.sql into statements: drop `--` comments, split on ';' at end of line.
const splitSql = (script) => script.replace(/--[^\n]*/g, '').split(/;[ \t]*\r?\n|;[ \t]*$/).map(s => s.trim()).filter(Boolean);

function neonAdapter(url) {
  const { neon } = require('@neondatabase/serverless');
  const sql = neon(url);
  return {
    query: (text, params) => sql.query(text, params),
    tx: (list) => sql.transaction(list.map(([t, p]) => sql.query(t, p))),
    exec: (script) => sql.transaction(splitSql(script).map(s => sql.query(s, []))),
    close: async () => { },
  };
}

module.exports = { PgStore, neonAdapter, splitSql, SCHEMA_VERSION };
