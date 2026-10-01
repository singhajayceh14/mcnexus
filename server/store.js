'use strict';
// MCNexus storage. Two implementations of one async contract:
//   JsonStore — store.json + scans/<cid>/<n>.json in a data folder (default; local and single-VM use)
//   PgStore   — PostgreSQL via server/store-pg.js (Neon in production), selected by DATABASE_URL
// test/store.test.js runs the same contract tests against both.
//
// Contract (every method async; returned objects are copies the caller may mutate):
//   init()                                   ready the store (PgStore: check the schema is installed)
//   countUsers() · listUsers()               listUsers → [{ email, name, role }]
//   getUser(email)                           → { email, name, role, salt, hash } | null
//   createFirstOwner(user)                   → true only if there were no users (atomic)
//   setPassword(email, salt, hash)
//   getSettings()                            → { [section]: value } for sections that were saved
//   putSettings({ [section]: value })        sections: SETTING_SECTIONS
//   listConnections() · getConnection(id)    connection objects use CONN_KEYS
//   createConnection(conn)
//   updateConnection(id, patch)              → updated connection | null
//   deleteConnection(id)                     also removes its scans, snapshots and triage
//   listScans(cid)                           → summaries ordered by n
//   addScan(cid, summary, snapshot)          → false if the connection no longer exists
//   getSnapshot(cid, n)                      → snapshot | null
//   pruneScans(cid, keep) · clearScans(cid)  → number of scans removed (keep <= 0 keeps all)
//   getTriage(cid) · putTriage(cid, fx)      fx = { [findingId]: { status, owner, notes, … } }
//   createSession(s)                         s = { hash, email, created, seen, expires, ua, ip }; times in ms;
//                                            hash = sha256(cookie token) — the raw token is never stored
//   getSession(hash) · listSessions(email)   → session(s), expired ones included (the caller checks)
//   touchSession(hash, seen, expires) · deleteSession(hash)
//   deleteSessions(email, exceptHash)        → number ended
//   purgeExpired(now)                        drops expired sessions and stale sign-in failure counters
//   countFailures(key, now, windowMs)        → { count, resetAt }  failed sign-ins in the current window
//   recordFailure(key, now, windowMs)        → { count, resetAt }  window starts at the first failure
//   clearFailures(key)
//   stats()                                  → { connections, scans, users, bytes, location }
//   close()
const fs = require('fs'), path = require('path');

const SETTING_SECTIONS = ['rulesX', 'naming', 'scan', 'report', 'data'];
const CONN_KEYS = ['id', 'name', 'env', 'sub', 'cid', 'mid', 'secEnc', 'secretUpdated', 'status', 'validated', 'buList', 'buOff', 'access', 'scopes', 'created'];
const clone = (x) => x == null ? x : structuredClone(x);
const pick = (o, keys) => Object.fromEntries(keys.filter(k => o[k] !== undefined).map(k => [k, o[k]]));
function checkKeys(o, keys, what) { const bad = Object.keys(o).filter(k => !keys.includes(k)); if (bad.length) throw new Error(what + ': unknown field(s) ' + bad.join(', ')); }

class JsonStore {
  constructor(dir) {
    this.dir = dir; this.file = path.join(dir, 'store.json');
    fs.mkdirSync(path.join(dir, 'scans'), { recursive: true });
    const raw = fs.existsSync(this.file) ? JSON.parse(fs.readFileSync(this.file, 'utf8')) : {};
    this.db = { users: [], connections: [], scans: {}, triage: {}, settings: {}, sessions: [], ...raw };
    this.fails = new Map();   // sign-in failures: in memory, as the JSON store is a single process
  }
  _save() { const tmp = this.file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(this.db, null, 1), { mode: 0o600 }); fs.renameSync(tmp, this.file); }
  _scanPath(cid, n) { return path.join(this.dir, 'scans', cid, n + '.json'); }
  _conn(id) { return this.db.connections.find(c => c.id === id); }

  async init() { }
  async close() { }

  async countUsers() { return this.db.users.length; }
  async listUsers() { return this.db.users.map(u => ({ email: u.email, name: u.name, role: u.role })); }
  async getUser(email) { return clone(this.db.users.find(u => u.email === email) || null); }
  async createFirstOwner(u) { if (this.db.users.length) return false; this.db.users.push(pick(u, ['email', 'name', 'role', 'salt', 'hash'])); this._save(); return true; }
  async setPassword(email, salt, hash) { const u = this.db.users.find(x => x.email === email); if (!u) return false; u.salt = salt; u.hash = hash; this._save(); return true; }

  async getSettings() { return clone(pick(this.db.settings, SETTING_SECTIONS)); }
  async putSettings(patch) { checkKeys(patch, SETTING_SECTIONS, 'settings'); Object.assign(this.db.settings, clone(patch)); this._save(); }

  async listConnections() { return clone(this.db.connections); }
  async getConnection(id) { return clone(this._conn(id) || null); }
  async createConnection(c) { checkKeys(c, CONN_KEYS, 'connection'); if (this._conn(c.id)) throw new Error('connection exists: ' + c.id); this.db.connections.push(clone(c)); this._save(); }
  async updateConnection(id, patch) { checkKeys(patch, CONN_KEYS, 'connection'); const c = this._conn(id); if (!c) return null; Object.assign(c, clone(patch), { id }); this._save(); return clone(c); }
  async deleteConnection(id) {
    const before = this.db.connections.length;
    this.db.connections = this.db.connections.filter(c => c.id !== id); delete this.db.scans[id]; delete this.db.triage[id]; this._save();
    fs.rmSync(path.join(this.dir, 'scans', id), { recursive: true, force: true });
    return this.db.connections.length < before;
  }

  async listScans(cid) { return clone(this.db.scans[cid] || []); }
  async addScan(cid, summary, snapshot) {
    if (!this._conn(cid)) return false;
    fs.mkdirSync(path.join(this.dir, 'scans', cid), { recursive: true });
    fs.writeFileSync(this._scanPath(cid, summary.n), JSON.stringify(snapshot));
    (this.db.scans[cid] = this.db.scans[cid] || []).push(clone(summary)); this._save(); return true;
  }
  async getSnapshot(cid, n) { try { return JSON.parse(fs.readFileSync(this._scanPath(cid, n), 'utf8')); } catch { return null; } }
  async pruneScans(cid, keep) {
    const list = this.db.scans[cid] || []; let n = 0;
    while (keep > 0 && list.length > keep) { const o = list.shift(); n++; try { fs.unlinkSync(this._scanPath(cid, o.n)); } catch { } }
    if (n) this._save(); return n;
  }
  async clearScans(cid) { const n = (this.db.scans[cid] || []).length; this.db.scans[cid] = []; this._save(); fs.rmSync(path.join(this.dir, 'scans', cid), { recursive: true, force: true }); return n; }

  async getTriage(cid) { return clone(this.db.triage[cid] || {}); }
  async putTriage(cid, fx) { if (!this._conn(cid)) return false; this.db.triage[cid] = clone(fx || {}); this._save(); return true; }

  async createSession(x) { if (!this.db.users.some(u => u.email === x.email)) return false; this.db.sessions.push(pick(x, ['hash', 'email', 'created', 'seen', 'expires', 'ua', 'ip'])); this._save(); return true; }
  async getSession(hash) { return clone(this.db.sessions.find(x => x.hash === hash) || null); }
  async touchSession(hash, seen, expires) { const x = this.db.sessions.find(y => y.hash === hash); if (x) { x.seen = seen; x.expires = expires; this._save(); } }
  async deleteSession(hash) { const n = this.db.sessions.length; this.db.sessions = this.db.sessions.filter(x => x.hash !== hash); if (this.db.sessions.length === n) return false; this._save(); return true; }
  async listSessions(email) { return clone(this.db.sessions.filter(x => x.email === email)); }
  async deleteSessions(email, exceptHash) { const n = this.db.sessions.length; this.db.sessions = this.db.sessions.filter(x => x.email !== email || x.hash === exceptHash); const d = n - this.db.sessions.length; if (d) this._save(); return d; }
  async purgeExpired(now) {
    const n = this.db.sessions.length; this.db.sessions = this.db.sessions.filter(x => x.expires > now); const d = n - this.db.sessions.length; if (d) this._save();
    for (const [k, v] of this.fails) if (v.start < now - 864e5) this.fails.delete(k);
    return d;
  }

  async countFailures(key, now, windowMs) { const v = this.fails.get(key); return v && v.start > now - windowMs ? { count: v.count, resetAt: v.start + windowMs } : { count: 0, resetAt: now }; }
  async recordFailure(key, now, windowMs) { let v = this.fails.get(key); if (!v || v.start <= now - windowMs) v = { count: 0, start: now }; v.count++; this.fails.set(key, v); return { count: v.count, resetAt: v.start + windowMs }; }
  async clearFailures(key) { this.fails.delete(key); }

  async stats() {
    let bytes = 0; const walk = (d) => { try { fs.readdirSync(d, { withFileTypes: true }).forEach(e => { const f = path.join(d, e.name); if (e.isDirectory()) walk(f); else bytes += fs.statSync(f).size; }); } catch { } }; walk(this.dir);
    return { connections: this.db.connections.length, scans: Object.values(this.db.scans).reduce((n, l) => n + l.length, 0), users: this.db.users.length, bytes, location: this.dir };
  }
}

// DATABASE_URL → PostgreSQL; otherwise the JSON store in `dir`.
function createStore({ databaseUrl = process.env.DATABASE_URL, dir } = {}) {
  if (databaseUrl) { const { PgStore, neonAdapter } = require('./store-pg'); return new PgStore(neonAdapter(databaseUrl)); }
  return new JsonStore(dir);
}

module.exports = { createStore, JsonStore, SETTING_SECTIONS, CONN_KEYS, checkKeys, pick };
