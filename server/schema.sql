-- MCNexus — PostgreSQL schema, version 3. Target: PostgreSQL 14+ (Neon in production, PGlite in tests).
--
-- Applied by `npm run db:schema` (server/migrate-json-to-pg.js --schema). Idempotent: every statement can be
-- re-run. Statements end with ';' at the end of a line and contain no other ';' — the Neon HTTP driver runs
-- them one at a time inside a single transaction, so no plpgsql bodies, no extensions, no enums.
--
-- Mapping from the JSON store (server/data):
--   store.json users[]              -> app_user
--   store.json settings.<section>   -> app_setting (one row per section)
--   store.json connections[]        -> connection
--   store.json scans[cid][]         -> scan (summary)
--   scans/<cid>/<n>.json            -> scan_snapshot (full dataset, json — kept byte-for-byte, never queried)
--   store.json triage[cid][fid]     -> triage
--   (in memory today)               -> app_session; invite and password_reset are for user management
--
-- Hard rules carried over from CLAUDE.md:
--   * Client secrets are stored ONLY as AES-256-GCM ciphertext (connection.secret_enc). The key (MCNEXUS_KEY)
--     never goes into the database.
--   * Finding IDs are stable ('F-' + sha1(rule|objKey)[0:6]); triage is keyed on (connection, finding_id), not on
--     scan, so it survives rescans.
--   * Domain order is fixed; scan summaries keep dom[] aligned to it inside summary jsonb.

CREATE TABLE IF NOT EXISTS schema_version (
  version     integer     PRIMARY KEY,
  applied_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_user (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text        NOT NULL UNIQUE CHECK (email = lower(email)),
  name        text        NOT NULL,
  role        text        NOT NULL DEFAULT 'Consultant' CHECK (role IN ('Owner', 'Admin', 'Consultant', 'Viewer')),
  pw_salt     text        NOT NULL,
  pw_hash     text        NOT NULL,
  disabled    boolean     NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_setting (
  section     text        PRIMARY KEY CHECK (section IN ('rulesX', 'naming', 'scan', 'report', 'data')),
  value       jsonb,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS connection (
  id              text        PRIMARY KEY,
  name            text        NOT NULL,
  env             text        NOT NULL DEFAULT 'Production',
  sub             text        NOT NULL,
  client_id       text        NOT NULL,
  mid             text        NOT NULL DEFAULT '',
  secret_enc      text        NOT NULL,
  secret_updated  timestamptz,
  status          text        NOT NULL DEFAULT 'Connected',
  validated       text,
  bu_list         jsonb       NOT NULL DEFAULT '[]',
  bu_off          jsonb       NOT NULL DEFAULT '{}',
  access          jsonb       NOT NULL DEFAULT '[]',
  scopes          jsonb       NOT NULL DEFAULT '[]',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan (
  conn_id     text        NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
  n           integer     NOT NULL,
  scan_id     text        NOT NULL,
  summary     jsonb       NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (conn_id, n)
);

CREATE TABLE IF NOT EXISTS scan_snapshot (
  conn_id     text        NOT NULL,
  n           integer     NOT NULL,
  data        json        NOT NULL,
  PRIMARY KEY (conn_id, n),
  FOREIGN KEY (conn_id, n) REFERENCES scan (conn_id, n) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS triage (
  conn_id     text        NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
  finding_id  text        NOT NULL,
  data        jsonb       NOT NULL,
  updated_by  text,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (conn_id, finding_id)
);

-- Sessions are looked up by sha256(token); the raw token only ever lives in the browser cookie.
CREATE TABLE IF NOT EXISTS app_session (
  token_hash  text        PRIMARY KEY,
  user_id     uuid        NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  user_agent  text,
  ip          text
);
CREATE INDEX IF NOT EXISTS app_session_user_idx ON app_session (user_id);
CREATE INDEX IF NOT EXISTS app_session_expires_idx ON app_session (expires_at);

CREATE TABLE IF NOT EXISTS invite (
  token_hash  text        PRIMARY KEY,
  email       text        NOT NULL CHECK (email = lower(email)),
  role        text        NOT NULL CHECK (role IN ('Admin', 'Consultant', 'Viewer')),
  invited_by  uuid        REFERENCES app_user (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

CREATE TABLE IF NOT EXISTS password_reset (
  token_hash  text        PRIMARY KEY,
  user_id     uuid        NOT NULL REFERENCES app_user (id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

INSERT INTO schema_version (version) VALUES (1) ON CONFLICT (version) DO NOTHING;

-- ---------- version 2: sign-in rate limiting ----------
-- Failed sign-ins per key ('email:<address>' or 'ip:<address>') in a fixed window that starts at the first failure.
CREATE TABLE IF NOT EXISTS login_attempt (
  key           text        PRIMARY KEY,
  count         integer     NOT NULL,
  window_start  timestamptz NOT NULL
);

INSERT INTO schema_version (version) VALUES (2) ON CONFLICT (version) DO NOTHING;

-- ---------- version 3: resumable scan jobs ----------
-- A scan is a job worked through in short steps (see runStep in mcnexus-server.js). state is json, not jsonb, so
-- key order survives. lease_until stops two workers running the same step; at most one running job per connection.
CREATE TABLE IF NOT EXISTS scan_job (
  id                text        PRIMARY KEY,
  conn_id           text        NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
  status            text        NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'failed')),
  state             json        NOT NULL,
  cancel_requested  boolean     NOT NULL DEFAULT false,
  lease_until       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS scan_job_one_running ON scan_job (conn_id) WHERE status = 'running';

-- What each step collected: a gzipped, base64 JSON fragment of the raw model. Deleted when the job ends.
CREATE TABLE IF NOT EXISTS scan_job_part (
  job_id  text     NOT NULL REFERENCES scan_job (id) ON DELETE CASCADE,
  seq     integer  NOT NULL,
  data    text     NOT NULL,
  PRIMARY KEY (job_id, seq)
);

INSERT INTO schema_version (version) VALUES (3) ON CONFLICT (version) DO NOTHING;
