-- MCNexus — PostgreSQL schema (v1)
-- Target: PostgreSQL 14+. Mirrors the current file store (store.json + scans/<conn>/<n>.json)
-- so the server can move to Postgres without changing the UI data contract.
--
-- Mapping from today's store:
--   db.users            -> app_user
--   sessions (memory)   -> app_session
--   db.settings         -> app_setting (one row per section, JSONB)
--   db.connections      -> connection, connection_bu, connection_access
--   db.scans[cid][]     -> scan            (summary row)
--   scans/<cid>/<n>.json-> scan_snapshot   (full dataset, JSONB) + normalized tables below
--   ds.findings         -> finding
--   ds.assets           -> asset, asset_edge, graph_node
--   db.triage[cid]      -> triage, triage_note
--
-- Hard rules carried over from CLAUDE.md:
--   * Client secrets are stored ONLY as AES-256-GCM ciphertext (secret_enc). Key stays outside the DB.
--   * Finding IDs are stable: 'F-' + sha1(rule|objKey)[0:6]. Triage is keyed on (connection, finding_id),
--     not on scan, so it survives rescans.
--   * Domain order is fixed; domain.ord is the index into scan.dom[]. Append only.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()

-- ---------- enums ----------
CREATE TYPE user_role      AS ENUM ('Owner', 'Admin', 'Consultant', 'Viewer');
CREATE TYPE conn_env       AS ENUM ('Production', 'Sandbox', 'Development');
CREATE TYPE conn_status    AS ENUM ('Connected', 'Limited', 'Failed', 'Expired');
CREATE TYPE severity       AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE scan_mode      AS ENUM ('Quick', 'Full', 'Custom');
CREATE TYPE scan_state     AS ENUM ('RUNNING', 'SUCCESS', 'PARTIAL', 'FAILED');
CREATE TYPE triage_status  AS ENUM ('Open', 'In review', 'Accepted', 'Resolved', 'False positive');
CREATE TYPE asset_kind     AS ENUM ('DE', 'SQL', 'AUTO', 'IMP', 'SCR', 'JRN', 'CNT');   -- real assets
CREATE TYPE vnode_kind     AS ENUM ('DV', 'EML', 'USR', 'NAM');                          -- virtual graph nodes

-- ---------- updated_at helper ----------
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$;

-- ---------- identity ----------
CREATE TABLE app_user (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         citext_placeholder,  -- replaced below if citext is unavailable
  name          text        NOT NULL,
  role          user_role   NOT NULL DEFAULT 'Consultant',
  pw_salt       text        NOT NULL,             -- hex, 16 bytes
  pw_hash       text        NOT NULL,             -- hex, scrypt/pbkdf2 output (see hashPw)
  disabled      boolean     NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
COMMIT;
