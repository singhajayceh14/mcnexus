# MCNexus — Handover

**Version:** 1.0.0 · **Rule set:** v2.0 · **Date:** 30 Sep 2026

## 1. Summary
MCNexus connects to a Salesforce Marketing Cloud Engagement org through a server-to-server installed package. It collects metadata across Business Units using read-only calls, builds a dependency graph, runs 19 rules and presents the results as:
- an executive dashboard
- a findings center with triage
- asset, organization and data-model explorers
- a dependency explorer
- scan history and compare
- exportable reports

## 2. Package contents
| Path | Purpose |
| --- | --- |
| `MCNexus App.dc.html` | Production UI (live + demo fallback) |
| `support.js` | DC runtime (required by the UI) |
| `_ds/industry-…/` | Industry design system (styles + component bundle) |
| `server/mcnexus-server.js` | Backend: static hosting, auth, SFMC client, scanner, rules engine, storage |
| `server/README.md` | Run and package-setup guide |
| `package.json` | `npm start` convenience script (no dependencies) |
| `CLAUDE.md` | Standing engineering rules and data contract |
| `MCNexus Prototype.dc.html` | Original prototype (design reference) |
| `uploads/MCNexus_Solution_Design.md` | Original solution design brief |

## 3. Quick start
1. Install Node 18 or newer.
2. From the project folder, run `npm start` (or `node server/mcnexus-server.js`).
3. Open http://127.0.0.1:8787. The first sign-in creates the **Owner** account (password 8+ characters).
4. In SFMC, create an Installed Package with an **API Integration → Server-to-Server** component. Grant the read scopes listed in `server/README.md` and give it access to every Business Unit you want scanned.
5. In MCNexus, go to **Connections → Connect an SFMC org**:
   - Enter the subdomain or Auth Base URI, the Client ID and Client Secret, and optionally the Enterprise MID.
   - Test the connection, pick Business Units, then Save & scan.
6. When the scan completes, the dashboard and all explorers fill with live data.

## 4. Architecture
```
Browser (MCNexus App.dc.html)
   │  same-origin fetch, HttpOnly session cookie
   ▼
Node server (server/mcnexus-server.js)
   ├─ Auth: scrypt passwords, in-memory sessions (8h idle)
   ├─ Store: server/data/store.json (users, connections, scan index, triage, settings)
   │         server/data/scans/<connId>/<n>.json (full snapshot per scan)
   ├─ Crypto: AES-256-GCM for client secrets (server/data/.key or MCNEXUS_KEY)
   └─ SFMC client: OAuth2 client_credentials per BU (account_id), REST + SOAP,
                   pagination, 429/5xx retry with backoff, property fallback
   ▼
Salesforce Marketing Cloud (auth / rest / soap endpoints per tenant subdomain)
```

### Scan pipeline
1. **Organization** — tokenContext plus the SOAP BusinessUnit list (all accounts).
2. **Security** — the SOAP AccountUser list (enterprise-wide).
3. **Per Business Unit**, using a BU-scoped token:
   - **Data** — DataExtension, DataExtensionField, DataFolder
   - **SQL** — QueryDefinition
   - **Automation** — automations, with details, imports and scripts
   - **Journey** — interactions (all versions), details and eventDefinitions
   - **Content / CloudPages** — asset query
4. **Analysis:**
   - resolve relationships
   - build the graph
   - run the rules
   - score assets, BUs and domains
   - compute coverage
   - derive inventory, limitations, architecture notes and quick wins
5. **Persist:** the snapshot is written to disk. Compare uses stable finding IDs.

### Scoring
Severity weights for health scores: CRIT 10, HIGH 4, MED 1.5, LOW 0.4. The same formula applies to the org, each BU and each domain:

`health = 100 − 100·P / (P + 10 + 1.5·N)`

- `P` = the weighted sum of findings in scope
- `N` = the number of assets in scope

Each asset starts at 100 and loses a fixed amount per finding: 45 (critical), 25 (high), 12 (medium), 5 (low). It never drops below 20.

Coverage is the share of successful collection calls per module.

## 5. API reference (server)
| Method | Path | Notes |
| --- | --- | --- |
| GET | /api/health | `{ok, version, ruleset, firstRun}`, no auth |
| GET | /api/session | Current user or null |
| POST | /api/login · /api/logout | First login creates the Owner |
| GET/PUT | /api/settings | `rulesX`, `naming`, `scan` (default mode/modules, limits), `report` (firm, logo, disclaimer, format), `data` (keepScans) + rule catalog |
| GET | /api/connections | List (no secrets) |
| POST | /api/connections/test | Live 6-step connection test and BU discovery |
| POST | /api/connections | Create, or re-authenticate (`reauth: id`) |
| DELETE | /api/connections/:id | Also deletes its scans and triage |
| PATCH | /api/connections/:id | Edit name/env/subdomain/MID; rotate Client ID or Secret. Tests credentials first unless `test:false`; nothing saved on failure |
| DELETE | /api/connections/:id/scans | Clear scan history + triage (connection kept) |
| GET | /api/connections/:id/export | JSON download of snapshots + triage (no secrets) |
| POST | /api/me/password | Change password (signs out other sessions) |
| GET | /api/me/sessions · POST /api/me/signout-others | Session list / revoke |
| GET | /api/about | Version, uptime, data size, key source |
| POST | /api/connections/:id/access | Access assessment (per API area) |
| GET | /api/connections/:id/dataset[?scan=#NNN] | Full dataset for the UI |
| PUT | /api/connections/:id/triage | Persist status, owner, notes, in-report |
| GET | /api/connections/:id/compare?a=&b= | Added and resolved findings |
| POST | /api/scans | Start a scan `{connId, mids[], modules[], mode, naming}` |
| GET | /api/jobs/:id · POST /api/jobs/:id/cancel | Progress polling and cancellation |

## 6. Rule catalog (v2.0)
DE-RET-001, DE-PK-001, DE-ORP-001, SQL-001, SQL-007, SQL-TGT-001, SQL-SRC-001, AUTO-FAIL-002, AUTO-STL-001, AUTO-EMP-001, JRN-COR-004, JRN-ENT-001, JRN-VER-002, CP-002, SEC-SCR-001, USR-INA-001, CNT-REF-002, CNT-DE-001, GOV-NAM-001.

Severity overrides and enable/disable are set in **Admin → Rules** and apply from the next scan. Naming patterns (**Admin → Rules → Naming**) drive GOV-NAM-001.

## 7. Status and known limitations
- **Not yet validated against a live tenant.**
  - This was built from SFMC API documentation. Expect adjustments on the first real scan.
  - Likely areas: exact automation status and last-run fields, and journey entry-source shapes. Some SOAP properties may also be rejected in some editions.
  - Rejected SOAP properties fall back to a minimal property list automatically. Other failures show in the scan log and in coverage.
- **Not collectable via public API:** installed packages and user role assignments.
- **Not collected in this version:** send/open tracking and row-level data (for example, duplicate rates).
- **Limits for large orgs:** capped by `MCNEXUS_MAX_PAGES` and `MCNEXUS_MAX_DETAIL`. When a cap is hit, coverage is marked PARTIAL. The UI shows the first 400 findings or assets per filter.
- **Deployment:**
  - Sessions are in-memory, so a restart signs users out.
  - It runs as a single process with a JSON-file store. That suits a consultant laptop or a single VM.
  - For multi-user hosting, move the store to a database and put TLS in front.
- **Report formats:** PDF uses the browser print dialog. "Excel" exports CSV (UTF-8 with BOM).

## 8. Recommended next steps
1. Run a first scan against a sandbox. Fix any field-shape issues reported in the scan log.
2. Add automation run history (the legacy automation instance endpoints) to strengthen AUTO-FAIL-002 and JRN-COR-004.
3. Add user role retrieval (SOAP Role / AccountUser roles) to restore admin-specific inactivity checks.
4. Move to SQLite or Postgres, add persistent sessions, and add multi-user roles (Owner / Consultant / Viewer).
5. Add a CI syntax check (`node --check`) and fixture-based tests for `analyze()`.

## 9. Operations
- **Backup:** copy `server/data/` (it contains `.key` — without it, stored secrets can't be decrypted).
- **Key rotation:**
  1. Export the connections.
  2. Set a new `MCNEXUS_KEY`.
  3. Re-authenticate each connection. This re-encrypts the secret.
- **Reset:** stop the server and delete `server/data/`. The next sign-in becomes the first run again.
