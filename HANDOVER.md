# MCNexus — Handover

**Version:** 1.0.0 · **Rule set:** v2.1 · **Date:** 30 Sep 2026

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
1. Install Node 22 or newer.
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
   ├─ Auth: scrypt passwords; sessions in the store, keyed by sha256(token) (8h idle, 7-day absolute); sign-in throttling
   ├─ Store (server/store.js): one async contract, two backends
   │    JSON (default): server/data/store.json + scans/<connId>/<n>.json
   │    PostgreSQL (DATABASE_URL, Neon): server/store-pg.js + server/schema.sql
   ├─ Crypto: AES-256-GCM for client secrets (server/data/.key or MCNEXUS_KEY)
   └─ SFMC client: OAuth2 client_credentials per BU (account_id), REST + SOAP,
                   pagination, 429/5xx retry with backoff, property fallback
   ▼
Salesforce Marketing Cloud (auth / rest / soap endpoints per tenant subdomain)
```

### Scan pipeline
A scan is a job in the store, worked through as short, resumable steps (one per BU and module; content is paged over several steps). Each step saves what it collected; the last step merges everything and analyses it. Locally a background loop runs the steps. On Vercel (or `MCNEXUS_SCAN_MODE=poll`) each progress poll from the UI runs one step. A crashed or abandoned step is retried once its 10-minute lease expires.

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
5. **Persist:** the snapshot is saved to the store (JSON files or PostgreSQL). Compare uses stable finding IDs.

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
| GET | /api/jobs/:id · POST /api/jobs/:id/cancel | Progress and cancellation. In poll mode each GET also runs the next scan step. Starting a scan while one runs returns 409 with that `jobId` |

## 6. Rule catalog (v2.1)
DE-RET-001, DE-PK-001, DE-ORP-001, SQL-001, SQL-007, SQL-TGT-001, SQL-SRC-001, AUTO-FAIL-002, AUTO-STL-001, AUTO-EMP-001, JRN-COR-004, JRN-ENT-001, JRN-VER-002, CP-002, SEC-SCR-001, USR-INA-001, CNT-REF-002, CNT-DE-001, GOV-NAM-001.

Severity overrides and enable/disable are set in **Admin → Rules** and apply from the next scan. Naming patterns (**Admin → Rules → Naming**) drive GOV-NAM-001.

**Changes in v2.1** (no finding IDs changed):
- SQL-TGT-001, SQL-SRC-001, JRN-ENT-001 and CNT-DE-001 only report a DE as missing when that Business Unit's DE list was collected. `ENT.` names need the Enterprise BU to have been scanned. Before, a scan without Data, a BU whose DE retrieve failed, or a child-BU-only scan reported every reference as missing.
- DE-ORP-001 only runs when SQL, Automation, Journey, Content and CloudPages all ran without failures. Before, a Quick Scan marked every DE unchanged for a year as orphaned. The scan log notes when the check is skipped.
- Hitting `MCNEXUS_MAX_PAGES` on any SOAP retrieve or REST list now marks that module PARTIAL. Before, only automation/journey detail and content were flagged; everything else was cut off silently. A BU whose DE list was cut off is treated as not collected for the missing-DE rules. A cut-off field list is discarded, so it can't produce a false DE-PK-001.
- REST paging trusts the reported total over a short page, because SFMC can return fewer items per page than requested. Before, a short first page ended collection after page 1.

## 7. Status and known limitations
- **Not yet validated against a live tenant.**
  - This was built from SFMC API documentation. Expect adjustments on the first real scan.
  - Likely areas: exact automation status and last-run fields, and journey entry-source shapes. Some SOAP properties may also be rejected in some editions.
  - Rejected SOAP properties fall back to a minimal property list automatically. Other failures show in the scan log and in coverage.
- **Not collectable via public API:** installed packages and user role assignments.
- **Not collected in this version:** send/open tracking and row-level data (for example, duplicate rates).
- **Limits for large orgs:** capped by `MCNEXUS_MAX_PAGES` and `MCNEXUS_MAX_DETAIL`. When a cap is hit, coverage is marked PARTIAL. The UI shows the first 400 findings or assets per filter.
- **Deployment:**
  - Storage can be JSON files (laptop or single VM) or PostgreSQL (`DATABASE_URL`, Neon). See "Moving to PostgreSQL" in server/README.md. With JSON storage, run a single process.
  - In poll mode (Vercel) a scan advances only while the progress screen is open. If the tab is closed, the scan pauses; starting a scan for that org again re-attaches to it and carries on.
  - The final analysis step holds the whole org in memory, as before, and each step must fit the function time limit. Very large Business Units may need a higher Vercel `maxDuration`.
  - For multi-user hosting, put TLS in front.
- **Report formats:** PDF uses the browser print dialog. "Excel" exports CSV (UTF-8 with BOM).

## 8. Recommended next steps
1. Run a first scan against a sandbox. Fix any field-shape issues reported in the scan log.
2. Add automation run history (the legacy automation instance endpoints) to strengthen AUTO-FAIL-002 and JRN-COR-004.
3. Add user role retrieval (SOAP Role / AccountUser roles) to restore admin-specific inactivity checks.
4. Add multi-user roles (Owner / Admin / Consultant / Viewer), invites and password reset. PostgreSQL storage and persistent sessions are done; the schema already has the invite and password-reset tables.
5. Add CI (GitHub Actions) that runs `npm ci && npm test` on every push. The test suites exist (`test/`).

## 9. Operations
- **Backup:** JSON storage: copy `server/data/` (it contains `.key` — without it, stored secrets can't be decrypted). PostgreSQL: Neon point-in-time restore or branches, plus a safe copy of `MCNEXUS_KEY`.
- **Key rotation:**
  1. Export the connections.
  2. Set a new `MCNEXUS_KEY`.
  3. Re-authenticate each connection. This re-encrypts the secret.
- **Reset:** stop the server and delete `server/data/`. The next sign-in becomes the first run again.
