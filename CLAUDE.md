# CLAUDE.md — MCNexus

Standing instructions for any AI or developer working on this project.

## What this is
MCNexus is a read-only assessment tool for Salesforce Marketing Cloud Engagement (SFMC). Consultants and architects use it to review an org's health, dependencies and governance across Business Units.

## Layout
- `MCNexus App.dc.html` — **the product UI.** One Design Component: a template plus a `class Component extends DCLogic` logic block. Opens directly in a browser.
- `support.js` — DC runtime. Never edit by hand.
- `server/mcnexus-server.js` — **the backend.** Node 22+. Serves the UI, handles auth and sessions, calls SFMC, runs the rules. Scans are resumable jobs: `STEPS` (one per BU × module, content paged across steps) run by `runStep()`, which holds a lease. A step must be idempotent: it collects into its own part and never mutates earlier parts. New collection goes into a step plus the plan built in `STEPS.org`.
- `server/analyze.js` — the rule catalog (`RULES`, `DOMAINS`, `RULESET`), SQL/AMPscript parsers and `analyze()`. No I/O; it also runs in `server/analyze-worker.js`, the worker thread that analyses a finished scan.
- `server/store.js` — the storage contract (documented at the top) and `JsonStore` (default). `server/store-pg.js` — `PgStore` for PostgreSQL/Neon, chosen when `DATABASE_URL` is set. Routes only talk to `store`; never read or write files or SQL from a route.
- `server/schema.sql` — PostgreSQL schema. Idempotent; each statement ends with `;` at end of line and contains no other `;` (the Neon HTTP driver runs them one by one). Change it by appending, and bump `schema_version` / `SCHEMA_VERSION`.
- `server/migrate-json-to-pg.js` — installs the schema and copies a JSON data folder into PostgreSQL.
- `test/` — `node:test` suites. SFMC is faked in `test/helpers.js`; the store and API suites run on both stores (PostgreSQL via PGlite).
- `server/README.md` — how to run it and how to set up the SFMC installed package.
- `server/data/` — created at runtime by the JSON store (store.json, .key, scans/). **Never commit.** Also never commit `.env` files (`DATABASE_URL`, `MCNEXUS_KEY`).
- `MCNexus Prototype.dc.html` — the original clickable prototype (ACME demo data). Keep it as a design reference only.
- `_ds/industry-…/` — the bound **Industry** design system (styles.css + bundle).
- `uploads/MCNexus_Solution_Design.md` — the original solution design brief.

## Hard rules
1. **Read-only against SFMC.** Only SOAP `Retrieve`, REST `GET`, and `POST /asset/v1/content/assets/query`. Never add create, update, delete, send, publish or execute calls.
2. **Secrets stay server-side.** Client secrets are encrypted with AES-256-GCM (`enc`/`dec`) and never returned by any endpoint. `publicConn()` is the only shape a connection is exposed in.
3. **Visual system is Industry.**
   - Steel-blue accent, Barlow Condensed headings over Barlow body.
   - Square corners, hairline borders, `.blueprint` frames with 4 corner marks.
   - Colors only from `var(--color-*)` tokens. No new colors, no rounded cards, no emoji.
4. **DC authoring rules.**
   - Inline styles only.
   - Template holes are dotted lookups only (`{{ a.b }}`); compute everything in `renderVals()`.
   - Always close tags.
   - Always set `hint-*` on `sc-if` / `sc-for`.
5. **Demo fallback must keep working.** If `/api/health` isn't reachable, the UI runs on the embedded `DEMO` dataset with a banner. Every new UI value needs both a `live` path and a demo path.
6. **Finding IDs are stable:** `F-` + sha1(rule|objKey)[0:6]. Don't change the scheme; triage and scan-compare depend on it.
7. **Domain order is fixed** (`DOMAINS` in `server/analyze.js`). Scan `dom[]` arrays are aligned to it. Append new domains only at the end.

## Data contract (server → UI)
`GET /api/connections/:id/dataset` returns:
- `scans[]` — summary per scan: `{id, date, health, cov, sev[5], rules, assets, dom[], clean, mode, by}`
- `bus[]`
- `domains[]`
- `findings[]` — `{id, rule, sev, domain, bu, objType, obj, objKey, title, why, evidence[[k,v]], affected, rec, limit, chain?, code?}`
  - `code` (code-based rules) — `[{where, line, col, lines[[n, text, isHit]]}]`: excerpts around each location, credential values masked. `where` is the code segment (`content`, `views.html`, `views.html.slots.<slot>.blocks.<block>`, `script`).
- `assets[]` — `{key, name, type, bu, health, status, config[[k,v]], deps[], dependents[], history[], degree}`
- `graph` — `{nodes:{key:[name,type,bu]}, edges:[[from,to,rel]]}` (the `nodes` map holds only virtual nodes: data views, emails, users)
- `typeCounts`, `model`, `modules`, `inventory`, `limits`, `archNotes`, `quickWins`
- `triage`, `owners`

Asset keys are `TYPE:MID:id`: DE, SQL, AUTO, IMP, SCR, JRN, CNT. Virtual node keys: DV, EML, USR, NAM.

## Adding a rule
All in `server/analyze.js`:
1. Add a row to `RULES`: `[id, name, CATEGORY, objectType, defaultSev, version]`. CATEGORY must map through `DOMAIN_OF`.
2. Emit it inside `analyze()` with `finding(ruleId, asset, {why, evidence, rec, …})`, guarded by `mods.has(module)`.
3. Increment `rulesRun` for each evaluation.
4. Bump `RULESET` when rule semantics change.

## Commands
- Run: `node server/mcnexus-server.js` (or `npm start`), then open http://127.0.0.1:8787
- Syntax check: `node --check server/mcnexus-server.js`
- Tests: `npm install` once, then `npm test`. Tests never reach a real org. Without `npm install` the PostgreSQL suites skip. `MCNEXUS_TEST_PG=<url>` also runs the store contract against a real database (use an empty Neon branch: it deletes rows).
- PostgreSQL: `DATABASE_URL=… npm run db:schema` installs the schema; `DATABASE_URL=… npm run db:migrate [-- --from server/data]` copies a JSON data folder. `MCNEXUS_KEY` is required whenever `DATABASE_URL` is set.
