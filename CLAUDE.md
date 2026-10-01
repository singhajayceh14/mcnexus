# CLAUDE.md — MCNexus

Standing instructions for any AI or developer working on this project.

## What this is
MCNexus is a read-only assessment tool for Salesforce Marketing Cloud Engagement (SFMC). Consultants and architects use it to review an org's health, dependencies and governance across Business Units.

## Layout
- `MCNexus App.dc.html` — **the product UI.** One Design Component: a template plus a `class Component extends DCLogic` logic block. Opens directly in a browser.
- `support.js` — DC runtime. Never edit by hand.
- `server/mcnexus-server.js` — **the backend.** Node 18+, no npm dependencies. Serves the UI, handles auth, stores data and calls SFMC.
- `server/README.md` — how to run it and how to set up the SFMC installed package.
- `server/data/` — created at runtime (store.json, .key, scans/). **Never commit.**
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
7. **Domain order is fixed** (`DOMAINS` in the server). Scan `dom[]` arrays are aligned to it. Append new domains only at the end.

## Data contract (server → UI)
`GET /api/connections/:id/dataset` returns:
- `scans[]` — summary per scan: `{id, date, health, cov, sev[5], rules, assets, dom[], clean, mode, by}`
- `bus[]`
- `domains[]`
- `findings[]` — `{id, rule, sev, domain, bu, objType, obj, objKey, title, why, evidence[[k,v]], affected, rec, limit, chain?}`
- `assets[]` — `{key, name, type, bu, health, status, config[[k,v]], deps[], dependents[], history[], degree}`
- `graph` — `{nodes:{key:[name,type,bu]}, edges:[[from,to,rel]]}` (the `nodes` map holds only virtual nodes: data views, emails, users)
- `typeCounts`, `model`, `modules`, `inventory`, `limits`, `archNotes`, `quickWins`
- `triage`, `owners`

Asset keys are `TYPE:MID:id`: DE, SQL, AUTO, IMP, SCR, JRN, CNT. Virtual node keys: DV, EML, USR, NAM.

## Adding a rule
1. Add a row to `RULES`: `[id, name, CATEGORY, objectType, defaultSev, version]`. CATEGORY must map through `DOMAIN_OF`.
2. Emit it inside `analyze()` with `finding(ruleId, asset, {why, evidence, rec, …})`, guarded by `mods.has(module)`.
3. Increment `rulesRun` for each evaluation.
4. Bump `RULESET` when rule semantics change.

## Commands
- Run: `node server/mcnexus-server.js` (or `npm start`), then open http://127.0.0.1:8787
- Syntax check: `node --check server/mcnexus-server.js`
