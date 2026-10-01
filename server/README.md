# MCNexus — live version

Read-only assessment of Salesforce Marketing Cloud Engagement orgs, fed by real metadata from your org's APIs.

## Run

Needs Node 22+. The default JSON-file storage needs no npm install. PostgreSQL (Neon) needs `npm install`.

```
node server/mcnexus-server.js
```

Open http://127.0.0.1:8787. The first sign-in creates the owner account (password 8+ characters).

If you open `MCNexus App.dc.html` without the server, it runs on demo data and shows a banner saying so.

## SFMC installed package

Setup → Apps → Installed Packages → New → Add Component → **API Integration → Server-to-Server**. Grant **read** on:
Email, Documents and Images, Saved Content, Journeys, List and Subscribers, Data Extensions, File Locations, Automations, Accounts, Users, Webhooks, Audiences.
Give the package access to every Business Unit you want scanned.

In MCNexus: Connections → Connect an SFMC org → enter the subdomain (or the Auth Base URI), Client ID, Client Secret and the Enterprise MID (optional).

## What is collected

| Module | API |
| --- | --- |
| Organization | REST tokenContext, SOAP BusinessUnit |
| Security | SOAP AccountUser, secret scan of script activities |
| Data | SOAP DataExtension, DataExtensionField, DataFolder |
| SQL | SOAP QueryDefinition (sources parsed from SQL) |
| Automation | REST /automation/v1 automations, imports, scripts |
| Journey | REST /interaction/v1 interactions, eventDefinitions |
| Content / CloudPages | REST /asset/v1 query (AMPscript/SSJS parsed for DE and block references) |
| Governance | Naming patterns + orphan analysis |

The scanner builds a dependency graph from these relationships: import/query → DE, DE → query, automation → activity, DE → journey entry, journey → email, DE → content.

Not collected: installed packages (no public API), send/open tracking, and row-level data.

## Configuration (env vars)

- `PORT` (8787) and `HOST` (127.0.0.1). Keep it on localhost unless you put it behind TLS.
- `MCNEXUS_KEY`: 64-char hex AES key. If unset, a key is generated at `server/data/.key` (JSON storage only).
- `MCNEXUS_DATA`: data folder for JSON storage (default `server/data`).
- `DATABASE_URL`: a Neon connection string. When set, everything is stored in PostgreSQL and nothing is written to disk. Requires `MCNEXUS_KEY`. The Neon serverless HTTP driver is used, so the URL must be a Neon one.
- `MCNEXUS_MAX_PAGES` (40), `MCNEXUS_MAX_DETAIL` (400), `MCNEXUS_CONCURRENCY` (6): limits for large orgs. When a limit is hit, coverage is marked partial.

## Security

- Client secrets are encrypted at rest with AES-256-GCM and never sent back to the browser.
- Sessions use an HttpOnly, SameSite=Strict cookie with an 8-hour idle timeout.
- All SFMC calls are read-only: `Retrieve`, `GET`, and the asset query `POST`.
- Back up `server/data/`: it holds connections, scan snapshots and triage. On PostgreSQL, use Neon's point-in-time restore or branches, and keep `MCNEXUS_KEY` somewhere safe — the database alone can't decrypt client secrets.

## Moving to PostgreSQL (Neon)

1. Create a Neon project (or a branch) and copy its connection string.
2. Install the schema: `DATABASE_URL=<url> npm run db:schema`.
3. Copy existing data (optional): `DATABASE_URL=<url> MCNEXUS_KEY=<key> npm run db:migrate -- --from server/data`.
   - Re-running is safe: existing rows are never overwritten.
   - Client secrets are copied encrypted. Use the key they were encrypted with — the contents of `server/data/.key` if you never set `MCNEXUS_KEY`. The script checks the key and never prints it.
   - Every snapshot is compared with its source file; the exit code is 1 on any mismatch.
4. Start the server with `DATABASE_URL` and `MCNEXUS_KEY` set. `/api/health` returns 503 and explains why if the database or schema isn't reachable.
