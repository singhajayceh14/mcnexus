# MCNexus — live version

Read-only assessment of Salesforce Marketing Cloud Engagement orgs, fed by real metadata from your org's APIs.

## Run

Needs Node 18+. No npm install required.

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
- `MCNEXUS_KEY`: 64-char hex AES key. If unset, a key is generated at `server/data/.key`.
- `MCNEXUS_DATA`: data folder (default `server/data`).
- `MCNEXUS_MAX_PAGES` (40), `MCNEXUS_MAX_DETAIL` (400), `MCNEXUS_CONCURRENCY` (6): limits for large orgs. When a limit is hit, coverage is marked partial.

## Security

- Client secrets are encrypted at rest with AES-256-GCM and never sent back to the browser.
- Sessions use an HttpOnly, SameSite=Strict cookie with an 8-hour idle timeout.
- All SFMC calls are read-only: `Retrieve`, `GET`, and the asset query `POST`.
- Back up `server/data/`: it holds connections, scan snapshots and triage.
