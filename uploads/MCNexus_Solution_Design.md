# MCNexus Platform
## Complete Solution Design Document (SDD)

**Document Version:** 1.0  
**Status:** Solution Design / Pre-Development  
**Primary Use:** Source of truth for product architecture, scope, assessment methodology, UX, and development planning  
**Target Platform:** Salesforce Marketing Cloud Engagement (SFMC)  
**Initial Product Form:** React Web Application + Secure Backend  
**Future Extension:** Chrome Extension companion  
**Assessment Mode:** Read-only

---

# 1. Executive Summary

The MCNexus Platform is a professional assessment, architecture-review, governance, security-review, and operational-health solution for Salesforce Marketing Cloud Engagement organizations.

The platform will connect to an SFMC Enterprise using a client-provided Installed Package / OAuth integration with appropriate read-only access, discover accessible Business Units and metadata, normalize the collected information, build cross-object dependency relationships, execute deterministic health-check rules, calculate risk and health scores, and produce detailed technical and executive reports.

The product is intentionally more than a metadata inventory tool.

It should answer:

- What exists in the SFMC org?
- How is the org structured?
- How many Business Units exist and how are they configured?
- What data assets exist?
- How are Data Extensions related?
- Which Data Extensions are used by automations and journeys?
- Which automations are active, stale, failing, or potentially unused?
- Which journeys are active, stale, duplicated, or dependent on risky upstream processes?
- Which CloudPages and code assets require review?
- What integrations and installed packages exist?
- What security and governance risks exist?
- What assets are unused, orphaned, duplicated, or stale?
- What dependencies exist between assets?
- What could be affected if an asset is changed or retired?
- Which findings have the highest business or technical impact?
- What remediation should the client prioritize?
- What is the evidence behind each finding?
- What areas could not be assessed because of API or permission limitations?

The product must be evidence-based, transparent about coverage, read-only, modular, extensible, and suitable for professional Salesforce consulting engagements.

---

# 2. Product Vision

## Vision

Build a professional **SFMC Org Health, Architecture & Governance Assessment Platform** that allows Salesforce consultants, architects, managed-service teams, and enterprise clients to assess the health and complexity of an SFMC environment in a repeatable and evidence-driven way.

## Product Positioning

The product should combine capabilities conceptually similar to:

- Enterprise observability
- Configuration assessment
- Architecture assessment
- Security assessment
- Data architecture review
- Dependency mapping
- Static code/configuration analysis
- Technical debt analysis
- Executive reporting

The product should not be positioned as a generic "metadata export."

---

# 3. Business Objectives

## Primary objectives

1. Reduce the manual effort required for SFMC health assessments.
2. Standardize the assessment methodology across consulting engagements.
3. Provide repeatable and evidence-based findings.
4. Identify technical, operational, security, governance, and architectural risks.
5. Visualize dependencies across SFMC assets.
6. Identify unused, orphaned, stale, and duplicate assets.
7. Provide client-ready executive and technical reports.
8. Provide historical scan comparison.
9. Establish a reusable rules engine that can evolve over time.
10. Create a foundation for a future multi-client SaaS platform.

## Business value

The platform should help organizations:

- Understand their current SFMC estate.
- Reduce operational risk.
- Improve governance.
- Reduce technical debt.
- Improve data architecture.
- Identify security concerns.
- Improve automation reliability.
- Understand Journey dependencies.
- Rationalize unused assets.
- Prepare for migrations or redesigns.
- Establish a remediation roadmap.

---

# 4. Target Users

## 4.1 Salesforce Marketing Cloud Architect

Needs:

- Architecture visualization
- Dependency graph
- Data model assessment
- Integration analysis
- Technical debt
- Cross-BU comparison

## 4.2 SFMC Developer

Needs:

- SQL analysis
- AMPscript/SSJS static analysis
- Automation analysis
- CloudPage analysis
- Asset dependencies
- Concrete technical findings

## 4.3 SFMC Administrator

Needs:

- Inventory
- Users
- BUs
- Automations
- Journeys
- Governance
- Unused assets

## 4.4 Security / Compliance Team

Needs:

- Access analysis
- Installed Package review
- API access
- Credential/security observations
- Sensitive-data indicators where safely detectable
- Evidence

## 4.5 Consulting / Delivery Team

Needs:

- Repeatable assessments
- Executive reports
- Technical reports
- Findings management
- Scan comparison
- Client presentation material

## 4.6 Client Executive

Needs:

- Overall health
- Major risks
- Business impact
- Top recommendations
- 30/60/90 day roadmap

---

# 5. Product Principles

The following principles are mandatory.

1. **Read-only by default.**
2. **Evidence before conclusion.**
3. **Do not invent API capabilities.**
4. **Do not claim an area is healthy when it was not accessible.**
5. **Separate collection from analysis.**
6. **Separate deterministic rules from AI-generated narrative.**
7. **Support Enterprise and Business Unit scope explicitly.**
8. **Treat dependencies as first-class data.**
9. **Keep customer data collection to the minimum required.**
10. **Never execute customer AMPscript or SSJS as part of scanning.**
11. **Credentials must be handled server-side and securely.**
12. **Every scanner reports coverage and limitations.**
13. **Rules must be configurable and versioned.**
14. **Findings must be reproducible from collected evidence.**
15. **Architecture must support future multi-org and multi-client operation.**

---

# 6. Scope

## 6.1 In Scope

### Organization

- Enterprise
- Business Units
- BU hierarchy
- BU configuration
- BU comparison

### Security

- Users
- Roles/permissions where accessible
- Installed Packages
- API integrations
- Access scopes
- Security-related configuration
- Credential/code exposure indicators

### Data

- Data Extensions
- Data Extension fields
- Sendability
- Send relationships
- Primary keys
- Retention
- Folders
- Usage
- Relationships
- Contact Builder
- Subscriber-related configuration

### Automation

- Automations
- Activities
- Schedules
- SQL Query Activities
- Import Activities
- Export Activities
- File Transfer Activities
- Script Activities
- Execution metadata where accessible

### SQL

- Static SQL analysis
- Dependency extraction
- Naming
- Query complexity
- Anti-pattern detection

### Journeys

- Journeys
- Versions
- Entry sources
- Activities
- Decision branches
- Waits
- Email/SMS/etc. activities
- Dependencies
- Entry Data Extensions
- Re-entry configuration where accessible

### Content

- Content Builder assets
- Emails
- Content Blocks
- Templates
- Images
- Dynamic Content
- Code snippets
- References/dependencies where available

### CloudPages

- CloudPages
- Landing pages
- Microsites
- AMPscript
- SSJS
- Static code analysis
- Dependencies

### Integrations

- Installed Packages
- REST/SOAP API usage indicators where available
- SFTP/file-transfer relationships
- External integration metadata where available

### Governance

- Naming conventions
- Folder structure
- Ownership indicators
- Lifecycle
- Unused assets
- Orphan assets
- Duplicate/similar assets
- Stale assets

### Reporting

- Executive report
- Technical report
- Findings
- Recommendations
- Risk matrix
- Scan coverage
- Scan comparison
- Export

---

# 7. Out of Scope for Initial Release

The following should not be enabled in the initial read-only product:

- Creating assets
- Updating assets
- Deleting assets
- Publishing assets
- Activating journeys
- Modifying automations
- Changing users
- Changing permissions
- Changing retention settings
- Sending email
- Sending SMS
- Executing customer code
- Writing customer data
- Automated remediation

Future versions may introduce controlled remediation with explicit user approval, but that is not part of the initial architecture.

---

# 8. Assessment Domains

The platform will assess at least these domains:

1. Organization & Business Unit Architecture
2. Security & Access
3. Data Architecture
4. Contact Model
5. Subscriber Management
6. Automation Studio
7. SQL / Query Quality
8. Journey Builder
9. Content Builder
10. Email Governance
11. CloudPages
12. AMPscript / SSJS Static Analysis
13. Integrations
14. Installed Packages
15. Folder & Asset Governance
16. Naming Standards
17. Unused / Orphaned Assets
18. Duplicate / Similar Assets
19. Dependency Architecture
20. Operational Health
21. Performance Indicators
22. Technical Debt
23. Architecture Quality
24. Assessment Coverage & Limitations

---

# 9. High-Level Architecture

```text
                         ┌─────────────────────────────┐
                         │       React Web App         │
                         │                             │
                         │ Dashboard                   │
                         │ Assessment Setup            │
                         │ Org Explorer                │
                         │ Asset Explorer              │
                         │ Dependency Explorer         │
                         │ Findings                    │
                         │ Architecture                │
                         │ Reports                     │
                         └──────────────┬──────────────┘
                                        │ HTTPS
                                        ▼
                         ┌─────────────────────────────┐
                         │        Backend API          │
                         │                             │
                         │ Authentication              │
                         │ Scan Orchestration          │
                         │ Tenant / Org Context         │
                         │ API Clients                 │
                         │ Report Generation           │
                         └──────────────┬──────────────┘
                                        │
                ┌───────────────────────┼────────────────────────┐
                │                       │                        │
                ▼                       ▼                        ▼
       ┌────────────────┐     ┌──────────────────┐     ┌────────────────┐
       │ SFMC Collector │     │ Assessment Engine│     │ Report Engine  │
       │                │     │                  │     │                │
       │ REST           │     │ Rule Engine      │     │ PDF            │
       │ SOAP           │     │ Risk Engine      │     │ Excel          │
       │ OAuth          │     │ Score Engine     │     │ HTML           │
       │ Metadata       │     │ Dependency       │     │ Executive      │
       └───────┬────────┘     │ SQL Analyzer     │     └────────────────┘
               │              └────────┬─────────┘
               │                       │
               └──────────────┬────────┘
                              ▼
                    ┌─────────────────────┐
                    │    PostgreSQL       │
                    │                     │
                    │ Organizations       │
                    │ BUs                 │
                    │ Assets              │
                    │ Relationships       │
                    │ Findings            │
                    │ Rules               │
                    │ Scans               │
                    │ Evidence            │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │ Optional AI Layer   │
                    │                     │
                    │ Summaries           │
                    │ Explanations        │
                    │ Recommendations     │
                    └─────────────────────┘
```

---

# 10. Product Form Factor

## Primary product

Use a React web application as the primary user interface.

Reason:

- Better for large dashboards.
- Better for long-running scans.
- Better for reports.
- Better for multi-org support.
- Better for database-backed scan history.
- Better for client collaboration.
- Better for enterprise deployment.
- Better for secure server-side credentials.

## Future Chrome Extension

The Chrome Extension should be a companion, not the primary scanner.

Potential future functionality:

- Detect current SFMC BU/MID from the SFMC browser context.
- Provide quick health status.
- Deep-link to the web application.
- Trigger a BU-specific assessment.
- Show recent findings for the current BU.

Architecture:

```text
Chrome Extension
       │
       ▼
React Web Application
       │
       ▼
Backend
       │
       ▼
SFMC
```

Do not place the full scanner in the extension.

---

# 11. Authentication & Credential Strategy

## Recommended method

Client provides an SFMC Installed Package configured for read-only API access.

Expected configuration may include:

- Client ID
- Client Secret
- Authentication Base URI
- Appropriate API scopes
- Business Unit / Enterprise access as required

The exact scopes must be validated against current Salesforce documentation before implementation.

## Important security rules

Never store secrets in:

- localStorage
- sessionStorage
- URL parameters
- frontend source
- browser logs
- application analytics
- report output

Tokens must not be returned unnecessarily to the browser.

Preferred model:

```text
Browser
   │
   │ Secure HTTPS
   ▼
Backend
   │
   ├── Secure credential storage
   ├── OAuth token handling
   └── SFMC API calls
```

## Access Assessment

Before a full scan, perform an access assessment.

Example:

```text
Authentication              ✓
OAuth                       ✓
Enterprise discovery        ✓
BU discovery                ✓
REST API                    ✓
SOAP API                    ✓
Data Extensions             ✓
Automations                 ✓
Journeys                    ✓
Content                     ✓
CloudPages                  ⚠ Partial
Users                       ⚠ Partial
Permissions                 ⚠ Partial
Tracking                    ✗
```

The final report must include this coverage.

---

# 12. Assessment Lifecycle

```text
1. Connect SFMC
        ↓
2. Validate Authentication
        ↓
3. Determine API Capabilities
        ↓
4. Discover Enterprise/BUs
        ↓
5. Select BUs
        ↓
6. Start Scan
        ↓
7. Collect Metadata
        ↓
8. Normalize Metadata
        ↓
9. Build Relationships
        ↓
10. Build Dependency Graph
        ↓
11. Execute Rules
        ↓
12. Analyze Risk
        ↓
13. Calculate Scores
        ↓
14. Generate Findings
        ↓
15. Generate Recommendations
        ↓
16. Generate Reports
        ↓
17. Store Scan Snapshot
```

---

# 13. Scan Modes

## Quick Scan

Focus on:

- Organization
- BUs
- Basic inventory
- Basic security
- High-value findings

## Full Assessment

Scan all supported modules.

## Custom Assessment

Allow the user to select:

- BUs
- Domains
- Asset types
- Rules

## Future scheduled assessment

Allow recurring assessments and trend analysis.

---

# 14. Scan Job Architecture

A scan can contain thousands of assets.

Use asynchronous scan jobs.

```text
Scan
 ├── Discovery
 ├── Collection
 ├── Normalization
 ├── Relationship Mapping
 ├── Rule Evaluation
 ├── Scoring
 └── Reporting
```

Track:

- Scan ID
- Organization
- BUs
- Start time
- End time
- Status
- Current module
- Assets scanned
- Rules executed
- Findings generated
- Errors
- Warnings
- Coverage

Statuses:

```text
QUEUED
RUNNING
PARTIAL
COMPLETED
FAILED
CANCELLED
```

---

# 15. Error Handling

A failure in one module must not automatically terminate the complete assessment.

Example:

```text
Journey API failure
       ↓
Record scanner error
       ↓
Mark Journey module PARTIAL
       ↓
Continue remaining scanners
       ↓
Include limitation in report
```

Every scanner should return:

```text
SUCCESS
PARTIAL
UNAVAILABLE
FAILED
```

---

# 16. Assessment Coverage Model

Every scanner must expose:

```text
Module
API
Permission / Scope
Objects Collected
Checks Executed
Coverage
Limitations
Errors
```

Example:

```text
Data Extension Assessment

Collection:
REST + SOAP

Collected:
Name
Customer Key
Fields
Sendability
Retention
Folder
Relationships

Checks:
Naming
Retention
Primary Key
Sendability
Usage
Dependencies
Orphan detection

Coverage:
98%

Limitations:
Row-level profiling not enabled.
```

Never infer health from unavailable information.

---

# 17. Organization & Business Unit Assessment

## Collect

- Enterprise MID
- BU MID
- Parent BU
- Child BUs
- Name
- Timezone
- Locale
- Currency where accessible
- Users
- Packages
- Integrations
- Shared assets
- BU-specific assets

## Analyze

- BU hierarchy
- Configuration consistency
- Naming consistency
- Governance consistency
- Shared asset strategy
- API access
- User access
- BU utilization

## Example findings

- Inconsistent BU timezone configuration.
- Duplicate or unclear BU naming.
- Potentially unused BU.
- Inconsistent governance across BUs.
- API integration scope differs between BUs.

---

# 18. Security Assessment

## Users

Analyze where supported:

- Active users
- Inactive users
- Duplicate accounts
- Shared accounts indicators
- User roles
- Last activity where accessible

## Permissions

Analyze:

- Administrative access
- API access
- Least-privilege indicators
- Role inconsistencies

## Installed Packages

Analyze:

- Package inventory
- Package purpose
- API scopes
- BU access
- Potentially unused packages
- Excessive scope indicators

## Code security

Static analysis for:

- Hard-coded credentials
- Client secrets
- Tokens
- Unsafe endpoints
- Sensitive parameters
- Potential unsafe input handling

Do not execute customer code.

---

# 19. Data Extension Assessment

For each DE capture, where accessible:

```text
Name
Customer Key
Object ID
BU
Folder
Created
Modified
Field count
Fields
Data types
Field lengths
Nullable
Default values
Primary key
Sendable
Send relationship
Retention
Usage
Dependencies
Dependents
```

## Checks

### Naming

- Naming convention
- Environment convention
- BU convention
- Functional naming

### Structure

- Missing PK
- Suspicious PK
- Composite key
- Excessive fields
- Suspicious field lengths
- Inconsistent data types
- Email field configuration
- Subscriber key configuration

### Retention

- No retention
- Excessive retention
- Inconsistent retention
- Retention mismatch with governance

### Usage

- Journey
- Automation
- SQL
- Email
- CloudPage
- API
- Import
- Export

### Lifecycle

- Active
- Unused
- Stale
- Orphaned

---

# 20. Row-Level Data Profiling

Row-level profiling must be optional and explicitly controlled.

The default audit should prefer metadata-only analysis.

If future row-level profiling is enabled:

- Minimize retrieved data.
- Avoid storing raw customer records.
- Sample only where necessary.
- Detect data quality statistically.
- Mask or hash sensitive values.
- Never include customer data in reports.

Possible checks:

- Null rate
- Duplicate rate
- Email format indicators
- Key uniqueness
- Date freshness
- Unexpected values
- Approximate data volume

---

# 21. Contact Builder / Data Model Assessment

Analyze:

- Attribute Groups
- Relationships
- Cardinality
- Contact Key
- Population
- Data Extension relationships
- Synchronized DE relationships
- Duplicate relationships
- Unused relationships
- Potential identity inconsistencies

Generate a visual data model.

---

# 22. Subscriber Assessment

Analyze:

- All Subscribers
- Subscriber Keys
- Email addresses
- Status
- Publication Lists
- Send relationships
- Unsubscribe configuration

Potential findings:

- Email address used as identity without documented strategy.
- Subscriber Key inconsistency.
- Unclear subscription model.
- Publication-list governance inconsistency.
- Potential duplicate identity patterns.

Do not claim duplicate subscribers unless the evidence supports it.

---

# 23. Automation Studio Assessment

For each automation:

```text
Name
Key / ID
Status
Schedule
Created
Modified
Activities
Activity sequence
Owner where accessible
Last execution where accessible
Last success where accessible
Last failure where accessible
Duration where accessible
Dependencies
Dependents
```

## Analyze schedules

- High-frequency jobs
- Overlapping jobs
- Potential concurrency
- Scheduling gaps
- Unclear sequencing

## Analyze activities

- SQL
- Import
- Export
- File Transfer
- Script
- Verification
- Other supported activity types

## Operational checks

- Repeated failures
- Long execution
- Stale automation
- Inactive automation
- Potentially unused automation
- Journey dependency

---

# 24. SQL Analyzer

The SQL analyzer performs static analysis only.

Never execute customer SQL outside SFMC.

## Checks

- SELECT *
- Missing filters
- Large joins
- Join complexity
- DISTINCT usage
- GROUP BY complexity
- ORDER BY usage
- UNION
- Nested subqueries
- Hard-coded values
- Hard-coded asset names
- Duplicate SQL
- Unused SQL
- Source dependencies
- Target dependencies

## Example

```text
SQL-001
SELECT * detected

Severity: MEDIUM

Risk:
Schema changes may unexpectedly affect downstream processing.

Recommendation:
Explicitly select required columns.
```

The exact severity must be configurable.

---

# 25. Journey Builder Assessment

For each Journey:

```text
Journey Name
Journey Key
Version
Status
Created
Modified
Entry Source
Entry Data Extension
Activities
Branches
Waits
Goals
Exit Criteria
Re-entry configuration
Dependencies
Dependents
```

## Entry checks

- Entry DE health
- Contact Key
- Re-entry
- Schedule
- Entry filters

## Activity checks

- Email
- SMS
- Push
- Wait
- Decision Split
- Engagement Split
- Update Contact
- Custom activities

## Logic checks

- Dead-end branches
- Missing/default branches
- Long waits
- Duplicate logic
- Unused versions
- Stale versions
- Missing exit criteria

---

# 26. Journey + Automation Correlation

Build cross-domain analysis.

Example:

```text
Automation
   ↓
Customer_Refresh_DE
   ↓
Journey Entry
   ↓
Welcome Journey
```

If the automation has repeated failures, create a correlated finding:

```text
HIGH

Active Journey depends on an upstream automation
with recent execution failures.

Evidence:
Automation: Customer_Refresh
Entry DE: Customer_Refresh_DE
Journey: Welcome Journey
```

This is more valuable than reporting each issue independently.

---

# 27. Content Builder Assessment

Analyze:

- Emails
- Content Blocks
- Templates
- Images
- Dynamic Content
- Code Snippets
- Folders
- References

Checks:

- Unused content
- Duplicate/similar content
- Broken references
- Old assets
- Naming
- Folder governance
- Hard-coded links
- Hard-coded IDs
- Personalization patterns
- Fallback patterns
- Subscription/unsubscribe patterns where applicable

---

# 28. Email Governance

Analyze:

- Sender Profile
- Delivery Profile
- Send Classification
- Publication List
- Suppression
- Subscriber Key
- Personalization
- Dynamic content
- Unsubscribe patterns

The scanner should identify configuration observations, not make unsupported claims about business compliance.

---

# 29. CloudPages Assessment

Analyze:

- Pages
- Collections
- Published status
- URLs
- Folders
- References
- AMPscript
- SSJS

Static analysis checks:

```text
CP-001 Hard-coded credential
CP-002 Hard-coded client secret
CP-003 Hard-coded token
CP-004 Hard-coded endpoint
CP-005 Unvalidated input
CP-006 Potential injection pattern
CP-007 Excessive lookup
CP-008 Missing error handling
CP-009 Sensitive data exposure indicator
CP-010 Deprecated pattern indicator
CP-011 Unused page
CP-012 Broken dependency
```

Never execute customer code.

---

# 30. AMPscript / SSJS Analysis

Static analysis only.

## AMPscript

Check:

- Hard-coded IDs
- Hard-coded URLs
- Hard-coded credentials
- Lookup complexity
- Nested logic
- Repeated lookups
- Potential unsafe inputs
- Missing fallback behavior
- Unused variables where detectable

## SSJS

Check:

- HTTP calls
- REST calls
- SOAP calls
- External endpoints
- Hard-coded credentials
- Error handling
- API usage patterns
- Unsafe input handling
- Excessive processing indicators

---

# 31. Integration Assessment

Inventory:

- Installed Packages
- REST integrations
- SOAP integrations
- SFTP/file-transfer relationships
- External system indicators
- API users where accessible

Build:

```text
External System
      ↓
Integration
      ↓
SFMC
      ↓
Data Extension
      ↓
Automation
      ↓
Journey
```

Find:

- Unknown/unowned integrations
- Potentially unused packages
- Excessive scopes
- Duplicate integrations
- Missing documentation indicators
- Broken dependency chains where evidence exists

---

# 32. Folder & Governance Assessment

Analyze:

- Folder hierarchy
- Naming
- Depth
- Empty folders
- Duplicate folders
- Assets without expected folders
- Shared vs BU-specific assets
- Stale assets

---

# 33. Naming Convention Engine

Rules must be configurable.

Example:

```text
DE_<BU>_<DOMAIN>_<PURPOSE>
AUTO_<BU>_<PURPOSE>
SQL_<BU>_<PURPOSE>
JRN_<BU>_<PURPOSE>
EMAIL_<BU>_<PURPOSE>
CP_<BU>_<PURPOSE>
```

The client should be able to define its own conventions.

Find:

- Invalid names
- Missing prefixes
- Inconsistent separators
- Duplicate names
- Environment collisions

---

# 34. Unused / Orphaned Asset Engine

Definitions must be explicit.

## Unused

An asset has no known current dependency and no recent evidence of usage.

## Orphaned

An asset is not connected to a meaningful active dependency chain and appears disconnected from the active architecture.

## Stale

An asset has not been modified/used for a configurable period.

The system must avoid declaring an asset safe to delete.

Use language such as:

> Candidate for review / retirement.

Never:

> Safe to delete.

---

# 35. Duplicate Detection

Use multiple signals:

- Exact name
- Similar name
- Same structure
- Similar SQL
- Similar Journey topology
- Similar content
- Same dependency pattern

Output:

```text
Potential Duplicate

Asset A
Asset B

Similarity:
High

Evidence:
Same field structure
Same folder pattern
Same downstream usage pattern
```

Do not automatically merge or delete assets.

---

# 36. Dependency Engine

Dependency mapping is a core capability.

Represent assets as nodes and relationships as edges.

Example:

```text
Data Extension
      │
      ├── referenced by SQL
      │
      ├── populated by Automation
      │
      ├── used by Journey
      │
      └── queried by CloudPage
```

Every asset should store:

```json
{
  "assetId": "...",
  "assetType": "DataExtension",
  "dependencies": [],
  "dependents": [],
  "findings": []
}
```

## Relationship types

Examples:

```text
USES
POPULATES
READS
WRITES
TRIGGERS
ENTRY_SOURCE
REFERENCES
CONTAINS
DEPENDS_ON
SENDS_TO
CALLS
```

---

# 37. Blast Radius

For an asset, calculate potential affected assets.

Example:

```text
Customer_Master_DE
       ↓
7 Automations
       ↓
3 Journey Entry Sources
       ↓
3 Journeys
       ↓
12 Emails
```

Display:

- Direct dependents
- Indirect dependents
- Active production dependencies
- High-risk dependencies

---

# 38. Rule Engine

Rules must be data-driven and versioned.

Example:

```json
{
  "ruleId": "DE-RET-001",
  "version": "1.0",
  "category": "DATA",
  "objectType": "DataExtension",
  "name": "Retention Not Configured",
  "severity": "HIGH",
  "description": "Retention is not configured.",
  "detection": "...",
  "recommendation": "Review and configure retention.",
  "enabled": true
}
```

## Rule attributes

- Rule ID
- Version
- Category
- Object type
- Name
- Description
- Severity
- Detection logic
- Evidence requirements
- Risk
- Recommendation
- Remediation effort
- API dependency
- Coverage limitation
- Enabled/disabled

---

# 39. Initial Rule Catalog

The first release should target at least 150 rules.

Suggested distribution:

```text
Organization / BU              10+
Security                       20+
Data Extensions               25+
Contact Model                 10+
Subscriber                    10+
Automation                    20+
SQL                           15+
Journey                       20+
Content                       15+
CloudPages                    15+
Integration                   10+
Governance                    20+
Architecture                  15+
```

Rules can overlap across domains where necessary.

---

# 40. Finding Model

Every finding should contain:

```json
{
  "findingId": "...",
  "ruleId": "...",
  "ruleVersion": "1.0",
  "scanId": "...",
  "severity": "HIGH",
  "category": "DATA",
  "businessUnitId": "...",
  "objectType": "DataExtension",
  "objectId": "...",
  "objectName": "...",
  "title": "...",
  "description": "...",
  "evidence": [],
  "impact": "...",
  "risk": "...",
  "recommendation": "...",
  "remediationEffort": "MEDIUM",
  "confidence": "HIGH",
  "status": "OPEN"
}
```

---

# 41. Severity Model

Use:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

Severity should represent the importance of the detected condition within the assessment methodology.

Do not use severity as a substitute for evidence.

---

# 42. Impact / Likelihood / Confidence

Each finding should separately store:

- Impact
- Likelihood
- Confidence

Example:

```text
Severity: HIGH
Impact: HIGH
Likelihood: MEDIUM
Confidence: HIGH
```

This provides more useful information than a single number.

---

# 43. Health Scoring Model

Do not create an arbitrary score.

Use a documented methodology.

Suggested domain scores:

```text
Organization
Security
Data
Contact Model
Automation
SQL
Journey
Content
CloudPages
Integration
Governance
Architecture
Operations
```

Example display:

```text
Overall Health       82

Security             91
Integration          88
Automation           84
Architecture         82
Operations           79
Journey              78
Data                 76
Governance            72
CloudPages            68
```

The score should be reproducible from findings, coverage, and configured weights.

If coverage is incomplete, display coverage separately.

---

# 44. Coverage Score

Coverage is NOT the same as health.

Example:

```text
Health: 82
Audit Coverage: 94%
```

Do not convert missing data directly into a bad health score unless the scoring methodology explicitly supports that.

---

# 45. Architecture Assessment

Create a dedicated architecture assessment.

Analyze:

- BU architecture
- Data architecture
- Process architecture
- Journey architecture
- Integration architecture
- Security architecture
- Governance architecture

Identify patterns such as:

- High coupling
- Single points of dependency
- Duplicate data structures
- Legacy assets
- Cross-BU inconsistency
- Excessive automation dependency
- Unclear ownership
- Complex dependency chains

All observations must be evidence-based.

---

# 46. Technical Debt

Create a technical debt indicator based on:

- Stale assets
- Duplicate assets
- Orphaned assets
- Naming violations
- Complex SQL
- Complex automation
- Legacy content
- Unused journeys
- Unused CloudPages
- Inconsistent architecture

Display:

```text
Technical Debt Indicator: 71/100
```

Document the formula.

---

# 47. Executive Dashboard

The dashboard should answer:

> What is the current state of the org?

Main sections:

1. Overall Health
2. Coverage
3. Critical / High Findings
4. Domain Scores
5. Top Risks
6. Asset Inventory
7. Architecture Highlights
8. Quick Wins
9. Scan History

Example:

```text
┌─────────────────────────────────────────────────────────┐
│ SFMC ORG HEALTH                                         │
│                                                         │
│                     82                                  │
│                  HEALTH SCORE                           │
│                                                         │
│ Coverage 94%      3 Critical     18 High                │
└─────────────────────────────────────────────────────────┘
```

---

# 48. Organization Explorer

Visualize:

```text
Enterprise
   │
   ├── Corporate BU
   ├── US BU
   ├── UK BU
   ├── APAC BU
   └── Other BUs
```

Each BU displays:

- Health
- Findings
- Asset count
- Users
- Packages
- Integrations

---

# 49. Data Architecture UI

Tabs:

```text
Architecture
Data Extensions
Contact Builder
Relationships
Findings
```

The architecture canvas should support:

- Zoom
- Pan
- Search
- Filters
- Node selection
- Relationship highlighting
- Finding indicators
- Dependency expansion

---

# 50. Asset Detail UI

All object types should use a consistent detail pattern.

```text
Overview
Configuration
Usage
Dependencies
Dependents
Findings
Evidence
History
```

Object-specific tabs may be added.

---

# 51. Dependency Explorer UI

Provide:

- Search
- Node graph
- Dependency direction
- Direct vs indirect
- Blast radius
- Active/inactive indicator
- Finding overlay

Example:

```text
Customer_Master_DE
      │
      ├── Automation
      ├── SQL
      ├── Journey
      └── CloudPage
```

---

# 52. Findings Center

Filters:

- Severity
- Domain
- BU
- Object type
- Rule
- Status
- Confidence
- Remediation effort

Actions:

- Open
- Acknowledge
- Add note
- Assign owner
- Add to report
- Export

---

# 53. Finding Detail UI

Required sections:

1. Finding title
2. Severity
3. Object
4. Business Unit
5. Why it matters
6. Evidence
7. Affected assets
8. Dependency context
9. Recommendation
10. Remediation effort
11. Rule
12. Coverage limitations

---

# 54. Scan Setup UI

```text
Connected Organization
Business Units
Scan Mode
Modules
Rules
Estimated Coverage
Start Assessment
```

Allow custom module selection.

---

# 55. Scan Progress UI

Show:

```text
Overall progress
Current module
Assets scanned
Relationships found
Rules executed
Findings found
Errors
Warnings
```

Example:

```text
68%

✓ Organization
✓ Data
✓ Automation
✓ Journey
◉ Content
○ Security

Assets: 2,846
Relationships: 4,291
Rules: 7,821
Findings: 109
```

---

# 56. Scan History

Store every scan as a snapshot.

Display:

```text
Scan #001
30 Sep 2026
Health 78
Coverage 91%

Scan #002
15 Oct 2026
Health 82
Coverage 94%
```

---

# 57. Scan Comparison

Compare:

- Health
- Coverage
- Findings
- Assets
- BUs
- Automations
- Journeys
- DEs
- Security
- Architecture

Example:

```text
New Findings              +12
Resolved Findings          -8
New Assets                +23
Removed Assets            -11
Critical Findings          -1
Health                     +4
```

---

# 58. Report Architecture

Generate at least:

## Executive Assessment

For executives and client stakeholders.

## Technical Assessment

For architects and developers.

## Security Assessment

For security stakeholders.

## Data Architecture Assessment

For data teams.

## Complete Assessment

All sections.

---

# 59. Executive Report Structure

```text
Cover
Executive Summary
Assessment Scope
Audit Coverage
Overall Health
Domain Health
Top Risks
Key Architecture Observations
Major Findings
Quick Wins
30/60/90 Roadmap
Conclusion
Appendix
```

---

# 60. Technical Report Structure

```text
Organization
Business Units
Security
Data Architecture
Contact Model
Subscriber Model
Automation
SQL
Journeys
Content
CloudPages
Integrations
Governance
Dependencies
Technical Debt
Findings
Recommendations
Coverage
Limitations
Appendix
```

---

# 61. Finding Report Format

```text
Finding ID: DATA-RET-001

Severity: HIGH

Domain:
Data

Business Unit:
Production

Object:
Customer_Master_DE

Issue:
Retention configuration is not present.

Evidence:
Retention is disabled.

Potential Impact:
Data governance and storage management concern.

Recommendation:
Review business and organizational retention requirements
and configure an appropriate policy.

Remediation Effort:
MEDIUM

Confidence:
HIGH
```

---

# 62. Recommendations Framework

Recommendations should be grouped into:

## Quick Wins

0–30 days

## Medium-Term

31–60 days

## Strategic

61–90+ days

Examples:

- Fix naming violations.
- Review stale assets.
- Review failed automations.
- Review risky integrations.
- Standardize BU governance.
- Improve data retention governance.
- Reduce unnecessary dependencies.
- Rationalize duplicate assets.

---

# 63. AI Layer

AI is optional and secondary.

Deterministic scanner:

```text
Metadata
   ↓
Rules
   ↓
Evidence
   ↓
Findings
```

AI:

```text
Findings
   ↓
AI
   ↓
Executive narrative
   ↓
Architecture explanation
   ↓
Recommendations
```

AI must not be the source of truth for configuration detection.

AI should not invent facts.

AI-generated statements must be grounded in stored scan evidence.

---

# 64. Ask Your SFMC Org

Future feature.

Users can ask:

- Which journeys depend on Customer_Master_DE?
- Which automations feed active journeys?
- Which BUs have the most findings?
- Which assets are potentially unused?
- What are the top architecture risks?
- Show the blast radius of this DE.
- Which automations have recent failures?
- Which findings are related?

Answers must be generated from the organization's stored assessment data.

---

# 65. Database Architecture

Recommended database: PostgreSQL.

Core entities:

```text
Organization
BusinessUnit
User
Role
InstalledPackage
Integration
Scan
ScanModule
Asset
AssetVersion
AssetRelationship
DataExtension
DataExtensionField
Automation
AutomationActivity
Journey
JourneyVersion
JourneyActivity
CloudPage
ContentAsset
Email
Rule
Finding
Evidence
Recommendation
Risk
ScanComparison
AuditLog
```

---

# 66. Conceptual ERD

```text
Organization
    │
    ├── BusinessUnit
    │      │
    │      ├── Asset
    │      ├── User
    │      └── InstalledPackage
    │
    ├── Scan
    │      │
    │      ├── ScanModule
    │      └── Finding
    │
    └── Integration

Asset
    │
    ├── AssetRelationship
    │
    ├── Finding
    │
    └── AssetVersion

Rule
    │
    └── Finding
             │
             ├── Evidence
             └── Recommendation
```

---

# 67. Asset Model

Use a common asset abstraction.

```json
{
  "id": "...",
  "type": "DataExtension",
  "name": "...",
  "businessUnitId": "...",
  "folderId": "...",
  "status": "ACTIVE",
  "createdAt": "...",
  "modifiedAt": "...",
  "metadata": {},
  "dependencies": [],
  "dependents": []
}
```

Specialized tables may hold object-specific properties.

---

# 68. Scanner Framework

Use a modular interface.

```typescript
interface Scanner {
  name: string;
  category: ScanCategory;

  discover(context: ScanContext): Promise<Asset[]>;
  normalize(asset: unknown): Promise<Asset>;
  analyze(asset: Asset, context: ScanContext): Promise<Finding[]>;
}
```

Example scanners:

```text
OrganizationScanner
BusinessUnitScanner
UserScanner
PackageScanner
DataExtensionScanner
ContactModelScanner
SubscriberScanner
AutomationScanner
SQLScanner
JourneyScanner
ContentScanner
EmailScanner
CloudPageScanner
IntegrationScanner
GovernanceScanner
SecurityScanner
```

---

# 69. Dependency Engine

Dependency extraction should be modular.

Potential sources:

- SQL text
- Automation activity configuration
- Journey entry configuration
- Content references
- CloudPage code
- Asset metadata
- Folder relationships
- API configuration

Do not assume a relationship exists without evidence.

Each relationship should include:

```json
{
  "sourceAssetId": "...",
  "targetAssetId": "...",
  "relationshipType": "USES",
  "confidence": "HIGH",
  "evidence": "..."
}
```

---

# 70. API Capability Matrix

Before implementing a scanner, document:

| Module | REST | SOAP | Other | Required Scope | BU Scope | Limitations |
|---|---|---|---|---|---|---|
| Organization | Validate | Validate | - | TBD | Enterprise | Validate current docs |
| Business Units | Validate | Validate | - | TBD | Enterprise | Validate |
| Data Extensions | Validate | Validate | - | TBD | BU | Validate |
| Automations | Validate | Validate | - | TBD | BU | Validate |
| Journeys | Validate | Validate | - | TBD | BU | Validate |
| Content | Validate | Validate | - | TBD | BU | Validate |
| CloudPages | Validate | Validate | - | TBD | BU | Validate |
| Users | Validate | Validate | - | TBD | Enterprise/BU | Validate |
| Packages | Validate | Validate | - | TBD | Enterprise | Validate |
| Tracking | Validate | Validate | - | TBD | BU | Validate |

The development team must replace "Validate/TBD" with verified current Salesforce API documentation before implementation.

---

# 71. Technology Stack

## Frontend

Recommended:

- React
- TypeScript
- Vite
- Tailwind CSS
- Component library
- React Query / TanStack Query
- React Flow or equivalent
- Charting library

## Backend

Recommended:

- Node.js
- TypeScript
- REST API
- Background job framework
- SFMC REST client
- SFMC SOAP client

## Database

- PostgreSQL
- Prisma or equivalent ORM

## Reporting

- PDF generation
- Excel generation
- HTML report generation

## Future

- Redis/job queue
- Object storage
- AI service
- Multi-tenant administration

---

# 72. Repository Architecture

Use a monorepo.

```text
sfmc-health-assessment/
│
├── apps/
│   ├── web/
│   ├── api/
│   └── extension/
│
├── packages/
│   ├── shared-types/
│   ├── sfmc-client/
│   ├── scanner-core/
│   ├── scanners/
│   ├── rules/
│   ├── dependency-engine/
│   ├── scoring/
│   ├── reporting/
│   └── ui/
│
├── docs/
│   ├── solution-design.md
│   ├── api-matrix.md
│   ├── rule-catalog.md
│   └── ux-spec.md
│
└── infrastructure/
```

---

# 73. Security Architecture

## Credential security

- Server-side only
- Encryption at rest
- Encryption in transit
- No secrets in logs
- No secrets in reports
- No secrets in analytics

## Tenant isolation

Design the database so all customer data is scoped to:

```text
Tenant
   ↓
Organization
   ↓
Business Unit
   ↓
Scan
   ↓
Assets / Findings
```

## Audit logging

Track:

- Login
- Connection creation
- Scan start
- Scan completion
- Report generation
- Credential changes
- Rule changes
- Admin actions

---

# 74. Privacy Principles

Default to metadata-only.

Avoid storing:

- Customer email addresses
- Customer names
- Raw subscriber records
- Message content unless required for static analysis
- Sensitive values

When code must be analyzed:

- Store only the required source representation.
- Mask secrets.
- Do not expose secrets in reports.

---

# 75. Observability

The product itself should monitor:

- Scan failures
- API errors
- API latency
- Rate limiting
- Scanner failures
- Queue depth
- Database performance
- Report generation failures

Each scan should have an internal execution log.

---

# 76. Performance Requirements

The system should be designed for:

- Hundreds/thousands of assets
- Multiple BUs
- Large metadata payloads
- Pagination
- API throttling
- Retry
- Parallel module execution where safe
- Incremental processing

Do not perform unnecessary repeated API calls.

Use caching within a scan where possible.

---

# 77. API Rate Limit Strategy

Implement:

- Pagination
- Retry with backoff
- Rate-limit awareness
- Request batching where supported
- Caching
- Scan checkpointing

A single failed request should not fail the complete scan.

---

# 78. Data Retention for Scan History

Store:

- Scan summary
- Asset inventory snapshot
- Findings
- Evidence
- Relationships
- Scores

Allow configurable retention of historical scans.

---

# 79. Rule Versioning

Rules may change over time.

Therefore store:

```text
Rule ID
Rule Version
Created
Updated
Severity
Logic Version
```

When comparing scans, preserve the rule version used for each scan.

---

# 80. Rule Confidence

Not every detection is equally certain.

Use:

```text
HIGH
MEDIUM
LOW
```

Example:

- Direct API metadata → HIGH
- Explicit dependency in SQL → HIGH
- Similar-name duplicate detection → MEDIUM
- Pattern-based architectural observation → MEDIUM/LOW

---

# 81. Evidence Model

Evidence should be structured.

```json
{
  "type": "CONFIGURATION",
  "source": "SFMC_API",
  "field": "retentionEnabled",
  "observedValue": false,
  "timestamp": "..."
}
```

Other evidence types:

```text
API_METADATA
CONFIGURATION
RELATIONSHIP
STATIC_ANALYSIS
EXECUTION_HISTORY
PATTERN
USER_CONFIGURATION
```

---

# 82. Finding Status

Use:

```text
OPEN
ACKNOWLEDGED
IN_REVIEW
RESOLVED
FALSE_POSITIVE
ACCEPTED_RISK
```

Allow notes and ownership in future versions.

---

# 83. Report Quality Requirements

Reports must be:

- Professional
- Client-ready
- Consistent
- Evidence-based
- Traceable
- Versioned
- Exportable

The executive report should not overwhelm executives with technical metadata.

The technical appendix should contain the detailed evidence.

---

# 84. Recommended Dashboard Navigation

```text
HOME

ASSESS
  New Assessment
  Scan History
  Compare

EXPLORE
  Organization
  Data
  Automations
  Journeys
  Content
  CloudPages
  Integrations

ANALYZE
  Findings
  Dependencies
  Architecture
  Security
  Governance

REPORT
  Executive Report
  Technical Report
  Report Builder

ADMIN
  Connections
  Rules
  Settings
```

---

# 85. Wireframe — Executive Dashboard

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ ACME CORP / PRODUCTION                                  Scan #004       │
│ Last scan: 30 Sep 2026                              [Rescan] [Report]    │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────────┐   ┌──────────────────────────────────────┐ │
│  │                        │   │ FINDINGS                              │ │
│  │          82            │   │ 🔴 3 Critical   🔴 18 High            │ │
│  │      ORG HEALTH        │   │ 🟠 46 Medium    🟡 72 Low             │ │
│  │                        │   │                                      │ │
│  │ Coverage 94%           │   │ [View Findings]                       │ │
│  └────────────────────────┘   └──────────────────────────────────────┘ │
│                                                                          │
│ HEALTH BY DOMAIN                                                         │
│                                                                          │
│ Security      ████████████████████ 91                                    │
│ Integration   ███████████████████  88                                    │
│ Automation    █████████████████    84                                    │
│ Architecture  ████████████████     82                                    │
│ Journey       ███████████████      78                                    │
│ Data          ██████████████       76                                    │
│ Governance    █████████████         72                                    │
│ CloudPages    ████████████          68                                    │
│                                                                          │
│ TOP RISKS                         QUICK WINS                             │
│ 01 Automation dependency           12 retention reviews                 │
│ 02 Data retention                  24 stale assets                      │
│ 03 CloudPage security              14 automation reviews                │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# 86. Wireframe — Asset Explorer

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ ASSET EXPLORER                                          🔍 Search       │
├───────────────┬──────────────────────────────────────────────────────────┤
│ Asset Types   │ Customer_Master_DE                                      │
│               │ Data Extension · Production BU                          │
│ Data Extension│                                                          │
│ Automation    │ Health 72       Findings 4                              │
│ Journey       │                                                          │
│ CloudPage     │ [Overview] [Fields] [Usage] [Dependencies] [Findings]  │
│ Content       │                                                          │
│               │ Sendable       YES                                      │
│               │ Retention      NOT CONFIGURED                           │
│               │ Fields         87                                       │
│               │                                                          │
│               │ Used by:                                                 │
│               │ 7 Automations · 3 Journeys · 14 SQL Queries             │
└───────────────┴──────────────────────────────────────────────────────────┘
```

---

# 87. Wireframe — Finding

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ HIGH · DATA-RET-001                                                     │
│ Missing Retention Configuration                                          │
├──────────────────────────────────────────────────────────────────────────┤
│ OBJECT                                                                   │
│ Customer_Master_DE                                                       │
│ Production BU                                                            │
│                                                                          │
│ IMPACT: HIGH       LIKELIHOOD: MEDIUM       CONFIDENCE: HIGH             │
│                                                                          │
│ WHY THIS MATTERS                                                         │
│ Retention is not explicitly configured.                                  │
│                                                                          │
│ EVIDENCE                                                                 │
│ retentionEnabled = false                                                 │
│ source = SFMC API                                                        │
│                                                                          │
│ AFFECTED DEPENDENCIES                                                    │
│ 7 Automations · 3 Journeys · 12 downstream assets                       │
│                                                                          │
│ RECOMMENDATION                                                           │
│ Review organizational retention requirements and configure an            │
│ appropriate policy.                                                      │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# 88. Wireframe — Dependency Explorer

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ DEPENDENCY EXPLORER                                                      │
│ [Customer_Master_DE____________________] [Analyze]                       │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                         CUSTOMER_MASTER_DE                               │
│                                  │                                       │
│                  ┌───────────────┼──────────────┐                        │
│                  ▼               ▼              ▼                        │
│                SQL          Automation       CloudPage                   │
│                 │               │                                        │
│                 │               ▼                                        │
│                 │          Journey Entry                                 │
│                 │               │                                        │
│                 │               ▼                                        │
│                 │            Journey                                     │
│                 │               │                                        │
│                 └───────────────┼──────────────┐                         │
│                                 ▼              ▼                         │
│                               Email          Email                       │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│ BLAST RADIUS: 31 assets                                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# 89. Report Builder

Allow users to select:

- Report type
- BUs
- Domains
- Severity
- Findings
- Recommendations
- Appendix
- Asset inventory
- Dependency diagrams

Output:

- PDF
- Excel
- HTML

---

# 90. Executive Summary Generation

The platform should generate an executive narrative from verified findings.

Example structure:

```text
Overall Assessment

The assessment covered 94% of the accessible SFMC environment.
The organization contains 8 Business Units, 642 Data Extensions,
218 Automations and 67 Journeys.

The primary observations relate to data governance, automation
reliability, asset lifecycle and CloudPage configuration.

Three critical findings and eighteen high-severity findings
require review.
```

Do not generate unsupported statements.

---

# 91. 30/60/90 Day Roadmap

## 0–30 days

- Critical security findings
- Critical operational failures
- High-risk dependency issues
- High-priority data governance issues

## 31–60 days

- Automation cleanup
- Journey rationalization
- Data model improvements
- Content cleanup
- Governance standardization

## 61–90+ days

- Architecture improvements
- Technical debt reduction
- Integration redesign
- Long-term governance

The roadmap should be generated from actual findings and configured priorities.

---

# 92. MVP Definition

MVP should include:

## Connection

- Installed Package
- OAuth
- Access assessment

## Discovery

- Enterprise
- BUs

## Inventory

- Data Extensions
- Automations
- Journeys
- Content
- CloudPages
- Installed Packages
- Users where accessible

## Analysis

- Basic rules
- Naming
- Retention
- Usage
- Dependencies
- Unused/orphan indicators
- Automation checks
- Journey checks

## UI

- Dashboard
- BU explorer
- Asset explorer
- Findings
- Dependency graph
- Scan history

## Reporting

- Executive PDF
- Technical PDF
- CSV/Excel export

---

# 93. Phase 2

Add:

- Advanced SQL analyzer
- AMPscript analyzer
- SSJS analyzer
- Advanced dependency discovery
- Duplicate detection
- Architecture scoring
- Advanced security
- Scan comparison
- Custom rules
- Client-specific rules

---

# 94. Phase 3

Add:

- Multi-tenant SaaS
- Multiple client organizations
- Scheduled scans
- Notifications
- AI assistant
- Advanced trend analysis
- Architecture recommendations
- Team collaboration
- Finding assignment

---

# 95. Future Chrome Extension

The extension should provide:

```text
Current BU
Health
Critical Findings
Quick Scan
Open Assessment
```

It should not duplicate the backend scanner.

---

# 96. Development Roadmap

## Sprint 0 — Design

Deliver:

- Solution design
- API matrix
- Rule catalog
- Database ERD
- UX specification

## Sprint 1 — Foundation

- Monorepo
- React
- Node API
- PostgreSQL
- Authentication
- Basic organization model

## Sprint 2 — SFMC Connection

- Installed Package
- OAuth
- Access assessment
- BU discovery

## Sprint 3 — Inventory

- DE
- Automation
- Journey
- Content
- CloudPage
- Users
- Packages

## Sprint 4 — Rule Engine

- Rule schema
- Rule execution
- Finding model
- Severity

## Sprint 5 — Dependency Engine

- Relationship extraction
- Graph
- Blast radius

## Sprint 6 — Dashboard

- Executive dashboard
- Asset explorer
- Findings

## Sprint 7 — Reports

- PDF
- Excel
- Executive report
- Technical report

## Sprint 8 — Advanced Analysis

- SQL
- Code
- Duplicate
- Orphan
- Architecture

---

# 97. Quality Requirements

Every scanner must have:

- Unit tests
- Mock API responses
- Error tests
- Pagination tests
- Permission failure tests
- Partial access tests
- Large dataset tests

Every rule should have:

- Positive test
- Negative test
- Edge case
- Evidence validation

---

# 98. Acceptance Criteria

The first production-ready release should be able to:

1. Connect securely to an SFMC org.
2. Determine accessible APIs/scopes.
3. Discover BUs.
4. Scan supported assets.
5. Store normalized metadata.
6. Build relationships.
7. Execute rules.
8. Generate evidence-based findings.
9. Calculate documented health scores.
10. Show audit coverage.
11. Show limitations.
12. Provide dependency visualization.
13. Produce executive and technical reports.
14. Store scan history.
15. Compare scans.
16. Remain completely read-only.

---

# 99. Important Salesforce API Validation Requirement

Before implementation, the development team must validate every planned API operation against current official Salesforce Marketing Cloud documentation.

Do not assume:

- REST can replace SOAP.
- SOAP can replace REST.
- A UI-visible object is fully exposed by API.
- A metadata object is accessible with every package scope.
- Enterprise-level credentials automatically provide every BU-level capability.
- Runtime data is available for every object.
- All Journey configuration is exposed identically across APIs.

The API Capability Matrix must be completed before implementing the corresponding scanner.

---

# 100. Product Success Metrics

Measure:

- Assessment completion rate
- Average scan duration
- API failure rate
- Scan coverage
- Number of assets discovered
- Number of relationships discovered
- Number of findings
- Findings by severity
- Findings resolved between scans
- Report generation success
- Scan comparison changes

---

# 101. Final Product Experience

The intended experience is:

```text
CONNECT CLIENT ORG
       ↓
ACCESS ASSESSMENT
       ↓
RUN FULL ASSESSMENT
       ↓
94% AUDIT COVERAGE
       ↓
ORG HEALTH 82
       ↓
3 Critical
18 High
46 Medium
72 Low
       ↓
UNDERSTAND FINDINGS
       ↓
VIEW EVIDENCE
       ↓
VIEW DEPENDENCIES
       ↓
UNDERSTAND BUSINESS / TECHNICAL IMPACT
       ↓
REVIEW RECOMMENDATIONS
       ↓
BUILD 30/60/90 ROADMAP
       ↓
GENERATE CLIENT REPORT
       ↓
COMPARE FUTURE SCANS
```

---

# 102. Final Architecture Principle

The product should be built around five core engines:

```text
┌───────────────────────────────────────────────┐
│                 SFMC HEALTHSCAN               │
├───────────────────────────────────────────────┤
│                                               │
│  1. COLLECTION ENGINE                         │
│     REST / SOAP / OAuth / Metadata            │
│                                               │
│  2. NORMALIZATION ENGINE                      │
│     Common SFMC Asset Model                   │
│                                               │
│  3. DEPENDENCY ENGINE                         │
│     Relationships / Blast Radius              │
│                                               │
│  4. ASSESSMENT ENGINE                         │
│     Rules / Risk / Scoring / Evidence         │
│                                               │
│  5. REPORTING ENGINE                          │
│     Dashboard / PDF / Excel / HTML            │
│                                               │
└───────────────────────────────────────────────┘
```

The React application is the experience layer over these engines.

---

# 103. Instructions for Claude Code

This document is the source of truth for the product.

Before writing application code:

1. Review this entire document.
2. Identify ambiguous requirements.
3. Produce a technical implementation plan.
4. Validate current Salesforce Marketing Cloud API capabilities using official Salesforce documentation.
5. Complete the API Capability Matrix.
6. Design the PostgreSQL schema.
7. Design scanner interfaces.
8. Design the rule schema.
9. Design the dependency model.
10. Define the initial MVP rule catalog.
11. Confirm security architecture.
12. Confirm UX component hierarchy.
13. Confirm the monorepo structure.

Do not generate the entire application in one step.

Build incrementally.

## Required development order

```text
Solution Validation
        ↓
API Capability Validation
        ↓
Database Schema
        ↓
Authentication
        ↓
SFMC Client
        ↓
Organization / BU Scanner
        ↓
Data Extension Scanner
        ↓
Automation Scanner
        ↓
Journey Scanner
        ↓
Content / CloudPage Scanners
        ↓
Rule Engine
        ↓
Dependency Engine
        ↓
Findings
        ↓
Scoring
        ↓
Dashboard
        ↓
Reports
        ↓
Advanced Analysis
```

## Coding rules

- TypeScript strict mode.
- Strong typing.
- No secrets in frontend.
- No credentials in logs.
- Read-only SFMC integration.
- Modular scanners.
- Modular rules.
- Unit tests for scanners.
- Unit tests for rules.
- Mock SFMC APIs during tests.
- Pagination support.
- Retry/backoff.
- Graceful partial failures.
- Evidence-first findings.
- No invented API endpoints.
- No unsupported Salesforce claims.
- No destructive operations.
- No execution of customer AMPscript/SSJS.
- Keep AI optional and downstream of deterministic analysis.

---

# 104. Definition of Done

A scanner is complete only when:

- API capability is verified.
- Required permission is documented.
- Data collection works.
- Pagination works.
- Error handling works.
- Normalized asset model exists.
- Relationships are extracted where possible.
- Rules are implemented.
- Evidence is stored.
- Findings are generated.
- Tests exist.
- Coverage is reported.
- Limitations are documented.
- UI supports drill-down.
- Reports can include the results.

---

# 105. Final Product Statement

The product should ultimately provide a consultant with a single workflow:

> Connect an SFMC organization → assess accessible configuration → discover the complete supported estate → understand relationships → identify risks → explain the evidence → prioritize remediation → generate a professional client-ready assessment → repeat the scan later and measure change.

The system must remain transparent about what it can and cannot assess.

The objective is not to produce an impressive score.

The objective is to produce a **trustworthy, repeatable, evidence-based SFMC assessment** that an architect can defend in front of a client.


---

# 106. User Account, Authentication & Multi-Organization Architecture

The platform must support a secure SaaS-style user model.

A single application user must be able to:

- Register / sign in.
- Sign out.
- Connect one or more SFMC organizations.
- Assign a friendly name to each connection.
- Connect multiple Enterprise/MID environments.
- Select one or more Business Units within an organization.
- Run a scan for a single BU.
- Run a scan across multiple selected BUs.
- Run a complete Enterprise assessment where the user's access permits.
- View historical scans for organizations they are authorized to access.
- Compare previous scans.
- View retained findings and results.
- Generate reports from current or historical assessments.

The user must never see another user's organizations, credentials, scans, assets, findings, or reports unless explicit future collaboration/sharing functionality grants access.

---

# 107. User Account Lifecycle

```text
                         ┌──────────────────────┐
                         │       Sign Up        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │       Sign In        │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    User Dashboard    │
                         └──────────┬───────────┘
                                    │
                       ┌────────────┼────────────┐
                       ▼            ▼            ▼
                  Add SFMC     View Scans    Reports
                  Connection
                       │
                       ▼
                 Access Test
                       │
                       ▼
                 BU Discovery
                       │
                       ▼
                  Run Scan
                       │
                       ▼
                Store Results
```

## Authentication requirements

The platform should support:

- Email/password or enterprise authentication depending on the final identity provider.
- Secure session management.
- MFA support through the selected identity provider.
- Password reset where applicable.
- Session expiration.
- Sign out from current session.
- Sign out from all sessions.
- Login activity/audit logging.

The application should prefer a managed identity provider rather than implementing password security from scratch.

---

# 108. User Logout

When a user logs out:

- Invalidate the application session.
- Remove active session tokens from the browser.
- Clear sensitive frontend state.
- Do not delete SFMC organization connections.
- Do not delete scan history.
- Do not delete findings.
- Do not delete reports.
- Require authentication again to access protected resources.

SFMC credentials must never be dependent on browser session state.

---

# 109. Multi-SFMC Organization Model

One user can connect multiple SFMC organizations.

Example:

```text
User: Consultant A

My Organizations
│
├── Client A - Production
│   ├── Enterprise
│   ├── US BU
│   ├── UK BU
│   └── APAC BU
│
├── Client B - Production
│   ├── Enterprise
│   └── India BU
│
├── Client C - Sandbox
│   ├── Enterprise
│   └── Development BU
│
└── Internal Demo Org
    └── Demo BU
```

The UI should make the active organization explicit at all times.

Example:

```text
┌──────────────────────────────────────────────┐
│ Organization                                 │
│                                              │
│ Client A - Production                    ▼  │
└──────────────────────────────────────────────┘
```

Never allow the user to accidentally run a scan against the wrong organization.

Before starting a scan, show:

```text
Organization:
Client A - Production

Enterprise:
ABC Corporation

Business Units:
✓ US BU
✓ UK BU
○ APAC BU

Scan:
Full Assessment
```

---

# 110. Organization Connection Model

A user connection should be modeled independently from the user session.

Conceptual model:

```text
User
 │
 ├── Organization Connection A
 │       │
 │       ├── SFMC Enterprise
 │       ├── Credentials
 │       └── Business Units
 │
 ├── Organization Connection B
 │       │
 │       ├── SFMC Enterprise
 │       ├── Credentials
 │       └── Business Units
 │
 └── Organization Connection C
         │
         ├── SFMC Enterprise
         ├── Credentials
         └── Business Units
```

A connection should have:

```text
Connection ID
User/Tenant ID
Organization Name
Environment
Enterprise MID
Authentication Base URI
API Base URI
Credential Reference
Connection Status
Last Connection Test
Created At
Updated At
```

Do not store raw Client Secret values in normal application tables.

Store only a secure reference to encrypted credential material.

---

# 111. Connection Management UI

Create a dedicated:

## My SFMC Organizations

screen.

```text
┌──────────────────────────────────────────────────────────────────────┐
│ MY SFMC ORGANIZATIONS                              [+ Add SFMC Org]  │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │ Client A - Production                                ● Connected │ │
│ │ Enterprise MID: 123456                                           │ │
│ │ Business Units: 8                                                │ │
│ │ Last Scan: Today · Health 82                                     │ │
│ │                                                                  │ │
│ │ [Open] [Run Scan] [Manage Connection]                           │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │ Client B - Production                                ● Connected │ │
│ │ Enterprise MID: 789012                                           │ │
│ │ Business Units: 4                                                │ │
│ │ Last Scan: 3 days ago · Health 76                                │ │
│ │                                                                  │ │
│ │ [Open] [Run Scan] [Manage Connection]                           │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │ Client C - Sandbox                                   ● Connected │ │
│ │ Enterprise MID: 456789                                           │ │
│ │ Business Units: 2                                                │ │
│ │ Last Scan: Never                                                  │ │
│ │                                                                  │ │
│ │ [Open] [Run First Scan]                                          │ │
│ └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

# 112. Business Unit Selection

The scan must support both single-BU and multi-BU assessments.

## Single BU

```text
Organization
   ↓
Select one BU
   ↓
Run Assessment
   ↓
Results scoped to that BU
```

## Multiple BUs

```text
Organization
   ↓
Select multiple BUs
   ↓
Run Assessment
   ↓
Analyze each BU
   ↓
Analyze cross-BU relationships
   ↓
Generate consolidated result
```

## Example UI

```text
┌──────────────────────────────────────────────────────────────┐
│ SELECT BUSINESS UNITS                                        │
│                                                              │
│ ☑ US Marketing                                               │
│ ☑ UK Marketing                                               │
│ ☐ APAC Marketing                                             │
│ ☐ Corporate                                                  │
│                                                              │
│ Selected: 2 of 4                                             │
│                                                              │
│ ○ Single BU Assessment                                       │
│ ● Multi-BU Assessment                                        │
│                                                              │
│ [ Continue ]                                                 │
└──────────────────────────────────────────────────────────────┘
```

---

# 113. Multi-BU Assessment

A multi-BU assessment must provide two layers of results.

## BU-Level Results

Each BU gets its own:

- Health score
- Coverage
- Findings
- Assets
- Dependencies
- Recommendations

## Enterprise / Cross-BU Results

The platform additionally analyzes:

- Configuration differences
- Naming differences
- Governance differences
- Shared assets
- Cross-BU dependencies
- Integration differences
- Security differences
- Architecture inconsistencies

Example:

```text
Enterprise Assessment
       │
       ├── US BU
       │    └── Health 84
       │
       ├── UK BU
       │    └── Health 79
       │
       ├── APAC BU
       │    └── Health 72
       │
       └── Corporate BU
            └── Health 91

Cross-BU Findings
       │
       ├── Naming inconsistency
       ├── Retention inconsistency
       ├── Package scope inconsistency
       └── Architecture inconsistency
```

---

# 114. Scan Scope Model

Every scan must explicitly store its scope.

```text
Scan
│
├── Organization
│
├── Scope Type
│    ├── SINGLE_BU
│    ├── MULTI_BU
│    └── ENTERPRISE
│
├── Selected BUs
│
├── Modules
│
└── Rules
```

Example:

```json
{
  "scanId": "SCAN-001",
  "organizationId": "ORG-001",
  "scopeType": "MULTI_BU",
  "businessUnits": [
    "BU-US",
    "BU-UK",
    "BU-APAC"
  ],
  "modules": [
    "DATA",
    "AUTOMATION",
    "JOURNEY",
    "SECURITY"
  ]
}
```

---

# 115. Scan History

Scan history is a core product capability, not an optional feature.

Every completed scan should create a persistent assessment snapshot.

Example:

```text
Client A - Production

Assessment History

Scan #001
30 Sep 2026
Scope: US BU
Health: 72
Coverage: 91%
Findings: 118

Scan #002
15 Oct 2026
Scope: US BU
Health: 78
Coverage: 94%
Findings: 101

Scan #003
30 Oct 2026
Scope: US + UK
Health: 81
Coverage: 95%
Findings: 137
```

---

# 116. Historical Result Storage

The platform must preserve historical assessment results.

For each scan retain:

- Scan metadata
- Scan scope
- Selected BUs
- Module coverage
- Asset inventory snapshot
- Asset relationships
- Findings
- Evidence
- Scores
- Recommendations
- Report metadata
- Rule versions
- API capability results
- Scan errors/warnings

Historical results must remain immutable.

If a new scan is executed, create a new snapshot rather than overwriting the previous scan.

---

# 117. Historical Result Model

```text
Organization
     │
     ├── Scan 001
     │    ├── Assets Snapshot
     │    ├── Relationships
     │    ├── Findings
     │    ├── Scores
     │    └── Report
     │
     ├── Scan 002
     │    ├── Assets Snapshot
     │    ├── Relationships
     │    ├── Findings
     │    ├── Scores
     │    └── Report
     │
     └── Scan 003
          ├── Assets Snapshot
          ├── Relationships
          ├── Findings
          ├── Scores
          └── Report
```

---

# 118. Scan Comparison

Users should be able to select any two compatible scans.

Example:

```text
Compare

Scan #001
30 Sep 2026
US BU

VS

Scan #002
30 Oct 2026
US BU
```

Display:

```text
Health
72 → 81

Coverage
91% → 95%

Critical
4 → 2

High
21 → 14

Medium
48 → 43

Resolved Findings
19

New Findings
7
```

Also compare:

- New assets
- Removed assets
- Changed configuration
- New dependencies
- Removed dependencies
- New findings
- Resolved findings
- Severity changes
- Health score changes

---

# 119. Cross-Organization Isolation

A user's multiple SFMC organizations must remain logically isolated.

Example:

```text
User A
│
├── Client A
│   └── Scans A
│
├── Client B
│   └── Scans B
│
└── Client C
    └── Scans C
```

The application must enforce organization-level authorization on every request.

Never trust an organization ID supplied by the browser.

The backend must derive and validate access from the authenticated user's tenant/connection permissions.

---

# 120. Multi-Tenant SaaS Architecture

The platform should be designed for future SaaS use.

Recommended logical model:

```text
Tenant
 │
 ├── Users
 │
 ├── SFMC Organizations
 │      │
 │      ├── Business Units
 │      ├── Connections
 │      └── Scans
 │
 ├── Rules
 │
 └── Reports
```

A tenant may represent:

- An individual consultant.
- A consulting team.
- A Salesforce partner.
- An enterprise customer.

---

# 121. Roles & Permissions

Initial roles:

## Owner

- Manage organization connections
- Run scans
- View all results
- Generate reports
- Manage users

## Admin

- Manage connections
- Run scans
- View results
- Manage rules where enabled

## Analyst / Consultant

- Run scans
- View results
- Analyze findings
- Generate reports

## Viewer

- View dashboards
- View findings
- View reports
- Cannot manage credentials

Future roles can be added.

---

# 122. User-Level Data Access

Every protected API request should validate:

```text
Authenticated User
       ↓
Tenant
       ↓
Organization Connection
       ↓
Scan
       ↓
Requested Resource
```

Example:

```text
GET /api/scans/SCAN-001
```

The backend must verify:

1. User is authenticated.
2. User belongs to the appropriate tenant.
3. Scan belongs to an organization connection accessible to that tenant.
4. User role permits scan access.
5. Resource is not outside the user's scope.

Never rely only on frontend route protection.

---

# 123. Secure Organization Connection

Connection records should have statuses:

```text
CONNECTED
AUTHENTICATION_REQUIRED
ACCESS_CHANGED
ERROR
DISABLED
```

Example:

```text
Client A - Production
● Connected

Last verified:
30 Sep 2026 14:42

API Coverage:
94%

[ Test Connection ]
[ Manage ]
```

If credentials stop working:

```text
Client A - Production
⚠ Authentication Required

Last successful connection:
29 Sep 2026

[ Reconnect ]
```

Historical scans must remain accessible even if the live connection is no longer available.

---

# 124. Credential Separation from Scan Results

Scan results must not depend on the live credential being available.

Example:

```text
SFMC Connection
       │
       ▼
Run Scan
       │
       ▼
Snapshot Results
       │
       ▼
Persist
       │
       ├── Findings
       ├── Scores
       ├── Evidence
       ├── Relationships
       └── Report
```

If the SFMC connection is later disconnected:

```text
Connection: DISCONNECTED

Historical Results:
✓ Available

Previous Reports:
✓ Available

Previous Findings:
✓ Available

New Scan:
✗ Requires reconnection
```

---

# 125. Organization Deletion / Disconnect

Provide separate actions:

## Disconnect

Stops future live access but preserves historical assessment data.

## Delete Connection

Removes stored credentials and connection metadata.

## Delete Organization Data

A separate destructive action requiring explicit confirmation and appropriate authorization.

The product must not automatically delete historical reports when credentials are disconnected.

---

# 126. Secure Storage Architecture

Use:

```text
Browser
   │
   │ HTTPS
   ▼
API Gateway / Backend
   │
   ├── Authentication Provider
   │
   ├── Authorization Layer
   │
   ├── Encrypted Credential Store
   │
   └── PostgreSQL
```

Credential secrets should be encrypted using a managed key-management approach where available.

Do not expose encryption keys to the frontend.

---

# 127. Audit Trail

Track security-sensitive actions:

```text
USER_LOGIN
USER_LOGOUT
CONNECTION_CREATED
CONNECTION_UPDATED
CONNECTION_TESTED
CONNECTION_DISCONNECTED
SCAN_STARTED
SCAN_COMPLETED
SCAN_FAILED
REPORT_GENERATED
REPORT_DOWNLOADED
RULE_CHANGED
USER_INVITED
USER_REMOVED
```

Audit records should include:

- Actor
- Tenant
- Organization
- Action
- Timestamp
- Result
- Request context where appropriate

Never log credentials or access tokens.

---

# 128. User Dashboard

The user's home dashboard should summarize all accessible SFMC organizations.

```text
┌────────────────────────────────────────────────────────────────────────┐
│ MY SFMC ASSESSMENTS                                  [+ Add SFMC Org]  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│ Connected Organizations: 4                                             │
│ Total Assessments: 18                                                  │
│ Last Assessment: Today                                                  │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Client A - Production                             HEALTH 82       │ │
│ │ 8 BUs · Last scan Today · 3 Critical · 18 High                    │ │
│ │ [Open] [Run Assessment]                                            │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Client B - Production                             HEALTH 76       │ │
│ │ 4 BUs · Last scan 2 days ago · 5 Critical · 21 High               │ │
│ │ [Open] [Run Assessment]                                            │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│ RECENT ASSESSMENTS                                                     │
│                                                                        │
│ Client A · US BU       Today        Health 82     [View]               │
│ Client B · Enterprise  Yesterday    Health 76     [View]               │
│ Client A · UK BU       3 days ago   Health 79     [View]               │
└────────────────────────────────────────────────────────────────────────┘
```

---

# 129. User Experience — Switching Organizations

The active organization must always be visible.

Example top bar:

```text
MCNexus Scan

[ Client A - Production ▼ ]     [ US BU ▼ ]     🔔    User ▼
```

Changing the organization should reset the current context.

Show a confirmation when switching from one organization to another if a scan is active.

---

# 130. User Experience — Scan Context

Every result page should show:

```text
Organization:
Client A - Production

Assessment Scope:
US + UK BU

Scan:
#004

Assessment Date:
30 Sep 2026

Coverage:
94%
```

This prevents users from confusing results from different clients or BUs.

---

# 131. Multi-Organization Reporting

Reports must include:

- Organization name
- Environment
- Enterprise MID where appropriate
- Assessment scope
- Selected BUs
- Scan ID
- Assessment date
- Coverage
- Rule version
- Limitations

A report must never accidentally combine data from separate organizations.

---

# 132. Multi-BU Reporting

For multi-BU reports include:

```text
Enterprise Summary

BU Comparison

US BU       84
UK BU       79
APAC BU     72
Corporate   91

Cross-BU Findings

1. Naming inconsistency
2. Retention inconsistency
3. Package scope inconsistency
4. Governance inconsistency
```

---

# 133. Database Additions for Multi-Org / Multi-User

Add these core entities:

```text
User
Tenant
TenantUser
OrganizationConnection
Organization
BusinessUnit
CredentialReference
Scan
ScanBusinessUnit
ScanModule
Asset
Finding
Evidence
Report
AuditLog
```

Conceptual relationship:

```text
User
 │
 └── TenantUser
        │
        ▼
      Tenant
        │
        ├── OrganizationConnection
        │       │
        │       └── Organization
        │               │
        │               └── BusinessUnit
        │
        └── Users
```

---

# 134. Historical Data Security

Historical scans can contain sensitive metadata.

Therefore:

- Apply tenant isolation.
- Apply organization-level authorization.
- Encrypt data in transit.
- Encrypt sensitive data at rest.
- Avoid storing unnecessary customer records.
- Restrict report access.
- Log report generation/download actions.
- Define retention policies.
- Support deletion according to product policy.

---

# 135. Scan Result Ownership

Every scan must have:

```text
Tenant ID
Organization ID
Connection ID
Created By User ID
Scope
Selected BUs
Created At
Completed At
```

This allows the system to answer:

> Who ran this assessment?

> Which organization was assessed?

> Which BUs were included?

> When was it performed?

> Which rule version was used?

---

# 136. Revised Core Product Model

The final product should be understood as:

```text
USER
 │
 ▼
TENANT
 │
 ├───────────────────────────────────────┐
 ▼                                       ▼
SFMC ORGANIZATION A                  SFMC ORGANIZATION B
 │                                       │
 ├── BU 1                                ├── BU 1
 ├── BU 2                                ├── BU 2
 └── BU 3                                └── BU 3
 │                                       │
 ├── Scan History                        ├── Scan History
 ├── Findings                            ├── Findings
 ├── Reports                             ├── Reports
 └── Dependencies                        └── Dependencies
```

---

# 137. Updated Product Architecture

```text
                         USER
                          │
                          ▼
                 ┌──────────────────┐
                 │ Identity Provider│
                 │ Authentication   │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ React Web App    │
                 │                  │
                 │ Multi-Org        │
                 │ Multi-BU         │
                 │ Dashboard        │
                 │ Reports          │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Secure API       │
                 │                  │
                 │ Authorization    │
                 │ Tenant Isolation │
                 │ Scan Jobs        │
                 └────────┬─────────┘
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
       Credential     SFMC API     Assessment
         Vault          Client        Engine
             │            │            │
             └────────────┼────────────┘
                          ▼
                    PostgreSQL
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
          Scans        Findings      Reports
             │            │            │
             └────────────┼────────────┘
                          ▼
                    Historical Data
```

---

# 138. Updated MVP Requirements

The MVP must include multi-user and multi-organization foundations even if the initial product is used by a small number of consultants.

Minimum requirements:

### User

- Sign up/sign in
- Sign out
- Secure sessions
- User profile

### Organizations

- Add SFMC organization
- Multiple organizations per user
- Connection status
- Test connection
- Disconnect/reconnect

### Business Units

- Discover BUs
- Single-BU scan
- Multi-BU scan
- Enterprise-level scan where supported

### Scan history

- Persist scans
- Persist findings
- Persist scores
- Persist relationships
- Persist coverage
- Persist reports
- Compare scans

### Security

- Tenant isolation
- Organization authorization
- Encrypted credentials
- No secrets in browser
- Audit logging

---

# 139. Updated Acceptance Criteria

The initial production-ready release must additionally satisfy:

1. A user can securely create an account.
2. A user can sign in and sign out.
3. A user can connect multiple SFMC organizations.
4. Each connection is isolated.
5. A user can switch between organizations.
6. A user can discover available BUs.
7. A user can run a scan for one BU.
8. A user can run a scan for multiple BUs.
9. A user can run an Enterprise assessment where supported.
10. Each scan records its exact scope.
11. Scan results are stored as immutable historical snapshots.
12. Findings remain available after the live SFMC connection is disconnected.
13. A user can view historical scans.
14. A user can compare historical scans.
15. A user can generate reports from historical scans.
16. One organization cannot access another organization's data.
17. One user cannot access another user's private organization data.
18. Credentials are never exposed in frontend logs or reports.
19. Sign-out invalidates the active application session.
20. Reconnection is required when SFMC credentials are no longer valid.
21. Multi-BU assessments produce both BU-level and cross-BU analysis.
22. Reports clearly identify organization, scope, date, coverage, and scan ID.

---

# 140. Claude Code Instructions — Multi-User / Multi-Org

Before implementing the application, Claude must design and document:

1. Authentication architecture.
2. Tenant model.
3. User model.
4. Organization connection model.
5. Credential storage strategy.
6. Authorization middleware.
7. Organization-level isolation.
8. Scan ownership.
9. Historical snapshot model.
10. Multi-BU scan model.
11. Report ownership/access.
12. Audit logging.
13. Session management.
14. Connection lifecycle.
15. Disconnect/reconnect behavior.

Claude must not implement a single-user architecture and plan to retrofit multi-tenancy later.

The database and backend authorization model must support multiple users and multiple SFMC organizations from the beginning.

---

# 141. Final Multi-Organization Product Experience

The complete workflow should be:

```text
USER SIGN IN
     │
     ▼
MY SFMC ORGANIZATIONS
     │
     ├───────────────┬─────────────────┐
     ▼               ▼                 ▼
 Client A          Client B          Client C
     │               │                 │
     ▼               ▼                 ▼
 Select BU(s)     Select BU(s)      Select BU(s)
     │               │                 │
     ▼               ▼                 ▼
 Run Assessment   Run Assessment   Run Assessment
     │               │                 │
     ▼               ▼                 ▼
 Store Snapshot   Store Snapshot   Store Snapshot
     │               │                 │
     ▼               ▼                 ▼
 Findings          Findings          Findings
     │               │                 │
     ▼               ▼                 ▼
 Reports           Reports           Reports
     │
     ▼
Historical Scan Comparison
     │
     ▼
Trend / Improvement Analysis
```

The platform should therefore behave as a secure **multi-tenant SFMC assessment workspace**, where a consultant or organization can manage multiple SFMC environments and maintain a complete historical assessment record for each environment.

---

# 142. Updated Product Vision Statement

The final product is not simply a scanner.

It is a secure assessment workspace where:

> **One authenticated user can securely connect multiple Salesforce Marketing Cloud organizations, assess one or multiple Business Units within each organization, maintain complete historical scan results, compare assessments over time, understand architecture and dependencies, track findings, and generate professional client-ready reports — while keeping every organization's credentials, metadata, findings, and reports securely isolated.**


---

# Final Product Branding

**Product Name:** MCNexus  
**Product Category:** Salesforce Marketing Cloud Intelligence & Health Platform  
**Primary Purpose:** Comprehensive Salesforce Marketing Cloud organization assessment, architecture intelligence, governance, security, dependency analysis, technical-debt detection, and historical health tracking.

### MCNexus Product Suite

- **MCNexus Scan** — Full and targeted SFMC assessments
- **MCNexus Health** — Health scores, coverage, and domain-level assessment
- **MCNexus Atlas** — Architecture, data model, and dependency visualization
- **MCNexus Insights** — Findings, risks, evidence, and recommendations
- **MCNexus Guard** — Security and governance assessment
- **MCNexus Compare** — Historical scan comparison and trend analysis
- **MCNexus Reports** — Executive and technical assessment reports
- **MCNexus AI** — Natural-language analysis and explanation of assessment results

### Brand Positioning

> **MCNexus — Marketing Cloud Intelligence & Health Platform**

MCNexus is designed to become the central intelligence layer for understanding the health, architecture, dependencies, governance, security, and technical debt of Salesforce Marketing Cloud environments.
