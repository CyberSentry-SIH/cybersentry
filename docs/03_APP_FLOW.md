# CyberSentry V1 --- Application Flow

**Version:** 1.0\
**Purpose:** Exact end-to-end behavior for implementation and UI
navigation

------------------------------------------------------------------------

## 1. High-Level Flow

``` text
LOGIN
  ↓
DASHBOARD
  ↓
UPLOAD .EML
  ↓
EVIDENCE PRESERVATION
  ↓
EMAIL PARSING
  ↓
┌─────────────────────────────────────────────┐
│ Header/Auth │ Content/Intent │ URL/Domain  │
└─────────────────────────────────────────────┘
  ↓
INFRASTRUCTURE INTELLIGENCE
  ↓
PHISHDNA
  ↓
RISK FUSION
  ↓
EXPLAINABLE DECISION
  ↓
CAMPAIGN CORRELATION
  ↓
ATTACK CAMPAIGN MODEL
  ↓
CAMPAIGN EARLY WARNING
  ↓
ATTACK INTENT GRAPH
  ↓
RECOMMENDED ACTION
  ↓
CASE
  ↓
FORENSIC REPORT
```

------------------------------------------------------------------------

## 2. Login Flow

### User action

Enter email + password.

### System

1.  Validate credentials.
2.  Create authenticated session.
3.  Return user profile and role.
4.  Redirect to Dashboard.

### Failure

Show:

> Invalid email or password.

Do not reveal whether the email exists.

------------------------------------------------------------------------

## 3. Dashboard Flow

Dashboard displays:

-   Total analyzed emails
-   Critical/high findings
-   Open cases
-   Campaigns detected
-   Recent analyses
-   Analysis queue/status
-   Quick actions

Primary action:

> **Analyze Email**

Secondary:

> **Hunter Mode**

------------------------------------------------------------------------

## 4. EML Upload Flow

### Screen

Large drag-and-drop zone:

> Drop `.eml` file here

Also:

> Browse files

### Validation

Accept:

-   `.eml`

Reject:

-   `.msg`
-   `.pst`
-   executable files
-   unsupported formats

Show file:

-   name
-   size
-   SHA-256 after ingestion
-   status

### Progress states

``` text
Uploading
↓
Preserving Evidence
↓
Parsing Email
↓
Analyzing Signals
↓
Building PhishDNA
↓
Correlating Campaign
↓
Complete
```

------------------------------------------------------------------------

## 5. Evidence Preservation Flow

Before displaying a final threat decision:

1.  Read file bytes.
2.  Generate SHA-256.
3.  Create evidence record.
4.  Store original file.
5.  Create custody event.
6.  Link event to previous hash-chain state.
7.  Continue to parsing.

UI should show:

``` text
Evidence ID: EV-000123
SHA-256: 7c8...
Integrity: VERIFIED
Source: User Upload
Collected: 2026-09-06 22:10
```

------------------------------------------------------------------------

## 6. Email Parsing Flow

Extract:

``` text
Message
├── Metadata
├── Headers
├── Received hops
├── Authentication
├── Plain body
├── HTML body
├── URLs
└── Attachments
```

Parser errors must not destroy the evidence record.

If parsing is partially successful:

> Partial analysis available --- some fields could not be parsed.

------------------------------------------------------------------------

## 7. Analysis Result Flow

After analysis, open:

> **Threat Analysis**

Top area:

``` text
RISK SCORE: 87
CRITICAL
```

Then:

-   Why flagged
-   Authentication
-   Sender identity
-   Intent
-   URL/domain
-   Infrastructure
-   PhishDNA
-   Campaign
-   Recommended actions

------------------------------------------------------------------------

## 8. Header Analysis Flow

Display:

### Sender Identity

-   Display Name
-   From
-   Reply-To
-   Return-Path
-   Sender domain
-   Lookalike score

### Authentication

``` text
SPF       PASS
DKIM      PASS
DMARC     PASS
Alignment PASS
```

But if other evidence is suspicious, show:

> Authentication passed, but this does not establish message legitimacy.

### Received Chain

Timeline:

``` text
Hop 1
↓
Hop 2
↓
Hop 3
↓
Observed sending infrastructure
```

Each hop:

-   host
-   IP
-   timestamp
-   trust level
-   ASN/ISP if available
-   confidence

------------------------------------------------------------------------

## 9. Content / Intent Flow

Display:

``` text
Detected Intent

Credential Harvesting      HIGH
Urgency Manipulation       HIGH
Brand Impersonation        HIGH
Payment Request            LOW
```

Show supporting evidence as short excerpts or normalized phrases.

Avoid displaying raw HTML.

------------------------------------------------------------------------

## 10. URL Analysis Flow

For each URL:

``` text
Original URL
↓
Canonical URL
↓
Domain
↓
Lookalike Analysis
↓
Reputation
↓
Infrastructure
```

Example UI:

``` text
login-company-secure.xyz

Reputation: UNKNOWN
Lookalike: HIGH
Punycode: NO
Suspicious path: YES
Infrastructure: VPS/Hosting
```

Banner:

> **Unknown reputation does not mean safe.**

------------------------------------------------------------------------

## 11. Risk Explanation Flow

The explanation panel must answer:

> Why did CyberSentry assign this score?

Example:

``` text
87 / 100 — CRITICAL

+18  Lookalike sender domain
+16  Credential harvesting intent
+14  Reply-To mismatch
+12  Suspicious URL structure
+10  Related campaign infrastructure
+08  High PhishDNA similarity
+05  Unknown reputation + anomaly
-04  DKIM aligned
```

The exact configured weights may differ, but every displayed
contribution must correspond to an actual engine signal.

------------------------------------------------------------------------

## 12. PhishDNA View

Show six dimensions:

``` text
HEADER DNA
████████░░

CONTENT DNA
█████████░

URL DNA
██████████

INFRASTRUCTURE DNA
████████░░

BEHAVIORAL DNA
███████░░░

ATTACHMENT DNA
████░░░░░░
```

Do not make the visualization imply mathematical certainty.

Below it:

> Similarity to selected email: 87%

------------------------------------------------------------------------

## 13. What Changed? Flow

User selects two emails.

Screen split:

``` text
EMAIL A                    EMAIL B

Sender                     Sender
Domain                     Domain
URL                        URL
Intent                     Intent
Infrastructure             Infrastructure
PhishDNA                   PhishDNA
```

Middle/right comparison:

``` text
CHANGED
Sender domain
URL host

UNCHANGED / RELATED
Intent
ASN
HTML structure
Infrastructure pattern

PhishDNA similarity: 87%
Campaign likelihood: 92%
```

The goal is to explain how attackers changed surface indicators while
retaining campaign characteristics.

------------------------------------------------------------------------

## 14. Campaign Flow

Campaign page shows:

-   campaign ID
-   confidence
-   number of related emails
-   shared indicators
-   shared infrastructure
-   common intent
-   first seen / last seen
-   related cases

Example:

``` text
Campaign CS-2026-0042

Emails: 7
Domains: 4
URLs: 6
IPs: 3
ASNs: 2
Primary intent: Credential Harvesting
Confidence: 91%
```

------------------------------------------------------------------------

## 15. Attack Campaign Model, Evolution Timeline & Early Warning Flow

After campaign correlation, CyberSentry creates or updates an evidence-backed campaign model. The model represents only the observed/analyzed state of a suspected campaign; it is not a literal digital twin of the attacker and does not represent unseen activity.

Show:

- campaign state: Emerging / Active / Expanding / Monitoring
- confidence
- risk trend
- related email count
- observed domains/IPs/ASNs
- dominant intent
- first seen / last seen
- **Campaign Evolution Timeline**

Timeline events may include:

- related email observed
- new domain/IP/ASN observed
- new PhishDNA variant observed
- intent changed
- risk trend changed
- campaign state changed

Each event must link back to the analysis/evidence that caused it.

Example:

> Campaign expanding — 2 new related domains observed.

The early-warning layer may recommend increased monitoring or historical search **within evidence available to CyberSentry**. It must not claim certainty about future attacks or imply continuous mailbox monitoring.

## 16. Attack Intent Graph Flow

Graph center:

``` text
EMAIL
  ↓
SENDER
  ↓
IMPERSONATION
  ↓
INTENT
  ↓
URL
  ↓
DOMAIN
  ↓
IP
  ↓
ASN
  ↓
CAMPAIGN
```

Clicking a node opens an evidence drawer.

The drawer shows:

-   value
-   type
-   confidence
-   source
-   related evidence
-   related cases

------------------------------------------------------------------------

## 17. Hunter Mode Flow

Search bar supports:

``` text
sender:
domain:
url:
ip:
asn:
hash:
campaign:
intent:
risk:
```

Example:

> `domain:example.com`

Results:

-   emails
-   cases
-   campaigns
-   related infrastructure

Clicking a result opens the investigation.

------------------------------------------------------------------------

## 18. Case Flow

Create case from analysis.

Fields:

-   title
-   severity
-   owner
-   status
-   notes

Statuses:

``` text
OPEN
INVESTIGATING
CONTAINED
CLOSED
```

Decision:

``` text
CONFIRMED_PHISHING
FALSE_POSITIVE
NEEDS_INVESTIGATION
```

------------------------------------------------------------------------

## 19. Recommended Action Flow

Actions are grouped by priority:

### Immediate

-   Quarantine message
-   Verify suspicious payment request
-   Review credential exposure

### Investigation

-   Search related messages
-   Review campaign
-   Review infrastructure
-   Check affected accounts

### Preventive

-   Block/review domain
-   Strengthen MFA
-   Update mail controls
-   User awareness action

CyberSentry only recommends these actions in V1; it does not claim to
execute them.

------------------------------------------------------------------------

## 20. Report Flow

User selects:

> Generate Report

Choose:

-   PDF
-   JSON

Report is generated from persisted evidence and analysis, not from a
fresh re-analysis.

Report must include:

-   evidence hash
-   custody
-   score
-   findings
-   PhishDNA
-   campaign
-   graph summary
-   recommendations
-   analyst decision
-   confidence/limitations

------------------------------------------------------------------------

## 21. Error Flows

### Invalid EML

Show:

> This file could not be parsed as an email.

Keep evidence record if file preservation succeeded.

### LLM unavailable

Show:

> Semantic AI unavailable. Deterministic analysis completed.

Do not fail the analysis.

### Threat-intel provider unavailable

Show:

> External intelligence unavailable. Local intelligence and structural
> analysis used.

### Malformed URL

Store as extracted artifact with:

> URL normalization failed.

Do not fetch it.

------------------------------------------------------------------------

## 22. Navigation Map

``` text
/login

/dashboard
  ├── /analyze
  ├── /emails
  │     └── /emails/:id
  │           ├── overview
  │           ├── headers
  │           ├── content
  │           ├── urls
  │           ├── phishdna
  │           ├── graph
  │           └── evidence
  ├── /compare
  ├── /campaigns
  │     └── /campaigns/:id
  ├── /hunt
  ├── /cases
  │     └── /cases/:id
  └── /reports

/admin
  ├── /admin/users
  ├── /admin/intelligence
  └── /admin/audit
```

------------------------------------------------------------------------

## 23. Primary Demo Path

The judge demo should follow:

``` text
Login
 ↓
Upload Email A
 ↓
Show Evidence Hash
 ↓
Show Header/Auth
 ↓
Show Risk Explanation
 ↓
Show PhishDNA
 ↓
Upload Email B
 ↓
Show "What Changed?"
 ↓
Reveal Shared Infrastructure / Intent
 ↓
Open Campaign
 ↓
Open Attack Intent Graph
 ↓
Show Recommended Action
 ↓
Create Case
 ↓
Export Forensic PDF
```

This is the primary V1 story. Do not dilute the demo with deferred
features.
