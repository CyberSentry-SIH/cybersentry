# CyberSentry V1 --- Implementation Plan

**Version:** 1.0\
**Target:** One-day hackathon build / approximately 14 focused hours\
**Team:** 6 people\
**AI coding:** AI performs most implementation; humans review, integrate
and demo

------------------------------------------------------------------------

## 1. Implementation Strategy

Build the **smallest complete investigation story**, not the largest
architecture.

The build order is:

``` text
Foundation
 ↓
EML Evidence
 ↓
Parser
 ↓
Detection
 ↓
PhishDNA
 ↓
Risk
 ↓
Correlation
 ↓
Graph
 ↓
Case/Report
 ↓
UI Polish
 ↓
Demo Hardening
```

Do not start with:

-   advanced ML training
-   mailbox integrations
-   sandboxing
-   OCR
-   external API integrations
-   elaborate infrastructure

Those are not required to prove the V1 differentiator.

------------------------------------------------------------------------

## 2. Team Split

### Person 1 --- Lead / Integration

Own:

-   architecture
-   repo setup
-   environment
-   integration
-   final demo
-   code review

### Person 2 --- Backend / EML

Own:

-   FastAPI
-   upload endpoint
-   evidence storage
-   SHA-256
-   custody hash chain
-   email parsing

### Person 3 --- Detection Engine

Own:

-   header analysis
-   SPF/DKIM/DMARC representation
-   URL/domain analysis
-   risk scoring
-   explanation codes

### Person 4 --- AI / PhishDNA

Own:

-   LLM adapter
-   intent extraction
-   prompt/schema
-   PhishDNA
-   similarity logic
-   fallback behavior

### Person 5 --- Frontend

Own:

-   Next.js shell
-   dashboard
-   upload
-   analysis overview
-   risk/explanation panels

### Person 6 --- Correlation / Reports / QA

Own:

-   campaign correlation
-   graph data
-   What Changed?
-   cases
-   PDF/JSON report
-   synthetic dataset
-   end-to-end testing

Everyone reviews the integration branch before the final demo.

------------------------------------------------------------------------

## 3. Repository Structure

``` text
cybersentry/
├── frontend/
│   ├── app/
│   ├── components/
│   ├── hooks/
│   ├── lib/
│   └── types/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── engines/
│   │   ├── providers/
│   │   └── utils/
│   ├── tests/
│   └── requirements.txt
│
├── data/
│   ├── synthetic/
│   └── threat-intel/
│
├── docs/
│
├── docker-compose.yml
└── README.md
```

------------------------------------------------------------------------

## 4. Phase 0 --- Foundation

### Architecture invariant

Keep the analysis contracts provider-agnostic. The core engine must accept structured AI results and must continue to work when the LLM provider is disabled or replaced.

### Deliverables

-   Git repository
-   frontend app
-   backend app
-   PostgreSQL
-   Docker Compose
-   environment configuration
-   health endpoint
-   database connection

### Exit criteria

``` text
docker compose up
       ↓
frontend opens
backend health returns OK
database connects
```

Do not proceed until this works.

------------------------------------------------------------------------

## 5. Phase 1 --- Authentication

### Build

-   user table
-   password hashing
-   login
-   logout
-   session
-   role checks
-   seed analyst/admin users

### Exit criteria

-   analyst can sign in
-   admin can sign in
-   unauthorized API calls fail
-   analyst cannot access admin routes

------------------------------------------------------------------------

## 6. Phase 2 --- EML Evidence Intake

### Build

-   upload endpoint
-   drag/drop UI
-   `.eml` validation
-   file size validation
-   SHA-256
-   local evidence storage
-   evidence record
-   custody hash chain

### Exit criteria

Upload one `.eml` and display:

``` text
Evidence ID
SHA-256
File name
Collected time
Integrity status
```

This should work before detection is added.

------------------------------------------------------------------------

## 7. Phase 3 --- Email Parser

### Build

Extract:

-   headers
-   sender
-   recipients
-   Reply-To
-   Return-Path
-   Message-ID
-   Received hops
-   auth headers
-   text body
-   HTML body
-   URLs
-   attachments

### Security

-   no HTML execution
-   no URL fetching
-   no attachment execution
-   size limits
-   safe parser configuration

### Exit criteria

Given a known synthetic email, the parser returns expected structured
fields.

------------------------------------------------------------------------

## 8. Phase 4 --- Header/Auth Engine

### Build

-   From/Reply-To comparison
-   display-name mismatch
-   domain mismatch
-   Received-hop parsing
-   trust classification
-   SPF/DKIM/DMARC extraction
-   alignment representation

### Exit criteria

Dashboard displays a complete authentication/header analysis.

------------------------------------------------------------------------

## 9. Phase 5 --- URL/Domain Engine

### Build

-   URL canonicalization
-   hostname extraction
-   punycode detection
-   homoglyph/lookalike detection
-   suspicious path checks
-   local threat-intel lookup
-   optional external lookup adapter

### Important

Do not build live crawling.

Do not automatically open arbitrary email URLs.

### Exit criteria

At least three synthetic URL conditions work:

1.  known malicious
2.  unknown but suspicious
3.  benign

------------------------------------------------------------------------

## 10. Phase 6 --- Semantic Intent AI

### Build

LLM provider interface:

``` text
SemanticAnalyzer
    ├── GeminiProvider
    └── Disabled/MockProvider
```

Prompt asks for:

-   intent
-   impersonation target
-   urgency
-   social engineering indicators
-   semantic risk
-   explanation

### Fallback

If no API key:

``` text
LLM unavailable
      ↓
deterministic intent heuristics
      ↓
analysis continues
```

### Exit criteria

The same demo email produces a valid structured semantic result with or
without the LLM.

------------------------------------------------------------------------

## 11. Phase 7 --- PhishDNA

### Build

Normalization functions for:

-   headers
-   identity/auth
-   content
-   URLs
-   infrastructure
-   behavior
-   attachments

Generate:

-   normalized feature object
-   fingerprint
-   similarity function

### Exit criteria

Two emails with changed wording/sender/URL but shared campaign
characteristics produce a meaningful similarity result.

------------------------------------------------------------------------

## 12. Phase 8 --- Risk Fusion

### Build

Combine:

-   header
-   auth
-   identity
-   intent
-   URL
-   domain
-   infrastructure
-   attachment
-   campaign
-   anomaly

Output:

``` text
score
band
confidence
signals
```

### Required behavior

Test:

``` text
SPF PASS + DKIM PASS + DMARC PASS
```

with malicious intent/lookalike domain.

Expected:

> Still capable of HIGH/CRITICAL risk.

Test:

``` text
Unknown reputation
```

with no other anomalies.

Expected:

> Not automatically malicious.

Test:

``` text
Unknown reputation
+
multiple anomalies
```

Expected:

> Elevated investigation risk.

------------------------------------------------------------------------

## 13. Phase 9 --- Campaign Correlation

### Build

For every analyzed email:

1.  Search previous PhishDNA.
2.  Search shared indicators.
3.  Search shared infrastructure.
4.  Search intent similarity.
5.  Calculate relationship score.
6.  Create/update campaign.

### Exit criteria

Email A + Email B become related.

UI shows:

> Likely same campaign --- 92% confidence.

------------------------------------------------------------------------

## 14. Phase 10 --- Attack Campaign Model & Early Warning

### Build

After campaign correlation, create/update a lightweight campaign state projection in PostgreSQL.

Track:

-   state: Emerging / Active / Expanding / Monitoring
-   confidence
-   risk trend
-   first/last seen
-   related message count
-   infrastructure count
-   dominant intent
-   evolution events
-   first-class Campaign Evolution Timeline records

Generate early-warning messages only from observed evidence, for example:

> Campaign expanding — new related infrastructure observed.

Do **not** build a future-attack prediction model in the 14-hour V1.

### Exit criteria

A second/third related email updates the campaign state and produces an explainable evolution event.

------------------------------------------------------------------------

## 15. Phase 11 --- What Changed?

### Build

Comparison service.

Inputs:

``` text
email_a_id
email_b_id
```

Output:

-   field differences
-   shared features
-   structural similarity
-   infrastructure similarity
-   intent similarity
-   PhishDNA similarity
-   campaign likelihood

### Exit criteria

The judge can visually understand why two different-looking emails are
related.

------------------------------------------------------------------------

## 16. Phase 12 --- Attack Intent Graph

### Build

Create relational graph nodes/edges.

Minimum graph:

``` text
Email
 ↓
Sender
 ↓
Impersonation
 ↓
Intent
 ↓
URL
 ↓
Domain
 ↓
IP
 ↓
ASN
 ↓
Campaign
```

### Exit criteria

Graph renders and clicking a node opens evidence details.

Do not build a dedicated graph database.

------------------------------------------------------------------------

## 17. Phase 13 --- Case Management

### Build

-   create case
-   assign owner
-   status
-   decision
-   comments
-   linked evidence
-   linked findings

### Exit criteria

Analyst can turn an analysis into a case and record:

> Confirmed Phishing

or

> False Positive

------------------------------------------------------------------------

## 18. Phase 14 --- Reports

### Build

PDF:

-   title
-   case
-   evidence hash
-   summary
-   score
-   reasons
-   auth
-   URL
-   infrastructure
-   PhishDNA
-   campaign
-   graph summary
-   actions
-   analyst decision
-   limitations

JSON:

Use a stable versioned schema.

### Exit criteria

PDF opens successfully and JSON validates.

------------------------------------------------------------------------

## 19. Phase 15 --- Hunter Mode

### Build

One search endpoint with filters.

Minimum:

-   domain
-   URL
-   IP
-   sender
-   hash
-   campaign
-   intent
-   risk

### Exit criteria

Searching a known domain finds all related analyzed emails.

------------------------------------------------------------------------

## 20. Phase 16 --- UI Integration

Prioritize:

1.  Login
2.  Dashboard
3.  Upload
4.  Analysis result
5.  Risk explanation
6.  PhishDNA
7.  What Changed?
8.  Campaign
9.  Graph
10. Case
11. Report

Do not spend time on secondary settings pages before the investigation
flow works.

------------------------------------------------------------------------

## 21. Synthetic Demo Dataset

Create at least three `.eml` messages.

### Email A --- Primary phishing

Characteristics:

-   lookalike sender
-   suspicious Reply-To
-   credential harvesting intent
-   suspicious URL
-   unknown/new infrastructure
-   authentication that may pass partially or fully
-   high risk

### Email B --- Polymorphic variant

Characteristics:

-   different sender/domain
-   different wording
-   different URL
-   same/similar infrastructure
-   same intent
-   similar HTML/structure

Expected:

> Related to Email A.

### Email C --- Benign

Characteristics:

-   legitimate sender
-   normal relationship
-   ordinary business language
-   benign URL/domain
-   no suspicious indicators

Expected:

> LOW.

------------------------------------------------------------------------

## 22. Evaluation Strategy

Create a small reproducible evaluation manifest before the final presentation. Do not invent accuracy numbers.

### Required categories

-   known phishing
-   BEC/impersonation
-   unknown/novel phishing
-   AI-generated phishing
-   lookalike domains
-   URL obfuscation/polymorphic variants
-   legitimate business email
-   hard negatives

### Measure

Detection:

-   precision
-   recall
-   F1
-   false-positive rate

Intelligence:

-   correct PhishDNA variant links
-   correct campaign links
-   incorrect campaign links
-   evidence/explanation completeness

If the sample is too small for statistically meaningful percentages, present counts and qualitative error analysis.

Do not include QR/image/OCR benchmark claims in V1 because those capabilities are explicitly out of scope.

------------------------------------------------------------------------

## 23. Recommended Demo Narrative

### Minute 0--1

Introduce:

> "CyberSentry is not just a phishing classifier. It is an email
> investigation and campaign intelligence platform."

### Minute 1--2

Upload Email A.

Show:

-   evidence hash
-   header/auth
-   risk score

### Minute 2--3

Explain:

> "Authentication passed, but authentication alone does not prove
> legitimacy."

Show:

-   lookalike domain
-   Reply-To mismatch
-   intent
-   URL

### Minute 3--4

Show PhishDNA.

Upload Email B.

Open:

> **What Changed?**

Reveal:

> Different surface indicators, same underlying campaign
> characteristics.

### Minute 4--5

Open the **Attack Campaign Model** and show campaign state/evolution.

Say:

> "The attacker changed the email. CyberSentry detected the campaign."

Then open the Attack Intent Graph.

Explain:

> "Instead of stopping at 'phishing', CyberSentry connects the email to
> the infrastructure and related attempts behind it."

### Minute 5--6

Show recommended actions and forensic report.

Close with:

> "V1 is analyst-side forensic triage. The same API analysis engine can
> later sit behind a mailbox or mail gateway for pre-delivery
> detection. Our campaign model represents observed campaign state; it
> does not claim to predict the attacker with certainty."

------------------------------------------------------------------------

## 24. Final Hardening Checklist

### Functional

-   [ ] Login works
-   [ ] EML upload works
-   [ ] SHA-256 displayed
-   [ ] Parser works
-   [ ] SPF/DKIM/DMARC displayed
-   [ ] URL analysis works
-   [ ] Risk score works
-   [ ] PhishDNA works
-   [ ] Campaign correlation works
-   [ ] Campaign Evolution Timeline works
-   [ ] What Changed? works
-   [ ] Graph works
-   [ ] Case works
-   [ ] PDF works
-   [ ] JSON works
-   [ ] Hunter Mode works

### Security

-   [ ] No email HTML executes
-   [ ] No URL auto-fetch
-   [ ] No attachment execution
-   [ ] Auth protected
-   [ ] Role checks backend-enforced
-   [ ] Secrets not committed
-   [ ] API errors do not leak stack traces
-   [ ] Raw evidence is not public
-   [ ] Analyst decisions are audited

### Demo

-   [ ] Demo data is synthetic
-   [ ] LLM can be disabled
-   [ ] External APIs can be disabled
-   [ ] Local threat-intel seed data exists
-   [ ] Database is pre-seeded
-   [ ] Two related emails are ready
-   [ ] One benign email is ready
-   [ ] Docker Compose starts cleanly
-   [ ] PDF export tested

------------------------------------------------------------------------

## 25. V1/Future Boundary

Only capabilities explicitly assigned to Phases 0–16 are V1 implementation work. Features in `07_FUTURE_SCOPE.md` are not fallback tasks for unused time; they are post-V1 roadmap items. Do not partially implement a future feature if it weakens a complete V1 investigation workflow.

## 26. What Must NOT Consume Hackathon Time

Stop implementation of any feature that becomes:

-   full ML training pipeline
-   dedicated graph database
-   distributed queue
-   mailbox integration
-   malware sandbox
-   OCR
-   QR detection
-   webpage screenshot analysis
-   employee profiling
-   organization-wide victim profiling
-   predictive next-attack model
-   blockchain
-   full SIEM/SOAR

The objective is not feature count.

The objective is a **complete, believable, technically defensible
investigation workflow**.
