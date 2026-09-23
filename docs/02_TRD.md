# CyberSentry V1 --- Technical Requirements Document (TRD)

**Version:** 1.0\
**Status:** Locked for implementation\
**Stack:** Next.js + TypeScript, FastAPI + Python, PostgreSQL\
**Deployment:** Docker Compose\
**AI:** Hybrid deterministic engine + optional LLM
**Design principle:** Model-agnostic intelligence layer; providers are adapters, not core dependencies.

------------------------------------------------------------------------

## 1. Technical Architecture

``` text
Browser
   │
   ▼
Next.js Frontend
   │ HTTPS/JSON
   ▼
FastAPI Backend
   │
   ├── Auth & RBAC
   ├── EML Intake
   ├── Evidence Service
   ├── Parser
   ├── Detection Engine
   ├── PhishDNA Engine
   ├── Risk Fusion
   ├── Intelligence Service
   ├── Campaign Correlation
   ├── Campaign Model Service
   ├── Campaign Evolution Timeline
   ├── Early Warning Service
   ├── Graph Service
   ├── Case Service
   └── Report Service
   │
   ▼
PostgreSQL
   │
   ├── relational entities
   ├── graph nodes/edges
   ├── audit events
   └── analysis results

Local filesystem / mounted volume
   └── encrypted-at-rest application evidence store
```

No Redis, RabbitMQ, Neo4j, S3, Kubernetes or separate graph database is
required for V1.

------------------------------------------------------------------------

## 2. Technology Choices

  -----------------------------------------------------------------------
  Layer                   Technology              Reason
  ----------------------- ----------------------- -----------------------
  Frontend                Next.js + TypeScript    Fast dashboard
                                                  development and strong
                                                  typing

  Styling                 Tailwind CSS            Rapid consistent UI

  Components              shadcn/ui               Accessible reusable
                                                  primitives

  Icons                   Lucide                  Technical/security UI
                                                  iconography

  Backend                 FastAPI                 Python ecosystem is
                                                  suitable for
                                                  email/security analysis

  Database                PostgreSQL              Single source of truth
                                                  and relational graph
                                                  representation

  ORM                     SQLAlchemy              Mature Python ORM and
                                                  explicit schema control

  Validation              Pydantic                API and analysis data
                                                  validation

  Auth                    JWT/session via         Real authentication
                          HttpOnly cookie         without external SaaS
                                                  dependency

  Password hashing        Argon2id or bcrypt      Secure password storage

  PDF                     ReportLab               Local deterministic
                                                  report generation

  JSON                    Native Python           Structured export
                          JSON/Pydantic           

  LLM                     Provider adapter;       Optional semantic
                          Gemini target           analysis

  Threat Intel            Local DB + optional     Demo works without
                          connectors              Internet/API

  Deployment              Docker Compose          Simple reproducible
                                                  local deployment
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 3. Backend Service Boundaries

### `backend/app/api/`

Owns:

-   HTTP routes
-   request/response schemas
-   authentication dependency wiring
-   route-level authorization

Must not contain:

-   complex parsing logic
-   scoring algorithms
-   direct LLM prompts
-   raw SQL spread across handlers

### `backend/app/core/`

Owns:

-   configuration
-   security primitives
-   authentication
-   authorization
-   shared constants
-   application errors

### `backend/app/models/`

Owns SQLAlchemy models.

### `backend/app/schemas/`

Owns Pydantic request/response contracts.

### `backend/app/services/`

Owns application use cases:

-   evidence
-   parsing
-   detection
-   intelligence
-   campaign correlation
-   graph
-   cases
-   reports

### `backend/app/engines/`

Owns pure analysis logic:

-   `header_engine`
-   `intent_engine`
-   `url_engine`
-   `phishdna_engine`
-   `risk_engine`
-   `campaign_engine`

Engines should be deterministic where possible and independently
testable.

### `backend/app/providers/`

Owns external integrations:

-   LLM provider
-   optional threat-intel providers
-   optional RDAP/DNS/GeoIP adapters

Provider failure must not crash the core analysis. Mailbox/gateway providers are future-scope adapters and are not implemented in V1.

### `backend/app/utils/`

Small reusable utilities only.

------------------------------------------------------------------------

## 4. Frontend Boundaries

``` text
frontend/
├── app/
├── components/
│   ├── ui/
│   ├── layout/
│   ├── dashboard/
│   ├── analysis/
│   ├── graph/
│   ├── cases/
│   └── reports/
├── lib/
├── hooks/
├── types/
└── styles/
```

Rules:

-   UI components do not contain security scoring logic.
-   API access is centralized.
-   Shared types mirror backend contracts.
-   Severity rendering uses shared design tokens.
-   Raw email HTML is never injected directly into the DOM.

------------------------------------------------------------------------

## 5. Authentication and Authorization

V1 has two roles:

``` text
ANALYST
ADMINISTRATOR
```

### Authentication

-   Username/email + password.
-   Passwords stored as secure hashes.
-   Authenticated session/token stored using HttpOnly, Secure, SameSite
    cookie.
-   Protected backend endpoints require authenticated user.
-   Frontend route protection is supplementary; backend authorization is
    authoritative.

### Authorization

Analyst:

-   Upload email
-   View own/permitted analyses
-   Search Hunter Mode
-   Compare emails
-   View campaigns/graphs
-   Create/update cases
-   Add analyst dispositions
-   Export reports

Administrator:

-   All analyst capabilities
-   User management
-   Configuration
-   Threat-intel seed data management
-   System audit view

------------------------------------------------------------------------

## 6. EML Processing Pipeline

``` text
Upload
  ↓
File validation
  ↓
SHA-256
  ↓
Evidence record
  ↓
Custody hash-chain event
  ↓
Safe MIME parsing
  ↓
Normalization
  ↓
Header/Auth Analysis
  ↓
Content/Intent Analysis
  ↓
URL/Domain Analysis
  ↓
Infrastructure Intelligence
  ↓
PhishDNA
  ↓
Risk Fusion
  ↓
Campaign Correlation
  ↓
Attack Intent Graph
  ↓
Recommended Actions
  ↓
Persist analysis
```

### Safety invariant

The primary application must never execute:

-   JavaScript from an email
-   HTML active content
-   macros
-   binaries
-   attachments
-   arbitrary URLs

------------------------------------------------------------------------

## 7. Header Trust Model

The parser should preserve the complete Received chain.

The system then creates a `hop_trust_level`:

-   `TRUSTED`
-   `OBSERVED`
-   `UNTRUSTED`
-   `UNKNOWN`

V1 does not pretend that every Received header is trustworthy.

Default logic:

1.  Parse hops in header order.
2.  Identify configured organizational/trusted gateway domains/IP
    ranges.
3.  Mark known trusted infrastructure as `TRUSTED`.
4.  Mark syntactically valid but unverified external hops as `OBSERVED`.
5.  Mark malformed/contradictory or clearly sender-controlled evidence
    as `UNTRUSTED`.
6.  Use only sufficiently trusted evidence for strong infrastructure
    conclusions.
7.  Preserve all hops for forensic visibility.

If no trusted boundary is configured, the report must state that
infrastructure attribution confidence is limited.

------------------------------------------------------------------------

## 8. Authentication Model

SPF, DKIM and DMARC are independent evidence sources.

The engine must preserve:

-   raw result
-   normalized result
-   alignment result when available
-   source of result
-   confidence
-   explanation

No authentication result alone can produce a final verdict.

------------------------------------------------------------------------

## 9. Risk Fusion Engine

### Risk bands

``` text
0–24    LOW
25–49   MEDIUM
50–74   HIGH
75–100  CRITICAL
```

### Signal families

  Family           Example signals
  ---------------- --------------------------------------------------
  Identity         display-name mismatch, From/Reply-To mismatch
  Authentication   SPF/DKIM/DMARC results and alignment
  Header           route anomalies, timestamp inconsistencies
  Domain           lookalike, punycode, suspicious characteristics
  URL              suspicious path, redirect indicators, reputation
  Intent           credential theft, payment fraud, impersonation
  Infrastructure   suspicious ASN/hosting/reputation
  Attachment       type mismatch, archive depth, known hash
  Campaign         similarity to known analyzed malicious samples
  Anomaly          unknown indicator + multiple suspicious features

### Important scoring rule

Authentication is a weighted signal, not a gate.

Unknown reputation is neutral by itself but can contribute to anomaly
risk when combined with other suspicious signals.

The score must be clamped to `[0,100]`.

The engine returns:

``` json
{
  "score": 87,
  "band": "CRITICAL",
  "signals": [
    {
      "code": "LOOKALIKE_DOMAIN",
      "label": "Lookalike sender domain",
      "weight": 18,
      "direction": "risk_increase",
      "evidence_id": "..."
    }
  ],
  "confidence": 0.89,
  "engine_version": "risk-v1"
}
```

The exact weights should live in configuration, not scattered through UI
code.

------------------------------------------------------------------------

## 10. LLM Contract

The LLM is a semantic analyst, not the final security authority.

Input should be minimized to fields such as:

-   subject
-   sanitized body text
-   sender/domain context
-   extracted URL/domain metadata
-   relevant normalized features

Output must be structured JSON:

``` json
{
  "intent_categories": [],
  "impersonation_target": null,
  "urgency_level": "low|medium|high",
  "social_engineering_indicators": [],
  "semantic_risk": 0,
  "confidence": 0,
  "explanation": []
}
```

If the LLM:

-   times out
-   is unavailable
-   returns invalid JSON
-   exceeds quota
-   is not configured

the deterministic engine continues.

Never allow free-form LLM text to directly become a security verdict.

### Model-agnostic AI contract

The core engine must consume structured analysis objects rather than provider-specific text. A provider adapter may use Gemini, a local model, or another compatible model later. The required interface returns structured fields such as intent, impersonation target, semantic risk, confidence, and evidence references.

The LLM must never create an indicator, relationship, or finding without a corresponding extracted/evidence-backed input. The deterministic engine remains authoritative for technical facts.

------------------------------------------------------------------------

## 11. PhishDNA Technical Model

PhishDNA is a normalized feature object plus a comparison fingerprint.

Example structure:

``` json
{
  "header": {
    "from_domain": "...",
    "reply_to_mismatch": true,
    "received_hop_count": 4
  },
  "auth": {
    "spf": "pass",
    "dkim": "pass",
    "dmarc": "pass"
  },
  "content": {
    "intent": ["credential_harvesting"],
    "urgency": "high",
    "impersonation": "bank"
  },
  "url": {
    "host_features": [],
    "lookalike_score": 0.91,
    "punycode": false
  },
  "infrastructure": {
    "asn": 12345,
    "country": "..."
  },
  "behavioral": {
    "normalized_time_bucket": "...",
    "language": "en"
  },
  "attachment": {
    "hashes": []
  }
}
```

Similarity is calculated using an explicit 5-factor weighted model:
1. **Semantic Intent & Target Brand (40%)**: Semantic cosine similarity over the 32-dimensional normalized feature vector (intent, target, coercion strategy, CTA).
2. **URL & Domain Canonical Structure (25%)**: Exact canonical landing host match and path structure similarity.
3. **Infrastructure & /24 Subnet Network (20%)**: Shared MTA origin IPs and `/24` subnet network mask matches (`extract_subnet_24`), acting strictly as corroborating evidence.
4. **HTML DOM Layout (10%)**: Jaccard tag n-gram sequence matching.
5. **Authentication Alignment (5%)**: Reported SPF/DKIM/DMARC failure mode consistency.

**Hard-Negative Rejection Gate**: Payloads exhibiting valid corporate authentication and benign intent are rejected from malicious clusters with similarity strictly < 20%.

------------------------------------------------------------------------

## 12. Campaign Correlation & Investigation

Use PostgreSQL tables rather than a graph database.

Correlation score combines the 5-factor PhishDNA model with multi-family corroboration:

``` text
5-Factor PhishDNA similarity (40% Semantic + 25% URL + 20% Subnet + 10% HTML + 5% Auth)
+ Retained Attack Invariants verification (Intent + Target + Strategy)
+ Infrastructure Relationships classification (/24 Subnet + Origin IP)
+ Chronological evolution tracking
```

Campaigns progress through multi-dimensional activity states:
- `CANDIDATE`: Single initial email payload (Campaign Anchor baseline).
- `EMERGING`: 2–3 confirmed correlated email variants.
- `ACTIVE`: Sustained temporal recurrence or targeting multiple internal mailboxes.
- `EXPANDING`: Broadening infrastructure or technique mutations across multiple networks.

Create a campaign edge/membership only when the similarity threshold (>=70%) is met with multi-family validation.

Each edge stores:

-   relation type
-   evidence strength (`STRONG`, `MODERATE`, `BASELINE`)
-   evidence/source
-   created timestamp

## 13. Attack Campaign Model

The Attack Campaign Model is a derived projection over campaigns, PhishDNA, graph relationships, findings, and observed infrastructure. It is implemented with PostgreSQL tables/JSONB, not a dedicated digital-twin platform.

Required state:

-   campaign status
-   confidence
-   risk trend
-   first/last observed
-   dominant intent
-   observed infrastructure count
-   related message count
-   evolution events

Each state change references the evidence/analysis that caused the update.

### Early-warning rules

V1 may emit a campaign warning when observed evidence shows expansion, new related infrastructure, repeated intent, or increasing risk. This is risk-based forecasting of campaign state, not deterministic prediction of the next attack.


------------------------------------------------------------------------

## 14. Campaign Evolution Timeline

The timeline is a first-class V1 projection of observed campaign evolution. It is not a prediction timeline.

Each event records:

- event type
- event time
- campaign ID
- triggering analysis/evidence ID
- concise event summary
- previous/new value where applicable
- confidence where applicable
- provenance/source

Examples:

- `RELATED_EMAIL_OBSERVED`
- `NEW_DOMAIN_OBSERVED`
- `NEW_IP_OBSERVED`
- `INTENT_CHANGE_OBSERVED`
- `PHISHDNA_VARIANT_OBSERVED`
- `RISK_TREND_CHANGED`
- `CAMPAIGN_STATE_CHANGED`

Only events derived from evidence already analyzed by CyberSentry may appear. No event may imply that CyberSentry observed activity outside its configured inputs.

---

## 14. Infrastructure Intelligence

V1 may enrich observed IPs using:

-   local seed intelligence
-   optional GeoIP dataset
-   optional passive DNS/RDAP
-   optional external reputation provider

Every enrichment result stores:

-   provider
-   lookup time
-   raw/normalized result
-   confidence
-   freshness
-   status

UI language:

-   `Observed IP`
-   `Infrastructure`
-   `ASN`
-   `ISP/Organization`
-   `Country/Region`
-   `Confidence`

Do not label the result `Attacker Location`.

------------------------------------------------------------------------

## 15. Evidence Integrity

For each uploaded file:

``` text
raw bytes
   ↓
SHA-256
   ↓
evidence record
   ↓
custody event
   ↓
previous event hash
   ↓
current event hash
```

Current event hash:

``` text
SHA256(
  previous_hash +
  evidence_id +
  actor_id +
  action +
  timestamp +
  metadata_hash
)
```

The raw file remains separate from the hash-chain metadata.

V1 does not use blockchain.

------------------------------------------------------------------------

## 16. External Intelligence Failure Policy

External services are optional.

If unavailable:

-   analysis continues
-   status becomes `UNAVAILABLE`
-   result is not treated as malicious/benign solely because the
    provider failed
-   provenance records the failure

Local seed intelligence must be sufficient for the demo.

------------------------------------------------------------------------

## 17. Evaluation and Dataset Contract

The repository must contain a reproducible evaluation dataset manifest. Each sample has a category and expected label/relationship. The evaluation runner should calculate detection metrics and campaign-linking results from actual outputs.

Minimum V1 categories: known phishing, BEC/impersonation, unknown/novel phishing, AI-generated phishing, lookalike domains, URL obfuscation/polymorphic variants, legitimate email, and hard negatives.

Do not hardcode claimed accuracy values.

------------------------------------------------------------------------

## 18. API Contract

### Authentication

``` text
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

### Evidence / Analysis

``` text
POST /api/v1/emails/analyze
GET  /api/v1/emails/{id}
GET  /api/v1/emails/{id}/evidence
GET  /api/v1/emails/{id}/graph
```

### Comparison

``` text
GET /api/v1/emails/compare?left_id=...&right_id=...
```

### Hunter

``` text
GET /api/v1/hunt
```

### Campaigns

``` text
GET /api/v1/campaigns
GET /api/v1/campaigns/{id}
GET /api/v1/campaigns/{id}/model
```

### Cases

``` text
POST /api/v1/cases
GET  /api/v1/cases
GET  /api/v1/cases/{id}
POST /api/v1/cases/{id}/decision
```

### Reports

``` text
GET /api/v1/reports/{case_id}/pdf
GET /api/v1/reports/{case_id}/json
```

### Admin

``` text
GET /api/v1/admin/users
POST /api/v1/admin/users
PATCH /api/v1/admin/users/{id}
GET /api/v1/admin/audit
```

------------------------------------------------------------------------

## 19. Error Contract

All API errors should follow:

``` json
{
  "error": {
    "code": "INVALID_EML",
    "message": "The uploaded file could not be parsed as an email.",
    "request_id": "..."
  }
}
```

Do not expose stack traces or internal provider errors to users.

------------------------------------------------------------------------

## 20. Performance Targets

V1 target:

-   File validation: \< 1 second for normal demo files.
-   Initial parse + deterministic analysis: preferably \< 10 seconds for
    a standard EML.
-   UI should show progress during analysis.
-   External intelligence/LLM may extend total time but must show
    provider state.

Because V1 uses a single FastAPI process for the hackathon, asynchronous
infrastructure is not mandatory.

------------------------------------------------------------------------

## 21. Testing Requirements

### Unit

-   EML parsing
-   Received-hop parsing
-   auth interpretation
-   URL normalization
-   punycode/homoglyph detection
-   risk calculation
-   PhishDNA normalization
-   similarity
-   campaign correlation
-   hash chain

### Integration

-   upload → analysis → DB
-   login → role protection
-   analysis → case
-   case → report
-   two emails → campaign
-   LLM unavailable → deterministic fallback

### Security

-   malformed EML
-   oversized file
-   HTML/JS injection
-   path traversal
-   SQL injection
-   unauthorized case access
-   role bypass
-   invalid JWT/session
-   malicious attachment names
-   XSS through email content

------------------------------------------------------------------------

## 22. Deployment

Docker Compose services:

``` text
frontend
backend
postgres
```

Optional:

``` text
geoip / intelligence data volume
```

The application must start with one command and work without external
services.

------------------------------------------------------------------------

## 23. Core Technical Invariants

1.  The backend is authoritative for authorization.
2.  Raw email content is treated as untrusted input.
3.  No email content or attachment is executed.
4.  No arbitrary URL is fetched automatically.
5.  Authentication results never alone determine the verdict.
6.  Unknown reputation never means safe.
7.  Campaign model state must be derived from stored evidence/analysis.
8.  AI provider changes must not alter the core evidence, graph, or risk contracts.
7.  Infrastructure location never means attacker identity/location.
8.  LLM output never directly determines the final verdict.
9.  External provider failure never breaks core analysis.
10. Every finding retains provenance and confidence where applicable.
11. PostgreSQL is the only database in V1.
12. Graph relationships are relational tables in V1.
