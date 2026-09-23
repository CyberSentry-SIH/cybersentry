# CyberSentry V1 --- Backend Schema

**Version:** 1.0\
**Database:** PostgreSQL\
**Graph:** Relational node/edge model\
**ORM:** SQLAlchemy

------------------------------------------------------------------------

## 1. Entity Relationship Overview

``` text
User ───────< AuditEvent
 │
 └──────────< Case
                │
Evidence ───────┼────< CaseEvidence >──── Case
 │              │
 └── Message ───┼────< Finding
                 │
Indicator ───────┼────< Enrichment
 │               │
 └───────────────┼────< GraphEdge
                 │
Campaign ────────┼────< CampaignMember
 │
 └──────────< CampaignModelSnapshot
                 │
Analysis ────────┘
```

------------------------------------------------------------------------

## 2. users

``` sql
users (
    id UUID PRIMARY KEY,
    email VARCHAR(320) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(200) NOT NULL,
    role VARCHAR(32) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
)
```

Allowed roles:

``` text
ANALYST
ADMINISTRATOR
```

------------------------------------------------------------------------

## 3. sessions

``` sql
sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL
)
```

Store only a hash of the session token.

------------------------------------------------------------------------

## 4. evidence

Represents the original uploaded `.eml`.

``` sql
evidence (
    id UUID PRIMARY KEY,
    evidence_id VARCHAR(32) UNIQUE NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(128) NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    collected_by UUID REFERENCES users(id),
    retention_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL
)
```

`source_type` allowed in V1:

``` text
USER_UPLOAD
```

Future migration values (DO NOT use in V1 application behavior):

``` text
GMAIL_API
GRAPH_API
MAIL_GATEWAY
```

The schema may reserve these values for forward compatibility, but V1 APIs must reject them as unsupported input sources.

------------------------------------------------------------------------

## 5. custody_events

``` sql
custody_events (
    id UUID PRIMARY KEY,
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    actor_id UUID REFERENCES users(id),
    action VARCHAR(64) NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    metadata_hash CHAR(64) NOT NULL,
    previous_event_hash CHAR(64) NULL,
    event_hash CHAR(64) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'
)
```

Actions:

``` text
INGESTED
PARSED
ANALYZED
EXPORTED
VIEWED
DECISION_RECORDED
```

The hash chain is per evidence stream or globally ordered by
implementation choice; V1 should use a deterministic ordering and
document it.

------------------------------------------------------------------------

## 6. emails

``` sql
emails (
    id UUID PRIMARY KEY,
    evidence_id UUID UNIQUE NOT NULL REFERENCES evidence(id),

    message_id TEXT NULL,
    subject TEXT NULL,
    from_name TEXT NULL,
    from_address TEXT NULL,
    from_domain TEXT NULL,
    reply_to TEXT NULL,
    return_path TEXT NULL,

    sent_at TIMESTAMPTZ NULL,
    received_at TIMESTAMPTZ NULL,

    body_text TEXT NULL,
    body_html TEXT NULL,

    parser_status VARCHAR(32) NOT NULL,
    parser_version VARCHAR(32) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
)
```

Raw HTML must not be rendered unsafely in the frontend.

------------------------------------------------------------------------

## 7. email_recipients

``` sql
email_recipients (
    id UUID PRIMARY KEY,
    email_id UUID NOT NULL REFERENCES emails(id),
    address TEXT NOT NULL,
    recipient_type VARCHAR(16) NOT NULL
)
```

Allowed:

``` text
TO
CC
BCC
```

------------------------------------------------------------------------

## 8. received_hops

``` sql
received_hops (
    id UUID PRIMARY KEY,
    email_id UUID NOT NULL REFERENCES emails(id),
    hop_order INTEGER NOT NULL,
    raw_value TEXT NOT NULL,
    hostname TEXT NULL,
    ip_address INET NULL,
    timestamp TIMESTAMPTZ NULL,
    trust_level VARCHAR(16) NOT NULL,
    trust_reason TEXT NULL
)
```

Trust levels:

``` text
TRUSTED
OBSERVED
UNTRUSTED
UNKNOWN
```

------------------------------------------------------------------------

## 9. authentication_results

``` sql
authentication_results (
    id UUID PRIMARY KEY,
    email_id UUID UNIQUE NOT NULL REFERENCES emails(id),
    spf_result VARCHAR(32) NULL,
    spf_alignment VARCHAR(32) NULL,
    dkim_result VARCHAR(32) NULL,
    dkim_alignment VARCHAR(32) NULL,
    dmarc_result VARCHAR(32) NULL,
    dmarc_alignment VARCHAR(32) NULL,
    raw_header TEXT NULL,
    source VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)
```

------------------------------------------------------------------------

## 10. attachments

``` sql
attachments (
    id UUID PRIMARY KEY,
    email_id UUID NOT NULL REFERENCES emails(id),
    filename TEXT NOT NULL,
    content_type TEXT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    extension TEXT NULL,
    static_risk VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    metadata JSONB NOT NULL DEFAULT '{}'
)
```

V1 stores metadata and hashes. No execution.

------------------------------------------------------------------------

## 11. indicators

``` sql
indicators (
    id UUID PRIMARY KEY,
    indicator_type VARCHAR(32) NOT NULL,
    canonical_value TEXT NOT NULL,
    display_value TEXT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(indicator_type, canonical_value)
)
```

Types:

``` text
EMAIL
DOMAIN
URL
IP
ASN
ATTACHMENT_HASH
MESSAGE_ID
```

------------------------------------------------------------------------

## 12. email_indicators

``` sql
email_indicators (
    email_id UUID NOT NULL REFERENCES emails(id),
    indicator_id UUID NOT NULL REFERENCES indicators(id),
    source VARCHAR(64) NOT NULL,
    confidence NUMERIC(5,4) NULL,
    PRIMARY KEY(email_id, indicator_id)
)
```

------------------------------------------------------------------------

## 13. enrichments

``` sql
enrichments (
    id UUID PRIMARY KEY,
    indicator_id UUID NOT NULL REFERENCES indicators(id),
    provider VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    result JSONB NOT NULL DEFAULT '{}',
    confidence NUMERIC(5,4) NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL
)
```

Statuses:

``` text
KNOWN_MALICIOUS
KNOWN_BENIGN
UNKNOWN
UNAVAILABLE
ERROR
```

------------------------------------------------------------------------

## 14. analysis_runs

``` sql
analysis_runs (
    id UUID PRIMARY KEY,
    email_id UUID UNIQUE NOT NULL REFERENCES emails(id),
    engine_version VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NULL,
    llm_used BOOLEAN NOT NULL DEFAULT FALSE,
    external_intel_used BOOLEAN NOT NULL DEFAULT FALSE,
    error_message TEXT NULL
)
```

------------------------------------------------------------------------

## 15. findings

``` sql
findings (
    id UUID PRIMARY KEY,
    analysis_id UUID NOT NULL REFERENCES analysis_runs(id),
    category VARCHAR(32) NOT NULL,
    code VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_contribution NUMERIC(6,2) NOT NULL DEFAULT 0,
    confidence NUMERIC(5,4) NULL,
    provenance JSONB NOT NULL DEFAULT '{}',
    evidence JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL
)
```

Categories:

``` text
IDENTITY
AUTHENTICATION
HEADER
CONTENT
INTENT
URL
DOMAIN
INFRASTRUCTURE
ATTACHMENT
CAMPAIGN
ANOMALY
```

------------------------------------------------------------------------

## 16. risk_scores

``` sql
risk_scores (
    id UUID PRIMARY KEY,
    analysis_id UUID UNIQUE NOT NULL REFERENCES analysis_runs(id),
    score NUMERIC(5,2) NOT NULL,
    band VARCHAR(16) NOT NULL,
    confidence NUMERIC(5,4) NULL,
    signal_snapshot JSONB NOT NULL,
    engine_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)
```

Score band:

``` text
LOW
MEDIUM
HIGH
CRITICAL
```

------------------------------------------------------------------------

## 17. llm_analyses

``` sql
llm_analyses (
    id UUID PRIMARY KEY,
    analysis_id UUID UNIQUE NOT NULL REFERENCES analysis_runs(id),
    provider VARCHAR(64) NOT NULL,
    model VARCHAR(128) NOT NULL,
    prompt_version VARCHAR(32) NOT NULL,
    intent_categories JSONB NOT NULL DEFAULT '[]',
    impersonation_target TEXT NULL,
    urgency_level VARCHAR(16) NULL,
    social_engineering_indicators JSONB NOT NULL DEFAULT '[]',
    semantic_risk NUMERIC(5,2) NULL,
    confidence NUMERIC(5,4) NULL,
    explanation JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)
```

Do not store raw provider secrets.

------------------------------------------------------------------------

## 18. phishdna

``` sql
phishdna (
    id UUID PRIMARY KEY,
    analysis_id UUID UNIQUE NOT NULL REFERENCES analysis_runs(id),
    fingerprint VARCHAR(128) NOT NULL,
    header_dna JSONB NOT NULL DEFAULT '{}',
    identity_auth_dna JSONB NOT NULL DEFAULT '{}',
    content_dna JSONB NOT NULL DEFAULT '{}',
    url_dna JSONB NOT NULL DEFAULT '{}',
    infrastructure_dna JSONB NOT NULL DEFAULT '{}',
    behavioral_dna JSONB NOT NULL DEFAULT '{}',
    attachment_dna JSONB NOT NULL DEFAULT '{}',
    normalized_features JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL
)
```

------------------------------------------------------------------------

## 19. campaigns

``` sql
campaigns (
    id UUID PRIMARY KEY,
    campaign_key VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    confidence NUMERIC(5,4) NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    primary_intent VARCHAR(64) NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'EMERGING',
    risk_trend VARCHAR(16) NOT NULL DEFAULT 'STABLE',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL
)
```

------------------------------------------------------------------------

## 20. campaign_members

``` sql
campaign_members (
    campaign_id UUID NOT NULL REFERENCES campaigns(id),
    email_id UUID NOT NULL REFERENCES emails(id),
    similarity_score NUMERIC(5,2) NULL,
    relationship_reason JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(campaign_id, email_id)
)
```

------------------------------------------------------------------------

## 21. campaign_model_snapshots

Stores the evidence-backed state of a campaign as it evolves. This is the V1 implementation of the conceptual **Attack Campaign Model**; it is not a literal digital twin of an attacker.

``` sql
campaign_model_snapshots (
    id UUID PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES campaigns(id),
    state VARCHAR(32) NOT NULL,
    confidence NUMERIC(5,4) NULL,
    risk_score NUMERIC(5,2) NULL,
    risk_trend VARCHAR(16) NOT NULL DEFAULT 'STABLE',
    dominant_intent VARCHAR(64) NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    infrastructure_count INTEGER NOT NULL DEFAULT 0,
    evolution_event JSONB NOT NULL DEFAULT '{}',
    triggered_by_analysis_id UUID NULL REFERENCES analysis_runs(id),
    created_at TIMESTAMPTZ NOT NULL
)
```

Allowed campaign states:

``` text
EMERGING
ACTIVE
EXPANDING
MONITORING
```

Allowed risk trends:

``` text
INCREASING
STABLE
DECREASING
```

A snapshot is created when new evidence materially changes campaign state.

------------------------------------------------------------------------

## 22. campaign_evolution_events

First-class V1 timeline of observed campaign evolution. This is evidence history, not prediction.

``` sql
campaign_evolution_events (
    id UUID PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES campaigns(id),
    event_type VARCHAR(64) NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    triggering_analysis_id UUID NULL REFERENCES analysis_runs(id),
    triggering_evidence_id UUID NULL REFERENCES evidence(id),
    summary TEXT NOT NULL,
    previous_value JSONB NULL,
    new_value JSONB NULL,
    confidence NUMERIC(5,4) NULL,
    provenance JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL
)
```

Allowed event types include:

``` text
RELATED_EMAIL_OBSERVED
NEW_DOMAIN_OBSERVED
NEW_IP_OBSERVED
NEW_ASN_OBSERVED
INTENT_CHANGE_OBSERVED
PHISHDNA_VARIANT_OBSERVED
RISK_TREND_CHANGED
CAMPAIGN_STATE_CHANGED
```

Every event must reference the analyzed evidence/analysis that caused it when available. The application must never create a timeline event for activity it did not observe.

------------------------------------------------------------------------

## 23. graph_nodes

``` sql
graph_nodes (
    id UUID PRIMARY KEY,
    node_type VARCHAR(32) NOT NULL,
    reference_id UUID NULL,
    label TEXT NOT NULL,
    value TEXT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL
)
```

Node types:

``` text
EMAIL
SENDER
RECIPIENT
DOMAIN
URL
IP
ASN
ATTACHMENT_HASH
CAMPAIGN
INTENT
```

------------------------------------------------------------------------

## 24. graph_edges

``` sql
graph_edges (
    id UUID PRIMARY KEY,
    from_node UUID NOT NULL REFERENCES graph_nodes(id),
    to_node UUID NOT NULL REFERENCES graph_nodes(id),
    relation VARCHAR(64) NOT NULL,
    confidence NUMERIC(5,4) NULL,
    source VARCHAR(64) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL
)
```

Relations:

``` text
SENT_BY
TARGETS
CONTAINS_URL
RESOLVES_TO
BELONGS_TO_ASN
HAS_ATTACHMENT_HASH
HAS_INTENT
IMPERSONATES
SIMILAR_TO
PART_OF_CAMPAIGN
```

------------------------------------------------------------------------

## 25. cases

``` sql
cases (
    id UUID PRIMARY KEY,
    case_key VARCHAR(32) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    owner_id UUID REFERENCES users(id),
    created_by UUID NOT NULL REFERENCES users(id),
    summary TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ NULL
)
```

Statuses:

``` text
OPEN
INVESTIGATING
CONTAINED
CLOSED
```

------------------------------------------------------------------------

## 26. case_evidence

``` sql
case_evidence (
    case_id UUID NOT NULL REFERENCES cases(id),
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    added_by UUID NOT NULL REFERENCES users(id),
    added_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(case_id, evidence_id)
)
```

------------------------------------------------------------------------

## 27. analyst_decisions

``` sql
analyst_decisions (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id),
    analyst_id UUID NOT NULL REFERENCES users(id),
    decision VARCHAR(32) NOT NULL,
    comment TEXT NULL,
    score_at_decision NUMERIC(5,2) NULL,
    created_at TIMESTAMPTZ NOT NULL
)
```

Decisions:

``` text
CONFIRMED_PHISHING
FALSE_POSITIVE
NEEDS_INVESTIGATION
```

------------------------------------------------------------------------

## 28. recommended_actions

``` sql
recommended_actions (
    id UUID PRIMARY KEY,
    analysis_id UUID NOT NULL REFERENCES analysis_runs(id),
    priority VARCHAR(16) NOT NULL,
    action_code VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    explanation TEXT NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL
)
```

------------------------------------------------------------------------

## 29. audit_events

``` sql
audit_events (
    id UUID PRIMARY KEY,
    actor_id UUID REFERENCES users(id),
    action VARCHAR(128) NOT NULL,
    object_type VARCHAR(64) NOT NULL,
    object_id UUID NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL
)
```

Audit events should not contain raw email bodies, passwords or API
secrets.

------------------------------------------------------------------------

## 30. Local Threat Intelligence

A minimal seed table can be used:

``` sql
threat_intel_entries (
    id UUID PRIMARY KEY,
    indicator_type VARCHAR(32) NOT NULL,
    canonical_value TEXT NOT NULL,
    verdict VARCHAR(32) NOT NULL,
    source VARCHAR(64) NOT NULL,
    confidence NUMERIC(5,4) NULL,
    notes TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(indicator_type, canonical_value, source)
)
```

This guarantees a useful demo without external APIs.

------------------------------------------------------------------------

## 31. Important Indexes

Create indexes on:

``` text
users.email
emails.from_address
emails.from_domain
emails.message_id
indicators.indicator_type + indicators.canonical_value
received_hops.ip_address
attachments.sha256
campaign_members.email_id
campaign_members.campaign_id
graph_edges.from_node
graph_edges.to_node
cases.status
risk_scores.band
risk_scores.score
audit_events.created_at
```

------------------------------------------------------------------------

## 32. Data Integrity Rules

1.  Every analysis references exactly one evidence record.
2.  Every evidence record has a SHA-256 hash.
3.  Evidence cannot be mutated through normal application APIs.
4.  Analyst decisions are append-only.
5.  Audit events are append-only.
6.  Graph edges require valid source and target nodes.
7.  Enrichment results retain provider provenance.
8.  LLM analysis retains provider/model/prompt version.
9.  Deleted evidence must not silently leave orphaned forensic
    references; retention workflow must define behavior.
10. Raw evidence storage is never exposed directly as a public URL.
