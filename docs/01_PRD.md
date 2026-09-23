# CyberSentry V1 --- Product Requirements Document (PRD)

**Version:** 1.0\
**Status:** Locked for V1 implementation\
**Target:** Smart India Hackathon --- PS 26106\
**Primary users:** SOC Analysts and Administrators\
**Input:** `.eml` files\
**Deployment:** Docker Compose, local/on-premise friendly

------------------------------------------------------------------------

## 1. Product Definition

CyberSentry V1 is an **AI-powered email forensic and campaign
intelligence platform** that analyzes suspicious `.eml` files, preserves
evidence, explains the threat decision, fingerprints the email using
PhishDNA, correlates related messages into campaigns, reconstructs
attack intent and infrastructure relationships, and recommends defensive
actions.

### Core positioning

> **CyberSentry does not just determine whether an email is malicious.
> It analyzes its identity, intent, infrastructure and behavioral
> fingerprint, correlates it with other attacks, and reconstructs the
> campaign behind it---even when indicators have no prior reputation.**

### Important V1 boundary

V1 is an **analyst-side forensic/triage product**, not a pre-delivery
real-time email gateway.

The `.eml` upload workflow means the email has already been received. V1
therefore must not claim that it prevents user interaction before inbox
delivery.

The analysis engine is designed behind an API boundary so future
versions can integrate with Microsoft Graph, Gmail APIs, or an
enterprise mail gateway/MTA for pre-delivery detection.

------------------------------------------------------------------------

## 2. Problem

Email remains a major attack vector for phishing, business email
compromise, impersonation, financial fraud, credential theft and
malicious links.

Existing controls often answer:

-   Is this sender/domain known?
-   Did SPF/DKIM/DMARC pass?
-   Is this URL or IP known to be malicious?
-   Does this message look suspicious?

CyberSentry focuses on the next analyst question:

> **Why is this email suspicious, what evidence supports the decision,
> is it related to other attacks, and where should the defender
> intervene?**

The product therefore emphasizes evidence, explainability and
campaign-level correlation rather than a single opaque phishing score.

------------------------------------------------------------------------

## 3. Goals

1.  Analyze an uploaded `.eml` safely without executing its active
    content.
2.  Preserve the original email as evidence using SHA-256 and a
    tamper-evident hash chain.
3.  Analyze sender identity, headers, routing, SPF/DKIM/DMARC, content
    intent, URLs and infrastructure.
4.  Produce a transparent 0--100 risk score with human-readable reasons.
5.  Treat **unknown reputation as unknown, not safe**.
6.  Generate a multi-dimensional **PhishDNA** fingerprint.
7.  Detect polymorphic/obfuscated variations using normalization and
    structural similarity.
8.  Correlate multiple analyzed emails into likely campaigns.
9.  Show an **Attack Intent Graph** linking sender, impersonation,
    intent, URL, infrastructure and campaign.
10. Provide a **What Changed?** comparison between two analyzed emails.
11. Allow analysts to record Confirmed Phishing or False Positive
    feedback without automatic model retraining.
12. Provide Hunter Mode for searching analyzed indicators and
    relationships.
13. Generate forensic reports in PDF and JSON.
14. Remain usable when external APIs or the LLM are unavailable.
15. Maintain an evidence-backed **Attack Campaign Model** that represents the current state of a suspected campaign using only observed/analyzed evidence.
16. Provide campaign-level early warning by surfacing campaign growth, new infrastructure, repeated intent, and increasing risk; V1 must not claim deterministic prediction of future attacks.
17. Keep the intelligence layer **model-agnostic** so the underlying LLM/ML provider can be replaced without changing core detection, correlation, evidence, or graph behavior.

------------------------------------------------------------------------

## 4. Non-Goals / Explicitly Out of Scope

The following are NOT V1 features:

-   Pre-delivery real-time mailbox interception.
-   Live Gmail/Outlook mailbox integration.
-   QR phishing analysis.
-   OCR or image-text phishing detection.
-   Screenshot/visual webpage analysis.
-   Full browser sandbox or malware detonation.
-   Automatic execution of attachments.
-   Automatic browsing of email URLs.
-   Automatic model retraining.
-   Employee surveillance or invasive employee risk profiling.
-   Exact attacker identity attribution.
-   Exact physical attacker location.
-   Unauthorized scanning or probing.
-   Credential harvesting.
-   Blockchain evidence storage.
-   Full SIEM/SOAR integration.
-   Large distributed queue infrastructure.
-   Neo4j or another dedicated graph database.
-   Paid threat-intelligence subscriptions as a dependency.
-   Continuous organization-wide mailbox monitoring.
-   Deterministic prediction of the attacker's next action.
-   A persistent digital twin of the real attacker, victim organization, or external infrastructure.

------------------------------------------------------------------------

## 5. Target Users

### SOC Analyst

Needs fast triage, evidence, explanations, correlation and recommended
next actions.

### Administrator

Needs system configuration, user/role management and visibility into
analysis operations.

V1 has exactly two application roles:

-   `ANALYST`
-   `ADMINISTRATOR`

------------------------------------------------------------------------

## 6. Core User Flow

1.  User signs in.
2.  User uploads or drags an `.eml` file.
3.  CyberSentry validates file type/size and creates an evidence record.
4.  Original bytes are hashed with SHA-256.
5.  Evidence custody event is written to the hash chain.
6.  Email is parsed into headers, body, MIME parts, URLs, attachments
    and received hops.
7.  Header/authentication analysis runs.
8.  Content/intent analysis runs.
9.  URL/domain analysis runs without automatically browsing live links.
10. Infrastructure intelligence is derived from approved email evidence
    and optional passive lookups.
11. PhishDNA is generated.
12. Risk Fusion Engine calculates the 0--100 score.
13. Related analyzed emails are searched for campaign relationships.
14. Attack Intent Graph is generated.
15. Recommended defensive actions are produced.
16. Analyst reviews evidence and records a disposition.
17. A case can be created and exported as PDF/JSON forensic report.

------------------------------------------------------------------------

## 7. V1 Feature Requirements

### FR-01 --- Secure EML Intake

-   Accept `.eml`.
-   Support drag-and-drop and file picker.
-   Enforce configurable size limits.
-   Reject unsupported file types.
-   Never execute attachment content.
-   Generate SHA-256 of original bytes.
-   Store evidence metadata and custody event.

### FR-02 --- RFC 5322/MIME Parsing

Extract:

-   From
-   To
-   Cc
-   Reply-To
-   Return-Path
-   Subject
-   Date
-   Message-ID
-   Received headers
-   Authentication-Results
-   SPF result when present/derived
-   DKIM result when present/derived
-   DMARC result when present/derived
-   Plain-text body
-   HTML body
-   URLs
-   Attachments
-   Attachment filename/content type/size/hash

Malformed input must fail safely and produce a readable parser error.

### FR-03 --- Header and Authentication Analysis

Detect:

-   From vs Reply-To mismatch
-   Display-name/domain mismatch
-   Suspicious or contradictory Received hops
-   Timestamp anomalies
-   Message-ID inconsistencies
-   SPF result
-   DKIM result
-   DMARC result/alignment where available
-   Authentication anomalies

Authentication is **never a hard allow/deny gate**.

Example:

`SPF PASS + DKIM PASS + DMARC PASS` can still be high risk when other
evidence indicates impersonation, credential theft, lookalike domains or
malicious intent.

### FR-04 --- Semantic Intent Analysis

Classify intent into one or more categories:

-   Credential harvesting
-   Password/MFA manipulation
-   Payment redirection
-   Invoice fraud
-   Executive impersonation
-   Account verification
-   Document/download lure
-   Callback/social engineering
-   Data disclosure request
-   Malware delivery indication
-   Benign/ordinary communication

The LLM may provide semantic analysis, but the final risk decision
remains controlled by the deterministic Risk Fusion Engine.

### FR-05 --- URL and Domain Analysis

Perform:

-   URL extraction
-   Canonicalization
-   Host/domain extraction
-   Punycode detection
-   Unicode/homoglyph detection
-   Lookalike-domain comparison
-   Suspicious path/query patterns
-   Domain age/reputation when available
-   Local threat-intelligence lookup
-   Optional external reputation lookup

V1 does **not** automatically visit arbitrary email URLs.

### FR-06 --- Sending Infrastructure Intelligence

For observed IP addresses:

-   Identify candidate IPs from Received headers.
-   Establish a configurable trusted-header boundary.
-   Prefer evidence from trusted/known organizational hops.
-   Mark lower-confidence sender-supplied hops as untrusted/uncertain.
-   Enrich IP with ASN/ISP/organization and country/region where
    available.
-   Record source, timestamp and confidence.

The UI and reports must use:

> **Infrastructure location**

rather than:

> Attacker location

The system must explicitly state:

> Infrastructure location does not prove attacker location or identity.

### FR-07 --- PhishDNA

Generate normalized features across:

-   Header DNA
-   Identity/Auth DNA
-   Content/Intent DNA
-   URL/Domain DNA
-   Infrastructure DNA
-   Behavioral DNA
-   Attachment DNA

The fingerprint must be stable enough to compare different versions of a
campaign.

Normalization must account for:

-   Unicode/homoglyph substitutions
-   URL/HTML encoding
-   Excess whitespace
-   Common obfuscation
-   Case variation
-   Tracking/query parameter noise
-   Lookalike domains
-   Structural HTML similarity

### FR-08 --- Unknown ≠ Safe

Threat-intelligence state must support:

-   Known malicious
-   Known benign
-   Unknown
-   Unavailable

`Unknown` must never automatically reduce risk.

Unknown + multiple anomalous signals can increase risk or trigger
investigation.

### FR-09 --- Transparent Risk Scoring

Risk score range:

-   `0–24`: Low
-   `25–49`: Medium
-   `50–74`: High
-   `75–100`: Critical

The UI must show:

-   Overall score
-   Severity band
-   Contributing signals
-   Positive and negative contributions
-   Source/provenance where applicable
-   AI/model status
-   Analyst override/disposition

The score is a prioritization mechanism, not proof of malicious intent.

### FR-10 --- Campaign Correlation

Compare analyzed messages using:

-   PhishDNA similarity
-   Shared URL/domain
-   Shared IP/ASN
-   Shared attachment hash
-   Similar intent
-   Similar normalized content/structure
-   Similar sender identity patterns within the analyzed CyberSentry evidence set
-   Temporal proximity

Store relationship confidence.

### FR-11 --- What Changed?

Given two analyzed emails, show:

-   Changed sender
-   Changed Reply-To
-   Changed domain
-   Changed URL
-   Changed infrastructure
-   Shared infrastructure
-   Shared intent
-   Similar HTML/content structure
-   PhishDNA similarity
-   Campaign likelihood

### FR-12 --- Attack Intent Graph

V1 graph node types:

-   Email
-   Sender
-   Recipient
-   Domain
-   URL
-   IP
-   ASN
-   Attachment Hash
-   Campaign
-   Intent

V1 relationship examples:

-   `SENT_BY`
-   `TARGETS`
-   `REPLIES_TO`
-   `CONTAINS_URL`
-   `RESOLVES_TO`
-   `BELONGS_TO_ASN`
-   `HAS_ATTACHMENT_HASH`
-   `SIMILAR_TO`
-   `PART_OF_CAMPAIGN`
-   `HAS_INTENT`
-   `IMPERSONATES`

Every meaningful relationship should retain a confidence/source where
applicable.

### FR-13 --- Hunter Mode

Analysts can search across analyzed data by:

-   Sender
-   Recipient
-   Domain
-   URL
-   IP
-   ASN
-   Attachment hash
-   Campaign
-   Risk band
-   Intent

Results should expose related cases and campaign relationships.

### FR-14 --- Attack Campaign Model

The campaign model is a derived, evidence-backed representation of a suspected phishing campaign. It is not a claim of attacker identity and is not a full digital twin of the real-world adversary.

The model summarizes:

-   campaign state
-   first seen / last seen
-   observed emails
-   shared PhishDNA characteristics
-   shared indicators and infrastructure
-   dominant intent
-   risk trend
-   confidence
-   campaign evolution events

Every state update must be traceable to analyzed evidence.

### FR-15 --- Campaign Early Warning

V1 provides a **risk-based early-warning indicator**, not a guaranteed forecast. It may flag:

-   campaign expansion
-   new domains/IPs/ASNs associated with an existing campaign
-   repeated or escalating attack intent
-   increasing campaign confidence or risk
-   newly observed variants with similar PhishDNA

The UI must use language such as `Campaign expanding`, `New related infrastructure observed`, or `Monitoring recommended`. It must not say `next attack will occur`.

The campaign model must expose a **Campaign Evolution Timeline** containing timestamped, evidence-linked events such as new related email variants, newly observed domains/IPs/ASNs, intent changes, PhishDNA similarity changes, campaign-state changes, and risk-trend changes.

### FR-16 --- Analyst Feedback

Analyst dispositions:

-   Confirmed Phishing
-   False Positive
-   Needs Investigation

Store:

-   analyst
-   timestamp
-   previous score
-   final disposition
-   optional comment

V1 does not automatically retrain models.

### FR-17 --- Recommended Actions

Recommendations must be defensive and evidence-linked, such as:

-   Quarantine message
-   Block or review suspicious domain/URL
-   Search for related messages
-   Verify payment instructions through a trusted channel
-   Reset credentials if compromise is suspected
-   Enforce MFA review
-   Notify security administrator
-   Open/raise incident case

Recommendations must never claim that the system has actually blocked or
remediated something unless an integration has performed that action.

### FR-18 --- Forensic Reports

Export:

-   PDF
-   JSON

Report sections:

1.  Case summary
2.  Evidence identity
3.  SHA-256
4.  Custody history
5.  Email metadata
6.  Header/route analysis
7.  SPF/DKIM/DMARC
8.  Content/intent findings
9.  URL/domain findings
10. Infrastructure intelligence
11. PhishDNA
12. Risk score and reasons
13. Campaign relationships
14. Attack Campaign Model state/evolution
15. Attack Intent Graph summary
15. Recommended actions
17. Analyst disposition
18. Limitations and confidence notes

------------------------------------------------------------------------

## 8. Security and Privacy Requirements

-   Demo data should be synthetic.
-   Raw email content must not be sent to third-party AI services by
    default.
-   If an external LLM is configured, minimize/redact data before
    transmission where possible.
-   LLM calls must be optional.
-   Raw evidence must never be rendered as executable HTML.
-   Attachments must never execute in the primary application.
-   User authentication and role checks apply to all protected
    operations.
-   Audit sensitive operations.
-   Use least privilege.
-   Support configurable retention.
-   Preserve provenance for external intelligence.
-   Do not expose exact personal information unnecessarily.
-   Never present infrastructure intelligence as identity attribution.

------------------------------------------------------------------------

## 9. Evaluation and Dataset Strategy

V1 must include a small reproducible synthetic/public evaluation set rather than invented accuracy claims.

Recommended categories:

-   known phishing
-   BEC/impersonation
-   unknown/novel phishing
-   AI-generated phishing
-   lookalike domains
-   URL obfuscation/polymorphic variants
-   legitimate business email
-   hard negatives

Record actual precision, recall, F1 and false-positive rate where the dataset size supports them. For campaign correlation, report the number of correctly linked/unlinked variants and explain the test construction. Do not put benchmark numbers in the presentation until they have been measured.

## 10. Success Criteria

A V1 demo is successful when:

1.  An analyst can sign in and upload a synthetic `.eml`.
2.  Original evidence receives a SHA-256 hash and custody record.
3.  Headers, MIME parts, URLs and attachments are parsed safely.
4.  SPF/DKIM/DMARC and header anomalies are visible.
5.  A transparent risk score is generated.
6.  The score remains useful even without the LLM/external APIs.
7.  A suspicious email receives a PhishDNA fingerprint.
8.  Two related but visually/textually different emails can be
    correlated.
9.  The What Changed? view explains the relationship.
10. The Attack Campaign Model shows campaign state/evolution and at least one evidence-backed early-warning event when the demo dataset supports it.
11. The Attack Intent Graph shows the investigation path.
12. The analyst can record a disposition.
13. A PDF and JSON forensic report can be exported.
14. The demo never claims exact attacker identity/location, deterministic next-attack prediction, or pre-delivery interception.

------------------------------------------------------------------------

## 11. V1 Differentiator

The differentiator is not:

> "We use AI to detect phishing."

The differentiator is:

> **Evidence-backed investigation and campaign correlation.**

CyberSentry converts:

`Email → Evidence → Signals → PhishDNA → Risk → Infrastructure → Campaign → Intent → Action`

The product-level message is:

> **The attacker can change the email. CyberSentry detects the campaign.**

The Attack Campaign Model is the evidence-backed representation that makes this campaign-level investigation understandable. It summarizes observed campaign state and evolution; it is not a literal twin of the attacker and does not claim deterministic prediction.

This makes the product an investigation assistant rather than another
reputation lookup dashboard.

------------------------------------------------------------------------

## 12. Future Roadmap

The complete post-V1 roadmap is maintained in **`07_FUTURE_SCOPE.md`**.

V1 implementation must not begin work on roadmap items unless the V1 scope is formally re-approved. The future roadmap includes mailbox/gateway integration, richer contextual baselines, image/OCR/QR analysis, dynamic sandboxing, expanded intelligence connectors, local/multilingual AI, validated forecasting, and automated response integrations.

------------------------------------------------------------------------

## 13. V1/Future Boundary

All V1 implementation decisions must use this document together with `07_FUTURE_SCOPE.md`. A feature is V1 only when it appears in the V1 requirements and implementation plan. Roadmap capabilities are architectural direction, not implemented behavior.

## 14. Product Constraints

-   Six-person team.
-   Approximately one effective hackathon day / 14 focused hours.
-   AI performs most implementation; team reviews.
-   Avoid infrastructure that does not directly improve the demo.
-   PostgreSQL is the only database.
-   Docker Compose is the target deployment.
