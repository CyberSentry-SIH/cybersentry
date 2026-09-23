# CyberSentry — Future Scope

**Version:** 1.0
**Status:** Post-V1 roadmap
**Applies to:** CyberSentry V1 specification set

---

## 1. Purpose

This document defines capabilities intentionally deferred until after V1. These features represent the long-term evolution of CyberSentry and must **not** be treated as implemented V1 behavior.

The V1 product is an analyst-side `.eml` forensic and campaign-intelligence platform. Future versions can extend the same analysis engine toward mailbox ingestion, richer context, dynamic analysis, proactive protection and enterprise integrations.

### V1 boundary

V1 does **not** include:

- pre-delivery email interception
- continuous organization-wide mailbox monitoring
- Gmail/Microsoft Graph ingestion
- mail gateway/MTA integration
- OCR/image-text detection
- QR phishing detection
- visual webpage analysis
- dynamic URL/browser sandboxing
- dynamic attachment detonation
- automatic containment/remediation
- employee surveillance or invasive victim profiling
- deterministic next-attack prediction
- exact attacker attribution/location

---

## 2. V1.1 — Context and Intelligence Improvements

These are the nearest-term improvements after the hackathon prototype.

### 2.1 Relationship-Aware Sender/Recipient Context

Build an organizational communication context layer using authorized historical email metadata to determine whether a sender-recipient relationship is expected, unusual, or newly observed.

**Guardrails:**
- use only authorized organizational data
- avoid invasive employee profiling
- provide explainable evidence
- allow administrators to configure retention and scope

### 2.2 Improved Campaign Similarity

Improve PhishDNA weighting and campaign clustering using larger validated datasets and analyst feedback.

Potential methods:
- learned similarity weights
- calibrated thresholds
- clustering evaluation
- hard-negative testing

### 2.3 Campaign Evolution Analytics

Extend the V1 timeline into richer historical analytics:

- infrastructure churn
- sender/domain rotation
- intent transitions
- variant frequency
- campaign growth rate
- confidence/risk trend visualization

This remains observation-based; forecasting requires separate validation.

### 2.4 Periodic URL Re-Scanning / At-Click Verification

Re-check suspicious URLs after initial email analysis to address time-delayed phishing where a benign URL later changes behavior.

Possible deployment modes:
- scheduled rescans
- analyst-triggered rescans
- mail-client/gateway at-click verification

All active retrieval must occur through an isolated/safe analysis service.

### 2.5 Expanded Threat-Intelligence Connectors

Add optional connectors for additional reputation, passive DNS, RDAP, malware and infrastructure sources.

Provider failures must remain non-fatal. Local intelligence remains the fallback.

### 2.6 Analyst Feedback Analytics

Use stored analyst dispositions to measure:

- false-positive patterns
- recurring detection weaknesses
- analyst agreement
- campaign-clustering quality

Feedback should inform controlled model updates rather than automatic retraining.

---

## 3. V1.2 — Organizational Baseline and Prioritization

### 3.1 Communication Baseline

Create an authorized baseline of normal organizational communication patterns:

- expected sender domains
- common sender-recipient relationships
- normal message frequency
- common attachment types
- normal business URL/domain patterns
- normal authentication patterns

The baseline should be organization-specific and privacy-controlled.

### 3.2 Business-Impact Prioritization

Introduce optional business context supplied by administrators, such as:

- asset criticality
- department criticality
- role criticality
- campaign impact

Do not create covert behavioral or personality scores for employees.

### 3.3 Validated Campaign Forecasting

Only after sufficient historical campaign data exists, evaluate whether campaign evolution can support useful probabilistic forecasting.

Any forecasting must:

- be experimentally validated
- expose uncertainty
- distinguish prediction from observation
- never claim certainty about an attacker's next action

---

## 4. V2 — Proactive Mailbox and Gateway Protection

### 4.1 Gmail API Integration

Allow authorized ingestion of email metadata/content for analysis using the same core pipeline.

### 4.2 Microsoft Graph Integration

Support authorized Microsoft 365 mail analysis.

### 4.3 Mail Gateway / MTA Integration

Expose CyberSentry as a decision service for enterprise mail gateways or MTAs.

The same analysis engine can then support pre-delivery or near-real-time workflows.

### 4.4 Automated Containment

After strong validation and administrator approval, integrate with mail systems to perform actions such as:

- quarantine
- message removal
- domain blocking
- IOC propagation
- incident creation

V1 intentionally provides recommendations only.

### 4.5 SIEM/SOAR Integration

Add enterprise integrations for:

- alert forwarding
- incident creation
- IOC sharing
- automated playbooks
- case synchronization

---

## 5. V2 — Advanced Content and Dynamic Analysis

### 5.1 OCR / Image-Based Phishing

Analyze phishing content embedded in images using OCR and image classifiers.

Potential capabilities:
- text extraction
- logo/brand similarity
- fake login-page detection
- visual deception analysis

### 5.2 QR Phishing Detection

Detect QR codes in emails/images and safely analyze their destination without exposing the analyst or user to the live URL.

### 5.3 Visual Webpage Analysis

In an isolated environment, render suspicious pages and analyze:

- page structure
- login forms
- brand impersonation
- visual similarity
- suspicious JavaScript behavior

### 5.4 Dynamic Attachment Sandbox

Execute suspicious attachments only inside a strongly isolated analysis environment and collect:

- process behavior
- file changes
- network connections
- persistence attempts
- dropped artifacts

Static V1 analysis remains the safe fallback.

### 5.5 Safe URL Detonation

Analyze redirects and final destinations in an isolated browser/sandbox instead of directly opening links in the application environment.

---

## 6. V2+ — Advanced AI

### 6.1 Local LLM Support

Provide local/self-hosted semantic analysis for organizations that cannot send email content to external AI providers.

### 6.2 Multilingual and Regional-Language Analysis

Expand semantic intent detection to Indian and other multilingual phishing patterns, including transliterated/romanized language.

### 6.3 Multimodal Threat Analysis

Combine text, HTML, images, QR codes and rendered-page signals into a unified analysis pipeline.

### 6.4 Controlled Model Improvement

Use validated analyst feedback and curated datasets for periodic model evaluation/retraining.

No autonomous production retraining without governance, validation and rollback.

---

## 7. V3 — Advanced Campaign Intelligence

### 7.1 Attack Campaign Twin / Persistent Campaign Representation

If future data sources justify it, evolve the V1 Attack Campaign Model into a richer persistent representation containing longer-term campaign history, infrastructure churn, observed variants and defensive actions.

This should still represent **observed evidence**, not an omniscient model of an attacker.

### 7.2 Cross-Organization Campaign Intelligence

With appropriate legal, privacy and sharing controls, correlate anonymized campaign indicators across participating organizations.

### 7.3 Advanced Campaign Forecasting

Research probabilistic forecasting of campaign evolution using validated historical datasets. Forecasts must include confidence/uncertainty and must never be presented as guaranteed future events.

### 7.4 Threat Actor Attribution Support

Potentially correlate infrastructure and campaign evidence with authorized external intelligence to support **confidence-based attribution hypotheses**.

This must never claim that software alone proves the identity of a person.

---

## 8. Future Security and Compliance Work

Future enterprise versions may add:

- centralized policy management
- stronger key management
- enterprise SSO/OIDC
- retention/legal-hold controls
- privacy/redaction policies
- tenant isolation
- signed evidence packages
- configurable audit exports
- organization-specific compliance mappings

These should be implemented only when the deployment context requires them.

---

## 9. Future Scope Prioritization

| Priority | Capability | Why it matters |
|---|---|---|
| P0 | Gmail/Graph/mail-gateway ingestion | Moves analysis toward proactive protection |
| P0 | URL re-scan / at-click verification | Addresses time-delayed phishing |
| P0 | Improved campaign similarity | Strengthens core differentiator |
| P0 | Communication baseline | Adds contextual anomaly detection |
| P1 | OCR/image analysis | Covers image-based phishing |
| P1 | QR phishing | Covers QR-based credential lures |
| P1 | Dynamic attachment sandbox | Detects behavior missed by static analysis |
| P1 | Safe webpage analysis | Detects visual/web execution techniques |
| P1 | Local LLM | Improves privacy for sensitive deployments |
| P1 | Multilingual analysis | Improves Indian institutional applicability |
| P2 | SIEM/SOAR | Enterprise response integration |
| P2 | Automated containment | Reduces response time after validation |
| P2 | Campaign forecasting | Adds validated predictive intelligence |
| P3 | Cross-organization intelligence | Enables broader campaign visibility |
| P3 | Attribution support | Adds evidence-based threat-intelligence context |

---

## 10. Rule for Future Development

Future features must extend the core CyberSentry principle:

> **Evidence → Analysis → Correlation → Intelligence → Defensible Action**

A future feature should not be added merely because it is technically impressive. It should improve detection, investigation, campaign understanding, response, privacy, or evidence quality without weakening the platform's explainability and defensibility.
