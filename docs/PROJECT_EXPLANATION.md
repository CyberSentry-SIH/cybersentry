# CyberSentry V1 - Technical Architecture & Implementation Report

**Target:** Smart India Hackathon (PS 26106)  
**Project:** CyberSentry V1 - AI-Powered Email Forensic and Campaign Intelligence Platform  
**Version:** 1.0.0  

---

## 1. What Was Built

CyberSentry V1 is an analyst-side **forensic triage and campaign intelligence platform** designed for SOC analysts and security administrators. It processes suspicious `.eml` files, preserves evidence with SHA-256 digests and custody hash chains, calculates transparent 0–100 risk scores, extracts multi-dimensional **PhishDNA** fingerprints, correlates related messages into evidence-backed attack campaigns, generates interactive Attack Intent Graphs, provides "What Changed?" side-by-side differential analysis, and exports forensic PDF/JSON reports.

### Key Capabilities Built:
1. **Secure `.eml` Intake & Evidence Integrity**:
   - RFC 5322 and MIME safe parsing (extracting headers, received route hops, SPF/DKIM/DMARC, URLs, and attachments without executing active code).
   - SHA-256 byte hashing and an immutable, append-only custody event hash chain (`INGESTED`, `PARSED`, `ANALYZED`, `EXPORTED`, `VIEWED`, `DECISION_RECORDED`).

2. **Deterministic Forensic Engines**:
   - **Header & Auth Engine**: Display-name spoofing detection, From vs Reply-To mismatches, Received hops trust chain (`TRUSTED`, `OBSERVED`, `UNTRUSTED`), and SPF/DKIM/DMARC alignment representation.
   - **URL & Domain Engine**: Homoglyphs / typosquatting detection (e.g. `paypa1`, `micr0soft`), Punycode IDN homograph checks, direct IP URL detection, and high-abuse TLD flagging.
   - **Intent Engine**: Classifies semantic attack intent (Credential harvesting, Payment/Wire fraud, Executive BEC impersonation, MFA manipulation, Account verification, Benign).
   - **PhishDNA Engine**: Generates a 7-vector fingerprint across Header DNA, Identity/Auth DNA, Content DNA, URL DNA, Infrastructure DNA, Behavioral DNA, and Attachment DNA.
   - **Risk Fusion Engine**: Calculates an explainable 0–100 score mapped to severity bands (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with positive and negative signal contributions and actionable defensive recommendations.

3. **Attack Campaign Model & Early Warning**:
   - Automated correlation of polymorphic variants using PhishDNA similarity, shared infrastructure IPs, landing domains, and intent matching.
   - Campaign state machine (`EMERGING`, `ACTIVE`, `EXPANDING`, `MONITORING`) and risk trends (`INCREASING`, `STABLE`, `DECREASING`).
   - Campaign Evolution Timeline tracking timestamped, evidence-linked milestones (e.g., `RELATED_EMAIL_OBSERVED`, `NEW_DOMAIN_OBSERVED`, `CAMPAIGN_STATE_CHANGED`).

4. **Interactive Attack Intent Graph**:
   - Interactive visual network displaying relationships between `EMAIL`, `SENDER`, `RECIPIENT`, `DOMAIN`, `URL`, `IP`, `ASN`, `CAMPAIGN`, and `INTENT` nodes.

5. **"What Changed?" Email Diff Comparison**:
   - Side-by-side differential breakdown of two email variants highlighting changes in sender, Reply-To, landing domains, URLs, infrastructure, and PhishDNA similarity.

6. **Hunter Mode**:
   - Multi-indicator query engine across senders, domains, IPs, URLs, attachment hashes, campaigns, and risk bands.

7. **Forensic Reporting & Case Management**:
   - Incident cases with evidence attachments and immutable analyst dispositions (`CONFIRMED_PHISHING`, `FALSE_POSITIVE`, `NEEDS_INVESTIGATION`).
   - Forensic Report generation in JSON and formatted PDF via ReportLab.

8. **Enterprise SOC Dark UI**:
   - Next.js App Router with Tailwind CSS matching dark SOC design tokens (`#0A0D12`, `#11161D`, `#171D26`, `#4DA3FF`, etc.), live pipeline stepper, and responsive navigation.

---

## 2. Why It Was Built (Design Decisions & Problem Solved)

Traditional anti-phishing tools only answer:
- *Is this sender domain known?*
- *Did SPF/DKIM pass?*
- *Is this URL on a blacklist?*

Attackers easily bypass these with lookalike domains, freshly registered infrastructure, or legitimate relay services. Furthermore, when external intelligence has no prior record for a domain, standard tools erroneously treat "unknown" as "safe."

**CyberSentry solves this by:**
1. **Treating Unknown Reputation as Unknown, Not Safe**: Unverified infrastructure combined with hostile heuristic signals appropriately raises the risk score.
2. **Focusing on Evidence & Explainability**: Every point of the 0–100 score is linked directly to a verifiable technical finding.
3. **Detecting the Campaign, Not Just the Email**: Attackers frequently alter sender names or text, but their underlying infrastructure, intent, and PhishDNA remain correlated.
4. **Offline Resilience**: Operates deterministically with zero dependence on external SaaS or paid APIs. If configured, external LLMs (Gemini) enhance semantic analysis without becoming a single point of failure.

---

## 3. What Changes & Files Were Created

### Architecture Overview:
```
CyberSentry/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routers (auth, evidence, analysis, campaigns, graph, cases, hunter, reports, admin, health)
│   │   ├── core/         # Config, Database (Postgres + SQLite fallback), Security (bcrypt + JWT)
│   │   ├── engines/      # Pure forensic engines (Header, URL, Intent, PhishDNA, Risk, Campaign)
│   │   ├── models/       # 30 SQLAlchemy entities matching 05_BACKEND_SCHEMA.md
│   │   ├── providers/    # Model-agnostic AI provider adapter (Google Gemini)
│   │   ├── schemas/      # Pydantic request/response contracts
│   │   ├── services/     # Evidence custody, Parser, Detection, Graph, Campaign, Case, Report services
│   │   ├── main.py       # FastAPI application entrypoint
│   │   └── seed.py       # Initial seed script (users, threat intel, synthetic dataset)
│   ├── tests/            # Pytest test suite (11 unit/integration tests)
│   ├── requirements.txt  # Python dependencies
│   └── Dockerfile        # Python 3.13 container
│
├── frontend/
│   ├── app/              # Next.js App Router pages (Dashboard, Login, Analyze, Analysis Detail, Campaigns, Compare, Hunter, Cases, Reports, Admin)
│   ├── components/       # Layout (AppLayout), Graph (AttackIntentGraph), Analysis panels
│   ├── lib/              # API client wrapper
│   ├── types/            # TypeScript interfaces
│   ├── package.json      # Node.js dependencies (Next.js 14, React 18, Lucide, Tailwind)
│   └── Dockerfile        # Node 20 container
│
├── data/
│   ├── synthetic/        # 5 realistic synthetic .eml samples (PayPal phish, variant, BEC wire fraud, M365 MFA phish, benign invoice)
│   └── threat-intel/     # Seed offline threat intelligence JSON
│
├── .env                  # Configured environment variables
├── .env.example          # Template environment file
├── docker-compose.yml    # Multi-container orchestration (Postgres, Backend, Frontend)
├── README.md             # Complete user guide and run manual
└── PROJECT_EXPLANATION.md # Detailed technical architecture & changes documentation
```

---

## 4. Verification & Testing

- **Backend Test Suite**: Verified with `pytest backend/tests/ -v` (11 unit & integration tests passing 100%).
- **Frontend Production Build**: Verified with `npm run build` (All 12 Next.js routes compiled and typed with 0 errors).
- **Synthetic Sample Pipeline**: All 5 sample emails successfully parsed, hashed into custody chains, scored, and correlated into campaign clusters.
