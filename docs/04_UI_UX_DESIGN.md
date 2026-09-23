# CyberSentry V1 --- UI/UX Design Specification

**Version:** 1.0\
**Design direction:** Enterprise SOC / forensic workspace\
**Style:** Dark, minimal, professional, technical\
**Avoid:** Cyberpunk, excessive neon, decorative hacker aesthetics

------------------------------------------------------------------------

## 1. UX Principles

1.  **Evidence before opinion.**
2.  **Explain every important score.**
3.  **Never use color alone to communicate severity.**
4.  **Keep analyst workflows dense but readable.**
5.  **Make uncertainty visible.**
6.  **Never imply exact attribution from network metadata.**
7.  **Make the investigation path obvious.**
8.  **Minimize clicks between detection and evidence.**

------------------------------------------------------------------------

## 2. Theme

Dark-only V1.

Visual language:

-   near-black application background
-   slightly lighter panels
-   subtle borders
-   restrained accent color
-   high-contrast text
-   monospace typography for technical values
-   compact enterprise controls

The interface should look closer to a professional SOC console than a
gaming/cyberpunk dashboard.

------------------------------------------------------------------------

## 3. Color Tokens

Use CSS variables. Components must not hardcode colors.

  Role               Token                Value
  ------------------ -------------------- -----------
  Page background    `--bg-base`          `#0A0D12`
  Surface            `--bg-surface`       `#11161D`
  Elevated surface   `--bg-elevated`      `#171D26`
  Primary text       `--text-primary`     `#E7ECF2`
  Secondary text     `--text-secondary`   `#AAB4C2`
  Muted text         `--text-muted`       `#707B8A`
  Border             `--border-default`   `#27303B`
  Primary accent     `--accent-primary`   `#4DA3FF`
  Success            `--state-success`    `#35C98A`
  Warning            `--state-warning`    `#E6B84A`
  Error/Critical     `--state-error`      `#E05D6F`
  Info               `--state-info`       `#5BB7D9`

Severity should also use:

-   icon
-   label
-   numeric score
-   text

not color alone.

------------------------------------------------------------------------

## 4. Typography

  Role               Font
  ------------------ --------------------------------------
  UI                 Geist Sans / Inter fallback
  Technical values   Geist Mono / JetBrains Mono fallback
  Headings           UI font, semibold
  Body               UI font, regular

Technical values should use monospace:

-   hashes
-   IPs
-   domains
-   URLs
-   Message-ID
-   evidence IDs
-   timestamps where precision matters

------------------------------------------------------------------------

## 5. Spacing

Use a consistent 4px base scale.

Preferred:

-   `4px`
-   `8px`
-   `12px`
-   `16px`
-   `20px`
-   `24px`
-   `32px`

Avoid arbitrary spacing values.

------------------------------------------------------------------------

## 6. Border Radius

  Context         Radius
  --------------- --------------
  Inputs/badges   `rounded-md`
  Cards           `rounded-lg`
  Main panels     `rounded-lg`
  Modals          `rounded-xl`

Avoid excessive rounded/pill UI.

------------------------------------------------------------------------

## 7. Component Library

Use:

-   Tailwind CSS
-   shadcn/ui
-   Lucide React

Use shadcn primitives for:

-   Button
-   Card
-   Badge
-   Dialog
-   Tabs
-   Table
-   Dropdown
-   Tooltip
-   Sheet
-   Alert
-   Progress
-   Skeleton
-   Input
-   Select

Do not create duplicate UI primitives when shadcn already provides the
behavior.

------------------------------------------------------------------------

## 8. Global Layout

``` text
┌─────────────────────────────────────────────────────────────┐
│ Top Bar: CyberSentry | Search | Notifications | User       │
├──────────────┬──────────────────────────────────────────────┤
│ Sidebar      │                                                │
│              │ Main Content                                   │
│ Dashboard    │                                                │
│ Analyze      │                                                │
│ Emails       │                                                │
│ Campaigns    │                                                │
│ Hunter       │                                                │
│ Cases        │                                                │
│ Reports      │                                                │
│              │                                                │
│ Admin*       │                                                │
└──────────────┴──────────────────────────────────────────────┘
```

`Admin` appears only to administrators.

------------------------------------------------------------------------

## 9. Dashboard

### Top KPI row

-   Critical findings
-   High findings
-   Open cases
-   Active campaigns

### Recent analysis table

Columns:

-   Risk
-   Subject
-   Sender
-   Intent
-   Campaign
-   Analyzed
-   Status

### Quick action

Large primary card:

> **Analyze a suspicious email**

Supporting text:

> Upload an `.eml` file for forensic analysis.

------------------------------------------------------------------------

## 10. Upload Screen

Central drop zone.

``` text
┌─────────────────────────────────────────┐
│                                         │
│       Upload suspicious .EML            │
│                                         │
│       Drag & drop here                  │
│       or Browse files                   │
│                                         │
│       Max size: configured limit        │
│                                         │
└─────────────────────────────────────────┘
```

After upload:

``` text
email.eml
2.4 MB
SHA-256: calculating...
[ Analyze ]
```

------------------------------------------------------------------------

## 11. Analysis Overview

The overview must communicate the decision in under five seconds.

``` text
┌────────────────────────────────────────────┐
│ CRITICAL                                   │
│ 87 / 100                                   │
│ Credential Harvesting + Impersonation      │
└────────────────────────────────────────────┘

Why flagged
──────────────────────────────────────────────
+18 Lookalike domain
+16 Credential harvesting intent
+14 Reply-To mismatch
...

Evidence
──────────────────────────────────────────────
Sender | Auth | URL | Infrastructure | Campaign
```

------------------------------------------------------------------------

## 12. Risk Score Component

Use:

-   large numeric score
-   severity label
-   compact meter
-   explanation list

Do not use a huge decorative gauge.

Example:

``` text
87
CRITICAL

█████████████████░░░

Confidence 89%
```

The score is not displayed as "certainty".

Use:

> Risk score

not:

> Probability attacker is guilty.

------------------------------------------------------------------------

## 13. Evidence Panel

Each finding should have:

``` text
[ICON] Lookalike sender domain
      +18 risk
      evidence: From header
      confidence: 96%
      source: parser
```

Expandable evidence details:

-   raw field
-   normalized field
-   explanation
-   provenance

Sensitive/raw content should be collapsed by default.

------------------------------------------------------------------------

## 14. Header Timeline

Use a vertical timeline.

``` text
12:03:21  gateway.company.com
             ↓
12:03:22  relay.example.net
             ↓
12:03:25  observed IP
```

Each node displays:

-   timestamp
-   hostname
-   IP
-   trust state
-   ASN/ISP
-   confidence

Legend:

-   Trusted
-   Observed
-   Untrusted
-   Unknown

------------------------------------------------------------------------

## 15. Authentication Cards

Three cards:

``` text
SPF
PASS

DKIM
PASS

DMARC
PASS
```

Under cards:

> Authentication passed. This is one signal and does not by itself
> establish legitimacy.

If alignment is unknown, show:

> Alignment unavailable

not a false failure.

------------------------------------------------------------------------

## 16. URL Table

Columns:

-   URL
-   Domain
-   Reputation
-   Lookalike
-   Punycode
-   Risk
-   Confidence

Status examples:

`KNOWN MALICIOUS`, `KNOWN BENIGN`, `UNKNOWN`, `UNAVAILABLE`

Unknown should have a neutral visual style plus an explanatory warning
when other anomalies exist.

------------------------------------------------------------------------

## 17. Infrastructure Panel

Title:

> Sending Infrastructure

Fields:

-   Observed IP
-   Trust level
-   ASN
-   ISP/Organization
-   Country/Region
-   Reputation
-   Provider
-   Confidence

Important note:

> **Infrastructure location is not attacker location.**

Do not show a dramatic "attacker map".

A compact regional/network visualization is acceptable, but the evidence
table is primary.

------------------------------------------------------------------------

## 18. Attack Campaign Model Panel

The campaign page should visually communicate that CyberSentry maintains an evidence-backed model of the suspected campaign, not a literal model of the attacker.

Show:

-   campaign state: Emerging / Active / Expanding / Monitoring
-   confidence
-   risk trend
-   first seen / last seen
-   related email count
-   infrastructure count
-   dominant intent
-   evolution events

Use copy such as:

> Campaign expanding — 2 new related domains observed.

Never label this `Attacker Digital Twin`, `Attacker Identity`, or `Attacker Location`.

Primary campaign headline for the demo:

> **The attacker can change the email. CyberSentry detects the campaign.**

------------------------------------------------------------------------

## 19. Campaign Evolution Timeline

The Campaign page must include a chronological evidence-backed timeline below or beside the Attack Campaign Model summary.

Each event displays:

- timestamp
- event type
- concise change description
- affected entity (email/domain/IP/ASN/intent/campaign state)
- confidence where applicable
- link to supporting analysis/evidence

Example:

```text
10:42  EMAIL_VARIANT_OBSERVED
       New email shares 86% PhishDNA similarity
       Evidence: AN-0042

10:47  NEW_DOMAIN_OBSERVED
       secure-example.net linked to campaign
       Evidence: AN-0043

10:49  CAMPAIGN_STATE_CHANGED
       ACTIVE → EXPANDING
       Evidence: AN-0043
```

The timeline must never visually imply prediction. Use labels such as `Observed`, `Detected`, `State changed`, and `New related infrastructure`; never `Predicted attack`.

---

## 20. PhishDNA Panel

Six cards:

-   Header DNA
-   Identity/Auth DNA
-   Content DNA
-   URL DNA
-   Infrastructure DNA
-   Behavioral DNA

Attachment DNA appears when attachments exist.

Each card shows:

-   feature count
-   notable characteristics
-   normalized fingerprint ID

------------------------------------------------------------------------

## 21. What Changed? UI

Two-column comparison.

``` text
EMAIL A                  EMAIL B
────────                 ────────
sender-a.com             sender-b.com
login-a.com              secure-b.com

             ↓

         WHAT CHANGED?

Sender          DIFFERENT
URL             DIFFERENT
Intent          SAME
ASN             SAME
HTML structure  SIMILAR

PhishDNA similarity       87%
Campaign likelihood       92%
```

Use labels:

-   SAME
-   DIFFERENT
-   SIMILAR
-   NEW
-   REMOVED

------------------------------------------------------------------------

## 22. Attack Intent Graph

Graph canvas should occupy most of the screen.

Left side:

filters:

-   Node type
-   Relationship
-   Confidence
-   Campaign

Right side:

selected node details.

Node colors should be subtle and token-based.

Avoid neon graph styling.

------------------------------------------------------------------------

## 23. Hunter Mode

Search-first layout.

``` text
Search indicators...
[ Search ]

Filters:
Risk | Intent | Date | Campaign

Results
────────────────────────────
EMAIL
DOMAIN
IP
URL
HASH
CAMPAIGN
```

The analyst should be able to jump directly from a result to its
investigation.

------------------------------------------------------------------------

## 24. Case Workspace

Header:

``` text
CASE CS-00042
CRITICAL
OPEN
Owner: Analyst
```

Tabs:

-   Overview
-   Evidence
-   Findings
-   Graph
-   Timeline
-   Actions
-   Report

Decision control:

``` text
[ Confirmed Phishing ]
[ False Positive ]
[ Needs Investigation ]
```

------------------------------------------------------------------------

## 25. Report UI

Before export show:

-   report scope
-   evidence hash
-   generated timestamp
-   analyst
-   included findings

Buttons:

`Export PDF`

`Export JSON`

------------------------------------------------------------------------

## 26. Admin UI

Only administrators see:

-   Users
-   Roles
-   Local intelligence
-   System configuration
-   Audit events

No admin page should expose raw passwords, secrets or LLM API keys.

------------------------------------------------------------------------

## 27. Empty States

Examples:

### No analyses

> No email analyses yet. Upload a suspicious `.eml` to begin.

### No campaign

> No related campaign detected for this email.

### No external intelligence

> External intelligence is unavailable. Local analysis is still active.

### No graph relationship

> No high-confidence relationships found.

------------------------------------------------------------------------

## 28. Error States

Errors must explain:

-   what failed
-   whether evidence was preserved
-   what the analyst can do next

Example:

> **Semantic AI unavailable**\
> Evidence and deterministic analysis completed successfully. Review the
> current findings or retry semantic analysis.

------------------------------------------------------------------------

## 29. Accessibility

-   Keyboard navigation.
-   Visible focus states.
-   Semantic headings.
-   ARIA labels for icon-only controls.
-   Color is never the only severity indicator.
-   Tables have accessible headers.
-   Tooltips must not be the only source of critical information.

------------------------------------------------------------------------

## 30. Responsive Behavior

Primary target:

-   Desktop/laptop.

Minimum supported:

-   1280px wide analyst workspace.

Tablet should remain usable for review, but the graph and forensic
tables are optimized for desktop.

------------------------------------------------------------------------

## 31. Visual Priority

Highest priority:

1.  Risk score
2.  Why flagged
3.  Sender/authentication
4.  URL/domain evidence
5.  Infrastructure
6.  PhishDNA
7.  Campaign
8.  Graph
9.  Recommended actions
10. Raw evidence

This order follows the analyst's decision-making process.
