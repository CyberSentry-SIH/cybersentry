"""
CyberSentry V2 - Heuristic Risk Prioritization Configuration & Signal Weights
Centralized registry of forensic findings, risk weights, and category multipliers.
Every point contribution maps to verifiable forensic evidence.
Note: This is an explainable operational triage prioritization metric, not a statistically calibrated probability of malice.
"""

RISK_WEIGHTS = {
    # 1. Identity & Brand Spoofing
    "DISPLAY_NAME_SPOOFING": {
        "weight": 28.0,
        "severity": "CRITICAL",
        "rationale": "Direct deception where sender name impersonates a trusted brand while sending from an unauthorized domain."
    },
    "EXECUTIVE_IMPERSONATION_LURE": {
        "weight": 16.0,
        "severity": "HIGH",
        "rationale": "Display name claims executive or authority role (CEO, CFO, HR Admin) to exploit social hierarchy compliance."
    },
    "REPLY_TO_DOMAIN_MISMATCH": {
        "weight": 22.0,
        "severity": "HIGH",
        "rationale": "Replies diverted away from visible sender domain to an external/unverified inbox, indicative of credential/data harvesting."
    },
    "RETURN_PATH_MISMATCH": {
        "weight": 8.0,
        "severity": "LOW",
        "rationale": "Envelope Return-Path domain does not align with header From domain."
    },
    "MESSAGE_ID_DOMAIN_MISMATCH": {
        "weight": 5.0,
        "severity": "LOW",
        "rationale": "Message-ID domain does not align with sender domain."
    },

    # 2. Domain & URL Homoglyphs
    "LOOKALIKE_HOMOGLYPH_DOMAIN": {
        "weight": 32.0,
        "severity": "CRITICAL",
        "rationale": "URL hostname is a character-level confusable, typo-squatted, or Unicode-substituted lookalike of a protected organization."
    },
    "PUNYCODE_HOMOGRAPH_DETECTED": {
        "weight": 24.0,
        "severity": "HIGH",
        "rationale": "Hostname utilizes Internationalized Domain Name (Punycode xn--) encoding to disguise Cyrillic/Greek homoglyphs."
    },
    "DIRECT_IP_URL_DESTINATION": {
        "weight": 22.0,
        "severity": "HIGH",
        "rationale": "Link resolves directly to a raw numerical IP address, bypassing domain registration oversight."
    },
    "MALFORMED_URL": {
        "weight": 10.0,
        "severity": "LOW",
        "rationale": "Malformed or non-standard URL structure attempting to evade URL parser tokenization."
    },
    "HIGH_ABUSE_TLD": {
        "weight": 6.0,
        "severity": "LOW",
        "rationale": "Higher-abuse TLD observed (contextual signal only, does not prove malice)."
    },
    "NEWLY_REGISTERED_DOMAIN": {
        "weight": 30.0,
        "severity": "HIGH",
        "rationale": "Sender or landing domain registered less than 30 days ago."
    },

    # 3. Intent & Social Engineering Tactics
    "ARTIFICIAL_URGENCY_INDUCEMENT": {
        "weight": 16.0,
        "severity": "HIGH",
        "rationale": "Psychological pressure inducing hurried action via strict time limits (e.g. 24h expiration, immediate suspension)."
    },
    "INTENT_CREDENTIAL_HARVESTING": {
        "weight": 26.0,
        "severity": "HIGH",
        "rationale": "Message attempts to direct user to external authentication portals under pretense of security validation."
    },
    "INTENT_PAYMENT_REDIRECTION": {
        "weight": 30.0,
        "severity": "CRITICAL",
        "rationale": "Solicits urgent modification of bank account routing, escrow deposits, or wire transfers."
    },
    "INTENT_PASSWORD_MFA_MANIPULATION": {
        "weight": 24.0,
        "severity": "HIGH",
        "rationale": "Prompts synchronization or reset of 2FA/MFA authenticator tokens."
    },
    "INTENT_EXECUTIVE_IMPERSONATION": {
        "weight": 25.0,
        "severity": "HIGH",
        "rationale": "Urgent executive out-of-band request demanding secrecy or bypassing standard approval procedures."
    },
    "INTENT_INVOICE_FRAUD": {
        "weight": 20.0,
        "severity": "MEDIUM",
        "rationale": "Fabricated overdue invoice or altered remittance advice."
    },

    # 4. Attachment Risk Signals (B07)
    "EXECUTABLE_ATTACHMENT": {
        "weight": 35.0,
        "severity": "CRITICAL",
        "rationale": "Attachment is an executable binary or executable script capable of executing arbitrary code."
    },
    "DOUBLE_EXTENSION_ATTACHMENT": {
        "weight": 25.0,
        "severity": "CRITICAL",
        "rationale": "Attachment disguises its true file type using deceptive double extension naming (e.g. .pdf.exe)."
    },
    "MAGIC_BYTE_MISMATCH": {
        "weight": 40.0,
        "severity": "CRITICAL",
        "rationale": "Attachment magic bytes indicate executable binary masquerading under a non-executable file extension."
    },
    "MACRO_ENABLED_OFFICE_ATTACHMENT": {
        "weight": 20.0,
        "severity": "HIGH",
        "rationale": "Attachment is a macro-enabled Office document with automated VBA execution capabilities."
    },
    "ARCHIVE_ATTACHMENT": {
        "weight": 12.0,
        "severity": "MEDIUM",
        "rationale": "Compressed archive container frequently used to smuggle malicious payloads."
    },

    # 5. Authentication Signals
    "SPF_VALIDATION_FAILED": {
        "weight": 20.0,
        "severity": "HIGH",
        "rationale": "Sending MTA IP is explicitly rejected by the sender domain SPF policy."
    },
    "DMARC_ALIGNMENT_FAILED": {
        "weight": 18.0,
        "severity": "HIGH",
        "rationale": "Neither SPF nor DKIM aligns with the visible RFC 5322 From domain."
    },
    "VERIFIED_SPF_FAILED": {
        "weight": 25.0,
        "severity": "HIGH",
        "rationale": "Independent DNS verification of SPF record against boundary IP failed."
    },
    "VERIFIED_DKIM_FAILED": {
        "weight": 25.0,
        "severity": "HIGH",
        "rationale": "Independent cryptographic DKIM signature verification failed."
    },
    "VERIFIED_DMARC_FAILED": {
        "weight": 30.0,
        "severity": "CRITICAL",
        "rationale": "Independent DMARC evaluation failed alignment with From domain."
    },

    # 6. Routing & Infrastructure Anomaly
    "SUSPICIOUS_ROUTING_RELAY": {
        "weight": 14.0,
        "severity": "MEDIUM",
        "rationale": "Received path contains hops marked UNTRUSTED or associated with unverified proxy relays."
    },
    "THREAT_INTEL_MALICIOUS_DOMAIN": {
        "weight": 35.0,
        "severity": "CRITICAL",
        "rationale": "Domain flagged malicious in threat intelligence feeds."
    },
    "THREAT_INTEL_MALICIOUS_IP": {
        "weight": 30.0,
        "severity": "CRITICAL",
        "rationale": "Observed sending IP confirmed active in adversary campaign infrastructure."
    },
    "GEO_THREAT_ANONYMIZATION": {
        "weight": 20.0,
        "severity": "HIGH",
        "rationale": "Sending MTA operates as an active Tor exit node or public anonymizing proxy."
    },
    "ANALYSIS_STAGE_FAILED": {
        "weight": 25.0,
        "severity": "HIGH",
        "rationale": "Pipeline stage failed during execution; unanalyzable content treated with elevated risk."
    }
}

POSITIVE_MITIGATIONS = {
    "AUTH_CLEAN_ALL_PASS": {
        "weight": -15.0,
        "rationale": "Full reported SPF, DKIM, and DMARC alignment with legitimate enterprise gateway and no hostile indicators."
    },
    "INTERNAL_TRUSTED_BOUNDARY": {
        "weight": -5.0,
        "rationale": "Originates exclusively within verified internal corporate infrastructure."
    }
}
