import re
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup

INTENT_RULES = {
    "CREDENTIAL_HARVESTING": {
        "keywords": [
            r"verify\s+identity", r"confirm\s+credentials", r"login\s+attempt", r"account\s+suspended",
            r"sign\s+in\s+to\s+verify", r"restore\s+account", r"unlock\s+account", r"verify\s+within",
            r"restricted\s+access", r"suspension\s+notice", r"confirm\s+billing", r"temporary\s+lock",
            r"re-authenticate", r"restore\s+my\s+account", r"wallet\s+has\s+been\s+flagged", r"unlock\s+your\s+wallet",
            r"confirm\s+identity", r"confirm\s+your\s+card", r"verify\s+account\s+now"
        ],
        "weight": 26.0,
        "impersonation_target": "FINANCIAL_OR_IDENTITY_PROVIDER",
        "social_engineering_strategy": "FEAR_OF_ACCOUNT_SUSPENSION",
        "requested_action": "CREDENTIAL_VERIFICATION",
        "title": "Credential Harvesting Intent",
        "description": "Email content urges the recipient to verify credentials under threat of account suspension."
    },
    "PASSWORD_MFA_MANIPULATION": {
        "keywords": [
            r"synchronize\s+authenticator", r"mfa\s+token", r"multi-factor\s+reset", r"2fa\s+expired",
            r"reset\s+password\s+immediately", r"password\s+expires?\s+today", r"sync\s+your\s+authenticator"
        ],
        "weight": 24.0,
        "impersonation_target": "ENTERPRISE_IT_IDENTITY",
        "social_engineering_strategy": "SECURITY_POLICY_COMPLIANCE",
        "requested_action": "MFA_TOKEN_SYNCHRONIZATION",
        "title": "MFA / Security Token Manipulation",
        "description": "Message prompts the user to reset or synchronize Multi-Factor Authentication credentials."
    },
    "PAYMENT_REDIRECTION": {
        "keywords": [
            r"wire\s+transfer", r"escrow\s+deposit", r"updated\s+routing", r"swift\s+details",
            r"main\s+operating\s+account", r"bank\s+routing", r"process\s+this\s+wire", r"acquisition\s+advance"
        ],
        "weight": 30.0,
        "impersonation_target": "CORPORATE_EXECUTIVE_OR_VENDOR",
        "social_engineering_strategy": "AUTHORITY_PRESSURE_CONFIDENTIALITY",
        "requested_action": "FINANCIAL_WIRE_TRANSFER",
        "title": "Payment Redirection / Wire Fraud",
        "description": "Message solicits urgent financial transactions, wire transfer redirections, or banking account changes."
    },
    "EXECUTIVE_IMPERSONATION": {
        "keywords": [
            r"chief\s+executive\s+officer", r"nda\s+is\s+strictly\s+in\s+effect",
            r"confidential\s+acquisition", r"do\s+not\s+discuss\s+via\s+phone",
            r"strict\s+confidentiality\s+required", r"handle\s+this\s+personally\s+and\s+confidentially"
        ],
        "weight": 25.0,
        "impersonation_target": "C_LEVEL_EXECUTIVE",
        "social_engineering_strategy": "EXECUTIVE_HIERARCHY_OVERRIDE",
        "requested_action": "CONFIDENTIAL_TASK_EXECUTION",
        "title": "Executive Impersonation (BEC)",
        "description": "Attacker impersonates a high-level executive demanding out-of-band compliance without verbal verification."
    },
    "INVOICE_FRAUD": {
        "keywords": [
            r"overdue\s+invoice", r"past\s+due\s+invoice", r"remittance\s+advice",
            r"payment\s+overdue", r"unpaid\s+invoice", r"wire\s+immediately"
        ],
        "weight": 20.0,
        "impersonation_target": "ACCOUNTS_RECEIVABLE_SUPPLIER",
        "social_engineering_strategy": "COMMERCIAL_PENALTY_AVOIDANCE",
        "requested_action": "INVOICE_PAYMENT",
        "title": "Invoice / Remittance Fraud",
        "description": "Email lures the recipient with fake overdue invoices or altered payment accounts."
    },
    "ACCOUNT_VERIFICATION": {
        "keywords": [
            r"verify\s+account", r"unusual\s+activity\s+detected", r"unrecognized\s+device",
            r"temporary\s+limitation\s+on\s+your"
        ],
        "weight": 18.0,
        "impersonation_target": "PLATFORM_SECURITY_OPERATIONS",
        "social_engineering_strategy": "INCIDENT_ALERT_URGENCY",
        "requested_action": "ACCOUNT_ACTIVITY_CONFIRMATION",
        "title": "Suspicious Account Verification Lure",
        "description": "Email fabricates security incidents to manipulate user into clicking an unverified verification link."
    }
}

def clean_html_content(raw_html: str) -> str:
    """Strip HTML and script tags to prevent markup from confusing text analysis."""
    if not raw_html:
        return ""
    try:
        soup = BeautifulSoup(raw_html, "html.parser")
        for tag in soup(["script", "style", "head", "meta"]):
            tag.decompose()
        return soup.get_text(separator=" ")
    except Exception:
        return re.sub(r"<[^>]+>", " ", raw_html)

def analyze_intent(subject: str, body_text: str, body_html: str) -> Dict[str, Any]:
    """
    B09: Resilient intent analysis without bypassable whitelists or crude keyword false positives.
    """
    clean_html = clean_html_content(body_html)
    full_content = f"{subject or ''} {body_text or ''} {clean_html}".lower()

    findings = []
    detected_intents = []
    urgency_detected = False

    # Multi-token urgency regex patterns (avoid single generic words like 'critical' alone)
    urgency_patterns = [
        r"\burgent(?:ly)?\b",
        r"\b(?:immediately|immediate\s+attention)\b",
        r"\bwithin\s+(?:12|24|48)\s+hours\b",
        r"\baction\s+required\b",
        r"\bexpires?\s+today\b",
        r"\bimmediate\s+action\s+required\b",
        # F14: Indian / Hinglish urgency patterns
        r"\bturant\b",
        r"\bkhata\s+band\b",
        r"\baaj\s+hi\b",
        r"\bkyc\s+update\b"
    ]

    matched_urgency = []
    for pat in urgency_patterns:
        if re.search(pat, full_content):
            matched_urgency.append(pat.replace(r"\b", ""))

    # Evaluate intents across all rules (NO EARLY RETURN WHITELISTS)
    primary_intent = None
    max_matches = 0
    matched_target = None
    matched_strategy = None
    matched_action = None

    for intent_name, rule in INTENT_RULES.items():
        matched_kws = []
        for kw_pat in rule["keywords"]:
            if re.search(r"\b" + kw_pat + r"\b", full_content):
                matched_kws.append(kw_pat)

        if matched_kws:
            detected_intents.append({
                "intent": intent_name,
                "matched_keywords": matched_kws,
                "weight": rule["weight"],
                "impersonation_target": rule["impersonation_target"],
                "strategy": rule["social_engineering_strategy"],
                "action": rule["requested_action"]
            })
            if len(matched_kws) > max_matches:
                max_matches = len(matched_kws)
                primary_intent = intent_name
                matched_target = rule["impersonation_target"]
                matched_strategy = rule["social_engineering_strategy"]
                matched_action = rule["requested_action"]

            findings.append({
                "category": "INTENT",
                "code": f"INTENT_{intent_name}",
                "title": rule["title"],
                "description": rule["description"],
                "severity": "HIGH" if rule["weight"] >= 24.0 else "MEDIUM",
                "risk_contribution": rule["weight"],
                "evidence": {
                    "intent": intent_name,
                    "triggers": matched_kws,
                    "impersonation_target": rule["impersonation_target"],
                    "strategy": rule["social_engineering_strategy"]
                }
            })

    # Only flag urgency finding if intent is non-benign or multiple urgency triggers exist
    if matched_urgency and (primary_intent or len(matched_urgency) >= 2):
        urgency_detected = True
        findings.append({
            "category": "INTENT",
            "code": "ARTIFICIAL_URGENCY_INDUCEMENT",
            "title": "High Urgency / Pressure Tactics Detected",
            "description": f"Language uses coercive pressure triggers to induce hurried compliance.",
            "severity": "HIGH",
            "risk_contribution": 16.0,
            "evidence": {"urgency_triggers": matched_urgency}
        })

    if not detected_intents:
        primary_intent = "BENIGN_COMMUNICATION"
        matched_target = "NONE"
        matched_strategy = "ROUTINE_OPERATIONAL"
        matched_action = "INFORMATIONAL_NOTIFICATION"
        detected_intents.append({
            "intent": "BENIGN_COMMUNICATION",
            "matched_keywords": [],
            "weight": 0.0,
            "impersonation_target": "NONE",
            "strategy": "ROUTINE_OPERATIONAL",
            "action": "INFORMATIONAL_NOTIFICATION"
        })

    semantic_profile = {
        "primary_intent": primary_intent,
        "impersonation_target": matched_target or "NONE",
        "social_engineering_strategy": matched_strategy or "NONE",
        "requested_action": matched_action or "NONE",
        "urgency_pattern": "HIGH_TIME_PRESSURE" if urgency_detected else "NORMAL"
    }

    return {
        "findings": findings,
        "primary_intent": primary_intent,
        "detected_intents": detected_intents,
        "urgency_detected": urgency_detected,
        "urgency_keywords": matched_urgency,
        "semantic_profile": semantic_profile
    }
