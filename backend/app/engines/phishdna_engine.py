"""
PhishDNA™ Forensic Profiling Engine
-----------------------------------
Terminology & Forensic Ground Truth:
- SHA-256 Digest: Exact cryptographic evidence fingerprint ensuring physical payload integrity and tamper-evidence.
- PhishDNA™: Normalized Semantic Feature Vector and Behavioral/Structural Attack Fingerprint (PDNA-...)
  capturing invariant behavioral tactics, social engineering cues, and structural traits across polymorphic mutations.
  (Note: Constructed deterministically via explainable multi-layer feature extraction; not an uncalibrated neural embedding.)

Layer 1: Exact forensic indicators (exact sender, domain, URLs, IPs, attachment hashes)
Layer 2: Normalized semantic feature vectors & structural abstractions (intent, strategy, CTA, HTML tag sequences, network /24 CIDR)
"""

import hashlib
import json
import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple

def extract_canonical_host(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""

def normalize_string(s: str) -> str:
    if not s:
        return ""
    s = re.sub(r'[\r\n\t]+', ' ', s)
    s = re.sub(r'[^a-zA-Z0-9\s]', '', s)
    return ' '.join(s.lower().split())

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def get_length_bucket(length: int) -> str:
    if length < 200:
        return "SHORT"
    elif length < 1000:
        return "MEDIUM"
    elif length < 5000:
        return "LONG"
    return "EXTENSIVE"

INTENT_INDEX = {
    "CREDENTIAL_HARVESTING": 0,
    "PAYMENT_REDIRECTION": 1,
    "PASSWORD_MFA_MANIPULATION": 2,
    "EXECUTIVE_IMPERSONATION": 3,
    "INVOICE_FRAUD": 4,
    "ACCOUNT_VERIFICATION": 5,
    "BENIGN_COMMUNICATION": 6
}

STRATEGY_INDEX = {
    "FEAR_OF_ACCOUNT_SUSPENSION": 0,
    "SECURITY_POLICY_COMPLIANCE": 1,
    "AUTHORITY_PRESSURE_CONFIDENTIALITY": 2,
    "EXECUTIVE_HIERARCHY_OVERRIDE": 3,
    "COMMERCIAL_PENALTY_AVOIDANCE": 4,
    "INCIDENT_ALERT_URGENCY": 5,
    "ROUTINE_OPERATIONAL": 6
}

ACTION_INDEX = {
    "CREDENTIAL_VERIFICATION": 0,
    "MFA_TOKEN_SYNCHRONIZATION": 1,
    "FINANCIAL_WIRE_TRANSFER": 2,
    "CONFIDENTIAL_TASK_EXECUTION": 3,
    "INVOICE_PAYMENT": 4,
    "ACCOUNT_ACTIVITY_CONFIRMATION": 5,
    "INFORMATIONAL_NOTIFICATION": 6
}

def generate_phishdna(
    sender_domain: str,
    from_name: str,
    from_address: str,
    subject: str,
    body_text: str,
    body_html: str,
    urls: List[str],
    hops: List[Dict[str, Any]],
    auth_results: Dict[str, Any],
    attachments: List[Dict[str, Any]],
    primary_intent: str,
    semantic_profile: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    norm_subject = normalize_string(subject or "")
    norm_body = normalize_string(body_text or "")
    canonical_hosts = [extract_canonical_host(u) for u in urls if u]
    origin_ips = [h.get("ip_address") for h in hops if h.get("ip_address")]
    att_hashes = [a.get("sha256") for a in attachments if a.get("sha256")]

    # ─────────────────────────────────────────────────────────────
    # LAYER 1: EXACT FORENSIC INDICATORS (Deterministic Ground Truth)
    # ─────────────────────────────────────────────────────────────
    exact_features = {
        "exact_sender_address": (from_address or "").strip().lower(),
        "exact_sender_domain": (sender_domain or "").strip().lower(),
        "exact_canonical_hosts": canonical_hosts,
        "exact_origin_ips": origin_ips,
        "exact_attachment_hashes": att_hashes,
        "exact_subject_hash": hashlib.sha256((subject or "").encode()).hexdigest()[:16]
    }

    # ─────────────────────────────────────────────────────────────
    # LAYER 2: NORMALIZED SEMANTIC FEATURE VECTOR REPRESENTATION
    # ─────────────────────────────────────────────────────────────
    sem_prof = semantic_profile or {}
    effective_intent = sem_prof.get("primary_intent") or primary_intent or "BENIGN_COMMUNICATION"
    impersonation_target = sem_prof.get("impersonation_target", "NONE")
    social_engineering_strategy = sem_prof.get("social_engineering_strategy", "NONE")
    requested_action = sem_prof.get("requested_action", "NONE")
    urgency_pattern = sem_prof.get("urgency_pattern", "NORMAL")

    html_tags = extract_html_tags(body_html or "")
    url_tokens = extract_url_path_tokens(urls)

    untrusted_hops_count = sum(1 for h in hops if h.get("trust_level") == "UNTRUSTED")
    trusted_hops_count = sum(1 for h in hops if h.get("trust_level") == "TRUSTED")

    # Generate 32-dimensional normalized semantic feature vector
    semantic_vector = generate_semantic_vector(
        norm_text=f"{norm_subject} {norm_body[:500]}",
        intent=effective_intent,
        strategy=social_engineering_strategy,
        action=requested_action,
        urgency=urgency_pattern
    )

    normalized_features = {
        "semantic_intent": effective_intent,
        "impersonation_target": impersonation_target,
        "social_engineering_strategy": social_engineering_strategy,
        "requested_action": requested_action,
        "urgency_pattern": urgency_pattern,
        "semantic_vector": [round(v, 4) for v in semantic_vector],
        "html_tag_sequence": html_tags[:25],
        "url_tokens": url_tokens,
        "hop_count": len(hops),
        "untrusted_hops_count": untrusted_hops_count,
        "trusted_hops_count": trusted_hops_count,
        "auth_profile": f"{auth_results.get('spf_result', 'NONE')}_{auth_results.get('dkim_result', 'NONE')}_{auth_results.get('dmarc_result', 'NONE')}".upper(),
        "norm_subject_tokens": norm_subject[:60],
        "content_length_bucket": get_length_bucket(len(body_text or ""))
    }

    # Backward compatibility sub-dictionaries
    header_dna = {
        "sender_domain": exact_features["exact_sender_domain"],
        "has_reply_to": bool(auth_results.get("reply_to")),
        "spf_status": auth_results.get("spf_result", "NONE"),
        "dkim_status": auth_results.get("dkim_result", "NONE"),
        "dmarc_status": auth_results.get("dmarc_result", "NONE")
    }

    identity_auth_dna = {
        "display_name_pattern": re.sub(r'[^a-zA-Z]', '', from_name or "").lower()[:20],
        "domain_entropy": calculate_entropy(sender_domain or ""),
        "auth_profile": normalized_features["auth_profile"]
    }

    content_dna = {
        "intent": effective_intent,
        "impersonation_target": impersonation_target,
        "social_engineering_strategy": social_engineering_strategy,
        "length_bucket": normalized_features["content_length_bucket"],
        "html_structure_hash": hashlib.md5("-".join(html_tags[:30]).encode()).hexdigest()[:8],
        "subject_signature": hashlib.md5(norm_subject[:40].encode()).hexdigest()[:12]
    }

    url_dna = {
        "url_count": len(urls),
        "domains": canonical_hosts,
        "has_ip_url": any(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', h) for h in canonical_hosts),
        "url_hash": hashlib.md5("".join(canonical_hosts).encode()).hexdigest()[:12]
    }

    infrastructure_dna = {
        "hop_count": len(hops),
        "origin_ips": origin_ips[:3],
        "untrusted_hops": untrusted_hops_count,
        "infra_hash": hashlib.md5("".join(origin_ips[:3]).encode()).hexdigest()[:12]
    }

    behavioral_dna = {
        "urgency": urgency_pattern,
        "requested_action": requested_action,
        "call_to_action_types": ["verify", "link_click"] if urls else ["reply_only"]
    }

    attachment_dna = {
        "count": len(attachments),
        "hashes": [a[:12] for a in att_hashes]
    }

    # Composite Cryptographic Fingerprint
    dna_components = [
        exact_features["exact_sender_domain"][:15],
        normalized_features["auth_profile"],
        effective_intent,
        impersonation_target,
        social_engineering_strategy,
        content_dna["html_structure_hash"],
        url_dna["url_hash"],
        infrastructure_dna["infra_hash"]
    ]
    raw_fingerprint = ":".join(dna_components)
    fingerprint = f"PDNA-{hashlib.sha256(raw_fingerprint.encode()).hexdigest()[:16].upper()}"

    return {
        "fingerprint": fingerprint,
        "exact_features": exact_features,
        "normalized_features": normalized_features,
        "header_dna": header_dna,
        "identity_auth_dna": identity_auth_dna,
        "content_dna": content_dna,
        "url_dna": url_dna,
        "infrastructure_dna": infrastructure_dna,
        "behavioral_dna": behavioral_dna,
        "attachment_dna": attachment_dna
    }

def calculate_phishdna_similarity(dna1: Dict[str, Any], dna2: Dict[str, Any]) -> float:
    score, _ = calculate_phishdna_similarity_detailed(dna1, dna2)
    return score

def calculate_phishdna_similarity_detailed(
    dna1: Dict[str, Any],
    dna2: Dict[str, Any]
) -> Tuple[float, List[str]]:
    """
    Calculates multi-vector PhishDNA forensic similarity (0.0 to 100.0)
    evaluating:
    1. Normalized Semantic Feature Similarity (40% - Intent & Behavioral Strategy)
    2. URL & Domain Structural Alignment (25% - Brand, Token & Host patterns)
    3. Infrastructure & Network Subnet Relationship (20% - Corroborating Evidence: Shared IP / Subnet)
    4. HTML DOM Jaccard Similarity (10% - Structural template layout)
    5. Reported Authentication Profile Alignment (5%)
    """
    reasons = []

    # 1. Normalized Semantic Feature Similarity (40%)
    v1 = dna1.get("normalized_features", {}).get("semantic_vector") or []
    v2 = dna2.get("normalized_features", {}).get("semantic_vector") or []

    intent1 = dna1.get("normalized_features", {}).get("semantic_intent") or dna1.get("content_dna", {}).get("intent")
    intent2 = dna2.get("normalized_features", {}).get("semantic_intent") or dna2.get("content_dna", {}).get("intent")

    if v1 and v2 and len(v1) == len(v2):
        semantic_cos = cosine_similarity(v1, v2)
    else:
        # Fallback to discrete intent match if vectors not available
        semantic_cos = 1.0 if (intent1 == intent2 and intent1 != "BENIGN_COMMUNICATION") else 0.0

    semantic_score = semantic_cos * 40.0
    if semantic_cos >= 0.70 and intent1 != "BENIGN_COMMUNICATION":
        reasons.append(f"High semantic feature similarity ({semantic_cos:.0%}) in attack intent & lure tactics")
    elif semantic_cos >= 0.50:
        reasons.append(f"Moderate semantic feature similarity ({semantic_cos:.0%})")

    # Hard Negative Rejection Gate:
    # If either email is benign, or if semantic intent is entirely disjoint and has zero infrastructure relation,
    # the similarity is strictly penalized.
    if intent1 == "BENIGN_COMMUNICATION" or intent2 == "BENIGN_COMMUNICATION":
        return min(15.0, round(semantic_score * 0.35, 1)), ["Benign baseline separation (Low correlation)"]

    # 2. URL & Domain Structural Alignment (25%)
    hosts1 = set(dna1.get("exact_features", {}).get("exact_canonical_hosts") or dna1.get("url_dna", {}).get("domains", []))
    hosts2 = set(dna2.get("exact_features", {}).get("exact_canonical_hosts") or dna2.get("url_dna", {}).get("domains", []))

    url_score = 0.0
    shared_hosts = hosts1 & hosts2
    if shared_hosts:
        url_score += 18.0
        reasons.append(f"Shared landing host ({', '.join(shared_hosts)})")
    elif hosts1 and hosts2:
        # Check brand root / Levenshtein similarity across hosts
        max_host_sim = max([string_similarity(h1, h2) for h1 in hosts1 for h2 in hosts2] or [0.0])
        if max_host_sim >= 0.70:
            url_score += 12.0
            reasons.append(f"Related landing domain structure ({max_host_sim:.0%} lexical similarity)")

    # Path token overlap
    tokens1 = set(dna1.get("normalized_features", {}).get("url_tokens", []))
    tokens2 = set(dna2.get("normalized_features", {}).get("url_tokens", []))
    if tokens1 and tokens2:
        path_jaccard = jaccard_similarity(tokens1, tokens2)
        if path_jaccard >= 0.3:
            url_score += min(7.0, round(path_jaccard * 7.0, 1))
            reasons.append(f"Similar URL path routing pattern ({path_jaccard:.0%} token match)")

    # Sender domain comparison
    dom1 = dna1.get("exact_features", {}).get("exact_sender_domain") or dna1.get("header_dna", {}).get("sender_domain", "")
    dom2 = dna2.get("exact_features", {}).get("exact_sender_domain") or dna2.get("header_dna", {}).get("sender_domain", "")
    if dom1 and dom2 and dom1 == dom2:
        url_score = min(25.0, url_score + 5.0)
        reasons.append(f"Identical sender domain ({dom1})")

    # 3. Infrastructure & Network Subnet Relationship (20% - Corroborating Evidence)
    # Problem 5: Infrastructure is supporting evidence. If semantic similarity is low (< 0.40),
    # shared infrastructure alone cannot create a campaign match.
    ips1 = set(dna1.get("exact_features", {}).get("exact_origin_ips") or dna1.get("infrastructure_dna", {}).get("origin_ips", []))
    ips2 = set(dna2.get("exact_features", {}).get("exact_origin_ips") or dna2.get("infrastructure_dna", {}).get("origin_ips", []))

    infra_score = 0.0
    shared_ips = ips1 & ips2
    if shared_ips:
        infra_score = 20.0
        reasons.append(f"Shared infrastructure IP ({', '.join(shared_ips)})")
    elif ips1 and ips2:
        # Check /24 subnet match (e.g. 185.220.101.x)
        subnets1 = set([extract_subnet_24(ip) for ip in ips1 if ip])
        subnets2 = set([extract_subnet_24(ip) for ip in ips2 if ip])
        shared_subnets = subnets1 & subnets2
        if shared_subnets:
            infra_score = 14.0
            reasons.append(f"Shared /24 subnet segment ({', '.join(shared_subnets)}.0/24)")

    # If semantic similarity is weak (< 0.40) and URL overlap is absent, discount infrastructure
    # to avoid false correlation on shared hosting providers/CDNs
    if semantic_cos < 0.40 and url_score == 0.0:
        infra_score = min(infra_score, 8.0)

    # 4. HTML DOM Structural Jaccard Similarity (10%)
    tags1 = dna1.get("normalized_features", {}).get("html_tag_sequence", [])
    tags2 = dna2.get("normalized_features", {}).get("html_tag_sequence", [])
    html_score = 0.0
    if tags1 and tags2:
        html_jaccard = jaccard_n_grams(tags1, tags2, n=2)
        html_score = round(html_jaccard * 10.0, 1)
        if html_jaccard >= 0.50:
            reasons.append(f"Matching HTML template DOM layout ({html_jaccard:.0%} structural overlap)")

    # 5. Reported Authentication / Delivery Profile (5%)
    auth1 = dna1.get("normalized_features", {}).get("auth_profile") or dna1.get("identity_auth_dna", {}).get("auth_profile")
    auth2 = dna2.get("normalized_features", {}).get("auth_profile") or dna2.get("identity_auth_dna", {}).get("auth_profile")
    auth_score = 0.0
    if auth1 and auth2 and auth1 == auth2:
        auth_score = 5.0
        reasons.append(f"Matching reported authentication profile ({auth1})")

    raw_total = semantic_score + url_score + infra_score + html_score + auth_score
    final_score = max(0.0, min(100.0, round(raw_total, 1)))

    return final_score, reasons

def generate_semantic_vector(norm_text: str, intent: str, strategy: str, action: str, urgency: str) -> List[float]:
    """Generates a 32-dimensional normalized dense feature vector representing email semantics."""
    vec = [0.0] * 32

    # Slots 0-6: Intent Distribution
    i_idx = INTENT_INDEX.get(intent, 6)
    vec[i_idx] = 1.0

    # Slots 7-13: Social Engineering Strategy
    s_idx = STRATEGY_INDEX.get(strategy, 6)
    vec[7 + s_idx] = 1.0

    # Slots 14-20: Action Request
    a_idx = ACTION_INDEX.get(action, 6)
    vec[14 + a_idx] = 1.0

    # Slot 21: Urgency level
    vec[21] = 1.0 if urgency == "HIGH_TIME_PRESSURE" else 0.0

    # Slots 22-31: Hashed Lexical Token n-grams (10 buckets)
    # NOTE: We deliberately use hashlib.sha256 here instead of Python's built-in
    # hash(). Python randomizes str hashing per-process (PYTHONHASHSEED) as a
    # defense against hash-flooding DoS attacks, which means hash("token") can
    # return a different value every time the server restarts. That's fine for
    # a dict, but fatal for a forensic fingerprint: the same email must always
    # bucket its tokens the same way, on any machine, in any process, forever.
    # sha256 is fixed and unsalted, so it gives us that determinism.
    tokens = norm_text.split()
    for tok in tokens:
        digest = hashlib.sha256(tok.encode("utf-8")).digest()
        bucket = digest[0] % 10
        vec[22 + bucket] += 0.2

    # L2 Normalize
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]

    return vec

def cosine_similarity(u: List[float], v: List[float]) -> float:
    dot = sum(a * b for a, b in zip(u, v))
    norm_u = math.sqrt(sum(a * a for a in u))
    norm_v = math.sqrt(sum(b * b for b in v))
    if norm_u == 0 or norm_v == 0:
        return 0.0
    return max(0.0, min(1.0, dot / (norm_u * norm_v)))

def extract_subnet_24(ip: str) -> str:
    parts = ip.strip().split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ip

def extract_host(url: str) -> str:
    from urllib.parse import urlparse
    return (urlparse(url).hostname or "").lower().strip()

def extract_html_tags(html: str) -> List[str]:
    if not html:
        return []
    return [tag.lower() for tag in re.findall(r'<\s*([a-zA-Z0-9]+)', html)]

def extract_url_path_tokens(urls: List[str]) -> List[str]:
    from urllib.parse import urlparse
    tokens = set()
    for u in urls:
        p = urlparse(u).path
        for seg in p.split("/"):
            clean = re.sub(r'[^a-zA-Z0-9]', '', seg).lower()
            if clean and len(clean) > 2:
                tokens.add(clean)
    return sorted(list(tokens))

def jaccard_similarity(s1: set, s2: set) -> float:
    if not s1 or not s2:
        return 0.0
    inter = len(s1 & s2)
    union = len(s1 | s2)
    return inter / union if union > 0 else 0.0

def jaccard_n_grams(seq1: List[str], seq2: List[str], n: int = 2) -> float:
    if len(seq1) < n or len(seq2) < n:
        return 1.0 if seq1 == seq2 else 0.0
    ngrams1 = set([tuple(seq1[i:i+n]) for i in range(len(seq1) - n + 1)])
    ngrams2 = set([tuple(seq2[i:i+n]) for i in range(len(seq2) - n + 1)])
    return jaccard_similarity(ngrams1, ngrams2)

def string_similarity(s1: str, s2: str) -> float:
    if not s1 or not s2:
        return 0.0
    if s1 == s2:
        return 1.0
    from backend.app.engines.url_engine import levenshtein_distance
    dist = levenshtein_distance(s1, s2)
    max_len = max(len(s1), len(s2))
    return max(0.0, 1.0 - (dist / max_len))

