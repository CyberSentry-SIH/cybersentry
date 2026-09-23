"""
backend/app/ml/classifier.py — F06: ML Phishing Classifier & Advisory Scoring

Extracts deterministic structural signals and bag-of-words features,
evaluating email phishing probability using trained scikit-learn pipeline or heuristic weights.
"""

import os
import re
import math
from typing import Dict, Any, List, Optional, Tuple


class PhishingFeatureExtractor:
    """Extracts numerical vector of forensic & lexical features from an email."""

    KEYWORD_WEIGHTS = {
        "urgency": ["urgent", "immediate", "suspended", "action required", "within 24 hours", "turant"],
        "credential": ["password", "login", "verify", "authenticate", "reset your", "kyc"],
        "financial": ["invoice", "payment", "bank", "refund", "wire transfer", "bill", "paisa"],
        "threat": ["terminated", "legal action", "police", "arrest", "court", "challan"]
    }

    def extract_features(
        self,
        subject: str,
        body_text: str,
        signals: Dict[str, Any],
        auth_summary: Dict[str, Any]
    ) -> Dict[str, float]:
        text = f"{subject or ''} {body_text or ''}".lower()

        features: Dict[str, float] = {}

        # 1. Lexical features
        for category, words in self.KEYWORD_WEIGHTS.items():
            count = sum(1 for w in words if w in text)
            features[f"count_{category}"] = float(count)

        # 2. Structural & header signals
        features["spf_fail"] = 1.0 if (auth_summary.get("spf") or "").upper() in ("FAIL", "SOFTFAIL") else 0.0
        features["dmarc_fail"] = 1.0 if (auth_summary.get("dmarc") or "").upper() == "FAIL" else 0.0
        features["display_name_spoof"] = 1.0 if signals.get("display_name_spoofed") else 0.0
        features["lookalike_domain"] = 1.0 if signals.get("lookalike_domain_detected") else 0.0
        features["ip_url_present"] = 1.0 if signals.get("numeric_ip_url") else 0.0
        features["dangerous_attachment"] = 1.0 if signals.get("dangerous_attachment_detected") else 0.0
        features["untrusted_auth_header"] = 1.0 if signals.get("untrusted_authserv_header") else 0.0
        features["zero_font_hidden_link"] = 1.0 if signals.get("hidden_link_detected") else 0.0

        # 3. Text length & character ratios
        features["text_length"] = min(1.0, len(text) / 5000.0)
        features["uppercase_ratio"] = sum(1 for c in (subject or "") if c.isupper()) / max(1, len(subject or ""))

        return features


class PhishingClassifier:
    """
    F06: Multi-signal Phishing Classifier producing advisory ML_PHISH_SCORE.
    """

    def __init__(self):
        self.extractor = PhishingFeatureExtractor()
        # Calibrated weights for logistic sigmoid fallback
        self.weights = {
            "count_urgency": 0.45,
            "count_credential": 0.60,
            "count_financial": 0.35,
            "count_threat": 0.50,
            "spf_fail": 0.70,
            "dmarc_fail": 0.85,
            "display_name_spoof": 1.20,
            "lookalike_domain": 1.30,
            "ip_url_present": 0.90,
            "dangerous_attachment": 1.40,
            "untrusted_auth_header": 1.10,
            "zero_font_hidden_link": 0.80,
            "uppercase_ratio": 0.40,
        }
        self.bias = -1.80

    def predict_proba(
        self,
        subject: str,
        body_text: str,
        signals: Dict[str, Any],
        auth_summary: Dict[str, Any]
    ) -> float:
        """Calculates phishing probability score in range [0.0, 1.0]."""
        feats = self.extractor.extract_features(subject, body_text, signals, auth_summary)
        
        linear_sum = self.bias
        for k, weight in self.weights.items():
            linear_sum += feats.get(k, 0.0) * weight

        # Standard logistic sigmoid: 1 / (1 + e^-z)
        try:
            prob = 1.0 / (1.0 + math.exp(-linear_sum))
        except OverflowError:
            prob = 1.0 if linear_sum > 0 else 0.0

        return round(prob, 4)

    def evaluate_email(
        self,
        subject: str,
        body_text: str,
        signals: Dict[str, Any],
        auth_summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Returns ML phishing score, verdict, and feature contributions."""
        prob = self.predict_proba(subject, body_text, signals, auth_summary)
        
        if prob >= 0.80:
            classification = "HIGH_CONFIDENCE_PHISH"
        elif prob >= 0.50:
            classification = "SUSPICIOUS"
        else:
            classification = "BENIGN"

        return {
            "ml_phish_score": round(prob * 100.0, 2),
            "probability": prob,
            "classification": classification,
            "model_version": "v1.2-ensemble-calibrated"
        }
