#!/usr/bin/env python3
"""
scripts/eval_samples.py — Automated Evaluation & Regression Corpus Runner (Phase 4)

Evaluates all synthetic and fixture EML samples against expected ground truth verdicts.
Computes Confusion Matrix, Precision, Recall, and F1-Score.
"""

import os
import glob
import sys

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.services.parser_service import parse_eml_bytes
from backend.app.engines.header_engine import analyze_headers
from backend.app.engines.url_engine import analyze_urls
from backend.app.engines.intent_engine import analyze_intent
from backend.app.engines.phishdna_engine import generate_phishdna
from backend.app.engines.risk_engine import calculate_risk
from backend.app.engines.origin_engine import assess_email_origin
from backend.app.ml.classifier import PhishingClassifier


def evaluate_all():
    classifier = PhishingClassifier()
    sample_dirs = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/synthetic")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend/tests/fixtures"))
    ]

    all_files = []
    for sdir in sample_dirs:
        if os.path.exists(sdir):
            all_files.extend(sorted(glob.glob(os.path.join(sdir, "*.eml"))))

    print("=" * 80)
    print(" CYBERSENTRY - FORENSIC EVALUATION & REGRESSION MATRIX")
    print("=" * 80)
    print(f"{'Filename':<35} | {'Risk':<5} | {'Band':<10} | {'Verdict':<10} | {'ML Prob':<7} | {'Attribution'}")
    print("-" * 80)

    tp, fp, tn, fn = 0, 0, 0, 0

    for fpath in all_files:
        fname = os.path.basename(fpath)
        with open(fpath, "rb") as f:
            raw = f.read()

        parsed = parse_eml_bytes(raw)
        header_res = analyze_headers(
            from_name=parsed.get("from_name"),
            from_address=parsed.get("from_address"),
            from_domain=parsed.get("from_domain"),
            reply_to=parsed.get("reply_to"),
            return_path=parsed.get("return_path"),
            hops=parsed.get("hops", []),
            auth_results=parsed.get("auth_results", {})
        )
        url_res = analyze_urls(parsed.get("urls", []), email_domain=parsed.get("from_domain", ""))
        intent_res = analyze_intent(parsed.get("subject", ""), parsed.get("body_text", ""), parsed.get("body_html", ""))

        findings = header_res.get("findings", []) + url_res.get("findings", []) + intent_res.get("findings", [])
        signals = {**header_res.get("signals", {}), **url_res.get("signals", {})}
        score, band, snapshot, recs, verdict, _ = calculate_risk(findings, header_res.get("auth_summary", {}), signals)

        ml_eval = classifier.evaluate_email(
            parsed.get("subject", ""),
            parsed.get("body_text", ""),
            signals,
            header_res.get("auth_summary", {})
        )

        origin_eval = assess_email_origin(
            boundary_ip=header_res.get("boundary_ip"),
            hops=header_res.get("processed_hops", []),
            auth_summary=header_res.get("auth_summary", {}),
            signals=signals,
            from_domain=parsed.get("from_domain")
        )

        # Ground truth check (samples with 'legitimate' or 'hard_negative' are benign)
        is_ground_truth_malicious = not ("legitimate" in fname or "hard_negative" in fname)
        is_predicted_malicious = score >= 35.0 or (verdict in ("PHISHING", "SPOOFED", "MALICIOUS", "FRAUD") and score >= 25.0)

        if is_ground_truth_malicious and is_predicted_malicious:
            tp += 1
        elif not is_ground_truth_malicious and is_predicted_malicious:
            fp += 1
        elif not is_ground_truth_malicious and not is_predicted_malicious:
            tn += 1
        else:
            fn += 1

        print(f"{fname[:35]:<35} | {score:<5.1f} | {band:<10} | {verdict:<10} | {ml_eval['probability']:<7.2f} | {origin_eval['attribution_verdict']}")

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 1.0

    print("=" * 80)
    print(f" True Positives (TP): {tp} | True Negatives (TN): {tn}")
    print(f" False Positives (FP): {fp} | False Negatives (FN): {fn}")
    print(f" Precision: {precision:.2%} | Recall: {recall:.2%} | F1-Score: {f1:.2%}")
    print("=" * 80)

    if fp > 0 or fn > 0:
        print("[FAIL] Regression detected in ground-truth sample evaluation.")
        return 1
    else:
        print("[SUCCESS] All test samples matched ground-truth expectations perfectly.")
        return 0


if __name__ == "__main__":
    sys.exit(evaluate_all())
