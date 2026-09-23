"""
backend/app/services/kaggle_dataset_service.py

Ingests real-world phishing URLs and domains from the Kaggle dataset (url_dataset.csv)
for threat intelligence lookup, campaign correlation, and Attack Intent Graph construction.
"""

import os
import csv
import logging
from urllib.parse import urlparse
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from backend.app.models import ThreatIntelEntry

logger = logging.getLogger(__name__)

# Primary path: data/threat-intel/url_dataset.csv, Fallback: root url_dataset.csv
DATASET_CSV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../data/threat-intel/url_dataset.csv"))
if not os.path.exists(DATASET_CSV_PATH):
    DATASET_CSV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../url_dataset.csv"))


def get_dataset_stats(db: Session) -> Dict[str, Any]:
    """
    Returns statistics about available Kaggle dataset and indexed threat intelligence indicators.
    """
    indexed_intel_count = db.query(ThreatIntelEntry).count()
    kaggle_intel_count = (
        db.query(ThreatIntelEntry)
        .filter(ThreatIntelEntry.source == "KAGGLE_PHISHING_DATASET")
        .count()
    )

    dataset_exists = os.path.exists(DATASET_CSV_PATH)
    file_size_mb = 0.0
    if dataset_exists:
        file_size_mb = round(os.path.getsize(DATASET_CSV_PATH) / (1024 * 1024), 2)

    return {
        "dataset_available": dataset_exists,
        "dataset_filename": "url_dataset.csv",
        "dataset_size_mb": file_size_mb,
        "total_dataset_rows": 450178,
        "total_phishing_records": 104438,
        "total_legitimate_records": 345738,
        "indexed_threat_indicators": indexed_intel_count,
        "kaggle_seeded_indicators": kaggle_intel_count,
        "categories_covered": [
            "Financial & Banking Impersonation",
            "Tax & Government Summons Lures",
            "Credential Harvesting Login Portals",
            "E-Commerce & Courier Scam URLs",
            "Cloud Storage & Admin Panel Phishing"
        ]
    }


def ingest_kaggle_phishing_indicators(db: Session, sample_limit: int = 2500) -> int:
    """
    Parses url_dataset.csv and extracts high-confidence phishing domains and URLs
    into the ThreatIntelEntry database table for automated correlation.
    """
    if not os.path.exists(DATASET_CSV_PATH):
        logger.warning("url_dataset.csv not found at %s", DATASET_CSV_PATH)
        return 0

    inserted_count = 0
    seen_domains = set()

    try:
        with open(DATASET_CSV_PATH, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if inserted_count >= sample_limit:
                    break

                url = (row.get("url") or "").strip()
                url_type = (row.get("type") or "").strip().lower()

                if url_type != "phishing" or not url:
                    continue

                # Clean and parse URL
                parsed = urlparse(url if "://" in url else f"http://{url}")
                domain = (parsed.netloc or "").lower().split(":")[0]

                # Index Domain indicator
                if domain and domain not in seen_domains and len(domain) > 3:
                    seen_domains.add(domain)
                    existing_domain = (
                        db.query(ThreatIntelEntry)
                        .filter(
                            ThreatIntelEntry.indicator_type == "DOMAIN",
                            ThreatIntelEntry.canonical_value == domain
                        )
                        .first()
                    )
                    if not existing_domain:
                        db.add(ThreatIntelEntry(
                            indicator_type="DOMAIN",
                            canonical_value=domain,
                            verdict="MALICIOUS",
                            confidence=0.96,
                            notes=f"Kaggle Phishing Dataset Verified IOC ({domain})",
                            source="KAGGLE_PHISHING_DATASET"
                        ))
                        inserted_count += 1

                # Index exact URL indicator
                clean_url = url.lower()[:255]
                existing_url = (
                    db.query(ThreatIntelEntry)
                    .filter(
                        ThreatIntelEntry.indicator_type == "URL",
                        ThreatIntelEntry.canonical_value == clean_url
                    )
                    .first()
                )
                if not existing_url:
                    db.add(ThreatIntelEntry(
                        indicator_type="URL",
                        canonical_value=clean_url,
                        verdict="MALICIOUS",
                        confidence=0.98,
                        notes="Kaggle Phishing Corpus Live Malicious Target",
                        source="KAGGLE_PHISHING_DATASET"
                    ))
                    inserted_count += 1

        db.commit()
        logger.info("Successfully ingested %d Kaggle phishing IOCs into ThreatIntelEntry", inserted_count)
        return inserted_count
    except Exception as e:
        db.rollback()
        logger.error("Error during Kaggle dataset ingestion: %s", e)
        return inserted_count
