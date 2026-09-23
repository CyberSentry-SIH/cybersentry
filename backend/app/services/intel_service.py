"""
backend/app/services/intel_service.py — F08: Threat Intel Matcher & STIX/CSV Importer

Provides indicator lookup against local threat database and bulk importing from CSV and STIX 2.1 JSON.
"""

import csv
import io
import json
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from backend.app.models import ThreatIntelEntry


def lookup_indicator(db: Session, indicator_type: str, canonical_value: str) -> Dict[str, Any]:
    entry = (
        db.query(ThreatIntelEntry)
        .filter(
            ThreatIntelEntry.indicator_type == indicator_type.upper(),
            ThreatIntelEntry.canonical_value == canonical_value.lower()
        )
        .first()
    )
    if entry:
        return {
            "status": entry.verdict,
            "source": entry.source,
            "confidence": float(entry.confidence or 0.9),
            "notes": entry.notes
        }
    return {
        "status": "UNKNOWN",
        "source": "LOCAL_INTEL",
        "confidence": 0.0,
        "notes": "Indicator has no prior recorded reputation (Unknown ≠ Safe)"
    }


def import_indicators_from_csv(db: Session, csv_content: str, source_label: str = "CSV_IMPORT") -> Dict[str, Any]:
    """
    F08: Import IOCs from CSV string (columns: type, value, verdict, confidence, notes).
    """
    reader = csv.DictReader(io.StringIO(csv_content))
    imported_count = 0
    errors = []

    for idx, row in enumerate(reader):
        itype = row.get("type", "").strip().upper()
        ivalue = row.get("value", "").strip().lower()
        iverdict = row.get("verdict", "MALICIOUS").strip().upper()
        iconf = float(row.get("confidence", 0.9))
        inotes = row.get("notes", "")

        if not itype or not ivalue:
            errors.append(f"Row {idx}: Missing type or value")
            continue

        existing = (
            db.query(ThreatIntelEntry)
            .filter(ThreatIntelEntry.indicator_type == itype, ThreatIntelEntry.canonical_value == ivalue)
            .first()
        )
        if existing:
            existing.verdict = iverdict
            existing.confidence = iconf
            existing.notes = inotes
            existing.source = source_label
        else:
            new_entry = ThreatIntelEntry(
                indicator_type=itype,
                canonical_value=ivalue,
                verdict=iverdict,
                confidence=iconf,
                notes=inotes,
                source=source_label
            )
            db.add(new_entry)
        imported_count += 1

    db.commit()
    return {"imported": imported_count, "errors": errors}


def import_indicators_from_stix(db: Session, stix_json_str: str, source_label: str = "STIX_BUNDLE") -> Dict[str, Any]:
    """
    F08: Import IOCs from STIX 2.1 Bundle (Indicator objects).
    """
    try:
        bundle = json.loads(stix_json_str)
    except Exception as e:
        return {"imported": 0, "errors": [f"Invalid JSON: {str(e)}"]}

    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
    imported_count = 0

    for obj in objects:
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            name = obj.get("name", "")
            description = obj.get("description", "")
            
            # Simple pattern parsing: [domain-name:value = 'evil.com'] or [ipv4-addr:value = '1.2.3.4']
            import re
            dom_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
            ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
            hash_match = re.search(r"file:hashes\.(?:SHA-256|MD5)\s*=\s*'([^']+)'", pattern)

            if dom_match:
                itype, ival = "DOMAIN", dom_match.group(1).lower()
            elif ip_match:
                itype, ival = "IPV4", ip_match.group(1).lower()
            elif hash_match:
                itype, ival = "HASH_SHA256", hash_match.group(1).lower()
            else:
                continue

            existing = db.query(ThreatIntelEntry).filter(ThreatIntelEntry.indicator_type == itype, ThreatIntelEntry.canonical_value == ival).first()
            if existing:
                existing.verdict = "MALICIOUS"
                existing.notes = f"{name}: {description}"
            else:
                db.add(ThreatIntelEntry(
                    indicator_type=itype,
                    canonical_value=ival,
                    verdict="MALICIOUS",
                    confidence=0.95,
                    notes=f"{name}: {description}",
                    source=source_label
                ))
            imported_count += 1

    db.commit()
    return {"imported": imported_count, "errors": []}
