import os
import glob
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.core.security import get_password_hash
from backend.app.models import User, ThreatIntelEntry, Evidence
from backend.app.services.evidence_service import create_evidence
from backend.app.services.detection_service import process_email_analysis
from backend.app.core.config import settings

def seed_database():
    print("[CyberSentry Seed] Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    if not settings.SEED_DEMO_DATA:
        print("[CyberSentry Seed] SEED_DEMO_DATA is False. Skipping demo data insertion.")
        return
    db: Session = SessionLocal()

    try:
        # 1. Seed Users
        # NOTE (security): these are fixed demo credentials for local
        # evaluation/judging convenience only. They were previously ALSO
        # hardcoded into the frontend login page's source (now removed --
        # see app/login/page.tsx), which means they've already been shipped
        # to any browser that loaded that page and must be treated as
        # public knowledge, not a secret. Never reuse these values, or this
        # seeding pattern, for a real deployment -- rotate them (or disable
        # seeding entirely) before this app is exposed anywhere beyond a
        # local demo/judging environment.
        admin_email = "admin@cybersentry.local"
        analyst_email = "analyst@cybersentry.local"

        guest_email = "guest@cybersentry.local"

        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin = User(
                email=admin_email,
                password_hash=get_password_hash("Admin@CyberSentry123!"),
                full_name="SOC Security Administrator",
                role="ADMINISTRATOR",
                is_active=True
            )
            db.add(admin)
            print(f" [+] Created Admin: {admin_email}")

        analyst = db.query(User).filter(User.email == analyst_email).first()
        if not analyst:
            analyst = User(
                email=analyst_email,
                password_hash=get_password_hash("Analyst@CyberSentry123!"),
                full_name="Lead SOC Analyst",
                role="ANALYST",
                is_active=True
            )
            db.add(analyst)
            print(f" [+] Created Analyst: {analyst_email}")

        guest = db.query(User).filter(User.email == guest_email).first()
        if not guest:
            guest = User(
                email=guest_email,
                password_hash=get_password_hash("Guest@CyberSentry123!"),
                full_name="Guest Forensics Evaluator",
                role="ANALYST",
                is_active=True
            )
            db.add(guest)
            print(f" [+] Created Guest: {guest_email}")

        db.commit()
        db.refresh(analyst)

        # 2. Seed Threat Intel
        intel_path = os.path.join(os.path.dirname(__file__), "../../data/threat-intel/seed_indicators.json")
        if os.path.exists(intel_path):
            with open(intel_path, "r") as f:
                entries = json.load(f)
                for item in entries:
                    existing = (
                        db.query(ThreatIntelEntry)
                        .filter(
                            ThreatIntelEntry.indicator_type == item["indicator_type"],
                            ThreatIntelEntry.canonical_value == item["canonical_value"],
                            ThreatIntelEntry.source == item["source"]
                        )
                        .first()
                    )
                    if not existing:
                        db.add(ThreatIntelEntry(
                            indicator_type=item["indicator_type"],
                            canonical_value=item["canonical_value"],
                            verdict=item["verdict"],
                            source=item["source"],
                            confidence=item.get("confidence", 0.95),
                            notes=item.get("notes")
                        ))
            db.commit()
            print(" [+] Seeded offline threat intelligence indicators.")

        # 2b. Seed high-confidence indicators from Kaggle phishing dataset
        from backend.app.services.kaggle_dataset_service import ingest_kaggle_phishing_indicators
        k_count = ingest_kaggle_phishing_indicators(db=db, sample_limit=1000)
        if k_count > 0:
            print(f" [+] Seeded {k_count} indicators from Kaggle phishing dataset.")

        # 3. Ingest synthetic samples if no evidence yet
        if db.query(Evidence).count() == 0:
            print(" [+] Ingesting synthetic evaluation dataset...")
            synthetic_dir = os.path.join(os.path.dirname(__file__), "../../data/synthetic")
            eml_files = sorted(glob.glob(os.path.join(synthetic_dir, "*.eml")))

            for eml_path in eml_files:
                filename = os.path.basename(eml_path)
                with open(eml_path, "rb") as f:
                    file_bytes = f.read()
                
                evidence, _ = create_evidence(
                    db=db,
                    filename=filename,
                    file_bytes=file_bytes,
                    collector_user=analyst
                )
                print(f"   -> Processing {filename} ({evidence.evidence_id})...")
                process_email_analysis(db=db, evidence=evidence, actor_user=analyst)

            print(" [+] Successfully analyzed and indexed all synthetic sample emails.")

        print("[CyberSentry Seed] Database initialization and seed completed successfully!")

    except Exception as e:
        db.rollback()
        print(f"[CyberSentry Seed] Error during seeding: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
