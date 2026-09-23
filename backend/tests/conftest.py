import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.config import settings
from backend.app.core.database import Base, get_db
from backend.app.core.security import get_password_hash
from backend.app.models import User, ThreatIntelEntry, Evidence
from backend.app.services.evidence_service import create_evidence
from backend.app.services.detection_service import process_email_analysis
from backend.app.main import app

# Create a temporary directory for test DB and evidence
_temp_dir = tempfile.TemporaryDirectory()
_test_db_path = os.path.join(_temp_dir.name, "test_cybersentry.db")
_test_evidence_path = os.path.join(_temp_dir.name, "test_evidence_store")
os.makedirs(_test_evidence_path, exist_ok=True)

_test_db_url = f"sqlite:///{_test_db_path}"

# Point settings to test locations
settings.DATABASE_URL = _test_db_url
settings.EVIDENCE_STORAGE_PATH = _test_evidence_path
settings.ENVIRONMENT = "development"
settings.SEED_DEMO_DATA = False
settings.ENABLE_LLM = False
settings.ENABLE_EXTERNAL_INTEL = False



_test_engine = create_engine(
    _test_db_url,
    echo=False,
    connect_args={"check_same_thread": False}
)
_TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create all tables and seed standard test users and samples in temp DB."""
    # Ensure fresh schema
    Base.metadata.drop_all(bind=_test_engine)
    Base.metadata.create_all(bind=_test_engine)

    db = _TestSessionLocal()
    try:
        # Seed users
        admin = User(
            email="admin@cybersentry.local",
            password_hash=get_password_hash("Admin@CyberSentry123!"),
            full_name="SOC Security Administrator",
            role="ADMINISTRATOR",
            is_active=True
        )
        analyst = User(
            email="analyst@cybersentry.local",
            password_hash=get_password_hash("Analyst@CyberSentry123!"),
            full_name="Lead SOC Analyst",
            role="ANALYST",
            is_active=True
        )
        viewer = User(
            email="guest@cybersentry.local",
            password_hash=get_password_hash("Guest@CyberSentry123!"),
            full_name="Guest Forensics Evaluator",
            role="VIEWER",
            is_active=True
        )
        db.add_all([admin, analyst, viewer])
        db.commit()
        db.refresh(analyst)

        # Seed sample threat intel
        sample_intel = [
            ThreatIntelEntry(
                indicator_type="DOMAIN",
                canonical_value="paypa1-security-update.com",
                verdict="MALICIOUS",
                source="SEED_INTEL",
                confidence=0.95,
                notes="Known credential harvesting phishing domain"
            ),
            ThreatIntelEntry(
                indicator_type="IPV4",
                canonical_value="185.220.101.5",
                verdict="MALICIOUS",
                source="SEED_INTEL",
                confidence=0.90,
                notes="Known bulletproof host / Tor exit relay"
            )
        ]
        db.add_all(sample_intel)
        db.commit()

        # Seed synthetic samples
        synthetic_dir = os.path.join(os.path.dirname(__file__), "../../data/synthetic")
        if os.path.exists(synthetic_dir):
            import glob
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
                process_email_analysis(db=db, evidence=evidence, actor_user=analyst)

        yield
    finally:
        db.close()
        _temp_dir.cleanup()

def override_get_db():
    db = _TestSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture(scope="session")
def analyst_headers(client):
    res = client.post(
        "/api/v1/auth/login",
        json={
            "email": "analyst@cybersentry.local",
            "password": "Analyst@CyberSentry123!"
        },
        headers={"X-Requested-With": "CyberSentryClient"}
    )
    assert res.status_code == 200, f"Analyst login failed: {res.text}"
    token = res.json()["access_token"]
    return {
        "Authorization": f"Bearer {token}",
        "X-Requested-With": "CyberSentryClient"
    }

@pytest.fixture(scope="session")
def admin_headers(client):
    res = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@cybersentry.local",
            "password": "Admin@CyberSentry123!"
        },
        headers={"X-Requested-With": "CyberSentryClient"}
    )
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    token = res.json()["access_token"]
    return {
        "Authorization": f"Bearer {token}",
        "X-Requested-With": "CyberSentryClient"
    }

@pytest.fixture(scope="session")
def viewer_headers(client):
    res = client.post(
        "/api/v1/auth/login",
        json={
            "email": "guest@cybersentry.local",
            "password": "Guest@CyberSentry123!"
        },
        headers={"X-Requested-With": "CyberSentryClient"}
    )
    assert res.status_code == 200, f"Viewer login failed: {res.text}"
    token = res.json()["access_token"]
    return {
        "Authorization": f"Bearer {token}",
        "X-Requested-With": "CyberSentryClient"
    }

@pytest.fixture
def db_session():
    db = _TestSessionLocal()
    try:
        yield db
    finally:
        db.close()
