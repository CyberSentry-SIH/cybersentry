import os
import logging
import secrets
import warnings
from typing import List, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("cybersentry.config")

DEFAULT_INSECURE_SECRET_KEY = "cybersentry-super-secret-production-grade-signing-key-2026-sih"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "CyberSentry"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    SECRET_KEY: str = DEFAULT_INSECURE_SECRET_KEY
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"

    DATABASE_URL: str = "sqlite:///./cybersentry.db"
    EVIDENCE_STORAGE_PATH: str = "./evidence_store"
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024  # 25MB

    # Seeding
    SEED_DEMO_DATA: bool = True

    # Privacy & Evidence Retention
    RETENTION_DAYS: int = 365
    ENABLE_PII_MASKING: bool = True
    PRIVACY_MODE: str = "full"  # "off" | "metadata_only" | "full"
    EVIDENCE_ENCRYPTION_KEY: str = ""

    # Trust Boundary Configuration (Configurable Enterprise Perimeter)
    TRUSTED_GATEWAY_DOMAINS: List[str] = [
        "company-corp.com", "internal.corp", "mail.internal",
        "mx.google.com", "protection.outlook.com", "mimecast.com", "proofpoint.com"
    ]
    TRUSTED_GATEWAY_IPS: List[str] = [
        "203.0.113.10", "198.51.100.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    ]
    TRUSTED_AUTHSERV_IDS: List[str] = [
        "mx.google.com", "protection.outlook.com", "cybersentry.local", "mail.company-corp.com"
    ]

    # Shared Infrastructure Allowlist (Avoid false-cluster correlations)
    SHARED_INFRA_ALLOWLIST: List[str] = [
        "google.com", "gmail.com", "docs.google.com", "forms.gle", "drive.google.com",
        "microsoft.com", "outlook.com", "office365.com", "sharepoint.com",
        "sendgrid.net", "mailchimp.com", "amazonaws.com", "cloudflare.com",
        "bit.ly", "tinyurl.com", "t.co"
    ]

    # External AI & Threat Feeds (Optional with 100% Offline Fallback)
    ENABLE_LLM: bool = False
    GEMINI_API_KEY: str = ""
    LLM_PROVIDER: str = "gemini"
    LLM_MODEL: str = "gemini-1.5-flash"

    ENABLE_EXTERNAL_INTEL: bool = False
    VIRUSTOTAL_API_KEY: str = ""
    VT_SUBMIT_URLS: bool = False
    IPGEOLOCATION_API_KEY: str = ""

    # Offline GeoIP / Infrastructure Intelligence
    GEOIP_DB_PATH: str = "./data/GeoLite2-City.mmdb"
    GEOIP_ASN_DB_PATH: str = "./data/GeoLite2-ASN.mmdb"
    TOR_EXIT_LIST_URL: str = "https://check.torproject.org/torbulkexitlist"

    # URL Redirection Analysis
    ENABLE_REDIRECT_RESOLUTION: bool = False
    MAX_REDIRECT_HOPS: int = 5

    # Browser Extension & CORS
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:3001", "http://127.0.0.1:3001",
        "http://localhost:3002", "http://127.0.0.1:3002",
    ]
    EXTENSION_ALLOWED_ORIGINS: List[str] = []

    # Alerting Channels
    ALERT_WEBHOOK_URL: str = ""
    ALERT_WEBHOOK_SECRET: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "alerts@cybersentry.local"

    # IMAP Connector
    ENABLE_IMAP_POLLER: bool = False
    IMAP_HOST: str = ""
    IMAP_PORT: int = 993
    IMAP_USER: str = ""
    IMAP_PASSWORD: str = ""
    IMAP_FOLDER: str = "INBOX"
    IMAP_POLL_INTERVAL_SECONDS: int = 60

    @model_validator(mode="after")
    def validate_and_harden_secret_key(self) -> "Settings":
        env = (self.ENVIRONMENT or "development").lower()
        key = self.SECRET_KEY

        if env != "development":
            if key == DEFAULT_INSECURE_SECRET_KEY:
                raise ValueError(
                    "SECRET_KEY must not be the default insecure key in non-development environments! "
                    "Set a secure, high-entropy SECRET_KEY in your environment."
                )
            if len(key.encode("utf-8")) < 32:
                raise ValueError("SECRET_KEY must be at least 32 bytes (256 bits) in non-development environments.")
        else:
            if key == DEFAULT_INSECURE_SECRET_KEY or not key:
                generated = secrets.token_urlsafe(32)
                self.SECRET_KEY = generated
                warnings.warn(
                    "[SECURITY WARNING] Using an auto-generated ephemeral SECRET_KEY for development. "
                    "For persistent sessions across restarts, set a SECRET_KEY in your .env file."
                )
        return self

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, str):
            import json
            try:
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        return v

settings = Settings()

os.makedirs(settings.EVIDENCE_STORAGE_PATH, exist_ok=True)
