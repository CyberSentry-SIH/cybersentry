import os
import uuid
from datetime import datetime, timezone
from typing import Generator
from sqlalchemy import create_engine, TypeDecorator, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.app.core.config import settings

class UTCDateTime(TypeDecorator):
    """
    SQLAlchemy TypeDecorator for timezone-aware UTC datetime fields.
    Ensures datetime is stored and retrieved consistently with timezone.utc,
    preventing SQLite/Postgres timezone stripping from invalidating forensic hashes.
    """
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if not isinstance(value, datetime):
                return value
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            if not isinstance(value, datetime):
                return value
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value

db_url = settings.DATABASE_URL

# Normalize sqlite URL connect args
connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    echo=False,
    connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_uuid() -> str:
    return str(uuid.uuid4())
