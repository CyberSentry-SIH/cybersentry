from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.app.core.database import get_db
from backend.app.core.config import settings

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_status = "HEALTHY"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"UNHEALTHY: {str(e)}"

    return {
        "status": "OK",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "llm_enabled": settings.ENABLE_LLM
    }
