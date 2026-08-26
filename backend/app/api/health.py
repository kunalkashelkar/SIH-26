from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.database import get_db
from app.ml.engine import MLEngine

router = APIRouter()

@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    # 1. Test database connection
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    # 2. Check ML engine
    ml_engine = MLEngine.get_instance()

    return {
        "status": "ok" if db_ok else "degraded",
        "service": "sentinel-security-backend",
        "components": {
            "backend": "healthy",
            "database": "connected" if db_ok else "disconnected",
            "ml_model": "loaded" if (ml_engine.is_ready and ml_engine.model is not None) else "offline",
            "preprocessor": "loaded" if (ml_engine.is_ready and ml_engine.preprocessor is not None) else "offline",
            "scanner": "ready"
        }
    }
