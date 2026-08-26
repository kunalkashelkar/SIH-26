import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import engine, Base
import app.models.models
from app.core.seeder import seed_initial_data

from app.api.health import router as health_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.targets import router as targets_router
from app.api.projects import router as projects_router
from app.api.payloads import router as payloads_router
from app.api.reports import router as reports_router

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database schema is created
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Seed initial payload library, project, and target
    await seed_initial_data()
    yield

app = FastAPI(
    title="Sentinel Web Application Fuzzer Backend",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "message": str(exc)},
    )

# Mount routers
app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings_router, prefix="/api/findings", tags=["Findings"])
app.include_router(targets_router, prefix="/api/targets", tags=["Targets"])
app.include_router(projects_router, prefix="/api/projects", tags=["Projects"])
app.include_router(payloads_router, prefix="/api/payloads", tags=["Payloads"])
app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
