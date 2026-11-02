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
from app.api.repositories import router as repositories_router
from app.api.endpoints import router as endpoints_router
from app.api.ml import router as ml_router
from app.ml.engine import MLEngine

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
    # Apply additive migrations
    from app.core.migrations import run_safe_schema_migrations
    await run_safe_schema_migrations()
    # Seed initial payload library, project, and target
    await seed_initial_data()
    # Initialize ML Inference Engine (loads Phase 14 model & preprocessor)
    ml_engine = MLEngine.get_instance()
    if ml_engine.is_ready:
        logger.info("ML Inference Engine ready on application startup.")
    else:
        logger.warning("ML Inference Engine initialized with warnings (check final_model directory).")
    # Recover interrupted scans from previous process/worker restarts
    from app.scanner.orchestrator import scan_orchestrator
    await scan_orchestrator.recover_interrupted_scans()
    yield

app = FastAPI(
    title="Sentinel Web Application Fuzzer Backend",
    version="1.0.0",
    lifespan=lifespan
)

from app.middleware.request_id import RequestIdMiddleware, get_current_request_id
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.core.exceptions import AppException, format_error_response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

# Configure CORS
origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests=200, window_seconds=60)

# Centralized exception handlers
@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()
    logger.warning(f"[{req_id}] AppException ({exc.code}): {exc.message}")
    return JSONResponse(
        status_code=exc.status_code,
        content=format_error_response(
            code=exc.code,
            message=exc.message,
            request_id=req_id,
            details=exc.details
        )
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()
    logger.warning(f"[{req_id}] Validation error: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content=format_error_response(
            code="VALIDATION_ERROR",
            message="Request validation failed",
            request_id=req_id,
            details={"errors": str(exc.errors())}
        )
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()
    return JSONResponse(
        status_code=exc.status_code,
        content=format_error_response(
            code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            request_id=req_id
        )
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", None) or get_current_request_id()
    logger.error(f"[{req_id}] Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=format_error_response(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected error occurred. Please contact support.",
            request_id=req_id
        )
    )

# Mount routers - Legacy & v1 conventions
app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(health_router, prefix="/api/v1", tags=["Health"])

app.include_router(repositories_router, prefix="/api/repositories", tags=["Repositories"])
app.include_router(repositories_router, prefix="/api/v1/repositories", tags=["Repositories"])

app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(scans_router, prefix="/api/v1/scans", tags=["Scans"])

app.include_router(findings_router, prefix="/api/findings", tags=["Findings"])
app.include_router(findings_router, prefix="/api/v1/findings", tags=["Findings"])

app.include_router(targets_router, prefix="/api/targets", tags=["Targets"])
app.include_router(targets_router, prefix="/api/v1/targets", tags=["Targets"])

app.include_router(projects_router, prefix="/api/projects", tags=["Projects"])
app.include_router(projects_router, prefix="/api/v1/projects", tags=["Projects"])

app.include_router(payloads_router, prefix="/api/payloads", tags=["Payloads"])
app.include_router(payloads_router, prefix="/api/v1/payloads", tags=["Payloads"])

app.include_router(reports_router, prefix="/api/reports", tags=["Reports"])
app.include_router(reports_router, prefix="/api/v1/reports", tags=["Reports"])

app.include_router(endpoints_router, prefix="/api/endpoints", tags=["Endpoints"])
app.include_router(endpoints_router, prefix="/api/v1/endpoints", tags=["Endpoints"])

app.include_router(ml_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
