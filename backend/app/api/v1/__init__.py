from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.targets import router as targets_router
from app.api.projects import router as projects_router
from app.api.payloads import router as payloads_router
from app.api.reports import router as reports_router
from app.api.repositories import router as repositories_router
from app.api.endpoints import router as endpoints_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router, tags=["Health"])
api_v1_router.include_router(scans_router, prefix="/scans", tags=["Scans"])
api_v1_router.include_router(findings_router, prefix="/findings", tags=["Findings"])
api_v1_router.include_router(targets_router, prefix="/targets", tags=["Targets"])
api_v1_router.include_router(projects_router, prefix="/projects", tags=["Projects"])
api_v1_router.include_router(payloads_router, prefix="/payloads", tags=["Payloads"])
api_v1_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
api_v1_router.include_router(repositories_router, prefix="/repositories", tags=["Repositories"])
api_v1_router.include_router(endpoints_router, prefix="/endpoints", tags=["Endpoints"])
