from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, case

from app.models.models import Scan, Endpoint, Finding, Parameter, Subdomain
from app.schemas.scans import DashboardMetricsResponse

class DashboardService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_metrics(self, user_id: Optional[str] = None) -> DashboardMetricsResponse:
        """
        Calculate global or tenant-scoped dashboard metrics using optimized
        database-level aggregation queries instead of loading full tables into memory.
        """
        # 1. Aggregate Scan counts
        scan_stmt = select(
            func.count(Scan.id).label("total"),
            func.count(case((Scan.status == "COMPLETED", 1))).label("completed"),
            func.count(case((Scan.status.in_(["RUNNING", "QUEUED"]), 1))).label("running"),
            func.count(case((Scan.status == "FAILED", 1))).label("failed")
        )
        if user_id:
            scan_stmt = scan_stmt.where(Scan.user_id == user_id)
        
        scan_counts = (await self.db.execute(scan_stmt)).one()
        total_scans = scan_counts.total or 0
        completed_scans = scan_counts.completed or 0
        running_scans = scan_counts.running or 0
        failed_scans = scan_counts.failed or 0

        # 2. Aggregate Endpoint counts
        ep_stmt = select(
            func.count(Endpoint.id).label("total"),
            func.count(case((Endpoint.is_api.is_(True), 1))).label("apis")
        )
        ep_counts = (await self.db.execute(ep_stmt)).one()
        total_endpoints = ep_counts.total or 0
        total_apis = ep_counts.apis or 0

        # 3. Parameters count
        param_res = await self.db.execute(select(func.count(Parameter.id)))
        total_parameters = param_res.scalar() or 0

        # 4. Subdomains count
        sub_res = await self.db.execute(select(func.count(Subdomain.id)))
        total_subdomains = sub_res.scalar() or 0

        # 5. Aggregate Finding counts by severity and status
        finding_stmt = select(
            func.count(Finding.id).label("total"),
            func.count(case((Finding.severity == "CRITICAL", 1))).label("critical"),
            func.count(case((Finding.severity == "HIGH", 1))).label("high"),
            func.count(case((Finding.severity == "MEDIUM", 1))).label("medium"),
            func.count(case((Finding.severity == "LOW", 1))).label("low"),
            func.count(case((Finding.status.in_(["verified", "verified_fixed"]), 1))).label("validated"),
            func.count(case((Finding.status == "open", 1))).label("open"),
            func.count(case((Finding.status == "verified_fixed", 1))).label("resolved")
        )
        f_counts = (await self.db.execute(finding_stmt)).one()
        total_findings = f_counts.total or 0
        critical_findings = f_counts.critical or 0
        high_findings = f_counts.high or 0
        medium_findings = f_counts.medium or 0
        low_findings = f_counts.low or 0
        validated_findings = f_counts.validated or 0
        open_findings = f_counts.open or 0
        resolved_findings = f_counts.resolved or 0

        # Contextual Risk Score calculation
        risk_score = 0.0
        if total_findings > 0:
            raw_score = (
                critical_findings * 9.5 +
                high_findings * 7.5 +
                medium_findings * 4.5 +
                low_findings * 2.0
            ) / max(total_findings, 1)
            risk_score = round(min(raw_score, 10.0), 1)

        return DashboardMetricsResponse(
            total_scans=total_scans,
            completed_scans=completed_scans,
            running_scans=running_scans,
            failed_scans=failed_scans,
            total_endpoints=total_endpoints,
            total_apis=total_apis,
            total_parameters=total_parameters,
            total_subdomains=total_subdomains,
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            validated_findings=validated_findings,
            open_findings=open_findings,
            resolved_findings=resolved_findings,
            risk_score=risk_score
        )
