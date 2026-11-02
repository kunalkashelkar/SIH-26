import pytest
import uuid
from sqlalchemy.future import select

from app.core.database import AsyncSessionLocal
from app.models.models import Target, Scan, Finding, Endpoint
from app.services.scan_service import ScanService
from app.services.finding_service import FindingService
from app.services.dashboard_service import DashboardService
from app.core.exceptions import NotFoundException, ForbiddenException

@pytest.mark.asyncio
async def test_scan_service_lifecycle_and_isolation():
    async with AsyncSessionLocal() as session:
        target = Target(name="Service Test", base_url="http://localhost:8000")
        scan_id_1 = str(uuid.uuid4())
        scan_1 = Scan(id=scan_id_1, target=target, user_id="user_alice", status="QUEUED")
        session.add_all([target, scan_1])
        await session.commit()

        service = ScanService(session)

        # 1. Successful fetch by owner
        fetched = await service.get_scan(scan_id_1, user_id="user_alice")
        assert fetched.id == scan_id_1

        # 2. Access denied for another user
        with pytest.raises(ForbiddenException):
            await service.get_scan(scan_id_1, user_id="user_bob")

        # 3. Not found for non-existent scan
        with pytest.raises(NotFoundException):
            await service.get_scan(str(uuid.uuid4()))

@pytest.mark.asyncio
async def test_dashboard_service_aggregation():
    async with AsyncSessionLocal() as session:
        target = Target(name="Dash Test", base_url="http://localhost:8000")
        scan = Scan(target=target, status="COMPLETED")
        session.add_all([target, scan])
        await session.flush()

        ep = Endpoint(scan_id=scan.id, url="http://localhost:8000/api/users", path="/api/users", method="GET", is_api=True)
        f_crit = Finding(scan_id=scan.id, severity="CRITICAL", status="verified", vulnerability_type="SQLI")
        f_high = Finding(scan_id=scan.id, severity="HIGH", status="open", vulnerability_type="XSS")
        session.add_all([ep, f_crit, f_high])
        await session.commit()

        dash_service = DashboardService(session)
        metrics = await dash_service.get_metrics()

        assert metrics.total_scans >= 1
        assert metrics.total_endpoints >= 1
        assert metrics.total_apis >= 1
        assert metrics.critical_findings >= 1
        assert metrics.high_findings >= 1
        assert metrics.risk_score > 0.0
