import pytest
import asyncio
import uuid
import concurrent.futures
from sqlalchemy import select

from app.core.database import AsyncSessionLocal, engine, Base
from app.core.migrations import run_safe_schema_migrations
from app.models.models import (
    Target, Scan, Endpoint, Parameter, Finding, Evidence,
    DiscoveredAsset, AssetType, DiscoveryStatus
)
from app.scanner.http_client import ResilientHttpClient, is_safe_target_url
from app.scanner.fuzzer.payload_manager import PayloadManager
from app.scanner.context.parameter_context import ParameterContext
from app.scanner.analysis.anomaly import AnomalyReport, DifferentialSignals
from app.scanner.validation.validator import EvidenceValidator
from app.scanner.orchestrator.orchestrator import ScanOrchestrator

@pytest.fixture(autouse=True, scope="function")
def setup_test_db():
    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await run_safe_schema_migrations()
    
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(asyncio.run, _setup()).result()
    else:
        asyncio.run(_setup())

@pytest.mark.asyncio
async def test_ssrf_safety_checks():
    # Cloud metadata must be blocked unconditionally
    assert not is_safe_target_url("http://169.254.169.254/latest/meta-data/")
    assert not is_safe_target_url("http://metadata.google.internal/computeMetadata/v1/")
    assert not is_safe_target_url("http://100.100.100.200/")

    # Loopback / localhost allowed when allow_localhost=True
    assert is_safe_target_url("http://localhost:8000/api/test", allow_localhost=True)
    assert is_safe_target_url("http://127.0.0.1:3000/rest/user/login", allow_localhost=True)
    assert not is_safe_target_url("http://127.0.0.1:3000/rest/user/login", allow_localhost=False)

    # Valid external URLs
    assert is_safe_target_url("https://example.com/api/v1")
    assert not is_safe_target_url("ftp://example.com/resource")

@pytest.mark.asyncio
async def test_payload_manager_boundary_expansion():
    ep = Endpoint(id="ep-1", url="http://localhost:8000/api/items", method="GET")
    
    # Numeric parameter should get boundary tests
    ctx_num = ParameterContext(
        parameter_id="p-1",
        endpoint_id="ep-1",
        parameter="user_id",
        location="query",
        type="numeric",
        endpoint_type="api",
        method="GET",
        content_type="application/json",
        is_sensitive=False,
        recommended_tests=["IDOR"]
    )
    tests = PayloadManager.generate_tests_for_parameter("scan-1", ep, ctx_num)
    categories = [t.category for t in tests]
    assert "BOUNDARY" in categories
    payloads = [t.payload for t in tests]
    assert any(p in ["0", "-1", "2147483647"] for p in payloads)

@pytest.mark.asyncio
async def test_validator_finding_persistence():
    async with AsyncSessionLocal() as session:
        target_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        ep_id = str(uuid.uuid4())
        param_id = str(uuid.uuid4())

        target = Target(id=target_id, name="Test Target", base_url="http://localhost:8000")
        scan = Scan(id=scan_id, target_id=target_id, website_url="http://localhost:8000", status="RUNNING")
        ep = Endpoint(id=ep_id, scan_id=scan_id, url="http://localhost:8000/search", path="/search", method="GET")
        param = Parameter(id=param_id, endpoint_id=ep_id, name="q", location="query")
        session.add_all([target, scan, ep, param])
        await session.commit()

        diff = DifferentialSignals(
            baseline_status=200,
            test_status=500,
            status_code_changed=True,
            length_diff_bytes=150,
            length_diff_ratio=2.5,
            payload_reflected=False,
            sql_error_detected=True,
            server_error_triggered=True,
            content_type_changed=False
        )
        anomaly = AnomalyReport(
            test_id="t-1",
            scan_id=scan_id,
            endpoint_id=ep_id,
            parameter_id=param_id,
            parameter_name="q",
            category="SQLI",
            payload="' OR '1'='1",
            anomaly=True,
            score=95,
            signals=["SQL error message"],
            baseline_summary="HTTP 200, 200 bytes",
            test_summary="HTTP 500, SQL error",
            differential=diff
        )

        client = ResilientHttpClient(max_requests=10, allow_localhost=True)
        
        class MockResponse:
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

        async def mock_request(method, url, params=None, data=None, **kwargs):
            if params and params.get("q") == "' OR '1'='1":
                return MockResponse(500, "syntax error in sqlite3 query")
            return MockResponse(200, "safe result")

        client._request = mock_request

        validator = EvidenceValidator(session, scan_id, client)
        
        cancel_event = asyncio.Event()
        findings = await validator.validate_anomalies([anomaly], cancel_event)
        await client.close()

        # Verify findings persisted to DB without crashing
        assert len(findings) > 0
        saved = findings[0]
        assert saved.parameter_name == "q"
        assert saved.scan_id == scan_id
        assert saved.status == "verified"

@pytest.mark.asyncio
async def test_json_body_parameter_sync():
    async with AsyncSessionLocal() as session:
        target_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        asset_id = str(uuid.uuid4())

        target = Target(id=target_id, name="Test Target", base_url="http://localhost:8000")
        scan = Scan(id=scan_id, target_id=target_id, website_url="http://localhost:8000", status="RUNNING")
        asset = DiscoveredAsset(
            id=asset_id,
            scan_id=scan_id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="POST /api/login",
            name="/api/login",
            path="/api/login",
            url="http://localhost:8000/api/login",
            method="POST",
            discovery_status=DiscoveryStatus.RUNTIME_OBSERVED,
            metadata_json={
                "request_body": {
                    "username": "admin",
                    "password": "secret_password"
                }
            }
        )
        session.add_all([target, scan, asset])
        await session.commit()

        orchestrator = ScanOrchestrator()
        synced = await orchestrator._sync_all_assets_to_legacy(session, scan_id)
        assert synced == 1

        res = await session.execute(select(Parameter).where(Parameter.endpoint_id == asset_id))
        params = res.scalars().all()
        param_names = [p.name for p in params]
        assert "username" in param_names
        assert "password" in param_names
        for p in params:
            assert p.location == "body"
