import pytest
import pytest_asyncio
from uuid import uuid4
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.core.migrations import run_safe_schema_migrations
from app.models.models import Scan, Target, Endpoint, Parameter, Finding
from app.models.discovery import DiscoveredAsset, ScanStage, StageStatus
from app.scanner.graph.builder import AttackSurfaceGraphBuilder, NodeType
from app.api.scans import get_scan_graph, get_scan_inventory

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

@pytest_asyncio.fixture
async def async_session():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    await run_safe_schema_migrations()
    
    async_session_factory = sessionmaker(
        engine, expire_on_commit=False, class_=AsyncSession
    )
    async with async_session_factory() as session:
        yield session
    
    await engine.dispose()

@pytest.mark.asyncio
async def test_attack_surface_graph_depth_traversal(async_session: AsyncSession):
    """
    Verify server-side BFS traversal limits edge distance from root node
    according to max_depth (bounds: 3 to 10, default 5).
    """
    scan_id = f"test-depth-{uuid4().hex[:8]}"
    target_id = f"target-{uuid4().hex[:8]}"
    target = Target(id=target_id, name="Test Depth Target", base_url="http://test-depth.local")
    async_session.add(target)
    
    scan = Scan(
        id=scan_id,
        target_id=target_id,
        status="COMPLETED",
        started_at=datetime.now(timezone.utc)
    )
    async_session.add(scan)
    await async_session.commit()

    # Create a chain of endpoints:
    # Root (Target) -> Domain (depth 1) -> ep1 (depth 2) -> param1 (depth 3) -> finding1 (depth 4)
    ep1 = Endpoint(
        id=f"ep-1-{uuid4().hex[:6]}",
        scan_id=scan_id,
        url="http://test-depth.local/api/v1/users",
        path="/api/v1/users",
        method="GET",
        depth=1
    )
    async_session.add(ep1)
    await async_session.commit()

    param1 = Parameter(
        id=f"param-1-{uuid4().hex[:6]}",
        endpoint_id=ep1.id,
        name="user_id",
        location="query",
        value_type="integer"
    )
    async_session.add(param1)
    await async_session.commit()

    finding1 = Finding(
        id=f"f-1-{uuid4().hex[:6]}",
        scan_id=scan_id,
        endpoint_id=ep1.id,
        parameter_id=param1.id,
        parameter_name="user_id",
        vulnerability_type="SQL_INJECTION",
        severity="CRITICAL",
        confidence="CONFIRMED",
        status="CONFIRMED"
    )
    async_session.add(finding1)
    await async_session.commit()

    # 1. Test builder with max_depth = 3
    builder_depth_3 = AttackSurfaceGraphBuilder(async_session, scan_id, max_depth=3)
    graph_3 = await builder_depth_3.build()
    
    assert graph_3.graph.get("max_depth") == 3
    # Target (0), Domain (1), Endpoint (2), Parameter (3) should be within depth 3
    # Finding is distance 4, so it should be pruned at depth 3
    assert not graph_3.has_node(f"finding_{finding1.id}")
    assert graph_3.has_node(f"param_{param1.id}")
    assert graph_3.has_node(f"endpoint_{ep1.id}")

    # 2. Test builder with max_depth = 5 (default)
    builder_depth_5 = AttackSurfaceGraphBuilder(async_session, scan_id, max_depth=5)
    graph_5 = await builder_depth_5.build()
    assert graph_5.graph.get("max_depth") == 5
    # At depth 5, finding1 (distance 4) is included
    assert graph_5.has_node(f"finding_{finding1.id}")
    assert graph_5.has_node(f"param_{param1.id}")

@pytest.mark.asyncio
async def test_attack_surface_graph_high_risk_only_filter(async_session: AsyncSession):
    """
    Verify high_risk_only=True preserves CRITICAL and HIGH findings and their
    attack paths while pruning unrelated Low/Medium branches.
    """
    scan_id = f"test-hr-{uuid4().hex[:8]}"
    target_id = f"target-{uuid4().hex[:8]}"
    target = Target(id=target_id, name="Test HR Target", base_url="http://test-hr.local")
    async_session.add(target)
    
    scan = Scan(
        id=scan_id,
        target_id=target_id,
        status="COMPLETED",
        started_at=datetime.now(timezone.utc)
    )
    async_session.add(scan)
    await async_session.commit()

    # Endpoint A: has CRITICAL finding
    ep_a = Endpoint(
        id=f"ep-a-{uuid4().hex[:6]}",
        scan_id=scan_id,
        url="http://test-hr.local/api/admin",
        path="/api/admin",
        method="POST"
    )
    # Endpoint B: has LOW informational finding
    ep_b = Endpoint(
        id=f"ep-b-{uuid4().hex[:6]}",
        scan_id=scan_id,
        url="http://test-hr.local/about",
        path="/about",
        method="GET"
    )
    async_session.add_all([ep_a, ep_b])
    await async_session.commit()

    f_crit = Finding(
        id=f"f-crit-{uuid4().hex[:6]}",
        scan_id=scan_id,
        endpoint_id=ep_a.id,
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        status="CONFIRMED"
    )
    f_low = Finding(
        id=f"f-low-{uuid4().hex[:6]}",
        scan_id=scan_id,
        endpoint_id=ep_b.id,
        vulnerability_type="HEADER_DISCLOSURE",
        severity="LOW",
        status="CONFIRMED"
    )
    async_session.add_all([f_crit, f_low])
    await async_session.commit()

    # Query with high_risk_only=True
    builder_hr = AttackSurfaceGraphBuilder(async_session, scan_id, max_depth=5, high_risk_only=True)
    graph_hr = await builder_hr.build()

    assert graph_hr.graph.get("high_risk_only") is True
    # The Critical finding and its parent endpoint must be visible
    assert graph_hr.has_node(f"finding_{f_crit.id}")
    assert graph_hr.has_node(f"endpoint_{ep_a.id}")
    # The Low finding must NOT be visible
    assert not graph_hr.has_node(f"finding_{f_low.id}")
    assert not graph_hr.has_node(f"endpoint_{ep_b.id}")

@pytest.mark.asyncio
async def test_coverage_and_gaps_measured_metrics(async_session: AsyncSession):
    """
    Verify get_scan_inventory provides genuine measured Section 13 metrics
    (pages discovered/visited/failed, runtime vs source endpoints, source files, subsystem statuses).
    """
    scan_id = f"test-cov-{uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id,
        target_id="target-cov",
        status="COMPLETED",
        discovery_mode="HYBRID",
        started_at=datetime.now(timezone.utc)
    )
    async_session.add(scan)

    # Add ScanStage records
    s1 = ScanStage(
        scan_id=scan_id,
        stage_name="BROWSER_CRAWLING",
        stage_status="COMPLETED",
        output_count=8,
        successful_count=7,
        failed_count=1
    )
    s2 = ScanStage(
        scan_id=scan_id,
        stage_name="SOURCE_INVENTORY",
        stage_status="COMPLETED",
        output_count=42,
        successful_count=42
    )
    s3 = ScanStage(
        scan_id=scan_id,
        stage_name="SOURCE_EXTRACTION",
        stage_status="COMPLETED",
        successful_count=40,
        skipped_count=2,
        failed_count=0
    )
    s4 = ScanStage(
        scan_id=scan_id,
        stage_name="SOURCE_RUNTIME_CORRELATION",
        stage_status="COMPLETED"
    )
    s5 = ScanStage(
        scan_id=scan_id,
        stage_name="VULNERABILITY_VALIDATION",
        stage_status="COMPLETED"
    )
    async_session.add_all([s1, s2, s3, s4, s5])

    # Add assets
    a_matched = DiscoveredAsset(
        id=f"asset-{uuid4().hex[:6]}",
        identifier="POST:/api/login",
        scan_id=scan_id,
        asset_type="HTTP_ENDPOINT",
        discovery_status="SOURCE_AND_RUNTIME_MATCH",
        path="/api/login",
        method="POST"
    )
    a_source = DiscoveredAsset(
        id=f"asset-{uuid4().hex[:6]}",
        identifier="GET:/api/internal/debug",
        scan_id=scan_id,
        asset_type="HTTP_ENDPOINT",
        discovery_status="SOURCE_DEFINED",
        path="/api/internal/debug",
        method="GET"
    )
    async_session.add_all([a_matched, a_source])
    await async_session.commit()

    inv_res = await get_scan_inventory(scan_id=scan_id, db=async_session)

    assert inv_res.coverage_gaps is not None
    cg = inv_res.coverage_gaps
    assert cg.pages_discovered == 8
    assert cg.pages_visited >= 7
    assert cg.pages_failed == 1
    assert cg.source_files_inventoried == 42
    assert cg.source_files_analyzed == 40
    assert cg.source_files_skipped == 2
    assert cg.source_files_failed == 0
    assert cg.browser_discovery_status == "COMPLETED"
    assert cg.correlation_status == "COMPLETED"
    assert cg.validation_status == "COMPLETED"
    assert cg.matched_endpoints == 1
    assert cg.source_only_endpoints == 1
    assert len(cg.coverage_notes) > 0
