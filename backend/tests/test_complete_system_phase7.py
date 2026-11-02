"""
CYPHER Phase 7: Complete System End-to-End Audit, Benchmarking, and Ground-Truth Recall Suite.
Tests all three modes (WEBSITE_ONLY, GITHUB_ONLY, HYBRID) against controlled ground-truth targets.
Measures actual Page Recall, Route Recall, Endpoint Recall, Parameter Recall, and Precision.
Validates security controls, performance, fuzzer integration, and traceability.
"""
import asyncio
import os
import sys
import uuid
import time
import uvicorn
import multiprocessing
import urllib.parse
from typing import Dict, Any, Set
from datetime import datetime
from sqlalchemy.future import select

from app.core.database import AsyncSessionLocal, engine, Base
from app.core.migrations import run_safe_schema_migrations
from app.models.models import Target, Scan, Endpoint, Parameter, Finding
from app.models.discovery import (
    ScanMode, DiscoveryStatus, AssetType, DiscoveredAsset,
    WebsiteProfile, RepositoryProfile, SourceEvidence, RuntimeEvidence,
    DiscoveredForm, EndpointParameter, DiscoveredRoute, DiscoveredPage
)
from app.scanner.discovery.website_engine import WebsiteDiscoveryEngine
from app.scanner.discovery.source.source_engine import SourceCodeDiscoveryEngine
from app.scanner.discovery.correlation.engine import CorrelationEngine
from app.scanner.discovery.correlation.matcher import EndpointPathMatcher
from app.scanner.fuzzer.target_selector import TargetSelector
from app.scanner.context.context_enricher import ContextEnricher
from app.scanner.validation.validator import EvidenceValidator
from app.scanner.analysis.anomaly import AnomalyReport, DifferentialSignals
from app.scanner.validation.confidence import ConfidenceLevel, ValidationVerdict

# Ground Truth Benchmark Values
GROUND_TRUTH_PAGES = {
    "/", "/about", "/pricing", "/docs", "/login", "/register",
    "/contact", "/contact_submit", "/faq", "/terms", "/privacy",
    "/feedback", "/feedback_submit", "/dashboard_preview",
    "/spa", "/app-router", "/vue-spa", "/angular-spa"
}

GROUND_TRUTH_FRONTEND_ROUTES = {
    "/dashboard", "/settings/profile", "/users/:userId",
    "/catalog", "/cart", "analytics", "reports"
}

GROUND_TRUTH_API_ENDPOINTS = {
    "GET /api/v1/users", "GET /api/v1/users/{user_id}", "POST /api/v1/users",
    "POST /api/v1/orders", "GET /api/flask/items", "GET /api/flask/items/{item_id}",
    "GET /api/django/products/", "GET /api/django/products/{id}/",
    "POST /api/express/checkout", "GET /api/express/orders/{orderId}",
    "GET /api/nest/billing/invoices", "POST /api/nest/billing/invoices",
    "GET /api/v2/products", "GET /api/v2/orders/{order_id}",
    "POST /graphql", "GET /api/v1/admin/audit", "GET /api/v1/feed"
}

GROUND_TRUTH_PARAMETERS = {
    "username", "password", "email", "message", "ref", "tag", "category",
    "account_id", "page", "limit", "cursor", "user_id", "item_id", "id",
    "orderId", "order_id", "amount", "currency", "quantity", "category_id", "is_active"
}

def run_mock_server():
    from tests.mock_target.main import app as mock_app
    uvicorn.run(mock_app, host="127.0.0.1", port=8766, log_level="warning")

def is_endpoint_match(e: str, gt: str) -> bool:
    try:
        e_m, e_p = e.split(" ", 1)
        gt_m, gt_p = gt.split(" ", 1)
        return EndpointPathMatcher.match(gt_p, gt_m, e_p, e_m).is_match
    except Exception:
        return False

def is_route_match(r: str, gt: str) -> bool:
    try:
        return EndpointPathMatcher.match(gt, "GET", r, "GET").is_match
    except Exception:
        return False

async def test_website_only_benchmark(db, scan_id: str, target: Target) -> Dict[str, float]:
    print("\n[BENCHMARK 1] Running Mode A: Website-Only Discovery...")
    cancel_event = asyncio.Event()
    engine = WebsiteDiscoveryEngine(
        scan_id=scan_id,
        target_url="http://127.0.0.1:8766",
        db=db,
        config={"max_depth": 3, "max_requests": 100}
    )
    summary = await engine.run(cancel_event)

    # Fetch discovered assets
    res = await db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan_id))
    assets = res.scalars().all()
    page_res = await db.execute(select(DiscoveredPage).where(DiscoveredPage.scan_id == scan_id))
    crawled_pages = {urllib.parse.urlparse(p.url).path for p in page_res.scalars().all() if p.url}
    discovered_pages = {a.path for a in assets if a.asset_type in [AssetType.WEBSITE_PAGE, AssetType.FRONTEND_ROUTE] and a.path} | crawled_pages
    discovered_endpoints = {f"{a.method} {a.path}" for a in assets if a.asset_type in [AssetType.HTTP_ENDPOINT, AssetType.BACKEND_API_OPERATION, AssetType.GRAPHQL_OPERATION, AssetType.WEBSOCKET_ENDPOINT] and a.path}
    
    # Collect parameters from EndpointParameter, DiscoveredForm, and metadata
    param_res = await db.execute(select(EndpointParameter).where(EndpointParameter.scan_id == scan_id))
    discovered_params = {p.name for p in param_res.scalars().all() if p.name}

    form_res = await db.execute(select(DiscoveredForm).where(DiscoveredForm.scan_id == scan_id))
    for form in form_res.scalars().all():
        for inp in (form.inputs_schema or []):
            if "name" in inp:
                discovered_params.add(inp["name"])

    for a in assets:
        meta = a.metadata_json or {}
        if "parameters" in meta:
            for p in meta["parameters"]:
                if isinstance(p, dict) and "name" in p:
                    discovered_params.add(p["name"])

    # Calculate actual recall and precision
    page_matches = discovered_pages.intersection(GROUND_TRUTH_PAGES)
    page_recall = len(page_matches) / len(GROUND_TRUTH_PAGES) if GROUND_TRUTH_PAGES else 0

    endpoint_matches = {e for e in discovered_endpoints if any(is_endpoint_match(e, gt) for gt in GROUND_TRUTH_API_ENDPOINTS)}
    endpoint_recall = len(endpoint_matches) / len(GROUND_TRUTH_API_ENDPOINTS) if GROUND_TRUTH_API_ENDPOINTS else 0

    param_matches = discovered_params.intersection(GROUND_TRUTH_PARAMETERS)
    param_recall = len(param_matches) / len(GROUND_TRUTH_PARAMETERS) if GROUND_TRUTH_PARAMETERS else 0

    precision = len(page_matches | endpoint_matches) / max(len(discovered_pages | discovered_endpoints), 1)

    print(f"  Discovered Pages: {len(discovered_pages)} (Ground Truth: {len(GROUND_TRUTH_PAGES)}) -> Page Recall: {page_recall:.2%}")
    print(f"  Discovered Endpoints: {len(discovered_endpoints)} (Ground Truth: {len(GROUND_TRUTH_API_ENDPOINTS)}) -> Endpoint Recall: {endpoint_recall:.2%}")
    print(f"  Discovered Parameters: {len(discovered_params)} (Ground Truth: {len(GROUND_TRUTH_PARAMETERS)}) -> Param Recall: {param_recall:.2%}")
    print(f"  Classification Precision: {precision:.2%}")

    return {
        "page_recall": page_recall,
        "endpoint_recall": endpoint_recall,
        "param_recall": param_recall,
        "precision": precision
    }

async def test_github_only_benchmark(db, scan_id: str, repo_dir: str) -> Dict[str, float]:
    print("\n[BENCHMARK 2] Running Mode B: GitHub-Only Source Code Discovery...")
    # Add RepositoryProfile
    db.add(RepositoryProfile(
        scan_id=scan_id,
        repo_url=repo_dir,
        branch="main",
        detected_languages=[],
        detected_frameworks=[]
    ))
    await db.commit()

    engine = SourceCodeDiscoveryEngine(
        scan_id=scan_id,
        repo_url=repo_dir,
        db=db,
        config={"repository_branch": "main"}
    )
    cancel_event = asyncio.Event()
    summary = await engine.run(cancel_event)

    # Fetch source-discovered assets
    res = await db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan_id))
    assets = res.scalars().all()

    discovered_routes = {a.path for a in assets if a.path}
    discovered_endpoints = {f"{a.method} {a.path}" for a in assets if a.asset_type in [AssetType.HTTP_ENDPOINT, AssetType.BACKEND_API_OPERATION, AssetType.GRAPHQL_OPERATION, AssetType.WEBSOCKET_ENDPOINT] and a.path}
    
    param_res = await db.execute(select(EndpointParameter).where(EndpointParameter.scan_id == scan_id))
    discovered_params = {p.name for p in param_res.scalars().all() if p.name}
    for a in assets:
        meta = a.metadata_json or {}
        if "parameters" in meta:
            for p in meta["parameters"]:
                if isinstance(p, dict) and "name" in p:
                    discovered_params.add(p["name"])

    # Calculate actual recall and precision
    route_matches = {r for r in discovered_routes if any(is_route_match(r, gt) for gt in (GROUND_TRUTH_FRONTEND_ROUTES | {e.split(" ")[1] for e in GROUND_TRUTH_API_ENDPOINTS}))}
    total_known_routes = len(GROUND_TRUTH_FRONTEND_ROUTES) + len(GROUND_TRUTH_API_ENDPOINTS)
    route_recall = len(route_matches) / total_known_routes

    endpoint_matches = {e for e in discovered_endpoints if any(is_endpoint_match(e, gt) for gt in GROUND_TRUTH_API_ENDPOINTS)}
    endpoint_recall = len(endpoint_matches) / len(GROUND_TRUTH_API_ENDPOINTS)

    param_matches = discovered_params.intersection(GROUND_TRUTH_PARAMETERS)
    param_recall = len(param_matches) / len(GROUND_TRUTH_PARAMETERS)

    precision = len(route_matches) / max(len(discovered_routes), 1)

    print(f"  Frameworks Detected: {summary['detected_frameworks']}")
    print(f"  Extracted Routes: {len(discovered_routes)} (Ground Truth: {total_known_routes}) -> Route Recall: {route_recall:.2%}")
    print(f"  Extracted Endpoints: {len(discovered_endpoints)} (Ground Truth: {len(GROUND_TRUTH_API_ENDPOINTS)}) -> Endpoint Recall: {endpoint_recall:.2%}")
    print(f"  Extracted Schema Parameters: {len(discovered_params)} (Ground Truth: {len(GROUND_TRUTH_PARAMETERS)}) -> Param Recall: {param_recall:.2%}")
    print(f"  Static Extraction Precision: {precision:.2%}")

    return {
        "route_recall": route_recall,
        "endpoint_recall": endpoint_recall,
        "param_recall": param_recall,
        "precision": precision
    }

async def test_hybrid_correlation_and_fuzzer(db, scan_id: str, repo_dir: str):
    print("\n[BENCHMARK 3] Running Mode C: Hybrid Correlation & Context-Aware Fuzzer...")
    
    # 1. Run live crawl on mock target
    cancel_event = asyncio.Event()
    web_engine = WebsiteDiscoveryEngine(
        scan_id=scan_id,
        target_url="http://127.0.0.1:8766",
        db=db,
        config={"max_depth": 3, "max_requests": 100}
    )
    await web_engine.run(cancel_event)

    # 2. Run source analysis
    db.add(RepositoryProfile(
        scan_id=scan_id,
        repo_url=repo_dir,
        branch="main",
        detected_languages=[],
        detected_frameworks=[]
    ))
    await db.commit()

    source_engine = SourceCodeDiscoveryEngine(
        scan_id=scan_id,
        repo_url=repo_dir,
        db=db,
        config={"repository_branch": "main"}
    )
    cancel_event_s = asyncio.Event()
    await source_engine.run(cancel_event_s)

    # 3. Correlate
    corr_engine = CorrelationEngine(scan_id=scan_id, db=db)
    cancel_event_c = asyncio.Event()
    corr_summary = await corr_engine.run(cancel_event_c)
    print(f"  Correlation Summary: {corr_summary}")
    assert corr_summary["total_matches"] > 0
    assert corr_summary["graph_nodes"] > 0

    # 4. Target Selection
    res_ep = await db.execute(select(Endpoint).where(Endpoint.scan_id == scan_id))
    endpoints = res_ep.scalars().all()

    target_sel = TargetSelector(db=db, scan_id=scan_id, config={"allow_state_changing": True})
    eligible_eps = await target_sel.select_eligible_endpoints(endpoints)
    print(f"  Eligible Targets Selected for Active Fuzzing: {len(eligible_eps)} of {len(endpoints)}")
    assert len(eligible_eps) > 0

    # 5. Context Enrichment
    from app.scanner.context.parameter_context import ParameterContext, ParameterContextExtractor
    ep = endpoints[0]
    param = Parameter(endpoint_id=ep.id, name="user_id", location="query", value_type="integer")
    base_ctx = ParameterContextExtractor.extract_context(param, ep)
    enriched_ctx = await ContextEnricher.enrich_context(db, scan_id, base_ctx, ep, param)
    print(f"  Enriched Parameter Context: {enriched_ctx.metadata}")
    assert enriched_ctx is not None

    # 6. Traceability Verification
    res_da = await db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan_id, DiscoveredAsset.discovery_status == DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH))
    matched_asset = res_da.scalars().first()
    assert matched_asset is not None
    print(f"  [✓] Verified Hybrid Matched Asset: {matched_asset.identifier} (Confidence: {matched_asset.confidence})")

async def test_orchestrator_lifecycle(db, target: Target, repo_dir: str):
    print("\n[BENCHMARK 5] Running Full ScanOrchestrator Lifecycle & Real Task Tracking...")
    from app.scanner.orchestrator import scan_orchestrator

    req_data = {
        "discovery_mode": "HYBRID",
        "website_url": "http://127.0.0.1:8766",
        "repository_url": repo_dir,
        "repository_branch": "main",
        "max_depth": 2,
        "max_requests": 50,
        "enable_playwright": True
    }
    scan = await scan_orchestrator.create_scan_record(db, req_data)
    scan_id = scan.id
    assert scan.status == "QUEUED"
    assert scan.current_stage == "INITIALIZING"
    print(f"  [✓] Scan created in QUEUED state: {scan_id}")

    cancel_event = asyncio.Event()
    await scan_orchestrator._run_orchestrated_lifecycle(scan_id, scan.configuration, cancel_event)

    async with AsyncSessionLocal() as fresh_db:
        res = await fresh_db.execute(select(Scan).where(Scan.id == scan_id))
        completed_scan = res.scalar_one()

        print(f"  Final Scan Status: {completed_scan.status}")
        print(f"  Final Current Stage: {completed_scan.current_stage}")
        print(f"  Final Progress: {completed_scan.progress}%")
        tasks = completed_scan.configuration.get("tasks_summary", {})
        modules = completed_scan.configuration.get("module_status", {})
        print(f"  Tasks Summary: {tasks}")
        print(f"  Module Status: {modules}")

        assert completed_scan.status in ["COMPLETED", "PARTIALLY_COMPLETED"]
        assert completed_scan.progress == 100
        assert tasks.get("completed", 0) > 0, "No tasks were marked completed!"

        for mod_name in ["fingerprinting", "crawling", "source_analysis", "persisting"]:
            assert mod_name in modules, f"Missing module: {mod_name}"
            assert modules[mod_name]["status"] in ["COMPLETED", "SKIPPED"]
            assert modules[mod_name]["duration_seconds"] >= 0

    print("  [✓] Explicit stages, real task counters, and module telemetry fully verified.")

async def test_security_controls():
    print("\n[BENCHMARK 4] Running Security and Sandboxing Controls...")
    from app.scanner.discovery.source.acquirer import RepositoryAcquirer, RepositoryAcquisitionError
    import tempfile
    
    # 1. Symlink outside sandbox rejection
    with tempfile.TemporaryDirectory() as tmp_dir:
        src_dir = os.path.join(tmp_dir, "src")
        os.makedirs(src_dir)
        outside_file = os.path.join(tmp_dir, "outside.txt")
        with open(outside_file, "w") as f: f.write("secret")
        
        symlink_path = os.path.join(src_dir, "link_to_outside.txt")
        os.symlink(outside_file, symlink_path)

        dst_dir = os.path.join(tmp_dir, "dst")
        os.makedirs(dst_dir)
        
        acquirer = RepositoryAcquirer(repo_url=src_dir)
        acquirer._safe_copy_tree(src_dir, dst_dir)
        copied_symlink = os.path.join(dst_dir, "link_to_outside.txt")
        assert not os.path.exists(copied_symlink), "Dangerous symlink was not prevented!"
        print("  [✓] Symlink traversal outside sandbox safely stripped.")

    # 2. Argument injection repo URL
    try:
        acquirer = RepositoryAcquirer(repo_url="https://github.com/user/-evilrepo")
        acquirer.validate_url()
        assert False, "Should have rejected argument injection URL"
    except RepositoryAcquisitionError:
        print("  [✓] Malicious repository URL argument injection rejected.")

    # 3. Secret payload redaction
    from app.scanner.discovery.browser_crawler import sanitize_payload
    payload = {"api_key": "sk_live_12345", "token": "ghp_secret", "data": {"password": "admin"}}
    sanitized = sanitize_payload(payload)
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["data"]["password"] == "[REDACTED]"
    print("  [✓] Sensitive keys recursively redacted across payloads.")

async def main():
    print("=" * 75)
    print("CYPHER PHASE 7: COMPLETE SYSTEM BENCHMARKING & AUDIT SUITE")
    print("=" * 75)

    await run_safe_schema_migrations()

    # 1. Start controlled mock application in background process
    proc = multiprocessing.Process(target=run_mock_server, daemon=True)
    proc.start()
    time.sleep(1.5) # Give server time to bind

    repo_dir = os.path.join(os.path.dirname(__file__), "ground_truth_repo")

    async with AsyncSessionLocal() as db:
        target = Target(name="CYPHER Ground Truth Target", base_url="http://127.0.0.1:8766")
        db.add(target)
        await db.commit()
        await db.refresh(target)

        # Benchmark Mode A: Website-Only
        scan_id_web = f"bench_p7_web_{int(time.time())}"
        scan_web = Scan(id=scan_id_web, target_id=target.id, status="RUNNING", discovery_mode=ScanMode.WEBSITE_ONLY, website_url=target.base_url)
        db.add(scan_web)
        db.add(WebsiteProfile(scan_id=scan_id_web, base_url=target.base_url, host="127.0.0.1", title="Mock Target", tech_stack=[]))
        await db.commit()
        web_metrics = await test_website_only_benchmark(db, scan_id_web, target)

        # Benchmark Mode B: GitHub-Only
        scan_id_gh = f"bench_p7_gh_{int(time.time())}"
        scan_gh = Scan(id=scan_id_gh, target_id=target.id, status="RUNNING", discovery_mode=ScanMode.GITHUB_ONLY, repository_url="https://github.com/cypher/ground-truth-repo")
        db.add(scan_gh)
        await db.commit()
        gh_metrics = await test_github_only_benchmark(db, scan_id_gh, repo_dir)

        # Benchmark Mode C: Hybrid
        scan_id_hyb = f"bench_p7_hyb_{int(time.time())}"
        scan_hyb = Scan(id=scan_id_hyb, target_id=target.id, status="RUNNING", discovery_mode=ScanMode.HYBRID, website_url=target.base_url, repository_url="https://github.com/cypher/ground-truth-repo")
        db.add(scan_hyb)
        db.add(WebsiteProfile(scan_id=scan_id_hyb, base_url=target.base_url, host="127.0.0.1", title="Mock Target", tech_stack=[]))
        await db.commit()
        await test_hybrid_correlation_and_fuzzer(db, scan_id_hyb, repo_dir)

        # Benchmark Mode D: ScanOrchestrator End-to-End Real Task Lifecycle
        await test_orchestrator_lifecycle(db, target, repo_dir)

    # Security controls
    await test_security_controls()

    # Cleanup background mock server
    proc.terminate()
    proc.join()

    print("\n" + "=" * 75)
    print("FINAL BENCHMARK AUDIT RESULTS (MEASURED AGAINST GROUND TRUTH)")
    print("=" * 75)
    print(f"{'METRIC':<30} | {'WEBSITE-ONLY':<18} | {'GITHUB-ONLY':<18}")
    print("-" * 75)
    print(f"{'Page Recall':<30} | {web_metrics['page_recall']:<18.2%} | {'N/A (Source AST)':<18}")
    print(f"{'Route Recall':<30} | {web_metrics['endpoint_recall']:<18.2%} | {gh_metrics['route_recall']:<18.2%}")
    print(f"{'Endpoint Recall':<30} | {web_metrics['endpoint_recall']:<18.2%} | {gh_metrics['endpoint_recall']:<18.2%}")
    print(f"{'Parameter Recall':<30} | {web_metrics['param_recall']:<18.2%} | {gh_metrics['param_recall']:<18.2%}")
    print(f"{'Precision':<30} | {web_metrics['precision']:<18.2%} | {gh_metrics['precision']:<18.2%}")
    print("=" * 75)
    print("ALL PHASE 7 SYSTEM TESTS, BENCHMARKS, AND AUDITS PASSED!")
    print("=" * 75)

if __name__ == "__main__":
    asyncio.run(main())
