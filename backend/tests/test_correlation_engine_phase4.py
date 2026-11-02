"""
Comprehensive Test Suite for Phase 4: Source Code and Runtime Correlation Engine.
Tests endpoint matching, dynamic templates, asset classification, discrepancy analysis,
NetworkX Attack Surface Graph construction, and ground-truth validation.
"""
import asyncio
import os
import unittest
from datetime import datetime

from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.models.models import Scan, Target
from app.models.discovery import (
    ScanMode, DiscoveryStatus, DiscoverySource, AssetType, RelationshipType,
    DiscoveredAsset, DiscoveredRoute, DiscoveredForm, SourceEvidence,
    RuntimeEvidence, EndpointParameter, AssetRelationship
)
from app.scanner.discovery.correlation.matcher import EndpointPathMatcher, MatchResult
from app.scanner.discovery.correlation.classifier import AssetClassifier, ConfidenceLevel
from app.scanner.discovery.correlation.diff_analyzer import DifferenceAnalyzer
from app.scanner.discovery.correlation.graph_builder import (
    UnifiedAttackSurfaceGraphBuilder, UnifiedGraphNodeType, UnifiedGraphEdgeType
)
from app.scanner.discovery.correlation.engine import CorrelationEngine


def test_endpoint_path_matcher():
    print("\n[TEST 1] Testing Endpoint Path & Method Matcher...")

    # 1. Exact match
    res1 = EndpointPathMatcher.match("GET", "/api/v1/users", "GET", "/api/v1/users")
    assert res1.is_match is True
    assert res1.confidence == 1.0
    assert res1.match_type == "EXACT"

    # 2. Method mismatch must be strictly rejected
    res2 = EndpointPathMatcher.match("POST", "/api/v1/users", "GET", "/api/v1/users")
    assert res2.is_match is False
    assert "Method mismatch" in res2.explanation

    # 3. Dynamic parameter template: {id} vs 42
    res3 = EndpointPathMatcher.match("GET", "/api/v1/users/{user_id}", "GET", "/api/v1/users/42")
    assert res3.is_match is True
    assert res3.matched_parameters.get("user_id") == "42"
    assert res3.match_type == "PARAMETERIZED"

    # 4. Express style :id parameter
    res4 = EndpointPathMatcher.match("GET", "/api/v1/orders/:orderId/items", "GET", "/api/v1/orders/ord_999/items")
    assert res4.is_match is True
    assert res4.matched_parameters.get("orderId") == "ord_999"

    # 5. Django style <int:id> parameter
    res5 = EndpointPathMatcher.match("GET", "/api/products/<int:prod_id>/", "GET", "/api/products/108")
    assert res5.is_match is True
    assert res5.matched_parameters.get("prod_id") == "108"

    # 6. Trailing slashes and URL decoding
    res6 = EndpointPathMatcher.match("GET", "/api/search%20results/", "GET", "/api/search results")
    assert res6.is_match is True

    # 7. Reverse proxy prefix normalization
    res7 = EndpointPathMatcher.match("GET", "/v1/metrics", "GET", "/api/v1/metrics")
    assert res7.is_match is True
    assert res7.match_type == "PREFIX_NORMALIZED"

    print("  [✓] Path matcher accurately handles exact routes, dynamic parameters, method divergence, and proxy prefixes.")


def test_asset_classifier_and_confidence():
    print("\n[TEST 2] Testing Asset Classification & Confidence Scoring Model...")

    # 1. SOURCE_AND_RUNTIME_MATCH -> HIGH confidence (1.0)
    status, level, score, exp = AssetClassifier.classify_asset(has_source=True, has_runtime=True)
    assert status == DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH
    assert level == ConfidenceLevel.HIGH
    assert score == 1.0

    # 2. SOURCE_ONLY -> MEDIUM confidence (0.85)
    status, level, score, exp = AssetClassifier.classify_asset(has_source=True, has_runtime=False)
    assert status == DiscoveryStatus.SOURCE_ONLY
    assert level == ConfidenceLevel.MEDIUM
    assert score == 0.85
    assert "not observed during runtime" in exp

    # 3. RUNTIME_ONLY -> HIGH confidence (0.90)
    status, level, score, exp = AssetClassifier.classify_asset(has_source=False, has_runtime=True)
    assert status == DiscoveryStatus.RUNTIME_ONLY
    assert level == ConfidenceLevel.HIGH
    assert score == 0.90

    # 4. RESTRICTED -> HTTP 401 or 403
    status, level, score, exp = AssetClassifier.classify_asset(has_source=False, has_runtime=True, response_status=403)
    assert status == DiscoveryStatus.RESTRICTED
    assert score == 0.95
    assert "inaccessible in the current session" in exp

    # 5. CANDIDATE -> LOW confidence (0.55)
    status, level, score, exp = AssetClassifier.classify_asset(has_source=False, has_runtime=False, is_candidate=True)
    assert status == DiscoveryStatus.CANDIDATE
    assert level == ConfidenceLevel.LOW
    assert score == 0.55

    print("  [✓] Deterministic classification and explainable confidence ratings verified.")


def test_difference_analyzer():
    print("\n[TEST 3] Testing Source/Runtime Difference Analysis...")

    source_routes = [
        {"path": "/api/v1/users", "method": "GET", "source_file": "api.py", "line_start": 10, "auth_required": True},
        {"path": "/api/v1/admin/secret", "method": "GET", "source_file": "admin.py", "line_start": 20, "auth_required": True}
    ]
    runtime_endpoints = [
        {"path": "/api/v1/users", "method": "GET", "status_code": 200, "source": "XHR"},
        {"path": "/api/v1/shadow-endpoint", "method": "POST", "status_code": 200, "source": "FETCH"}
    ]
    matches = [
        {
            "source_key": "GET /api/v1/users",
            "runtime_key": "GET /api/v1/users",
            "source": source_routes[0],
            "runtime": runtime_endpoints[0]
        }
    ]

    discrepancies = DifferenceAnalyzer.analyze_discrepancies(source_routes, runtime_endpoints, matches)
    disc_types = [d.discrepancy_type for d in discrepancies]
    print(f"  Discrepancies identified: {disc_types}")

    # Uncovered source route (/api/v1/admin/secret)
    assert "UNCOVERED_SOURCE_ROUTE" in disc_types
    # Shadow runtime endpoint (/api/v1/shadow-endpoint)
    assert "SHADOW_RUNTIME_ENDPOINT" in disc_types
    # Authentication discrepancy (source requires auth, runtime responded 200)
    assert "AUTHENTICATION_DISCREPANCY" in disc_types

    print("  [✓] Discrepancies (uncovered routes, shadow APIs, auth discrepancies) successfully flagged.")


def test_unified_attack_surface_graph():
    print("\n[TEST 4] Testing NetworkX Unified Attack Surface Graph Builder...")

    builder = UnifiedAttackSurfaceGraphBuilder(
        scan_id="test_scan",
        website_url="https://example.com",
        repo_url="https://github.com/example/app"
    )

    assets = [
        {"id": "page_1", "asset_type": "WEBSITE_PAGE", "path": "/dashboard", "method": "GET", "discovery_status": "SOURCE_AND_RUNTIME_MATCH"},
        {"id": "api_1", "asset_type": "BACKEND_API_OPERATION", "path": "/api/v1/data", "method": "GET", "discovery_status": "SOURCE_AND_RUNTIME_MATCH"}
    ]
    routes = [
        {"id": "r_1", "asset_id": "api_1", "route_pattern": "/api/v1/data", "method": "GET", "framework": "FASTAPI", "handler_name": "get_data", "source_file": "server.py", "source_line": 25, "auth_required": True}
    ]
    forms = [
        {"id": "f_1", "action": "/api/v1/data", "method": "POST", "page_url": "https://example.com/dashboard"}
    ]
    client_calls = [
        {"file_path": "Dashboard.tsx", "line_number": 15, "client_library": "axios", "method": "GET", "url_pattern": "/api/v1/data"}
    ]
    relationships = [
        {"source_asset_id": "page_1", "target_asset_id": "api_1", "relationship_type": "CORRELATED_WITH", "confidence": 1.0}
    ]

    graph = builder.build_graph(assets, routes, forms, client_calls, [], relationships)

    print(f"  Graph created: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    assert graph.number_of_nodes() >= 5
    assert graph.number_of_edges() >= 4

    # Verify JSON export
    graph_json = builder.to_json()
    assert graph_json["total_nodes"] == graph.number_of_nodes()
    assert graph_json["total_edges"] == graph.number_of_edges()

    node_types = {n["type"] for n in graph_json["nodes"]}
    assert UnifiedGraphNodeType.WEBSITE in node_types
    assert UnifiedGraphNodeType.FRONTEND_PAGE in node_types
    assert UnifiedGraphNodeType.API_ENDPOINT in node_types
    assert UnifiedGraphNodeType.BACKEND_CONTROLLER in node_types

    print("  [✓] Unified Attack Surface Graph models multi-layer relationships and serializes to JSON.")


async def test_hybrid_correlation_live_e2e():
    print("\n[TEST 5] Testing End-to-End Hybrid Correlation Pipeline...")

    async with AsyncSessionLocal() as db:
        scan_id = f"test_phase4_scan_{int(datetime.utcnow().timestamp())}"
        target = Target(name="Hybrid Target", base_url="http://127.0.0.1:8000", repo_url="https://github.com/mock/repo")
        db.add(target)
        await db.commit()
        await db.refresh(target)

        scan = Scan(
            id=scan_id,
            target_id=target.id,
            status="RUNNING",
            current_stage="CORRELATION",
            discovery_mode=ScanMode.HYBRID,
            website_url="http://127.0.0.1:8000",
            repository_url="https://github.com/mock/repo",
            progress=40
        )
        db.add(scan)
        await db.commit()

        # 1. Create Source-Defined Assets
        s_asset_1 = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="GET /api/v1/users/{id}",
            name="/api/v1/users/{id}",
            path="/api/v1/users/{id}",
            method="GET",
            discovery_status=DiscoveryStatus.SOURCE_ONLY,
            confidence=0.85,
            metadata_json={"file_path": "server/api.py", "line_start": 30, "framework": "FASTAPI"}
        )
        s_asset_2 = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="POST /api/v1/users",
            name="/api/v1/users",
            path="/api/v1/users",
            method="POST",
            discovery_status=DiscoveryStatus.SOURCE_ONLY,
            confidence=0.85,
            metadata_json={"file_path": "server/api.py", "line_start": 45, "framework": "FASTAPI"}
        )
        s_asset_3 = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="DELETE /api/v1/users/{id}",
            name="/api/v1/users/{id}",
            path="/api/v1/users/{id}",
            method="DELETE",
            discovery_status=DiscoveryStatus.SOURCE_ONLY,
            confidence=0.85,
            metadata_json={"file_path": "server/api.py", "line_start": 60, "framework": "FASTAPI"}
        )
        db.add_all([s_asset_1, s_asset_2, s_asset_3])
        await db.commit()

        # Add Source Evidence for s_asset_1
        ev1 = SourceEvidence(
            scan_id=scan_id,
            asset_id=s_asset_1.id,
            file_path="server/api.py",
            line_start=30,
            line_end=35,
            snippet="@router.get('/users/{id}')\ndef get_user(id: int): ...",
            confidence=0.95,
            ast_node_type="ROUTE_DECLARATION"
        )
        db.add(ev1)

        # 2. Create Runtime-Observed Assets
        r_asset_1 = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.HTTP_ENDPOINT,
            identifier="GET /api/v1/users/42",
            name="/api/v1/users/42",
            path="/api/v1/users/42",
            url="http://127.0.0.1:8000/api/v1/users/42",
            method="GET",
            discovery_status=DiscoveryStatus.RUNTIME_ONLY,
            confidence=0.90,
            metadata_json={"status_code": 200, "source": "XHR"}
        )
        r_asset_2 = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.HTTP_ENDPOINT,
            identifier="POST /api/v1/users",
            name="/api/v1/users",
            path="/api/v1/users",
            url="http://127.0.0.1:8000/api/v1/users",
            method="POST",
            discovery_status=DiscoveryStatus.RUNTIME_ONLY,
            confidence=0.90,
            metadata_json={"status_code": 201, "source": "FETCH"}
        )
        r_asset_3 = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.HTTP_ENDPOINT,
            identifier="GET /api/v1/shadow-ping",
            name="/api/v1/shadow-ping",
            path="/api/v1/shadow-ping",
            url="http://127.0.0.1:8000/api/v1/shadow-ping",
            method="GET",
            discovery_status=DiscoveryStatus.RUNTIME_ONLY,
            confidence=0.90,
            metadata_json={"status_code": 200, "source": "FETCH"}
        )
        db.add_all([r_asset_1, r_asset_2, r_asset_3])
        await db.commit()

        # Add Runtime Evidence for r_asset_1
        rev1 = RuntimeEvidence(
            scan_id=scan_id,
            asset_id=r_asset_1.id,
            discovery_source=DiscoverySource.PLAYWRIGHT,
            observation_type="HTTP_REQUEST",
            url="http://127.0.0.1:8000/api/v1/users/42",
            method="GET",
            response_status=200
        )
        db.add(rev1)
        await db.commit()

        # Execute CorrelationEngine
        cancel_event = asyncio.Event()
        engine = CorrelationEngine(scan_id=scan_id, db=db)
        summary = await engine.run(cancel_event)

        print(f"  Correlation summary: {summary}")
        assert summary["total_matches"] == 2, f"Expected 2 matches, got: {summary['total_matches']}"
        assert summary["source_only_count"] == 1, f"Expected 1 source-only, got: {summary['source_only_count']}"
        assert summary["runtime_only_count"] == 1, f"Expected 1 runtime-only, got: {summary['runtime_only_count']}"

        # 3. Verify Classifications
        await db.refresh(s_asset_1)
        await db.refresh(r_asset_1)
        await db.refresh(s_asset_3)
        await db.refresh(r_asset_3)

        assert s_asset_1.discovery_status == DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH
        assert r_asset_1.discovery_status == DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH
        assert s_asset_3.discovery_status == DiscoveryStatus.SOURCE_ONLY
        assert r_asset_3.discovery_status == DiscoveryStatus.RUNTIME_ONLY

        # 4. Verify AssetRelationship Created for Matched Pair
        rel_res = await db.execute(
            select(AssetRelationship).where(
                AssetRelationship.scan_id == scan_id,
                AssetRelationship.source_asset_id == s_asset_1.id,
                AssetRelationship.target_asset_id == r_asset_1.id
            )
        )
        rel = rel_res.scalar_one_or_none()
        assert rel is not None
        assert rel.relationship_type == RelationshipType.CORRELATED_WITH
        assert rel.metadata_json.get("matched_parameters", {}).get("id") == "42"

        # 5. Verify Original Evidence Retained
        a1_res = await db.execute(
            select(DiscoveredAsset)
            .options(selectinload(DiscoveredAsset.source_evidences))
            .where(DiscoveredAsset.id == s_asset_1.id)
        )
        loaded_a1 = a1_res.scalar_one_or_none()
        assert len(loaded_a1.source_evidences) == 1
        assert loaded_a1.source_evidences[0].file_path == "server/api.py"

        print("  [✓] Complete hybrid correlation pipeline executed successfully and verified.")


async def main():
    print("=" * 70)
    print("CYPHER PHASE 4: SOURCE CODE & RUNTIME CORRELATION ENGINE TEST SUITE")
    print("=" * 70)

    test_endpoint_path_matcher()
    test_asset_classifier_and_confidence()
    test_difference_analyzer()
    test_unified_attack_surface_graph()
    await test_hybrid_correlation_live_e2e()

    print("\n" + "=" * 70)
    print("ALL PHASE 4 CORRELATION ENGINE TESTS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
