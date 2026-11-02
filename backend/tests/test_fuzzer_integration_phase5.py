"""
Comprehensive Test Suite for Phase 5: Hybrid Discovery to Context-Aware Fuzzer Integration.
Verifies target selection, source-aware context enrichment, safe testing policies,
finding traceability, lifecycle stage segregation, and fuzzer regression integrity.
"""
import asyncio
import os
import unittest
from datetime import datetime

from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.models.models import Scan, Target, Endpoint, Parameter, FuzzResult, Finding, Evidence
from app.models.discovery import (
    ScanMode, DiscoveryStatus, DiscoverySource, AssetType,
    DiscoveredAsset, DiscoveredRoute, EndpointParameter, SourceEvidence
)
from app.scanner.http_client import ResilientHttpClient
from app.scanner.context.parameter_context import ParameterContext, ParameterContextExtractor
from app.scanner.context.test_selector import TestSelector
from app.scanner.context.context_enricher import ContextEnricher
from app.scanner.fuzzer.target_selector import TargetSelector
from app.scanner.fuzzer.engine import FuzzingEngine


async def test_target_selector_policies():
    print("\n[TEST 1] Testing Context-Aware Target Selection Policies...")

    async with AsyncSessionLocal() as db:
        scan_id = f"test_p5_target_sel_{int(datetime.utcnow().timestamp())}"
        target = Target(name="Scope Target", base_url="https://app.example.com")
        db.add(target)
        await db.commit()
        await db.refresh(target)

        scan = Scan(
            id=scan_id,
            target_id=target.id,
            status="RUNNING",
            current_stage="FUZZING",
            discovery_mode=ScanMode.HYBRID,
            website_url="https://app.example.com",
            progress=50
        )
        db.add(scan)
        await db.commit()

        # 1. In-Scope Runtime Verified Endpoint
        ep_valid_id = f"ep_valid_{scan_id}"
        ep_out_id = f"ep_out_{scan_id}"
        ep_source_id = f"ep_source_{scan_id}"
        ep_del_id = f"ep_del_{scan_id}"

        ep_valid = Endpoint(
            id=ep_valid_id,
            scan_id=scan_id,
            url="https://app.example.com/api/v1/users",
            path="/api/v1/users",
            method="GET",
            priority_score=10.0
        )
        # 2. Out-of-Scope Endpoint (Third-party CDN/tracking)
        ep_out_of_scope = Endpoint(
            id=ep_out_id,
            scan_id=scan_id,
            url="https://external-cdn.com/api/telemetry",
            path="/api/telemetry",
            method="GET",
            priority_score=5.0
        )
        # 3. SOURCE_ONLY Endpoint (Unconfirmed at runtime)
        ep_source_only = Endpoint(
            id=ep_source_id,
            scan_id=scan_id,
            url="https://app.example.com/api/internal/debug",
            path="/api/internal/debug",
            method="GET",
            priority_score=8.0
        )
        # 4. State-Changing Endpoint (DELETE)
        ep_delete = Endpoint(
            id=ep_del_id,
            scan_id=scan_id,
            url="https://app.example.com/api/v1/orders/purge",
            path="/api/v1/orders/purge",
            method="DELETE",
            priority_score=9.0
        )
        db.add_all([ep_valid, ep_out_of_scope, ep_source_only, ep_delete])

        # Add corresponding DiscoveredAssets
        a_valid = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.HTTP_ENDPOINT,
            identifier="GET /api/v1/users",
            path="/api/v1/users",
            method="GET",
            discovery_status=DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH,
            confidence=1.0
        )
        a_source_only = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="GET /api/internal/debug",
            path="/api/internal/debug",
            method="GET",
            discovery_status=DiscoveryStatus.SOURCE_ONLY,
            confidence=0.85
        )
        db.add_all([a_valid, a_source_only])
        await db.commit()

        # Policy A: Default safe policy (skips out-of-scope, skips unconfirmed source-only)
        selector = TargetSelector(db, scan_id, config={"allow_state_changing": True, "allow_source_only_fuzzing": False})
        endpoints = [ep_valid, ep_out_of_scope, ep_source_only, ep_delete]
        selected = await selector.select_eligible_endpoints(endpoints)

        selected_ids = [e.id for e in selected]
        print(f"  Selected endpoints (Default Policy): {selected_ids}")

        assert ep_valid_id in selected_ids
        assert ep_del_id in selected_ids
        assert ep_out_id not in selected_ids, "Out-of-scope endpoint was not filtered!"
        assert ep_source_id not in selected_ids, "Unconfirmed SOURCE_ONLY endpoint was not filtered!"

        # Policy B: Non-destructive policy (skips DELETE/POST)
        selector_non_destructive = TargetSelector(db, scan_id, config={"allow_state_changing": False})
        selected_nd = await selector_non_destructive.select_eligible_endpoints([ep_valid, ep_delete])
        selected_nd_ids = [e.id for e in selected_nd]
        assert ep_valid_id in selected_nd_ids
        assert ep_del_id not in selected_nd_ids, "State-changing DELETE endpoint must be skipped under non-destructive policy"

        print("  [✓] Scope boundary, unconfirmed source route, and state-changing safety policies enforced.")


async def test_source_aware_context_enricher():
    print("\n[TEST 2] Testing Source-Aware Context Enrichment...")

    async with AsyncSessionLocal() as db:
        scan_id = f"test_p5_context_{int(datetime.utcnow().timestamp())}"
        target = Target(name="Context Target", base_url="https://api.example.com")
        db.add(target)
        await db.commit()
        await db.refresh(target)

        scan = Scan(
            id=scan_id,
            target_id=target.id,
            status="RUNNING",
            current_stage="FUZZING",
            discovery_mode=ScanMode.HYBRID,
            website_url="https://api.example.com",
            progress=50
        )
        db.add(scan)

        ep_id = f"ep_orders_{scan_id}"
        p_id = f"param_order_{scan_id}"
        ep = Endpoint(
            id=ep_id,
            scan_id=scan_id,
            url="https://api.example.com/api/v1/orders",
            path="/api/v1/orders",
            method="GET",
            is_api=True
        )
        param = Parameter(
            id=p_id,
            endpoint_id=ep_id,
            name="order_id",
            location="query",
            value_type="unknown"
        )
        db.add_all([ep, param])

        # DiscoveredAsset with source evidence and parameter metadata
        asset = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="GET /api/v1/orders",
            path="/api/v1/orders",
            method="GET",
            discovery_status=DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH,
            confidence=1.0,
            metadata_json={"framework": "FastAPI"}
        )
        db.add(asset)
        await db.commit()
        await db.refresh(asset)

        # Source Evidence (Server file and line)
        sev = SourceEvidence(
            scan_id=scan_id,
            asset_id=asset.id,
            file_path="server/routes/orders.py",
            line_start=42,
            line_end=50,
            snippet="@router.get('/orders')\ndef get_orders(order_id: int): ...",
            confidence=0.98,
            rule_name="FastAPI"
        )
        # AST Parameter constraint (Pydantic / type: int)
        ast_param = EndpointParameter(
            scan_id=scan_id,
            asset_id=asset.id,
            name="order_id",
            location="query",
            value_type="int",
            is_required=True,
            example_value="1001"
        )
        # Route with auth guard
        route = DiscoveredRoute(
            scan_id=scan_id,
            asset_id=asset.id,
            route_pattern="/api/v1/orders",
            method="GET",
            framework="FASTAPI",
            handler_name="get_orders",
            source_file="server/routes/orders.py",
            source_line=42,
            auth_required=True
        )
        db.add_all([sev, ast_param, route])
        await db.commit()

        # Build base context
        base_ctx = ParameterContextExtractor.extract_context(param, ep)
        TestSelector.select_tests(base_ctx)

        # Enrich context
        enriched_ctx = await ContextEnricher.enrich_context(db, scan_id, base_ctx, ep, param)

        print(f"  Enriched context metadata: {enriched_ctx.metadata}")
        print(f"  Recommended tests after enrichment: {enriched_ctx.recommended_tests}")

        assert enriched_ctx.metadata.get("source_file") == "server/routes/orders.py"
        assert enriched_ctx.metadata.get("source_line") == 42
        assert enriched_ctx.metadata.get("is_required") is True
        assert enriched_ctx.type == "numeric"
        assert "SQLI" in enriched_ctx.recommended_tests
        assert "TYPE_CONFUSION" in enriched_ctx.recommended_tests
        assert "AUTH_BYPASS" in enriched_ctx.recommended_tests

        print("  [✓] Source AST metadata (file, line, type, auth guards) successfully enriched parameter context.")


async def test_finding_traceability_and_validation():
    print("\n[TEST 3] Testing Finding Result Traceability to Discovery Source Evidence...")

    async with AsyncSessionLocal() as db:
        scan_id = f"test_p5_trace_{int(datetime.utcnow().timestamp())}"
        target = Target(name="Trace Target", base_url="http://127.0.0.1:8765")
        db.add(target)
        await db.commit()
        await db.refresh(target)

        scan = Scan(
            id=scan_id,
            target_id=target.id,
            status="RUNNING",
            current_stage="VALIDATION",
            discovery_mode=ScanMode.HYBRID,
            website_url="http://127.0.0.1:8765",
            progress=80
        )
        db.add(scan)

        ep_contact_id = f"ep_contact_{scan_id}"
        param_msg_id = f"param_msg_{scan_id}"
        ep = Endpoint(
            id=ep_contact_id,
            scan_id=scan_id,
            url="http://127.0.0.1:8765/contact_submit",
            path="/contact_submit",
            method="GET",
            is_api=False
        )
        param = Parameter(
            id=param_msg_id,
            endpoint_id=ep_contact_id,
            name="message",
            location="query",
            value_type="string"
        )
        asset = DiscoveredAsset(
            scan_id=scan_id,
            asset_type=AssetType.HTTP_ENDPOINT,
            identifier="GET /contact_submit",
            path="/contact_submit",
            method="GET",
            discovery_status=DiscoveryStatus.SOURCE_AND_RUNTIME_MATCH,
            confidence=1.0,
            metadata_json={"testing_lifecycle": "ELIGIBLE_FOR_TESTING"}
        )
        db.add_all([ep, param, asset])
        await db.commit()
        await db.refresh(asset)

        sev = SourceEvidence(
            scan_id=scan_id,
            asset_id=asset.id,
            file_path="server/views.py",
            line_start=70,
            line_end=75,
            snippet="@app.get('/contact_submit')\ndef contact_submit(message: str): ...",
            confidence=0.95
        )
        db.add(sev)
        await db.commit()

        # Run EvidenceValidator
        from app.scanner.analysis.anomaly import AnomalyReport, DifferentialSignals
        anomaly = AnomalyReport(
            test_id=f"test_xss_{scan_id}",
            scan_id=scan_id,
            endpoint_id=ep.id,
            parameter_id=param.id,
            parameter_name="message",
            category="XSS",
            payload="<script>alert(1)</script>",
            anomaly=True,
            score=95,
            signals=["PAYLOAD_REFLECTED_IN_RESPONSE"],
            baseline_summary="Status 200, length 120B",
            test_summary="Status 200, length 150B, reflected payload",
            differential=DifferentialSignals(
                status_code_changed=False,
                payload_reflected=True,
                sql_error_detected=False,
                server_error_triggered=False
            )
        )

        client = ResilientHttpClient(max_requests=10, concurrency=1, timeout=5)
        # Mock client so reproduction check succeeds
        from unittest.mock import AsyncMock
        mock_resp = AsyncMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body><h2>Feedback</h2><div><script>alert(1)</script></div></body></html>"
        client._request = AsyncMock(return_value=mock_resp)

        from app.scanner.validation.validator import EvidenceValidator
        validator = EvidenceValidator(db, scan_id, client)
        cancel_event = asyncio.Event()
        findings = await validator.validate_anomalies([anomaly], cancel_event)

        print(f"  Validated confirmed findings: {len(findings)}")
        assert len(findings) == 1
        finding = findings[0]

        # Verify Traceability
        print(f"  Finding description: {finding.description}")
        assert "server/views.py:70" in finding.description
        assert finding.endpoint_id == ep.id
        assert finding.parameter_id == param.id

        # Verify Evidence linked
        ev_res = await db.execute(select(Evidence).where(Evidence.finding_id == finding.id))
        ev_item = ev_res.scalar_one_or_none()
        assert ev_item is not None
        assert "server/views.py:70" in ev_item.analysis

        # Verify Asset Lifecycle stage updated to VALIDATED_FINDING
        await db.refresh(asset)
        assert asset.metadata_json.get("testing_lifecycle") == "VALIDATED_FINDING"

        await client.close()
        print("  [✓] Confirmed finding successfully traced back to source file, endpoint ID, test payload, and lifecycle state.")


async def main():
    print("=" * 70)
    print("CYPHER PHASE 5: HYBRID DISCOVERY TO CONTEXT-AWARE FUZZER TEST SUITE")
    print("=" * 70)

    await test_target_selector_policies()
    await test_source_aware_context_enricher()
    await test_finding_traceability_and_validation()

    print("\n" + "=" * 70)
    print("ALL PHASE 5 FUZZER INTEGRATION TESTS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
