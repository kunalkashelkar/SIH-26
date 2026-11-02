import asyncio
import os
import sys
import unittest
import urllib.parse
from datetime import datetime

import uvicorn
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal, engine, Base
from app.models.models import Scan, Target, Endpoint, Parameter
from app.models.discovery import (
    ScanMode, DiscoveryStatus, DiscoverySource, AssetType,
    WebsiteProfile, DiscoveredAsset, DiscoveredPage, DiscoveredForm,
    EndpointParameter, RuntimeEvidence, DiscoveryEvent
)
from app.scanner.http_client import ResilientHttpClient
from app.scanner.discovery.fingerprint import TechnologyFingerprinter
from app.scanner.discovery.sitemap_parser import SitemapDiscoverer
from app.scanner.discovery.js_analyzer import JavaScriptAnalyzer
from app.scanner.discovery.api_docs_parser import ApiDocsParser
from app.scanner.discovery.browser_crawler import sanitize_payload, PlaywrightDynamicCrawler
from app.scanner.discovery.website_engine import WebsiteDiscoveryEngine


def test_technology_fingerprinter():
    print("\n[TEST 1] Testing TechnologyFingerprinter...")
    # 1. React SPA
    react_html = '<html><body><div id="root" data-reactroot=""><p>Hello React</p></div></body></html>'
    techs, archs = TechnologyFingerprinter.fingerprint({"Server": "nginx"}, react_html)
    assert "React" in techs, f"Expected React in techs, got: {techs}"
    assert "SPA" in archs, f"Expected SPA in archs, got: {archs}"

    # 2. Next.js SSR
    next_html = '<html><head><script id="__NEXT_DATA__">{"props":{}}</script></head><body><div id="__next">Hello Next</div></body></html>'
    techs, archs = TechnologyFingerprinter.fingerprint({"X-Powered-By": "Next.js"}, next_html)
    assert "Next.js" in techs
    assert "SSR" in archs
    assert "SPA" in archs

    # 3. Vue & Express Header
    vue_html = '<html><body><div id="app" data-v-34a9b><p>Vue component</p></div></body></html>'
    techs, archs = TechnologyFingerprinter.fingerprint({"X-Powered-By": "Express"}, vue_html)
    assert "Vue" in techs
    assert "Express" in techs

    # 4. Angular & FastAPI Header
    angular_html = '<html><body><app-root ng-version="16.2.0">Loading...</app-root></body></html>'
    techs, archs = TechnologyFingerprinter.fingerprint({"Server": "uvicorn"}, angular_html)
    assert "Angular" in techs
    assert "FastAPI" in techs

    # 5. WordPress & Svelte
    wp_html = '<html><head><meta name="generator" content="WordPress 6.4"><link rel="stylesheet" href="/wp-content/themes/main.css"></head><body><div class="svelte-1a89b">App</div></body></html>'
    techs, archs = TechnologyFingerprinter.fingerprint({}, wp_html)
    assert "WordPress" in techs
    assert "Svelte" in techs

    # 6. Django with CSRF token and API driven
    django_html = '<html><body><form><input type="hidden" name="csrfmiddlewaretoken" value="xyz123"><script>fetch("/api/v1/data")</script></form></body></html>'
    techs, archs = TechnologyFingerprinter.fingerprint({}, django_html)
    assert "Django" in techs
    assert "API_DRIVEN" in archs

    print("  [✓] TechnologyFingerprinter accurately identifies frontend, backend, and architectures.")


def test_sensitive_payload_redaction():
    print("\n[TEST 2] Testing Sensitive Payload Redaction...")
    payload = {
        "user": {
            "name": "alice",
            "password": "SuperSecretPassword123!",
            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "profile": {
                "apiKey": "sk-live-1234567890",
                "notes": "Safe text",
                "nested_secrets": [
                    {"client_secret": "my-secret", "status": "active"}
                ]
            }
        }
    }
    sanitized = sanitize_payload(payload)
    assert sanitized["user"]["name"] == "alice"
    assert sanitized["user"]["password"] == "[REDACTED]"
    assert sanitized["user"]["auth_token"] == "[REDACTED]"
    assert sanitized["user"]["profile"]["apiKey"] == "[REDACTED]"
    assert sanitized["user"]["profile"]["notes"] == "Safe text"
    assert sanitized["user"]["profile"]["nested_secrets"][0]["client_secret"] == "[REDACTED]"
    assert sanitized["user"]["profile"]["nested_secrets"][0]["status"] == "active"
    print("  [✓] Sensitive fields recursively redacted across dicts and lists.")


async def test_javascript_bundle_analysis():
    print("\n[TEST 3] Testing JavaScript Bundle Analysis...")
    from unittest.mock import AsyncMock
    client = ResilientHttpClient(max_requests=10, concurrency=2, timeout=5)

    mock_js = """
    // Config
    const LOGIN_API = "/api/v1/auth/login";
    const USERS_API = "/api/v2/users/list";
    const METRICS = "/v1/metrics/prometheus";
    
    // Router
    const routes = [
        { path: "/dashboard/analytics", component: Analytics },
        { path: "/users/:id/edit", component: EditUser }
    ];

    // GraphQL
    const GET_USER = `
        query GetUserProfile($id: ID!) {
            user(id: $id) { name email role }
        }
    `;
    const MUTATION_UPDATE = `mutation UpdateSettings { updateSettings { success } }`;
    """

    # Mock client response
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.text = mock_js
    client._request = AsyncMock(return_value=mock_resp)

    analyzer = JavaScriptAnalyzer("http://example.com", client)
    res = await analyzer.analyze_bundle("http://example.com/static/main.js")

    assert "/api/v1/auth/login" in res["api_paths"]
    assert "/api/v2/users/list" in res["api_paths"]
    assert "/v1/metrics/prometheus" in res["api_paths"]
    assert "/dashboard/analytics" in res["routes"]
    assert "/users/:id/edit" in res["routes"]
    assert any("QUERY GetUserProfile" in op for op in res["graphql_ops"])
    assert any("MUTATION UpdateSettings" in op for op in res["graphql_ops"])

    await client.close()
    print("  [✓] JavaScript bundle analyzer accurately extracted API paths, router paths, and GraphQL operations.")


async def test_openapi_spec_parser():
    print("\n[TEST 4] Testing OpenAPI Specification Parser...")
    from unittest.mock import AsyncMock
    client = ResilientHttpClient(max_requests=10, concurrency=2, timeout=5)

    mock_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/products/{id}": {
                "get": {
                    "operationId": "getProductById",
                    "summary": "Retrieve product details",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        {"name": "include_reviews", "in": "query", "required": False, "schema": {"type": "boolean"}}
                    ]
                },
                "put": {
                    "operationId": "updateProduct",
                    "summary": "Update existing product",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"name": {"type": "string"}, "price": {"type": "number"}}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: mock_spec
    client._request = AsyncMock(return_value=mock_resp)

    parser = ApiDocsParser("http://example.com", client)
    ops = await parser.discover_and_parse()

    assert len(ops) == 2, f"Expected 2 operations, got: {len(ops)}"
    get_op = next(o for o in ops if o["method"] == "GET")
    put_op = next(o for o in ops if o["method"] == "PUT")

    assert get_op["operation_id"] == "getProductById"
    assert len(get_op["parameters"]) == 2
    assert put_op["body_schema"] is not None

    await client.close()
    print("  [✓] OpenAPI specification parser extracted paths, operations, parameters, and request schemas.")


async def run_live_crawler_integration():
    print("\n[TEST 5] Testing Live Multi-Engine Website Discovery Pipeline...")
    # 1. Start mock server on port 8765
    from tests.mock_target.main import app as mock_fastapi_app
    config = uvicorn.Config(mock_fastapi_app, host="127.0.0.1", port=8765, log_level="warning")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Wait for server to bind
    await asyncio.sleep(1.0)
    target_url = "http://127.0.0.1:8765"

    try:
        async with AsyncSessionLocal() as db:
            scan_id = f"test_phase2_scan_{int(datetime.utcnow().timestamp())}"

            # Create target first
            target = Target(
                name="Mock Target",
                base_url=target_url,
                description="Test target"
            )
            db.add(target)
            await db.commit()
            await db.refresh(target)

            # Create scan record and website profile
            scan = Scan(
                id=scan_id,
                target_id=target.id,
                status="RUNNING",
                current_stage="DISCOVERY",
                discovery_mode=ScanMode.WEBSITE_ONLY,
                website_url=target_url,
                progress=10,
                configuration={"max_depth": 3, "max_requests": 50, "enable_playwright": True}
            )
            db.add(scan)
            profile = WebsiteProfile(
                scan_id=scan_id,
                base_url=target_url,
                host="127.0.0.1",
                title="Mock Target",
                tech_stack=[]
            )
            db.add(profile)
            await db.commit()

            cancel_event = asyncio.Event()

            # Execute the WebsiteDiscoveryEngine
            engine = WebsiteDiscoveryEngine(
                scan_id=scan_id,
                target_url=target_url,
                db=db,
                config={"max_depth": 3, "max_requests": 50, "enable_playwright": True}
            )
            summary = await engine.run(cancel_event)

            print(f"  Crawler execution summary: {summary}")
            assert summary["static_pages"] >= 3, f"Expected >= 3 static pages, got: {summary['static_pages']}"
            assert summary["total_endpoints_synced"] >= 4, f"Expected >= 4 synced endpoints, got: {summary['total_endpoints_synced']}"

            # 2. Verify Discovered Assets
            assets_res = await db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan_id))
            assets = assets_res.scalars().all()
            asset_paths = [a.path for a in assets]
            print(f"  Discovered asset paths: {asset_paths}")

            assert "/" in asset_paths
            assert "/login" in asset_paths
            assert "/about" in asset_paths

            # 3. Verify Discovered Forms
            forms_res = await db.execute(select(DiscoveredForm).where(DiscoveredForm.scan_id == scan_id))
            forms = forms_res.scalars().all()
            print(f"  Discovered {len(forms)} forms: {[f.action for f in forms]}")
            assert len(forms) >= 1
            form_actions = [f.action for f in forms]
            assert any("/login_submit" in (act or "") for act in form_actions)

            # 4. Verify WebsiteProfile updated with tech stack
            p_res = await db.execute(select(WebsiteProfile).where(WebsiteProfile.scan_id == scan_id))
            updated_profile = p_res.scalar_one_or_none()
            assert updated_profile is not None
            print(f"  Detected tech stack: {updated_profile.tech_stack}")
            assert "FastAPI" in updated_profile.tech_stack

            # 5. Verify Legacy Endpoints Synchronized for Fuzzing Pipeline
            eps_res = await db.execute(select(Endpoint).where(Endpoint.scan_id == scan_id))
            endpoints = eps_res.scalars().all()
            print(f"  Synchronized legacy endpoints: {[f'{ep.method} {ep.path}' for ep in endpoints]}")
            assert len(endpoints) >= 4

            print("  [✓] Complete multi-engine website crawler pipeline executed successfully and verified.")

    finally:
        server.should_exit = True
        await server_task


async def main():
    print("=" * 70)
    print("CYPHER PHASE 2: WEBSITE CRAWLER ENGINE VERIFICATION SUITE")
    print("=" * 70)

    test_technology_fingerprinter()
    test_sensitive_payload_redaction()
    await test_javascript_bundle_analysis()
    await test_openapi_spec_parser()
    await run_live_crawler_integration()

    print("\n" + "=" * 70)
    print("ALL PHASE 2 WEBSITE CRAWLER ENGINE TESTS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
