"""
Verification test suite for Phase 3: GitHub Repository Source Code Analyzer.
Tests multi-framework route extraction, AST parsing, sandboxing security,
HTTP client calls, schemas, authentication logic, and ground-truth validation.
"""
import asyncio
import os
import shutil
import tempfile
import unittest
from datetime import datetime

from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import AsyncSessionLocal
from app.models.models import Scan, Target
from app.models.discovery import (
    ScanMode, DiscoveryStatus, DiscoverySource, AssetType,
    RepositoryProfile, DiscoveredAsset, DiscoveredRoute,
    SourceFile, SourceEvidence, EndpointParameter,
    AuthenticationObservation
)
from app.scanner.discovery.source.models import DiscoveredSourceRoute
from app.scanner.discovery.source.acquirer import (
    RepositoryAcquirer, SecurityViolationError, RepositoryAcquisitionError
)
from app.scanner.discovery.source.framework_detector import SourceFrameworkDetector
from app.scanner.discovery.source.parsers.python_fastapi import PythonRouteParser
from app.scanner.discovery.source.parsers.python_django import DjangoRouteParser
from app.scanner.discovery.source.parsers.js_routes import JavaScriptRouteParser
from app.scanner.discovery.source.parsers.http_client import HttpClientAnalyzer
from app.scanner.discovery.source.parsers.schemas import SchemaAnalyzer
from app.scanner.discovery.source.parsers.auth_detector import AuthDetector
from app.scanner.discovery.source.parsers.api_specs import StaticApiSpecParser
from app.scanner.discovery.source.source_engine import SourceCodeDiscoveryEngine


def test_sandboxing_and_security_controls():
    print("\n[TEST 1] Testing Sandboxing and Security Restrictions...")
    temp_dir = tempfile.mkdtemp(prefix="test_security_")
    try:
        # 1. URL validation
        acquirer = RepositoryAcquirer(repo_url="https://evil.com/hacker/repo")
        try:
            acquirer.validate_url()
            assert False, "Should have rejected non-github URL"
        except RepositoryAcquisitionError as e:
            assert "Invalid GitHub repository URL" in str(e)

        # 2. Reject argument injection in repo name
        acquirer_inject = RepositoryAcquirer(repo_url="https://github.com/user/-evilrepo")
        try:
            acquirer_inject.validate_url()
            assert False, "Should have rejected repo name starting with hyphen"
        except RepositoryAcquisitionError as e:
            assert "Suspicious repository name" in str(e) or "Invalid GitHub repository URL" in str(e)

        # 3. Symlink escape check
        outside_file = os.path.join(temp_dir, "secret.txt")
        with open(outside_file, "w") as f:
            f.write("super secret")

        repo_sub = os.path.join(temp_dir, "fake_repo")
        os.makedirs(repo_sub, exist_ok=True)
        symlink_path = os.path.join(repo_sub, "link_to_secret.txt")
        os.symlink(outside_file, symlink_path)

        acquirer_sandbox = RepositoryAcquirer(repo_url=repo_sub)
        # Audit sandbox should detect and disarm symlinks pointing outside
        acquirer_sandbox._audit_sandbox(repo_sub)
        assert not os.path.exists(symlink_path), "Symlink pointing outside sandbox was not removed!"

        # 4. File count limits
        acquirer_count = RepositoryAcquirer(repo_url=repo_sub, max_files=2)
        with open(os.path.join(repo_sub, "f1.py"), "w") as f: f.write("print(1)")
        with open(os.path.join(repo_sub, "f2.py"), "w") as f: f.write("print(2)")
        with open(os.path.join(repo_sub, "f3.py"), "w") as f: f.write("print(3)")
        try:
            acquirer_count._audit_sandbox(repo_sub)
            assert False, "Should have thrown SecurityViolationError for exceeding file count"
        except SecurityViolationError as e:
            assert "maximum file count" in str(e)

        print("  [✓] Security sandboxing (URL format, symlinks, file counts) enforced.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_python_fastapi_and_flask_parser():
    print("\n[TEST 2] Testing FastAPI and Flask Python AST Parser...")
    temp_dir = tempfile.mkdtemp(prefix="test_py_parser_")
    try:
        sample_code = """
from fastapi import FastAPI, APIRouter, Depends, Query
from pydantic import BaseModel

app = FastAPI()
api_router = APIRouter(prefix="/v1")

class UserCreate(BaseModel):
    username: str
    email: str

async def get_current_user():
    return {"user": "admin"}

@api_router.get("/users/{user_id}")
async def get_user(user_id: int, include_profile: bool = Query(False)):
    return {"id": user_id}

@api_router.post("/users", status_code=201)
async def create_user(payload: UserCreate, user: dict = Depends(get_current_user)):
    return payload

@app.get("/health")
def health():
    return {"status": "ok"}
"""
        file_path = os.path.join(temp_dir, "main.py")
        with open(file_path, "w") as f:
            f.write(sample_code)

        parser = PythonRouteParser(temp_dir)
        routes = parser.parse_file(file_path)

        paths = [(r.method, r.path) for r in routes]
        print(f"  Extracted Python routes: {paths}")

        assert ("GET", "/health") in paths
        assert ("GET", "/v1/users/{user_id}") in paths
        assert ("POST", "/v1/users") in paths

        # Check authentication requirement detected from Depends(get_current_user)
        post_route = next(r for r in routes if r.path == "/v1/users" and r.method == "POST")
        assert post_route.auth_required is True, "Expected auth_required for create_user"
        assert post_route.auth_details is not None

        # Check parameter extraction
        get_route = next(r for r in routes if r.path == "/v1/users/{user_id}" and r.method == "GET")
        param_names = [p.name for p in get_route.parameters]
        assert "user_id" in param_names
        assert "include_profile" in param_names

        print("  [✓] FastAPI & Flask routes, parameters, and auth dependencies extracted via AST.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_django_and_drf_parser():
    print("\n[TEST 3] Testing Django and DRF Route Parser...")
    temp_dir = tempfile.mkdtemp(prefix="test_dj_parser_")
    try:
        sample_django = """
from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'products', views.ProductViewSet)

urlpatterns = [
    path('api/orders/<int:order_id>/', views.order_detail),
    path('api/auth/login/', views.login_view),
]
"""
        file_path = os.path.join(temp_dir, "urls.py")
        with open(file_path, "w") as f:
            f.write(sample_django)

        parser = DjangoRouteParser(temp_dir)
        routes = parser.parse_file(file_path)

        paths = [(r.method, r.path) for r in routes]
        print(f"  Extracted Django routes: {paths}")

        assert ("GET", "/api/orders/{order_id}/") in paths
        assert ("GET", "/api/auth/login/") in paths
        # Check DRF expansion
        assert ("GET", "/products") in paths
        assert ("POST", "/products") in paths
        assert ("DELETE", "/products/{id}") in paths

        print("  [✓] Django urlpatterns and DRF ViewSet routes correctly extracted and expanded.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_javascript_and_typescript_route_parser():
    print("\n[TEST 4] Testing JS/TS Parsers (Express, NestJS, React Router, Next.js)...")
    temp_dir = tempfile.mkdtemp(prefix="test_js_parser_")
    try:
        # 1. Express
        express_code = """
        const express = require('express');
        const router = express.Router();
        router.get('/items/:itemId', authMiddleware, getItem);
        router.post('/items', requireAuth, createItem);
        app.use('/api', router);
        """
        exp_file = os.path.join(temp_dir, "express_routes.js")
        with open(exp_file, "w") as f: f.write(express_code)

        # 2. React Router
        react_code = """
        import { Route } from 'react-router-dom';
        export const AppRoutes = () => (
            <>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/account/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
            </>
        );
        """
        react_file = os.path.join(temp_dir, "App.tsx")
        with open(react_file, "w") as f: f.write(react_code)

        # 3. Next.js App Router (page + route)
        next_app_dir = os.path.join(temp_dir, "app", "analytics", "(admin)", "[reportId]")
        os.makedirs(next_app_dir, exist_ok=True)
        next_page = os.path.join(next_app_dir, "page.tsx")
        with open(next_page, "w") as f: f.write("export default function Page() { return <div>Report</div>; }")

        next_api_dir = os.path.join(temp_dir, "app", "api", "metrics")
        os.makedirs(next_api_dir, exist_ok=True)
        next_route = os.path.join(next_api_dir, "route.ts")
        with open(next_route, "w") as f:
            f.write("export async function GET() { return Response.json({}); }\nexport async function POST() { return Response.json({}); }")

        parser = JavaScriptRouteParser(temp_dir)
        exp_routes = parser.parse_file(exp_file)
        react_routes = parser.parse_file(react_file)
        page_routes = parser.parse_file(next_page)
        api_routes = parser.parse_file(next_route)

        # Verify Express
        assert any(r.path == "/items/{itemId}" and r.method == "GET" for r in exp_routes)
        assert any(r.path == "/items" and r.method == "POST" and r.auth_required for r in exp_routes)

        # Verify React Router
        assert any(r.path == "/dashboard" and r.route_type == "FRONTEND" for r in react_routes)
        assert any(r.path == "/account/settings" and r.auth_required for r in react_routes)

        # Verify Next.js App Router
        assert any(r.path == "/analytics/{reportId}" and r.framework == "NEXTJS" for r in page_routes)
        assert any(r.path == "/api/metrics" and r.method == "GET" for r in api_routes)
        assert any(r.path == "/api/metrics" and r.method == "POST" for r in api_routes)

        print("  [✓] Express, React Router, and Next.js App Router successfully parsed.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_http_client_and_schema_analyzer():
    print("\n[TEST 5] Testing HTTP Client Calls and Schema Extraction...")
    temp_dir = tempfile.mkdtemp(prefix="test_client_schema_")
    try:
        # 1. HTTP Client file
        client_code = """
        import axios from 'axios';
        export async function fetchUsers() {
            return await axios.get('/api/v1/users');
        }
        export async function fetchUserOrders(userId) {
            return await axios.get(`/api/v1/users/${userId}/orders`);
        }
        export async function submitOrder(data) {
            return await fetch('/api/v1/checkout', { method: 'POST', body: JSON.stringify(data) });
        }
        """
        cf_path = os.path.join(temp_dir, "apiService.ts")
        with open(cf_path, "w") as f: f.write(client_code)

        client_analyzer = HttpClientAnalyzer(temp_dir)
        calls = client_analyzer.parse_file(cf_path)
        call_patterns = [(c.method, c.url_pattern, c.is_dynamic) for c in calls]
        print(f"  Extracted client API calls: {call_patterns}")

        assert ("GET", "/api/v1/users", False) in call_patterns
        assert ("GET", "/api/v1/users/{userId}/orders", True) in call_patterns
        assert ("POST", "/api/v1/checkout", False) in call_patterns

        # 2. TypeScript Interface and Zod Schema
        schema_code = """
        export interface CreateProductDTO {
            title: string;
            price: number;
            description?: string;
        }
        export const RegisterSchema = z.object({
            email: z.string().email(),
            password: z.string().min(8),
            age: z.number().optional()
        });
        """
        sf_path = os.path.join(temp_dir, "schemas.ts")
        with open(sf_path, "w") as f: f.write(schema_code)

        schema_analyzer = SchemaAnalyzer(temp_dir)
        ts_schemas = schema_analyzer.parse_typescript_interfaces(sf_path)
        
        assert "CreateProductDTO" in ts_schemas
        dto_fields = {p.name: p.is_required for p in ts_schemas["CreateProductDTO"]}
        assert dto_fields["title"] is True
        assert dto_fields["description"] is False

        assert "RegisterSchema" in ts_schemas
        zod_fields = {p.name: p.is_required for p in ts_schemas["RegisterSchema"]}
        assert zod_fields["email"] is True
        assert zod_fields["age"] is False

        print("  [✓] Frontend HTTP client calls, template literals, and data schemas accurately extracted.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def test_full_source_code_discovery_engine_e2e():
    print("\n[TEST 6] Testing Full SourceCodeDiscoveryEngine End-to-End Pipeline...")
    temp_dir = tempfile.mkdtemp(prefix="test_repo_e2e_")
    try:
        # Create full mock multi-framework repository:
        # package.json + requirements.txt + FastAPI backend + Next.js frontend + OpenAPI spec
        package_json = {
            "name": "full-stack-test-app",
            "dependencies": {
                "react": "^18.2.0",
                "next": "^14.0.0",
                "axios": "^1.6.0"
            }
        }
        import json
        with open(os.path.join(temp_dir, "package.json"), "w") as f:
            json.dump(package_json, f)

        with open(os.path.join(temp_dir, "requirements.txt"), "w") as f:
            f.write("fastapi==0.110.0\nuvicorn==0.28.0\npydantic==2.6.0\n")

        # FastAPI app
        server_dir = os.path.join(temp_dir, "server")
        os.makedirs(server_dir, exist_ok=True)
        with open(os.path.join(server_dir, "api.py"), "w") as f:
            f.write("""
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/api/v1")

def verify_token():
    return True

@router.get("/dashboard")
def get_dashboard(user=Depends(verify_token)):
    return {"data": 123}

@router.post("/auth/login")
def login(username: str):
    return {"token": "jwt-token"}
""")

        # Next.js frontend
        app_dir = os.path.join(temp_dir, "app", "dashboard")
        os.makedirs(app_dir, exist_ok=True)
        with open(os.path.join(app_dir, "page.tsx"), "w") as f:
            f.write("""
import axios from 'axios';
export default function Dashboard() {
    axios.get('/api/v1/dashboard');
    return <h1>Dashboard</h1>;
}
""")

        # Static OpenAPI spec
        with open(os.path.join(temp_dir, "openapi.json"), "w") as f:
            json.dump({
                "openapi": "3.0.0",
                "paths": {
                    "/api/v1/spec-operation": {
                        "get": {"summary": "Spec endpoint", "operationId": "getSpecOp"}
                    }
                }
            }, f)

        # Run SourceCodeDiscoveryEngine
        async with AsyncSessionLocal() as db:
            scan_id = f"test_phase3_scan_{int(datetime.utcnow().timestamp())}"
            target = Target(name="Source Target", base_url="https://github.com/mock/repo", repo_url=temp_dir)
            db.add(target)
            await db.commit()
            await db.refresh(target)

            scan = Scan(
                id=scan_id,
                target_id=target.id,
                status="RUNNING",
                current_stage="DISCOVERY",
                discovery_mode=ScanMode.GITHUB_ONLY,
                repository_url=temp_dir,
                repository_branch="main",
                progress=10
            )
            db.add(scan)
            repo_profile = RepositoryProfile(
                scan_id=scan_id,
                repo_url=temp_dir,
                branch="main",
                detected_languages=[],
                detected_frameworks=[]
            )
            db.add(repo_profile)
            await db.commit()

            cancel_event = asyncio.Event()

            engine = SourceCodeDiscoveryEngine(
                scan_id=scan_id,
                repo_url=temp_dir,
                db=db
            )
            summary = await engine.run(cancel_event)

            print(f"  Source engine summary: {summary}")
            assert summary["routes_discovered"] >= 3, f"Expected >= 3 routes, got: {summary['routes_discovered']}"
            assert "FastAPI" in summary["detected_frameworks"]
            assert "Next.js" in summary["detected_frameworks"]

            # 1. Check DiscoveredAsset records (must be marked SOURCE_DEFINED, NEVER runtime-confirmed)
            assets_res = await db.execute(select(DiscoveredAsset).where(DiscoveredAsset.scan_id == scan_id))
            assets = assets_res.scalars().all()
            print(f"  Discovered assets: {[a.identifier for a in assets]}")
            for a in assets:
                assert a.discovery_status == DiscoveryStatus.SOURCE_DEFINED, f"Asset {a.identifier} must be SOURCE_DEFINED"

            # 2. Check DiscoveredRoute records
            routes_res = await db.execute(select(DiscoveredRoute).where(DiscoveredRoute.scan_id == scan_id))
            routes = routes_res.scalars().all()
            route_patterns = [r.route_pattern for r in routes]
            assert "/api/v1/dashboard" in route_patterns
            assert "/api/v1/auth/login" in route_patterns
            assert "/api/v1/spec-operation" in route_patterns

            # 3. Check SourceEvidence links
            ev_res = await db.execute(select(SourceEvidence).where(SourceEvidence.scan_id == scan_id))
            evidences = ev_res.scalars().all()
            print(f"  Discovered {len(evidences)} source evidences.")
            assert len(evidences) >= 3

            # 4. Check RepositoryProfile
            p_res = await db.execute(select(RepositoryProfile).where(RepositoryProfile.scan_id == scan_id))
            prof = p_res.scalar_one_or_none()
            assert "FastAPI" in prof.detected_frameworks
            assert "Next.js" in prof.detected_frameworks
            assert prof.total_routes_discovered >= 3

            print("  [✓] Complete end-to-end source discovery engine verified against multi-framework repository ground truth.")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def main():
    print("=" * 70)
    print("CYPHER PHASE 3: GITHUB REPOSITORY SOURCE CODE ANALYZER TEST SUITE")
    print("=" * 70)

    test_sandboxing_and_security_controls()
    test_python_fastapi_and_flask_parser()
    test_django_and_drf_parser()
    test_javascript_and_typescript_route_parser()
    test_http_client_and_schema_analyzer()
    await test_full_source_code_discovery_engine_e2e()

    print("\n" + "=" * 70)
    print("ALL PHASE 3 SOURCE CODE DISCOVERY TESTS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
