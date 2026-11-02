import asyncio
from datetime import datetime

from app.core.database import AsyncSessionLocal, engine, Base
from sqlalchemy.future import select
import app.models
from app.models.discovery import (
    ScanMode, DiscoveryStatus, DiscoverySource, AssetType,
    WebsiteProfile, RepositoryProfile, DiscoveredAsset,
    SourceEvidence, RuntimeEvidence, DiscoveryEvent, DiscoveryError,
    AssetRelationship
)
from app.models.models import Scan, Target
from app.scanner.orchestrator import scan_orchestrator, ValidationError

async def test_validation_rules():
    """Verify input validation for all three scan modes."""
    print("Testing ScanOrchestrator validation rules...")
    # 1. WEBSITE_ONLY requires website_url
    try:
        scan_orchestrator.validate_request({"discovery_mode": "WEBSITE_ONLY"})
        assert False, "Should have failed for missing website_url"
    except ValidationError as e:
        assert "WEBSITE_ONLY scan mode requires a valid website URL" in str(e)

    # 1b. Reject non-http/https URL
    try:
        scan_orchestrator.validate_request({"discovery_mode": "WEBSITE_ONLY", "website_url": "ftp://example.com"})
        assert False, "Should have failed for ftp scheme"
    except ValidationError as e:
        assert "Invalid website URL format" in str(e)

    # 2. GITHUB_ONLY requires repository_url
    try:
        scan_orchestrator.validate_request({"discovery_mode": "GITHUB_ONLY"})
        assert False, "Should have failed for missing repository_url"
    except ValidationError as e:
        assert "GITHUB_ONLY scan mode requires a valid GitHub repository URL" in str(e)

    # 2b. Reject invalid non-github repository URL
    try:
        scan_orchestrator.validate_request({"discovery_mode": "GITHUB_ONLY", "repository_url": "https://malicious.site/repo"})
        assert False, "Should have failed for non-github domain"
    except ValidationError as e:
        assert "Invalid repository URL" in str(e)

    # 3. HYBRID requires both
    try:
        scan_orchestrator.validate_request({"discovery_mode": "HYBRID", "website_url": "https://example.com"})
        assert False, "Should have failed for missing repository_url in HYBRID"
    except ValidationError as e:
        assert "HYBRID scan mode requires a GitHub repository URL" in str(e)

    try:
        scan_orchestrator.validate_request({"discovery_mode": "HYBRID", "repository_url": "https://github.com/OWASP/NodeGoat"})
        assert False, "Should have failed for missing website_url in HYBRID"
    except ValidationError as e:
        assert "HYBRID scan mode requires an authorized website URL" in str(e)

    # 4. Valid inputs pass
    res_web = scan_orchestrator.validate_request({"discovery_mode": "WEBSITE_ONLY", "target_url": "https://example.com"})
    assert res_web["website_url"] == "https://example.com"
    assert res_web["discovery_mode"] == "WEBSITE_ONLY"

    res_gh = scan_orchestrator.validate_request({"discovery_mode": "GITHUB_ONLY", "repository_url": "https://github.com/OWASP/NodeGoat"})
    assert res_gh["repository_url"] == "https://github.com/OWASP/NodeGoat"
    assert res_gh["repository_branch"] == "main"

    res_hybrid = scan_orchestrator.validate_request({
        "discovery_mode": "HYBRID",
        "website_url": "https://example.com",
        "repository_url": "https://github.com/OWASP/NodeGoat"
    })
    assert res_hybrid["website_url"] == "https://example.com"
    assert res_hybrid["repository_url"] == "https://github.com/OWASP/NodeGoat"
    print("  -> All validation test cases passed!")

async def test_database_models_and_persistence():
    """Verify database schema creation and record persistence across all discovery models."""
    print("Testing database models & persistence...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Create a WEBSITE_ONLY scan record
        scan_web = await scan_orchestrator.create_scan_record(db, {
            "discovery_mode": "WEBSITE_ONLY",
            "website_url": "https://test-target.com",
            "scan_mode": "Standard"
        })
        assert scan_web.id is not None
        assert scan_web.discovery_mode == "WEBSITE_ONLY"
        assert scan_web.website_url == "https://test-target.com"
        assert scan_web.status == "QUEUED"

        # Create a GITHUB_ONLY scan record
        scan_gh = await scan_orchestrator.create_scan_record(db, {
            "discovery_mode": "GITHUB_ONLY",
            "repository_url": "https://github.com/OWASP/NodeGoat",
            "repository_branch": "dev"
        })
        assert scan_gh.id is not None
        assert scan_gh.discovery_mode == "GITHUB_ONLY"
        assert scan_gh.repository_url == "https://github.com/OWASP/NodeGoat"
        assert scan_gh.repository_branch == "dev"

        # Create a HYBRID scan record
        scan_hybrid = await scan_orchestrator.create_scan_record(db, {
            "discovery_mode": "HYBRID",
            "website_url": "https://nodegoat.herokuapp.com",
            "repository_url": "https://github.com/OWASP/NodeGoat",
            "repository_branch": "main"
        })
        assert scan_hybrid.id is not None
        assert scan_hybrid.discovery_mode == "HYBRID"

        # Verify DiscoveredAsset and Evidence persistence
        asset = DiscoveredAsset(
            scan_id=scan_hybrid.id,
            asset_type=AssetType.BACKEND_API_OPERATION,
            identifier="POST /api/v1/auth/login",
            name="/api/v1/auth/login",
            path="/api/v1/auth/login",
            url="https://nodegoat.herokuapp.com/api/v1/auth/login",
            method="POST",
            discovery_status=DiscoveryStatus.BOTH,
            confidence=0.98,
            metadata_json={"controller": "authController.js"}
        )
        db.add(asset)
        await db.commit()
        await db.refresh(asset)

        # Attach SourceEvidence
        src_ev = SourceEvidence(
            scan_id=scan_hybrid.id,
            asset_id=asset.id,
            discovery_source=DiscoverySource.SOURCE_CODE_ANALYSIS,
            file_path="app/routes/auth.js",
            line_start=45,
            line_end=52,
            snippet="router.post('/login', authController.handleLogin);",
            confidence=1.0,
            verification_status=DiscoveryStatus.SOURCE_DEFINED
        )
        db.add(src_ev)

        # Attach RuntimeEvidence
        rt_ev = RuntimeEvidence(
            scan_id=scan_hybrid.id,
            asset_id=asset.id,
            discovery_source=DiscoverySource.STATIC_HTML,
            observation_type="HTTP_REQUEST",
            url="https://nodegoat.herokuapp.com/api/v1/auth/login",
            method="POST",
            response_status=200,
            confidence=1.0,
            verification_status=DiscoveryStatus.RUNTIME_OBSERVED
        )
        db.add(rt_ev)

        # Attach DiscoveryEvent and DiscoveryError
        event = DiscoveryEvent(
            scan_id=scan_hybrid.id,
            event_type="CORRELATION_MATCH",
            phase="CORRELATION",
            message="Matched source route /login to runtime endpoint /api/v1/auth/login"
        )
        db.add(event)

        error = DiscoveryError(
            scan_id=scan_hybrid.id,
            component="PLAYWRIGHT_WORKER",
            error_type="HeadlessBrowserUnavailable",
            message="Chromium sandbox binary missing; fallback to ResilientHttpClient succeeded",
            retryable=False
        )
        db.add(error)
        await db.commit()

        # Query and assert relationships with eager loading
        from sqlalchemy.orm import selectinload
        q_res = await db.execute(
            select(DiscoveredAsset)
            .options(
                selectinload(DiscoveredAsset.source_evidences),
                selectinload(DiscoveredAsset.runtime_evidences)
            )
            .where(DiscoveredAsset.id == asset.id)
        )
        loaded_asset = q_res.scalar_one()
        assert loaded_asset.id is not None
        assert len(loaded_asset.source_evidences) == 1
        assert len(loaded_asset.runtime_evidences) == 1
        assert loaded_asset.source_evidences[0].file_path == "app/routes/auth.js"
        assert loaded_asset.runtime_evidences[0].response_status == 200
        print("  -> All database models and persistence test cases passed!")

async def main():
    await test_validation_rules()
    await test_database_models_and_persistence()
    print("\nALL PHASE 1 ARCHITECTURE & DATABASE TESTS PASSED WITH 100% SUCCESS!")

if __name__ == "__main__":
    asyncio.run(main())
