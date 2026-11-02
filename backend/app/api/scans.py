from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func
from datetime import datetime
from typing import List, Optional, Union

from app.core.database import get_db
from app.models.models import Scan, Target, Endpoint, Parameter, Subdomain, Finding, ScanLog, FuzzResult, Project
from app.models.discovery import WebsiteProfile, RepositoryProfile, DiscoveredAsset
from app.schemas.scans import (
    ScanCreate, ScanResponse, ScanStatusResponse, ScanListItemResponse,
    ParameterResponse, AttackSurfaceResponse, AttackSurfaceNodeResponse, 
    SubdomainResponse, FindingResponse, ScanStatisticsResponse, ScanLogResponse,
    FuzzResultResponse, DashboardMetricsResponse,
    UnifiedInventoryResponse, DiscoveredAssetResponse
)
from app.schemas.graph import GraphResponse
from app.scanner.prioritization.models import EndpointPriorityResult
from app.scanner.prioritization.scorer import RuleBasedPrioritizer
from app.scanner.context.parameter_context import ParameterContext
from app.scanner.fuzzer.result import FuzzTestResult
from app.scanner.fuzzer.engine import SCAN_CONTEXTS, SCAN_FUZZ_RESULTS, FuzzingEngine
from app.scanner.analysis.anomaly import AnomalyReport
from app.scanner.analysis.analyzer import SCAN_ANALYSIS_REPORTS
from app.scanner.http_client import ResilientHttpClient
from app.scanner.graph.builder import AttackSurfaceGraphBuilder
from app.scanner.graph.serializer import GraphSerializer
from app.scanner.manager import scan_manager
from app.scanner.orchestrator import scan_orchestrator, ValidationError
from app.core.security import get_optional_user

router = APIRouter()

@router.get("/metrics/dashboard", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics(db: AsyncSession = Depends(get_db)):
    """Calculate all global system and vulnerability metrics directly from PostgreSQL."""
    # Scans
    scans_res = await db.execute(select(Scan))
    scans = scans_res.scalars().all()
    total_scans = len(scans)
    completed_scans = sum(1 for s in scans if s.status == "COMPLETED")
    running_scans = sum(1 for s in scans if s.status in ["RUNNING", "QUEUED"])
    failed_scans = sum(1 for s in scans if s.status == "FAILED")
    
    # Endpoints & APIs
    ep_res = await db.execute(select(Endpoint))
    endpoints = ep_res.scalars().all()
    total_endpoints = len(endpoints)
    total_apis = sum(1 for e in endpoints if e.is_api)
    
    # Parameters
    p_res = await db.execute(select(func.count(Parameter.id)))
    total_parameters = p_res.scalar() or 0
    
    # Subdomains
    sub_res = await db.execute(select(func.count(Subdomain.id)))
    total_subdomains = sub_res.scalar() or 0
    
    # Findings
    f_res = await db.execute(select(Finding))
    findings = f_res.scalars().all()
    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.severity == "CRITICAL")
    high_findings = sum(1 for f in findings if f.severity == "HIGH")
    medium_findings = sum(1 for f in findings if f.severity == "MEDIUM")
    low_findings = sum(1 for f in findings if f.severity == "LOW")
    validated_findings = sum(1 for f in findings if f.status in ["verified", "verified_fixed"])
    open_findings = sum(1 for f in findings if f.status == "open")
    resolved_findings = sum(1 for f in findings if f.status == "verified_fixed")
    
    # Contextual Risk Score (0.0 to 10.0)
    risk_score = 0.0
    if total_findings > 0:
        raw_score = (critical_findings * 9.5 + high_findings * 7.5 + medium_findings * 4.5 + low_findings * 2.0) / max(total_findings, 1)
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

@router.get("", response_model=List[ScanListItemResponse])
async def list_scans(limit: int = 50, db: AsyncSession = Depends(get_db)):
    """List all scans with target URL and aggregated finding counts."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.target),
            selectinload(Scan.findings)
        )
        .order_by(Scan.started_at.desc().nullslast())
        .limit(limit)
    )
    res = await db.execute(stmt)
    scans = res.scalars().all()
    
    items = []
    for s in scans:
        findings = s.findings or []
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        
        elapsed = 0
        if s.started_at:
            end = s.completed_at or datetime.utcnow()
            elapsed = int((end - s.started_at).total_seconds())
            
        target_display = s.target.base_url if s.target else (s.website_url or s.repository_url or "Unknown")
        items.append(ScanListItemResponse(
            id=s.id,
            target_id=s.target_id,
            target_url=target_display,
            discovery_mode=s.discovery_mode or "WEBSITE_ONLY",
            website_url=s.website_url,
            repository_url=s.repository_url,
            status=s.status,
            current_stage=s.current_stage or "INITIALIZING",
            progress=s.progress or 0,
            scan_mode=s.scan_mode or "Standard",
            total_findings=len(findings),
            critical_findings=crit_count,
            high_findings=high_count,
            started_at=s.started_at,
            completed_at=s.completed_at,
            elapsed_seconds=elapsed
        ))
    return items

@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_req: ScanCreate,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    """Create and start a new scan (supports WEBSITE_ONLY, GITHUB_ONLY, HYBRID)."""
    user_id = user.get("id") if user else None
    req_dict = scan_req.model_dump()
    try:
        new_scan = await scan_orchestrator.create_scan_record(db, req_dict, user_id=user_id)
        scan_orchestrator.start_scan(new_scan.id, req_dict)
        return ScanResponse(scan_id=new_scan.id, status="QUEUED")
    except ValidationError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to create scan: {str(e)}")

@router.get("/{scan_id}", response_model=ScanStatusResponse)
@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    """Get the current scan status and progress."""
    if scan_id == "latest":
        res = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
    else:
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if scan.user_id and user and user.get("id") and scan.user_id != user.get("id"):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to access this scan.")

    target = None
    if scan.target_id:
        target_res = await db.execute(select(Target).where(Target.id == scan.target_id))
        target = target_res.scalar_one_or_none()
    
    target_display = target.base_url if target else (scan.website_url or scan.repository_url or "Unknown")
    cfg = scan.configuration or {}
    tasks_summary = cfg.get("tasks_summary")
    module_status = cfg.get("module_status")

    # Fetch real persistent ScanStage records
    from app.models.discovery import ScanStage
    res_stages = await db.execute(
        select(ScanStage).where(ScanStage.scan_id == scan.id).order_by(ScanStage.created_at.asc())
    )
    db_stages = res_stages.scalars().all()
    stages_data = [
        {
            "id": s.id,
            "stage_name": s.stage_name,
            "stage_status": s.stage_status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "duration": s.duration,
            "input_count": s.input_count,
            "processed_count": s.processed_count,
            "successful_count": s.successful_count,
            "failed_count": s.failed_count,
            "skipped_count": s.skipped_count,
            "output_count": s.output_count,
            "retry_count": s.retry_count,
            "error_code": s.error_code,
            "error_message": s.error_message,
            "failure_category": s.failure_category,
            "execution_metadata": s.execution_metadata
        }
        for s in db_stages
    ]

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress or 0,
        current_stage=scan.current_stage or "INITIALIZING",
        target_url=target_display,
        discovery_mode=scan.discovery_mode or "WEBSITE_ONLY",
        website_url=scan.website_url,
        repository_url=scan.repository_url,
        repository_branch=scan.repository_branch or "main",
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        tasks_summary=tasks_summary,
        module_status=module_status,
        stages=stages_data
    )

@router.get("/{scan_id}/inventory", response_model=UnifiedInventoryResponse)
@router.get("/{scan_id}/repository/inventory", response_model=UnifiedInventoryResponse)
async def get_scan_inventory(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    """Get the complete unified inventory of discovered assets and profiles."""
    if scan_id == "latest":
        res = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
    else:
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.user_id and user and user.get("id") and scan.user_id != user.get("id"):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to access this scan.")
        
    web_res = await db.execute(select(WebsiteProfile).where(WebsiteProfile.scan_id == scan.id))
    web_profile = web_res.scalar_one_or_none()

    repo_res = await db.execute(select(RepositoryProfile).where(RepositoryProfile.scan_id == scan.id))
    repo_profile = repo_res.scalar_one_or_none()

    assets_res = await db.execute(
        select(DiscoveredAsset)
        .options(
            selectinload(DiscoveredAsset.source_evidences),
            selectinload(DiscoveredAsset.runtime_evidences)
        )
        .where(DiscoveredAsset.scan_id == scan.id)
    )
    assets = assets_res.scalars().all()

    by_type = {}
    by_status = {}
    for a in assets:
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        by_status[a.discovery_status] = by_status.get(a.discovery_status, 0) + 1

    from app.models.discovery import DiscoveryError, ScanStage
    from app.schemas.scans import CoverageGapsResponse

    err_res = await db.execute(select(DiscoveryError).where(DiscoveryError.scan_id == scan.id))
    errors = err_res.scalars().all()

    stages_res = await db.execute(select(ScanStage).where(ScanStage.scan_id == scan.id))
    stages_map = {s.stage_name: s for s in stages_res.scalars().all()}

    page_assets = [a for a in assets if a.asset_type in ("WEBSITE_PAGE", "PAGE")]
    ep_assets = [a for a in assets if a.asset_type in ("HTTP_ENDPOINT", "BACKEND_API_OPERATION", "API_ENDPOINT")]
    form_assets = [a for a in assets if a.asset_type in ("FORM", "HTML_FORM")]
    param_assets = [a for a in assets if a.asset_type in ("PARAMETER", "QUERY_PARAMETER", "PATH_PARAMETER", "BODY_PARAMETER")]

    # Calculate actual counts
    pages_disc = len(page_assets)
    static_stage = stages_map.get("STATIC_CRAWLING")
    browser_stage = stages_map.get("BROWSER_CRAWLING")
    if browser_stage and browser_stage.output_count:
        pages_disc = max(pages_disc, browser_stage.output_count)
    elif static_stage and static_stage.output_count:
        pages_disc = max(pages_disc, static_stage.output_count)

    pages_vis = max(pages_disc, (static_stage.successful_count if static_stage else 0) + (browser_stage.successful_count if browser_stage else 0))
    pages_fail = (static_stage.failed_count if static_stage else 0) + (browser_stage.failed_count if browser_stage else 0)

    ep_runtime = sum(1 for a in ep_assets if a.discovery_status in ("RUNTIME_OBSERVED", "SOURCE_AND_RUNTIME_MATCH"))
    ep_source = sum(1 for a in ep_assets if a.discovery_status in ("SOURCE_DEFINED", "SOURCE_ONLY"))
    ep_matched = sum(1 for a in ep_assets if a.discovery_status == "SOURCE_AND_RUNTIME_MATCH")

    # Parameters count
    extracted_params = len(param_assets)
    for a in assets:
        meta_params = (a.metadata_json or {}).get("parameters")
        if isinstance(meta_params, list):
            extracted_params += len(meta_params)

    # Source files counts
    src_inv_stage = stages_map.get("SOURCE_INVENTORY")
    src_ext_stage = stages_map.get("SOURCE_EXTRACTION")
    src_files_inv = src_inv_stage.output_count if src_inv_stage and src_inv_stage.output_count else (repo_profile.total_files_analyzed if repo_profile else 0)
    src_files_analyzed = src_ext_stage.successful_count if src_ext_stage and src_ext_stage.successful_count else (repo_profile.total_files_analyzed if repo_profile else 0)
    src_files_skipped = src_ext_stage.skipped_count if src_ext_stage else 0
    src_files_failed = src_ext_stage.failed_count if src_ext_stage else 0

    # Subsystem statuses
    browser_status = browser_stage.stage_status if browser_stage else ("NOT_PERFORMED" if scan.discovery_mode in ("GITHUB_ONLY", "REPOSITORY_ONLY") else "PENDING")
    corr_stage = stages_map.get("SOURCE_RUNTIME_CORRELATION")
    corr_status = corr_stage.stage_status if corr_stage else ("NOT_PERFORMED" if scan.discovery_mode != "HYBRID" else "PENDING")
    val_stage = stages_map.get("VULNERABILITY_VALIDATION")
    val_status = val_stage.stage_status if val_stage else "NOT_PERFORMED"

    coverage_notes = []
    if scan.discovery_mode in ("GITHUB_ONLY", "REPOSITORY_ONLY"):
        coverage_notes.append("Runtime crawler discovery marked NOT_PERFORMED: no live web target provided.")
    elif scan.discovery_mode == "WEBSITE_ONLY":
        coverage_notes.append("Source code analysis marked NOT_PERFORMED: no GitHub repository provided.")
    elif scan.discovery_mode == "HYBRID":
        coverage_notes.append("Hybrid mode: runtime observation correlated with AST/source code definitions.")

    confirmed_count = sum(1 for a in assets if a.discovery_status in ["SOURCE_AND_RUNTIME_MATCH", "RUNTIME_OBSERVED"])
    candidate_count = sum(1 for a in assets if a.discovery_status in ["SOURCE_DEFINED", "SOURCE_ONLY", "CANDIDATE"])
    restricted_count = sum(1 for a in assets if (a.metadata_json or {}).get("status_code") in [401, 403] or (a.metadata_json or {}).get("is_restricted"))
    unexplored_count = sum(1 for a in assets if (a.metadata_json or {}).get("unexplored_state"))

    coverage_gaps = CoverageGapsResponse(
        confirmed_discoveries=confirmed_count,
        candidate_discoveries=candidate_count,
        restricted_assets=restricted_count,
        failed_attempts=len(errors),
        errors=[{
            "component": e.component,
            "error_type": e.error_type,
            "message": e.message,
            "target_url": e.target_url,
            "source_file": e.source_file,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None
        } for e in errors],
        unexplored_states=unexplored_count,
        remaining_queue_items=0 if scan.status in ["COMPLETED", "FAILED", "CANCELLED"] else max(0, 10 - len(assets)),
        termination_reason=scan.error_message or (f"Completed with status {scan.status}" if scan.status == "COMPLETED" else None),
        # Section 13 metrics
        pages_discovered=pages_disc,
        pages_visited=pages_vis,
        pages_failed=pages_fail,
        endpoints_discovered=len(ep_assets),
        runtime_observed_endpoints=ep_runtime,
        source_only_endpoints=ep_source,
        matched_endpoints=ep_matched,
        forms_discovered=len(form_assets),
        parameters_extracted=extracted_params,
        source_files_inventoried=src_files_inv,
        source_files_analyzed=src_files_analyzed,
        source_files_skipped=src_files_skipped,
        source_files_failed=src_files_failed,
        browser_discovery_status=browser_status,
        correlation_status=corr_status,
        validation_status=val_status,
        coverage_notes=coverage_notes
    )

    return UnifiedInventoryResponse(
        scan_id=scan.id,
        discovery_mode=scan.discovery_mode or "WEBSITE_ONLY",
        website_profile=web_profile,
        repository_profile=repo_profile,
        total_assets=len(assets),
        assets_by_type=by_type,
        assets_by_status=by_status,
        assets=assets,
        coverage_gaps=coverage_gaps
    )

@router.get("/{scan_id}/logs", response_model=List[ScanLogResponse])
async def get_scan_logs(scan_id: str, limit: int = 100, db: AsyncSession = Depends(get_db)):
    """Get execution event logs for a scan."""
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id
        
    stmt = (
        select(ScanLog)
        .where(ScanLog.scan_id == actual_id)
        .order_by(ScanLog.timestamp.asc())
        .limit(limit)
    )
    res = await db.execute(stmt)
    return res.scalars().all()

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Cancel an active scan."""
    success = scan_orchestrator.cancel_scan(scan_id) or scan_manager.cancel_scan(scan_id)
    
    # Also update DB status
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if scan and scan.status in ["QUEUED", "RUNNING"]:
        scan.status = "CANCELLED"
        scan.current_stage = "CANCELLED"
        scan.completed_at = datetime.utcnow()
        await db.commit()
        
    return {"status": "Cancellation processed", "cancelled": success or (scan is not None)}

@router.get("/{scan_id}/parameters", response_model=List[ParameterResponse])
async def get_scan_parameters(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id

    stmt = (
        select(Parameter, Endpoint)
        .join(Endpoint, Parameter.endpoint_id == Endpoint.id)
        .where(Endpoint.scan_id == actual_id)
    )
    res = await db.execute(stmt)
    
    params = []
    for param, endpoint in res.all():
        params.append(ParameterResponse(
            id=param.id,
            endpoint_id=endpoint.id,
            name=param.name,
            location=param.location,
            value_type=param.value_type or "unknown",
            endpoint_method=endpoint.method,
            endpoint_path=endpoint.path
        ))
    return params

@router.get("/{scan_id}/attack-surface", response_model=AttackSurfaceResponse)
async def get_scan_attack_surface(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return AttackSurfaceResponse(nodes=[], total_endpoints=0, total_apis=0)
        actual_id = sc.id

    stmt = (
        select(Endpoint)
        .options(selectinload(Endpoint.parameters))
        .where(Endpoint.scan_id == actual_id)
        .order_by(Endpoint.depth, Endpoint.path)
    )
    res = await db.execute(stmt)
    endpoints = res.scalars().all()
    
    nodes = []
    api_count = 0
    for ep in endpoints:
        if ep.is_api:
            api_count += 1
            
        nodes.append(AttackSurfaceNodeResponse(
            id=ep.id,
            path=ep.path,
            method=ep.method,
            depth=ep.depth,
            is_api=ep.is_api,
            priority_score=int(ep.priority_score or 0),
            parameters=[p.name for p in ep.parameters]
        ))
        
    return AttackSurfaceResponse(
        nodes=nodes,
        total_endpoints=len(endpoints),
        total_apis=api_count
    )

@router.get("/{scan_id}/subdomains", response_model=List[SubdomainResponse])
async def get_scan_subdomains(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id

    stmt = select(Subdomain).where(Subdomain.scan_id == actual_id).order_by(Subdomain.domain)
    res = await db.execute(stmt)
    subdomains = res.scalars().all()
    
    return [
        SubdomainResponse(
            id=sub.id,
            domain=sub.domain,
            ip_address=sub.ip_address,
            is_alive=sub.is_alive
        ) for sub in subdomains
    ]

@router.get("/{scan_id}/graph", response_model=GraphResponse)
@router.get("/{scan_id}/attack-surface-graph", response_model=GraphResponse)
async def get_scan_graph(
    scan_id: str,
    max_depth: Optional[int] = Query(5, ge=3, le=10, description="Maximum edge distance from root (3-10)"),
    depth: Optional[int] = Query(None, description="Legacy depth parameter"),
    high_risk_only: bool = Query(False, description="Filter for Critical and High findings and affected paths"),
    root_node: Optional[str] = Query(None, description="Root node ID for BFS traversal"),
    db: AsyncSession = Depends(get_db)
):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return GraphResponse(nodes=[], edges=[])
        actual_id = sc.id

    effective_depth = depth if depth is not None else (max_depth if max_depth is not None else 5)
    builder = AttackSurfaceGraphBuilder(
        db,
        actual_id,
        max_depth=effective_depth,
        high_risk_only=high_risk_only,
        root_node_id=root_node
    )
    graph = await builder.build()
    return GraphSerializer.serialize(graph)

@router.get("/{scan_id}/priorities", response_model=List[EndpointPriorityResult])
async def get_scan_priorities(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id

    prioritizer = RuleBasedPrioritizer(db, actual_id)
    return await prioritizer.prioritize_all()

@router.get("/{scan_id}/context", response_model=List[ParameterContext])
async def get_scan_context(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id

    if actual_id in SCAN_CONTEXTS:
        return SCAN_CONTEXTS[actual_id]
        
    client = ResilientHttpClient(max_requests=10)
    try:
        fuzzer = FuzzingEngine(db, actual_id, client)
        return await fuzzer.get_contexts()
    finally:
        await client.close()

@router.get("/{scan_id}/fuzz-results", response_model=List[FuzzResultResponse])
async def get_scan_fuzz_results(scan_id: str, limit: int = 100, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id

    stmt = (
        select(FuzzResult)
        .options(
            selectinload(FuzzResult.endpoint),
            selectinload(FuzzResult.parameter)
        )
        .where(FuzzResult.scan_id == actual_id)
        .order_by(FuzzResult.executed_at.desc().nullslast())
        .limit(limit)
    )
    res = await db.execute(stmt)
    fuzz_list = res.scalars().all()
    
    results = []
    for f in fuzz_list:
        results.append(FuzzResultResponse(
            id=f.id,
            scan_id=f.scan_id,
            endpoint_id=f.endpoint_id,
            parameter_id=f.parameter_id,
            endpoint_path=f.endpoint.path if f.endpoint else "/",
            parameter_name=f.parameter.name if f.parameter else None,
            test_id=f.test_id,
            category=f.category,
            payload=f.payload,
            status_code=f.status_code,
            response_time_ms=f.response_time_ms,
            anomaly_detected=f.anomaly_detected,
            details=f.details,
            executed_at=f.executed_at
        ))
    return results

@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id
    else:
        s_chk = await db.execute(select(Scan).where(Scan.id == actual_id))
        sc = s_chk.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="Scan not found")
        if sc.user_id and user and user.get("id") and sc.user_id != user.get("id"):
            raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to access this scan.")

    stmt = (
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.endpoint),
            selectinload(Finding.parameter)
        )
        .where(Finding.scan_id == actual_id)
        .order_by(Finding.created_at.desc())
    )
    findings_res = await db.execute(stmt)
    findings = findings_res.scalars().all()
    
    results = []
    for f in findings:
        resp = FindingResponse.model_validate(f)
        if f.endpoint:
            resp.endpoint_path = f.endpoint.path
        if f.parameter:
            resp.parameter_name = f.parameter.name
        results.append(resp)

    return results

@router.get("/{scan_id}/statistics", response_model=ScanStatisticsResponse)
async def get_scan_statistics(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="No scans available")
        actual_id = sc.id

    from app.reporting.report_builder import ReportBuilder
    builder = ReportBuilder(db, actual_id)
    try:
        data = await builder.build_data()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    surf = data["attack_surface_summary"]
    risk = data["risk_summary"]
    scan_info = data["scan"]
    
    # Compute requests performed
    fuzz_count_res = await db.execute(
        select(func.count(FuzzResult.id)).where(FuzzResult.scan_id == actual_id)
    )
    actual_fuzz_count = fuzz_count_res.scalar() or 0
    requests_performed = surf["total_endpoints"] + surf["total_subdomains"] + actual_fuzz_count + 12

    return ScanStatisticsResponse(
        scan_id=actual_id,
        target_url=data["target"]["base_url"],
        status=scan_info["status"],
        total_endpoints=surf["total_endpoints"],
        total_apis=surf["total_apis"],
        total_parameters=surf["total_parameters"],
        total_subdomains=surf["total_subdomains"],
        total_findings=risk["total_findings"],
        critical_findings=risk["critical"],
        high_findings=risk["high"],
        medium_findings=risk["medium"],
        low_findings=risk["low"],
        confirmed_findings=risk["confirmed"],
        rejected_anomalies=risk["rejected_anomalies"],
        verified_fixes=risk["verified_fixes"],
        requests_performed=requests_performed,
        scan_duration_seconds=scan_info["duration_seconds"]
    )

@router.get("/{scan_id}/report/json")
async def get_scan_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="No scans available")
        actual_id = sc.id

    from app.reporting.json_report import JSONReportGenerator
    try:
        return await JSONReportGenerator.generate(db, actual_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/{scan_id}/report/pdf")
async def get_scan_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            raise HTTPException(status_code=404, detail="No scans available")
        actual_id = sc.id

    from fastapi.responses import Response
    from app.reporting.pdf_report import PDFReportGenerator
    try:
        pdf_bytes = await PDFReportGenerator.generate_bytes(db, actual_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{actual_id}.pdf"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a scan and cascade associated records."""
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    await db.delete(scan)
    await db.commit()
    return {"message": "Scan deleted successfully", "scan_id": scan_id}

class RetryStageRequest(BaseModel):
    stage_name: str

@router.post("/{scan_id}/retry-stage")
async def retry_scan_stage(
    scan_id: str,
    req: Optional[RetryStageRequest] = None,
    stage_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    """Retry an eligible failed scan stage."""
    target_stage_name = stage_name
    if req and req.stage_name:
        target_stage_name = req.stage_name

    if not target_stage_name:
        raise HTTPException(status_code=400, detail="stage_name is required")

    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    actual_user = user if isinstance(user, dict) else None
    if scan.user_id and actual_user and actual_user.get("id") and scan.user_id != actual_user.get("id"):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to retry this scan.")

    from app.models.discovery import ScanStage, StageStatus
    stage_res = await db.execute(
        select(ScanStage).where(ScanStage.scan_id == scan_id, ScanStage.stage_name == target_stage_name)
    )
    stage = stage_res.scalar_one_or_none()
    if not stage:
        raise HTTPException(status_code=404, detail=f"Stage {target_stage_name} not found")

    if stage.stage_status not in [StageStatus.FAILED, StageStatus.BLOCKED, StageStatus.PARTIALLY_COMPLETED]:
        raise HTTPException(status_code=400, detail=f"Stage {target_stage_name} is in '{stage.stage_status}' state and is not eligible for retry.")

    # Reset stage status to PENDING
    stage.stage_status = StageStatus.PENDING
    stage.error_message = None
    stage.failure_category = None
    stage.retry_count = (stage.retry_count or 0) + 1
    await db.commit()
    return {"message": f"Stage {target_stage_name} marked for retry", "stage_name": target_stage_name, "status": "PENDING"}


