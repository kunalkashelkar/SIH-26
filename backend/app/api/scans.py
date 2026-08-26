from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func
from datetime import datetime
from typing import List, Optional

from app.core.database import get_db
from app.models.models import Scan, Target, Endpoint, Parameter, Subdomain, Finding, ScanLog, FuzzResult, Project
from app.schemas.scans import (
    ScanCreate, ScanResponse, ScanStatusResponse, ScanListItemResponse,
    ParameterResponse, AttackSurfaceResponse, AttackSurfaceNodeResponse, 
    SubdomainResponse, FindingResponse, ScanStatisticsResponse, ScanLogResponse,
    FuzzResultResponse, DashboardMetricsResponse
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
            
        items.append(ScanListItemResponse(
            id=s.id,
            target_id=s.target_id,
            target_url=s.target.base_url if s.target else "Unknown",
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
async def create_scan(scan_req: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create and start a new scan."""
    # 1. Ensure target exists or create it
    target = None
    if scan_req.target_id:
        res = await db.execute(select(Target).where(Target.id == scan_req.target_id))
        target = res.scalar_one_or_none()
        
    if not target:
        res = await db.execute(select(Target).where(Target.base_url == scan_req.target_url))
        target = res.scalar_one_or_none()
    
    if not target:
        # Get first project if available
        p_res = await db.execute(select(Project).limit(1))
        first_proj = p_res.scalars().first()
        proj_id = scan_req.project_id or (first_proj.id if first_proj else None)
        
        # Determine a clean display name
        from urllib.parse import urlparse
        parsed = urlparse(scan_req.target_url)
        target_name = parsed.netloc or scan_req.target_url

        target = Target(
            name=target_name,
            base_url=scan_req.target_url,
            project_id=proj_id,
            description=f"Target created for scan {scan_req.scan_mode}"
        )
        db.add(target)
        await db.commit()
        await db.refresh(target)
        
    # 2. Create Scan
    new_scan = Scan(
        target_id=target.id,
        status="QUEUED",
        current_stage="INITIALIZING",
        scan_mode=scan_req.scan_mode,
        started_at=datetime.utcnow(),
        progress=0
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # 3. Trigger Background Manager
    scan_manager.start_scan(new_scan.id, scan_req.model_dump())
    
    return ScanResponse(scan_id=new_scan.id, status="QUEUED")

@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get the current scan status and progress."""
    if scan_id == "latest":
        res = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
    else:
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    target_res = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_res.scalar_one_or_none()
    
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress or 0,
        current_stage=scan.current_stage or "INITIALIZING",
        target_url=target.base_url if target else "Unknown",
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message
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
    success = scan_manager.cancel_scan(scan_id)
    
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
async def get_scan_graph(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return GraphResponse(nodes=[], edges=[])
        actual_id = sc.id

    builder = AttackSurfaceGraphBuilder(db, actual_id)
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
async def get_scan_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    actual_id = scan_id
    if scan_id == "latest":
        latest = await db.execute(select(Scan).order_by(Scan.started_at.desc().nullslast()).limit(1))
        sc = latest.scalar_one_or_none()
        if not sc:
            return []
        actual_id = sc.id

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
