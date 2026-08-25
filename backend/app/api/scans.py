from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime

from app.core.database import get_db
from app.models.models import Scan, Target
from app.schemas.scans import ScanCreate, ScanResponse, ScanStatusResponse, ParameterResponse, AttackSurfaceResponse, AttackSurfaceNodeResponse, SubdomainResponse
from app.schemas.graph import GraphResponse
from app.scanner.prioritization.models import EndpointPriorityResult
from app.scanner.prioritization.scorer import RuleBasedPrioritizer
from app.scanner.context.parameter_context import ParameterContext
from app.scanner.fuzzer.result import FuzzTestResult
from app.scanner.fuzzer.engine import SCAN_CONTEXTS, SCAN_FUZZ_RESULTS, FuzzingEngine
from app.scanner.http_client import ResilientHttpClient
from app.scanner.graph.builder import AttackSurfaceGraphBuilder
from app.scanner.graph.serializer import GraphSerializer
from app.scanner.manager import scan_manager

router = APIRouter()

@router.post("/", response_model=ScanResponse)
async def create_scan(scan_req: ScanCreate, db: AsyncSession = Depends(get_db)):
    # 1. Ensure target exists or create it
    res = await db.execute(select(Target).where(Target.base_url == scan_req.target_url))
    target = res.scalar_one_or_none()
    
    if not target:
        target = Target(name="Auto-created Target", base_url=scan_req.target_url)
        db.add(target)
        await db.commit()
        await db.refresh(target)
        
    # 2. Create Scan
    new_scan = Scan(
        target_id=target.id,
        status="QUEUED",
        current_stage="INITIALIZING",
        scan_mode=scan_req.scan_mode,
        started_at=datetime.utcnow()
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # 3. Trigger Background Manager
    scan_manager.start_scan(new_scan.id, scan_req.model_dump())
    
    return ScanResponse(scan_id=new_scan.id, status="QUEUED")

@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    target_res = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_res.scalar_one_or_none()
    
    return ScanStatusResponse(
        status=scan.status,
        progress=scan.progress,
        current_stage=scan.current_stage,
        target_url=target.base_url if target else "Unknown",
        started_at=scan.started_at,
        completed_at=scan.completed_at
    )

@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    success = scan_manager.cancel_scan(scan_id)
    if not success:
        # Check if it even exists or is already completed in db?
        # For simplicity, we just return status
        return {"status": "Not running or could not cancel"}
    return {"status": "Cancellation requested"}

@router.get("/{scan_id}/parameters", response_model=list[ParameterResponse])
async def get_scan_parameters(scan_id: str, db: AsyncSession = Depends(get_db)):
    from app.models.models import Endpoint, Parameter
    from sqlalchemy.orm import selectinload
    
    # Check if scan exists
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Query parameters associated with the scan's endpoints
    stmt = (
        select(Parameter, Endpoint)
        .join(Endpoint, Parameter.endpoint_id == Endpoint.id)
        .where(Endpoint.scan_id == scan_id)
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
    from app.models.models import Endpoint
    from sqlalchemy.orm import selectinload
    
    # Check if scan exists
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
        
    stmt = (
        select(Endpoint)
        .options(selectinload(Endpoint.parameters))
        .where(Endpoint.scan_id == scan_id)
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
            priority_score=ep.priority_score,
            parameters=[p.name for p in ep.parameters]
        ))
        
    return AttackSurfaceResponse(
        nodes=nodes,
        total_endpoints=len(endpoints),
        total_apis=api_count
    )

@router.get("/{scan_id}/subdomains", response_model=list[SubdomainResponse])
async def get_scan_subdomains(scan_id: str, db: AsyncSession = Depends(get_db)):
    from app.models.models import Subdomain
    # Check if scan exists
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
        
    stmt = select(Subdomain).where(Subdomain.scan_id == scan_id).order_by(Subdomain.domain)
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
    # Check if scan exists
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
        
    builder = AttackSurfaceGraphBuilder(db, scan_id)
    graph = await builder.build()
    return GraphSerializer.serialize(graph)

@router.get("/{scan_id}/priorities", response_model=list[EndpointPriorityResult])
async def get_scan_priorities(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
        
    prioritizer = RuleBasedPrioritizer(db, scan_id)
    return await prioritizer.prioritize_all()

@router.get("/{scan_id}/context", response_model=list[ParameterContext])
async def get_scan_context(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan_id in SCAN_CONTEXTS:
        return SCAN_CONTEXTS[scan_id]
        
    # Build on demand
    client = ResilientHttpClient(max_requests=10)
    try:
        fuzzer = FuzzingEngine(db, scan_id, client)
        return await fuzzer.get_contexts()
    finally:
        await client.close()

@router.get("/{scan_id}/fuzz-results", response_model=list[FuzzTestResult])
async def get_scan_fuzz_results(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    return SCAN_FUZZ_RESULTS.get(scan_id, [])
