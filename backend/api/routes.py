from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List
import time
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import get_db
from models.models import Project, Target, Scan, Finding, Endpoint
from schemas.schemas import ProjectCreate, ProjectResponse, TargetCreate, TargetResponse, ScanCreate, ScanResponse, FindingResponse, EndpointResponse
from scanner import ScannerEngine

router = APIRouter()

@router.get("/projects", response_model=List[ProjectResponse])
async def get_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project))
    return result.scalars().all()

@router.post("/projects", response_model=ProjectResponse)
async def create_project(project: ProjectCreate, db: AsyncSession = Depends(get_db)):
    db_project = Project(name=project.name, description=project.description)
    db.add(db_project)
    await db.commit()
    await db.refresh(db_project)
    return db_project

@router.get("/targets", response_model=List[TargetResponse])
async def get_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target))
    return result.scalars().all()

@router.post("/targets", response_model=TargetResponse)
async def create_target(target: TargetCreate, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Project).where(Project.id == target.project_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
        
    db_target = Target(url=target.url, description=target.description, project_id=target.project_id)
    db.add(db_target)
    await db.commit()
    await db.refresh(db_target)
    return db_target

# In-memory dict to hold scanner instances so we can stream live logs easily.
# In a real system, you'd use Redis or a proper Task Queue (Celery) + WebSockets.
active_scanners = {}

@router.post("/scans", response_model=ScanResponse)
async def start_scan(scan_req: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Target).where(Target.id == scan_req.target_id))
    target = res.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    db_scan = Scan(target_id=target.id, status="Initializing")
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    
    scanner = ScannerEngine(db_scan.id, target.url, scan_req.request_limit, scan_req.crawl_depth)
    active_scanners[db_scan.id] = scanner
    
    background_tasks.add_task(scanner.scan)
    
    return db_scan

@router.get("/scans/{scan_id}")
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    db_scan = res.scalar_one_or_none()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scanner = active_scanners.get(scan_id)
    
    if scanner:
        # It's active, return live stats
        elapsed = int(time.time() - scanner.start_time)
        return {
            "id": db_scan.id,
            "target_id": db_scan.target_id,
            "target": scanner.target_url,
            "status": scanner.status,
            "progress": scanner.progress,
            "elapsed": elapsed,
            "logs": scanner.logs[-100:],
            "start_time": db_scan.start_time
        }
    else:
        # Completed or not active
        res_target = await db.execute(select(Target).where(Target.id == db_scan.target_id))
        target = res_target.scalar_one_or_none()
        elapsed = 0
        if db_scan.end_time and db_scan.start_time:
             elapsed = int((db_scan.end_time - db_scan.start_time).total_seconds())
             
        return {
            "id": db_scan.id,
            "target_id": db_scan.target_id,
            "target": target.url if target else "Unknown",
            "status": db_scan.status,
            "progress": db_scan.progress,
            "elapsed": elapsed,
            "logs": ["[INFO] Scan is no longer active."],
            "start_time": db_scan.start_time
        }

@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scanner = active_scanners.get(scan_id)
    if scanner:
        scanner.cancel()
        return {"message": "Cancellation requested"}
    raise HTTPException(status_code=404, detail="Active scan not found")

@router.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return result.scalars().all()

@router.get("/scans/{scan_id}/surface", response_model=List[EndpointResponse])
async def get_scan_surface(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Endpoint).where(Endpoint.scan_id == scan_id))
    return result.scalars().all()
