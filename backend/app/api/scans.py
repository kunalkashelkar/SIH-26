from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime

from app.core.database import get_db
from app.models.models import Scan, Target
from app.schemas.scans import ScanCreate, ScanResponse, ScanStatusResponse

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
        status="queued",
        scan_mode=scan_req.scan_mode,
        started_at=datetime.utcnow()
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    return ScanResponse(scan_id=new_scan.id, status="queued")

@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    target_res = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_res.scalar_one_or_none()
        
    # Mocking current_stage for the frontend requirement
    current_stage = "Initialization"
    if scan.status == "queued": current_stage = "Queued for execution"
    elif scan.progress > 0 and scan.progress < 100: current_stage = "Discovery & Scanning"
    elif scan.progress == 100: current_stage = "Complete"
    
    return ScanStatusResponse(
        status=scan.status,
        progress=scan.progress,
        current_stage=current_stage,
        target_url=target.base_url if target else "Unknown",
        started_at=scan.started_at,
        completed_at=scan.completed_at
    )
