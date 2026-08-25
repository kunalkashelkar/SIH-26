from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime

from app.core.database import get_db
from app.models.models import Scan, Target
from app.schemas.scans import ScanCreate, ScanResponse, ScanStatusResponse
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
