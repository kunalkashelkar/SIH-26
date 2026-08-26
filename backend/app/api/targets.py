from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List
from urllib.parse import urlparse

from app.core.database import get_db
from app.models.models import Target, Scan, Finding, Project
from app.schemas.scans import TargetCreate, TargetResponse

router = APIRouter()

@router.get("", response_model=List[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)):
    """Retrieve all defined targets with scan metrics."""
    stmt = (
        select(Target)
        .options(
            selectinload(Target.scans).selectinload(Scan.findings)
        )
        .order_by(Target.created_at.desc())
    )
    res = await db.execute(stmt)
    targets = res.scalars().all()
    
    items = []
    for t in targets:
        # Collect all findings across all scans for this target
        all_findings = []
        last_scan_date = None
        for s in t.scans:
            if s.started_at:
                if last_scan_date is None or s.started_at > last_scan_date:
                    last_scan_date = s.started_at
            if s.findings:
                all_findings.extend(s.findings)
                
        crit_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in all_findings if f.severity == "HIGH")
        med_count = sum(1 for f in all_findings if f.severity == "MEDIUM")
        
        if crit_count > 0:
            risk = "CRITICAL"
        elif high_count > 0:
            risk = "HIGH"
        elif med_count > 0:
            risk = "MEDIUM"
        else:
            risk = "LOW"
            
        items.append(TargetResponse(
            id=t.id,
            project_id=t.project_id,
            name=t.name,
            base_url=t.base_url,
            description=t.description,
            created_at=t.created_at,
            last_scanned=last_scan_date,
            total_findings=len(all_findings),
            risk_status=risk
        ))
    return items

@router.post("", response_model=TargetResponse)
async def create_target(target_req: TargetCreate, db: AsyncSession = Depends(get_db)):
    """Create a new target for scanning."""
    # Check if target URL already exists
    res = await db.execute(select(Target).where(Target.base_url == target_req.base_url))
    existing = res.scalar_one_or_none()
    if existing:
        return TargetResponse(
            id=existing.id,
            project_id=existing.project_id,
            name=existing.name,
            base_url=existing.base_url,
            description=existing.description,
            created_at=existing.created_at,
            last_scanned=None,
            total_findings=0,
            risk_status="LOW"
        )
        
    name = target_req.name
    if not name:
        parsed = urlparse(target_req.base_url)
        name = parsed.netloc or target_req.base_url
        
    new_target = Target(
        name=name,
        base_url=target_req.base_url,
        project_id=target_req.project_id,
        description=target_req.description or "User defined scan target"
    )
    db.add(new_target)
    await db.commit()
    await db.refresh(new_target)
    
    return TargetResponse(
        id=new_target.id,
        project_id=new_target.project_id,
        name=new_target.name,
        base_url=new_target.base_url,
        description=new_target.description,
        created_at=new_target.created_at,
        last_scanned=None,
        total_findings=0,
        risk_status="LOW"
    )

@router.delete("/{target_id}")
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Delete target and cascade delete related scans."""
    res = await db.execute(select(Target).where(Target.id == target_id))
    target = res.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
        
    await db.delete(target)
    await db.commit()
    return {"status": "Target deleted successfully", "id": target_id}
