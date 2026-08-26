from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional

from app.core.database import get_db
from app.models.models import PayloadItem
from app.schemas.scans import PayloadItemCreate, PayloadItemResponse

router = APIRouter()

@router.get("", response_model=List[PayloadItemResponse])
async def list_payloads(
    category: Optional[str] = Query(None, description="Filter by category e.g. SQLI, XSS, IDOR"),
    search: Optional[str] = Query(None, description="Search in payload string or description"),
    db: AsyncSession = Depends(get_db)
):
    """List payloads from database with usage count and success rate."""
    stmt = select(PayloadItem)
    if category and category.upper() != "ALL":
        stmt = stmt.where(PayloadItem.category == category.upper())
    if search:
        search_fmt = f"%{search}%"
        stmt = stmt.where(
            (PayloadItem.payload.ilike(search_fmt)) |
            (PayloadItem.description.ilike(search_fmt)) |
            (PayloadItem.category.ilike(search_fmt))
        )
        
    stmt = stmt.order_by(PayloadItem.usage_count.desc(), PayloadItem.created_at.desc())
    res = await db.execute(stmt)
    payloads = res.scalars().all()
    
    results = []
    for p in payloads:
        u_count = p.usage_count or 0
        s_count = p.success_count or 0
        rate = round((s_count / u_count * 100.0), 1) if u_count > 0 else 0.0
        
        results.append(PayloadItemResponse(
            id=p.id,
            category=p.category,
            payload=p.payload,
            indicator=p.indicator,
            description=p.description,
            is_custom=p.is_custom or False,
            usage_count=u_count,
            success_count=s_count,
            success_rate=rate,
            created_at=p.created_at
        ))
    return results

@router.post("", response_model=PayloadItemResponse)
async def create_payload(payload_req: PayloadItemCreate, db: AsyncSession = Depends(get_db)):
    """Create a new custom payload."""
    new_item = PayloadItem(
        category=payload_req.category.upper(),
        payload=payload_req.payload,
        indicator=payload_req.indicator or "custom_indicator",
        description=payload_req.description or "User provided custom fuzzing vector",
        is_custom=True,
        usage_count=0,
        success_count=0
    )
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)
    
    return PayloadItemResponse(
        id=new_item.id,
        category=new_item.category,
        payload=new_item.payload,
        indicator=new_item.indicator,
        description=new_item.description,
        is_custom=True,
        usage_count=0,
        success_count=0,
        success_rate=0.0,
        created_at=new_item.created_at
    )

@router.delete("/{payload_id}")
async def delete_payload(payload_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a custom payload."""
    res = await db.execute(select(PayloadItem).where(PayloadItem.id == payload_id))
    item = res.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Payload not found")
        
    await db.delete(item)
    await db.commit()
    return {"status": "Payload deleted successfully", "id": payload_id}
