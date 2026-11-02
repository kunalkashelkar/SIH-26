from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional

from app.core.database import get_db
from app.models.models import Endpoint, Parameter
from app.schemas.scans import EndpointDetailResponse, ParameterResponse
from app.core.exceptions import NotFoundException

router = APIRouter()

@router.get("", response_model=List[EndpointDetailResponse])
async def list_endpoints(
    scan_id: Optional[str] = None,
    is_api: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve discovered endpoints with optional filtering by scan or API status."""
    stmt = select(Endpoint).options(selectinload(Endpoint.parameters))
    if scan_id:
        stmt = stmt.where(Endpoint.scan_id == scan_id)
    if is_api is not None:
        stmt = stmt.where(Endpoint.is_api == is_api)
    
    stmt = stmt.order_by(Endpoint.created_at.desc()).offset(offset).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{endpoint_id}", response_model=EndpointDetailResponse)
async def get_endpoint(endpoint_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve single endpoint by ID."""
    stmt = select(Endpoint).options(selectinload(Endpoint.parameters)).where(Endpoint.id == endpoint_id)
    res = await db.execute(stmt)
    ep = res.scalar_one_or_none()
    if not ep:
        raise NotFoundException(resource="Endpoint", identifier=endpoint_id)
    return ep

@router.get("/{endpoint_id}/parameters", response_model=List[ParameterResponse])
async def get_endpoint_parameters(endpoint_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve all parameters associated with an endpoint."""
    stmt = select(Parameter).where(Parameter.endpoint_id == endpoint_id)
    res = await db.execute(stmt)
    return res.scalars().all()
