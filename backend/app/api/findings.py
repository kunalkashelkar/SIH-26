from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.models import Finding, Retest
from app.schemas.scans import FindingResponse, RetestResponse
from app.scanner.http_client import ResilientHttpClient
from app.scanner.retest.engine import RetestEngine

router = APIRouter()

@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding_by_id(finding_id: str, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.endpoint),
            selectinload(Finding.parameter)
        )
        .where(Finding.id == finding_id)
    )
    res = await db.execute(stmt)
    finding = res.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    resp = FindingResponse.model_validate(finding)
    if finding.endpoint:
        resp.endpoint_path = finding.endpoint.path
    if finding.parameter:
        resp.parameter_name = finding.parameter.name
        
    return resp

@router.post("/{finding_id}/retest", response_model=dict)
async def retest_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    client = ResilientHttpClient(max_requests=10, timeout=10)
    try:
        engine = RetestEngine(db, client)
        finding, retest = await engine.execute_retest(finding_id)
        return {
            "finding_id": finding.id,
            "status": finding.status,
            "retest_id": retest.id,
            "result": retest.result,
            "executed_at": retest.executed_at
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        await client.close()

@router.get("/{finding_id}/retests", response_model=list[RetestResponse])
async def get_finding_retests(finding_id: str, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Retest)
        .where(Retest.finding_id == finding_id)
        .order_by(Retest.executed_at.desc())
    )
    res = await db.execute(stmt)
    retests = res.scalars().all()
    return retests
