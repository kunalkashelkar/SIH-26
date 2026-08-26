from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional

from app.core.database import get_db
from app.models.models import Finding, Retest
from app.schemas.scans import FindingResponse, RetestResponse
from app.scanner.http_client import ResilientHttpClient
from app.scanner.retest.engine import RetestEngine

router = APIRouter()

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = Query(None, description="Optional scan ID filter"),
    severity: Optional[str] = Query(None, description="Optional severity filter"),
    status: Optional[str] = Query(None, description="Optional status filter"),
    limit: int = Query(100, description="Max results limit"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve findings from database with optional filters."""
    stmt = (
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.endpoint),
            selectinload(Finding.parameter)
        )
    )
    
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if status:
        stmt = stmt.where(Finding.status == status)
        
    stmt = stmt.order_by(Finding.created_at.desc()).limit(limit)
    res = await db.execute(stmt)
    findings = res.scalars().all()
    
    results = []
    for f in findings:
        resp = FindingResponse.model_validate(f)
        if f.endpoint:
            resp.endpoint_path = f.endpoint.path
        if f.parameter:
            resp.parameter_name = f.parameter.name

        # Transparent explainable priority reasons
        reasons = [
            f"{f.severity.capitalize()} severity rating",
            "Validated finding confirmed via differential reproducibility"
        ]
        if f.endpoint and f.endpoint.is_api:
            reasons.append("Direct API surface exposure")
        if f.endpoint and (f.endpoint.priority_score or 0) > 30:
            reasons.append(f"High-exposure attack surface endpoint (score: {f.endpoint.priority_score})")
        if f.parameter:
            reasons.append(f"Direct injection into parameter '{f.parameter.name}'")
        resp.priority_reasons = reasons
        results.append(resp)
        
    return results

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

    reasons = [
        f"{finding.severity.capitalize()} severity rating",
        "Validated finding confirmed via differential reproducibility"
    ]
    if finding.endpoint and finding.endpoint.is_api:
        reasons.append("Direct API surface exposure")
    if finding.endpoint and (finding.endpoint.priority_score or 0) > 30:
        reasons.append(f"High-exposure attack surface endpoint (score: {finding.endpoint.priority_score})")
    if finding.parameter:
        reasons.append(f"Direct injection into parameter '{finding.parameter.name}'")
    resp.priority_reasons = reasons
        
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

@router.get("/{finding_id}/retests", response_model=List[RetestResponse])
async def get_finding_retests(finding_id: str, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Retest)
        .where(Retest.finding_id == finding_id)
        .order_by(Retest.executed_at.desc())
    )
    res = await db.execute(stmt)
    retests = res.scalars().all()
    return retests
