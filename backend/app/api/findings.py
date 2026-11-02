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

from app.schemas.scans import FindingResponse, RetestResponse, FindingsMetricsResponse
from app.scanner.orchestrator.orchestrator import sanitize_sensitive_data
from app.core.security import get_optional_user

router = APIRouter()

@router.get("/metrics", response_model=FindingsMetricsResponse)
async def get_findings_metrics(
    scan_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    """Retrieve aggregate findings metrics calculated directly from database records."""
    stmt = select(Finding)
    if scan_id and isinstance(scan_id, str):
        stmt = stmt.where(Finding.scan_id == scan_id)

    res = await db.execute(stmt)
    findings = res.scalars().all()

    metrics = FindingsMetricsResponse(
        total=len(findings),
        critical=sum(1 for f in findings if (f.severity or "").upper() == "CRITICAL"),
        high=sum(1 for f in findings if (f.severity or "").upper() == "HIGH"),
        medium=sum(1 for f in findings if (f.severity or "").upper() == "MEDIUM"),
        low=sum(1 for f in findings if (f.severity or "").upper() == "LOW"),
        info=sum(1 for f in findings if (f.severity or "").upper() in ["INFO", "INFORMATIONAL"]),
        confirmed=sum(1 for f in findings if (f.status or "").lower() in ["verified", "confirmed"]),
        likely=sum(1 for f in findings if (f.status or "").lower() in ["likely"]),
        unconfirmed=sum(1 for f in findings if (f.status or "").lower() in ["open", "unconfirmed", "candidate"]),
        false_positive=sum(1 for f in findings if (f.status or "").lower() in ["false_positive", "closed"])
    )
    return metrics

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    detection_method: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user)
):
    """Retrieve findings from database with multi-dimensional filtering and search."""
    actual_limit = limit if isinstance(limit, int) else 100
    actual_offset = offset if isinstance(offset, int) else 0
    actual_user = user if isinstance(user, dict) else None
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
    if vulnerability_type:
        stmt = stmt.where(Finding.vulnerability_type.ilike(f"%{vulnerability_type}%"))
    if detection_method:
        stmt = stmt.where(Finding.detection_method == detection_method)
        
    stmt = stmt.order_by(Finding.created_at.desc()).offset(actual_offset).limit(actual_limit)
    res = await db.execute(stmt)
    findings = res.scalars().all()
    
    results = []
    for f in findings:
        resp = FindingResponse.model_validate(f)
        resp.title = f.title or f.vulnerability_type
        if f.endpoint:
            resp.endpoint_path = f.endpoint.path
            resp.http_method = f.http_method or f.endpoint.method or "GET"
        else:
            resp.endpoint_path = f.affected_endpoint or f.affected_url or (f"{f.source_file}:{f.source_line_start}" if f.source_file else None)
            resp.http_method = f.http_method or "GET"

        if f.parameter:
            resp.parameter_name = f.parameter.name
        elif f.parameter_name:
            resp.parameter_name = f.parameter_name

        # Transparent explainable priority reasons
        reasons = [
            f"{f.severity.capitalize()} severity rating",
            f"Detected via {f.detection_method or 'differential probe'}"
        ]
        if f.endpoint and f.endpoint.is_api:
            reasons.append("Direct API surface exposure")
        if f.endpoint and (f.endpoint.priority_score or 0) > 30:
            reasons.append(f"High-exposure attack surface endpoint (score: {f.endpoint.priority_score})")
        if resp.parameter_name:
            reasons.append(f"Direct injection into parameter '{resp.parameter_name}'")
        resp.priority_reasons = reasons

        # Client-side / query search filter match if specified
        if search:
            s_lower = search.lower()
            text_corpus = f"{resp.title} {resp.vulnerability_type} {resp.endpoint_path or ''} {resp.source_file or ''} {resp.cwe or ''} {resp.severity}".lower()
            if s_lower not in text_corpus:
                continue

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
    resp.title = finding.title or finding.vulnerability_type
    if finding.endpoint:
        resp.endpoint_path = finding.endpoint.path
        resp.http_method = finding.http_method or finding.endpoint.method or "GET"
    else:
        resp.endpoint_path = finding.affected_endpoint or finding.affected_url or (f"{finding.source_file}:{finding.source_line_start}" if finding.source_file else None)
        resp.http_method = finding.http_method or "GET"

    if finding.parameter:
        resp.parameter_name = finding.parameter.name
    elif finding.parameter:
        resp.parameter_name = finding.parameter

    reasons = [
        f"{finding.severity.capitalize()} severity rating",
        f"Detected via {finding.detection_method or 'differential probe'}"
    ]
    if finding.endpoint and finding.endpoint.is_api:
        reasons.append("Direct API surface exposure")
    if finding.endpoint and (finding.endpoint.priority_score or 0) > 30:
        reasons.append(f"High-exposure attack surface endpoint (score: {finding.endpoint.priority_score})")
    if resp.parameter_name:
        reasons.append(f"Direct injection into parameter '{resp.parameter_name}'")
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
