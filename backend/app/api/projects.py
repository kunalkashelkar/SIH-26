from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List

from app.core.database import get_db
from app.models.models import Project, Target, Scan, Finding
from app.schemas.scans import ProjectCreate, ProjectResponse

router = APIRouter()

@router.get("", response_model=List[ProjectResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    """List all projects with real targets, scans, findings counts, and risk score."""
    stmt = (
        select(Project)
        .options(
            selectinload(Project.targets)
            .selectinload(Target.scans)
            .selectinload(Scan.findings)
        )
        .order_by(Project.created_at.desc())
    )
    res = await db.execute(stmt)
    projects = res.scalars().all()
    
    items = []
    for p in projects:
        targets = p.targets or []
        scans = []
        findings = []
        for t in targets:
            for s in t.scans:
                scans.append(s)
                if s.findings:
                    findings.extend(s.findings)
                    
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        
        # Risk score calculation 0.0 - 10.0
        risk_score = 0.0
        if findings:
            if crit_count > 0:
                risk_score = round(min(7.5 + (crit_count * 0.5) + (high_count * 0.2), 9.9), 1)
            elif high_count > 0:
                risk_score = round(min(5.0 + (high_count * 0.4) + (med_count * 0.1), 7.4), 1)
            elif med_count > 0:
                risk_score = round(min(2.5 + (med_count * 0.3), 4.9), 1)
            else:
                risk_score = 1.5

        items.append(ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            created_at=p.created_at,
            total_targets=len(targets),
            total_scans=len(scans),
            total_findings=len(findings),
            risk_score=risk_score
        ))
    return items

@router.post("", response_model=ProjectResponse)
async def create_project(proj_req: ProjectCreate, db: AsyncSession = Depends(get_db)):
    """Create a new project."""
    new_proj = Project(
        name=proj_req.name,
        description=proj_req.description or "Security workspace for target applications"
    )
    db.add(new_proj)
    await db.commit()
    await db.refresh(new_proj)
    
    return ProjectResponse(
        id=new_proj.id,
        name=new_proj.name,
        description=new_proj.description,
        created_at=new_proj.created_at,
        total_targets=0,
        total_scans=0,
        total_findings=0,
        risk_score=0.0
    )

@router.delete("/{project_id}")
async def delete_project(project_id: str, db: AsyncSession = Depends(get_db)):
    """Delete project and associated targets."""
    res = await db.execute(select(Project).where(Project.id == project_id))
    proj = res.scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
        
    await db.delete(proj)
    await db.commit()
    return {"status": "Project deleted successfully", "id": project_id}
