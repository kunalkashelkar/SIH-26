from typing import Optional, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func, desc

from app.models.models import Finding

class FindingRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, finding_id: str) -> Optional[Finding]:
        stmt = (
            select(Finding)
            .options(
                selectinload(Finding.evidence),
                selectinload(Finding.endpoint),
                selectinload(Finding.parameter)
            )
            .where(Finding.id == finding_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def list_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        detection_method: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[Finding], int]:
        count_stmt = select(func.count(Finding.id))
        stmt = (
            select(Finding)
            .options(
                selectinload(Finding.evidence),
                selectinload(Finding.endpoint),
                selectinload(Finding.parameter)
            )
            .order_by(desc(Finding.created_at))
        )

        if scan_id:
            count_stmt = count_stmt.where(Finding.scan_id == scan_id)
            stmt = stmt.where(Finding.scan_id == scan_id)
        if severity:
            count_stmt = count_stmt.where(Finding.severity == severity.upper())
            stmt = stmt.where(Finding.severity == severity.upper())
        if status:
            count_stmt = count_stmt.where(Finding.status == status)
            stmt = stmt.where(Finding.status == status)
        if vulnerability_type:
            count_stmt = count_stmt.where(Finding.vulnerability_type.ilike(f"%{vulnerability_type}%"))
            stmt = stmt.where(Finding.vulnerability_type.ilike(f"%{vulnerability_type}%"))
        if detection_method:
            count_stmt = count_stmt.where(Finding.detection_method == detection_method)
            stmt = stmt.where(Finding.detection_method == detection_method)

        total_res = await self.db.execute(count_stmt)
        total = total_res.scalar() or 0

        res = await self.db.execute(stmt.offset(offset).limit(limit))
        items = res.scalars().all()
        return items, total
