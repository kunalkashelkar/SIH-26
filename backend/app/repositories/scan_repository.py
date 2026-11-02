from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func, desc

from app.models.models import Scan, Endpoint, Finding, Target
from app.models.discovery import ScanStage

class ScanRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_id(self, scan_id: str, user_id: Optional[str] = None) -> Optional[Scan]:
        """Fetch scan by ID, optionally enforcing user ownership isolation."""
        stmt = (
            select(Scan)
            .options(
                selectinload(Scan.endpoints),
                selectinload(Scan.findings),
                selectinload(Scan.target),
                selectinload(Scan.stages)
            )
            .where(Scan.id == scan_id)
        )
        if user_id:
            stmt = stmt.where(Scan.user_id == user_id)
        
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def list_scans(
        self,
        user_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None
    ) -> Tuple[List[Scan], int]:
        """Fetch paginated scans with total count."""
        count_stmt = select(func.count(Scan.id))
        stmt = (
            select(Scan)
            .options(
                selectinload(Scan.target),
                selectinload(Scan.endpoints),
                selectinload(Scan.findings)
            )
            .order_by(desc(Scan.started_at), desc(Scan.id))
        )
        if user_id:
            count_stmt = count_stmt.where(Scan.user_id == user_id)
            stmt = stmt.where(Scan.user_id == user_id)
        if status:
            count_stmt = count_stmt.where(Scan.status == status)
            stmt = stmt.where(Scan.status == status)

        total_res = await self.db.execute(count_stmt)
        total = total_res.scalar() or 0

        res = await self.db.execute(stmt.offset(offset).limit(limit))
        items = res.scalars().all()
        return items, total

    async def create(self, scan: Scan) -> Scan:
        """Persist a new scan record."""
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        return scan

    async def update(self, scan: Scan) -> Scan:
        """Update existing scan."""
        await self.db.commit()
        await self.db.refresh(scan)
        return scan
