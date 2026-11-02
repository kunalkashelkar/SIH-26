from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.models import Finding
from app.repositories.finding_repository import FindingRepository
from app.core.exceptions import NotFoundException

class FindingService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = FindingRepository(db)

    async def get_finding(self, finding_id: str) -> Finding:
        finding = await self.repo.get_by_id(finding_id)
        if not finding:
            raise NotFoundException(resource="Finding", identifier=finding_id)
        return finding

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
        return await self.repo.list_findings(
            scan_id=scan_id,
            severity=severity,
            status=status,
            vulnerability_type=vulnerability_type,
            detection_method=detection_method,
            limit=limit,
            offset=offset
        )
