import uuid
import logging
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Scan, Target
from app.repositories.scan_repository import ScanRepository
from app.core.exceptions import NotFoundException, ValidationException, ForbiddenException
from app.schemas.scans import ScanCreate

logger = logging.getLogger(__name__)

class ScanService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = ScanRepository(db)

    async def get_scan(self, scan_id: str, user_id: Optional[str] = None) -> Scan:
        scan = await self.repo.get_by_id(scan_id)
        if not scan:
            raise NotFoundException(resource="Scan", identifier=scan_id)
        if user_id and scan.user_id and scan.user_id != user_id:
            raise ForbiddenException(message="Access to this scan is not permitted")
        return scan

    async def list_scans(
        self,
        user_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None
    ) -> Tuple[List[Scan], int]:
        return await self.repo.list_scans(user_id=user_id, limit=limit, offset=offset, status=status)

    async def cancel_scan(self, scan_id: str, user_id: Optional[str] = None) -> Scan:
        scan = await self.get_scan(scan_id, user_id=user_id)
        if scan.status in ["COMPLETED", "FAILED", "CANCELLED"]:
            return scan

        from app.scanner.orchestrator import scan_orchestrator
        await scan_orchestrator.cancel_scan(scan_id)
        scan.status = "CANCELLED"
        return await self.repo.update(scan)
