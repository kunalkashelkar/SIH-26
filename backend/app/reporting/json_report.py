import json
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from app.reporting.report_builder import ReportBuilder

logger = logging.getLogger(__name__)

class JSONReportGenerator:
    @classmethod
    async def generate(cls, db: AsyncSession, scan_id: str) -> dict:
        builder = ReportBuilder(db, scan_id)
        data = await builder.build_data()
        return data
