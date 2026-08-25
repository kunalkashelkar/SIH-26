import logging
import re
import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Finding, Evidence, Endpoint, Parameter, Retest
from app.scanner.http_client import ResilientHttpClient
from app.scanner.retest.status import RetestVerdict, FindingStatus
from app.scanner.retest.comparison import RetestComparator

logger = logging.getLogger(__name__)

class RetestEngine:
    def __init__(self, db: AsyncSession, client: ResilientHttpClient):
        self.db = db
        self.client = client

    async def execute_retest(self, finding_id: str) -> tuple[Finding, Retest]:
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
        finding = res.scalar_one_or_none()
        
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        endpoint = finding.endpoint
        if not endpoint:
            raise ValueError(f"Associated endpoint not found for finding {finding_id}")

        # Extract payload and parameter name from evidence if available
        param_name = finding.parameter.name if finding.parameter else None
        if not param_name and finding.description:
            match = re.search(r"parameter ['\"]([^'\"]+)['\"]", finding.description)
            if match:
                param_name = match.group(1)

        payload = "<script>alert(1)</script>"
        if finding.evidence and len(finding.evidence) > 0:
            first_ev = finding.evidence[0]
            if first_ev.test_summary:
                p_match = re.search(r"\(Payload:\s*([^)]+)\)", first_ev.test_summary)
                if p_match:
                    payload = p_match.group(1).strip()

        # Send retest probe
        status_code = 0
        response_body = ""
        try:
            params = {param_name: payload} if (endpoint.method or "GET").upper() == "GET" and param_name else None
            data = {param_name: payload} if (endpoint.method or "GET").upper() == "POST" and param_name else None

            resp = await self.client._request(
                method=endpoint.method or "GET",
                url=endpoint.url,
                params=params,
                data=data
            )
            if resp:
                status_code = resp.status_code
                response_body = resp.text if hasattr(resp, "text") else ""
        except Exception as e:
            logger.error(f"Retest request failed: {e}")
            verdict = RetestVerdict.INCONCLUSIVE
            reason = f"Request connection failed: {e}"

        verdict, reason = RetestComparator.evaluate_response(
            vuln_type=finding.vulnerability_type,
            payload=payload,
            status_code=status_code,
            response_body=response_body
        )

        # Update finding status
        if verdict == RetestVerdict.FIXED:
            finding.status = FindingStatus.VERIFIED_FIXED.value
        elif verdict == RetestVerdict.STILL_VULNERABLE:
            finding.status = FindingStatus.OPEN.value
        else:
            finding.status = FindingStatus.REQUIRES_REVIEW.value

        retest_record = Retest(
            id=str(uuid.uuid4()),
            finding_id=finding.id,
            status="completed",
            result=f"{verdict.value}: {reason}",
            executed_at=datetime.utcnow()
        )
        self.db.add(retest_record)
        await self.db.commit()
        await self.db.refresh(finding)
        await self.db.refresh(retest_record)

        logger.info(f"Retest for finding {finding_id} completed. Verdict: {verdict.value}, New status: {finding.status}")
        return finding, retest_record
