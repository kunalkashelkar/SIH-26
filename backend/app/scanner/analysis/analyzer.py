import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Endpoint
from app.scanner.http_client import ResilientHttpClient
from app.scanner.fuzzer.result import FuzzTestResult
from app.scanner.analysis.baseline import BaselineCollector
from app.scanner.analysis.differential import DifferentialComparator
from app.scanner.analysis.anomaly import AnomalyReport

logger = logging.getLogger(__name__)

SCAN_ANALYSIS_REPORTS: dict[str, list[AnomalyReport]] = {}

class ResponseAnalyzer:
    def __init__(self, db: AsyncSession, scan_id: str, client: ResilientHttpClient):
        self.db = db
        self.scan_id = scan_id
        self.baseline_collector = BaselineCollector(client)

    async def analyze_fuzz_results(self, fuzz_results: list[FuzzTestResult]) -> list[AnomalyReport]:
        logger.info(f"Running Response Analysis on {len(fuzz_results)} fuzz test results for scan {self.scan_id}")
        
        # Load endpoints
        stmt = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        res = await self.db.execute(stmt)
        endpoints = {ep.id: ep for ep in res.scalars().all()}

        reports: list[AnomalyReport] = []

        for test in fuzz_results:
            endpoint = endpoints.get(test.endpoint_id)
            if not endpoint:
                continue

            baseline = await self.baseline_collector.get_baseline(endpoint)
            diff = DifferentialComparator.compare(baseline, test)

            # Compute score and signals deterministically
            signals = []
            score = 0

            # 1. SQL Injection indicators
            if diff.sql_error_detected:
                score += 50
                signals.append(f"SQL database error message reflected in response body")
            
            # 2. XSS payload reflection
            if test.category == "XSS" and diff.payload_reflected:
                score += 45
                signals.append(f"Raw unescaped script probe reflected in response")

            # 3. Status shifts
            if diff.status_code_changed:
                if diff.test_status == 500:
                    score += 35
                    signals.append(f"HTTP 500 Server Error triggered by probe (baseline: HTTP {diff.baseline_status})")
                elif diff.baseline_status in [401, 403] and diff.test_status == 200:
                    score += 45
                    signals.append(f"Authentication boundary bypass detected (HTTP {diff.baseline_status} -> HTTP 200)")

            # 4. Length divergence
            if diff.length_diff_ratio > 2.0 or (diff.length_diff_ratio < 0.3 and diff.length_diff_bytes > 100):
                score += 15
                signals.append(f"Significant response body length shift (diff: {diff.length_diff_bytes} bytes)")

            is_anomaly = score >= 30 or len(signals) > 0

            baseline_summary = f"HTTP {baseline.status_code}, {baseline.content_length} bytes, {baseline.content_type}"
            test_summary = f"HTTP {test.status_code}, latency {test.response_time_ms}ms"
            if diff.payload_reflected:
                test_summary += ", payload reflected"

            report = AnomalyReport(
                test_id=test.test_id,
                scan_id=self.scan_id,
                endpoint_id=test.endpoint_id,
                parameter_id=test.parameter_id,
                parameter_name=test.parameter_name,
                category=test.category,
                payload=test.payload,
                anomaly=is_anomaly,
                score=min(score, 100),
                signals=signals,
                baseline_summary=baseline_summary,
                test_summary=test_summary,
                differential=diff
            )
            reports.append(report)

        SCAN_ANALYSIS_REPORTS[self.scan_id] = reports
        anomalies_count = sum(1 for r in reports if r.anomaly)
        logger.info(f"Response analysis complete. Found {anomalies_count} anomalies out of {len(reports)} tests.")
        return reports
