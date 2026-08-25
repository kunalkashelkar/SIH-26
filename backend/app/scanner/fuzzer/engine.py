import asyncio
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Endpoint, Parameter
from app.scanner.http_client import ResilientHttpClient
from app.scanner.context.parameter_context import ParameterContextExtractor, ParameterContext
from app.scanner.context.test_selector import TestSelector
from app.scanner.fuzzer.payload_manager import PayloadManager
from app.scanner.fuzzer.executor import FuzzExecutor
from app.scanner.fuzzer.result import FuzzTestResult

logger = logging.getLogger(__name__)

# In-memory store for recent scan fuzz results (for API responses)
SCAN_FUZZ_RESULTS: dict[str, list[FuzzTestResult]] = {}
SCAN_CONTEXTS: dict[str, list[ParameterContext]] = {}

class FuzzingEngine:
    def __init__(self, db: AsyncSession, scan_id: str, client: ResilientHttpClient):
        self.db = db
        self.scan_id = scan_id
        self.client = client
        self.executor = FuzzExecutor(client)

    async def get_contexts(self) -> list[ParameterContext]:
        """
        Builds parameter contexts and recommended tests for all endpoints of this scan.
        """
        stmt = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        res = await self.db.execute(stmt)
        endpoints = res.scalars().all()

        contexts: list[ParameterContext] = []
        for ep in endpoints:
            for param in ep.parameters:
                ctx = ParameterContextExtractor.extract_context(param, ep)
                TestSelector.select_tests(ctx)
                contexts.append(ctx)

        SCAN_CONTEXTS[self.scan_id] = contexts
        return contexts

    async def run(self, cancel_event: asyncio.Event) -> list[FuzzTestResult]:
        logger.info(f"Starting Fuzzing Engine for scan {self.scan_id}")
        
        # 1. Fetch prioritized endpoints and build parameter contexts
        stmt = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
            .order_by(Endpoint.priority_score.desc())
        )
        res = await self.db.execute(stmt)
        endpoints = res.scalars().all()

        all_test_cases = []
        all_contexts: list[ParameterContext] = []

        for ep in endpoints:
            if cancel_event.is_set():
                break

            for param in ep.parameters:
                # 2. Extract context
                ctx = ParameterContextExtractor.extract_context(param, ep)
                # 3. Select appropriate tests
                TestSelector.select_tests(ctx)
                all_contexts.append(ctx)

                # 4. Generate targeted test cases
                test_cases = PayloadManager.generate_tests_for_parameter(self.scan_id, ep, ctx)
                all_test_cases.extend(test_cases)

        SCAN_CONTEXTS[self.scan_id] = all_contexts
        logger.info(f"Generated {len(all_test_cases)} targeted test cases for scan {self.scan_id}")

        # 5. Execute test cases asynchronously
        results: list[FuzzTestResult] = []
        for test in all_test_cases:
            if cancel_event.is_set():
                logger.warning(f"Fuzzing cancelled for scan {self.scan_id}")
                break

            result = await self.executor.execute_test(test, cancel_event)
            results.append(result)
            
            if result.is_anomaly:
                logger.info(f"Anomaly detected on {test.parameter_name} ({test.category}): {result.anomaly_reason}")

        SCAN_FUZZ_RESULTS[self.scan_id] = results
        logger.info(f"Fuzzing engine completed {len(results)} tests for scan {self.scan_id}")
        return results
