import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.models import Endpoint
from app.scanner.prioritization.models import EndpointPriorityResult, PriorityLevel, RuleEvaluation
from app.scanner.prioritization.rules import PrioritizationRules

logger = logging.getLogger(__name__)

class RuleBasedPrioritizer:
    def __init__(self, db: AsyncSession, scan_id: str):
        self.db = db
        self.scan_id = scan_id

    def score_endpoint(self, endpoint: Endpoint) -> EndpointPriorityResult:
        evaluations: list[RuleEvaluation] = []
        
        # Run all explainable rule checks
        checks = [
            PrioritizationRules.evaluate_parameters(endpoint),
            PrioritizationRules.evaluate_http_method(endpoint),
            PrioritizationRules.evaluate_api(endpoint),
            PrioritizationRules.evaluate_sensitive_paths(endpoint),
            PrioritizationRules.evaluate_status_code(endpoint),
            PrioritizationRules.evaluate_depth(endpoint),
        ]

        total_score = 0
        reasons = []
        for eval_result in checks:
            if eval_result:
                evaluations.append(eval_result)
                total_score += eval_result.score_contribution
                reasons.append(eval_result.explanation)

        # Categorize priority
        if total_score >= 12:
            priority = PriorityLevel.CRITICAL
        elif total_score >= 8:
            priority = PriorityLevel.HIGH
        elif total_score >= 4:
            priority = PriorityLevel.MEDIUM
        elif total_score > 0:
            priority = PriorityLevel.LOW
        else:
            priority = PriorityLevel.INFO

        return EndpointPriorityResult(
            endpoint_id=endpoint.id,
            score=total_score,
            priority=priority,
            reasons=reasons,
            rule_evaluations=evaluations
        )

    async def prioritize_all(self) -> list[EndpointPriorityResult]:
        logger.info(f"Running Rule-Based Prioritizer for scan {self.scan_id}")
        stmt = (
            select(Endpoint)
            .options(selectinload(Endpoint.parameters))
            .where(Endpoint.scan_id == self.scan_id)
        )
        res = await self.db.execute(stmt)
        endpoints = res.scalars().all()

        results: list[EndpointPriorityResult] = []
        for ep in endpoints:
            scored = self.score_endpoint(ep)
            # Store numeric score on the Endpoint model
            ep.priority_score = float(scored.score)
            self.db.add(ep)
            results.append(scored)

        await self.db.commit()
        logger.info(f"Prioritization completed for {len(results)} endpoints in scan {self.scan_id}")
        return results
