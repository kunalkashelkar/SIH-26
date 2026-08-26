from enum import Enum
from pydantic import BaseModel

class FindingPriority(str, Enum):
    P1 = "P1"  # Critical immediate attention
    P2 = "P2"  # High priority
    P3 = "P3"  # Medium priority
    P4 = "P4"  # Low priority / backlog

class ContextualRiskResult(BaseModel):
    priority: FindingPriority
    risk_score: float
    factors: list[str]

class ContextualRiskCalculator:
    """
    Computes priority based on CVSS severity, endpoint priority score, parameter sensitivity, and exposure.
    """
    @classmethod
    def calculate_priority(
        cls,
        cvss_severity: str,
        cvss_score: float = 5.0,
        endpoint_priority_score: float = 0.0,
        is_sensitive_endpoint: bool = False,
        is_api: bool = False,
        confidence_level: str = "HIGH",
        parameter_name: str = ""
    ) -> ContextualRiskResult:
        factors = []
        base_priority_weights = {
            "CRITICAL": 90.0,
            "HIGH": 75.0,
            "MEDIUM": 50.0,
            "LOW": 25.0,
            "INFO": 10.0
        }

        severity_upper = cvss_severity.upper()
        score = base_priority_weights.get(severity_upper, 50.0)
        factors.append(f"{severity_upper.capitalize()} severity rating (CVSS: {cvss_score})")

        # Validation & Evidence strength
        if confidence_level == "HIGH":
            factors.append("Strong evidence validated via reproducibility and control probing")
        else:
            factors.append("Validated finding confirmed via differential response signals")

        # Context factor: Endpoint Priority Scorer
        if endpoint_priority_score > 60:
            score += 15
            factors.append(f"High-exposure attack surface (endpoint score: {endpoint_priority_score})")
        elif endpoint_priority_score > 30:
            score += 5
            factors.append("Internet-facing exposed endpoint")

        # Context factor: Sensitive route
        if is_sensitive_endpoint:
            score += 10
            factors.append("Sensitive/Authentication boundary route")

        # Context factor: API route exposure
        if is_api:
            score += 5
            factors.append("Direct API surface exposure")

        # Context factor: User controlled parameter
        if parameter_name:
            factors.append(f"Direct injection into parameter '{parameter_name}'")

        score = min(score, 100.0)

        if score >= 85:
            priority = FindingPriority.P1
        elif score >= 65:
            priority = FindingPriority.P2
        elif score >= 40:
            priority = FindingPriority.P3
        else:
            priority = FindingPriority.P4

        return ContextualRiskResult(
            priority=priority,
            risk_score=score,
            factors=factors
        )
