from pydantic import BaseModel
from typing import Optional

from app.scanner.risk.cvss import CVSSCalculator, CVSSType
from app.scanner.risk.contextual import ContextualRiskCalculator, FindingPriority
from app.scanner.remediation.recommendations import RemediationProvider, StructuredRemediation
from app.models.models import Endpoint, Parameter

class EvaluatedRisk(BaseModel):
    category: str
    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    cvss_vector: str
    confidence_score: int  # 0 to 100
    priority: str  # P1, P2, P3, P4
    priority_reasons: list[str] = []
    impact: str
    description: str
    remediation: str
    cwe: str
    owasp_category: str
    prevention_guidance: str

class RiskClassifier:
    """
    Evaluates confirmed findings by generating distinct severity, confidence (0-100), and priority ratings with transparent reasons.
    """
    @classmethod
    def evaluate(
        cls,
        category: str,
        endpoint: Endpoint,
        parameter_name: str,
        validation_reproduced: bool,
        distinct_error_reflection: bool,
        raw_confidence_level: str
    ) -> EvaluatedRisk:
        # 1. Base CVSS severity
        is_auth_route = "/login" in (endpoint.path or "") or "/auth" in (endpoint.path or "")
        cvss_res = CVSSCalculator.calculate_base_cvss(category, is_authenticated=is_auth_route)

        # 2. Contextual Priority (P1-P4) with explainable factors
        context_res = ContextualRiskCalculator.calculate_priority(
            cvss_severity=cvss_res.severity.value,
            cvss_score=cvss_res.base_score,
            endpoint_priority_score=endpoint.priority_score or 0.0,
            is_sensitive_endpoint=is_auth_route,
            is_api=endpoint.is_api or False,
            confidence_level=raw_confidence_level,
            parameter_name=parameter_name
        )

        # 3. Separate Confidence calculation (0-100)
        confidence_score = 70
        if raw_confidence_level == "HIGH":
            confidence_score = 95 if distinct_error_reflection else 88
        elif raw_confidence_level == "MEDIUM":
            confidence_score = 75
        elif raw_confidence_level == "LOW":
            confidence_score = 50

        # 4. Remediation guidance
        remediation_info = RemediationProvider.get_remediation(
            category=category,
            endpoint_path=endpoint.path,
            parameter_name=parameter_name
        )

        vuln_type_names = {
            "SQLI": "SQL Injection",
            "XSS": "Cross-Site Scripting (XSS)",
            "IDOR": "Insecure Direct Object Reference (IDOR)",
            "AUTH_BYPASS": "Authentication Bypass",
            "OPEN_REDIRECT": "Open Redirect",
            "TYPE_CONFUSION": "Type Confusion Exception"
        }
        vuln_type = vuln_type_names.get(category.upper(), f"{category} Vulnerability")

        return EvaluatedRisk(
            category=category.upper(),
            vulnerability_type=vuln_type,
            severity=cvss_res.severity.value,
            cvss_score=cvss_res.base_score,
            cvss_vector=cvss_res.vector_string,
            confidence_score=confidence_score,
            priority=context_res.priority.value,
            priority_reasons=context_res.factors,
            impact=remediation_info.impact,
            description=remediation_info.explanation,
            remediation=remediation_info.remediation,
            cwe=remediation_info.cwe,
            owasp_category=remediation_info.owasp_category,
            prevention_guidance=remediation_info.prevention_guidance
        )
