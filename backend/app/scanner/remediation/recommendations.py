from pydantic import BaseModel
from typing import Optional

from app.scanner.remediation.cwe import CWE_CATALOG, CWEDefinition
from app.scanner.remediation.owasp import OWASP_CATALOG, OWASPDefinition
from app.scanner.remediation.rules import REMEDIATION_RULES, RemediationRule

class StructuredRemediation(BaseModel):
    category: str
    cwe: str
    cwe_name: str
    owasp_category: str
    owasp_name: str
    explanation: str
    impact: str
    remediation: str
    prevention_guidance: str

class RemediationProvider:
    @classmethod
    def get_remediation(cls, category: str, endpoint_path: str, parameter_name: str) -> StructuredRemediation:
        cat_key = category.upper()
        
        # 1. CWE
        cwe_def = CWE_CATALOG.get(cat_key, CWE_CATALOG["INPUT_VALIDATION"])
        
        # 2. OWASP
        owasp_def = OWASP_CATALOG.get(cat_key, OWASP_CATALOG["INPUT_VALIDATION"])
        
        # 3. Rule details
        rule = REMEDIATION_RULES.get(cat_key, REMEDIATION_RULES["INPUT_VALIDATION"])
        
        explanation = rule.explanation_template.format(
            parameter=parameter_name or "request",
            endpoint=endpoint_path or "endpoint"
        )
        impact = rule.impact_template.format(
            parameter=parameter_name or "request",
            endpoint=endpoint_path or "endpoint"
        )
        remediation = rule.remediation_template.format(
            parameter=parameter_name or "request",
            endpoint=endpoint_path or "endpoint"
        )

        return StructuredRemediation(
            category=cat_key,
            cwe=cwe_def.cwe_id,
            cwe_name=cwe_def.name,
            owasp_category=owasp_def.category_id,
            owasp_name=owasp_def.name,
            explanation=explanation,
            impact=impact,
            remediation=remediation,
            prevention_guidance=rule.prevention_guidance
        )
