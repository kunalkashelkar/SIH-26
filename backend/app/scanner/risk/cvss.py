from enum import Enum
from pydantic import BaseModel

class CVSSType(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class CVSSScoreResult(BaseModel):
    base_score: float
    severity: CVSSType
    vector_string: str

class CVSSCalculator:
    """
    Deterministic CVSS v3.1 base score approximation for vulnerability types.
    """
    CATEGORY_BASE_METRICS = {
        "AUTH_BYPASS": {
            "score": 9.8,
            "severity": CVSSType.CRITICAL,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "SQLI": {
            "score": 8.6,
            "severity": CVSSType.HIGH,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        },
        "IDOR": {
            "score": 7.5,
            "severity": CVSSType.HIGH,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "XSS": {
            "score": 6.1,
            "severity": CVSSType.MEDIUM,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "OPEN_REDIRECT": {
            "score": 4.7,
            "severity": CVSSType.LOW,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"
        },
        "TYPE_CONFUSION": {
            "score": 5.3,
            "severity": CVSSType.MEDIUM,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
        },
        "INPUT_VALIDATION": {
            "score": 3.7,
            "severity": CVSSType.LOW,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
        }
    }

    @classmethod
    def calculate_base_cvss(cls, category: str, is_authenticated: bool = False) -> CVSSScoreResult:
        cat_key = category.upper()
        entry = cls.CATEGORY_BASE_METRICS.get(cat_key, cls.CATEGORY_BASE_METRICS["INPUT_VALIDATION"])
        
        score = entry["score"]
        if is_authenticated:
            # Slightly lower score if attack requires authentication
            score = max(round(score - 1.0, 1), 1.0)
            
        severity = entry["severity"]
        if score >= 9.0:
            severity = CVSSType.CRITICAL
        elif score >= 7.0:
            severity = CVSSType.HIGH
        elif score >= 4.0:
            severity = CVSSType.MEDIUM
        else:
            severity = CVSSType.LOW

        return CVSSScoreResult(
            base_score=score,
            severity=severity,
            vector_string=entry["vector"]
        )
