from pydantic import BaseModel
from typing import Optional
from enum import Enum

class PriorityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class RuleEvaluation(BaseModel):
    feature: str
    score_contribution: int
    explanation: str

class EndpointPriorityResult(BaseModel):
    endpoint_id: str
    score: int
    priority: PriorityLevel
    reasons: list[str]
    rule_evaluations: Optional[list[RuleEvaluation]] = None
