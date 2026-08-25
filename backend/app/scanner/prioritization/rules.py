from typing import Optional
from app.models.models import Endpoint
from app.scanner.prioritization.models import RuleEvaluation

class PrioritizationRules:
    SENSITIVE_KEYWORDS = [
        "login", "admin", "administrator", "auth", "token", "user", "users",
        "account", "password", "config", "setup", "upload", "download",
        "exec", "cmd", "query", "debug", "test", "staging", "internal"
    ]

    @classmethod
    def evaluate_parameters(cls, endpoint: Endpoint) -> Optional[RuleEvaluation]:
        param_count = len(endpoint.parameters) if endpoint.parameters else 0
        if param_count > 0:
            score = min(param_count * 2, 6)
            return RuleEvaluation(
                feature="has_parameters",
                score_contribution=score,
                explanation=f"Endpoint has {param_count} user-controlled parameter(s)"
            )
        return None

    @classmethod
    def evaluate_http_method(cls, endpoint: Endpoint) -> Optional[RuleEvaluation]:
        method = (endpoint.method or "GET").upper()
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            return RuleEvaluation(
                feature="http_method",
                score_contribution=3,
                explanation=f"Endpoint uses state-changing HTTP method ({method})"
            )
        return None

    @classmethod
    def evaluate_api(cls, endpoint: Endpoint) -> Optional[RuleEvaluation]:
        path_lower = (endpoint.path or "").lower()
        if endpoint.is_api or "api" in path_lower or "/v1/" in path_lower or "/v2/" in path_lower:
            return RuleEvaluation(
                feature="is_api",
                score_contribution=4,
                explanation="Endpoint is an API route"
            )
        return None

    @classmethod
    def evaluate_sensitive_paths(cls, endpoint: Endpoint) -> Optional[RuleEvaluation]:
        path_lower = (endpoint.path or "").lower()
        matched = [kw for kw in cls.SENSITIVE_KEYWORDS if kw in path_lower]
        if matched:
            return RuleEvaluation(
                feature="sensitive_path",
                score_contribution=5,
                explanation=f"Endpoint path matches sensitive indicator '{matched[0]}'"
            )
        return None

    @classmethod
    def evaluate_depth(cls, endpoint: Endpoint) -> Optional[RuleEvaluation]:
        depth = endpoint.depth if endpoint.depth is not None else 1
        if depth <= 2:
            return RuleEvaluation(
                feature="endpoint_depth",
                score_contribution=1,
                explanation=f"Endpoint is shallow (depth={depth}) and readily accessible"
            )
        return None

    @classmethod
    def evaluate_status_code(cls, endpoint: Endpoint) -> Optional[RuleEvaluation]:
        code = endpoint.status_code
        if code in [401, 403]:
            return RuleEvaluation(
                feature="authentication_required",
                score_contribution=4,
                explanation=f"Endpoint returned HTTP {code} indicating access-restricted or authentication boundary"
            )
        elif code in [500, 502, 503]:
            return RuleEvaluation(
                feature="previous_anomaly",
                score_contribution=3,
                explanation=f"Endpoint returned server error HTTP {code} indicating potential instability"
            )
        return None
