from pydantic import BaseModel
from typing import Any, Optional
from app.models.models import Parameter, Endpoint
from app.scanner.context.classifier import EndpointClassifier

class ParameterContext(BaseModel):
    parameter_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    parameter: str
    location: str  # query, body, path, header
    type: str      # numeric, string, boolean, identifier, unknown
    endpoint_type: str  # api, web
    method: str
    content_type: str
    is_sensitive: bool
    recommended_tests: list[str] = []
    metadata: dict[str, Any] = {}

class ParameterContextExtractor:
    IDENTIFIER_NAMES = ["id", "uid", "user_id", "account_id", "item_id", "product_id", "order_id", "doc_id"]
    AUTH_NAMES = ["username", "user", "email", "password", "pass", "token", "secret", "apikey", "api_key"]
    SEARCH_NAMES = ["q", "query", "search", "keyword", "filter", "find"]
    REDIRECT_NAMES = ["url", "redirect", "next", "return", "ref", "target", "goto", "callback"]
    FILE_NAMES = ["file", "path", "filename", "doc", "image", "upload", "page", "include"]

    @classmethod
    def extract_context(cls, param: Parameter, endpoint: Endpoint, recommended_tests: list[str] = None) -> ParameterContext:
        ep_classification = EndpointClassifier.classify(endpoint)
        
        name_lower = (param.name or "").lower()
        param_type = param.value_type or "unknown"

        # Semantic type refinement
        if name_lower in cls.IDENTIFIER_NAMES or name_lower.endswith("_id"):
            semantic_type = "identifier"
        elif name_lower in cls.AUTH_NAMES:
            semantic_type = "credential"
        elif name_lower in cls.SEARCH_NAMES:
            semantic_type = "search_query"
        elif name_lower in cls.REDIRECT_NAMES:
            semantic_type = "redirect_target"
        elif name_lower in cls.FILE_NAMES:
            semantic_type = "file_path"
        else:
            semantic_type = param_type

        is_sensitive = (
            ep_classification["sensitivity_level"] == "HIGH" 
            or semantic_type in ["credential", "identifier", "file_path"]
        )

        return ParameterContext(
            parameter_id=param.id,
            endpoint_id=endpoint.id,
            parameter=param.name,
            location=param.location or "query",
            type=param_type,
            endpoint_type=ep_classification["endpoint_type"],
            method=ep_classification["method"],
            content_type=ep_classification["content_type"],
            is_sensitive=is_sensitive,
            recommended_tests=recommended_tests or [],
            metadata={
                "endpoint_path": endpoint.path,
                "semantic_type": semantic_type,
                "sensitivity_categories": ep_classification["sensitivity_categories"]
            }
        )
