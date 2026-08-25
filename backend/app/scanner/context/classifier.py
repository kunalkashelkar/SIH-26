import logging
from app.models.models import Endpoint

logger = logging.getLogger(__name__)

class EndpointClassifier:
    SENSITIVE_AUTH = ["login", "signin", "auth", "oauth", "token", "session", "password"]
    SENSITIVE_ADMIN = ["admin", "administrator", "manage", "root", "setup", "config"]
    SENSITIVE_USER = ["user", "users", "profile", "account", "member"]
    SENSITIVE_ACTIONS = ["upload", "download", "delete", "remove", "export", "exec", "cmd"]

    @classmethod
    def classify(cls, endpoint: Endpoint) -> dict:
        """
        Classifies endpoint type, sensitivity, and authentication context.
        """
        path_lower = (endpoint.path or "").lower()
        method = (endpoint.method or "GET").upper()

        is_api = endpoint.is_api or "api" in path_lower or "/v1/" in path_lower or "/v2/" in path_lower
        
        # Sensitivity classification
        sensitivities = []
        if any(kw in path_lower for kw in cls.SENSITIVE_AUTH):
            sensitivities.append("AUTHENTICATION")
        if any(kw in path_lower for kw in cls.SENSITIVE_ADMIN):
            sensitivities.append("ADMINISTRATIVE")
        if any(kw in path_lower for kw in cls.SENSITIVE_USER):
            sensitivities.append("USER_MANAGEMENT")
        if any(kw in path_lower for kw in cls.SENSITIVE_ACTIONS):
            sensitivities.append("HIGH_PRIVILEGE_ACTION")

        sensitivity_level = "HIGH" if sensitivities else "STANDARD"

        # Content-type inference
        content_type = endpoint.content_type or ("application/json" if is_api else "text/html")

        return {
            "is_api": is_api,
            "endpoint_type": "api" if is_api else "web",
            "method": method,
            "content_type": content_type,
            "sensitivity_level": sensitivity_level,
            "sensitivity_categories": sensitivities,
            "requires_auth_boundary": endpoint.status_code in [401, 403]
        }
