import logging
from app.scanner.context.parameter_context import ParameterContext

logger = logging.getLogger(__name__)

class TestSelector:
    """
    Deterministically selects targeted security test categories based on parameter & endpoint context.
    Prevents blind fuzzing and excessive payload volume.
    """

    @classmethod
    def select_tests(cls, context: ParameterContext) -> list[str]:
        recommended: set[str] = set()
        param_name = context.parameter.lower()
        param_type = context.type.lower()
        semantic_type = context.metadata.get("semantic_type", "")
        is_api = context.endpoint_type == "api"

        # 1. SQL Injection (SQLi)
        # Suitable for numeric identifiers, database query fields, or parameters on data-retrieval endpoints
        if param_type in ["numeric", "identifier"] or semantic_type in ["identifier", "search_query"] or "id" in param_name:
            recommended.add("SQLI")

        # 2. Cross-Site Scripting (XSS)
        # Suitable for string parameters, HTML forms, and search query inputs in web endpoints
        if (not is_api or "search" in param_name) and param_type in ["string", "unknown", "search_query"]:
            recommended.add("XSS")

        # 3. IDOR / Broken Object Level Authorization (BOLA)
        # Highly relevant for identifiers and numeric IDs in API endpoints
        if is_api and (param_type in ["numeric", "identifier"] or semantic_type == "identifier" or "id" in param_name):
            recommended.add("IDOR")

        # 4. Authentication / Credential Testing
        if semantic_type == "credential" or param_name in ["username", "user", "password", "pass", "token"]:
            recommended.add("AUTH_BYPASS")

        # 5. Open Redirect / SSRF
        if semantic_type == "redirect_target" or param_name in ["url", "redirect", "next", "return", "ref"]:
            recommended.add("OPEN_REDIRECT")

        # 6. Type Boundary & Error Provocation (General)
        if param_type == "numeric":
            recommended.add("TYPE_CONFUSION")

        # Default fallback for unclassified parameters
        if not recommended:
            recommended.add("INPUT_VALIDATION")

        tests = sorted(list(recommended))
        context.recommended_tests = tests
        return tests
