"""
Endpoint Path and Method Matcher.
Normalizes and correlates source-defined routes with runtime-observed HTTP requests.
Handles dynamic parameters, version prefixes, reverse proxy prefixes, trailing slashes,
and URL encoding.
"""
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)

COMMON_PREFIXES = ["/api/v1", "/api/v2", "/api", "/v1", "/v2", "/backend", "/rest"]

@dataclass
class MatchResult:
    is_match: bool
    confidence: float
    normalized_route: str
    http_method: str
    matched_parameters: Dict[str, str] = field(default_factory=dict)
    match_type: str = "EXACT"  # EXACT, PARAMETERIZED, PREFIX_NORMALIZED, NONE
    explanation: str = ""

class EndpointPathMatcher:
    """
    Robust path and method correlation logic.
    """

    @classmethod
    def clean_path(cls, path: str) -> str:
        """Strip query, fragment, trailing slashes, and URL decode."""
        if not path:
            return "/"
        # Strip scheme/host if full URL passed
        if "://" in path:
            parsed = urllib.parse.urlparse(path)
            path = parsed.path or "/"

        # Strip query and fragment
        path = path.split("?")[0].split("#")[0]
        # URL decode
        path = urllib.parse.unquote(path)
        # Normalize slashes
        clean = "/" + "/".join([p for p in path.split("/") if p])
        return clean if clean else "/"

    @classmethod
    def compile_source_template(cls, source_path: str) -> Tuple[re.Pattern, List[str]]:
        """
        Converts template patterns:
        - {id}
        - :id
        - <int:id>
        - [...slug]
        into compiled regular expression.
        """
        clean_source = cls.clean_path(source_path)
        param_names: List[str] = []

        # Replace Django <int:id> or <id>
        def django_sub(match):
            name = match.group(2) if match.group(2) else match.group(1)
            clean_name = name.split(":")[-1]
            param_names.append(clean_name)
            return f"(?P<{clean_name}>[^/]+)"

        regex_pattern = re.sub(r'<([a-zA-Z0-9_]+:)?([a-zA-Z0-9_]+)>', django_sub, clean_source)

        # Replace Next.js catch-all: {[...slug]} or [...slug]
        def catch_all_sub(match):
            name = match.group(1)
            param_names.append(name)
            return f"(?P<{name}>.+)"

        regex_pattern = re.sub(r'\{?\.\.\.([a-zA-Z0-9_]+)\}?', catch_all_sub, regex_pattern)

        # Replace {param} or :param
        def standard_sub(match):
            name = match.group(1) or match.group(2)
            param_names.append(name)
            return f"(?P<{name}>[^/]+)"

        regex_pattern = re.sub(r'\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)', standard_sub, regex_pattern)

        # Ensure exact string match
        compiled = re.compile(f"^{regex_pattern}$", re.IGNORECASE)
        return compiled, param_names

    @classmethod
    def match(
        cls,
        source_path: str,
        source_method: str,
        runtime_path: str,
        runtime_method: str
    ) -> MatchResult:
        """
        Evaluates whether source endpoint matches runtime request.
        """
        # Auto-detect if caller passed (method, path) instead of (path, method)
        http_verbs = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ALL", "*"}
        if str(source_path).upper() in http_verbs and str(source_method).startswith("/"):
            source_path, source_method = source_method, source_path
        if str(runtime_path).upper() in http_verbs and str(runtime_method).startswith("/"):
            runtime_path, runtime_method = runtime_method, runtime_path

        s_method = (source_method or "GET").upper()
        r_method = (runtime_method or "GET").upper()

        # Strict HTTP method check (except ALL / * wildcards)
        if s_method not in [r_method, "ALL", "*"]:
            return MatchResult(
                is_match=False,
                confidence=0.0,
                normalized_route=cls.clean_path(source_path),
                http_method=s_method,
                explanation=f"Method mismatch: source requires {s_method}, runtime observed {r_method}"
            )

        c_source = cls.clean_path(source_path)
        c_runtime = cls.clean_path(runtime_path)

        # 1. Exact path match
        if c_source.lower() == c_runtime.lower():
            return MatchResult(
                is_match=True,
                confidence=1.0,
                normalized_route=c_source,
                http_method=s_method,
                match_type="EXACT",
                explanation=f"Exact path and method match ({s_method} {c_source})"
            )

        # 2. Template / Dynamic Parameter Match
        compiled_regex, param_names = cls.compile_source_template(c_source)
        match = compiled_regex.match(c_runtime)
        if match:
            captured_params = match.groupdict()
            return MatchResult(
                is_match=True,
                confidence=0.98,
                normalized_route=c_source,
                http_method=s_method,
                matched_parameters=captured_params,
                match_type="PARAMETERIZED",
                explanation=f"Parameterized match: template {c_source} matched {c_runtime} with params {captured_params}"
            )

        # 3. Reverse Proxy / Prefix Normalization
        # Try stripping known prefixes from runtime path or source path
        stripped_source = cls._strip_known_prefixes(c_source)
        stripped_runtime = cls._strip_known_prefixes(c_runtime)

        if stripped_source and stripped_runtime and stripped_source.lower() == stripped_runtime.lower():
            return MatchResult(
                is_match=True,
                confidence=0.90,
                normalized_route=c_source,
                http_method=s_method,
                match_type="PREFIX_NORMALIZED",
                explanation=f"Normalized prefix match ({stripped_source}) after stripping proxy prefix"
            )

        # Prefix parameterized match
        compiled_stripped, _ = cls.compile_source_template(stripped_source)
        match_stripped = compiled_stripped.match(stripped_runtime)
        if match_stripped:
            return MatchResult(
                is_match=True,
                confidence=0.88,
                normalized_route=c_source,
                http_method=s_method,
                matched_parameters=match_stripped.groupdict(),
                match_type="PREFIX_NORMALIZED",
                explanation=f"Prefix-normalized parameterized match: {c_source} matched {c_runtime}"
            )

        return MatchResult(
            is_match=False,
            confidence=0.0,
            normalized_route=c_source,
            http_method=s_method,
            explanation=f"No matching pattern between {s_method} {c_source} and {r_method} {c_runtime}"
        )

    @classmethod
    def _strip_known_prefixes(cls, path: str) -> str:
        for pfx in COMMON_PREFIXES:
            if path.lower().startswith(pfx.lower()):
                remainder = path[len(pfx):]
                return cls.clean_path(remainder)
        return path
