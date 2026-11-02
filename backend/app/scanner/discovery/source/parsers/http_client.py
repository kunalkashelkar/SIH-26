"""
HTTP Client and API Call Analyzer.
Inspects frontend fetch(), axios, and service wrappers to identify backend calls.
Distinguishes static paths from dynamic templates with unresolved variables.
"""
import logging
import os
import re
from typing import List, Dict, Any, Optional

from app.scanner.discovery.source.models import DiscoveredClientCall

logger = logging.getLogger(__name__)

# Fetch call regex: fetch('/api/...', { method: 'POST' })
FETCH_REGEX = re.compile(
    r'fetch\s*\(\s*([`\'"][^`\'"]+[`\'"])(?:\s*,\s*\{([^}]*)\})?',
    re.MULTILINE
)

# Axios or api service call: axios.get('/api/...'), api.post(`/users/${id}`)
AXIOS_REGEX = re.compile(
    r'(?:axios|api|client|httpClient|http)\.(get|post|put|delete|patch)\s*\(\s*([`\'"][^`\'"]+[`\'"])',
    re.IGNORECASE
)

class HttpClientAnalyzer:
    """
    Extracts HTTP client API invocations from frontend files.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def parse_file(self, file_path: str) -> List[DiscoveredClientCall]:
        rel_path = os.path.relpath(file_path, self.repo_root)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        calls: List[DiscoveredClientCall] = []
        source_lines = content.splitlines()

        # 1. Inspect fetch() calls
        for match in FETCH_REGEX.finditer(content):
            raw_url_literal = match.group(1).strip()
            options = match.group(2) or ""
            line_num = content[:match.start()].count("\n") + 1
            snippet = "\n".join(source_lines[max(0, line_num - 1):min(len(source_lines), line_num + 2)])

            method = "GET"
            if options:
                m_match = re.search(r'method:\s*["\'](GET|POST|PUT|DELETE|PATCH)["\']', options, re.I)
                if m_match:
                    method = m_match.group(1).upper()

            parsed = self._normalize_url_literal(raw_url_literal)
            if parsed and (parsed["path"].startswith("/") or "/api/" in parsed["path"]):
                calls.append(DiscoveredClientCall(
                    url_pattern=parsed["path"],
                    method=method,
                    file_path=rel_path,
                    line_number=line_num,
                    client_library="fetch",
                    is_dynamic=parsed["is_dynamic"],
                    dynamic_variables=parsed["variables"],
                    code_snippet=snippet
                ))

        # 2. Inspect axios / service calls
        for match in AXIOS_REGEX.finditer(content):
            method = match.group(1).upper()
            raw_url_literal = match.group(2).strip()
            line_num = content[:match.start()].count("\n") + 1
            snippet = "\n".join(source_lines[max(0, line_num - 1):min(len(source_lines), line_num + 2)])

            parsed = self._normalize_url_literal(raw_url_literal)
            if parsed and (parsed["path"].startswith("/") or "/api/" in parsed["path"]):
                calls.append(DiscoveredClientCall(
                    url_pattern=parsed["path"],
                    method=method,
                    file_path=rel_path,
                    line_number=line_num,
                    client_library="axios",
                    is_dynamic=parsed["is_dynamic"],
                    dynamic_variables=parsed["variables"],
                    code_snippet=snippet
                ))

        return calls

    def _normalize_url_literal(self, literal: str) -> Optional[Dict[str, Any]]:
        """
        Parses JS string literals and template strings.
        e.g. `/api/users/${id}` -> path: "/api/users/{id}", variables: ["id"], is_dynamic: True
        """
        if not literal or len(literal) < 2:
            return None

        is_template = literal.startswith("`") and literal.endswith("`")
        inner = literal[1:-1]

        # Extract variables from ${var}
        variables = []
        is_dynamic = False

        if is_template and "${" in inner:
            is_dynamic = True
            for v_match in re.finditer(r'\$\{([^}]+)\}', inner):
                variables.append(v_match.group(1).strip())
            # Replace ${var} with {var}
            normalized_path = re.sub(r'\$\{([a-zA-Z0-9_\.]+)\}', r'{\1}', inner)
        else:
            normalized_path = inner

        # Strip host prefix if present (e.g. http://localhost:8000/api/...)
        if "://" in normalized_path:
            import urllib.parse
            parsed = urllib.parse.urlparse(normalized_path)
            normalized_path = parsed.path or "/"

        return {
            "path": normalized_path,
            "is_dynamic": is_dynamic,
            "variables": variables
        }
