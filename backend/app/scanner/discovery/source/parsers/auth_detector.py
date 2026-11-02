"""
Authentication and Authorization Logic Analyzer.
Detects JWT validation, session middleware, role checks (RBAC), and route guards.
"""
import logging
import os
import re
from typing import List, Dict, Any, Optional

from app.scanner.discovery.source.models import SourceAuthRequirement

logger = logging.getLogger(__name__)

# JWT validation markers in Python & JS
JWT_PATTERNS = [
    re.compile(r'jwt\.decode\s*\(', re.I),
    re.compile(r'jwt\.verify\s*\(', re.I),
    re.compile(r'jwt_required\s*\(', re.I),
    re.compile(r'decode_access_token', re.I),
    re.compile(r'PyJWT', re.I),
    re.compile(r'jsonwebtoken', re.I)
]

# Role / RBAC checks
ROLE_PATTERNS = [
    re.compile(r'has_role\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I),
    re.compile(r'roles\s*:\s*\[([^\]]+)\]', re.I),
    re.compile(r'roles_required\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I),
    re.compile(r'check_permission\s*\(\s*["\']([^"\']+)["\']\s*\)', re.I),
    re.compile(r'@Roles\s*\(\s*([^)]+)\)', re.I)
]

# Session middleware
SESSION_PATTERNS = [
    re.compile(r'express-session', re.I),
    re.compile(r'cookie-session', re.I),
    re.compile(r'SessionMiddleware', re.I),
    re.compile(r'request\.session', re.I)
]

class AuthDetector:
    """
    Scans source files to identify authentication mechanisms, middleware, and authorization rules.
    """

    def __init__(self, repo_root: str):
        self.repo_root = repo_root

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        rel_path = os.path.relpath(file_path, self.repo_root)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        observations: List[Dict[str, Any]] = []
        source_lines = content.splitlines()

        # 1. JWT Analysis
        for pat in JWT_PATTERNS:
            for match in pat.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                observations.append({
                    "auth_type": "JWT",
                    "mechanism": match.group(0).strip(),
                    "file_path": rel_path,
                    "line_number": line_num,
                    "roles_allowed": [],
                    "is_enforced": True
                })
                break # 1 per pattern per file

        # 2. Session Analysis
        for pat in SESSION_PATTERNS:
            for match in pat.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                observations.append({
                    "auth_type": "SESSION",
                    "mechanism": match.group(0).strip(),
                    "file_path": rel_path,
                    "line_number": line_num,
                    "roles_allowed": [],
                    "is_enforced": True
                })
                break

        # 3. RBAC / Role checks
        for pat in ROLE_PATTERNS:
            for match in pat.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                raw_roles = match.group(1).replace("'", "").replace('"', "").replace(" ", "").split(",")
                clean_roles = [r.strip() for r in raw_roles if r.strip()]
                observations.append({
                    "auth_type": "RBAC",
                    "mechanism": match.group(0).strip()[:100],
                    "file_path": rel_path,
                    "line_number": line_num,
                    "roles_allowed": clean_roles,
                    "is_enforced": True
                })

        return observations
