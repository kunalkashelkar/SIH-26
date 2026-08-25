import re
import logging
from app.scanner.retest.status import RetestVerdict

logger = logging.getLogger(__name__)

class RetestComparator:
    SQL_ERRORS = [
        "syntax error", "sqlite3.operationalerror", "psycopg2", "mysql", 
        "ora-", "sql syntax", "unclosed quotation mark", "database error",
        "pg_query", "sqlalchemy.exc"
    ]

    @classmethod
    def evaluate_response(
        cls,
        vuln_type: str,
        payload: str,
        status_code: int,
        response_body: str
    ) -> tuple[RetestVerdict, str]:
        """
        Evaluates retest response against expected vulnerability pattern.
        """
        vtype = (vuln_type or "").upper()
        body_lower = (response_body or "").lower()

        # 1. Cross-Site Scripting (XSS)
        if "XSS" in vtype or "SCRIPT" in vtype:
            if payload and payload in response_body:
                return (
                    RetestVerdict.STILL_VULNERABLE,
                    "Payload was reflected raw and unescaped into response body."
                )
            else:
                return (
                    RetestVerdict.FIXED,
                    "Payload was either sanitized, HTML-encoded, or rejected safely."
                )

        # 2. SQL Injection (SQLI)
        if "SQL" in vtype:
            if any(err in body_lower for err in cls.SQL_ERRORS) or status_code == 500:
                return (
                    RetestVerdict.STILL_VULNERABLE,
                    "Database error or HTTP 500 exception was triggered by SQL probe."
                )
            else:
                return (
                    RetestVerdict.FIXED,
                    "Database handled the probe parameter securely without syntax errors or unhandled crashes."
                )

        # 3. Authentication Bypass / IDOR
        if "AUTH" in vtype or "IDOR" in vtype:
            if status_code in [401, 403, 404]:
                return (
                    RetestVerdict.FIXED,
                    f"Access control successfully enforced (HTTP {status_code})."
                )
            elif status_code == 200:
                return (
                    RetestVerdict.STILL_VULNERABLE,
                    "Unauthenticated access permitted (HTTP 200)."
                )

        # Default fallback check
        if status_code == 500:
            return (
                RetestVerdict.STILL_VULNERABLE,
                "HTTP 500 Server Error occurred during test."
            )
            
        return (
            RetestVerdict.INCONCLUSIVE,
            f"Response returned status {status_code}; behavioral diff is inconclusive."
        )
