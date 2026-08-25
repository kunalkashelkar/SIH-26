import logging
from app.scanner.analysis.baseline import BaselineResponse
from app.scanner.fuzzer.result import FuzzTestResult
from app.scanner.analysis.anomaly import DifferentialSignals

logger = logging.getLogger(__name__)

class DifferentialComparator:
    SQL_ERRORS = [
        "syntax error", "sqlite3.operationalerror", "psycopg2", "mysql", 
        "ora-", "sql syntax", "unclosed quotation mark", "database error",
        "pg_query", "sqlalchemy.exc"
    ]

    @classmethod
    def compare(cls, baseline: BaselineResponse, test_result: FuzzTestResult) -> DifferentialSignals:
        test_status = test_result.status_code
        baseline_status = baseline.status_code
        test_body = (test_result.response_snippet or "").lower()

        status_changed = test_status is not None and test_status != baseline_status
        length_diff = abs(len(test_result.response_snippet) - len(baseline.body_snippet))
        length_ratio = (
            round(len(test_result.response_snippet) / max(len(baseline.body_snippet), 1), 2)
        )

        payload_reflected = bool(test_result.payload and test_result.payload in (test_result.response_snippet or ""))
        
        sql_detected = any(err in test_body for err in cls.SQL_ERRORS)
        server_error = test_status == 500

        return DifferentialSignals(
            status_code_changed=status_changed,
            baseline_status=baseline_status,
            test_status=test_status,
            length_diff_bytes=length_diff,
            length_diff_ratio=length_ratio,
            payload_reflected=payload_reflected,
            sql_error_detected=sql_detected,
            server_error_triggered=server_error,
            content_type_changed=False
        )
