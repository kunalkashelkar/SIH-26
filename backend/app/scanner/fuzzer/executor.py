import asyncio
import time
import urllib.parse
import logging
from typing import Optional

from app.scanner.http_client import ResilientHttpClient
from app.scanner.fuzzer.test_case import TestCase
from app.scanner.fuzzer.result import FuzzTestResult

logger = logging.getLogger(__name__)

class FuzzExecutor:
    def __init__(self, client: ResilientHttpClient):
        self.client = client

    async def execute_test(self, test: TestCase, cancel_event: asyncio.Event) -> FuzzTestResult:
        if cancel_event.is_set():
            return FuzzTestResult(
                test_id=test.test_id,
                scan_id=test.scan_id,
                endpoint_id=test.endpoint_id,
                parameter_name=test.parameter_name,
                category=test.category,
                payload=test.payload,
                error="Cancelled"
            )

        # Prepare request URL / Params / Body based on injection location
        method = test.http_method.upper()
        url = test.target_url
        params = {}
        data = {}
        json_body = None
        headers = {}

        is_api_endpoint = "/api/" in url or "/rest/" in url or test.parameter_location == "json"

        if test.parameter_location == "query":
            # Append query param
            params[test.parameter_name] = test.payload
        elif test.parameter_location in ["body", "json"]:
            if is_api_endpoint or method in ["POST", "PUT", "PATCH"]:
                val = test.payload
                if val == "null":
                    val = None
                elif val == "true":
                    val = True
                elif val == "false":
                    val = False
                elif isinstance(val, str) and val.isdigit():
                    try:
                        val = int(val)
                    except Exception:
                        pass
                json_body = {test.parameter_name: val}
                headers["Content-Type"] = "application/json"
            else:
                data[test.parameter_name] = test.payload
        elif test.parameter_location == "header":
            headers[test.parameter_name] = str(test.payload)
        elif test.parameter_location == "path":
            url = url.replace(f"{{{test.parameter_name}}}", urllib.parse.quote(str(test.payload)))
        else:
            params[test.parameter_name] = test.payload

        start_time = time.time()
        try:
            resp = await self.client._request(
                method=method,
                url=url,
                params=params if params else None,
                data=data if data else None,
                json=json_body if json_body is not None else None,
                headers=headers if headers else None
            )

            elapsed_ms = (time.time() - start_time) * 1000

            if not resp:
                return FuzzTestResult(
                    test_id=test.test_id,
                    scan_id=test.scan_id,
                    endpoint_id=test.endpoint_id,
                    parameter_name=test.parameter_name,
                    category=test.category,
                    payload=test.payload,
                    response_time_ms=round(elapsed_ms, 2),
                    error="No response received"
                )

            body_text = resp.text[:500] if hasattr(resp, "text") else ""
            status_code = resp.status_code

            # Prototype anomaly detection heuristic
            is_anomaly = False
            anomaly_reason = None

            # 1. SQL Error reflection
            sql_keywords = ["syntax error", "sqlite3.OperationalError", "psycopg2", "mysql", "ORA-", "SQL syntax", "Unclosed quotation mark"]
            if any(kw.lower() in body_text.lower() for kw in sql_keywords):
                is_anomaly = True
                anomaly_reason = "SQL error message reflected in response body"

            # 2. XSS payload unescaped reflection
            if test.category == "XSS" and test.payload in body_text:
                is_anomaly = True
                anomaly_reason = "Raw XSS payload reflected unescaped in response"

            # 3. Server error 500
            if status_code == 500:
                is_anomaly = True
                anomaly_reason = "Internal Server Error 500 triggered by payload"

            return FuzzTestResult(
                test_id=test.test_id,
                scan_id=test.scan_id,
                endpoint_id=test.endpoint_id,
                parameter_id=test.parameter_id,
                parameter_name=test.parameter_name,
                category=test.category,
                payload=test.payload,
                status_code=status_code,
                response_time_ms=round(elapsed_ms, 2),
                response_snippet=body_text[:200],
                is_anomaly=is_anomaly,
                anomaly_reason=anomaly_reason
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            return FuzzTestResult(
                test_id=test.test_id,
                scan_id=test.scan_id,
                endpoint_id=test.endpoint_id,
                parameter_id=test.parameter_id,
                parameter_name=test.parameter_name,
                category=test.category,
                payload=test.payload,
                response_time_ms=round(elapsed_ms, 2),
                error=str(e)
            )
