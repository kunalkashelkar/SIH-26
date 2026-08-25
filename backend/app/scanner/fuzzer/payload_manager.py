from typing import Any
import uuid
from app.scanner.fuzzer.test_case import TestCase
from app.scanner.context.parameter_context import ParameterContext
from app.models.models import Endpoint

class PayloadManager:
    """
    Curated set of non-destructive, safe diagnostic payloads for the prototype fuzzer.
    """
    PAYLOADS = {
        "SQLI": [
            {"payload": "'", "indicator": "sql_syntax_error", "desc": "Single quote SQL syntax break"},
            {"payload": "1' OR '1'='1", "indicator": "boolean_true_diff", "desc": "Classic tautology boolean test"},
            {"payload": "1 AND 1=2", "indicator": "boolean_false_diff", "desc": "Boolean false differentiation"},
            {"payload": "SLEEP(2)", "indicator": "time_delay", "desc": "Time-based probing"}
        ],
        "XSS": [
            {"payload": "<script>alert(1)</script>", "indicator": "unescaped_script_tag", "desc": "Standard inline script reflection"},
            {"payload": "\"><img src=x onerror=1>", "indicator": "unescaped_tag_break", "desc": "Attribute escape with image onerror handler"},
            {"payload": "'><svg/onload=1>", "indicator": "unescaped_svg", "desc": "SVG onload handler"}
        ],
        "IDOR": [
            {"payload": "0", "indicator": "id_zero_access", "desc": "Boundary ID test (0)"},
            {"payload": "-1", "indicator": "id_negative_access", "desc": "Negative ID boundary test"},
            {"payload": "999999", "indicator": "id_large_access", "desc": "Large index boundary test"},
            {"payload": "admin", "indicator": "privileged_object_access", "desc": "Privileged role/user alias access"}
        ],
        "AUTH_BYPASS": [
            {"payload": "admin' --", "indicator": "auth_comment_bypass", "desc": "SQL comment username bypass"},
            {"payload": "' OR '1'='1", "indicator": "auth_tautology_bypass", "desc": "Tautology password bypass"},
            {"payload": "admin", "indicator": "default_credential_test", "desc": "Default administrative user probe"}
        ],
        "OPEN_REDIRECT": [
            {"payload": "https://example.com", "indicator": "external_redirect_header", "desc": "Absolute external URL redirect"},
            {"payload": "//example.com", "indicator": "protocol_relative_redirect", "desc": "Protocol-relative redirect probe"}
        ],
        "TYPE_CONFUSION": [
            {"payload": "NaN", "indicator": "type_error_provocation", "desc": "Non-numeric input to numeric parameter"},
            {"payload": "true", "indicator": "boolean_injection", "desc": "Boolean keyword injection"}
        ],
        "INPUT_VALIDATION": [
            {"payload": "'\";><", "indicator": "special_char_handling", "desc": "Special characters fuzzing probe"}
        ]
    }

    @classmethod
    def generate_tests_for_parameter(
        cls, 
        scan_id: str, 
        endpoint: Endpoint, 
        context: ParameterContext, 
        max_payloads_per_cat: int = 2
    ) -> list[TestCase]:
        test_cases: list[TestCase] = []

        for category in context.recommended_tests:
            available_payloads = cls.PAYLOADS.get(category, cls.PAYLOADS["INPUT_VALIDATION"])
            selected = available_payloads[:max_payloads_per_cat]

            for item in selected:
                test_case = TestCase(
                    test_id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    endpoint_id=endpoint.id,
                    parameter_id=context.parameter_id,
                    parameter_name=context.parameter,
                    parameter_location=context.location,
                    category=category,
                    target_url=endpoint.url,
                    http_method=endpoint.method or "GET",
                    payload=item["payload"],
                    expected_indicator=item["indicator"],
                    description=item["desc"]
                )
                test_cases.append(test_case)

        return test_cases
