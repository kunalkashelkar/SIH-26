from pydantic import BaseModel

class OWASPDefinition(BaseModel):
    category_id: str
    name: str
    description: str

OWASP_CATALOG: dict[str, OWASPDefinition] = {
    "SQLI": OWASPDefinition(
        category_id="A03:2021-Injection",
        name="Injection",
        description="User-supplied data is not validated, filtered, or sanitized by the application before being used in an interpreter or database command."
    ),
    "XSS": OWASPDefinition(
        category_id="A03:2021-Injection",
        name="Injection",
        description="Cross-Site Scripting flaws occur when an application includes untrusted data in a new web page without proper validation or escaping."
    ),
    "IDOR": OWASPDefinition(
        category_id="A01:2021-Broken Access Control",
        name="Broken Access Control",
        description="Access control policies are not enforced properly, allowing users to act outside of their intended permissions or view unauthorized data."
    ),
    "AUTH_BYPASS": OWASPDefinition(
        category_id="A07:2021-Identification and Authentication Failures",
        name="Identification and Authentication Failures",
        description="Confirmation of the user's identity, authentication, and session management are not executed securely."
    ),
    "OPEN_REDIRECT": OWASPDefinition(
        category_id="A01:2021-Broken Access Control",
        name="Broken Access Control",
        description="Application redirects to untrusted external destinations without validating the target URL against an allowlist."
    ),
    "TYPE_CONFUSION": OWASPDefinition(
        category_id="A04:2021-Insecure Design",
        name="Insecure Design",
        description="Lack of type safety, schema enforcement, or boundary validation controls in software architecture."
    ),
    "INPUT_VALIDATION": OWASPDefinition(
        category_id="A04:2021-Insecure Design",
        name="Insecure Design",
        description="General failure to apply strict allow-lists and input constraints across untrusted boundaries."
    )
}
